# -*- coding: utf-8 -*-
"""Windows 安全审计采集器。

原理
----
1. auditpol 打开两个审计子类别：
   - 详细的文件共享 {0CCE9244-...}  -> 事件 5145，**自带客户端 IP / 用户名 / 共享路径**（网络访问主力）
   - 文件系统       {0CCE921D-...}  -> 事件 4663，按 SACL 触发（删除行为归因）
2. 在共享目录上写入一条 "Everyone + 指定访问掩码(DELETE 等)" 的 SACL 审计项；
   掩码越小日志量越小 —— 默认只审计删除类，不会把服务器安全日志刷爆。
3. 后台线程滚动拉取安全事件日志，解析后写入 access.log。

客户端 IP / 操作者的四级归因（越靠前越准）
----------------------------------------
a. **删除事件表**（``actors.remember_delete``）：4663 / 5145 命中删除动作时，把
   「这个路径刚刚被谁删了」记下来，记录里 ``attribution = delete_event``。
   这是「**同一次删除**」的直接证据，本机删除（服务端控制台 / 远程桌面）也能拿到操作者；
b. **5145 事件自带** ``IpAddress``：记录里 ``ip_source = share_audit``，最可靠的网络来源；
c. **路径/账号缓存**：5145 事件同时写入「路径 -> 账号+IP」缓存，删除事件按路径或账号命中，
   记录里 ``ip_source = path_cache / user_cache / recent_cache``；
d. **SMB 会话表**（``NetSessionEnum`` / ``net session``）：事件里确实没有 IP 时，按账号反查
   该客户端当前会话的 IP，记录里 ``ip_source = session``。
拿不到 IP 的场景（纯粹的服务端本地操作、机器账号、审计未开启）保持为空，不做猜测性归因。
"""
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from .logger import now_iso

try:
    import ntsecuritycon
    import win32api
    import win32evtlog
    import win32file
    import win32security
    HAS_PYWIN32 = True
    PYWIN32_ERROR = ""
except Exception as e:                                   # pragma: no cover
    HAS_PYWIN32 = False
    PYWIN32_ERROR = str(e)

try:
    import win32net                                       # SMB 会话表（客户端 IP 兜底来源）
    HAS_WIN32NET = True
    WIN32NET_ERROR = ""
except Exception as e:                                   # pragma: no cover
    HAS_WIN32NET = False
    WIN32NET_ERROR = str(e)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

SUBCATEGORY = {
    # 详细的文件共享 -> 事件 5145（含客户端 IP / 用户名 / 访问权限列表）
    "share": "{0CCE9244-69AE-11D9-BED3-505054503030}",
    # 文件共享 -> 事件 5140（较粗粒度，可选，作为兜底）
    "share_basic": "{0CCE9224-69AE-11D9-BED3-505054503030}",
    # 文件系统 -> 事件 4663（按 SACL 触发，用于删除行为归因）
    "delete": "{0CCE921D-69AE-11D9-BED3-505054503030}",
}
SUBCATEGORY_NAME = {
    "share": "详细的文件共享(5145)",
    "share_basic": "文件共享(5140)",
    "delete": "文件系统(4663)",
}
EVENT_ID = {"share": 5145, "share_basic": 5140, "delete": 4663}

# 中文/本地化系统渲染 AccessList 时返回 %%资源号，这里做可读化映射
ACCESS_RES_NAMES = {
    "%%1537": "DELETE", "%%1538": "READ_CONTROL", "%%1539": "WRITE_DAC",
    "%%1540": "WRITE_OWNER", "%%1541": "SYNCHRONIZE",
    "%%4416": "ReadData/ListDirectory", "%%4417": "WriteData/AddFile",
    "%%4418": "AppendData/AddSubdirectory", "%%4419": "ReadExtendedAttributes",
    "%%4420": "WriteExtendedAttributes", "%%4421": "Execute/Traverse",
    "%%4422": "DeleteChild", "%%4423": "ReadAttributes",
    "%%4424": "WriteAttributes", "%%4425": "WriteEA",
}

# 访问掩码位 -> 操作名（按优先级从高到低判断）
_MASK_DELETE = 0x10000 | 0x40                     # DELETE | FILE_DELETE_CHILD
_MASK_WRITE = (0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x00040000 | 0x00080000)
_MASK_READ = 0x0001 | 0x0008 | 0x0080

_CREATE_NO_WINDOW = 0x08000000
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def _same_user(a: str, b: str) -> bool:
    """账号比较：忽略域名前缀与大小写（CORP\\zhangsan == zhangsan）。"""
    a = (a or "").split("\\")[-1].strip().lower()
    b = (b or "").split("\\")[-1].strip().lower()
    return bool(a) and a == b


def _evt_close(handle) -> None:
    """pywin32 各版本关闭事件查询句柄的方式不同，逐一兜底。"""
    if handle is None:
        return
    for fn in (lambda h: h.Close(),
               lambda h: win32evtlog.EvtClose(h),
               lambda h: win32api.CloseHandle(h)):
        try:
            fn(handle)
            return
        except Exception:
            continue


class ActorCache:
    """记录"最近是谁（账号 + 客户端 IP）在访问这个路径 / 目录 / 共享"，用于给删除事件定位操作者。"""

    #: 「同一次删除」归属的有效期（秒）。4663/5145 命中的是**那一次删除本身**，
    #: 比任何缓存兜底都可靠，所以单列一张短 TTL 表并优先命中。
    DELETE_TTL = 180

    def __init__(self, ttl_seconds: int = 1800, max_entries: int = 20000):
        self.ttl = max(30, int(ttl_seconds))
        self.max_entries = max_entries
        self._path = {}          # normpath -> (user, ip, ts, client)
        self._user = {}          # user.lower -> (ip, ts, client)
        self._share = {}         # sharename.lower -> (user, ip, ts, client)
        self._del = {}           # normpath -> (user, ip, ts, client, ip_source)
        self._last = ("", "", 0.0, "")
        self._lock = threading.RLock()

    def remember_delete(self, path: str, user: str = "", ip: str = "",
                        ts: float = None, client: str = "",
                        ip_source: str = "object_audit") -> None:
        """记录「这个路径刚刚被谁删了」——来自审计事件（4663 / 5145）。

        这是删除归因里最可靠的一档：它描述的就是这一次删除，而不是"最近谁来过"。
        """
        if not path or (not user and not ip):
            return
        ts = ts or time.time()
        with self._lock:
            self._del[_norm(path)] = (user or "", ip or "", ts, client or "",
                                      ip_source or "object_audit")
            if len(self._del) > self.max_entries:
                self._gc_delete_locked(force=True)

    def _gc_delete_locked(self, force: bool = False) -> None:
        cutoff = time.time() - self.DELETE_TTL
        if force or len(self._del) > self.max_entries * 0.9:
            for k, v in list(self._del.items()):
                if v[2] < cutoff:
                    self._del.pop(k, None)

    def lookup_delete(self, path: str) -> dict:
        """按路径查「刚刚这次删除是谁干的」；命中返回完整归因，未命中返回 {}。"""
        key = _norm(path)
        with self._lock:
            self._gc_delete_locked()
            hit = self._del.get(key)
        if not hit or time.time() - hit[2] > self.DELETE_TTL:
            return {}
        return {"user": hit[0], "ip": hit[1], "client": hit[3],
                "attribution": "delete_event", "ip_source": hit[4]}

    def remember(self, path: str, user: str, ip: str, ts: float = None,
                 share: str = "", client: str = "") -> None:
        ts = ts or time.time()
        user = user or ""
        ip = ip or ""
        client = client or ""
        if not user and not ip:
            return
        with self._lock:
            if path:
                self._path[_norm(path)] = (user, ip, ts, client)
            if user:
                self._user[user.lower()] = (ip, ts, client)
            if share:
                self._share[str(share).lower()] = (user, ip, ts, client)
            self._last = (user, ip, ts, client)
            if len(self._path) > self.max_entries:
                self._gc_locked(force=True)

    def _gc_locked(self, force: bool = False) -> None:
        cutoff = time.time() - self.ttl
        if force or len(self._path) > self.max_entries * 0.9:
            for k, v in list(self._path.items()):
                if v[2] < cutoff:
                    self._path.pop(k, None)

    @staticmethod
    def _pack(hit, attribution: str, ip_source: str = "") -> dict:
        return {"user": hit[0], "ip": hit[1], "client": hit[3] if len(hit) > 3 else "",
                "attribution": attribution, "ip_source": ip_source}

    def lookup(self, path: str, user: str = "") -> dict:
        """返回 {'user','ip','client','attribution','ip_source'}。

        匹配顺序：同一次删除的审计事件 → 精确路径 → 上级目录 → 该账号最近的 IP
        → 全局最近一次访问。
        """
        # 0) 同一次删除的审计事件（4663/5145）—— 最准，直接采信
        got = self.lookup_delete(path)
        if got and (got["user"] or got["ip"]):
            return got
        now = time.time()
        key = _norm(path)
        with self._lock:
            self._gc_locked()
            hit = self._path.get(key)
            if hit and now - hit[2] <= self.ttl and (hit[1] or not user):
                return self._pack(hit, "exact", "path_cache")
            # 逐级往上找目录上的最近访问者
            cur = os.path.dirname(key)
            for _ in range(6):
                if not cur or cur == os.path.dirname(cur):
                    break
                hit = self._path.get(cur)
                if hit and now - hit[2] <= self.ttl and hit[1]:
                    return self._pack(hit, "parent_dir", "path_cache")
                cur = os.path.dirname(cur)
            if user:
                uhit = self._user.get(user.lower())
                if uhit and now - uhit[1] <= self.ttl and uhit[0]:
                    out = self._pack((user, uhit[0], uhit[1], uhit[2]), "user", "user_cache")
                    return out
            if self._last[2] and now - self._last[2] <= self.ttl and self._last[1]:
                return self._pack(self._last, "recent", "recent_cache")
        return {"user": "", "ip": "", "client": "", "attribution": "unknown",
                "ip_source": ""}

    def lookup_user(self, user: str) -> dict:
        """只按账号查最近一次的客户端 IP。"""
        if not user:
            return {}
        now = time.time()
        with self._lock:
            hit = self._user.get(user.lower())
            if hit and now - hit[1] <= self.ttl:
                return self._pack((user, hit[0], hit[1], hit[2]), "user", "user_cache")
        return {}


class SessionResolver:
    """按账号反查客户端 IP：读取服务器当前的 SMB 会话表（NetSessionEnum）。

    5145 事件自带客户端 IP，但只在「详细的文件共享」审计开启且命中共享访问时才有；
    4663 / 文件系统事件拿不到 IP 时，用会话表兜底（结果带 TTL 缓存，避免频繁 RPC）。
    """

    def __init__(self, ttl_seconds: int = 30):
        self.ttl = max(5, int(ttl_seconds))
        self._lock = threading.RLock()
        self._by_user = {}        # user.lower -> {"ip","client"}
        self._ips = []
        self._at = 0.0
        self.state = {"available": HAS_WIN32NET, "reason": WIN32NET_ERROR,
                      "sessions": 0, "lookups": 0, "hits": 0, "last_error": "",
                      "refreshed_at": ""}

    # ---- 数据源 ----
    @staticmethod
    def _rows_from_win32net() -> list:
        """返回 [{'ip':..., 'user':..., 'client':...}]；pywin32 各版本参数顺序不同，逐一尝试。"""
        if not HAS_WIN32NET:
            return []
        last = None
        for args in ((10, None), (None, 10)):
            try:
                rows = win32net.NetSessionEnum(*args)
            except Exception as e:                    # pragma: no cover
                last = e
                continue
            out = []
            for r in rows or []:
                item = {}
                for k, v in dict(r).items():
                    lk = str(k).lower()
                    if "cname" in lk:
                        item["cname"] = v
                    elif "username" in lk:
                        item["user"] = v
                if item:
                    out.append(item)
            return out
        if last is not None:
            raise last
        return []

    @staticmethod
    def _rows_from_net_session() -> list:
        """兜底：解析 `net session`（列名随系统语言变化，这里只认「首列是 IP」的行）。"""
        try:
            r = subprocess.run(["net", "session"], capture_output=True, timeout=10,
                               creationflags=_CREATE_NO_WINDOW)
        except Exception:
            return []
        text = (r.stdout or b"").decode("gbk", "replace")
        out = []
        for line in text.splitlines():
            parts = line.replace("\t", " ").split()
            if len(parts) >= 2 and _IPV4_RE.match(parts[0]):
                out.append({"cname": parts[0], "user": parts[1]})
        return out

    def refresh(self, force: bool = False) -> dict:
        now = time.time()
        with self._lock:
            if not force and self._at and now - self._at < self.ttl:
                return dict(self._by_user)
        rows, err = [], ""
        try:
            rows = self._rows_from_win32net()
        except Exception as e:
            err = f"NetSessionEnum 失败：{e}"
            rows = []
        if not rows:
            rows = self._rows_from_net_session()
        by_user, ips = {}, []
        for r in rows:
            ip = str(r.get("ip") or r.get("cname") or "").strip()
            user = str(r.get("user") or "").strip()
            client = str(r.get("cname") or "").strip()
            if ip and _IPV4_RE.match(ip) and ip not in ips:
                ips.append(ip)
            if user and ip:
                by_user.setdefault(user.lower(), {"ip": ip, "client": client})
        with self._lock:
            self._by_user, self._ips, self._at = by_user, ips, now
            self.state["sessions"] = len(rows)
            self.state["last_error"] = err if not rows else ""
            self.state["refreshed_at"] = now_iso()
        return dict(by_user)

    # ---- 查询 ----
    def ips(self) -> list:
        self.refresh()
        with self._lock:
            return list(self._ips)

    def lookup(self, user: str, allow_sole: bool = False) -> dict:
        """返回 {'ip','client','ip_source'}；查不到返回空 dict。"""
        with self._lock:
            self.state["lookups"] += 1
        by_user = self.refresh()
        u = (user or "").lower()
        if u:
            for key, val in by_user.items():
                if key == u or _same_user(key, u):
                    with self._lock:
                        self.state["hits"] += 1
                    return {"ip": val["ip"], "client": val.get("client", ""),
                            "ip_source": "session"}
        if allow_sole:
            ips = self.ips()
            if len(ips) == 1:
                with self._lock:
                    self.state["hits"] += 1
                return {"ip": ips[0], "client": "", "ip_source": "session_sole"}
        return {}

    def snapshot(self) -> dict:
        s = dict(self.state)
        s["known_users"] = len(self._by_user)
        s["ips"] = self.ips()
        return s


class AuditCollector:
    def __init__(self, cfg, logs, on_log=None, on_event=None):
        self.cfg = cfg
        self.logs = logs
        self.on_log = on_log or (lambda *a, **k: None)
        self.on_event = on_event or (lambda *a, **k: None)
        self.actors = ActorCache(
            ttl_seconds=int(cfg.get("audit.ip_cache_minutes", 30)) * 60)
        self.sessions = SessionResolver(
            ttl_seconds=int(cfg.get("audit.session_cache_seconds", 30)))
        if not cfg.get("audit.session_lookup", True):
            self.sessions.state["available"] = False
            self.sessions.state["reason"] = "已在配置中关闭（audit.session_lookup = false）"
        self._stop = threading.Event()
        self._thread = None
        self._drive_map = {}
        self._self_names = set()
        self._self_pid = 0
        # 读取记录相关
        self._dedup_ttl = max(0, int(cfg.get("audit.dedup_seconds", 2) or 0))
        self._dedup = {}              # (路径, 账号, IP, 操作) -> 最近一次写入时间
        self._lock_dedup = threading.RLock()
        self._dir_names = {}          # normcase(目录) -> (读取时间, {小写名: 真实名})
        self._skip_loopback = bool(cfg.get("audit.skip_loopback", False))
        rex = cfg.get("audit.read_extensions") or []
        self._read_exts = {str(e).lower() if str(e).startswith(".")
                           else "." + str(e).lower() for e in rex if str(e).strip()}
        self._last_seen = {}          # event_id -> 最近一次处理时间（UTC 字符串）
        self._seen_ids = {}           # event_id -> set(record_id)
        self._lock_poll = threading.Lock()
        self._last_catch_up = 0.0     # 即时补采的限流时间戳
        self._actor_hook = None       # fn(path)：刚拿到某路径归因时的回调（写「创建」日志用）
        self.state = {
            "available": HAS_PYWIN32,
            "reason": PYWIN32_ERROR,
            "admin": is_admin(),
            "configured": False,
            "configure_msg": "",
            "running": False,
            "collected": 0,
            "last_error": "",
            "last_poll": "",
        }
        self._build_self_names()
        self._build_drive_map()

    # ---------------- 环境探测 ----------------
    def _build_self_names(self) -> None:
        """只收集「本程序自己」的进程标识，用于过滤自身回填/还原产生的噪声事件。

        ⚠️ 不要把 system / smss.exe 这类系统进程当噪声过滤掉：
        网络删除的 4663 是内核 SMB 服务产生的（``ProcessId=0x4``、``ProcessName`` 常为空），
        早期版本按进程名过滤，结果把网络删除整条丢掉。
        """
        import sys
        names = {"fileguard.exe"}
        if getattr(sys, "frozen", False):
            for p in (sys.executable, sys.argv[0] if sys.argv else ""):
                if p:
                    names.add(os.path.basename(p).lower())
        self._self_names = names
        self._self_pid = os.getpid()

    def _build_drive_map(self) -> None:
        if not HAS_PYWIN32:
            return
        m = {}
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            try:
                targets = win32file.QueryDosDevice(letter + ":")
            except Exception:
                continue
            for t in (targets or []):
                m[str(t).rstrip("\\").lstrip("\\").lower()] = letter + ":"
        self._drive_map = m

    def normalize_path(self, raw: str) -> str:
        """把 \\Device\\HarddiskVolume3\\Share\\a.txt 还原成 D:\\Share\\a.txt。"""
        if not raw:
            return ""
        p = raw.strip()
        if p.startswith("\\\\Device\\\\") or p.startswith("\\Device\\"):
            body = p.lstrip("\\")
            parts = body.split("\\")
            device = "\\".join(parts[:2])            # Device\HarddiskVolume3
            rest = parts[2:]
            # Mup / LanmanRedirector 等网络路径原样返回
            if "harddiskvolume" in device.lower() and device.lower() in self._drive_map:
                return os.path.normpath(self._drive_map[device.lower()] + "\\" + "\\".join(rest))
            return p
        return os.path.normpath(p)

    def preflight(self) -> dict:
        issues = []
        if not HAS_PYWIN32:
            issues.append(f"缺少 pywin32 组件（{PYWIN32_ERROR}），无法采集共享访问审计")
        if not is_admin():
            issues.append("当前进程不是管理员权限，无法配置 SACL / 读取安全日志"
                          "（请右键以管理员身份运行，或使用打包好的 FileGuard.exe）")
        if not os.path.isfile(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                           "System32", "auditpol.exe")):
            issues.append("系统中未找到 auditpol.exe，无法开启审计策略")
        self.state["preflight_issues"] = issues
        if not HAS_WIN32NET:
            self.on_log(f"[审计] 会话表组件不可用（{WIN32NET_ERROR}），"
                        f"删除记录的客户端 IP 将只依赖 5145 事件", "warn")
        return {"ok": not issues, "issues": issues}

    # ---------------- 策略配置 ----------------
    def configure(self) -> dict:
        """开启审计子类别 + 给监控目录写入 SACL。幂等，可重复调用。"""
        pf = self.preflight()
        if not pf["ok"]:
            self.state["configure_msg"] = "；".join(pf["issues"])
            return {"ok": False, "message": self.state["configure_msg"],
                    "issues": pf["issues"]}

        msgs, failures = [], []
        for scope in (self.cfg.get("audit.scopes") or []):
            guid = SUBCATEGORY.get(scope)
            if not guid:
                continue
            label = SUBCATEGORY_NAME.get(scope, scope)
            ok, out = self._auditpol_enable(guid)
            msgs.append(f"{label} {'已开启' if ok else '开启失败：' + out}")
            if not ok:
                failures.append(f"{label}：{out}")
                self.on_log(f"[审计] 开启 {label} 审计失败：{out}", "warn")

        sacl_ok, sacl_msg = self._apply_sacl()
        msgs.append(sacl_msg)
        if not sacl_ok:
            failures.append(sacl_msg)
        self.state["configured"] = bool(sacl_ok) and not failures
        self.state["configure_msg"] = " | ".join(msgs)
        self.on_log(f"[审计] 策略配置{'完成' if not failures else '存在失败'}："
                    f"{self.state['configure_msg']}",
                    "info" if not failures else "warn")
        return {"ok": not failures, "message": self.state["configure_msg"],
                "failures": failures}

    @staticmethod
    def _auditpol(args) -> tuple:
        try:
            r = subprocess.run(["auditpol"] + list(args), capture_output=True,
                               creationflags=_CREATE_NO_WINDOW, timeout=20)
        except Exception as e:
            return False, str(e)
        out = (r.stdout or b"").decode("gbk", "replace")
        err = (r.stderr or b"").decode("gbk", "replace")
        return (r.returncode == 0), ((out + err).strip() or f"exit={r.returncode}")

    def _auditpol_enable(self, guid: str) -> tuple:
        """启用子类别成功审计。注意：GUID 必须写成 /subcategory:{GUID}（冒号紧贴）。"""
        ok, out = self._auditpol(["/set", f"/subcategory:{guid}", "/success:enable"])
        if not ok:
            return False, out.splitlines()[-1][:120] if out else "未知错误"
        # 回读确认真正生效
        vok, vout = self._auditpol(["/get", f"/subcategory:{guid}", "/r"])
        if vok:
            cols = [c.strip() for c in vout.splitlines()[-1].split(",")]
            setting = cols[4] if len(cols) > 4 else ""
            if "成功" in setting:
                return True, setting
            return False, f"回读设置为「{setting}」，未生效"
        return True, "已下发（未能回读确认）"

    def _privileges(self) -> bool:
        try:
            h_token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
            luid = win32security.LookupPrivilegeValue(None, win32security.SE_SECURITY_NAME)
            win32security.AdjustTokenPrivileges(
                h_token, False, [(luid, win32security.SE_PRIVILEGE_ENABLED)])
            return True
        except Exception as e:
            self.on_log(f"[审计] 启用 SeSecurityPrivilege 失败：{e}", "warn")
            return False

    def _mask_value(self) -> int:
        mask = 0
        names = list(self.cfg.get("audit.object_mask") or ["DELETE"])
        if self._read_exts:
            # audit.read_extensions 已配置：SACL 必须带上「读取数据」，
            # 4663 才会为读取产生事件（本机打开、缓存命中这类 5145 抓不到的读取靠它）
            if "FILE_READ_DATA" not in names:
                names.append("FILE_READ_DATA")
        for name in names:
            const = getattr(ntsecuritycon, str(name).upper(), None)
            if const:
                mask |= const
        return mask or ntsecuritycon.DELETE

    def _apply_sacl(self) -> tuple:
        if not self._privileges():
            return False, "SACL 写入失败：无法启用代管审核特权"
        principal = self.cfg.get("audit.principal", "Everyone") or "Everyone"
        try:
            sid, _domain, _type = win32security.LookupAccountName(None, principal)
        except Exception as e:
            return False, f"SACL 写入失败：找不到主体 {principal}（{e}）"
        mask = self._mask_value()
        # 注意：SACL 必须用 AddAuditAccessAceEx；AddAccessAllowedAceEx 会因
        #       SUCCESSFUL_ACCESS_ACE_FLAG 报 1004「无效标志」
        ace_flags = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
        done, skipped, failed = [], [], []
        for root in self.cfg.monitor_paths():
            if not os.path.isdir(root):
                continue
            try:
                sd = win32security.GetFileSecurity(root, win32security.SACL_SECURITY_INFORMATION)
                sacl = sd.GetSecurityDescriptorSacl()
                if sacl is None:
                    sacl = win32security.ACL()
                exists = False
                for i in range(sacl.GetAceCount()):
                    _hdr, ace_mask, ace_sid = sacl.GetAce(i)
                    if ace_sid == sid and (ace_mask & mask) == mask:
                        exists = True
                        break
                if exists:
                    skipped.append(root)
                    continue
                sacl.AddAuditAccessAceEx(win32security.ACL_REVISION, ace_flags, mask,
                                         sid, True, False)
                sd.SetSecurityDescriptorSacl(True, sacl, False)
                win32security.SetFileSecurity(
                    root, win32security.SACL_SECURITY_INFORMATION, sd)
                done.append(root)
            except Exception as e:
                failed.append(f"{root}: {e}")
        parts = []
        if done:
            parts.append(f"已写入 SACL：{', '.join(done)}（审计掩码 0x{mask:X}，子对象自动继承）")
        if skipped:
            parts.append(f"已存在审计项，跳过：{', '.join(skipped)}")
        if failed:
            parts.append("失败：" + "；".join(failed))
        if not parts:
            parts.append("没有可写入 SACL 的监控目录")
        for f in failed:
            self.on_log(f"[审计] SACL {f}", "error")
        return (not failed), " ".join(parts)

    # ---------------- 采集 ----------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="fg-audit")
        self._thread.start()
        self.state["running"] = True
        self.on_event("audit", "started")

    def stop(self) -> None:
        self._stop.set()
        t, self._thread = self._thread, None
        if t is not None:
            t.join(timeout=5)
        self.state["running"] = False

    def _loop(self) -> None:
        interval = max(1, int(self.cfg.get("audit.poll_interval_seconds", 2)))
        while not self._stop.is_set():
            try:
                self._poll_once()
                self.state["last_error"] = ""
            except Exception as e:
                self.state["last_error"] = str(e)
                if not hasattr(self, "_err_logged") or self._err_logged != str(e):
                    self._err_logged = str(e)
                    self.on_log(f"[审计] 采集异常：{e}", "warn")
            self._stop.wait(interval)

    def _xpath(self) -> str:
        ids = []
        for scope in (self.cfg.get("audit.scopes") or []):
            if scope in EVENT_ID:
                ids.append(EVENT_ID[scope])
        if not ids:
            return ""
        cond = " or ".join(f"EventID={i}" for i in ids)
        overlap = int(self.cfg.get("audit.overlap_seconds", 15)) + \
            max(1, int(self.cfg.get("audit.poll_interval_seconds", 2))) * 2
        since = datetime.fromtimestamp(time.time() - overlap, tz=timezone.utc)
        stamp = since.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return f"*[System[({cond}) and TimeCreated[@SystemTime>='{stamp}']]]"

    def _poll_once(self) -> None:
        if not HAS_PYWIN32:
            return
        xpath = self._xpath()
        if not xpath:
            return
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        try:
            handle = win32evtlog.EvtQuery("Security", flags, xpath)
        except Exception as e:
            self.state["last_error"] = f"打开安全日志失败：{e}"
            return
        batch = max(10, int(self.cfg.get("audit.batch_size", 500)))
        batch_size = 50
        got = 0
        try:
            while got < batch and not self._stop.is_set():
                try:
                    events = win32evtlog.EvtNext(handle, batch_size, -1, 0)
                except Exception:
                    break
                if not events:
                    break
                for ev in events:
                    try:
                        xml = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                    except Exception:
                        continue
                    self._handle_xml(xml)
                    got += 1
        finally:
            _evt_close(handle)
        self.state["last_poll"] = now_iso()

    # ---------------- 解析 ----------------
    def _handle_xml(self, xml: str) -> None:
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return
        sys_el = root.find("e:System", NS)
        if sys_el is None:
            return
        eid_el = sys_el.find("e:EventID", NS)
        if eid_el is None or not (eid_el.text or "").strip().isdigit():
            return
        eid = int(eid_el.text.strip())
        rid_el = sys_el.find("e:EventRecordID", NS)
        rid = (rid_el.text or "").strip() if rid_el is not None else ""
        if rid:
            seen = self._seen_ids.setdefault(eid, set())
            if rid in seen:
                return
            seen.add(rid)
            if len(seen) > 5000:
                self._seen_ids[eid] = set(list(seen)[-2000:])
        tc = sys_el.find("e:TimeCreated", NS)
        ts_raw = (tc.get("SystemTime") if tc is not None else "") or ""
        data = {}
        for d in root.findall("e:EventData/e:Data", NS):
            data[d.get("Name") or ""] = (d.text or "").strip()

        if eid == 5145:
            self._handle_5145(data, ts_raw)
        elif eid == 4663:
            self._handle_4663(data, ts_raw)

    @staticmethod
    def _local_ts(ts_raw: str) -> str:
        try:
            dt = datetime.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc)
            return dt.astimezone().isoformat(timespec="seconds")
        except Exception:
            return now_iso()

    @staticmethod
    def _op_from_access_list(access_list: str, fallback: str = "打开") -> str:
        s = (access_list or "").lower()
        if "delete" in s or "%%1537" in s or "%%4422" in s:
            return "删除"
        if any(k in s for k in ("writedata", "appenddata", "writeattributes",
                               "writeextendedattributes", "writeea", "writedac",
                               "writeowner", "%%4417", "%%4418", "%%4420",
                               "%%4424", "%%4425", "%%1539", "%%1540")):
            return "写入"
        if any(k in s for k in ("readdata", "readattributes", "readextendedattributes",
                                "%%4416", "%%4423", "%%4419")):
            return "读取"
        return fallback

    @classmethod
    def _op_from_mask(cls, mask_raw: str, access_list: str, fallback: str = "访问") -> str:
        """优先按 AccessMask 数值判定（本地化系统上 AccessList 常是 %%资源号）。"""
        try:
            mask = int(str(mask_raw).strip(), 16) if str(mask_raw).strip().lower() \
                .startswith("0x") else int(str(mask_raw).strip())
        except (TypeError, ValueError):
            mask = 0
        if mask & _MASK_DELETE:
            return "删除"
        if mask & _MASK_WRITE:
            return "写入"
        if mask & _MASK_READ:
            return "读取"
        if mask:
            return fallback
        return cls._op_from_access_list(access_list, fallback)

    @staticmethod
    def _expand_access(access_list: str) -> str:
        s = (access_list or "").replace("\t", " ").strip()
        for res, name in ACCESS_RES_NAMES.items():
            s = s.replace(res, name)
        return "; ".join(x.strip() for x in s.replace("\r", "\n").split("\n") if x.strip())

    @staticmethod
    def _strip_local_prefix(p: str) -> str:
        """去掉 5145 事件里 ShareLocalPath 的 \\??\\ / \\\\?\\ 前缀。"""
        p = (p or "").strip()
        for pre in ("\\??\\", "\\\\?\\", "\\\\.\\"):
            if p.startswith(pre):
                return p[len(pre):]
        return p

    def _in_scope(self, path: str) -> bool:
        if not path:
            return False
        p = _norm(path)
        for root in self.cfg.monitor_paths():
            if p == _norm(root) or p.startswith(_norm(root) + os.sep):
                return True
        return False

    # ---------------- 读取记录的两件小事 ----------------
    def _canon(self, path: str) -> str:
        """把路径的大小写还原成磁盘上的真实名字。

        SMB 客户端在解析文件名时会先按原样、再按大写探测一次，于是同一次读取会
        产生「A.TXT」和「a.txt」两条 5145；日志里出现一个并不存在的路径显然不对。
        目录名清单带 5 秒缓存，避免频繁列目录。
        """
        if not path:
            return path
        d, base = os.path.dirname(path), os.path.basename(path)
        if not d or not base:
            return path
        key = _norm(d)
        now = time.time()
        hit = self._dir_names.get(key)
        if hit is None or now - hit[0] > 5.0:
            try:
                names = {n.lower(): n for n in os.listdir(d)}
            except OSError:
                names = {}
            if len(self._dir_names) > 512:
                self._dir_names.clear()
            self._dir_names[key] = (now, names)
            hit = self._dir_names[key]
        real = hit[1].get(base.lower())
        return os.path.join(d, real) if real else path

    @staticmethod
    def _ts_epoch(ts_raw: str) -> float:
        """事件时间（UTC ISO）-> epoch 秒；解析失败用当前时间。"""
        try:
            dt = datetime.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return time.time()

    def _dedup_ok(self, op: str, path: str, user: str, source: str,
                  ev_ts: float = None) -> bool:
        """同一次访问会被多条事件重复上报（5145 的大小写探测/属性查询、4663 复核）。

        在 ``audit.dedup_seconds`` 窗口内，同「路径 + 操作 + 账号」只留一条：
        5145（自带客户端 IP）优先级高于 4663，因此后到的 5145 可以顶掉先到的 4663。
        删除类操作不做去重（每条都要留证）。

        ⚠️ 必须用**事件自身的时间**比较：一轮询会一次性取回好几秒的事件，
        若按处理时刻算，几秒内真正发生的多次访问会被错误地合并成一条。
        """
        if self._dedup_ttl <= 0 or op == "删除":
            return True
        key = (_norm(path), op, (user or "").lower())
        now = ev_ts if ev_ts else time.time()
        share = source == "share_audit"
        with self._lock_dedup:
            last = self._dedup.get(key)
            if last is not None and now - last[0] < self._dedup_ttl \
                    and not (share and last[1] != "share_audit"):
                return False
            self._dedup[key] = (now, source)
            if len(self._dedup) > 50000:
                cutoff = now - self._dedup_ttl
                self._dedup = {k: v for k, v in self._dedup.items()
                               if v[0] >= cutoff}
                if len(self._dedup) > 50000:
                    self._dedup.clear()
        return True

    def _read_ext_ok(self, path: str) -> bool:
        """4663 读取记录的扩展名白名单（read_extensions 为空表示不启用 4663 读取审计）。"""
        if not self._read_exts:
            return False
        return os.path.splitext(path)[1].lower() in self._read_exts

    def actor_info(self, path: str, user: str = "", fresh: bool = False) -> dict:
        """给「谁删的」做归因：删除事件表 → 路径缓存 → 账号缓存 → SMB 会话表。

        :param fresh: 缓存里查不到时，立刻补采一次安全事件再查一遍。
                      文件系统事件（watchdog）总是比安全事件（轮询）先到，
                      不补这一次的话，一个路径上**第一条**记录（通常是「创建」）
                      会因为缓存还冷而丢掉操作者 —— 后续的修改/删除才有名字。
        :returns: {'user','ip','client','attribution','ip_source'}
        """
        out = self._resolve_actor(path, user)
        if fresh and not (out.get("user") or out.get("ip")):
            if self.catch_up():
                out = self._resolve_actor(path, user)
        return out

    def set_actor_hook(self, fn) -> None:
        """注入「刚拿到某路径归因」的回调 fn(path)。

        用途：文件系统事件（创建）比安全事件早，Protector 会把「创建」日志挂着等归因。
        这里在**归因刚写入缓存的那一刻**就通知它落盘，保证「创建」行排在
        同一次访问产生的「读取/写入」行之前，日志顺序不会倒挂。
        """
        self._actor_hook = fn

    def _notify_actor(self, path: str) -> None:
        if not self._actor_hook or not path:
            return
        try:
            self._actor_hook(path)
        except Exception:                            # 回调异常不能影响采集
            pass

    def catch_up(self, min_interval: float = 0.8) -> bool:
        """立刻补采一次安全事件（限流），返回是否真的执行了采集。"""
        if not HAS_PYWIN32 or self._stop.is_set():
            return False
        now = time.time()
        with self._lock_poll:
            if now - self._last_catch_up < min_interval:
                return False
            self._last_catch_up = now
        try:
            self._poll_once()
        except Exception as e:                       # 采集失败不能影响写日志
            self.state["last_error"] = f"即时补采失败：{e}"
            return False
        return True

    def _resolve_actor(self, path: str, user: str = "") -> dict:
        info = self.actors.lookup(path, user=user)
        out = {"user": info.get("user", "") or user or "",
               "ip": info.get("ip", "") or "",
               "client": info.get("client", "") or "",
               "attribution": info.get("attribution", "unknown"),
               "ip_source": info.get("ip_source", "")}
        if out["ip"]:
            return out
        # 事件里没带 IP：退一步按账号查会话表（不做「只有一个会话就归给它」的猜测，避免误判）
        if self.sessions.state.get("available", True):
            got = self.sessions.lookup(out["user"])
            if got.get("ip"):
                out["ip"] = got["ip"]
                out["client"] = out["client"] or got.get("client", "")
                out["ip_source"] = got.get("ip_source", "session")
                if out["attribution"] == "unknown":
                    out["attribution"] = "user"
        return out

    def _skip_process(self, proc: str, pid_raw: str = "") -> bool:
        """是否属于「本程序自己」产生的文件系统事件（自身回填 / 还原，要过滤）。

        只按「进程 ID == 本进程」或「可执行名 == 本程序名」判定；
        进程名为空或 ProcessId=4（内核 SMB 服务）一律**不过滤**。
        """
        raw = str(pid_raw or "").strip()
        try:
            pid = int(raw, 16) if raw.lower().startswith("0x") else int(raw or 0)
        except (TypeError, ValueError):
            pid = 0
        if pid and pid == getattr(self, "_self_pid", 0):
            return True
        return (os.path.basename(proc or "") or "").lower() in self._self_names

    def _handle_5145(self, d: dict, ts_raw: str) -> None:
        user = d.get("SubjectUserName", "")
        if user.endswith("$") and user.upper() not in ("ANONYMOUS LOGON",):
            return                                     # 机器账号噪声
        src_ip = (d.get("IpAddress", "") or "").replace("::ffff:", "").strip()
        if src_ip in ("", "-"):
            return
        loopback = src_ip in ("127.0.0.1", "::1")
        if loopback and self._skip_loopback:
            return
        share_local = self._strip_local_prefix(d.get("ShareLocalPath", ""))
        relative = (d.get("RelativeTargetName", "") or "").lstrip("\\/")
        if not share_local:
            return
        path = os.path.normpath(os.path.join(share_local.rstrip("\\"), relative)) \
            if relative else os.path.normpath(share_local)
        if not self._in_scope(path):
            return
        path = self._canon(path)
        access_list = self._expand_access(d.get("AccessList", ""))
        op = self._op_from_mask(d.get("AccessMask", ""), access_list)
        if not self._dedup_ok(op, path, user, "share_audit",
                              self._ts_epoch(ts_raw)):
            return                                     # 同一次访问的重复上报
        domain = d.get("SubjectDomainName", "")
        account = f"{domain}\\{user}" if domain and not user.startswith(domain) else user
        share = d.get("ShareName", "")

        if not loopback:
            # 回环访问不进「谁删的」缓存：127.0.0.1 当成客户端 IP 会误导归因
            self.actors.remember(path, account, src_ip, share=share)
            parent = os.path.dirname(path)
            if parent:
                self.actors.remember(parent, account, src_ip, share=share)
            if op == "删除":
                # 这一次删除是这位客户端干的 —— 记进「删除事件表」，
                # 让 Protector 的 fs_event 删除记录也能拿到客户端 IP。
                self.actors.remember_delete(path, account, src_ip,
                                            ip_source="share_audit")
                if parent:
                    self.actors.remember_delete(parent, account, src_ip,
                                                ip_source="share_audit")
            # 归因刚就绪：让挂起的「创建」记录立刻落盘（保证排在下面的读取/写入之前）
            self._notify_actor(path)

        self.logs.log_access(
            op=op, path=path, name=os.path.basename(path), user=account, ip=src_ip,
            share=share, source="share_audit", event_id=5145,
            ip_source="share_audit_loopback" if loopback else "share_audit",
            time_local=self._local_ts(ts_raw), access_list=access_list,
            access_mask=d.get("AccessMask", ""), port=d.get("IpPort", ""),
            detail=("本机回环访问（" + src_ip + "）" if loopback
                    else d.get("ObjectType", "")),
        )
        self.state["collected"] += 1

    def _handle_4663(self, d: dict, ts_raw: str) -> None:
        user = d.get("SubjectUserName", "")
        if user.endswith("$"):
            return
        proc = d.get("ProcessName", "")
        if self._skip_process(proc, d.get("ProcessId", "")):
            return
        raw_path = d.get("ObjectName", "")
        path = self.normalize_path(self._strip_local_prefix(raw_path))
        if not self._in_scope(path):
            return
        path = self._canon(path)
        access_list = self._expand_access(d.get("AccessList", ""))
        op = self._op_from_mask(d.get("AccessMask", ""), access_list, fallback="访问")
        if op != "删除" and self._read_exts and not self._read_ext_ok(path):
            return                                     # 只审计指定扩展名的读取
        if not self._dedup_ok(op, path, user, "object_audit",
                              self._ts_epoch(ts_raw)):
            return                                     # 与 5145 的同一次访问合并成一条
        domain = d.get("SubjectDomainName", "")
        account = f"{domain}\\{user}" if domain and not user.startswith(domain) else user
        # 4663 事件本身不带客户端 IP：走「路径缓存 → 账号缓存 → SMB 会话表」三级归因
        info = self.actor_info(path, user=account)
        ip = info.get("ip", "") or ""
        actor = account or info.get("user", "")

        if op == "删除":
            # 关键：4663 是「这一次删除」的直接证据（账号准确，IP 可为空）。
            # 回灌进删除事件表后，Protector 那条 fs_event 删除记录（Web 界面里显示的
            # 就是它）在回填期就能命中 —— 本机删除正是靠这条才显示得出操作者。
            self.actors.remember_delete(
                path, actor, ip, ip_source=(info.get("ip_source") or "object_audit"))
            self.logs.log_delete(
                op="删除", path=path, name=os.path.basename(path), user=actor, ip=ip,
                client=info.get("client", ""), ip_source=info.get("ip_source", ""),
                attribution=info.get("attribution", ""), source="object_audit",
                event_id=4663, time_local=self._local_ts(ts_raw),
                process=os.path.basename(proc), access_list=access_list,
                access_mask=d.get("AccessMask", ""), action="audit_only",
                audit_only=True,
                note="安全审计记录（回收站存档见同路径的 fs_event 记录）",
            )
        else:
            self.logs.log_access(
                op=op, path=path, name=os.path.basename(path), user=actor, ip=ip,
                client=info.get("client", ""), ip_source=info.get("ip_source", ""),
                source="object_audit", event_id=4663,
                attribution=info.get("attribution", ""),
                time_local=self._local_ts(ts_raw), process=os.path.basename(proc),
                access_list=access_list, access_mask=d.get("AccessMask", ""),
            )
        self.state["collected"] += 1

    # ---------------- 状态 ----------------
    def snapshot(self) -> dict:
        s = dict(self.state)
        s["actor_cache"] = len(self.actors._path)
        s["delete_cache"] = len(self.actors._del)
        s["dedup_cache"] = len(self._dedup)
        s["read_log"] = {
            "source": "5145 + 4663" if self._read_exts else "5145 共享审计",
            "dedup_seconds": self._dedup_ttl,
            "skip_loopback": self._skip_loopback,
            "read_extensions": sorted(self._read_exts),
        }
        try:
            s["sessions"] = self.sessions.snapshot()
        except Exception as e:                            # pragma: no cover
            s["sessions"] = {"available": False, "reason": str(e)}
        return s


def resolve_actor(collector, path: str) -> dict:
    """给 Protector 用的回调：返回 {'user','ip','client','attribution','ip_source'}。"""
    if collector is None:
        return {"user": "", "ip": "", "client": "", "attribution": "unknown",
                "ip_source": ""}
    return collector.actor_info(path)
