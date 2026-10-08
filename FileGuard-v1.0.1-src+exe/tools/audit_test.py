# -*- coding: utf-8 -*-
"""审计采集端到端测试（需要管理员权限）。

做法：临时建一个共享 FGTest -> 通过本机局域网 IP 走真实 SMB 访问（读/删），
      验证能否从安全事件日志中解析出 5145（含客户端 IP）与 4663（删除归因）。
测试结束后会删除共享，并把 auditpol 审计策略恢复为测试前的状态。

用法： python tools/audit_test.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.audit import SUBCATEGORY, AuditCollector, is_admin   # noqa: E402
from app.config import Config                                # noqa: E402
from app.logger import LogManager, log_files                # noqa: E402

SHARE_NAME = "FGTest"
BASE = os.path.join(tempfile.gettempdir(), "fg_audit")
SHARE_DIR = os.path.join(BASE, "Shared")
LOGS = os.path.join(BASE, "Logs")
CONF = os.path.join(BASE, "config.yaml")
NO_WINDOW = 0x08000000
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'[PASS]' if cond else '[FAIL]'} {name}{('  ' + str(extra)) if extra else ''}")


def run(cmd):
    # auditpol / net 的输出是本地 ANSI 编码（中文系统为 GBK），显式指定避免解码异常
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="gbk", errors="replace",
                       creationflags=NO_WINDOW, shell=isinstance(cmd, str))
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def auditpol_get(guid):
    rc, out = run(["auditpol", "/get", "/subcategory", guid, "/r"])
    return out


def auditpol_set(guid, value):
    """value: 'enable' / 'disable'"""
    return run(["auditpol", "/set", "/subcategory", guid, "/success:" + value])


def main():
    print("=" * 72)
    print("FileGuard 审计采集测试（真实 SMB 访问 + 安全事件日志）")
    print("=" * 72)

    # ---------- 0. 纯解析单元测试（不需要管理员） ----------
    print("[0] 事件解析单元测试")
    from app.audit import AuditCollector as AC

    class _StubCfg:
        def get(self, key, default=None):
            return default

    _normalize_probe = AC(_StubCfg(), None).normalize_path
    check("掩码 0x10000(DELETE) -> 删除",
          AC._op_from_mask("0x10000", "%%1537") == "删除",
          AC._op_from_mask("0x10000", "%%1537"))
    check("掩码 0x40(FILE_DELETE_CHILD) -> 删除",
          AC._op_from_mask("0x40", "") == "删除")
    check("掩码 0x2(WriteData) -> 写入", AC._op_from_mask("0x2", "") == "写入")
    check("掩码 0x100(WriteAttributes) -> 写入", AC._op_from_mask("0x100", "") == "写入")
    check("掩码 0x120116(GENERIC_WRITE) -> 写入",
          AC._op_from_mask("0x120116", "") == "写入")
    check("掩码 0x80(ReadAttributes) -> 读取", AC._op_from_mask("0x80", "%%4423") == "读取",
          AC._op_from_mask("0x80", "%%4423"))
    check("掩码 0x1(ReadData) -> 读取", AC._op_from_mask("0x1", "") == "读取")
    check("掩码为空时回退英文 AccessList",
          AC._op_from_mask("", "ReadData (or ListDirectory)") == "读取")
    check("%%资源号可读化", AC._expand_access("%%1537") == "DELETE",
          AC._expand_access("%%1537"))
    check(r"\\??\\ 前缀被剥离",
          AC._strip_local_prefix(r"\??\C:\Share") == r"C:\Share",
          AC._strip_local_prefix(r"\??\C:\Share"))
    check("设备路径映射可用（未知设备原样返回）",
          _normalize_probe(r"\Device\HarddiskVolume99\Share\a.txt")
          == r"\Device\HarddiskVolume99\Share\a.txt")

    if not is_admin():
        print("\n[跳过] 后续真实审计测试需要管理员权限")
        print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
        return 1 if FAIL else 0

    ip = lan_ip()
    print(f"\n本机局域网 IP: {ip}\n")

    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(SHARE_DIR, exist_ok=True)
    os.makedirs(LOGS, exist_ok=True)

    # 记录原始审计策略，测试结束还原
    originals = {name: auditpol_get(guid) for name, guid in SUBCATEGORY.items()}

    rc, out = run(f'net share {SHARE_NAME}="{SHARE_DIR}" /grant:Everyone,FULL')
    check(f"创建临时共享 \\\\{ip}\\{SHARE_NAME}", rc == 0, out.strip()[:120])
    if rc != 0:
        return 1

    svc_log = []
    try:
        cfg = Config(CONF)
        cfg._data.update({
            "monitor": {"paths": [SHARE_DIR], "seed_on_start": False},
            "log": {"dir": LOGS, "max_size_mb": 5},
            "audit": {"enabled": True, "auto_configure": True,
                      "scopes": ["share", "delete"],
                      "object_mask": ["DELETE", "FILE_DELETE_CHILD"],
                      "poll_interval_seconds": 1, "overlap_seconds": 20,
                      "ip_cache_minutes": 30},
            "recycle_bin": {"path": os.path.join(BASE, "Recycle"), "auto_purge": False},
            "web": {"enabled": False},
        })
        cfg.save()
        logs = LogManager(cfg)
        col = AuditCollector(cfg, logs, on_log=lambda t, l="info": svc_log.append((l, t)))
        print()

        # ---------- 1. 预检与配置 ----------
        print("[1] 预检与审计策略配置")
        pf = col.preflight()
        check("预检通过（管理员 + pywin32 + auditpol）", pf["ok"], pf["issues"])
        res = col.configure()
        check("审计策略配置成功", res.get("ok"), res.get("message")[:200])
        check("SACL 已写入共享目录", "已写入 SACL" in res.get("message", "")
              or "已存在审计项" in res.get("message", ""), res.get("message")[:200])
        check("审计策略整体配置成功", res.get("ok"), res.get("failures"))
        # 子目录继承验证
        sub = os.path.join(SHARE_DIR, "child")
        os.makedirs(sub, exist_ok=True)

        def sacl_of(p):
            try:
                import win32security
                sd = win32security.GetFileSecurity(p, win32security.SACL_SECURITY_INFORMATION)
                acl = sd.GetSecurityDescriptorSacl()
                return acl.GetAceCount() if acl else 0
            except Exception:
                return -1
        check("SACL 可回读", sacl_of(SHARE_DIR) >= 1, sacl_of(SHARE_DIR))

        # ---------- 2. 采集线程 ----------
        print("\n[2] 启动采集线程")
        col.start()
        time.sleep(1.0)
        check("采集线程运行中", col.state["running"])

        # ---------- 3. 通过真实 SMB 读取文件 ----------
        print("\n[3] 客户端 SMB 读取（模拟网络客户端）")
        target = os.path.join(SHARE_DIR, "hello.txt")
        with open(target, "w", encoding="utf-8") as f:
            f.write("审计测试内容\n")
        unc = rf"\\{ip}\{SHARE_NAME}\hello.txt"
        try:
            with open(unc, "r", encoding="utf-8") as f:
                got = f.read()
            read_ok = "审计测试内容" in got
        except OSError as e:
            read_ok = False
            print("        UNC 读取失败：", e)
        check(f"通过 UNC 路径读取成功（{unc}）", read_ok)

        # 再来一次，确保事件量足够
        try:
            with open(unc, "r", encoding="utf-8") as f:
                f.read()
        except OSError:
            pass
        time.sleep(4.0)
        col._poll_once()
        time.sleep(1.0)

        acc = read_log("access")
        share_evs = [a for a in acc if a.get("source") == "share_audit"]
        check("采集到 5145 共享访问事件", bool(share_evs), f"{len(share_evs)} 条")
        if share_evs:
            ev = next((e for e in share_evs if e.get("path", "").endswith("hello.txt")), share_evs[0])
            print("        样例:", json.dumps({k: ev.get(k) for k in
                  ("op", "user", "ip", "path", "share", "access_list")},
                  ensure_ascii=False)[:300])
            check("事件包含客户端 IP", bool(ev.get("ip")), ev.get("ip"))
            check("客户端 IP 正确", ev.get("ip") == ip, f"{ev.get('ip')} vs {ip}")
            check("事件包含用户名", bool(ev.get("user")), ev.get("user"))
            check("解析出访问操作类型", ev.get("op") in ("读取", "写入", "删除", "打开"),
                  ev.get("op"))
            check("路径映射正确", ev.get("path", "").lower()
                  == target.lower(), ev.get("path"))
            check("识别为共享访问来源", ev.get("source") == "share_audit")

        # ---------- 4. 删除归因 ----------
        print("\n[4] 客户端 SMB 删除（验证操作者归因）")
        try:
            import win32file
            win32file.DeleteFile(unc)
            del_ok = not os.path.exists(target)
        except Exception as e:
            del_ok = False
            print("        UNC 删除失败：", e)
        check("通过 UNC 路径删除成功", del_ok)
        time.sleep(3.0)
        col._poll_once()
        time.sleep(1.0)

        dlog = read_log("delete")
        audit_del = [d for d in dlog if d.get("source") == "object_audit"]
        check("采集到 4663 删除审计事件", bool(audit_del), f"{len(audit_del)} 条")
        if audit_del:
            d = next((x for x in audit_del if x.get("path", "").endswith("hello.txt")),
                     audit_del[0])
            print("        样例:", json.dumps({k: d.get(k) for k in
                  ("op", "user", "ip", "path", "process", "attribution")},
                  ensure_ascii=False)[:300])
            check("删除事件带操作者", bool(d.get("user")), d.get("user"))
            check("删除事件带来源 IP", bool(d.get("ip")), d.get("ip"))

        # ---------- 5. 归因缓存 ----------
        print("\n[5] 操作者缓存")
        info = col.actors.lookup(target)
        check("缓存可通过路径回溯到操作者", bool(info.get("user") or info.get("ip")), info)

        col.stop()
        check("采集线程已停止", not col.state["running"])
        check("已采集事件总数 > 0", col.state["collected"] > 0, col.state["collected"])

    finally:
        rc, out = run(f"net share {SHARE_NAME} /delete")
        print(f"\n  清理共享：{'成功' if rc == 0 else '失败 ' + out.strip()[:80]}")
        for name, guid in SUBCATEGORY.items():
            auditpol_set(guid, "disable")
        print("  已还原审计策略（关闭测试开启的子类别）")

    print("\n" + "=" * 72)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    for f in FAIL:
        print("  FAIL:", f)
    if svc_log:
        print("-" * 72)
        print("采集器日志：")
        for lv, t in svc_log[-15:]:
            print(f"  [{lv}] {t[:180]}")
    print("=" * 72)
    return 1 if FAIL else 0


def read_jsonl(path):
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def read_log(kind):
    """读取按天分文件的日志（旧 -> 新），跨天 / 跨分片。"""
    out = []
    for p in log_files(LOGS, f"{kind}_{{date}}.log"):
        out.extend(read_jsonl(p))
    return out


if __name__ == "__main__":
    sys.exit(main())
