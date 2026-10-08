# -*- coding: utf-8 -*-
"""命令行模式：环境体检、打包后自检、无界面运行服务。

    FileGuard.exe            图形界面（默认）
    FileGuard.exe --check    环境体检，输出 FileGuard.check.json
    FileGuard.exe --selftest 打包后自检（临时环境跑通完整链路），输出 FileGuard.selftest.json
    FileGuard.exe --nogui    无界面前台运行服务，Ctrl+C 停止

之所以提供这些模式：exe 是 --windowed 打包，没有控制台输出，
运维需要一种"能拿到结果文件"的方式来确认部署是否正确。
"""
import json
import os
import queue
import shutil
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request

from . import paths, yamlconf


def _attach_console() -> None:
    """--windowed 打包后没有控制台；命令行模式下挂回父进程控制台以便实时看输出。"""
    if not paths.is_frozen() or sys.stdout is not None:
        return
    try:
        import ctypes
        if not ctypes.windll.kernel32.AttachConsole(-1):
            return
        # 按父控制台的代码页写，避免中文变乱码（不改动父进程的控制台设置）
        cp = ctypes.windll.kernel32.GetConsoleOutputCP()
        enc = {65001: "utf-8", 936: "gbk", 950: "big5", 932: "shift_jis"}.get(cp, "utf-8")
        sys.stdout = open("CONOUT$", "w", encoding=enc, errors="replace", buffering=1)
        sys.stderr = open("CONOUT$", "w", encoding=enc, errors="replace", buffering=1)
    except Exception:
        pass


def _out(text: str) -> None:
    try:
        if sys.stdout is not None:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
    except Exception:
        pass


def _dump(name: str, data: dict) -> str:
    path = os.path.join(paths.base_dir(), name)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError:
        path = ""
    return path


def _popup(title: str, text: str, icon: int = 0x40) -> None:
    """自动化/脚本调用时可通过 --nopopup 或 FILEGUARD_NO_POPUP=1 关闭弹窗。"""
    if os.environ.get("FILEGUARD_NO_POPUP") == "1":
        return
    if any(a.lower() == "--nopopup" for a in sys.argv[1:]):
        return
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, text, title, icon)
    except Exception:
        pass


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------- 环境体检
def check() -> int:
    from .audit import SUBCATEGORY, AuditCollector, is_admin
    from .config import load_config

    _attach_console()
    cfg = load_config()
    v = cfg.validate()
    result = {
        "ok": True,
        "checks": {},
        "config_path": cfg.path,
        "monitor_paths": cfg.monitor_paths(),
    }
    c = result["checks"]
    c["管理员权限"] = {"ok": is_admin(),
                   "detail": "OK" if is_admin() else "缺少管理员权限，审计功能不可用"}
    try:
        import flask, watchdog, win32security  # noqa: F401
        c["依赖组件"] = {"ok": True, "detail": "flask / watchdog / pywin32 均已就绪"}
    except ImportError as e:
        c["依赖组件"] = {"ok": False, "detail": f"缺少依赖：{e}"}
    try:
        import ctypes
        import win32evtlog
        h = win32evtlog.EvtQuery("Security",
                                 win32evtlog.EvtQueryChannelPath,
                                 "*[System[(EventID=1)]]")
        try:
            h.Close()
        except Exception:
            pass
        c["安全日志可读"] = {"ok": True, "detail": "OK"}
    except Exception as e:
        c["安全日志可读"] = {"ok": False, "detail": f"无法读取 Security 日志：{e}"}
    try:
        import subprocess
        r = subprocess.run(["auditpol", "/get", "/category:*"], capture_output=True,
                           creationflags=0x08000000, timeout=15)
        c["auditpol 可用"] = {"ok": r.returncode == 0,
                          "detail": "OK" if r.returncode == 0 else f"exit={r.returncode}"}
    except Exception as e:
        c["auditpol 可用"] = {"ok": False, "detail": str(e)}
    for p in cfg.monitor_paths():
        c[f"监控目录 {p}"] = {"ok": os.path.isdir(p),
                          "detail": "存在" if os.path.isdir(p) else "不存在"}
    try:
        rp = cfg.recycle_path()
        t = os.path.join(rp, ".wtest")
        with open(t, "w") as f:
            f.write("1")
        os.remove(t)
        c["回收站可写"] = {"ok": True, "detail": rp}
    except OSError as e:
        c["回收站可写"] = {"ok": False, "detail": f"{cfg.recycle_path()}：{e}"}
    try:
        ld = cfg.log_dir()
        t = os.path.join(ld, ".wtest")
        with open(t, "w") as f:
            f.write("1")
        os.remove(t)
        c["日志目录可写"] = {"ok": True, "detail": ld}
    except OSError as e:
        c["日志目录可写"] = {"ok": False, "detail": f"{cfg.log_dir()}：{e}"}
    c["日志文件名"] = {
        "ok": True,
        "detail": f"{os.path.basename(cfg.today_log_path('access'))} / "
                  f"{os.path.basename(cfg.today_log_path('delete'))}"
                  f"（按天分文件，保留最近 {cfg.get('log.retention_days', 90)} 天）"}
    _days, _hour = cfg.purge_interval_days(), cfg.purge_at_hour()
    if not cfg.auto_purge():
        c["回收站自动清理"] = {"ok": True, "detail": "已关闭（recycle_bin.auto_purge=false）"}
    else:
        _hour_txt = "不指定时点" if _hour < 0 else f"{_hour:02d}:00"
        _days_txt = f"每 {_days} 天" if _days > 1 else "每天"
        c["回收站自动清理"] = {
            "ok": True,
            "detail": f"{_days_txt} {_hour_txt} 清理一次；保留 {cfg.get('recycle_bin.retention_days', 30)} 天"
                      f" / 上限 {cfg.get('recycle_bin.max_size_gb', 20)} GB"}
    try:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((cfg.get("web.host", "0.0.0.0"), int(cfg.get("web.port", 8765))))
        srv.close()
        c["Web 端口可用"] = {"ok": True, "detail": str(cfg.get("web.port"))}
    except OSError as e:
        c["Web 端口可用"] = {"ok": False, "detail": str(e)}
    c["配置文件"] = {"ok": os.path.isfile(cfg.path),
                 "detail": f"{cfg.path}（YAML 格式）"
                           + (f"；{cfg.migration_note()}" if cfg.migrated_from else "")}
    if getattr(cfg, "load_error", ""):
        c["配置文件解析"] = {"ok": False, "detail": cfg.load_error}
    c["配置校验"] = {"ok": v["ok"], "detail": "；".join(v["errors"]) or "通过"}
    c["Web 登录密码"] = {"ok": bool(cfg.get("web.password")),
                     "detail": f"{cfg.get('web.username')} / {cfg.get('web.password')}"}

    result["ok"] = all(x["ok"] for k, x in c.items() if k not in ("Web 登录密码",))
    lines = [f"{'✓' if x['ok'] else '✗'} {k}：{x['detail']}" for k, x in c.items()]
    out = _dump("FileGuard.check.json", result)
    _out("=" * 60)
    _out("FileGuard 环境体检")
    _out("=" * 60)
    for ln in lines:
        _out("  " + ln)
    _out(f"\n结果文件：{out}")
    if paths.is_frozen():
        _popup("FileGuard 环境体检",
               ("全部通过 ✓" if result["ok"] else "存在未通过项 ✗") + "\n\n" +
               "\n".join(lines[:16]) + f"\n\n详细结果：{out}",
               0x40 if result["ok"] else 0x30)
    return 0 if result["ok"] else 1


# ---------------------------------------------------------------- 打包后自检
def selftest() -> int:
    """在临时目录里跑一遍完整链路，验证打包后的 exe 功能完好。"""
    from .config import Config
    from .service import GuardService

    _attach_console()
    base = os.path.join(tempfile.gettempdir(), "fg_selftest")
    shutil.rmtree(base, ignore_errors=True)
    share = os.path.join(base, "Share")
    for d in (share, os.path.join(base, "Recycle"), os.path.join(base, "Logs")):
        os.makedirs(d, exist_ok=True)
    port = _free_port()
    conf_path = os.path.join(base, "config.yaml")
    with open(conf_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(yamlconf.dump({
            "monitor": {"paths": [share], "seed_on_start": False, "log_changes": True},
            "protection": {"strategy": "mirror", "on_delete_action": "move_to_bin",
                           "debounce_seconds": 0.5},
            "recycle_bin": {"path": os.path.join(base, "Recycle"), "auto_purge": False},
            "log": {"dir": os.path.join(base, "Logs")},
            # 自检不改动系统审计策略
            "audit": {"enabled": False, "auto_configure": False},
            "web": {"enabled": True, "host": "127.0.0.1", "port": port,
                    "username": "admin", "password": "selftest",
                    "session_secret": "selftest"},
        }, header="FileGuard 自检用临时配置（YAML）"))

    os.environ["FILEGUARD_CONFIG"] = conf_path
    checks = []

    def ck(name, cond, extra=""):
        checks.append({"name": name, "ok": bool(cond), "extra": str(extra)})
        _out(f"  {'[PASS]' if cond else '[FAIL]'} {name}  {extra}")

    svc = None
    try:
        cfg = Config(conf_path).load()
        ck("YAML 配置文件加载", True, conf_path)
        txt = cfg.yaml_text()
        ck("保存时自动生成注释", "#" in txt and "monitor" in txt, f"{len(txt.splitlines())} 行")
        ck("注释可解析回环", yamlconf.load_text(txt).get("web", {}).get("port") == port,
           f"port={port}")
        # 托盘（需求：关闭窗口只隐藏界面，服务继续后台运行）
        try:
            from .tray import TrayIcon, tray_icon_path
            tray = TrayIcon("FileGuard 自检", icon_path=tray_icon_path())
            tray_ok = tray.start(timeout=3)
            tray.stop()
            ck("系统托盘图标可挂载", tray_ok, f"icon={tray_icon_path() or '默认图标'}")
        except Exception as e:
            ck("系统托盘图标可挂载", False, str(e))
        ck("删除动作默认为移入回收站", cfg.delete_action() == "move_to_bin",
           cfg.delete_action())
        svc = GuardService(cfg, ui_queue=queue.Queue())
        r = svc.start()
        ck("服务启动", r.get("ok"), r.get("message"))
        for _ in range(60):
            if _port_open(port):
                break
            time.sleep(0.2)
        ck("Web 服务监听", _port_open(port), f"port={port}")

        f1 = os.path.join(share, "selftest.txt")
        with open(f1, "w", encoding="utf-8") as f:
            f.write("self-test content\n")
        time.sleep(1.8)
        with open(f1, "w", encoding="utf-8") as f:
            f.write("self-test content v2\n")
        time.sleep(2.0)
        ck("镜像存档", svc.recycle.stats()["versions"] >= 1,
           svc.recycle.stats()["versions"])

        os.remove(f1)
        time.sleep(2.5)
        ck("删除后原文件消失（删除正常生效）", not os.path.isfile(f1))
        binp = svc.recycle.bin_path_for(f1)
        ck("文件已移入回收站实体目录", os.path.isfile(binp), binp)
        ck("回收站副本内容正确",
           os.path.isfile(binp) and "v2" in open(binp, encoding="utf-8").read())

        dlog = cfg.today_log_path("delete")
        dtext = open(dlog, encoding="utf-8").read() if os.path.isfile(dlog) else ""
        ck("删除日志按天命名 " + os.path.basename(dlog), os.path.basename(dlog) ==
           "delete_" + time.strftime("%Y%m%d") + ".log", os.path.basename(dlog))
        ck("删除日志写入", "selftest.txt" in dtext)
        ck("删除日志标记 action=move_to_bin", '"action": "move_to_bin"' in dtext)
        ck("删除日志带回收站副本路径", '"bin_path"' in dtext and "Recycle" in dtext.replace("/", "\\"))
        alog = cfg.today_log_path("access")
        has_acc = os.path.isfile(alog) and os.path.getsize(alog) > 0
        ck("访问日志按天命名 " + os.path.basename(alog), os.path.basename(alog) ==
           "access_" + time.strftime("%Y%m%d") + ".log", os.path.basename(alog))
        ck("访问日志写入", has_acc)

        cli = _WebClient(f"http://127.0.0.1:{port}")
        sc, j = cli.call("/api/ping")
        ck("Web API /api/ping", sc == 200, sc)
        cli.call("/api/login", "POST", {"username": "admin", "password": "selftest"})
        sc, j = cli.call("/api/status")
        ck("Web API /api/status", sc == 200 and j["data"]["running"], sc)
        sc, j = cli.call("/api/logs/delete?size=5")
        ck("Web API 删除日志查询", sc == 200 and j["data"]["items"], sc)
        sc, j = cli.call("/api/recycle?size=5")
        ck("Web API 回收站查询", sc == 200, sc)
        items = j["data"]["items"] if sc == 200 else []
        if items:
            sc, j = cli.call("/api/recycle/restore", "POST", {"ids": [items[0]["id"]]})
            ck("Web API 一键恢复", sc == 200 and j["data"]["ok"] == 1, sc)
        else:
            ck("Web API 一键恢复", False, "回收站为空")
        req = urllib.request.Request(f"http://127.0.0.1:{port}/")
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", "replace")
        ck("Web 界面页面可访问", resp.status == 200 and "FileGuard" in html,
           len(html))
    except Exception as e:
        import traceback
        ck("自检异常", False, f"{e}")
        _out(traceback.format_exc()[-800:])
    finally:
        if svc is not None:
            try:
                svc.stop()
            except Exception:
                pass
        time.sleep(0.5)
        ck("服务已停止且端口释放", not _port_open(port))

    passed = sum(1 for c in checks if c["ok"])
    result = {"ok": passed == len(checks), "passed": passed,
              "total": len(checks), "checks": checks,
              "exe": sys.executable if paths.is_frozen() else "源码模式",
              "frozen": paths.is_frozen()}
    out = _dump("FileGuard.selftest.json", result)
    _out("=" * 60)
    _out(f"自检结果：通过 {passed}/{len(checks)}　结果文件：{out}")
    _out("=" * 60)
    if paths.is_frozen():
        _popup("FileGuard 自检",
               f"通过 {passed}/{len(checks)}\n\n" +
               "\n".join(f"{'✓' if c['ok'] else '✗'} {c['name']}" for c in checks[:16]) +
               f"\n\n详细结果：{out}", 0x40 if result["ok"] else 0x10)
    return 0 if result["ok"] else 1


def _port_open(port: int) -> bool:
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


class _WebClient:
    def __init__(self, base):
        self.base = base
        self.cookie = ""

    def call(self, path, method="GET", body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json", "Cookie": self.cookie})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                sc = r.getheader("Set-Cookie")
                if sc:
                    self.cookie = sc.split(";")[0]
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))


# ---------------------------------------------------------------- 无界面运行
def nogui() -> int:
    from .config import load_config
    from .service import GuardService

    _attach_console()
    cfg = load_config()
    v = cfg.validate()
    if not v["ok"]:
        _out("配置错误：" + "；".join(v["errors"]))
        return 1
    q = queue.Queue()
    svc = GuardService(cfg, ui_queue=q)

    def drain():
        while True:
            rec = q.get()
            _out(f"[{rec.get('ts')}] {rec.get('text')}")

    import threading
    threading.Thread(target=drain, daemon=True).start()
    r = svc.start()
    _out(str(r))
    _out("按 Ctrl+C 停止服务 ...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _out("\n正在停止 ...")
        svc.stop()
    return 0
