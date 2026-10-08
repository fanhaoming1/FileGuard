# -*- coding: utf-8 -*-
"""GUI 冒烟测试：真实创建 tkinter 窗口，驱动「开始/停止服务」与关闭/托盘行为。

需要图形界面（Windows 桌面会话）。通过 root.after 驱动，最后自动关闭。

覆盖需求：
* 关闭主窗口不停止服务（隐藏到系统托盘），服务继续在后台运行；
* 托盘菜单「退出界面」同样不停止服务；
* 只有点击「停止服务」按钮才真正停止服务。

用法： python tools/gui_test.py
"""
import os
import shutil
import socket
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import yamlconf  # noqa: E402

BASE = os.path.join(tempfile.gettempdir(), "fg_gui")
SHARE = os.path.join(BASE, "Share")
CONF = os.path.join(BASE, "config.yaml")
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'[PASS]' if cond else '[FAIL]'} {name}{('  ' + str(extra)) if extra else ''}")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    print("=" * 72)
    print("FileGuard GUI 冒烟测试")
    print("=" * 72)
    shutil.rmtree(BASE, ignore_errors=True)
    for d in (SHARE, os.path.join(BASE, "Recycle"), os.path.join(BASE, "Logs")):
        os.makedirs(d, exist_ok=True)

    port = free_port()
    with open(CONF, "w", encoding="utf-8", newline="\n") as f:
        f.write(yamlconf.dump({
            "monitor": {"paths": [SHARE], "seed_on_start": False},
            "protection": {"on_delete_action": "move_to_bin", "debounce_seconds": 0.5,
                           "actor_backfill_ms": 0},
            "recycle_bin": {"path": os.path.join(BASE, "Recycle"), "auto_purge": False},
            "log": {"dir": os.path.join(BASE, "Logs")},
            "audit": {"enabled": False, "auto_configure": False},
            "web": {"enabled": True, "host": "127.0.0.1", "port": port,
                    "username": "admin", "password": "guipass",
                    "session_secret": "gui-secret"},
        }, header="FileGuard GUI 测试用临时配置（YAML）"))
    os.environ["FILEGUARD_CONFIG"] = CONF

    from app.config import load_config
    from app.gui import GuardGUI

    cfg = load_config()
    gui = GuardGUI(cfg)
    state = {"deleted_file": "", "bin_path": ""}

    print("\n[1] 窗口构建")
    check("主窗口已创建", gui.root is not None)
    check("标题正确", "FileGuard" in gui.root.title(), gui.root.title())
    check("开始按钮可用", str(gui.btn_start["state"]) == "normal")
    check("停止按钮初始禁用", str(gui.btn_stop["state"]) == "disabled")
    check("初始状态为已停止", "已停止" in gui.badge["text"], gui.badge["text"])
    check("信息面板已填充 Web 地址", "http" in gui.rows["web"]["text"],
          gui.rows["web"]["text"])
    check("面板显示登录账号密码", "admin" in gui.rows["auth"]["text"],
          gui.rows["auth"]["text"])
    check("面板显示删除动作", "move_to_bin" in gui.rows["action"]["text"],
          gui.rows["action"]["text"])
    check("config.yaml 已生成", os.path.isfile(CONF))

    def step_start():
        print("\n[2] 点击「开始服务」")
        gui.on_start()

    def verify_running():
        st = gui.service.status()
        check("服务状态为运行中", st["running"])
        check("徽标显示运行中", "运行中" in gui.badge["text"], gui.badge["text"])
        check("停止按钮已启用", str(gui.btn_stop["state"]) == "normal")
        check("开始按钮已禁用", str(gui.btn_start["state"]) == "disabled")
        check("Web 服务已监听", port_open(port))
        check("Protector 已挂载监听", gui.service.protector is not None
              and gui.service.protector.running)
        check("界面日志区有输出", int(gui.txt.index("end-1c").split(".")[0]) > 1,
              gui.txt.index("end-1c"))
        # 真实触发一次删除：文件应消失，内容落到回收站
        f = os.path.join(SHARE, "gui.txt")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("gui test\n")
        state["deleted_file"] = f
        time.sleep(2.5)
        os.remove(f)
        time.sleep(2.5)
        state["bin_path"] = gui.service.recycle.bin_path_for(f)
        check("删除后原文件消失（删除正常生效）", not os.path.isfile(f))
        check("内容已移入回收站实体目录", os.path.isfile(state["bin_path"]),
              state["bin_path"])

    def do_hide():
        print("\n[3] 关闭主窗口（服务运行中）")
        gui._on_close()

    def verify_hidden():
        check("关闭窗口后服务仍在运行", gui.service.running)
        check("窗口已隐藏", not bool(gui.root.winfo_viewable()))
        check("托盘图标已挂载", gui._tray is not None and gui._tray.running)
        check("Web 端口仍可访问", port_open(port))
        st = gui.service.status()
        check("界面状态仍标记运行中（后台继续跑）", st["running"])

    def do_show():
        print("\n[4] 托盘「显示主界面」")
        gui._on_tray_action("show")

    def verify_shown():
        check("窗口重新可见", gui.root.winfo_viewable())

    def do_tray_exit():
        print("\n[5] 托盘「退出界面（服务继续后台运行）」")
        gui._on_tray_action("exit")

    def verify_still_running():
        check("托盘退出后服务仍在运行", gui.service.running)
        check("窗口仍可随时打开（托盘图标在）",
              gui._tray is not None and gui._tray.running)
        check("Web 端口仍可访问", port_open(port))

    def step_stop():
        print("\n[6] 点击「停止服务」（唯一的停止入口）")
        gui.on_stop()

    def verify_stopped():
        st = gui.service.status()
        check("服务状态为已停止", not st["running"])
        check("徽标恢复已停止", "已停止" in gui.badge["text"], gui.badge["text"])
        check("开始按钮已恢复可用", str(gui.btn_start["state"]) == "normal")
        check("停止按钮已禁用", str(gui.btn_stop["state"]) == "disabled")
        check("Web 端口已释放", not port_open(port))

    def do_final_close():
        print("\n[7] 服务未运行时关闭窗口 -> 结束程序")
        gui._on_close()

    for delay, fn in ((400, step_start), (5600, verify_running),
                      (6600, do_hide), (8200, verify_hidden),
                      (8800, do_show), (9800, verify_shown),
                      (10400, do_tray_exit), (11600, verify_still_running),
                      (12200, step_stop), (16200, verify_stopped),
                      (16800, do_final_close)):
        gui.root.after(delay, fn)
    gui.root.mainloop()

    # do_final_close 已销毁窗口，mainloop 随之返回
    try:
        gui.root.winfo_exists()
        alive = True
    except Exception:
        alive = False
    check("服务未运行时关闭窗口会真正退出界面", not alive)

    gui._stop_tray()
    print("\n" + "=" * 72)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    for f in FAIL:
        print("  FAIL:", f)
    print("=" * 72)
    return 0 if not FAIL else 1


def port_open(port):
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(main())
