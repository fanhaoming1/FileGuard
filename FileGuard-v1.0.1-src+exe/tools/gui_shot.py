# -*- coding: utf-8 -*-
"""给 GUI 控制台真实截图：启动窗口 -> 点击开始服务 -> 抓取窗口位图。

用法： python tools/gui_shot.py <config.yaml路径> <输出png>
"""
import ctypes
import ctypes.wintypes as wt
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

user32 = ctypes.windll.user32
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'[PASS]' if cond else '[FAIL]'} {name}{('  ' + str(extra)) if extra else ''}")


def window_rect(title_kw="FileGuard"):
    found = []
    EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def cb(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            if n > 0:
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                if title_kw in buf.value:
                    found.append((hwnd, buf.value))
        return True

    user32.EnumWindows(EnumProc(cb), 0)
    if not found:
        return None, None
    hwnd, title = found[0]
    r = wt.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    return hwnd, (r.left, r.top, r.right, r.bottom)


def main():
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else None
    out = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "docs/screenshots/06-程序主界面.png")
    if cfg_path:
        os.environ["FILEGUARD_CONFIG"] = os.path.abspath(cfg_path)
    os.makedirs(os.path.dirname(out), exist_ok=True)

    from app.config import load_config
    from app.gui import GuardGUI

    cfg = load_config()
    gui = GuardGUI(cfg)
    state = {"shot": 0}

    def shoot(tag):
        hwnd, rect = window_rect()
        if not hwnd:
            print("  未找到窗口")
            return
        # 截屏抓的是屏幕区域，必须先把窗口置顶，否则会被其它窗口挡住
        HWND_TOPMOST, HWND_NOTOPMOST = -1, -2
        SWP_NOMOVE, SWP_NOSIZE = 0x0002, 0x0001
        user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
        user32.SetForegroundWindow(hwnd)
        user32.BringWindowToTop(hwnd)
        time.sleep(0.9)
        from PIL import ImageGrab
        img = ImageGrab.grab(bbox=rect, all_screens=True)
        path = out if tag == "running" else out.replace(".png", "-停止态.png")
        img.save(path)
        user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
        print(f"  已保存 {path}  {img.size}  {os.path.getsize(path)} bytes")
        check(f"截图成功({tag})", os.path.getsize(path) > 20000, img.size)

    def seq():
        shoot("stopped")
        print("\n  点击「开始服务」...")
        gui.on_start()
        # 注意：不能在 tkinter 回调里 sleep，否则事件循环被阻塞、界面不会重绘
        gui.root.after(6500, after_start)

    def after_start():
        check("服务已运行", gui.service.running)
        # 触发一次真实删除，让日志区出现「已移入回收站」记录
        import threading

        def poke():
            time.sleep(0.3)
            share = (cfg.monitor_paths() or [None])[0]
            if not share or not os.path.isdir(share):
                return
            for dp, _dn, fns in os.walk(share):
                if fns:
                    try:
                        os.remove(os.path.join(dp, fns[0]))
                    except OSError:
                        pass
                    break
        threading.Thread(target=poke, daemon=True).start()
        gui.root.after(3000, shoot_running)

    def shoot_running():
        shoot("running")
        gui.root.after(800, finish)

    def finish():
        gui.service.stop()
        gui.root.after(600, gui.root.destroy)

    gui.root.after(1200, seq)
    gui.root.mainloop()
    print(f"\n通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
