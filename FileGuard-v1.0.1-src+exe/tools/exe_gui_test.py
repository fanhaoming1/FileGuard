# -*- coding: utf-8 -*-
"""验证打包后的 GUI：真实启动 FileGuard.exe，用 Win32 API 找到主窗口，再优雅关闭。

用法： python tools/exe_gui_test.py <exe路径>
"""
import ctypes
import ctypes.wintypes as wt
import os
import shutil
import subprocess
import sys
import tempfile
import time

user32 = ctypes.windll.user32
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'[PASS]' if cond else '[FAIL]'} {name}{('  ' + str(extra)) if extra else ''}")


def find_windows(keyword="FileGuard"):
    found = []
    EnumProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def cb(hwnd, lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        n = user32.GetWindowTextLengthW(hwnd)
        if n <= 0:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        user32.GetWindowTextW(hwnd, buf, n + 1)
        if keyword in buf.value:
            found.append((hwnd, buf.value))
        return True

    user32.EnumWindows(EnumProc(cb), 0)
    return found


def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else os.path.join("dist", "FileGuard.exe")
    exe = os.path.abspath(exe)
    print("=" * 72)
    print("FileGuard 打包后 GUI 启动测试")
    print("exe:", exe)
    print("=" * 72)
    check("exe 存在", os.path.isfile(exe), exe)
    if not os.path.isfile(exe):
        return 1

    work = os.path.join(tempfile.gettempdir(), "fg_exegui")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    target = os.path.join(work, "FileGuard.exe")
    shutil.copyfile(exe, target)

    before = {h for h, _ in find_windows()}
    env = dict(os.environ)
    env.pop("FILEGUARD_CONFIG", None)
    proc = subprocess.Popen([target], cwd=work, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("\n[1] 启动 GUI（PID %d），等待窗口出现 ..." % proc.pid)

    win = None
    for _ in range(60):
        time.sleep(0.5)
        if proc.poll() is not None:
            break
        for h, title in find_windows():
            if h not in before:
                win = (h, title)
                break
        if win:
            break
    check("进程仍在运行（未崩溃退出）", proc.poll() is None,
          f"exitcode={proc.poll()}")
    check("主窗口已创建且可见", win is not None, win[1] if win else "未找到窗口")
    check("窗口标题正确", bool(win) and "FileGuard" in win[1],
          win[1] if win else "")
    check("已在 exe 同目录生成 config.yaml",
          os.path.isfile(os.path.join(work, "config.yaml")))

    cfgp = os.path.join(work, "config.yaml")
    if os.path.isfile(cfgp):
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from app import yamlconf
        raw = open(cfgp, encoding="utf-8").read()
        cfg = yamlconf.load_file(cfgp)
        check("config.yaml 内容合法（含 monitor.web.recycle_bin）",
              all(k in cfg for k in ("monitor", "web", "recycle_bin", "log", "audit")))
        check("配置文件带中文注释说明", "#" in raw and "默认值" in raw,
              f"{len(raw.splitlines())} 行")
        check("生成了随机 Web 密码", len(cfg.get("web", {}).get("password", "")) >= 8,
              cfg.get("web", {}).get("password", "")[:4] + "****")

    print("\n[2] 发送 WM_CLOSE 优雅关闭 ...")
    closed = False
    if win:
        WM_CLOSE = 0x0010
        user32.PostMessageW(win[0], WM_CLOSE, 0, 0)
        for _ in range(30):
            time.sleep(0.5)
            if proc.poll() is not None:
                closed = True
                break
    check("窗口关闭后进程正常退出", closed, f"exitcode={proc.poll()}")
    if proc.poll() is None:
        proc.kill()

    print("\n" + "=" * 72)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    for f in FAIL:
        print("  FAIL:", f)
    print("=" * 72)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
