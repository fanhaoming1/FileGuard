# -*- coding: utf-8 -*-
"""程序入口：单实例保护 + 启动 GUI。"""
import ctypes
import sys
import traceback

MUTEX_NAME = "Global\\FileGuard_SingleInstance_Mutex"


def _acquire_single_instance():
    """已有实例在运行时返回 None。"""
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
        if kernel32.GetLastError() == 183:      # ERROR_ALREADY_EXISTS
            if handle:
                kernel32.CloseHandle(handle)
            return None
        return handle
    except Exception:
        return True                              # 无法判断时不阻塞启动


def _safe_print(text: str) -> None:
    """打包为 --windowed 时 sys.stdout 为 None，这里做保护。"""
    try:
        if sys.stdout is not None:
            print(text)
    except Exception:
        pass


def _warn_already_running():
    msg = ("FileGuard 已经在运行中。\n\n"
           "关闭窗口并不会停止服务，程序仍在系统托盘里继续运行 ——\n"
           "请查看任务栏右下角的托盘图标（双击可重新打开主界面），\n"
           "或先「停止服务」再退出已有实例。")
    try:
        ctypes.windll.user32.MessageBoxW(None, msg, "FileGuard", 0x40)
    except Exception:
        _safe_print(msg)


def main():
    from .config import load_config
    from .gui import GuardGUI

    handle = _acquire_single_instance()
    if handle is None:
        _warn_already_running()
        return 1
    try:
        cfg = load_config()
        GuardGUI(cfg).run()
        return 0
    except Exception:
        err = traceback.format_exc()
        try:
            with open("FileGuard.crash.log", "a", encoding="utf-8") as f:
                f.write(err + "\n")
        except OSError:
            pass
        try:
            ctypes.windll.user32.MessageBoxW(None, err[-1500:], "FileGuard 启动异常", 0x10)
        except Exception:
            _safe_print(err)
        return 2
    finally:
        try:
            if handle:
                ctypes.windll.kernel32.ReleaseMutex(handle)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
