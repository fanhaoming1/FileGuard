# -*- coding: utf-8 -*-
"""FileGuard 启动脚本。

    python run.py                启动图形界面（默认）
    python run.py --check        环境体检
    python run.py --selftest     完整功能自检
    python run.py --nogui        无界面前台运行服务
    python run.py --help         查看帮助
"""
import os
import sys


def _setup_stdio():
    """--windowed 打包后无控制台：能挂回父控制台就挂，否则重定向到空设备。

    避免 logging / werkzeug 往 None 写而报错（"--- Logging error ---"）。
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    if sys.stdout is not None and sys.stderr is not None:
        return
    if getattr(sys, "frozen", False):
        try:
            import ctypes
            if ctypes.windll.kernel32.AttachConsole(-1):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
                return
        except Exception:
            pass
    try:
        devnull = open(os.devnull, "w", encoding="utf-8")
        if sys.stdout is None:
            sys.stdout = devnull
        if sys.stderr is None:
            sys.stderr = devnull
    except OSError:
        pass


_setup_stdio()

USAGE = __doc__


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = {a.lower() for a in argv}

    if args & {"--help", "-h", "/?", "-?"}:
        print(USAGE)
        return 0

    if args & {"--check", "--doctor", "check"}:
        from app.cli import check
        return check()

    if args & {"--selftest", "--self-test", "selftest"}:
        from app.cli import selftest
        return selftest()

    if args & {"--nogui", "--console", "nogui"}:
        from app.cli import nogui
        return nogui()

    from app.main import main as gui_main
    return gui_main()


if __name__ == "__main__":
    sys.exit(main())
