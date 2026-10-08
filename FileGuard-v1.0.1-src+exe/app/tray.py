# -*- coding: utf-8 -*-
"""系统托盘图标：纯 ctypes 调用 Win32 Shell_NotifyIconW，不引入任何第三方依赖。

为什么需要它
-----------
需求要求「关闭主窗口时服务必须继续运行，只有点『停止服务』按钮才真正停止服务」。
窗口关掉后程序仍在后台跑，就必须有一个用户能回到界面的入口 —— 托盘图标即入口。

设计要点
--------
* 在**独立线程**里 RegisterClass + CreateWindowEx（隐藏窗口）+ 消息循环，图标回调消息
  由该线程处理；菜单点击后只把动作名放进线程安全队列。
* tkinter 不是线程安全的，因此**绝不**在托盘线程里碰界面；主界面用 ``poll()``
  在自己的定时器里消费动作（见 ``app/gui.py`` 的 ``_tick``）。
* ``start()`` 会等图标真正挂上再返回，失败返回 False，界面据此降级为「最小化」。
"""
import ctypes
import ctypes.wintypes as wt
import os
import queue
import sys
import threading
import time

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

# ---------------- 消息 / 常量 ----------------
WM_APP = 0x8000
WM_TRAY = WM_APP + 1
WM_NULL = 0x0000
WM_QUIT = 0x0012
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B

NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x01, 0x02, 0x04, 0x10
NIIF_INFO, NIIF_WARNING = 0x01, 0x02

IMAGE_ICON = 1
LR_LOADFROMFILE, LR_DEFAULTSIZE, LR_SHARED = 0x0010, 0x0040, 0x8000
IDI_APPLICATION = 32512
SM_CXSMICON, SM_CYSMICON = 49, 50

MF_STRING = 0x0000
MF_SEPARATOR = 0x0800
TPM_RIGHTBUTTON, TPM_RETURNCMD = 0x0002, 0x0100

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

# ctypes 默认把 Python int 当 32 位 C int 传，64 位下 lParam/wParam 会溢出
# （OverflowError: int too long to convert），因此这里显式声明函数原型。
user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.DefWindowProcW.restype = LRESULT
user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                                   ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, wt.HWND, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p]
user32.CreateWindowExW.restype = wt.HWND
user32.RegisterClassW.argtypes = [ctypes.c_void_p]
user32.RegisterClassW.restype = wt.ATOM if hasattr(wt, "ATOM") else wt.WORD
user32.UnregisterClassW.argtypes = [wt.LPCWSTR, ctypes.c_void_p]
user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
user32.GetMessageW.restype = ctypes.c_int
user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
user32.DispatchMessageW.restype = LRESULT
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.PostMessageW.restype = wt.BOOL
user32.PostQuitMessage.argtypes = [ctypes.c_int]
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.SetForegroundWindow.restype = wt.BOOL
user32.CreatePopupMenu.restype = ctypes.c_void_p
user32.AppendMenuW.argtypes = [ctypes.c_void_p, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
user32.AppendMenuW.restype = wt.BOOL
user32.TrackPopupMenu.argtypes = [ctypes.c_void_p, wt.UINT, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_int, wt.HWND,
                                  ctypes.c_void_p]
user32.TrackPopupMenu.restype = ctypes.c_int
user32.DestroyMenu.argtypes = [ctypes.c_void_p]
user32.GetCursorPos.argtypes = [ctypes.POINTER(wt.POINT)]
user32.LoadImageW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.UINT,
                              ctypes.c_int, ctypes.c_int, wt.UINT]
user32.LoadImageW.restype = ctypes.c_void_p
user32.LoadIconW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
user32.LoadIconW.restype = ctypes.c_void_p
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.GetSystemMetrics.restype = ctypes.c_int
user32.DestroyIcon.argtypes = [ctypes.c_void_p]
user32.DestroyIcon.restype = wt.BOOL
shell32.ExtractIconExW.argtypes = [wt.LPCWSTR, ctypes.c_int,
                                   ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.POINTER(ctypes.c_void_p), wt.UINT]
shell32.ExtractIconExW.restype = wt.UINT
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
kernel32.GetModuleHandleW.restype = ctypes.c_void_p

ERROR_CLASS_ALREADY_EXISTS = 1410


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_byte * 8)]


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("hWnd", wt.HWND),
        ("uID", wt.UINT),
        ("uFlags", wt.UINT),
        ("uCallbackMessage", wt.UINT),
        ("hIcon", wt.HICON),
        ("szTip", wt.WCHAR * 128),
        ("dwState", wt.DWORD),
        ("dwStateMask", wt.DWORD),
        ("szInfo", wt.WCHAR * 256),
        ("uVersion", wt.UINT),
        ("szInfoTitle", wt.WCHAR * 64),
        ("dwInfoFlags", wt.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", wt.HICON),
    ]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wt.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE),
        ("hIcon", wt.HICON),
        ("hCursor", wt.HANDLE),
        ("hbrBackground", wt.HBRUSH),
        ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR),
    ]


_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_shell32.Shell_NotifyIconW.argtypes = [wt.DWORD,
                                       ctypes.POINTER(NOTIFYICONDATAW)]
_shell32.Shell_NotifyIconW.restype = wt.BOOL


def _notify(action: int, nid: "NOTIFYICONDATAW") -> bool:
    try:
        return bool(_shell32.Shell_NotifyIconW(action, ctypes.byref(nid)))
    except Exception:
        return False


def _small_icon_size() -> int:
    """托盘需要的是 16x16 小图标；显式取系统小图标尺寸比 LR_DEFAULTSIZE(32x32) 清晰。"""
    try:
        n = int(user32.GetSystemMetrics(SM_CXSMICON))
        return n if n > 0 else 16
    except Exception:
        return 16


_ICON_CACHE = {}


def _icon_from_exe():
    """从当前进程的 exe 里取出内嵌图标。

    打包成单文件 exe 后，图标是以「资源」形式嵌在 exe 里的；即使 assets/*.ico
    没有随包分发（或者资源目录被清理），也能拿到正确的 FileGuard 图标，
    而不是退化成 Windows 默认图标。
    """
    try:
        exe = sys.executable or ""
        if not exe or not os.path.isfile(exe):
            return None
        large = ctypes.c_void_p()
        small = ctypes.c_void_p()
        n = shell32.ExtractIconExW(exe, 0, ctypes.byref(large),
                                   ctypes.byref(small), 1)
        if not n:
            return None
        if large:                        # 只需要小图标，多余的立刻释放
            user32.DestroyIcon(large)
        return small or None
    except Exception:
        return None


def _load_icon(path: str = ""):
    """加载托盘图标，按「随包 ico → exe 内嵌资源 → 系统默认」依次尝试。

    结果按 key 缓存：同一个 HICON 被托盘与窗口类共用，避免重复加载与句柄泄漏。
    """
    key = path or ""
    cached = _ICON_CACHE.get(key)
    if cached:
        return cached

    size = _small_icon_size()
    h = None
    if path and os.path.isfile(path):
        # LR_SHARED：句柄由系统托管，进程退出自动释放，不需要（也不能）手动 DestroyIcon
        h = user32.LoadImageW(None, path, IMAGE_ICON, size, size,
                              LR_LOADFROMFILE | LR_SHARED)
    if not h:
        h = _icon_from_exe()             # 需要手动释放，故只加载一次并缓存
    if not h:
        h = user32.LoadIconW(None, wt.HICON(IDI_APPLICATION))
    if h:
        _ICON_CACHE[key] = h
    return h


class TrayIcon:
    """托盘图标 + 右键菜单。动作以字符串进队列，由主线程消费。"""

    def __init__(self, tooltip: str = "FileGuard",
                 menu=(("显示主界面", "show"), ("打开 Web 界面", "web"),
                       ("退出界面（服务继续后台运行）", "exit")),
                 icon_path: str = ""):
        self.tooltip = (tooltip or "FileGuard")[:127]
        self.menu = list(menu)
        self.icon_path = icon_path
        self.actions = queue.Queue()
        self._thread = None
        self._hwnd = None
        self._ready = threading.Event()
        self._ok = False
        self._closing = False
        self._wndproc = None            # 必须持有引用，否则回调会被 GC 掉
        self._mutex = threading.Lock()

    # ---------------- 生命周期 ----------------
    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self._ok)

    def start(self, timeout: float = 3.0) -> bool:
        if self.running:
            return True
        self._ready.clear()
        self._ok = False
        self._closing = False
        self._thread = threading.Thread(target=self._run, daemon=True, name="fg-tray")
        self._thread.start()
        self._ready.wait(timeout)
        return self._ok

    def stop(self) -> None:
        self._closing = True
        hwnd = self._hwnd
        if hwnd:
            try:
                user32.PostMessageW(hwnd, WM_QUIT, 0, 0)
            except Exception:
                pass
        t, self._thread = self._thread, None
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=2)
        self._ok = False

    # ---------------- 主线程接口 ----------------
    def poll(self, limit: int = 10) -> list:
        out = []
        for _ in range(max(1, int(limit))):
            try:
                out.append(self.actions.get_nowait())
            except queue.Empty:
                break
        return out

    def set_tooltip(self, text: str) -> None:
        self.tooltip = (text or "FileGuard")[:127]
        self._nid_call(NIM_MODIFY, NIF_TIP)

    def notify(self, title: str, text: str) -> None:
        """气泡提示（仅在图标已挂上时有效）。"""
        if not self.running:
            return
        nid = self._make_nid(NIF_INFO)
        nid.szInfoTitle = (title or "")[:63]
        nid.szInfo = (text or "")[:255]
        nid.dwInfoFlags = NIIF_INFO
        _notify(NIM_MODIFY, nid)

    # ---------------- 线程内部 ----------------
    def _make_nid(self, flags: int) -> NOTIFYICONDATAW:
        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = self._hwnd or 0
        nid.uID = 1
        nid.uFlags = flags
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = _load_icon(self.icon_path)
        nid.szTip = self.tooltip
        return nid

    def _nid_call(self, action: int, flags: int) -> bool:
        if not self._hwnd:
            return False
        return _notify(action, self._make_nid(flags))

    def _run(self) -> None:
        try:
            self._create_window()
        except Exception as e:                                # pragma: no cover
            self._err = str(e)
            self._ready.set()
            return
        if not self._nid_call(NIM_ADD, NIF_MESSAGE | NIF_ICON | NIF_TIP):
            self._ok = False
            self._ready.set()
            self._destroy_window()
            return
        self._ok = True
        self._ready.set()
        self._message_loop()

    def _create_window(self) -> None:
        hinst = kernel32.GetModuleHandleW(None)
        self._cls_name = f"FileGuardTray_{os.getpid()}"
        self._wndproc = WNDPROC(self._on_message)
        wc = WNDCLASSW()
        wc.style = 0
        wc.lpfnWndProc = self._wndproc
        wc.cbClsExtra = 0
        wc.cbWndExtra = 0
        wc.hInstance = hinst
        wc.hIcon = _load_icon(self.icon_path)
        wc.hCursor = None
        wc.hbrBackground = None
        wc.lpszMenuName = None
        wc.lpszClassName = self._cls_name
        if not user32.RegisterClassW(ctypes.byref(wc)):
            err = ctypes.get_last_error()
            if err != ERROR_CLASS_ALREADY_EXISTS:
                raise OSError(f"RegisterClassW 失败 (err={err})")
        # 隐藏窗口：只为接收托盘回调消息，不显示
        self._hwnd = user32.CreateWindowExW(
            0, self._cls_name, "FileGuard", 0, 0, 0, 0, 0, None, None, hinst, None)
        if not self._hwnd:
            raise OSError(f"CreateWindowExW 失败 (err={ctypes.get_last_error()})")

    def _destroy_window(self) -> None:
        hwnd, self._hwnd = self._hwnd, None
        if hwnd:
            try:
                user32.DestroyWindow(hwnd)
            except Exception:
                pass
        try:
            if getattr(self, "_cls_name", ""):
                user32.UnregisterClassW(self._cls_name, kernel32.GetModuleHandleW(None))
        except Exception:
            pass

    def _message_loop(self) -> None:
        msg = wt.MSG()
        try:
            while True:
                r = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if r == 0 or r == -1:                 # WM_QUIT / 出错
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            self._nid_call(NIM_DELETE, 0)
            self._destroy_window()
            self._ok = False

    def _on_message(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_TRAY:
                if lparam in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                    self.actions.put("show")
                elif lparam in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    self._popup_menu()
            elif msg == 0x0010:                       # WM_CLOSE
                user32.PostQuitMessage(0)
                return 0
        except Exception:
            pass
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _popup_menu(self) -> None:
        hmenu = user32.CreatePopupMenu()
        if not hmenu:
            return
        ids = {}
        try:
            for i, (label, action) in enumerate(self.menu):
                if label == "-":
                    user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
                    continue
                cid = 1000 + i
                ids[cid] = action
                user32.AppendMenuW(hmenu, MF_STRING, cid, label)
            pt = wt.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetForegroundWindow(self._hwnd)
            cmd = user32.TrackPopupMenu(hmenu, TPM_RIGHTBUTTON | TPM_RETURNCMD,
                                        pt.x, pt.y, 0, self._hwnd, None)
            # 经典要求：菜单关闭后给窗口发个空消息，否则菜单会残留
            user32.PostMessageW(self._hwnd, WM_NULL, 0, 0)
            if cmd in ids:
                self.actions.put(ids[cmd])
        finally:
            user32.DestroyMenu(hmenu)


def tray_icon_path() -> str:
    """找托盘用的 .ico 文件：随包资源 → exe 同目录 → 源码目录。

    找不到也不影响显示：_load_icon() 会退回 exe 内嵌图标 / 系统默认图标。
    """
    cands = []
    try:
        from . import paths
        cands.append(paths.resource_path("assets", "fileguard.ico"))
        cands.append(os.path.join(paths.base_dir(), "assets", "fileguard.ico"))
    except Exception:
        pass
    cands.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              os.pardir, "assets", "fileguard.ico"))
    for p in cands:
        if p and os.path.isfile(p):
            return os.path.normpath(p)
    return ""


def _selftest() -> int:                                   # pragma: no cover
    """手工验证：python -m app.tray 会在托盘挂 5 秒。"""
    t = TrayIcon("FileGuard 托盘自测", icon_path=tray_icon_path())
    ok = t.start()
    print("tray start:", ok)
    end = time.time() + 5
    while time.time() < end:
        for a in t.poll():
            print("action:", a)
        time.sleep(0.2)
    t.stop()
    print("tray stopped")
    return 0 if ok else 1


if __name__ == "__main__":                               # pragma: no cover
    raise SystemExit(_selftest())
