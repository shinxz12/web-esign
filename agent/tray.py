"""Khay hệ thống (System Tray) cho Web Signer Agent trên Windows.

Hiển thị biểu tượng ở góc phải thanh tác vụ khi agent chạy ẩn (silent/minimized):
- Nhấp chuột trái hoặc nhấp đúp: Mở/hiện cửa sổ Web Signer Agent.
- Nhấp chuột phải: Menu ngữ cảnh gồm "Mở Web Signer Agent" và "Thoát".
- Không phụ thuộc thư viện ngoài (sử dụng trực tiếp Win32 Shell_NotifyIcon qua ctypes).
"""

from __future__ import annotations

import sys
import threading
from typing import Callable

__all__ = ["TrayIcon"]


class TrayIcon:
    """Quản lý biểu tượng khay hệ thống Windows."""

    def __init__(
        self,
        tooltip: str = "Web Signer Agent",
        on_open: Callable[[], None] | None = None,
        on_quit: Callable[[], None] | None = None,
    ) -> None:
        self.tooltip = tooltip
        self.on_open = on_open
        self.on_quit = on_quit
        self._thread: threading.Thread | None = None
        self._hwnd: int = 0
        self._running: bool = False

    def is_alive(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if sys.platform != "win32":
            return
        if self.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, name="WebSignerTrayThread", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if sys.platform != "win32" or not self._running:
            return
        self._running = False
        if self._hwnd:
            import ctypes

            # Gửi WM_CLOSE để thoát vòng lặp GetMessage
            WM_CLOSE = 0x0010
            ctypes.windll.user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None
        self._hwnd = 0

    def _run_loop(self) -> None:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        shell32 = ctypes.windll.shell32
        kernel32 = ctypes.windll.kernel32

        LRESULT = ctypes.c_ssize_t
        WPARAM = ctypes.c_size_t
        LPARAM = ctypes.c_ssize_t

        WNDPROC = ctypes.WINFUNCTYPE(
            LRESULT, wintypes.HWND, wintypes.UINT, WPARAM, LPARAM
        )
        user32.DefWindowProcW.restype = LRESULT
        user32.DefWindowProcW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            WPARAM,
            LPARAM,
        ]

        WM_DESTROY = 0x0002
        WM_CLOSE = 0x0010
        WM_USER = 0x0400
        WM_TRAY = WM_USER + 55

        WM_LBUTTONUP = 0x0202
        WM_LBUTTONDBLCLK = 0x0203
        WM_RBUTTONUP = 0x0205

        NIM_ADD = 0x00000000
        NIM_MODIFY = 0x00000001
        NIM_DELETE = 0x00000002
        NIF_MESSAGE = 0x00000001
        NIF_ICON = 0x00000002
        NIF_TIP = 0x00000004

        MF_STRING = 0x0000
        MF_SEPARATOR = 0x0800
        TPM_RETURNCMD = 0x0100
        TPM_NONOTIFY = 0x0080
        TPM_RIGHTBUTTON = 0x0002

        ID_SHOW = 1001
        ID_QUIT = 1002

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT),
                ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256),
                ("uVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", ctypes.c_byte * 16),
                ("hBalloonIcon", wintypes.HICON),
            ]

        class POINT(ctypes.Structure):
            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

        class WNDCLASSEXW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT),
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HICON),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
                ("hIconSm", wintypes.HICON),
            ]

        def show_menu(hwnd: int) -> None:
            pt = POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetForegroundWindow(hwnd)

            h_menu = user32.CreatePopupMenu()
            try:
                user32.AppendMenuW(h_menu, MF_STRING, ID_SHOW, "Mở Web Signer Agent")
                user32.AppendMenuW(h_menu, MF_SEPARATOR, 0, None)
                user32.AppendMenuW(h_menu, MF_STRING, ID_QUIT, "Thoát")
                user32.SetMenuDefaultItem(h_menu, ID_SHOW, 0)

                cmd = user32.TrackPopupMenu(
                    h_menu,
                    TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                    pt.x,
                    pt.y,
                    0,
                    hwnd,
                    None,
                )
            finally:
                user32.DestroyMenu(h_menu)

            user32.PostMessageW(hwnd, 0, 0, 0)

            if cmd == ID_SHOW and self.on_open:
                self.on_open()
            elif cmd == ID_QUIT and self.on_quit:
                self.on_quit()

        def wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == WM_TRAY:
                event = lparam & 0xFFFF
                if event in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                    if self.on_open:
                        self.on_open()
                    return 0
                if event == WM_RBUTTONUP:
                    show_menu(hwnd)
                    return 0
            elif msg == WM_CLOSE:
                user32.DestroyWindow(hwnd)
                return 0
            elif msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        c_wnd_proc = WNDPROC(wnd_proc)
        h_instance = kernel32.GetModuleHandleW(None)
        class_name = f"WebSignerTray_{threading.get_ident()}"

        wndclass = WNDCLASSEXW()
        wndclass.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wndclass.lpfnWndProc = c_wnd_proc
        wndclass.hInstance = h_instance
        wndclass.lpszClassName = class_name

        atom = user32.RegisterClassExW(ctypes.byref(wndclass))
        if not atom:
            self._running = False
            return

        hwnd = user32.CreateWindowExW(
            0,
            class_name,
            "WebSignerTrayMsgWindow",
            0,
            0,
            0,
            0,
            0,
            None,
            None,
            h_instance,
            None,
        )
        if not hwnd:
            user32.UnregisterClassW(class_name, h_instance)
            self._running = False
            return

        self._hwnd = hwnd

        # Tìm biểu tượng ứng dụng từ sys.executable, hoặc fallback IDI_APPLICATION
        h_icon = 0
        try:
            h_icon = shell32.ExtractIconW(h_instance, sys.executable, 0)
        except Exception:
            pass
        if not h_icon or h_icon == 1:
            h_icon = user32.LoadIconW(0, 32512)  # IDI_APPLICATION

        nid = NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        nid.hWnd = hwnd
        nid.uID = 100
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = h_icon
        nid.szTip = self.tooltip[:127]

        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

        # Vòng lặp nhận thông điệp Win32 cho cửa sổ khay
        msg = wintypes.MSG()
        while self._running:
            res = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if res <= 0:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        # Dọn dẹp biểu tượng khỏi khay khi dừng
        shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
        user32.DestroyWindow(hwnd)
        user32.UnregisterClassW(class_name, h_instance)
        self._running = False
