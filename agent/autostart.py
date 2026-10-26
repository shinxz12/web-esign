"""Chạy agent cùng hệ điều hành — ba nền tảng, ba cơ chế riêng.

Không dùng dịch vụ hệ thống (service/daemon): agent cần chạy **trong phiên
đăng nhập của người dùng** thì mới đọc được token cắm vào máy họ và mới hiện
được hộp thoại xác nhận ký.

* Windows: khoá ``HKCU\\…\\CurrentVersion\\Run`` — không cần quyền admin.
* macOS:   ``~/Library/LaunchAgents/vn.websigner.agent.plist``.
* Linux:   ``~/.config/autostart/websigner-agent.desktop`` (XDG autostart).
"""

from __future__ import annotations

import plistlib
import subprocess
import sys
from pathlib import Path

APP_NAME = "WebSignerAgent"
LABEL = "vn.websigner.agent"

WINDOWS_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
MAC_PLIST = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
LINUX_DESKTOP = Path.home() / ".config" / "autostart" / "websigner-agent.desktop"


class AutostartError(RuntimeError):
    """Không bật/tắt được tự khởi động — báo nguyên văn cho người dùng."""


def command() -> list[str]:
    """Lệnh hệ điều hành sẽ chạy lúc đăng nhập.

    Bản đóng gói (.exe) tự nó là chương trình; chạy từ mã nguồn thì phải gọi
    qua python kèm đường dẫn ``gui.py``. ``--autoconnect`` để người dùng đăng
    nhập xong là token sẵn sàng, không phải bấm gì.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable, "--autoconnect"]
    return [
        sys.executable,
        str(Path(__file__).resolve().parent / "gui.py"),
        "--autoconnect",
    ]


def _quoted() -> str:
    return " ".join(f'"{part}"' for part in command())


def describe() -> str:
    """Nơi cơ chế tự khởi động được ghi — để hiện trong giao diện."""
    if sys.platform == "win32":
        return rf"HKCU\{WINDOWS_RUN_KEY}\{APP_NAME}"
    if sys.platform == "darwin":
        return str(MAC_PLIST)
    return str(LINUX_DESKTOP)


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------


def _win_set(enabled: bool) -> None:
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, WINDOWS_RUN_KEY, 0, winreg.KEY_SET_VALUE
    ) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _quoted())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass


def _win_enabled() -> bool:
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, WINDOWS_RUN_KEY, 0, winreg.KEY_READ
        ) as key:
            winreg.QueryValueEx(key, APP_NAME)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# macOS
# --------------------------------------------------------------------------


def _mac_set(enabled: bool) -> None:
    if not enabled:
        if MAC_PLIST.exists():
            subprocess.run(
                ["launchctl", "unload", str(MAC_PLIST)],
                capture_output=True,
                check=False,
            )
            MAC_PLIST.unlink()
        return

    MAC_PLIST.parent.mkdir(parents=True, exist_ok=True)
    MAC_PLIST.write_bytes(
        plistlib.dumps(
            {
                "Label": LABEL,
                "ProgramArguments": command(),
                "RunAtLoad": True,
                # Treo một lần không được tự nã lại liên tục; agent đã có vòng
                # nối lại riêng bên trong.
                "KeepAlive": False,
            }
        )
    )
    subprocess.run(
        ["launchctl", "load", str(MAC_PLIST)], capture_output=True, check=False
    )


# --------------------------------------------------------------------------
# Linux (XDG autostart)
# --------------------------------------------------------------------------


def _linux_set(enabled: bool) -> None:
    if not enabled:
        LINUX_DESKTOP.unlink(missing_ok=True)
        return

    LINUX_DESKTOP.parent.mkdir(parents=True, exist_ok=True)
    LINUX_DESKTOP.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        "Comment=Cầu nối USB token cho Web Signer\n"
        f"Exec={_quoted()}\n"
        "Terminal=false\n"
        "X-GNOME-Autostart-enabled=true\n",
        encoding="utf-8",
    )


# --------------------------------------------------------------------------
# API chung
# --------------------------------------------------------------------------


def is_enabled() -> bool:
    if sys.platform == "win32":
        return _win_enabled()
    if sys.platform == "darwin":
        return MAC_PLIST.is_file()
    return LINUX_DESKTOP.is_file()


def set_enabled(enabled: bool) -> None:
    try:
        if sys.platform == "win32":
            _win_set(enabled)
        elif sys.platform == "darwin":
            _mac_set(enabled)
        else:
            _linux_set(enabled)
    except OSError as exc:
        raise AutostartError(str(exc)) from exc
