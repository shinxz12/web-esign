"""Cấu hình và danh tính máy của agent — một tệp JSON duy nhất.

``~/.websigner/agent.json`` giữ hai thứ:

``device_token``
    bí mật cấp một lần, chứng minh "tôi là máy X". Nhờ nó trình duyệt đã kích
    hoạt không phải gõ mã ghép cặp nữa.
``settings``
    lựa chọn người dùng đặt trong cửa sổ agent (server, nguồn khoá, PIN…), để
    lần sau bật lên là chạy tiếp, nhất là khi agent tự khởi động cùng máy.

Tệp để quyền 600: ai đọc được nó thì ghép được trình duyệt vào máy này.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
import sys
from typing import Any

# Mặc định trỏ thẳng hệ thống thật: người dùng cuối mở .exe lên là chạy, không
# phải gõ URL. Chạy local thì đổi trong cửa sổ agent, hoặc truyền
# --server ws://127.0.0.1:8000/ws/agent
DEFAULT_SERVER = "wss://web-signer.btngoc.io.vn/ws/agent"

CONFIG_DIR = Path(os.environ.get("WEBSIGNER_AGENT_HOME", Path.home() / ".websigner"))
DEFAULT_CONFIG_FILE = CONFIG_DIR / "agent.json"

# Chỉ những khoá này được ghi xuống đĩa — tránh lỡ tay lưu thêm thứ không nên.
SETTING_KEYS = (
    "server",
    "source",  # "cng" | "pkcs11" | "pfx"
    "pkcs11",
    "token_label",
    "pin",
    "save_pin",
    "cng_store",
    "hardware_only",
    "pfx",
    "pfx_password",
    "auto_start",
)

DEFAULT_SETTINGS: dict[str, Any] = {
    "server": DEFAULT_SERVER,
    "source": "cng" if sys.platform == "win32" else "pkcs11",
    "pkcs11": "auto",
    "token_label": "",
    "pin": "",
    "save_pin": False,
    "cng_store": "MY",
    "hardware_only": False,
    "pfx": "",
    "pfx_password": "",
    "auto_start": False,
}


def _read(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    try:
        path.chmod(0o600)
    except OSError:  # Windows không có chmod POSIX
        pass


def device_token(path: Path = DEFAULT_CONFIG_FILE) -> str:
    """Token máy, sinh mới và ghi lại nếu chưa có."""
    data = _read(path)
    token = data.get("device_token")
    if isinstance(token, str) and token:
        return token

    token = secrets.token_urlsafe(32)
    data["device_token"] = token
    _write(path, data)
    return token


def is_enrolled(path: Path = DEFAULT_CONFIG_FILE) -> bool:
    """Máy đã từng ghi danh chưa."""
    return bool(_read(path).get("device_token"))


def browser_activated(path: Path = DEFAULT_CONFIG_FILE) -> bool:
    """Đã mở trang kích hoạt trình duyệt lần nào chưa.

    Khác ``is_enrolled``: lần chạy đầu không gọi được server vẫn ghi
    ``device_token`` xuống đĩa, nên nếu lấy sự tồn tại của tệp làm mốc thì
    những lần sau không bao giờ tự mở trình duyệt nữa.
    """
    return bool(_read(path).get("browser_activated"))


def mark_browser_activated(path: Path = DEFAULT_CONFIG_FILE) -> None:
    data = _read(path)
    data["browser_activated"] = True
    _write(path, data)


def load_settings(path: Path = DEFAULT_CONFIG_FILE) -> dict[str, Any]:
    stored = _read(path).get("settings") or {}
    settings = dict(DEFAULT_SETTINGS)
    settings.update({k: v for k, v in stored.items() if k in SETTING_KEYS})
    return settings


def save_settings(settings: dict[str, Any], path: Path = DEFAULT_CONFIG_FILE) -> None:
    data = _read(path)
    kept = {k: v for k, v in settings.items() if k in SETTING_KEYS}
    if not kept.get("save_pin"):
        # Không tích "nhớ PIN" thì cả PIN lẫn mật khẩu PFX đều không chạm đĩa:
        # với đường PFX, mật khẩu chính là khoá riêng.
        kept["pin"] = ""
        kept["pfx_password"] = ""
    data["settings"] = kept
    _write(path, data)
