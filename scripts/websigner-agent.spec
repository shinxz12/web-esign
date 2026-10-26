# -*- mode: python ; coding: utf-8 -*-
"""Đóng gói cửa sổ agent thành một tệp chạy trực tiếp.

    pyinstaller scripts/websigner-agent.spec        # ra dist/WebSignerAgent[.exe]

Một tệp, không console: người dùng cuối chỉ thấy cửa sổ. ``agent/`` nằm trong
``pathex`` vì các module trong đó import lẫn nhau theo tên phẳng
(``import config``, ``from agent import …``) y như khi chạy từ mã nguồn.
"""

import os

# SPECPATH do PyInstaller bơm vào: build được từ thư mục bất kỳ.
ROOT = os.path.dirname(SPECPATH)  # noqa: F821
AGENT = os.path.join(ROOT, "agent")


analysis = Analysis(
    [os.path.join(AGENT, "gui.py")],
    pathex=[AGENT],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Nguồn khoá nạp động theo nền tảng nên PyInstaller không tự thấy.
        "cng",
        "keysource",
        "pkcs11",
        "websockets",
        "tkinter",
    ],
    hookspath=[],
    runtime_hooks=[],
    # Không cần: chỉ làm phình tệp lên vài chục MB.
    excludes=["numpy", "PIL", "matplotlib", "pytest"],
    noarchive=False,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="WebSignerAgent",
    debug=False,
    strip=False,
    upx=False,
    console=False,  # .exe không bật cửa sổ đen
    disable_windowed_traceback=False,
    icon=None,
)
