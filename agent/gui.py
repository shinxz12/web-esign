#!/usr/bin/env python3
"""Cửa sổ agent — bản dành cho người dùng cuối, đóng gói thành .exe.

Cùng một lõi với ``agent.py``: vẫn chỉ nhận vài trăm byte signed attributes,
vẫn hỏi token ký, không bao giờ thấy tài liệu. Khác ở ba chỗ:

* mọi tuỳ chọn nằm trong form, lưu lại ở ``~/.websigner/agent.json``;
* hộp thoại xác nhận cho từng lần ký thay cho câu hỏi trong terminal;
* bật được "chạy cùng Windows" ngay trong cửa sổ.

Chạy từ mã nguồn::

    .venv/bin/python agent/gui.py
"""

from __future__ import annotations

import argparse
import asyncio
import queue
import random
import sys
import threading
import tkinter as tk
import urllib.error
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

import autostart  # noqa: E402
import config  # noqa: E402
from agent import (  # noqa: E402
    Agent,
    build_source,
    discover_pkcs11,
    new_activation,
    register_device,
)
from keysource import rfc4514_cn  # noqa: E402

PAD = {"padx": 8, "pady": 4}


class AgentWindow:
    def __init__(self, root: tk.Tk, config_file: Path) -> None:
        self.root = root
        self.config_file = config_file
        self.settings = config.load_settings(config_file)
        self.device_token = config.device_token(config_file)
        self.device: dict | None = None

        # Vòng lặp asyncio chạy ở luồng riêng; Tk vẫn giữ luồng chính.
        self.loop = asyncio.new_event_loop()
        self.worker: threading.Thread | None = None
        self.task: asyncio.Task | None = None
        self.messages: queue.Queue[str] = queue.Queue()
        # Yêu cầu ký đang chờ người dùng bấm Đồng ý / Từ chối.
        self.approvals: queue.Queue[tuple[dict, object]] = queue.Queue()

        root.title("Web Signer Agent")
        root.geometry("640x560")
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._build()
        self._pump()

    # ---------------------------------------------------------------- giao diện

    def _build(self) -> None:
        form = ttk.LabelFrame(self.root, text="Kết nối")
        form.pack(fill="x", **PAD)

        self.var_server = tk.StringVar(value=self.settings["server"])
        ttk.Label(form, text="Server (ws:// hoặc wss://)").grid(
            row=0, column=0, sticky="w", **PAD
        )
        ttk.Entry(form, textvariable=self.var_server, width=52).grid(
            row=0, column=1, columnspan=2, sticky="we", **PAD
        )
        form.columnconfigure(1, weight=1)

        source = ttk.LabelFrame(self.root, text="Nguồn khoá")
        source.pack(fill="x", **PAD)
        source.columnconfigure(1, weight=1)

        self.var_source = tk.StringVar(value=self.settings["source"])
        for column, (value, label) in enumerate(
            (
                ("pkcs11", "USB token (PKCS#11)"),
                ("cng", "Windows Certificate Store"),
                ("pfx", "Tệp PFX (chạy thử)"),
            )
        ):
            ttk.Radiobutton(
                source,
                text=label,
                value=value,
                variable=self.var_source,
                command=self._sync_source,
            ).grid(row=0, column=column, sticky="w", **PAD)

        self.var_driver = tk.StringVar(value=self.settings["pkcs11"])
        self.row_driver = ttk.Label(source, text="Driver PKCS#11")
        self.row_driver.grid(row=1, column=0, sticky="w", **PAD)
        self.combo_driver = ttk.Combobox(source, textvariable=self.var_driver)
        self.combo_driver.grid(row=1, column=1, sticky="we", **PAD)
        ttk.Button(source, text="Dò driver", command=self.find_drivers).grid(
            row=1, column=2, sticky="w", **PAD
        )

        self.var_label = tk.StringVar(value=self.settings["token_label"])
        ttk.Label(source, text="Nhãn token (nhiều token)").grid(
            row=2, column=0, sticky="w", **PAD
        )
        ttk.Entry(source, textvariable=self.var_label).grid(
            row=2, column=1, sticky="we", **PAD
        )

        self.var_pin = tk.StringVar(value=self.settings["pin"])
        ttk.Label(source, text="PIN").grid(row=3, column=0, sticky="w", **PAD)
        ttk.Entry(source, textvariable=self.var_pin, show="•").grid(
            row=3, column=1, sticky="we", **PAD
        )
        self.var_save_pin = tk.BooleanVar(value=self.settings["save_pin"])
        ttk.Checkbutton(source, text="Nhớ PIN", variable=self.var_save_pin).grid(
            row=3, column=2, sticky="w", **PAD
        )

        self.var_store = tk.StringVar(value=self.settings["cng_store"])
        self.label_store = ttk.Label(source, text="Store (CNG)")
        self.label_store.grid(row=4, column=0, sticky="w", **PAD)
        self.entry_store = ttk.Entry(source, textvariable=self.var_store)
        self.entry_store.grid(row=4, column=1, sticky="we", **PAD)
        self.var_hardware = tk.BooleanVar(value=self.settings["hardware_only"])
        self.check_hardware = ttk.Checkbutton(
            source, text="Chỉ khoá trên token", variable=self.var_hardware
        )
        self.check_hardware.grid(row=4, column=2, sticky="w", **PAD)

        self.var_pfx = tk.StringVar(value=self.settings["pfx"])
        self.label_pfx = ttk.Label(source, text="Tệp PFX")
        self.label_pfx.grid(row=5, column=0, sticky="w", **PAD)
        self.entry_pfx = ttk.Entry(source, textvariable=self.var_pfx)
        self.entry_pfx.grid(row=5, column=1, sticky="we", **PAD)
        self.button_pfx = ttk.Button(source, text="Chọn…", command=self.pick_pfx)
        self.button_pfx.grid(row=5, column=2, sticky="w", **PAD)

        self.var_pfx_password = tk.StringVar(value=self.settings["pfx_password"])
        self.label_pfx_password = ttk.Label(source, text="Mật khẩu PFX")
        self.label_pfx_password.grid(row=6, column=0, sticky="w", **PAD)
        self.entry_pfx_password = ttk.Entry(
            source, textvariable=self.var_pfx_password, show="•"
        )
        self.entry_pfx_password.grid(row=6, column=1, sticky="we", **PAD)

        actions = ttk.Frame(self.root)
        actions.pack(fill="x", **PAD)
        self.button_start = ttk.Button(
            actions, text="Kết nối", command=self.toggle_connection
        )
        self.button_start.pack(side="left", padx=4)
        ttk.Button(
            actions, text="Xem chứng thư", command=self.show_certificates
        ).pack(side="left", padx=4)
        ttk.Button(
            actions, text="Kích hoạt trình duyệt", command=self.activate_browser
        ).pack(side="left", padx=4)

        self.var_autostart = tk.BooleanVar(value=autostart.is_enabled())
        ttk.Checkbutton(
            actions,
            text="Chạy khi khởi động máy",
            variable=self.var_autostart,
            command=self.toggle_autostart,
        ).pack(side="right", padx=4)

        self.status = ttk.Label(self.root, text="Chưa kết nối", anchor="w")
        self.status.pack(fill="x", **PAD)

        log_frame = ttk.LabelFrame(self.root, text="Nhật ký")
        log_frame.pack(fill="both", expand=True, **PAD)
        self.log_view = tk.Text(log_frame, height=12, wrap="word", state="disabled")
        self.log_view.pack(fill="both", expand=True, side="left")
        scroll = ttk.Scrollbar(log_frame, command=self.log_view.yview)
        scroll.pack(fill="y", side="right")
        self.log_view.configure(yscrollcommand=scroll.set)

        self._sync_source()

    def _sync_source(self) -> None:
        """Chỉ hiện những ô thuộc về nguồn khoá đang chọn."""
        kind = self.var_source.get()
        pkcs11 = kind == "pkcs11"
        for widget in (self.row_driver, self.combo_driver):
            widget.grid() if pkcs11 else widget.grid_remove()
        cng = kind == "cng"
        for widget in (self.label_store, self.entry_store, self.check_hardware):
            widget.grid() if cng else widget.grid_remove()
        pfx = kind == "pfx"
        for widget in (
            self.label_pfx,
            self.entry_pfx,
            self.button_pfx,
            self.label_pfx_password,
            self.entry_pfx_password,
        ):
            widget.grid() if pfx else widget.grid_remove()

    # ------------------------------------------------------------------ nhật ký

    def log(self, line: str) -> None:
        """Gọi được từ luồng asyncio: chỉ xếp hàng, Tk tự lấy ra."""
        self.messages.put(str(line))

    def _pump(self) -> None:
        """Mọi thao tác Tk đều chạy ở đây — luồng asyncio chỉ xếp hàng.

        Tk không an toàn đa luồng: gọi widget thẳng từ luồng kia thì khi chạy
        khi treo, tuỳ máy.
        """
        while True:
            try:
                line = self.messages.get_nowait()
            except queue.Empty:
                break
            self.log_view.configure(state="normal")
            self.log_view.insert("end", line + "\n")
            self.log_view.see("end")
            self.log_view.configure(state="disabled")

        while True:
            try:
                request, reply = self.approvals.get_nowait()
            except queue.Empty:
                break
            reply(self._ask_dialog(request))

        self.root.after(120, self._pump)

    def _ask_dialog(self, request: dict) -> bool:
        return messagebox.askyesno(
            "Yêu cầu ký số",
            "Một trang web đang xin chữ ký của bạn.\n\n"
            f"Tài liệu: {request['document_name']}\n"
            f"Hash tài liệu: {request['document_digest']}\n"
            f"Thuật toán: {request['algo']}\n"
            f"Dữ liệu ký: {request['tbs_bytes']} byte\n\n"
            "Đồng ý ký?",
        )

    # --------------------------------------------------------------- tuỳ chọn

    def current_settings(self) -> dict:
        return {
            "server": self.var_server.get().strip(),
            "source": self.var_source.get(),
            "pkcs11": self.var_driver.get().strip(),
            "token_label": self.var_label.get().strip(),
            "pin": self.var_pin.get(),
            "save_pin": self.var_save_pin.get(),
            "cng_store": self.var_store.get().strip() or "MY",
            "hardware_only": self.var_hardware.get(),
            "pfx": self.var_pfx.get().strip(),
            "pfx_password": self.var_pfx_password.get(),
            "auto_start": self.var_autostart.get(),
        }

    def save(self) -> dict:
        settings = self.current_settings()
        config.save_settings(settings, self.config_file)
        return settings

    def as_args(self, settings: dict) -> argparse.Namespace:
        """Dựng đúng Namespace mà ``agent.build_source`` chờ đợi."""
        kind = settings["source"]
        return argparse.Namespace(
            cng=kind == "cng",
            cng_store=settings["cng_store"],
            hardware_only=settings["hardware_only"],
            pkcs11=settings["pkcs11"] or "auto" if kind == "pkcs11" else None,
            token_label=settings["token_label"] or None,
            pin=settings["pin"] or None,
            pfx=settings["pfx"] if kind == "pfx" else None,
            password=settings["pfx_password"] or None,
        )

    def pick_pfx(self) -> None:
        path = filedialog.askopenfilename(
            title="Chọn tệp PFX", filetypes=[("PKCS#12", "*.pfx *.p12"), ("Tất cả", "*")]
        )
        if path:
            self.var_pfx.set(path)

    def find_drivers(self) -> None:
        found = discover_pkcs11()
        self.combo_driver["values"] = ["auto", *found]
        if found:
            self.log(f"Tìm thấy {len(found)} driver PKCS#11:")
            for item in found:
                self.log(f"  • {item}")
        else:
            self.log("Không tìm thấy driver PKCS#11 nào đã cài trên máy.")

    def toggle_autostart(self) -> None:
        enabled = self.var_autostart.get()
        try:
            autostart.set_enabled(enabled)
        except autostart.AutostartError as exc:
            self.var_autostart.set(not enabled)
            messagebox.showerror("Không đổi được tự khởi động", str(exc))
            return
        self.log(
            f"{'Bật' if enabled else 'Tắt'} chạy cùng hệ điều hành "
            f"({autostart.describe()})"
        )
        self.save()

    # ------------------------------------------------------------------ token

    def open_source(self, settings: dict):
        return build_source(self.as_args(settings))

    def show_certificates(self) -> None:
        settings = self.save()
        try:
            entries = self.open_source(settings).certificates()
        except Exception as exc:  # driver lỗi, chưa cắm token -> báo nguyên văn
            messagebox.showerror("Không đọc được token", str(exc))
            return
        if not entries:
            self.log("Chưa cắm token, hoặc token không có chứng thư nào.")
            return
        self.log(f"Token có {len(entries)} chứng thư:")
        for entry in entries:
            cert = entry.cert
            self.log(
                f"  • {rfc4514_cn(cert.subject.rfc4514_string())}"
                f" — hạn {cert.not_valid_after_utc:%d/%m/%Y}"
            )

    # --------------------------------------------------------------- kết nối

    def toggle_connection(self) -> None:
        if self.task is None:
            self.connect()
        else:
            self.disconnect()

    def connect(self) -> None:
        settings = self.save()
        try:
            source = self.open_source(settings)
        except Exception as exc:
            messagebox.showerror("Không mở được nguồn khoá", str(exc))
            return

        # Ghi danh máy trước: có device_id thì trình duyệt đã kích hoạt tự thấy
        # token, không cần mã ghép cặp.
        paired = False
        try:
            info = register_device(settings["server"], self.device_token, source.label)
            self.device = info["device"]
            paired = True
            self.log(f"Máy đã ghi danh: {self.device['name']} ({self.device['id']})")
            if not config.browser_activated(self.config_file):
                # Lần đầu: mở trình duyệt mặc định để nó nhận cookie thiết bị.
                self.log(f"Mở trình duyệt để kích hoạt: {info['activate_url']}")
                webbrowser.open(info["activate_url"])
                config.mark_browser_activated(self.config_file)
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            self.log(f"Chưa ghi danh được máy ({exc}) — vẫn dùng được mã ghép cặp.")

        agent = Agent(
            source,
            f"{random.randint(0, 999999):06d}",
            auto_approve=False,
            device_token=self.device_token if paired else None,
            paired=paired,
            approve=self.ask_approval,
            log=self.log,
        )

        if self.worker is None:
            self.worker = threading.Thread(target=self._run_loop, daemon=True)
            self.worker.start()
        self.task = asyncio.run_coroutine_threadsafe(
            agent.run(settings["server"]), self.loop
        )
        self.button_start.configure(text="Ngắt kết nối")
        self.status.configure(text=f"Đang chạy — {source.label}")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def disconnect(self) -> None:
        self._stop_task()
        self.button_start.configure(text="Kết nối")
        self.status.configure(text="Đã ngắt")
        self.log("Đã ngắt kết nối.")

    def _stop_task(self) -> None:
        """Huỷ vòng chạy và chờ nó kết thúc — tránh rác asyncio lúc thoát."""
        if self.task is None:
            return
        self.task.cancel()
        try:
            self.task.result(timeout=2)
        except Exception:
            pass  # huỷ xong, hoặc quá hạn: đằng nào cũng đang đóng
        self.task = None

    def activate_browser(self) -> None:
        """Mở liên kết kích hoạt để gắn thêm một trình duyệt vào máy này."""
        settings = self.save()
        try:
            info = new_activation(settings["server"], self.device_token)
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            messagebox.showerror(
                "Không xin được liên kết kích hoạt",
                f"{exc}\n\nKết nối tới server trước đã.",
            )
            return
        self.log(f"Mở trình duyệt để kích hoạt: {info['activate_url']}")
        webbrowser.open(info["activate_url"])

    # ----------------------------------------------------------- xác nhận ký

    async def ask_approval(self, request: dict) -> bool:
        """Hỏi người dùng — hộp thoại do vòng ``_pump`` ở luồng Tk dựng lên."""
        loop = asyncio.get_running_loop()
        answer: asyncio.Future[bool] = loop.create_future()

        def reply(ok: bool) -> None:
            loop.call_soon_threadsafe(answer.set_result, ok)

        self.approvals.put((request, reply))
        return await answer

    # -------------------------------------------------------------------- đóng

    async def _drain(self) -> None:
        """Huỷ nốt task phụ của websockets trước khi dừng vòng lặp."""
        current = asyncio.current_task()
        rest = [t for t in asyncio.all_tasks() if t is not current]
        for task in rest:
            task.cancel()
        await asyncio.gather(*rest, return_exceptions=True)

    def on_close(self) -> None:
        self.save()
        self._stop_task()
        if self.worker is not None:
            try:
                asyncio.run_coroutine_threadsafe(self._drain(), self.loop).result(2)
            except Exception:
                pass
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.worker.join(timeout=2)
        self.root.destroy()


def main() -> int:
    parser = argparse.ArgumentParser(description="Web Signer Agent (giao diện)")
    parser.add_argument(
        "--config", default=str(config.DEFAULT_CONFIG_FILE), help="tệp cấu hình"
    )
    parser.add_argument(
        "--autoconnect",
        action="store_true",
        help="kết nối ngay khi mở (dùng khi chạy cùng hệ điều hành)",
    )
    args = parser.parse_args()

    root = tk.Tk()
    window = AgentWindow(root, Path(args.config))
    if args.autoconnect:
        root.after(200, window.connect)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
