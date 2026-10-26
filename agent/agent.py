#!/usr/bin/env python3
"""Web Signer Agent — cầu nối duy nhất giữa server và USB token.

Agent chủ động mở WebSocket ra server và giữ kết nối, nên browser không bao giờ
phải gọi vào máy người dùng.

Agent không biết PDF là gì. Nó chỉ nhận vài trăm byte signed attributes, đưa
token ký bằng thuật toán server chỉ định, rồi trả chữ ký về.

Nguồn khoá:
  --cng                  Windows Certificate Store (token VN đều có minidriver)
  --pkcs11 <driver.so>   USB token qua driver PKCS#11 của nhà cung cấp
  --pfx <file.pfx>       tệp PFX, dùng khi chưa có token để thử luồng
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import hashlib
import json
import os
import random
import socket
import sys
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import pkcs12

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config  # noqa: E402
from keysource import (  # noqa: E402
    CertEntry,
    KeySource,
    KeySourceError,
    SigAlgo,
    cert_id_for,
    ecdsa_raw_to_der,
    pss_salt_length,
    rfc4514_cn,
)

DEFAULT_SERVER = config.DEFAULT_SERVER

# Nối lại sau khi rớt: nhanh ở lần đầu, giãn dần để không nã server đang khởi
# động lại.
RECONNECT_MIN_SECONDS = 1.0
RECONNECT_MAX_SECONDS = 30.0

# Danh tính máy: cấp một lần, dùng mãi (xem agent/config.py). Nhờ nó trình
# duyệt đã kích hoạt không phải gõ mã ghép cặp nữa.
DEFAULT_DEVICE_FILE = config.DEFAULT_CONFIG_FILE


def http_base(server_url: str) -> str:
    """ws://host/ws/agent -> http://host. Agent chỉ cấu hình đúng một URL."""
    base = server_url.split("/ws/agent", 1)[0]
    if base.startswith("wss://"):
        return "https://" + base[len("wss://") :]
    if base.startswith("ws://"):
        return "http://" + base[len("ws://") :]
    return base


def _post_json(url: str, payload: dict, timeout: float = 10.0) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "WebSignerAgent/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    return json.loads(raw) if raw else {}


def register_device(server_url: str, token: str, label: str) -> dict:
    """Ghi danh máy với server. -> {'device': …, 'activate_url': …}"""
    return _post_json(
        f"{http_base(server_url)}/api/devices",
        {
            "token": token,
            "name": f"{socket.gethostname()} · {label}"[:120],
            "platform": sys.platform,
        },
    )


def new_activation(server_url: str, token: str) -> dict:
    """Xin liên kết kích hoạt mới cho một trình duyệt khác."""
    return _post_json(
        f"{http_base(server_url)}/api/devices/activation", {"token": token}
    )


# Thư viện PKCS#11 do phần mềm ký của các CA Việt Nam cài sẵn trên Windows.
# Tệp nằm trong System32 nên chỉ cần tên, không cần đường dẫn tuyệt đối.
WINDOWS_PKCS11_CANDIDATES = (
    "ica_csp11.dll",  # I-CA
    "eps2003csp11.dll",  # Feitian ePass2003 — Viettel-CA và nhiều CA khác
    "ShuttleCsp11_3003.dll",  # Feitian ePass3003
    "SignerPKCS11.dll",  # VNPT-CA
    "bkav_p11.dll",  # BKAV-CA
    "ncaP11.dll",  # Nacencomm / CA2
    "eTPKCS11.dll",  # SafeNet eToken
    "gclib.dll",  # Gemalto / Thales
    "opensc-pkcs11.dll",  # OpenSC nếu người dùng tự cài
)

UNIX_PKCS11_CANDIDATES = (
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/opt/homebrew/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/usr/local/lib/libcastle.dylib",
)


def discover_pkcs11() -> list[str]:
    """Tìm thư viện PKCS#11 đã cài sẵn trên máy.

    Trên Windows phần mềm ký của CA luôn cài kèm một DLL PKCS#11; dò theo tên
    thay vì bắt người dùng đi tìm đường dẫn.
    """
    if sys.platform != "win32":
        return [p for p in UNIX_PKCS11_CANDIDATES if Path(p).is_file()]

    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    return [
        str(system32 / name)
        for name in WINDOWS_PKCS11_CANDIDATES
        if (system32 / name).is_file()
    ]


# --------------------------------------------------------------------------
# Nguồn khoá: tệp PFX (chỉ để chạy thử)
# --------------------------------------------------------------------------


class PfxKeySource:
    label = "PFX (giả lập token)"

    def __init__(self, path: str, password: str | None):
        secret = (password or "").encode() or None
        key, cert, extra = pkcs12.load_key_and_certificates(
            open(path, "rb").read(), secret
        )
        if key is None or cert is None:
            raise KeySourceError(f"PFX {path} không chứa cặp khoá hợp lệ")
        self._key = key
        self._entry = CertEntry.build(
            cert.public_bytes(serialization.Encoding.DER),
            [c.public_bytes(serialization.Encoding.DER) for c in (extra or [])],
        )

    def certificates(self) -> list[CertEntry]:
        return [self._entry]

    def sign(
        self, cert_id: str, data: bytes, algo: SigAlgo, params: dict
    ) -> bytes:
        if cert_id != self._entry.cert_id:
            raise KeySourceError("cert_id không khớp chứng thư đang mở")
        if algo is SigAlgo.ECDSA_SHA256:
            return self._key.sign(data, ec.ECDSA(hashes.SHA256()))
        if algo is SigAlgo.RSA_PSS_SHA256:
            pad = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=pss_salt_length(params),
            )
            return self._key.sign(data, pad, hashes.SHA256())
        return self._key.sign(data, padding.PKCS1v15(), hashes.SHA256())


# --------------------------------------------------------------------------
# Nguồn khoá: USB token qua PKCS#11
# --------------------------------------------------------------------------


class Pkcs11KeySource:
    """Khoá riêng nằm trên token; token tự băm và tự ký.

    Không bám vào một token cố định: mỗi lần liệt kê hoặc ký đều dò lại slot.
    Người ký có thể rút token công ty này, cắm token công ty khác giữa chừng
    mà không phải khởi động lại agent — và cắm cùng lúc nhiều token cũng được.
    """

    label = "USB token (PKCS#11)"

    def __init__(
        self, module_path: str, pin: str | None, token_label: str | None = None
    ):
        import pkcs11  # import trễ: chỉ cần khi dùng token thật

        self._lib = pkcs11.lib(module_path)
        self._token_label = token_label
        self._default_pin = pin
        # PIN nhớ theo số sê-ri: mỗi token của mỗi công ty một PIN khác nhau.
        self._pins: dict[str, str] = {}
        # cert_id -> số sê-ri token đang giữ nó, điền lại mỗi lần liệt kê.
        self._owner: dict[str, str] = {}
        self.label = f"USB token (PKCS#11): {Path(module_path).name}"

    # ---- dò token --------------------------------------------------------

    def _tokens(self) -> list:
        """Mọi token đang cắm, dò lại từ đầu mỗi lần gọi."""
        return list(self._lib.get_tokens(token_label=self._token_label))

    @staticmethod
    def _serial(token) -> str:
        return str(token.serial.decode() if isinstance(token.serial, bytes)
                   else token.serial).strip()

    def _pin_for(self, token) -> str:
        serial = self._serial(token)
        if serial in self._pins:
            return self._pins[serial]
        if self._default_pin:
            return self._default_pin
        pin = getpass.getpass(f"PIN của token {token.label.strip()}: ")
        self._pins[serial] = pin
        return pin

    def _open(self, token):
        from pkcs11.exceptions import PinIncorrect

        try:
            return token.open(user_pin=self._pin_for(token))
        except PinIncorrect:
            # PIN đã nhớ không còn đúng (đổi token cùng sê-ri, hoặc gõ sai)
            self._pins.pop(self._serial(token), None)
            raise

    @staticmethod
    def _certs_on(session) -> dict[bytes, bytes]:
        from pkcs11 import Attribute, ObjectClass

        return {
            bytes(obj[Attribute.ID]): bytes(obj[Attribute.VALUE])
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})
        }

    # ---- giao diện KeySource --------------------------------------------

    def certificates(self) -> list[CertEntry]:
        from pkcs11 import Attribute, ObjectClass

        entries: list[CertEntry] = []
        self._owner.clear()
        errors: list[str] = []

        for token in self._tokens():
            serial = self._serial(token)
            try:
                with self._open(token) as session:
                    with_private_key = {
                        bytes(obj[Attribute.ID])
                        for obj in session.get_objects(
                            {Attribute.CLASS: ObjectClass.PRIVATE_KEY}
                        )
                    }
                    all_certs = self._certs_on(session)
            except Exception as exc:
                # Một token lỗi không được làm hỏng các token còn lại.
                errors.append(f"{token.label.strip()}: {exc}")
                continue

            chain = list(all_certs.values())
            for key_id, der in all_certs.items():
                if key_id not in with_private_key:
                    continue
                entry = CertEntry.build(der, chain)
                self._owner[entry.cert_id] = serial
                entries.append(entry)

        if not entries and errors:
            raise KeySourceError("; ".join(errors))
        return entries

    def sign(
        self, cert_id: str, data: bytes, algo: SigAlgo, params: dict
    ) -> bytes:
        from pkcs11 import MGF, Attribute, Mechanism, ObjectClass
        from pkcs11.exceptions import MechanismInvalid, MechanismParamInvalid

        if cert_id not in self._owner:
            self.certificates()  # token vừa được cắm lại, dò lại danh sách
        serial = self._owner.get(cert_id)
        if serial is None:
            raise KeySourceError(
                "Chứng thư này không còn trên token nào đang cắm — "
                "kiểm tra đã cắm đúng token chưa rồi bấm Kết nối lại"
            )

        token = next((t for t in self._tokens() if self._serial(t) == serial), None)
        if token is None:
            raise KeySourceError("Token giữ chứng thư này đã bị rút ra")

        with self._open(token) as session:
            key_id = next(
                (
                    kid
                    for kid, der in self._certs_on(session).items()
                    if cert_id_for(der) == cert_id
                ),
                None,
            )
            if key_id is None:
                raise KeySourceError("Không tìm thấy chứng thư tương ứng trên token")
            private_key = session.get_key(
                object_class=ObjectClass.PRIVATE_KEY, id=key_id
            )

            if algo is SigAlgo.RSA_PSS_SHA256:
                raw = private_key.sign(
                    data,
                    mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
                    mechanism_param=(
                        Mechanism.SHA256,
                        MGF.SHA256,
                        pss_salt_length(params),
                    ),
                )
                return bytes(raw)

            if algo is SigAlgo.ECDSA_SHA256:
                try:
                    raw = private_key.sign(data, mechanism=Mechanism.ECDSA_SHA256)
                except (MechanismInvalid, MechanismParamInvalid):
                    # Token đời cũ chỉ làm CKM_ECDSA trên bản băm có sẵn
                    raw = private_key.sign(
                        hashlib.sha256(data).digest(), mechanism=Mechanism.ECDSA
                    )
                return ecdsa_raw_to_der(bytes(raw))

            return bytes(private_key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS))


# --------------------------------------------------------------------------
# Vòng đời agent
# --------------------------------------------------------------------------


async def confirm(prompt: str) -> bool:
    loop = asyncio.get_running_loop()
    answer = await loop.run_in_executor(None, lambda: input(prompt).strip().lower())
    return answer in ("", "y", "yes", "c", "co")


class Agent:
    def __init__(
        self,
        source: KeySource,
        code: str,
        auto_approve: bool,
        device_token: str | None = None,
        paired: bool = False,
        approve=None,
        log=print,
    ):
        self.source = source
        self.code = code
        self.auto_approve = auto_approve
        self.device_token = device_token
        # Đã ghi danh máy: trình duyệt kích hoạt rồi thì không cần mã nữa, nên
        # chỉ nhắc mã như đường dự phòng.
        self.paired = paired
        # Cửa sổ agent thay hai cái này bằng hộp thoại và ô nhật ký của nó.
        self.approve = approve or self._approve_in_terminal
        self.log = log

    async def _approve_in_terminal(self, request: dict) -> bool:
        return await confirm("  Đồng ý ký? [Y/n] ")

    async def handle(self, message: dict) -> dict:
        kind = message.get("type")
        if kind == "list_certificates":
            entries = self.source.certificates()
            self.log(f"  → gửi {len(entries)} chứng thư cho server")
            return {"certificates": [e.describe() for e in entries]}

        if kind == "sign":
            return await self._handle_sign(message)

        raise KeySourceError(f"Yêu cầu không hỗ trợ: {kind}")

    async def _handle_sign(self, message: dict) -> dict:
        tbs = base64.b64decode(message["tbs_b64"])
        digest = hashlib.sha256(tbs).hexdigest()
        if digest != message.get("tbs_digest"):
            raise KeySourceError("Digest server gửi không khớp dữ liệu — từ chối ký")

        try:
            algo = SigAlgo(message.get("algo", SigAlgo.RSA_PKCS1_SHA256.value))
        except ValueError:
            raise KeySourceError(
                f"Thuật toán server yêu cầu không hỗ trợ: {message.get('algo')!r}"
            ) from None

        request = {
            "document_name": message.get("document_name"),
            "document_digest": message.get("document_digest"),
            "algo": algo.value,
            "tbs_bytes": len(tbs),
            "tbs_digest": digest,
        }
        self.log("")
        self.log("  ┌─ YÊU CẦU KÝ ──────────────────────────────────────────")
        self.log(f"  │ Tài liệu      : {request['document_name']}")
        self.log(f"  │ Hash tài liệu : {request['document_digest']}")
        self.log(f"  │ Thuật toán    : {algo.value}")
        self.log(f"  │ Dữ liệu ký    : {len(tbs)} byte, SHA-256 {digest[:32]}…")
        self.log("  └───────────────────────────────────────────────────────")

        if not self.auto_approve and not await self.approve(request):
            raise KeySourceError("Người dùng từ chối ký")

        loop = asyncio.get_running_loop()
        params = message.get("algo_params") or {}
        signature = await loop.run_in_executor(
            None, lambda: self.source.sign(message["cert_id"], tbs, algo, params)
        )
        self.log(f"  ✓ token trả về chữ ký {len(signature)} byte")
        return {"signature_b64": base64.b64encode(signature).decode()}

    def _print_pairing_code(self) -> None:
        self.log("")
        self.log("  ╔═══════════════════════════════════════╗")
        self.log(f"  ║   MÃ GHÉP CẶP:  {self.code}              ║")
        self.log("  ╚═══════════════════════════════════════╝")
        if self.paired:
            self.log("  Máy đã ghi danh — chỉ cần mã này nếu mở trên trình duyệt")
            self.log("  chưa kích hoạt (dùng nút “Kích hoạt trình duyệt”).")
        else:
            self.log("  Nhập mã này vào trang web để ghép cặp.")
        self.log("")

    async def _serve(self, ws) -> None:
        """Phục vụ yêu cầu cho tới khi server đóng kết nối."""
        await ws.send(
            json.dumps(
                {
                    "type": "hello",
                    "code": self.code,
                    "device_token": self.device_token,
                    "name": self.source.label,
                    "platform": sys.platform,
                }
            )
        )
        async for raw in ws:
            message = json.loads(raw)
            if message.get("type") == "ready":
                continue
            request_id = message.get("id")
            try:
                data = await self.handle(message)
                reply = {"id": request_id, "ok": True, "data": data}
            except Exception as exc:  # trả lỗi về server, giữ kết nối
                self.log(f"  ✗ {exc}")
                reply = {"id": request_id, "ok": False, "error": str(exc)}
            await ws.send(json.dumps(reply))

    async def run(self, server_url: str) -> None:
        """Giữ kết nối, tự nối lại khi rớt.

        Server khởi động lại (deploy, mạng chớp) là chuyện thường; agent chết
        theo thì người ký phải tự đi mở lại. Danh tính máy giữ nguyên nên
        trình duyệt đã kích hoạt không phải làm gì thêm.
        """
        delay = RECONNECT_MIN_SECONDS
        announced = False

        while True:
            try:
                async with websockets.connect(
                    server_url, max_size=4 * 1024 * 1024
                ) as ws:
                    self.log(f"Đã kết nối {server_url}")
                    if not announced:
                        self._print_pairing_code()
                        announced = True
                    delay = RECONNECT_MIN_SECONDS
                    await self._serve(ws)
                self.log("  Server đóng kết nối.")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.log(f"  Mất kết nối: {exc}")

            self.log(f"  Thử nối lại sau {delay:.0f}s…")
            await asyncio.sleep(delay)
            delay = min(delay * 2, RECONNECT_MAX_SECONDS)


def build_source(args: argparse.Namespace) -> KeySource:
    if args.cng:
        import cng

        if not cng.is_available():
            raise KeySourceError(
                "--cng chỉ chạy trên Windows. Trên hệ khác dùng --pkcs11."
            )
        return cng.WindowsCertStoreKeySource(
            store_name=args.cng_store, hardware_only=args.hardware_only
        )

    if args.pkcs11:
        driver = args.pkcs11
        if driver == "auto":
            found = discover_pkcs11()
            if not found:
                if sys.platform == "win32":
                    import cng

                    if cng.is_available():
                        return cng.WindowsCertStoreKeySource(
                            store_name=getattr(args, "cng_store", "MY"),
                            hardware_only=getattr(args, "hardware_only", True),
                        )
                raise KeySourceError(
                    "Không tìm thấy thư viện PKCS#11 nào đã cài. "
                    "Cài phần mềm ký của CA rồi thử lại, hoặc chỉ đúng đường dẫn."
                )
            driver = found[0]
            print(f"Dùng driver tự dò: {driver}")
            for other in found[1:]:
                print(f"  (còn có: {other})")
        # PIN hỏi khi thật sự mở token: mỗi công ty một token, một PIN khác.
        return Pkcs11KeySource(driver, args.pin, args.token_label)

    password = args.password
    if password is None:
        password = getpass.getpass("Mật khẩu PFX: ")
    return PfxKeySource(args.pfx, password)


def print_certificates(source: KeySource) -> int:
    entries = source.certificates()
    if not entries:
        print(
            "Không thấy chứng thư nào có khoá riêng.\n"
            "  • Token đã cắm chưa?\n"
            "  • Phần mềm ký của CA đã cài chưa? (nó đăng ký token vào Windows)\n"
            "  • Với --cng: thử bỏ --hardware-only, hoặc --cng-store MY",
            file=sys.stderr,
        )
        return 1
    for entry in entries:
        cert = entry.cert
        print(f"  • {rfc4514_cn(cert.subject.rfc4514_string())}")
        print(
            f"    cấp bởi {rfc4514_cn(cert.issuer.rfc4514_string())}, "
            f"hạn {cert.not_valid_after_utc:%d/%m/%Y}"
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Web Signer Agent")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument(
        "--cng", action="store_true", help="đọc Windows Certificate Store"
    )
    parser.add_argument("--cng-store", default="MY", help="tên store, mặc định MY")
    parser.add_argument(
        "--hardware-only",
        action="store_true",
        help="với --cng: chỉ nhận khoá nằm trên token/smartcard, bỏ khoá mềm",
    )
    parser.add_argument(
        "--pkcs11",
        metavar="DRIVER",
        help="đường dẫn thư viện PKCS#11, hoặc 'auto' để tự dò",
    )
    parser.add_argument("--token-label", help="nhãn token khi cắm nhiều thiết bị")
    parser.add_argument("--pin", help="PIN token (bỏ trống để nhập tay)")
    parser.add_argument("--pfx", help="tệp PFX dùng thay token khi chạy thử")
    parser.add_argument("--password", help="mật khẩu PFX")
    parser.add_argument("--code", help="mã ghép cặp cố định (mặc định ngẫu nhiên)")
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="ký không cần xác nhận — chỉ dùng khi chạy thử tự động",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="chỉ liệt kê chứng thư rồi thoát, không kết nối server",
    )
    parser.add_argument(
        "--find-drivers",
        action="store_true",
        help="liệt kê thư viện PKCS#11 tìm thấy trên máy rồi thoát",
    )
    parser.add_argument(
        "--device-file",
        default=str(DEFAULT_DEVICE_FILE),
        help=f"nơi lưu danh tính máy (mặc định {DEFAULT_DEVICE_FILE})",
    )
    parser.add_argument(
        "--activate-browser",
        action="store_true",
        help="mở lại liên kết kích hoạt để gắn thêm một trình duyệt",
    )
    parser.add_argument(
        "--no-activate",
        action="store_true",
        help="không tự mở trình duyệt khi ghi danh máy lần đầu",
    )
    args = parser.parse_args()

    if args.find_drivers:
        found = discover_pkcs11()
        print("\n".join(found) if found else "Không tìm thấy thư viện PKCS#11 nào.")
        return 0 if found else 1

    if not (args.cng or args.pkcs11 or args.pfx):
        parser.error("cần --cng, --pkcs11 <driver|auto> hoặc --pfx <file>")

    try:
        source = build_source(args)
    except Exception as exc:
        print(f"Không mở được nguồn khoá: {exc}", file=sys.stderr)
        return 1

    print(f"Nguồn khoá: {source.label}")
    try:
        status = print_certificates(source)
    except KeySourceError as exc:
        print(f"Không đọc được token: {exc}", file=sys.stderr)
        status = 1
    if args.list:
        return status
    # Chưa cắm token vẫn chạy tiếp: cắm vào rồi bấm "Kết nối" trên web là thấy.

    device_file = Path(args.device_file)
    # Mốc là "đã mở trang kích hoạt", không phải "tệp đã tồn tại": lần đầu
    # chạy mà server chưa lên thì lần sau vẫn phải mở.
    needs_activation = not config.browser_activated(device_file)
    device_token = config.device_token(device_file)
    paired = False
    try:
        info = register_device(args.server, device_token, source.label)
        paired = True
        print(f"Máy đã ghi danh: {info['device']['id']}")
        if args.activate_browser or (needs_activation and not args.no_activate):
            url = info["activate_url"]
            print(f"Mở trình duyệt để kích hoạt: {url}")
            webbrowser.open(url)
            config.mark_browser_activated(device_file)
    except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
        print(f"Chưa ghi danh được máy ({exc}) — vẫn dùng được mã ghép cặp.")

    agent = Agent(
        source,
        args.code or f"{random.randint(0, 999999):06d}",
        args.auto_approve,
        device_token=device_token if paired else None,
        paired=paired,
    )
    try:
        # run() tự nối lại, nên chỉ thoát khi người dùng dừng.
        asyncio.run(agent.run(args.server))
    except KeyboardInterrupt:
        print("\nĐã dừng agent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
