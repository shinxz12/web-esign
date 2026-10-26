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
import random
import sys
from pathlib import Path

import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import pkcs12

sys.path.insert(0, str(Path(__file__).resolve().parent))

from keysource import (  # noqa: E402
    CertEntry,
    KeySource,
    KeySourceError,
    SigAlgo,
    ecdsa_raw_to_der,
    pss_salt_length,
    rfc4514_cn,
)

DEFAULT_SERVER = "ws://127.0.0.1:8000/ws/agent"


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
    """Khoá riêng nằm trên token; token tự băm và tự ký."""

    label = "USB token (PKCS#11)"

    def __init__(self, module_path: str, pin: str, token_label: str | None = None):
        import pkcs11  # import trễ: chỉ cần khi dùng token thật

        lib = pkcs11.lib(module_path)
        tokens = list(lib.get_tokens(token_label=token_label))
        if not tokens:
            raise KeySourceError(
                "Không thấy token nào. Kiểm tra token đã cắm và driver đúng chưa."
            )
        self._token = tokens[0]
        self._pin = pin
        self.label = f"USB token: {self._token.label.strip()}"

    def _open(self):
        return self._token.open(user_pin=self._pin)

    @staticmethod
    def _certs_on(session) -> dict[bytes, bytes]:
        from pkcs11 import Attribute, ObjectClass

        return {
            bytes(obj[Attribute.ID]): bytes(obj[Attribute.VALUE])
            for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})
        }

    def certificates(self) -> list[CertEntry]:
        from pkcs11 import Attribute, ObjectClass

        with self._open() as session:
            with_private_key = {
                bytes(obj[Attribute.ID])
                for obj in session.get_objects(
                    {Attribute.CLASS: ObjectClass.PRIVATE_KEY}
                )
            }
            all_certs = self._certs_on(session)

        chain = list(all_certs.values())
        return [
            CertEntry.build(der, chain)
            for key_id, der in all_certs.items()
            if key_id in with_private_key
        ]

    def sign(
        self, cert_id: str, data: bytes, algo: SigAlgo, params: dict
    ) -> bytes:
        from pkcs11 import MGF, Attribute, Mechanism, ObjectClass
        from pkcs11.exceptions import MechanismInvalid, MechanismParamInvalid

        target = next((c for c in self.certificates() if c.cert_id == cert_id), None)
        if target is None:
            raise KeySourceError("Không tìm thấy chứng thư tương ứng trên token")

        with self._open() as session:
            key_id = next(
                kid
                for kid, der in self._certs_on(session).items()
                if der == target.cert_der
            )
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
    def __init__(self, source: KeySource, code: str, auto_approve: bool):
        self.source = source
        self.code = code
        self.auto_approve = auto_approve

    async def handle(self, message: dict) -> dict:
        kind = message.get("type")
        if kind == "list_certificates":
            entries = self.source.certificates()
            print(f"  → gửi {len(entries)} chứng thư cho server")
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

        print()
        print("  ┌─ YÊU CẦU KÝ ──────────────────────────────────────────")
        print(f"  │ Tài liệu      : {message.get('document_name')}")
        print(f"  │ Hash tài liệu : {message.get('document_digest')}")
        print(f"  │ Thuật toán    : {algo.value}")
        print(f"  │ Dữ liệu ký    : {len(tbs)} byte, SHA-256 {digest[:32]}…")
        print("  └───────────────────────────────────────────────────────")

        if not self.auto_approve and not await confirm("  Đồng ý ký? [Y/n] "):
            raise KeySourceError("Người dùng từ chối ký")

        loop = asyncio.get_running_loop()
        params = message.get("algo_params") or {}
        signature = await loop.run_in_executor(
            None, lambda: self.source.sign(message["cert_id"], tbs, algo, params)
        )
        print(f"  ✓ token trả về chữ ký {len(signature)} byte")
        return {"signature_b64": base64.b64encode(signature).decode()}

    async def run(self, server_url: str) -> None:
        async with websockets.connect(server_url, max_size=4 * 1024 * 1024) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "hello",
                        "code": self.code,
                        "name": self.source.label,
                        "platform": sys.platform,
                    }
                )
            )
            print(f"Đã kết nối {server_url}")
            print()
            print("  ╔═══════════════════════════════════════╗")
            print(f"  ║   MÃ GHÉP CẶP:  {self.code}              ║")
            print("  ╚═══════════════════════════════════════╝")
            print("  Nhập mã này vào trang web để ghép cặp.")
            print()

            async for raw in ws:
                message = json.loads(raw)
                if message.get("type") == "ready":
                    continue
                request_id = message.get("id")
                try:
                    data = await self.handle(message)
                    reply = {"id": request_id, "ok": True, "data": data}
                except Exception as exc:  # trả lỗi về server, giữ kết nối
                    print(f"  ✗ {exc}")
                    reply = {"id": request_id, "ok": False, "error": str(exc)}
                await ws.send(json.dumps(reply))


def build_source(args: argparse.Namespace) -> KeySource:
    if args.cng:
        import cng

        if not cng.is_available():
            raise KeySourceError(
                "--cng chỉ chạy trên Windows. Trên hệ khác dùng --pkcs11."
            )
        return cng.WindowsCertStoreKeySource(
            store_name=args.cng_store, hardware_only=not args.allow_software_key
        )

    if args.pkcs11:
        pin = args.pin or getpass.getpass("PIN của token: ")
        return Pkcs11KeySource(args.pkcs11, pin, args.token_label)

    password = args.password
    if password is None:
        password = getpass.getpass("Mật khẩu PFX: ")
    return PfxKeySource(args.pfx, password)


def main() -> int:
    parser = argparse.ArgumentParser(description="Web Signer Agent")
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument(
        "--cng", action="store_true", help="đọc Windows Certificate Store"
    )
    parser.add_argument("--cng-store", default="MY", help="tên store, mặc định MY")
    parser.add_argument(
        "--allow-software-key",
        action="store_true",
        help="với --cng: nhận cả chứng thư khoá mềm, không chỉ token phần cứng",
    )
    parser.add_argument("--pkcs11", metavar="DRIVER", help="đường dẫn thư viện PKCS#11")
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
    args = parser.parse_args()

    if not (args.cng or args.pkcs11 or args.pfx):
        parser.error("cần --cng, --pkcs11 <driver> hoặc --pfx <file>")

    try:
        source = build_source(args)
    except Exception as exc:
        print(f"Không mở được nguồn khoá: {exc}", file=sys.stderr)
        return 1

    code = args.code or f"{random.randint(0, 999999):06d}"
    print(f"Nguồn khoá: {source.label}")
    for entry in source.certificates():
        cert = entry.cert
        print(f"  • {rfc4514_cn(cert.subject.rfc4514_string())}")
        print(
            f"    cấp bởi {rfc4514_cn(cert.issuer.rfc4514_string())}, "
            f"hạn {cert.not_valid_after_utc:%d/%m/%Y}"
        )

    agent = Agent(source, code, args.auto_approve)
    try:
        asyncio.run(agent.run(args.server))
    except KeyboardInterrupt:
        print("\nĐã dừng agent.")
    except OSError as exc:
        print(f"Không kết nối được server: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
