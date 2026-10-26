"""TSA RFC 3161 chạy local để thử đóng dấu thời gian.

Production phải trỏ `WEBSIGNER_TSA_URL` sang TSA thật của CA công cộng. Server
này chỉ tồn tại để chạy thử khi không có mạng hoặc không có hợp đồng TSA: nó
nhận đúng `application/timestamp-query`, trả `application/timestamp-reply`, nên
backend đi qua `HTTPTimeStamper` y như với TSA thật.

    .venv/bin/python scripts/tsa_server.py --port 8080
"""

from __future__ import annotations

import argparse
import pathlib
import sys

from asn1crypto import keys as asn1_keys
from asn1crypto import tsp
from asn1crypto import x509 as asn1_x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)
from fastapi import FastAPI, Request, Response
from pyhanko.sign.timestamps import DummyTimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def build_timestamper(pfx_path: pathlib.Path, password: str) -> DummyTimeStamper:
    key, cert, extra = pkcs12.load_key_and_certificates(
        pfx_path.read_bytes(), password.encode()
    )
    if key is None or cert is None:
        raise SystemExit(f"{pfx_path} không chứa cặp khoá TSA")

    registry = SimpleCertificateStore()
    registry.register_multiple(
        asn1_x509.Certificate.load(c.public_bytes(Encoding.DER))
        for c in (extra or [])
    )
    key_der = key.private_bytes(
        Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
    )
    return DummyTimeStamper(
        tsa_cert=asn1_x509.Certificate.load(cert.public_bytes(Encoding.DER)),
        tsa_key=asn1_keys.PrivateKeyInfo.load(key_der),
        certs_to_embed=registry,
    )


def build_app(timestamper: DummyTimeStamper) -> FastAPI:
    app = FastAPI(title="Demo TSA")

    @app.post("/tsa")
    async def issue(request: Request) -> Response:
        req = tsp.TimeStampReq.load(await request.body())
        reply = await timestamper.async_request_tsa_response(req)
        return Response(reply.dump(), media_type="application/timestamp-reply")

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description="TSA RFC 3161 cho môi trường test")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--pfx", default=str(REPO_ROOT / "data/certs/tsa.pfx"))
    parser.add_argument("--password", default="123456")
    args = parser.parse_args()

    pfx = pathlib.Path(args.pfx)
    if not pfx.is_file():
        print(f"Chưa có {pfx} — chạy ./scripts/make_test_certs.sh trước", file=sys.stderr)
        return 1

    import uvicorn

    print(f"TSA test: http://127.0.0.1:{args.port}/tsa")
    uvicorn.run(build_app(build_timestamper(pfx, args.password)),
                host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
