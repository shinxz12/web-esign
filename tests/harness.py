"""Dựng môi trường thật cho test end-to-end: PostgreSQL, CA, CRL, TSA, SMTP,
người nhận webhook, backend, agent.

Không mock gì cả. Chứng thư do openssl cấp, CRL phục vụ qua HTTP, dấu thời gian
do TSA RFC 3161 cấp, agent nói chuyện với backend qua WebSocket thật, email đi
qua SMTP thật tới một hộp thư trong tiến trình test, webhook tới một HTTP server
thật. Mỗi phiên test dùng một cơ sở dữ liệu tạm, xoá khi xong.
"""

from __future__ import annotations

import hashlib
import hmac
import http.cookiejar
import json
import os
import pathlib
import secrets
import shutil
import socket
import socketserver
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "bin" / "python"
STARTUP_TIMEOUT = 40.0
# Kết nối quản trị để tạo/xoá cơ sở dữ liệu tạm cho mỗi phiên test.
ADMIN_DSN = os.environ.get("WEBSIGNER_TEST_ADMIN_DSN", "postgresql://127.0.0.1:5432/postgres")
PASSWORD = "mat-khau-thu-nghiem"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(predicate, what: str, timeout: float = STARTUP_TIMEOUT, interval: float = 0.15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception:
            pass
        time.sleep(interval)
    raise TimeoutError(f"Quá thời gian chờ: {what}")


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def postgres_available() -> bool:
    try:
        import psycopg

        with psycopg.connect(ADMIN_DSN, connect_timeout=3):
            return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# HTTP client: cookie + CSRF (giao diện) hoặc khoá API (hệ thống tích hợp)
# --------------------------------------------------------------------------


class Client:
    def __init__(self, base: str, *, api_key: str | None = None):
        self.base = base
        self.api_key = api_key
        self.csrf: str | None = None
        self.me: dict | None = None
        # Message của http.client: tra header không phân biệt hoa thường.
        self.last_headers = None
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(
        self,
        method: str,
        path: str,
        body=None,
        upload: bytes | None = None,
        form: dict | None = None,
        headers: dict | None = None,
        filename: str = "tai-lieu.pdf",
    ):
        """-> (http_status, payload). Lỗi HTTP trả về như dữ liệu, không raise."""
        url = self.base + path
        hdrs = dict(headers or {})
        data = None
        if upload is not None:
            boundary = "----websigner-" + uuid.uuid4().hex
            parts = [
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
                for name, value in (form or {}).items()
            ]
            parts.append(
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                    "Content-Type: application/octet-stream\r\n\r\n"
                ).encode()
                + upload
                + b"\r\n"
            )
            data = b"".join(parts) + f"--{boundary}--\r\n".encode()
            hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        if self.api_key:
            hdrs.setdefault("Authorization", f"Bearer {self.api_key}")
        elif self.csrf and method not in ("GET", "HEAD"):
            hdrs.setdefault("X-CSRF-Token", self.csrf)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)

        try:
            with self._opener.open(req, timeout=120) as response:
                self.last_headers = response.headers
                raw = response.read()
                if not raw:
                    return response.status, None
                try:
                    return response.status, json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return response.status, raw
        except urllib.error.HTTPError as exc:
            self.last_headers = exc.headers
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else None
            except json.JSONDecodeError:
                return exc.code, {"detail": raw.decode("utf-8", "replace")}

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body, **kw)

    def put(self, path, body):
        return self.request("PUT", path, body=body)

    def patch(self, path, body):
        return self.request("PATCH", path, body=body)

    def delete(self, path):
        return self.request("DELETE", path)

    def download(self, path: str) -> bytes:
        status, payload = self.get(path)
        assert status == 200 and isinstance(payload, bytes), (status, payload)
        return payload


# --------------------------------------------------------------------------
# Hộp thư SMTP và người nhận webhook chạy trong tiến trình test
# --------------------------------------------------------------------------


class _SmtpHandler(socketserver.StreamRequestHandler):
    """SMTP tối giản, đủ cho smtplib: EHLO, MAIL, RCPT, DATA, QUIT."""

    def handle(self) -> None:
        sink: SmtpSink = self.server.sink  # type: ignore[attr-defined]
        self.wfile.write(b"220 websigner-test ESMTP\r\n")
        rcpt: list[str] = []
        while line := self.rfile.readline():
            command = line.decode(errors="replace").strip()
            verb = command.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                self.wfile.write(b"250 websigner-test\r\n")
            elif verb == "MAIL":
                rcpt = []
                self.wfile.write(b"250 OK\r\n")
            elif verb == "RCPT":
                rcpt.append(command.split(":", 1)[1].strip().strip("<>"))
                self.wfile.write(b"250 OK\r\n")
            elif verb == "DATA":
                self.wfile.write(b"354 End with .\r\n")
                lines = []
                while (chunk := self.rfile.readline()) not in (b".\r\n", b""):
                    lines.append(chunk)
                import email

                message = email.message_from_bytes(b"".join(lines))
                body = message.get_payload(decode=True).decode("utf-8", "replace")
                subject = str(email.header.make_header(email.header.decode_header(message["Subject"])))
                with sink.lock:
                    sink.messages.extend({"to": r, "subject": subject, "body": body} for r in rcpt)
                self.wfile.write(b"250 Queued\r\n")
            elif verb == "QUIT":
                self.wfile.write(b"221 Bye\r\n")
                return
            else:
                self.wfile.write(b"250 OK\r\n")


@dataclass
class SmtpSink:
    port: int = field(default_factory=free_port)
    messages: list[dict] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def start(self) -> None:
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), _SmtpHandler)
        self.server.daemon_threads = True
        self.server.sink = self  # type: ignore[attr-defined]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def to(self, address: str) -> list[dict]:
        with self.lock:
            return [m for m in self.messages if m["to"] == address]

    def stop(self) -> None:
        self.server.shutdown()


class _HookHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        receiver: WebhookReceiver = self.server.receiver  # type: ignore[attr-defined]
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with receiver.lock:
            receiver.requests.append({"headers": dict(self.headers), "body": body})
            status = receiver.fail_next.pop(0) if receiver.fail_next else 200
        self.send_response(status)
        self.end_headers()

    def log_message(self, *args) -> None:
        pass


@dataclass
class WebhookReceiver:
    port: int = field(default_factory=free_port)
    requests: list[dict] = field(default_factory=list)
    fail_next: list[int] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook"

    def start(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), _HookHandler)
        self.server.receiver = self  # type: ignore[attr-defined]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def events(self, document_id: str | None = None) -> list[dict]:
        with self.lock:
            events = [json.loads(r["body"]) for r in self.requests]
        if document_id is None:
            return events
        return [e for e in events if e["data"].get("document", {}).get("id") == document_id]

    def stop(self) -> None:
        self.server.shutdown()


def verify_webhook_signature(secret: str, headers: dict, body: bytes) -> bool:
    """Đúng đoạn mã hệ thống tích hợp phải viết để kiểm chữ ký webhook."""
    parts = dict(p.split("=", 1) for p in headers["WebSigner-Signature"].split(","))
    expected = hmac.new(secret.encode(), parts["t"].encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts["v1"])


# --------------------------------------------------------------------------
# Tiến trình con
# --------------------------------------------------------------------------


class Process:
    def __init__(self, name: str, argv: list[str], env: dict, cwd: pathlib.Path):
        self.name = name
        self.log = pathlib.Path(env["WEBSIGNER_DATA"]) / f"{name}.log"
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.log.open("w")
        self.proc = subprocess.Popen(
            argv,
            env={**os.environ, **env},
            cwd=cwd,
            stdout=self._handle,
            stderr=subprocess.STDOUT,
        )

    def alive(self) -> bool:
        return self.proc.poll() is None

    def output(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._handle.close()


@dataclass
class Backend:
    process: Process
    port: int

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def client(self, **kwargs) -> Client:
        return Client(self.url, **kwargs)


class Lab:
    """Một môi trường hoàn chỉnh, dùng chung cho cả phiên test."""

    def __init__(self, workdir: pathlib.Path):
        self.data = workdir
        self.certs = workdir / "certs"
        self.trust = workdir / "trust"
        self.sample = workdir / "sample.pdf"
        self.main_port = free_port()
        self.tsa_port = free_port()
        self.db_name = f"websigner_e2e_{secrets.token_hex(4)}"
        self.db_url = ADMIN_DSN.rsplit("/", 1)[0] + "/" + self.db_name
        self.smtp = SmtpSink()
        self.hooks = WebhookReceiver()
        self._processes: list[Process] = []

    # ---- dựng ------------------------------------------------------------

    def setup(self) -> None:
        import psycopg

        self.data.mkdir(parents=True, exist_ok=True)
        with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{self.db_name}"')
        self.smtp.start()
        self.hooks.start()
        self._make_certs()
        self._make_sample()
        self.tsa = self._start_tsa()
        self.main = self.start_backend("backend", port=self.main_port)

    def _make_certs(self) -> None:
        crl_url = f"http://127.0.0.1:{self.main_port}/crl/demo-ca.crl"
        subprocess.run(
            [str(ROOT / "scripts" / "make_test_certs.sh"), str(self.certs)],
            env={**os.environ, "CRL_URL": crl_url},
            check=True,
            capture_output=True,
        )
        assert (self.trust / "demo-ca.crt").is_file(), "script không tạo trust store"

    def _make_sample(self) -> None:
        existing = ROOT / "data" / "samples" / "hop-dong-mau.pdf"
        if existing.is_file():
            shutil.copyfile(existing, self.sample)
            return
        subprocess.run(
            [str(PYTHON), str(ROOT / "scripts" / "make_sample_pdf.py"), str(self.sample)],
            check=True,
            capture_output=True,
        )

    def sql(self, query: str, params=()) -> list[tuple]:
        """Đi thẳng vào cơ sở dữ liệu: chỉnh gói, giả lập hết hạn, thử phá nhật ký."""
        import psycopg

        with psycopg.connect(self.db_url, autocommit=True) as conn:
            cur = conn.execute(query, params)
            return cur.fetchall() if cur.description else []

    # ---- tiến trình ------------------------------------------------------

    def env(self, **extra: str) -> dict:
        return {
            "WEBSIGNER_DATA": str(self.data),
            "WEBSIGNER_TRUST_DIR": str(self.trust),
            "WEBSIGNER_TSA_URL": f"http://127.0.0.1:{self.tsa_port}/tsa",
            "WEBSIGNER_DATABASE_URL": self.db_url,
            "WEBSIGNER_SECRET_KEY": "e2e-" + "k" * 40,
            "WEBSIGNER_WEBHOOK_ALLOW_PRIVATE": "1",
            "WEBSIGNER_SMTP_URL": f"smtp://127.0.0.1:{self.smtp.port}",
            # Agent in "Đã kết nối" ra log — phải thấy ngay, không chờ đầy bộ đệm.
            "PYTHONUNBUFFERED": "1",
            **extra,
        }

    def _track(self, process: Process) -> Process:
        self._processes.append(process)
        return process

    def _start_tsa(self) -> Process:
        process = self._track(
            Process(
                "tsa",
                [
                    str(PYTHON),
                    str(ROOT / "scripts" / "tsa_server.py"),
                    "--port",
                    str(self.tsa_port),
                    "--pfx",
                    str(self.certs / "tsa.pfx"),
                ],
                self.env(),
                ROOT,
            )
        )
        wait_until(lambda: port_open(self.tsa_port), f"TSA {self.tsa_port}")
        return process

    def start_backend(self, name: str, port: int | None = None, **env: str) -> Backend:
        port = port or free_port()
        process = self._track(
            Process(
                name,
                [
                    str(PYTHON),
                    "-m",
                    "uvicorn",
                    "app.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--log-level",
                    "warning",
                ],
                self.env(**env),
                ROOT / "backend",
            )
        )
        wait_until(
            lambda: port_open(port) or not process.alive(), f"backend {name}:{port}"
        )
        if not process.alive():
            raise RuntimeError(f"backend {name} chết:\n{process.output()}")
        return Backend(process, port)

    def start_agent(
        self,
        code: str,
        *args: str,
        backend: Backend | None = None,
        env: dict | None = None,
    ) -> Process:
        target = backend or self.main
        process = self._track(
            Process(
                f"agent-{code}",
                [
                    str(PYTHON),
                    str(ROOT / "agent" / "agent.py"),
                    "--server",
                    f"ws://127.0.0.1:{target.port}/ws/agent",
                    "--code",
                    code,
                    "--auto-approve",
                    # Danh tính máy nằm trong thư mục tạm của lab, và không
                    # được phép bật trình duyệt thật lên giữa lúc chạy test.
                    "--device-file",
                    str(self.data / f"device-{code}.json"),
                    "--no-activate",
                    *args,
                ],
                self.env(**(env or {})),
                ROOT,
            )
        )
        wait_until(
            lambda: "Đã kết nối" in process.output() or not process.alive(),
            f"agent {code}",
        )
        if not process.alive():
            raise RuntimeError(f"agent {code} chết:\n{process.output()}")
        return process

    def agent_with_pfx(self, code: str, pfx: str, **kwargs) -> Process:
        return self.start_agent(
            code,
            "--pfx",
            str(self.certs / pfx),
            "--password",
            "123456",
            **kwargs,
        )

    def teardown(self) -> None:
        for process in reversed(self._processes):
            process.stop()
        self.smtp.stop()
        self.hooks.stop()
        try:
            import psycopg

            with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
                conn.execute(f'DROP DATABASE IF EXISTS "{self.db_name}" WITH (FORCE)')
        except Exception:
            pass


# --------------------------------------------------------------------------
# Thao tác nghiệp vụ dùng lại nhiều lần
# --------------------------------------------------------------------------

BOX_LEFT = [65, 383, 238, 484]
BOX_RIGHT = [300, 383, 470, 484]

SIGNER_A = {"name": "Nguyễn Văn A", "tax_code": "0101234567"}
SIGNER_B = {"name": "Trần Thị Bích", "tax_code": "0107654321"}


def register(backend: Backend, *, plan: str | None = "enterprise", lab: Lab | None = None) -> Client:
    """Tổ chức mới + chủ tổ chức đã đăng nhập. Mặc định nâng lên gói không giới hạn
    để test không vấp hạn mức — test hạn mức tự hạ gói."""
    client = backend.client()
    email = f"owner-{uuid.uuid4().hex[:10]}@e2e.vn"
    status, me = client.post(
        "/api/auth/register",
        {"org_name": f"Công ty {email[:12]}", "name": "Chủ Tổ Chức", "email": email, "password": PASSWORD},
    )
    assert status == 201, me
    client.csrf, client.me = me["csrf_token"], me
    if plan and lab is not None:
        lab.sql("UPDATE organizations SET plan = %s WHERE id = %s", (plan, me["org"]["id"]))
    return client


def api_client(session: Client) -> Client:
    status, created = session.post("/api/org/api-keys", {"name": "ERP"})
    assert status == 201, created
    return Client(session.base, api_key=created["secret"])


def create_document(
    api: Client,
    pdf: bytes,
    recipients: list[dict],
    *,
    send: bool = True,
    headers: dict | None = None,
    **extra,
) -> dict:
    status, doc = api.post(
        "/v1/documents",
        upload=pdf,
        form={"data": json.dumps({"recipients": recipients, "send": send, **extra})},
        headers=headers,
    )
    assert status == 201, doc
    return doc


def invite_path(doc: dict, index: int) -> str:
    """Đường API của liên kết ký người nhận thứ ``index``."""
    token = doc["recipients"][index]["signing_url"].rsplit("/s/", 1)[1]
    return f"/api/sign/{token}"


def first_cert(client: Client, code: str) -> str:
    status, data = client.get(f"/api/agents/{code}/certificates")
    assert status == 200, data
    return data["certificates"][0]["id"]


def sign(client: Client, path: str, code: str, box=BOX_LEFT, page: int = 1, **options):
    """Ký qua liên kết người nhận ``path`` (``/api/sign/<token>``)."""
    return client.post(
        f"{path}/sign",
        body={
            "agent_code": code,
            "cert_id": first_cert(client, code),
            "page": page,
            "box": box,
            **options,
        },
    )


def softhsm_module() -> str | None:
    for candidate in (
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
    ):
        if pathlib.Path(candidate).is_file() and shutil.which("softhsm2-util"):
            return candidate
    return None


def cert_for(client: Client, code: str, subject: str) -> str:
    """cert_id của chứng thư có CN khớp — dùng khi agent cầm nhiều token."""
    status, data = client.get(f"/api/agents/{code}/certificates")
    assert status == 200, data
    for cert in data["certificates"]:
        if cert["subject"] == subject:
            return cert["id"]
    raise AssertionError(f"không thấy {subject} trong {data['certificates']}")


def make_softhsm_token(lab: Lab, pfx: str, label: str) -> dict:
    """Nạp một PFX vào token PKCS#11 ảo. -> env để chạy agent."""
    conf = lab.data / "softhsm" / "softhsm2.conf"
    subprocess.run(
        [
            str(ROOT / "scripts" / "make_softhsm_token.sh"),
            str(lab.certs / pfx),
            label,
        ],
        env={**os.environ, "WEBSIGNER_DATA": str(lab.data)},
        check=True,
        capture_output=True,
    )
    return {"SOFTHSM2_CONF": str(conf)}


def make_hybrid_pdf(pdf_bytes: bytes) -> bytes:
    """Thêm một revision dùng hybrid cross-reference vào PDF có sẵn.

    Cơ chế tương thích ngược của PDF 1.5: bảng xref cổ điển + ``/XRefStm``
    trỏ tới xref stream chứa phần còn lại. Word, Excel và nhiều máy in PDF
    đời cũ sinh ra kiểu này, và pyHanko ở chế độ strict từ chối ký.
    """
    import re

    prev_startxref = int(re.findall(rb"startxref\s+(\d+)", pdf_bytes)[-1])
    root_num, root_gen = re.findall(rb"/Root\s+(\d+)\s+(\d+)\s+R", pdf_bytes)[-1]
    size = int(re.findall(rb"/Size\s+(\d+)", pdf_bytes)[-1])
    root = f"{root_num.decode()} {root_gen.decode()} R"

    out = bytearray(pdf_bytes)
    if not out.endswith(b"\n"):
        out += b"\n"

    hidden_num, xrefstm_num = size, size + 1

    hidden_off = len(out)
    out += f"{hidden_num} 0 obj\n<< /Type /WebSignerHybridProbe >>\nendobj\n".encode()

    # Mục xref của đối tượng ẩn, chỉ tồn tại trong xref stream. W = [1 4 2].
    entry = bytes([1]) + hidden_off.to_bytes(4, "big") + (0).to_bytes(2, "big")
    xrefstm_off = len(out)
    out += (
        f"{xrefstm_num} 0 obj\n"
        f"<< /Type /XRef /Size {size + 2} /W [1 4 2] /Index [{hidden_num} 1] "
        f"/Root {root} /Length {len(entry)} >>\nstream\n"
    ).encode()
    out += entry + b"\nendstream\nendobj\n"

    table_off = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n"
    out += (
        f"trailer\n<< /Size {size + 2} /Root {root} "
        f"/Prev {prev_startxref} /XRefStm {xrefstm_off} >>\n"
        f"startxref\n{table_off}\n%%EOF\n"
    ).encode()
    return bytes(out)
