"""Dựng môi trường thật cho test end-to-end: CA, CRL, TSA, backend, agent.

Không mock gì cả. Chứng thư do openssl cấp, CRL phục vụ qua HTTP, dấu thời gian
do TSA RFC 3161 cấp, agent nói chuyện với backend qua WebSocket thật.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "bin" / "python"
STARTUP_TIMEOUT = 40.0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(predicate, what: str, timeout: float = STARTUP_TIMEOUT) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception:
            pass
        time.sleep(0.15)
    raise TimeoutError(f"Quá thời gian chờ: {what}")


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


# --------------------------------------------------------------------------
# HTTP client giữ cookie — mỗi phiên là một "người dùng" khác nhau
# --------------------------------------------------------------------------


class Client:
    def __init__(self, base: str):
        self.base = base
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def request(self, method: str, path: str, body=None, upload: bytes | None = None):
        """-> (http_status, payload). Lỗi HTTP trả về như dữ liệu, không raise."""
        url = self.base + path
        if upload is not None:
            boundary = "----websigner-e2e"
            head = (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="tai-lieu.pdf"\r\n'
                "Content-Type: application/pdf\r\n\r\n"
            ).encode()
            payload = head + upload + f"\r\n--{boundary}--\r\n".encode()
            req = urllib.request.Request(
                url,
                data=payload,
                method=method,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
        elif body is not None:
            req = urllib.request.Request(
                url,
                data=json.dumps(body).encode(),
                method=method,
                headers={"Content-Type": "application/json"},
            )
        else:
            req = urllib.request.Request(url, method=method)

        try:
            with self._opener.open(req, timeout=120) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else None
            except json.JSONDecodeError:
                return exc.code, {"detail": raw.decode("utf-8", "replace")}

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None, upload=None):
        return self.request("POST", path, body=body, upload=upload)

    def put(self, path, body):
        return self.request("PUT", path, body=body)

    def download(self, path: str) -> bytes:
        with self._opener.open(self.base + path, timeout=60) as response:
            return response.read()


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

    def client(self) -> Client:
        return Client(self.url)


class Lab:
    """Một môi trường hoàn chỉnh, dùng chung cho cả phiên test."""

    def __init__(self, workdir: pathlib.Path):
        self.data = workdir
        self.certs = workdir / "certs"
        self.trust = workdir / "trust"
        self.sample = workdir / "sample.pdf"
        self.main_port = free_port()
        self.tsa_port = free_port()
        self._processes: list[Process] = []

    # ---- dựng ------------------------------------------------------------

    def setup(self) -> None:
        self.data.mkdir(parents=True, exist_ok=True)
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

    # ---- tiến trình ------------------------------------------------------

    def _env(self, **extra: str) -> dict:
        return {
            "WEBSIGNER_DATA": str(self.data),
            "WEBSIGNER_TRUST_DIR": str(self.trust),
            "WEBSIGNER_TSA_URL": f"http://127.0.0.1:{self.tsa_port}/tsa",
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
                self._env(),
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
                self._env(**env),
                ROOT / "backend",
            )
        )
        wait_until(lambda: port_open(port), f"backend {name}:{port}")
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
                    *args,
                ],
                self._env(**(env or {})),
                ROOT,
            )
        )
        probe = Client(target.url)
        wait_until(
            lambda: probe.get(f"/api/agents/{code}/certificates")[0] == 200
            or not process.alive(),
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


# --------------------------------------------------------------------------
# Thao tác nghiệp vụ dùng lại nhiều lần
# --------------------------------------------------------------------------

BOX_LEFT = [65, 383, 238, 484]
BOX_RIGHT = [300, 383, 470, 484]


def upload(client: Client, pdf: bytes) -> str:
    status, doc = client.post("/api/documents", upload=pdf)
    assert status == 201, doc
    return doc["id"]


def first_cert(client: Client, code: str) -> str:
    status, data = client.get(f"/api/agents/{code}/certificates")
    assert status == 200, data
    return data["certificates"][0]["id"]


def sign(client: Client, path: str, code: str, box=BOX_LEFT, reason="Thử nghiệm"):
    """Ký qua `path` (đường chủ sở hữu hoặc đường liên kết mời)."""
    return client.post(
        f"{path}/sign",
        body={
            "agent_code": code,
            "cert_id": first_cert(client, code),
            "page": 1,
            "box": box,
            "reason": reason,
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
