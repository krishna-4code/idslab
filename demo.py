"""
demo.py — automated end-to-end proof of the challenge-response system.

Runs with no manual input and no pre-started server: it launches server.py on a
free port with a throw-away user store and a short challenge TTL, then drives the
same client code the CLI uses. Eight scenarios are reported, each printed as
[PASS]/[FAIL], followed by a summary. The process exits non-zero if any
scenario misbehaves, so it can be used as the project's verification step.

Scenarios
    1. server startup
    2. register alice (and reject a duplicate)
    3. successful login                      -> LOGIN SUCCESS
    4. replay the captured response          -> rejected (challenge already used)
    5. wrong password                        -> LOGIN FAILED
    6. expired challenge                     -> rejected
    7. tampered challenge signature          -> client aborts (fake-server detection)
    8. summary and exit status

Run:  python demo.py
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Tuple

import requests

try:  # Windows console (cp1252) cannot print nicer Unicode otherwise
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import client
from crypto_utils import compute_response, derive_verifier

PASSWORD = "correct-horse-battery-9"
WRONG_PASSWORD = "definitely-not-it"
USERNAME = "alice"
CHALLENGE_TTL = 3          # seconds; short so the expiry scenario is quick
BOOT_TIMEOUT = 20          # seconds to wait for the server to answer /api/status

_results: List[Tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str = "") -> bool:
    _results.append((name, passed, detail))
    suffix = f"  ({detail})" if detail else ""
    print(f"[{'PASS' if passed else 'FAIL'}] {name}{suffix}")
    return passed


def free_port() -> int:
    """Reserve an ephemeral localhost port for this run."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_server(port: int, workdir: str) -> subprocess.Popen:
    """Launch server.py with an isolated store/short TTL and wait until it is up."""
    env = os.environ.copy()
    env.update({
        "PORT": str(port),
        "CHALLENGE_TTL": str(CHALLENGE_TTL),
        "USERS_FILE": os.path.join(workdir, "users.json"),
        "PRIVATE_KEY_FILE": os.path.join(workdir, "server_private.pem"),
        "PUBLIC_KEY_FILE": os.path.join(workdir, "server_public.pem"),
    })
    server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.py")
    proc = subprocess.Popen([sys.executable, server_path], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + BOOT_TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("server process exited during startup")
        try:
            if requests.get(f"http://127.0.0.1:{port}/api/status", timeout=1).status_code == 200:
                return proc
        except requests.RequestException:
            time.sleep(0.2)
    raise RuntimeError("server did not become ready in time")


def flip_first_hex_byte(value: str) -> str:
    """Tamper helper: flip the first byte of a hex string to corrupt the signature."""
    return ("ff" if value[:2] != "ff" else "00") + value[2:]


class CountingSession(requests.Session):
    """A session that counts POSTs to /api/verify to prove none are made."""

    def __init__(self) -> None:
        super().__init__()
        self.verify_calls = 0

    def post(self, url: str, *args, **kwargs):  # type: ignore[override]
        if url.endswith("/api/verify"):
            self.verify_calls += 1
        return super().post(url, *args, **kwargs)


def main() -> int:
    print("=" * 72)
    print(" CHALLENGE-RESPONSE AUTH — END-TO-END DEMO")
    print("=" * 72)

    workdir = tempfile.mkdtemp(prefix="idslab-demo-")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    proc = None
    try:
        # --- 1. server startup -------------------------------------------------
        try:
            proc = start_server(port, workdir)
            record("1. server startup", True)
        except RuntimeError as exc:
            record("1. server startup", False, str(exc))
            return _finish()

        # --- 2. registration ---------------------------------------------------
        reg = client.perform_registration(USERNAME, PASSWORD, base_url=base)
        duplicate = client.perform_registration(USERNAME, PASSWORD, base_url=base)
        record("2. register alice (duplicate rejected)",
               bool(reg.get("success")) and "exist" in duplicate.get("message", "").lower(),
               f"register={reg.get('success')}")

        # --- 3. successful login ----------------------------------------------
        login = client.perform_login(USERNAME, PASSWORD, base_url=base)
        record("3. successful login -> LOGIN SUCCESS",
               login.success and login.status_code == 200 and bool(login.session_token),
               login.message)

        # --- 4. replay ---------------------------------------------------------
        replay = client.perform_replay(login.captured, base_url=base)
        record("4. replay of captured response blocked",
               replay.get("status_code") == 403 and not replay.get("success"),
               f"http={replay.get('status_code')}")

        # --- 5. wrong password -------------------------------------------------
        wrong = client.perform_login(USERNAME, WRONG_PASSWORD, base_url=base)
        record("5. wrong password -> LOGIN FAILED",
               (not wrong.success) and wrong.status_code == 401,
               f"http={wrong.status_code}")

        # --- 6. expired challenge ---------------------------------------------
        challenge_data = requests.post(f"{base}/api/request-challenge",
                                       json={"username": USERNAME}, timeout=10).json()
        expired_capture = {
            "username": USERNAME,
            "challenge": challenge_data["challenge"],
            "response": compute_response(
                derive_verifier(PASSWORD, challenge_data["salt"]),
                challenge_data["challenge"]),
        }
        time.sleep(CHALLENGE_TTL + 1)
        expired = client.perform_replay(expired_capture, base_url=base)
        record("6. expired challenge rejected",
               expired.get("status_code") == 410 and not expired.get("success"),
               f"http={expired.get('status_code')}")

        # --- 7. tampered signature (fake-server detection) --------------------
        counter = CountingSession()
        caught: Optional[Exception] = None
        try:
            client.perform_login(USERNAME, PASSWORD, base_url=base, session=counter,
                                 signature_transform=flip_first_hex_byte)
            caught = None
        except client.ServerSignatureError as exc:
            caught = exc
        record("7. tampered signature aborts before /api/verify",
               caught is not None and counter.verify_calls == 0,
               f"verify_calls={counter.verify_calls}")

    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)

    return _finish()


def _finish() -> int:
    # --- 8. summary -----------------------------------------------------------
    passed = sum(1 for _, ok, _ in _results if ok)
    total = len(_results)
    print("-" * 72)
    for name, ok, _ in _results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print("-" * 72)
    print(f"8. SUMMARY: {passed}/{total} scenarios passed "
          f"({sum(1 for _, ok, _ in _results if not ok)} failed)")
    if passed != total:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
