"""
client.py — command-line client for the Challenge-Response authentication system.

The password is read with getpass (never from argv) and never leaves this
machine: it is only turned into the verifier / HMAC response locally.

Usage:
    python client.py register <username>      prompt for a password, register
    python client.py login <username>         full challenge-response login
    python client.py replay <username>        valid login, then replay the capture
    python client.py attack-demo <username>   valid login + replay + wrong password

The server URL comes from the SERVER_URL environment variable, defaulting to
http://127.0.0.1:5000.

The reusable functions (perform_registration / perform_login / perform_replay)
are what demo.py drives, so the automated proof and the CLI exercise the exact
same code path.
"""
from __future__ import annotations

import getpass
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

import requests

try:  # Windows consoles default to cp1252, which cannot print non-ASCII text
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from crypto_utils import (
    compute_response,
    derive_verifier,
    generate_salt,
    public_key_from_pem,
    verify_signature,
)

DEFAULT_BASE_URL = "http://127.0.0.1:5000"


class LoginError(Exception):
    """The server refused an early login step (e.g. no challenge issued)."""


class ServerSignatureError(Exception):
    """The challenge signature did not verify — possible fake server / MITM.

    Raised *before* any response is sent, so a client never answers a server it
    could not authenticate.
    """


@dataclass
class LoginOutcome:
    """Result of a full login attempt, plus the capture needed to replay it."""

    status_code: int
    success: bool
    message: str
    session_token: Optional[str] = None
    challenge: str = ""
    captured: Dict[str, str] = field(default_factory=dict)


def _base_url(base_url: Optional[str]) -> str:
    return base_url or os.environ.get("SERVER_URL", DEFAULT_BASE_URL)


def _http(session: Optional[requests.Session]) -> requests.Session:
    return session if session is not None else requests


# --------------------------------------------------------------------------- #
# Reusable protocol steps (driven by both the CLI and demo.py)
# --------------------------------------------------------------------------- #

def perform_registration(username: str, password: str, *,
                         base_url: Optional[str] = None,
                         session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Register a user: derive salt + verifier locally and send only those.

    The plain password is never part of the request body.
    """
    salt = generate_salt()
    verifier = derive_verifier(password, salt)
    http = _http(session)
    reply = http.post(f"{_base_url(base_url)}/api/register",
                      json={"username": username, "salt": salt, "verifier": verifier},
                      timeout=10)
    return reply.json()


def perform_login(username: str, password: str, *,
                  base_url: Optional[str] = None,
                  session: Optional[requests.Session] = None,
                  signature_transform: Optional[Callable[[str], str]] = None
                  ) -> LoginOutcome:
    """Run the full three-step challenge-response login.

    1. request a signed single-use challenge;
    2. verify the server's RSA signature (abort if it fails);
    3. answer with HMAC-SHA256(verifier, challenge) and return the outcome.

    `signature_transform` lets tests tamper with the signature to prove the
    abort path; production callers leave it as None.
    """
    http = _http(session)
    base = _base_url(base_url)

    # Step 1: challenge
    challenge_reply = http.post(f"{base}/api/request-challenge",
                                json={"username": username}, timeout=10)
    challenge_data = challenge_reply.json()
    if not challenge_data.get("success"):
        raise LoginError(challenge_data.get("message", "no challenge issued"))

    challenge = challenge_data["challenge"]
    salt = challenge_data["salt"]
    signature = challenge_data["signature"]

    # Step 2: authenticate the server before trusting the challenge
    public_pem = http.get(f"{base}/api/public-key", timeout=10).json()["public_key"]
    public_key = public_key_from_pem(public_pem)
    if signature_transform is not None:
        signature = signature_transform(signature)
    if not verify_signature(public_key, challenge, signature):
        raise ServerSignatureError(
            "RSA signature over the challenge is invalid — possible fake server/MITM")

    # Step 3: derive locally and answer the challenge
    verifier = derive_verifier(password, salt)
    response = compute_response(verifier, challenge)
    captured = {"username": username, "challenge": challenge, "response": response}

    verify_reply = http.post(f"{base}/api/verify", json=captured, timeout=10)
    result = verify_reply.json()
    return LoginOutcome(
        status_code=verify_reply.status_code,
        success=bool(result.get("success")),
        message=result.get("message", ""),
        session_token=result.get("session_token"),
        challenge=challenge,
        captured=captured,
    )


def perform_replay(captured: Dict[str, str], *,
                   base_url: Optional[str] = None,
                   session: Optional[requests.Session] = None) -> Dict[str, Any]:
    """Re-submit a captured {username, challenge, response} to test replay defence."""
    http = _http(session)
    reply = http.post(f"{_base_url(base_url)}/api/verify", json=captured, timeout=10)
    return {"status_code": reply.status_code, **reply.json()}


# --------------------------------------------------------------------------- #
# CLI presentation
# --------------------------------------------------------------------------- #

def _tag(ok: bool) -> str:
    return "[OK]" if ok else "[FAIL]"


def do_register(username: str, password: str) -> Dict[str, Any]:
    print("CLIENT: deriving salt + PBKDF2 verifier locally (password stays here).")
    print("CLIENT: sending {username, salt, verifier} — no password in the request.")
    result = perform_registration(username, password)
    print(f"{_tag(bool(result.get('success')))} {result.get('message', '')}")
    return result


def do_login(username: str, password: str, label: str = "LOGIN") -> LoginOutcome:
    print(f"CLIENT: requesting a challenge for '{username}'.")
    try:
        outcome = perform_login(username, password)
    except ServerSignatureError as exc:
        print(f"[FAIL] {label}: {exc} — aborting, no response sent.")
        return LoginOutcome(0, False, str(exc))

    print("CLIENT: verified the server RSA signature before responding.")
    print("CLIENT: sent response = HMAC-SHA256(verifier, challenge) (32 bytes).")
    print(f"{_tag(outcome.success)} {label}: {outcome.message}")
    if outcome.session_token:
        print(f"       session_token={outcome.session_token[:24]}...")
    return outcome


def do_replay(captured: Dict[str, str]) -> Dict[str, Any]:
    print("ATTACKER: re-sending the previously captured {challenge, response}.")
    result = perform_replay(captured)
    blocked = not result.get("success")
    print(f"{_tag(blocked)} REPLAY {'BLOCKED' if blocked else 'ACCEPTED (BUG!)'}: "
          f"{result.get('message', '')}")
    return result


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(__doc__)
        return 1

    command, username = argv[0], argv[1]

    if command == "register":
        do_register(username, getpass.getpass("Password: "))
    elif command == "login":
        do_login(username, getpass.getpass("Password: "))
    elif command == "replay":
        password = getpass.getpass("Password (for the initial valid login): ")
        outcome = do_login(username, password)
        if outcome.captured:
            do_replay(outcome.captured)
    elif command == "attack-demo":
        password = getpass.getpass("Correct password: ")
        print("\n--- 1. valid login ---")
        outcome = do_login(username, password)
        if outcome.captured:
            print("\n--- 2. replay the captured response ---")
            do_replay(outcome.captured)
        print("\n--- 3. wrong password ---")
        do_login(username, "not-" + password, label="WRONG-PASSWORD LOGIN")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
