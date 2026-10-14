"""
crypto_utils.py — cryptographic primitives for the Challenge-Response auth system.

This module holds only cryptography helpers — no HTTP, Flask, request handling
or server state. It is the single source of truth for every primitive and is
imported by server.py, client.py and demo.py. (RSA key-file persistence lives
in load_or_create_rsa_keys here so every caller loads the identity identically.)

Primitives and WHY each is used
-------------------------------
* PBKDF2-HMAC-SHA256 (200,000 iterations + 16-byte random salt) to turn a
  password into a verifier. Key stretching makes offline guessing expensive;
  the per-user salt stops rainbow tables and makes identical passwords yield
  different verifiers.
* HMAC-SHA256 for the challenge response. HMAC needs a secret key (the
  verifier) and a message (the challenge); nobody can produce the response
  without the verifier, and the challenge never repeats.
* CSPRNG nonces (secrets) so an attacker cannot predict the next challenge.
* RSA-2048 PSS signatures so the client can prove the challenge came from the
  real server — this authenticates the SERVER and blocks fake-server / MITM.

Exact byte encodings (frozen contract — the browser WebCrypto code mirrors it)
-----------------------------------------------------------------------------
All values cross the network as lowercase hex strings. Before any primitive is
applied the hex is decoded to raw bytes:
  * PBKDF2 password  : password.encode("utf-8")
  * PBKDF2 salt      : bytes.fromhex(salt_hex)            (raw 16 bytes)
  * HMAC key         : bytes.fromhex(verifier_hex)        (raw 32 bytes)
  * HMAC message     : bytes.fromhex(challenge_hex)       (raw 32 bytes)
  * RSA sign/verify  : over bytes.fromhex(challenge_hex)  (raw 32 bytes)
  * RSA-PSS salt len : 32 bytes (SHA-256 digest size) so WebCrypto can verify
                       with crypto.subtle.verify({name:"RSA-PSS", saltLength:32}).
  * HMAC key should be at least the hash output length (32 bytes for
    HMAC-SHA256); the verifier is exactly 32 bytes, which satisfies that.

Run `python crypto_utils.py` to execute self_check(), which validates fixed
known-answer vectors plus every function against itself. The known-answer
vectors are also published in README/VIVA-GUIDE for the web UI self-test.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --------------------------------------------------------------------------- #
# Tunables / protocol constants
# --------------------------------------------------------------------------- #

PBKDF2_ITERATIONS = 200_000      # key-stretching work factor
PBKDF2_DIGEST = "sha256"         # PBKDF2-HMAC-SHA256
SALT_BYTES = 16                  # 128-bit random salt per user
VERIFIER_BYTES = 32              # SHA-256 output size
CHALLENGE_BYTES = 32             # 256-bit one-time nonce
RSA_KEY_SIZE = 2048              # RSA modulus size for the server identity
PSS_SALT_LENGTH = 32             # SHA-256 digest size; WebCrypto-compatible
SESSION_TOKEN_BYTES = 32         # entropy for session tokens

RSAPrivateKey = rsa.RSAPrivateKey
RSAPublicKey = rsa.RSAPublicKey


# --------------------------------------------------------------------------- #
# Password -> verifier (PBKDF2)
# --------------------------------------------------------------------------- #

def generate_salt(nbytes: int = SALT_BYTES) -> str:
    """Return a fresh random salt as hex.

    Why: every user needs a unique salt so that equal passwords never produce
    equal verifiers and precomputed tables (rainbow tables) are useless. The
    salt is not secret; it is stored and sent to the client during login.
    """
    return secrets.token_hex(nbytes)


def derive_verifier(password: str, salt_hex: str,
                    iterations: int = PBKDF2_ITERATIONS) -> str:
    """Derive the server-side password verifier, returned as hex.

        verifier = PBKDF2-HMAC-SHA256(key=password_utf8, salt=raw, iter)

    Encoding: the password is encoded as UTF-8, the salt is decoded from hex to
    raw bytes. Why: PBKDF2 with 200k iterations makes brute-forcing a stolen
    verifier expensive; the password itself never leaves the client, so the
    server stores only this one-way result.
    """
    raw_salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac(PBKDF2_DIGEST, password.encode("utf-8"),
                                  raw_salt, iterations, dklen=VERIFIER_BYTES)
    return derived.hex()


# --------------------------------------------------------------------------- #
# Challenge-response (HMAC)
# --------------------------------------------------------------------------- #

def generate_challenge(nbytes: int = CHALLENGE_BYTES) -> str:
    """Return a fresh CSPRNG challenge (nonce) as hex.

    Why: the challenge must be unpredictable and never repeat, otherwise an
    attacker could precompute a response or replay an old one. `secrets` is a
    cryptographically secure source; `random` is not suitable here.
    """
    return secrets.token_hex(nbytes)


def compute_response(verifier_hex: str, challenge_hex: str) -> str:
    """Return response = HMAC-SHA256(key=raw verifier, msg=raw challenge) hex.

    Encoding: both inputs are decoded from hex to raw bytes before use.

    Why: HMAC proves knowledge of the verifier without revealing it. Because
    the message is the one-time challenge, the same verifier produces a
    different response every login, so a captured response is useless later.
    """
    return hmac.new(bytes.fromhex(verifier_hex),
                    bytes.fromhex(challenge_hex),
                    hashlib.sha256).hexdigest()


def verify_response(stored_verifier_hex: str, challenge_hex: str,
                    client_response_hex: str) -> bool:
    """Recompute the expected HMAC and compare in constant time.

    The client response is untrusted input, so malformed hex (non-hex, odd
    length, non-ASCII) returns False instead of raising. Comparison is done on
    raw bytes: hmac.compare_digest avoids the timing side channel of `==`,
    which could otherwise leak how many leading bytes an attacker guessed.
    """
    try:
        provided = bytes.fromhex(client_response_hex)
    except (ValueError, TypeError):
        return False
    expected = bytes.fromhex(compute_response(stored_verifier_hex, challenge_hex))
    return hmac.compare_digest(expected, provided)


# --------------------------------------------------------------------------- #
# RSA server identity + signatures (extra mechanism)
# --------------------------------------------------------------------------- #

def load_or_create_rsa_keys(private_path: str,
                            public_path: str) -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """Load the server RSA keypair; the private key is the source of truth.

    Why: the server needs a stable private key so the public key clients verify
    against does not change between restarts (otherwise every restart would
    look like a new/fake server). If the private key exists the public key is
    derived from it and the public PEM is rewritten only when missing, so a
    deleted/corrupt public file self-heals without rotating the identity. A new
    pair is generated only when the private file is absent. The private key is
    written unencrypted in PEM for this lab (mode 0600 on POSIX); a production
    deployment would protect it with a KMS/HSM.
    """
    if os.path.exists(private_path):
        with open(private_path, "rb") as fh:
            private_key = serialization.load_pem_private_key(fh.read(), password=None)
        public_key = private_key.public_key()
        if not os.path.exists(public_path):
            with open(public_path, "wb") as fh:
                fh.write(public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ))
        return private_key, public_key

    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=RSA_KEY_SIZE)
    public_key = private_key.public_key()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(private_path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    if os.name == "posix":
        os.chmod(private_path, 0o600)
    with open(public_path, "wb") as fh:
        fh.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return private_key, public_key


def sign_challenge(private_key: RSAPrivateKey, challenge_hex: str) -> str:
    """RSA-PSS/SHA-256 sign the raw challenge bytes; return the signature as hex.

    Encoding: the challenge is decoded from hex and signed as raw bytes.

    Why: signing proves the challenge was minted by the holder of the server
    private key. The client checks this before answering, so a fake server that
    cannot sign is detected. PSS with salt length 32 (the SHA-256 digest size)
    is verified by browsers using WebCrypto's RSA-PSS with saltLength 32.
    """
    signature = private_key.sign(
        bytes.fromhex(challenge_hex),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=PSS_SALT_LENGTH),
        hashes.SHA256(),
    )
    return signature.hex()


def verify_signature(public_key: RSAPublicKey, challenge_hex: str,
                     signature_hex: str) -> bool:
    """Verify an RSA-PSS signature over the raw challenge bytes. Never raises.

    Why: verification happens on the untrusted client side, so malformed input
    must return False (treated as a fake server) instead of crashing the client.
    """
    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            bytes.fromhex(challenge_hex),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=PSS_SALT_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def public_key_to_pem(public_key: RSAPublicKey) -> str:
    """Serialise a public key to SubjectPublicKeyInfo PEM (for /api/public-key)."""
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_from_pem(pem_str: str) -> RSAPublicKey:
    """Parse a PEM public key fetched from the server's /api/public-key route."""
    return serialization.load_pem_public_key(pem_str.encode("ascii"))


# --------------------------------------------------------------------------- #
# Anti user-enumeration helper
# --------------------------------------------------------------------------- #

def derive_fake_salt(private_key: RSAPrivateKey, username: str,
                     nbytes: int = SALT_BYTES) -> str:
    """Return a deterministic decoy salt for an unknown username, as hex.

    Derivation: key = SHA-256(private key DER); fake_salt = HMAC-SHA256(key,
    b"fake-salt|" + username_utf8)[:nbytes]. The domain-separation prefix keeps
    this derivation separate from any other use of the same key. It is stable
    for a given key and username, so repeated enquiries look exactly like a real
    user's fixed salt, which removes the obvious "unknown user" signal that
    would let an attacker enumerate accounts. Because it is derived from the
    server private key, changing the key changes the decoys; the decoy is a
    decoy only and never authenticates anyone.
    """
    key = hashlib.sha256(private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )).digest()
    message = b"fake-salt|" + username.encode("utf-8")
    mac = hmac.new(key, message, hashlib.sha256).digest()
    return mac[:nbytes].hex()


def generate_session_token(nbytes: int = SESSION_TOKEN_BYTES) -> str:
    """Return a URL-safe random session token.

    Why: after a successful login the client gets an opaque, unguessable token
    instead of storing any password-derived secret.
    """
    return secrets.token_urlsafe(nbytes)


# --------------------------------------------------------------------------- #
# Self-check with fixed known-answer vectors
# --------------------------------------------------------------------------- #

KAT_PASSWORD = "Hunter2!KAT"
KAT_SALT_HEX = "00112233445566778899aabbccddeeff"
KAT_CHALLENGE_HEX = ("000102030405060708090a0b0c0d0e0f"
                     "101112131415161718191a1b1c1d1e1f")
KAT_VERIFIER_HEX = "48862173f52b431e679bd4e2f8aa45eb0809750a3746b751df719b372ae51b19"
KAT_RESPONSE_HEX = "d1f8af22935f2f9e0948efd5768ebbd646c4379119ce53a56917a94467e4fc9f"


def _check(label: str, condition: bool) -> bool:
    """Print one PASS/FAIL line and return the condition."""
    print(f"[{'PASS' if condition else 'FAIL'}] {label}")
    return condition


def _response_rejected_without_raising(client_response: str) -> bool:
    """True only if verify_response returns False for this input and never raises."""
    try:
        return verify_response(KAT_VERIFIER_HEX, KAT_CHALLENGE_HEX,
                               client_response) is False
    except Exception:
        return False


def self_check() -> bool:
    """Validate every primitive; the known-answer vectors are computed with the
    standard library directly (hashlib.pbkdf2_hmac / hmac.new) and hardcoded,
    so this test is independent of the functions it checks.

    Returns True when all checks pass and prints a line per check. Raisable on
    failure so callers can decide how to react (demo.py asserts on it).
    """
    print("crypto_utils self-check")
    print(f"  password  = {KAT_PASSWORD!r}")
    print(f"  salt_hex  = {KAT_SALT_HEX}")
    print(f"  challenge = {KAT_CHALLENGE_HEX}")

    results = []
    results.append(_check("derive_verifier matches known-answer vector",
                          derive_verifier(KAT_PASSWORD, KAT_SALT_HEX) == KAT_VERIFIER_HEX))
    results.append(_check("compute_response matches known-answer vector",
                          compute_response(KAT_VERIFIER_HEX, KAT_CHALLENGE_HEX)
                          == KAT_RESPONSE_HEX))
    results.append(_check("verify_response accepts the correct response",
                          verify_response(KAT_VERIFIER_HEX, KAT_CHALLENGE_HEX,
                                          KAT_RESPONSE_HEX)))
    results.append(_check("verify_response rejects a wrong response",
                          not verify_response(KAT_VERIFIER_HEX, KAT_CHALLENGE_HEX,
                                              "00" * 32)))
    results.append(_check("verify_response rejects non-hex without raising",
                          _response_rejected_without_raising("zz" * 32)))
    results.append(_check("verify_response rejects odd-length without raising",
                          _response_rejected_without_raising("0" * 63)))
    results.append(_check("verify_response rejects non-ASCII without raising",
                          _response_rejected_without_raising("\u00e9" * 32)))
    results.append(_check("generate_salt length is 16 bytes",
                          len(bytes.fromhex(generate_salt())) == SALT_BYTES))
    results.append(_check("generate_salt is random",
                          generate_salt() != generate_salt()))
    results.append(_check("generate_challenge length is 32 bytes",
                          len(bytes.fromhex(generate_challenge())) == CHALLENGE_BYTES))
    results.append(_check("generate_challenge is unique",
                          generate_challenge() != generate_challenge()))

    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=RSA_KEY_SIZE)
    public_key = private_key.public_key()
    signature = sign_challenge(private_key, KAT_CHALLENGE_HEX)
    results.append(_check("verify_signature accepts a valid signature",
                          verify_signature(public_key, KAT_CHALLENGE_HEX, signature)))
    tampered = ("ff" if signature[:2] != "ff" else "00") + signature[2:]
    results.append(_check("verify_signature rejects a tampered signature",
                          not verify_signature(public_key, KAT_CHALLENGE_HEX, tampered)))
    results.append(_check("public key PEM round-trips",
                          verify_signature(public_key_from_pem(public_key_to_pem(public_key)),
                                           KAT_CHALLENGE_HEX, signature)))

    fake_a = derive_fake_salt(private_key, "alice")
    fake_b = derive_fake_salt(private_key, "bob")
    results.append(_check("derive_fake_salt is deterministic per username",
                          derive_fake_salt(private_key, "alice") == fake_a))
    results.append(_check("derive_fake_salt differs across usernames",
                          fake_a != fake_b))
    results.append(_check("derive_fake_salt length is 16 bytes",
                          len(bytes.fromhex(fake_a)) == SALT_BYTES))
    results.append(_check("generate_session_token is non-empty and unique",
                          bool(generate_session_token())
                          and generate_session_token() != generate_session_token()))

    passed = all(results)
    print(f"\nself-check: {'ALL PASS' if passed else 'FAILURES PRESENT'}"
          f" ({sum(results)}/{len(results)})")
    if not passed:
        raise AssertionError("crypto_utils self-check failed")
    return True


if __name__ == "__main__":
    self_check()
