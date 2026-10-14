# Challenge–Response Authentication System (IDS Practical 14)

Authenticate a user **without ever sending the password over the network**.
The design combines PBKDF2 password storage, an HMAC challenge–response, a
single-use expiring nonce, and an RSA-2048 digital signature that proves the
server's identity.

## Protocol

| Step | Message / action |
|---|---|
| **Registration** | Client generates a 16-byte random salt and computes `verifier = PBKDF2-HMAC-SHA256(password, salt, 200000)`; sends `{username, salt, verifier}`. Server stores salt + verifier only — never the password. Duplicate usernames are rejected with HTTP 409. |
| **Login 1 — challenge** | Client → `POST /api/request-challenge {username}`. Server replies `{challenge, salt, signature, expires_in}`: `challenge` is a 32-byte CSPRNG nonce (single-use, `CHALLENGE_TTL` default 60 s), `signature` is RSA-2048 PSS/SHA-256 (salt length 32) over the raw challenge. |
| **Login 2 — client verifies server** | Client fetches `GET /api/public-key`, verifies the signature over the challenge, and **aborts if it does not verify** (fake-server / MITM detection). It then derives `verifier` locally and computes `response = HMAC-SHA256(key=verifier, msg=challenge)`. |
| **Login 3 — verify** | Client → `POST /api/verify {username, challenge, response}`. Server checks **unknown (400) → wrong user (400) → already used (403) → expired (410)**, marks the challenge used, then compares with `hmac.compare_digest` → `LOGIN SUCCESS` (200) + session token or `LOGIN FAILED` (401). |
| **Replay defence** | A challenge is consumed before the comparison, is single-use, and expires — a captured `{challenge, response}` cannot be reused. |

## Extra cryptographic mechanism — RSA-2048 signatures

Every challenge is signed by the server's private key; the client verifies the
signature with the server's public key **before** answering. This authenticates
the *server* (absent from a plain challenge–response), so a fake server that
cannot sign the challenge is detected and the client sends nothing.

## Anti-enumeration

`POST /api/request-challenge` for an unknown username returns HTTP 200 with a
shape-identical response, including a **deterministic decoy salt**
`HMAC-SHA256(b"fake-salt|" + username, key=SHA-256(private key DER))[:16]`. The
challenge carries a random decoy verifier so the later check fails exactly like
a wrong password — enquiries cannot be used to discover valid usernames.

## Run (Windows / PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

python server.py          # serves the web UI at http://127.0.0.1:5000
python demo.py            # automated 8-scenario proof; exits 0 on success

python client.py register alice
python client.py login alice
python client.py replay alice
python client.py attack-demo alice
```

Passwords are always read with `getpass` — never passed as command-line
arguments. In the web UI, after logging in press **Replay last response** to
watch the replay get blocked live.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5000` | HTTP port |
| `CHALLENGE_TTL` | `60` | Challenge lifetime in seconds |
| `USERS_FILE` | `users.json` | User store path |
| `PRIVATE_KEY_FILE` / `PUBLIC_KEY_FILE` | `server_private.pem` / `server_public.pem` | RSA identity paths |
| `SERVER_URL` | `http://127.0.0.1:5000` | Base URL used by `client.py` |

## Files

| File | Purpose |
|---|---|
| `server.py` | Flask server, web UI, RSA identity, replay-safe verification, HTTP API |
| `client.py` | CLI: `register` / `login` / `replay` / `attack-demo` + reusable `perform_*` steps |
| `crypto_utils.py` | PBKDF2, HMAC, nonce, RSA sign/verify, fake-salt helper, `self_check()` |
| `demo.py` | Scripted end-to-end proof (8 scenarios), PASS/FAIL summary, exit code |
| `requirements.txt` | Pinned dependencies |
| `README.md` / `VIVA-GUIDE.md` | Run instructions / study guide and limitations |
| `users.json`, `*.pem` | Created at runtime and git-ignored |

## API summary

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Web UI (all crypto in the browser via WebCrypto) |
| POST | `/api/register` | Create account from `{username, salt, verifier}` |
| POST | `/api/request-challenge` | Issue a signed, single-use challenge |
| POST | `/api/verify` | Check the HMAC response and issue a session token |
| GET | `/api/public-key` | Server RSA-2048 public key (PEM) |
| GET | `/api/status` | User/challenge/session counts |

## Known limitations

See `VIVA-GUIDE.md` for the full discussion. In short: the stored verifier is
password-equivalent (a leaked `users.json` lets an attacker answer challenges —
SRP/OPAQUE/PAKE fix this), there is no TLS, the challenge store is in-memory
(single process, no rate limiting), and `users.json` is a demo store.
