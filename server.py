"""
server.py — Challenge-Response authentication server (Flask) with a web UI.

Protocol (the password never travels over the network)
------------------------------------------------------
REGISTER
    client -> server : {username, salt, verifier}
    verifier = PBKDF2-HMAC-SHA256(password, salt, 200000). The server stores
    salt + verifier only; it never sees the password.

LOGIN step 1 — request a challenge
    client -> server : {username}
    server -> client : {challenge, salt, signature, expires_in}
    challenge = 32-byte CSPRNG nonce, single-use, CHALLENGE_TTL seconds.
    signature = RSA-2048 PSS/SHA-256 (salt length 32) over the raw challenge.

LOGIN step 2 — answer the challenge
    The client first verifies the signature with GET /api/public-key (server
    authentication; a fake server cannot sign), then sends
    {username, challenge, response} with response = HMAC-SHA256(verifier, challenge).

LOGIN step 3 — verify
    The server consumes the challenge and checks unknown -> wrong user ->
    already used (REPLAY) -> expired -> mark used -> constant-time HMAC
    compare, returning 200/400/401/403/410 with {success, message}.
    On success it issues a random session token.

Replay protection: a challenge is single-use and expires, and it is marked
used before the HMAC comparison, so a captured {challenge, response} is useless.

Environment overrides: PORT (5000), CHALLENGE_TTL (60), USERS_FILE (users.json).
Passwords, verifiers and responses are never logged.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

from flask import Flask, Response, jsonify, request

from crypto_utils import (
    CHALLENGE_BYTES,
    SALT_BYTES,
    VERIFIER_BYTES,
    derive_fake_salt,
    generate_challenge,
    generate_salt,
    generate_session_token,
    load_or_create_rsa_keys,
    public_key_to_pem,
    sign_challenge,
    verify_response,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env_path(name: str, default: str) -> str:
    """Resolve an env-provided path against BASE_DIR so cwd does not matter."""
    value = os.environ.get(name) or default
    return value if os.path.isabs(value) else os.path.join(BASE_DIR, value)


PORT = int(os.environ.get("PORT", "5000"))
CHALLENGE_TTL = int(os.environ.get("CHALLENGE_TTL", "60"))
USERS_FILE = _env_path("USERS_FILE", "users.json")
PRIVATE_KEY_FILE = _env_path("PRIVATE_KEY_FILE", "server_private.pem")
PUBLIC_KEY_FILE = _env_path("PUBLIC_KEY_FILE", "server_public.pem")

PURGE_AFTER = 10 * CHALLENGE_TTL   # keep consumed challenges this long for clear replay errors

app = Flask(__name__)


# --------------------------------------------------------------------------- #
# Shared state and locks
# --------------------------------------------------------------------------- #

_users: Dict[str, Dict[str, Any]] = {}        # username -> {salt, verifier, created}
_challenges: Dict[str, Dict[str, Any]] = {}   # challenge hex -> {username, expiry, used, decoy_verifier?}
_sessions: Dict[str, Dict[str, Any]] = {}     # token -> {username, created}

_users_lock = threading.Lock()                # guards _users + users.json writes
_challenge_lock = threading.Lock()            # guards challenge issue + single-use transition
_sessions_lock = threading.Lock()             # guards _sessions


def _load_users() -> None:
    """Load users.json into memory; a missing/corrupt file starts empty."""
    global _users
    if not os.path.exists(USERS_FILE):
        _users = {}
        return
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        _users = loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError):
        _users = {}


def _save_users_locked() -> None:
    """Atomically persist _users. Caller must hold _users_lock.

    Writes a temp file in the same directory, flushes + fsyncs it, then
    os.replace()s it over the real file so a crash mid-write cannot truncate
    users.json (os.replace is atomic on POSIX and Windows).
    """
    tmp_path = f"{USERS_FILE}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(_users, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, USERS_FILE)


def _purge_challenges_locked() -> None:
    """Drop challenge records that expired more than PURGE_AFTER seconds ago.

    Caller must hold _challenge_lock. Consumed challenges are kept for a while
    so a replay attempt gets "already used" (403) instead of "unknown" (400).
    """
    cutoff = time.time() - PURGE_AFTER
    for challenge in [c for c, rec in _challenges.items() if rec["expiry"] < cutoff]:
        del _challenges[challenge]


# Server RSA identity (private key is the source of truth) and user store
PRIVATE_KEY, PUBLIC_KEY = load_or_create_rsa_keys(PRIVATE_KEY_FILE, PUBLIC_KEY_FILE)
PUBLIC_KEY_PEM = public_key_to_pem(PUBLIC_KEY)
_load_users()


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #

def _clean_username(raw: Any) -> Optional[str]:
    """Return a validated username, or None if it is unacceptable.

    Allowed: 1-64 chars of [A-Za-z0-9_-]. Rejecting anything else keeps the
    username safe to use as a JSON key and in messages.
    """
    if not isinstance(raw, str):
        return None
    username = raw.strip()
    if not username or len(username) > 64:
        return None
    if not all(ch.isalnum() or ch in "_-" for ch in username):
        return None
    return username


def _is_hex(value: Any, nbytes: int) -> bool:
    """True if value is a lowercase-able hex string encoding exactly nbytes."""
    if not isinstance(value, str):
        return False
    if len(value) != 2 * nbytes:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def _error(message: str, code: int) -> Tuple[Response, int]:
    return jsonify({"success": False, "message": message}), code


# --------------------------------------------------------------------------- #
# Web UI (single page, all crypto in the browser via WebCrypto)
# --------------------------------------------------------------------------- #

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Challenge-Response Authentication</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f4f5f7;color:#222;margin:0}
.wrap{max-width:720px;margin:24px auto;padding:0 16px 40px}
h1{font-size:23px;margin:8px 0 4px}
p.sub{color:#555;font-size:14px;line-height:1.6;margin:0 0 16px}
p.sub code{background:#e8eaee;padding:1px 5px;border-radius:4px;font-size:12.5px}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:16px;margin:14px 0}
.card h2{font-size:16px;margin:0 0 10px}
.card p{font-size:13px;color:#555;margin:0 0 12px;line-height:1.6}
label{display:block;font-size:12px;color:#555;margin:8px 0 4px}
input{width:100%;padding:8px 10px;border:1px solid #bbb;border-radius:5px;font-size:14px;box-sizing:border-box}
button{padding:9px 16px;border-radius:5px;border:1px solid #1d4ed8;background:#2563eb;color:#fff;font-size:14px;cursor:pointer;margin-top:12px}
button:hover{background:#1d4ed8}
button.plain{background:#fff;color:#222;border-color:#bbb}
button.plain:hover{background:#eee}
button:disabled{opacity:.6;cursor:wait}
.msg{font-size:13px;margin-top:10px}
.ok{color:#15803d}.err{color:#b91c1c}
pre{background:#f0f1f4;border:1px solid #ddd;border-radius:5px;padding:10px;font-size:12px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:8px 0 0}
#log{background:#fff;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:Consolas,monospace;font-size:12.5px;height:220px;overflow:auto}
#log div{margin-bottom:4px}
ul.simple{font-size:13px;color:#555;line-height:1.7;margin:8px 0 0;padding-left:20px}
footer{font-size:12px;color:#888;text-align:center;margin-top:20px}
.row{display:flex;gap:8px}.row button{flex:1}
</style></head>
<body><div class="wrap">
<h1>Challenge-Response Authentication</h1>
<p class="sub" id="statline">Checking server…</p>
<p class="sub">The password <b>never leaves your browser</b>. Registration sends only
<code>verifier = PBKDF2(password, salt)</code>; login sends only
<code>response = HMAC(verifier, challenge)</code>. Every challenge is RSA-2048
signed, single-use and short-lived.</p>

<div class="card"><h2>1. Register</h2>
<p>The server stores the salt and verifier — never the password.</p>
<label>Username</label><input id="r_user" autocomplete="off">
<label>Password</label><input id="r_pass" type="password">
<button id="btnReg" onclick="register()">Register</button>
<div class="msg" id="regMsg"></div></div>

<div class="card"><h2>2. Login</h2>
<p>The server issues a one-time challenge; your browser answers with an HMAC.</p>
<label>Username</label><input id="l_user" autocomplete="off">
<label>Password</label><input id="l_pass" type="password">
<div class="row"><button id="btnLogin" onclick="login()">Login</button>
<button id="btnReplay" class="plain" onclick="replay()">Replay last response</button></div>
<div class="msg" id="loginMsg"></div></div>

<div class="card"><h2>Session</h2>
<div class="msg" id="sess">No active session.</div></div>

<div class="card"><h2>Last request body (what actually went on the wire)</h2>
<p>Notice there is no password, ever.</p>
<pre id="wire">Nothing sent yet.</pre></div>

<div class="card"><h2>Protocol log</h2>
<div id="log"></div>
<button class="plain" onclick="document.getElementById('log').innerHTML=''">Clear log</button></div>

<div class="card"><h2>Why replay fails</h2>
<ul class="simple">
<li>Each challenge is fresh random data valid for a short time.</li>
<li>A challenge is consumed on first use; sending it again is rejected.</li>
<li>After a login, press <b>Replay last response</b> to watch it get blocked.</li>
</ul></div>

<footer>IDS Practical 14 · PBKDF2 + HMAC challenge-response + RSA-2048 signatures</footer>
</div>
<script>
const $=id=>document.getElementById(id);
const enc=new TextEncoder();
let cachedKey=null,lastLogin=null;
function log(msg,kind){const d=document.createElement('div');if(kind)d.className=kind;d.textContent=msg;$('log').appendChild(d);$('log').scrollTop=1e9;}
function say(id,msg,ok){const e=$(id);e.textContent=msg;e.className='msg '+(ok?'ok':'err');}
const toHex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex=h=>new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));

async function deriveVerifier(password,saltHex){
  const k=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:fromHex(saltHex),iterations:200000,hash:'SHA-256'},k,256);
  return toHex(bits);
}
async function hmacHex(verifierHex,challengeHex){
  const k=await crypto.subtle.importKey('raw',fromHex(verifierHex),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return toHex(await crypto.subtle.sign('HMAC',k,fromHex(challengeHex)));
}
function pemToBytes(pem){
  const b64=pem.replace(/-----[^-]+-----/g,'').replace(/\s+/g,'');
  const bin=atob(b64);const out=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);
  return out;
}
async function serverKey(){
  if(cachedKey)return cachedKey;
  const r=await fetch('/api/public-key');
  const pem=(await r.json()).public_key;
  cachedKey=await crypto.subtle.importKey('spki',pemToBytes(pem),{name:'RSA-PSS',hash:'SHA-256'},false,['verify']);
  return cachedKey;
}
async function serverSignatureOk(challengeHex,sigHex){
  const key=await serverKey();
  return crypto.subtle.verify({name:'RSA-PSS',saltLength:32},key,fromHex(sigHex),fromHex(challengeHex));
}
async function post(path,body){
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  return {status:r.status,json:await r.json()};
}
async function status(){
  try{const s=await (await fetch('/api/status')).json();
    $('statline').textContent='Server online — '+s.users+' user(s), '+s.sessions+' session(s).';}
  catch(e){$('statline').textContent='Server unreachable.';}
}
async function register(){
  const u=$('r_user').value.trim(),p=$('r_pass').value;
  if(!u||!p){say('regMsg','Enter a username and password.',false);return;}
  $('btnReg').disabled=true;
  try{
    const salt=toHex(crypto.getRandomValues(new Uint8Array(16)));
    const verifier=await deriveVerifier(p,salt);
    log('Register: sending {username, salt, verifier} — no password.');
    $('wire').textContent=JSON.stringify({path:'POST /api/register',username:u,salt,verifier},null,2);
    const {json}=await post('/api/register',{username:u,salt,verifier});
    log((json.success?'Registered: ':'Failed: ')+json.message,json.success?'ok':'err');
    say('regMsg',json.message,json.success);
    if(json.success)$('l_user').value=u;
    status();
  }finally{$('btnReg').disabled=false;}
}
async function login(){
  const u=$('l_user').value.trim(),p=$('l_pass').value;
  if(!u||!p){say('loginMsg','Enter a username and password.',false);return;}
  $('btnLogin').disabled=true;
  try{
    log('Login: requesting a challenge for "'+u+'".');
    const {json:c}=await post('/api/request-challenge',{username:u});
    if(!c.success){log('Challenge request failed: '+c.message,'err');say('loginMsg',c.message,false);return;}
    log('Challenge received — single-use, TTL '+c.expires_in+'s, RSA-signed.');
    const sigOk=await serverSignatureOk(c.challenge,c.signature);
    if(!sigOk){
      log('RSA signature INVALID — server not authenticated. Aborting before sending any response.','err');
      say('loginMsg','Fake server detected — aborted.',false);
      return;
    }
    log('RSA signature verified — server authenticated.','ok');
    const verifier=await deriveVerifier(p,c.salt);
    const response=await hmacHex(verifier,c.challenge);
    lastLogin={username:u,challenge:c.challenge,response};
    log('Sending response = HMAC(verifier, challenge).');
    $('wire').textContent=JSON.stringify({path:'POST /api/verify',username:u,challenge:c.challenge,response},null,2);
    const {status:st,json:v}=await post('/api/verify',lastLogin);
    log('HTTP '+st+' — '+v.message,v.success?'ok':'err');
    say('loginMsg',v.message,v.success);
    $('sess').textContent=v.success?('Logged in as '+u+'. Session token: '+v.session_token):'No active session.';
    status();
  }finally{$('btnLogin').disabled=false;}
}
async function replay(){
  if(!lastLogin){say('loginMsg','Log in first, then replay.',false);return;}
  log('Replaying the captured {challenge, response}…');
  const {status:st,json:v}=await post('/api/verify',lastLogin);
  log('HTTP '+st+' — '+(v.success?'Replay accepted (BUG!) ':'Replay blocked: ')+v.message,!v.success?'ok':'err');
  say('loginMsg',(v.success?'Replay accepted (BUG!) ':'Replay blocked: ')+v.message,!v.success);
}
async function selfTest(){
  const pw='Hunter2!KAT', salt='00112233445566778899aabbccddeeff';
  const challenge='000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const wantVerifier='48862173f52b431e679bd4e2f8aa45eb0809750a3746b751df719b372ae51b19';
  const wantResponse='d1f8af22935f2f9e0948efd5768ebbd646c4379119ce53a56917a94467e4fc9f';
  try{
    const v=await deriveVerifier(pw,salt);
    log('Self-test PBKDF2 vs known vector: '+(v===wantVerifier?'PASS':'FAIL'),v===wantVerifier?'ok':'err');
    const r=await hmacHex(v,challenge);
    log('Self-test HMAC vs known vector: '+(r===wantResponse?'PASS':'FAIL'),r===wantResponse?'ok':'err');
  }catch(e){log('Self-test error: '+e,'err');}
}
['r_pass','l_pass'].forEach(id=>$(id).addEventListener('keydown',e=>{if(e.key==='Enter')(id[0]==='r'?register:login)();}));
status();setInterval(status,5000);selfTest();
log('Ready. Register an account, then log in.');
</script></body></html>"""


@app.get("/")
def index() -> Response:
    return Response(INDEX_HTML, mimetype="text/html")


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #

@app.get("/api/public-key")
def public_key() -> Response:
    """Return the server RSA public key (PEM) so clients can verify signatures."""
    return jsonify({"public_key": PUBLIC_KEY_PEM})


@app.post("/api/register")
def register() -> Tuple[Response, int]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("malformed request: expected a JSON object.", 400)

    username = _clean_username(data.get("username"))
    salt = data.get("salt")
    verifier = data.get("verifier")

    if username is None:
        return _error("username must be 1-64 chars of letters, digits, _ or -.", 400)
    if not _is_hex(salt, SALT_BYTES):
        return _error(f"salt must be {SALT_BYTES} bytes of hex.", 400)
    if not _is_hex(verifier, VERIFIER_BYTES):
        return _error(f"verifier must be {VERIFIER_BYTES} bytes of hex "
                      "(PBKDF2-HMAC-SHA256 output).", 400)

    with _users_lock:
        if username in _users:
            return _error(f"User '{username}' already exists.", 409)
        _users[username] = {"salt": salt.lower(), "verifier": verifier.lower(),
                            "created": time.time()}
        _save_users_locked()

    return jsonify({
        "success": True,
        "message": f"User '{username}' registered. Password verifier stored "
                   "(PBKDF2-SHA256). Password was never received.",
    })


@app.post("/api/request-challenge")
def request_challenge() -> Tuple[Response, int]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("malformed request: expected a JSON object.", 400)

    username = _clean_username(data.get("username"))
    if username is None:
        return _error("username must be 1-64 chars of letters, digits, _ or -.", 400)

    challenge = generate_challenge(CHALLENGE_BYTES)
    with _challenge_lock:
        _purge_challenges_locked()
        record: Dict[str, Any] = {
            "username": username,
            "expiry": time.time() + CHALLENGE_TTL,
            "used": False,
        }
        if username not in _users:
            # Unknown user: issue a normal-looking response with a deterministic
            # decoy salt. The decoy verifier makes the later HMAC check fail like
            # a wrong password, so this never becomes a user-enumeration oracle.
            record["decoy_verifier"] = generate_salt(VERIFIER_BYTES)
        _challenges[challenge] = record

    if username in _users:
        salt = _users[username]["salt"]
    else:
        salt = derive_fake_salt(PRIVATE_KEY, username, SALT_BYTES)

    signature = sign_challenge(PRIVATE_KEY, challenge)
    return jsonify({
        "success": True,
        "challenge": challenge,
        "salt": salt,
        "signature": signature,
        "expires_in": CHALLENGE_TTL,
        "message": "Challenge issued (RSA-signed, single-use).",
    })


@app.post("/api/verify")
def verify() -> Tuple[Response, int]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _error("malformed request: expected a JSON object.", 400)

    username = _clean_username(data.get("username"))
    challenge = data.get("challenge")
    response = data.get("response")

    if username is None:
        return _error("username must be 1-64 chars of letters, digits, _ or -.", 400)
    if not _is_hex(challenge, CHALLENGE_BYTES):
        return _error(f"challenge must be {CHALLENGE_BYTES} bytes of hex.", 400)
    if not _is_hex(response, VERIFIER_BYTES):
        return _error(f"response must be {VERIFIER_BYTES} bytes of hex.", 400)
    challenge = challenge.lower()
    response = response.lower()

    # Single critical section: the used-check and the mark happen atomically, so
    # two concurrent submissions of the same challenge cannot both pass.
    with _challenge_lock:
        record = _challenges.get(challenge)
        if record is None:
            return _error("LOGIN FAILED: unknown challenge — rejected.", 400)
        if record["username"] != username:
            return _error("LOGIN FAILED: challenge was not issued for this user.", 400)
        if record["used"]:
            return _error("LOGIN FAILED: challenge already used — REPLAY ATTACK "
                          "BLOCKED. Each challenge is single-use.", 403)
        if time.time() > record["expiry"]:
            return _error("LOGIN FAILED: challenge expired — request a fresh one.", 410)

        record["used"] = True  # consume before comparing; any replay now hits 403

        if username in _users:
            stored_verifier = _users[username]["verifier"]
        else:
            stored_verifier = record.get("decoy_verifier")

    if not stored_verifier or not verify_response(stored_verifier, challenge, response):
        return _error("LOGIN FAILED: wrong password (HMAC mismatch).", 401)

    token = generate_session_token()
    with _sessions_lock:
        _sessions[token] = {"username": username, "created": time.time()}
    return jsonify({
        "success": True,
        "message": "LOGIN SUCCESS: response verified.",
        "session_token": token,
    })


@app.get("/api/status")
def status() -> Response:
    with _challenge_lock:
        _purge_challenges_locked()
        active = sum(1 for rec in _challenges.values() if not rec["used"])
    with _sessions_lock:
        sessions = len(_sessions)
    return jsonify({"users": len(_users), "active_challenges": active,
                    "sessions": sessions})


if __name__ == "__main__":
    print(f"Challenge-Response Auth Server  ->  http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, debug=False)
