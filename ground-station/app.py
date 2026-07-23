"""
Orbital Ground Segment  --  web mission control (Stage 1)

Yamcs-inspired operator console. Viewers can watch telemetry; only OPERATORS may
open the command uplink console, read the uplink key, and pull the flight firmware
image. Escalate from viewer to operator to proceed to Stage 2.

VULN (intended path): the session is a JWT, and the verifier accepts alg="none".
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import time

from flask import Flask, request, redirect, make_response, send_file, Response
import ccsds

app = Flask(__name__)

SECRET = os.environ.get("JWT_SECRET", hashlib.sha256(os.urandom(32)).hexdigest()).encode()
FLAG_STAGE1 = os.environ.get("FLAG_STAGE1", "SATCTF{local_dev_flag_1}")
RELAY_HOST = os.environ.get("RELAY_HOST", "uplink-relay")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "9010"))
UPLINK_KEY = os.environ.get("UPLINK_KEY", "UPLINK-TC-2026")
FIRMWARE_PATH = "/firmware/flight_sw"

# ---------------------------------------------------------------------------
# Minimal JWT (with the intended vulnerability)
# ---------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def jwt_sign(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    seg = b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(payload).encode())
    sig = hmac.new(SECRET, seg.encode(), hashlib.sha256).digest()
    return seg + "." + b64url(sig)


def jwt_verify(token: str):
    """Return payload dict if the token is valid, else None.

    BUG: this accepts alg == "none" (unsigned tokens) in addition to HS256.
    """
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
        alg = header.get("alg", "").lower()
        if alg == "none":
            return payload  # <-- unsigned tokens trusted
        if alg == "hs256":
            seg = h_b64 + "." + p_b64
            expect = hmac.new(SECRET, seg.encode(), hashlib.sha256).digest()
            if hmac.compare_digest(expect, b64url_decode(sig_b64)):
                return payload
        return None
    except Exception:
        return None


def current_user():
    tok = request.cookies.get("session", "")
    if not tok:
        return None
    return jwt_verify(tok)

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>Orbital Ground Segment</title>
<style>
 body{{background:#0a0e17;color:#c8d6e5;font-family:Consolas,Menlo,monospace;margin:0}}
 header{{background:#101826;padding:14px 22px;border-bottom:1px solid #1e2b3d;display:flex;justify-content:space-between;align-items:center}}
 header h1{{font-size:16px;margin:0;color:#7dd3fc;letter-spacing:1px}}
 .role{{font-size:12px;color:#64748b}}
 .wrap{{max-width:1000px;margin:0 auto;padding:24px}}
 .card{{background:#0f1622;border:1px solid #1e2b3d;border-radius:8px;padding:18px 20px;margin:14px 0}}
 .card h2{{margin:0 0 10px;font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px}}
 .tm{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;font-size:13px}}
 .tm div span{{color:#64748b}}
 .locked{{color:#f87171}}
 .ok{{color:#4ade80}}
 input,textarea{{background:#0a0e17;color:#e2e8f0;border:1px solid #263447;border-radius:5px;padding:8px;font-family:inherit;width:100%;box-sizing:border-box}}
 button{{background:#1d4ed8;color:#fff;border:0;border-radius:5px;padding:9px 16px;cursor:pointer;font-family:inherit}}
 a{{color:#7dd3fc}}
 pre{{background:#070b12;padding:10px;border-radius:6px;overflow:auto;font-size:12px}}
 .flag{{color:#fbbf24;font-weight:bold}}
</style></head><body>
<header><h1>&#128225; ORBITAL GROUND SEGMENT &mdash; Mission Control</h1>
<span class=role>{role_line}</span></header>
<div class=wrap>{body}</div>
</body></html>"""


def render(body, user):
    role_line = "not authenticated &mdash; <a href=/login>login</a>"
    if user:
        role_line = f"user={user.get('user','?')} role={user.get('role','?')} &mdash; <a href=/logout>logout</a>"
    return PAGE.format(role_line=role_line, body=body)


TELEMETRY = """
<div class=card><h2>SAT-1 &mdash; Realtime Telemetry (read-only)</h2>
<div class=tm>
 <div><span>MODE</span><br>NOMINAL</div>
 <div><span>BATT V</span><br>28.4 V</div>
 <div><span>TEMP OBC</span><br>19.7 &deg;C</div>
 <div><span>ADCS</span><br>SUN-POINTING</div>
 <div><span>DOWNLINK</span><br>S-BAND 2.2GHz</div>
 <div><span>SW BUILD</span><br>cFE 6.7 / OS_AL</div>
</div></div>
"""


@app.route("/")
def index():
    user = current_user()
    body = TELEMETRY
    if not user:
        body += "<div class=card>You are browsing anonymously. <a href=/login>Log in</a> as a viewer to continue.</div>"
        return render(body, user)

    role = user.get("role", "viewer")
    if role == "operator":
        body += f"""
        <div class=card><h2>Operator Console &mdash; UNLOCKED</h2>
        <p>Welcome, operator. Stage 1 clear.</p>
        <p class=flag>{FLAG_STAGE1}</p>
        <p><b>SIGNAL PASS:</b> tcp <code>{RELAY_HOST}:{RELAY_PORT}</code>
           (exposed to you as <code>localhost:9010</code>)<br>
           <b>Uplink auth key:</b> <code>{UPLINK_KEY}</code><br>
           <b>Flight firmware image:</b> <a href=/firmware>/firmware</a> (pull it &mdash; you'll need it to pwn the OBC)</p>
        </div>
        <div class=card><h2>Command Uplink Console</h2>
        <form method=post action=/tc>
          <p>APID (hex): <input name=apid value=100 style=width:120px></p>
          <p>Command code (hex): <input name=cmd value=00 style=width:120px></p>
          <p>Payload (hex): <textarea name=payload rows=2 placeholder=deadbeef></textarea></p>
          <button>UPLINK TC &rarr; SAT-1</button>
        </form>
        <p style=color:#64748b>The console frames your input as CCSDS TC and forwards it to the relay,
           which only passes traffic during the AOS visibility window.</p>
        </div>"""
    else:
        body += """
        <div class=card><h2 class=locked>Operator Console &mdash; LOCKED</h2>
        <p>Your role is <b>viewer</b>. Command uplink, the uplink key, and firmware download
           require <b>operator</b> privileges. Talk to your session token about that.</p></div>"""
    return render(body, user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("user", "")
        p = request.form.get("pass", "")
        # public read-only guest account (documented on the login page)
        if (u, p) == ("guest", "guest"):
            resp = make_response(redirect("/"))
            token = jwt_sign({"user": "guest", "role": "viewer", "iat": int(time.time())})
            resp.set_cookie("session", token)
            return resp
        body = "<div class=card><h2 class=locked>Login failed</h2><a href=/login>try again</a></div>"
        return render(body, None)
    body = """<div class=card><h2>Sign in</h2>
      <form method=post>
        <p>User: <input name=user value=guest></p>
        <p>Pass: <input name=pass type=password value=guest></p>
        <button>LOGIN</button>
      </form>
      <p style=color:#64748b>Public viewer account: <code>guest / guest</code>.
         Operator accounts are provisioned by the mission director.</p></div>"""
    return render(body, None)


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session")
    return resp


@app.route("/firmware")
def firmware():
    user = current_user()
    if not user or user.get("role") != "operator":
        return Response("403 - operator role required\n", status=403)
    if not os.path.exists(FIRMWARE_PATH):
        return Response("firmware image not staged on this segment\n", status=404)
    return send_file(FIRMWARE_PATH, as_attachment=True, download_name="flight_sw")


@app.route("/tc", methods=["POST"])
def tc():
    user = current_user()
    if not user or user.get("role") != "operator":
        return Response("403 - operator role required\n", status=403)
    try:
        apid = int(request.form.get("apid", "100"), 16)
        cmd = int(request.form.get("cmd", "0"), 16)
        payload = bytes.fromhex(request.form.get("payload", "").strip() or "")
    except ValueError:
        return Response("bad hex input\n", status=400)

    frame = ccsds.build_tc(apid, cmd, payload)
    reply = uplink(frame)
    body = f"""<div class=card><h2>Uplink result</h2>
      <pre>TX frame: {frame.hex()}\n\n{reply}</pre>
      <a href=/>&larr; back to console</a></div>"""
    return render(body, user)


def uplink(frame: bytes) -> str:
    """Forward a CCSDS frame to the relay using its text protocol: KEY:HEX\\n"""
    try:
        s = socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=5)
        s.recv(4096)  # banner
        s.sendall(f"{UPLINK_KEY}:{frame.hex()}\n".encode())
        data = s.recv(65535)
        s.close()
        return data.decode(errors="replace")
    except Exception as e:
        return f"relay error: {e}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
