"""
Mission Operations Scoreboard + 3D situational-awareness GUI.

  GET  /                       -> 3D globe (GROUND ZEROs + orbiting satellites)
  GET  /api/state              -> live mission state (polled by the GUI)
  POST /api/submit             -> submit a flag {team, flag}; final flag de-orbits the sat
  POST /api/event/compromise   -> internal: flight-sw calls this on OBC pwn (token-gated)
  POST /api/demo/compromise    -> demo-only visual trigger (DEMO_MODE)
"""
import json
import os
import threading
import time

from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder=None)

CONFIG_PATH = os.environ.get("MISSION_CONFIG", "/config/mission.json")
EVENT_TOKEN = os.environ.get("EVENT_TOKEN", "orbit-internal-9f3a")
DEMO_MODE = os.environ.get("DEMO_MODE", "1") == "1"
WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

with open(CONFIG_PATH) as f:
    MISSION = json.load(f)

FLAGS = MISSION["flags"]                      # stage -> flag string
FLAG_LOOKUP = {v: k for k, v in FLAGS.items()}
WINDOW = MISSION["visibility_window"]

LOCK = threading.Lock()
START = time.time()
STATE = {
    # sat_id -> {"compromised": bool, "at": epoch}
    "sats": {s["id"]: {"compromised": False, "at": None} for s in MISSION["satellites"]},
    # team -> set(stage) captured
    "solves": {},
    "events": [],   # recent log lines for the GUI ticker
}


def log_event(msg):
    STATE["events"].append({"t": time.time(), "msg": msg})
    STATE["events"] = STATE["events"][-40:]


def compromise(sat_id, source):
    with LOCK:
        s = STATE["sats"].get(sat_id)
        if not s:
            return False
        if not s["compromised"]:
            s["compromised"] = True
            s["at"] = time.time()
            log_event(f"[{source}] OBC compromised on {sat_id} -- ATTITUDE LOST, DE-ORBIT")
        return True


def window_state():
    aos = WINDOW["aos_seconds"]
    los = WINDOW["los_seconds"]
    cycle = aos + los
    t = (time.time() - START) % cycle
    if t < aos:
        return {"state": "AOS", "remaining": int(aos - t) + 1, "aos": aos, "los": los}
    return {"state": "LOS", "remaining": int(cycle - t) + 1, "aos": aos, "los": los}


@app.route("/api/state")
def api_state():
    now = time.time()
    sats = []
    for s in MISSION["satellites"]:
        st = STATE["sats"][s["id"]]
        sats.append({
            **s,
            "compromised": st["compromised"],
            "since": (now - st["at"]) if st["at"] else None,
        })
    return jsonify({
        "mission": MISSION["mission"],
        "ctf_prefix": MISSION["ctf_prefix"],
        "window": window_state(),
        "satellites": sats,
        "ground_stations": MISSION["ground_stations"],
        "events": STATE["events"][-12:],
        "demo": DEMO_MODE,
        "solve_count": sum(len(v) for v in STATE["solves"].values()),
    })


@app.route("/api/submit", methods=["POST"])
def api_submit():
    data = request.get_json(force=True, silent=True) or {}
    team = (data.get("team") or "anon").strip()[:32]
    flag = (data.get("flag") or "").strip()
    stage = FLAG_LOOKUP.get(flag)
    if not stage:
        return jsonify({"ok": False, "msg": "incorrect or unknown flag"}), 200
    with LOCK:
        STATE["solves"].setdefault(team, set()).add(stage)
        STATE["solves"][team] = set(STATE["solves"][team])
    log_event(f"[scoreboard] {team} captured {stage}")
    result = {"ok": True, "stage": stage, "msg": f"{stage} accepted"}
    if stage == "stage3b_pwn":
        compromise("SAT-1", f"flag:{team}")
        result["deorbit"] = "SAT-1"
    return jsonify(result)


@app.route("/api/event/compromise", methods=["POST"])
def api_event():
    data = request.get_json(force=True, silent=True) or {}
    if data.get("token") != EVENT_TOKEN:
        return jsonify({"ok": False, "msg": "forbidden"}), 403
    sat = data.get("sat", "SAT-1")
    ok = compromise(sat, "OBC")
    return jsonify({"ok": ok})


@app.route("/api/demo/compromise", methods=["POST"])
def api_demo():
    if not DEMO_MODE:
        return jsonify({"ok": False, "msg": "demo disabled"}), 403
    data = request.get_json(force=True, silent=True) or {}
    sat = data.get("sat", "SAT-1")
    if data.get("reset"):
        with LOCK:
            STATE["sats"][sat] = {"compromised": False, "at": None}
        log_event(f"[demo] reset {sat} to nominal orbit")
        return jsonify({"ok": True})
    compromise(sat, "demo")
    return jsonify({"ok": True})


@app.route("/")
def index():
    return send_from_directory(WEB_DIR, "index.html")


@app.route("/<path:p>")
def static_files(p):
    return send_from_directory(WEB_DIR, p)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
