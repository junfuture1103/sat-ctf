"""
Orbital Uplink Relay  --  Stage 2

The only path from the ground segment to the spacecraft. It models a real LEO pass:
the satellite is only in view for a short AOS window, and telecommands sent during
LOS (loss of signal) are dropped.

  - AOS (acquisition of signal): default 15 s  -> traffic is forwarded to the OBC
  - LOS (loss of signal):        default 45 s  -> traffic is dropped

Text protocol, one request per line:
      <UPLINK_KEY>:<hex CCSDS TC frame>\n
Responses:
      LOS next AOS in <n>s
      ERR AUTH / ERR FRAME <why>
      AOS ACK ...\nTM <hex>\n<decoded>\n[STAGE2 <flag>]
"""
import os
import socket
import socketserver
import struct
import time

import ccsds

FLAG_STAGE2 = os.environ.get("FLAG_STAGE2", "SATCTF{local_dev_flag_2}")
FLIGHT_HOST = os.environ.get("FLIGHT_HOST", "flight-sw")
FLIGHT_PORT = int(os.environ.get("FLIGHT_PORT", "9020"))
UPLINK_KEY = os.environ.get("UPLINK_KEY", "UPLINK-TC-2026")
AOS = int(os.environ.get("AOS_SECONDS", "15"))
LOS = int(os.environ.get("LOS_SECONDS", "45"))
CYCLE = AOS + LOS

START = time.time()


def window():
    """Return (state, seconds_remaining_in_state)."""
    t = (time.time() - START) % CYCLE
    if t < AOS:
        return "AOS", int(AOS - t) + 1
    return "LOS", int(CYCLE - t) + 1


def forward_to_obc(frame: bytes) -> bytes:
    """Deliver a raw CCSDS frame to the flight software and read all telemetry it
    emits before it closes the link (the OBC may send several TM frames -- e.g. a
    handler ack followed by a privileged-context message after a OBC ESCAPE)."""
    s = socket.create_connection((FLIGHT_HOST, FLIGHT_PORT), timeout=8)
    try:
        s.sendall(struct.pack(">H", len(frame)) + frame)
        s.shutdown(socket.SHUT_WR)
        out = b""
        while True:
            hdr = recvn(s, 2)
            if len(hdr) < 2:
                break
            (n,) = struct.unpack(">H", hdr)
            body = recvn(s, n)
            out += body
            if len(body) < n:
                break
        return out
    finally:
        s.close()


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def handle_line(line: str) -> str:
    if ":" not in line:
        return "ERR FRAME expected <key>:<hexframe>"
    key, hexframe = line.split(":", 1)
    if key.strip() != UPLINK_KEY:
        return "ERR AUTH bad uplink key"

    state, rem = window()
    if state != "AOS":
        return f"LOS satellite below horizon, next AOS in {rem}s"

    try:
        frame = bytes.fromhex(hexframe.strip())
    except ValueError:
        return "ERR FRAME payload is not valid hex"

    try:
        pkt = ccsds.parse_tc(frame)
    except ValueError as e:
        return f"ERR CCSDS {e}"
    if pkt["type"] != 1 or pkt["sec_hdr"] != 1:
        return "ERR CCSDS not a valid telecommand (type/secHdr)"
    if not ccsds.checksum_ok(frame):
        return "ERR CCSDS secondary-header checksum mismatch"

    try:
        tm = forward_to_obc(frame)
    except Exception as e:
        return f"ERR LINK obc unreachable: {e}"

    decoded = tm.decode(errors="replace")
    out = [f"AOS ACK uplink delivered to OBC (apid=0x{pkt['apid']:03x} cmd=0x{pkt['cmd_code']:02x})",
           f"TM {tm.hex()}",
           decoded]
    # Reward: a successfully framed + timed + delivered telecommand.
    out.append(f"STAGE2 {FLAG_STAGE2}")
    return "\n".join(out)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        state, rem = window()
        self.wfile.write(
            (f"ORBITAL UPLINK RELAY :: link={state} ({rem}s) :: "
             f"AOS={AOS}s LOS={LOS}s :: send <key>:<hexframe>\n").encode())
        for raw in self.rfile:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            if line.lower() in ("quit", "exit"):
                return
            try:
                resp = handle_line(line)
            except Exception as e:
                resp = f"ERR internal {e}"
            self.wfile.write((resp + "\n").encode())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(f"[relay] listening :9010  AOS={AOS}s LOS={LOS}s  -> {FLIGHT_HOST}:{FLIGHT_PORT}", flush=True)
    Server(("0.0.0.0", 9010), Handler).serve_forever()
