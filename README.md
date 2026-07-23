# DEEP SAT EXPLOIT

**A full-chain satellite pwn CTF — from a ground-station login page all the way to code execution on a spacecraft's on-board computer.**

## About

**DEEP SAT EXPLOIT** is a four-stage capture-the-flag challenge that walks an attacker down the *entire command path of a space mission* — public web of a ground station → authenticated command uplink → radio pass → flight-software command router → memory of a flight app running on the on-board computer (OBC).

You never touch the spacecraft directly. Just like a real mission, the only route "up" is **through** the ground segment and a narrow radio-visibility window, so each layer's compromise becomes the credential for the next. That turns four bugs into **one escalating story**:

> web session ⟶ command authority ⟶ bus routing ⟶ app memory safety

The finale is a **memory-corruption sandbox escape across the flight software's Software Bus** — deliberately isomorphic to a browser/OS **IPC-message sandbox escape**, except here the "sandbox" is a NASA cFS-style flight app and the "IPC" is the spacecraft Software Bus.

Everything is built on the shape of real systems — [Yamcs](https://github.com/yamcs/yamcs) for the ground segment and [NASA cFS](https://github.com/nasa/cFS) for the flight software — with a simplified but faithful CCSDS telecommand format.

> ⚠️ **Deliberately vulnerable software for education / CTF use.** Do not expose it to the public internet.

## The full chain — ground station → satellite

You start with nothing but a browser pointed at a ground station, and you finish with a shell-equivalent on a spacecraft. Each step unlocks the next:

### Stage 1 — GROUND ZERO

**Service:** `ground-station` (Flask), http://localhost:8080

The session cookie is a JWT. A public `guest/guest` account issues a real HS256 token. Operator features require `role == "operator"`. The verifier accepts `alg: "none"` (unsigned) tokens — forge an unsigned `role=operator` token to unlock the command console, the **uplink key**, and a **firmware download**.

### Stage 2 — SIGNAL PASS

**Service:** `uplink` (raw TCP), `localhost:9010`

The uplink relay models a real LEO overpass: **~15 s of AOS** (acquisition of signal) when commands get through, then **~45 s of LOS** when everything is dropped. Frame a valid **CCSDS telecommand** and deliver it inside the window.

### Stage 3a — BUS HIJACK

**Service:** `flight-sw` (internal only)

The cFS-style flight software routes commands to apps by their **full 11-bit message id**, but authorizes them using only the **truncated low byte**. A privileged app whose low byte collides with an unrestricted one becomes reachable from a raw uplink — a classic parser-differential / route-confusion bug.

### Stage 3b — OBC ESCAPE

**Service:** `flight-sw` (internal only)

One of those now-reachable privileged apps copies your command payload into a fixed stack buffer with **no bounds check**. Overflow the saved return address (`-no-pie`, no stack canary, symbols intact) and **ret2win into the core flight-executive routine** — that's code execution on the OBC.

```
  ┌────────────┐   HTTP     ┌──────────────┐   CCSDS/TC    ┌───────────────┐   Software Bus   ┌──────────────┐
  │  attacker  │ ─────────▶ │ ground       │ ───(15s AOS)─▶│ uplink relay  │ ────(msgid)────▶ │  flight SW   │
  │            │            │ station web  │               │ (visibility)  │                  │  (cFS-like)  │
  └────────────┘            └──────────────┘               └───────────────┘                  └──────────────┘
    Stage 1: GROUND ZERO         Stage 2: SIGNAL PASS        Stage 3a: BUS HIJACK
    alg=none JWT → operator      ride the 15s window         ACL confusion → Stage 3b: OBC ESCAPE
```

## Run it

```bash
docker compose up --build
```

| Surface | URL / endpoint | Role |
|---|---|---|
| Ground station (web mission control) | http://localhost:8080 | **start here** |
| Uplink relay (raw TCP) | `localhost:9010` | stage 2+ |
| Scoreboard + 3D globe GUI | http://localhost:8000 | watch the mission, submit flags |

The `flight-sw` OBC is **not** directly reachable — it only speaks to the relay over the internal `spacelink` network, just like a real spacecraft behind a ground station.

## Directory structure

```
.
├── ground-station/     # Stage 1 — GROUND ZERO  (Flask web app)
├── uplink/             # Stage 2 — SIGNAL PASS  (CCSDS relay)
├── flight-sw/          # Stage 3a/3b — BUS HIJACK / OBC ESCAPE  (cFS-like flight software)
├── scoreboard/         # 3D situational-awareness globe + flag submission
├── solution/           # Organizer exploit scripts
├── config/             # Shared configuration
├── docs/               # Supporting images and diagrams
└── docker-compose.yml
```

## Challenge stages at a glance

| Stage | Name | Service | Bug class |
|---|---|---|---|
| 1 | GROUND ZERO | ground-station | JWT `alg:none` |
| 2 | SIGNAL PASS | uplink relay | CCSDS framing + timing |
| 3a | BUS HIJACK | flight-sw | ACL / msgid truncation |
| 3b | OBC ESCAPE | flight-sw | Stack buffer overflow → ret2win |
