"""
Simplified CCSDS Space Packet Protocol (TC) profile for the DEEP SAT EXPLOIT CTF.

This is a teaching subset of CCSDS 133.0-B / the cFS command format. It is intentionally
small so players can craft frames by hand, but the field layout is faithful.

Frame layout (all big-endian):

  Primary header (6 bytes)
    +--------+--------+--------+--------+--------+--------+
    |  b0    |  b1    |  b2    |  b3    |  b4    |  b5    |
    +--------+--------+--------+--------+--------+--------+
    b0-b1 : ver(3)=000 | type(1)=1(TC) | secHdrFlag(1)=1 | APID(11)
    b2-b3 : seqFlags(2)=11 | seqCount(14)
    b4-b5 : packet data length = (len(secondary_header + payload) - 1)

  Secondary header (2 bytes)  -- cFS-style command secondary header
    b6    : command code (function code)
    b7    : checksum = XOR of every OTHER byte in the frame, 8-bit

  Payload (N bytes)

Routing note: cFS routes a command by its MsgId, which here is derived from the full
11-bit APID. Keep that in mind when you reach the flight software.
"""

PRIMARY_LEN = 6
SECONDARY_LEN = 2


def _checksum(frame_wo_ck: bytes) -> int:
    ck = 0
    for b in frame_wo_ck:
        ck ^= b
    return ck & 0xFF


def build_tc(apid: int, cmd_code: int, payload: bytes = b"", seq_count: int = 0) -> bytes:
    """Build a valid CCSDS TC frame with a correct secondary-header checksum."""
    apid &= 0x07FF
    # primary header
    w0 = (0 << 13) | (1 << 12) | (1 << 11) | apid          # ver/type/secHdr/apid
    w1 = (0b11 << 14) | (seq_count & 0x3FFF)               # seqFlags=unsegmented, count
    data_len = (SECONDARY_LEN + len(payload)) - 1
    ph = bytes([
        (w0 >> 8) & 0xFF, w0 & 0xFF,
        (w1 >> 8) & 0xFF, w1 & 0xFF,
        (data_len >> 8) & 0xFF, data_len & 0xFF,
    ])
    # secondary header with placeholder checksum(0), then fix it up
    frame = ph + bytes([cmd_code & 0xFF, 0x00]) + payload
    ba = bytearray(frame)
    ba[7] = 0x00
    ba[7] = _checksum(bytes(ba[:7]) + bytes(ba[8:]))
    return bytes(ba)


def parse_tc(frame: bytes):
    """Parse a frame; returns dict. Raises ValueError on malformed input."""
    if len(frame) < PRIMARY_LEN + SECONDARY_LEN:
        raise ValueError("frame too short")
    w0 = (frame[0] << 8) | frame[1]
    apid = w0 & 0x07FF
    ptype = (w0 >> 12) & 1
    sec = (w0 >> 11) & 1
    data_len = ((frame[4] << 8) | frame[5]) + 1
    cmd_code = frame[6]
    checksum = frame[7]
    payload = frame[PRIMARY_LEN + SECONDARY_LEN:]
    return {
        "apid": apid,
        "type": ptype,
        "sec_hdr": sec,
        "data_len": data_len,
        "cmd_code": cmd_code,
        "checksum": checksum,
        "payload": payload,
    }


def checksum_ok(frame: bytes) -> bool:
    if len(frame) < PRIMARY_LEN + SECONDARY_LEN:
        return False
    calc = _checksum(frame[:7] + frame[8:])
    return calc == frame[7]
