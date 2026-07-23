"""Simplified CCSDS TC profile -- shared copy (see ground-station/ccsds.py for the full doc)."""

PRIMARY_LEN = 6
SECONDARY_LEN = 2


def _checksum(frame_wo_ck: bytes) -> int:
    ck = 0
    for b in frame_wo_ck:
        ck ^= b
    return ck & 0xFF


def build_tc(apid: int, cmd_code: int, payload: bytes = b"", seq_count: int = 0) -> bytes:
    apid &= 0x07FF
    w0 = (0 << 13) | (1 << 12) | (1 << 11) | apid
    w1 = (0b11 << 14) | (seq_count & 0x3FFF)
    data_len = (SECONDARY_LEN + len(payload)) - 1
    ph = bytes([
        (w0 >> 8) & 0xFF, w0 & 0xFF,
        (w1 >> 8) & 0xFF, w1 & 0xFF,
        (data_len >> 8) & 0xFF, data_len & 0xFF,
    ])
    ba = bytearray(ph + bytes([cmd_code & 0xFF, 0x00]) + payload)
    ba[7] = 0x00
    ba[7] = _checksum(bytes(ba[:7]) + bytes(ba[8:]))
    return bytes(ba)


def parse_tc(frame: bytes):
    if len(frame) < PRIMARY_LEN + SECONDARY_LEN:
        raise ValueError("frame too short")
    w0 = (frame[0] << 8) | frame[1]
    return {
        "apid": w0 & 0x07FF,
        "type": (w0 >> 12) & 1,
        "sec_hdr": (w0 >> 11) & 1,
        "data_len": ((frame[4] << 8) | frame[5]) + 1,
        "cmd_code": frame[6],
        "checksum": frame[7],
        "payload": frame[PRIMARY_LEN + SECONDARY_LEN:],
    }


def checksum_ok(frame: bytes) -> bool:
    if len(frame) < PRIMARY_LEN + SECONDARY_LEN:
        return False
    return _checksum(frame[:7] + frame[8:]) == frame[7]
