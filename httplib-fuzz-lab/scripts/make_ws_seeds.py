#!/usr/bin/env python3
"""Write valid RFC 6455 frames as seeds for websocket_frame_fuzzer.

Each file = 1 config byte (bit 7: expect_masked, bits 0-2: max_len bucket)
followed by one or more frames, exactly as they would arrive on a socket.
"""
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "corpora/websocket"
MASK = b"\x37\xfa\x21\x3d"

def frame(opcode, payload, fin=True, masked=True, force_len=None):
    b0 = (0x80 if fin else 0) | opcode
    n = len(payload) if force_len is None else force_len
    mbit = 0x80 if masked else 0
    if n <= 125 and force_len is None:
        hdr = bytes([b0, mbit | n])
    elif n <= 0xFFFF:
        hdr = bytes([b0, mbit | 126]) + struct.pack(">H", n)
    else:
        hdr = bytes([b0, mbit | 127]) + struct.pack(">Q", n)
    if masked:
        body = bytes(c ^ MASK[i % 4] for i, c in enumerate(payload))
        return hdr + MASK + body
    return hdr + payload

def cfg(masked, bucket):
    return bytes([(0x80 if masked else 0) | bucket])

SEEDS = {
    "text_masked":      cfg(1, 5) + frame(0x1, b"Hello"),
    "text_unmasked":    cfg(0, 5) + frame(0x1, b"Hello", masked=False),
    "text_utf8_multi":  cfg(1, 5) + frame(0x1, "héllo €𝄞".encode()),
    "binary_len126":    cfg(1, 5) + frame(0x2, b"A" * 126),
    "binary_len64bit":  cfg(1, 0) + frame(0x2, b"B" * 300, force_len=70000),
    "fragmented_text":  cfg(1, 5) + frame(0x1, b"Hel", fin=False) + frame(0x0, b"lo"),
    "ping_pong":        cfg(1, 5) + frame(0x9, b"p") + frame(0xA, b"p"),
    "close_1000":       cfg(1, 5) + frame(0x8, struct.pack(">H", 1000) + b"bye"),
    "close_empty":      cfg(1, 5) + frame(0x8, b""),
    "limit_125":        cfg(1, 1) + frame(0x2, b"C" * 125),
}

OUT.mkdir(parents=True, exist_ok=True)
for name, data in SEEDS.items():
    (OUT / name).write_bytes(data)
print(f"wrote {len(SEEDS)} seeds to {OUT}")
