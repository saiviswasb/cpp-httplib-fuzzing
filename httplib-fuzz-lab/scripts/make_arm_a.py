#!/usr/bin/env python3
"""Arm A: Hand-crafted seeds written by Sai (Human-authored)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def http(*lines, body=b""):
    """Join request lines with CRLF (\r\n) and add the blank line before the body."""
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body

def mp(boundary: bytes, body: bytes):
    """multipart_parser_fuzzer format: [len-1][boundary][body], boundary 1..16 bytes."""
    assert 1 <= len(boundary) <= 16, "Boundary must be 1 to 16 bytes"
    return bytes([len(boundary) - 1]) + boundary + body

# ---------------------------------------------------------------------------
# 17 Server Seeds (Raw HTTP/1.1 Requests)
# ---------------------------------------------------------------------------
SERVER = {
    "01_valid_get":          http("GET / HTTP/1.1", "Host: localhost"),
    "02_valid_head":         http("HEAD /index.html HTTP/1.1", "Host: localhost"),
    "03_valid_post_body":    http("POST /api HTTP/1.1", "Host: localhost", "Content-Length: 5", body=b"hello"),
    "04_invalid_method":     http("CUSTOMMETHOD / HTTP/1.1", "Host: localhost"),
    "05_invalid_version":    http("GET / HTTP/2.0", "Host: localhost"),
    "06_missing_host":       http("GET / HTTP/1.1"),
    "07_duplicate_host":     http("GET / HTTP/1.1", "Host: server1", "Host: server2"),
    "08_content_len_zero":   http("POST / HTTP/1.1", "Host: localhost", "Content-Length: 0"),
    "09_content_len_large":  http("POST / HTTP/1.1", "Host: localhost", "Content-Length: 999999999"),
    "10_chunked_valid":      http("POST / HTTP/1.1", "Host: localhost", "Transfer-Encoding: chunked", body=b"5\r\nhello\r\n0\r\n\r\n"),
    "11_range_single":       http("GET /file.txt HTTP/1.1", "Host: localhost", "Range: bytes=0-499"),
    "12_range_multi":        http("GET /file.txt HTTP/1.1", "Host: localhost", "Range: bytes=0-10,20-30"),
    "13_range_suffix":       http("GET /file.txt HTTP/1.1", "Host: localhost", "Range: bytes=-500"),
    "14_percent_encoded":    http("GET /test%20space%21 HTTP/1.1", "Host: localhost"),
    "15_multipart_post":     http("POST /upload HTTP/1.1", "Host: localhost", "Content-Type: multipart/form-data; boundary=X", body=b"--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--X--\r\n"),
    "16_header_no_colon":    http("GET / HTTP/1.1", "Host localhost"),
    "17_expect_continue":    http("POST /data HTTP/1.1", "Host: localhost", "Expect: 100-continue"),
}

# ---------------------------------------------------------------------------
# 15 Multipart Seeds (Binary Format: [len-1][boundary][body])
# ---------------------------------------------------------------------------
MULTIPART = {
    "01_boundary_1byte":     mp(b"X", b"--X\r\nContent-Disposition: form-data; name=\"field\"\r\n\r\nval\r\n--X--\r\n"),
    "02_boundary_16byte":    mp(b"1234567890123456", b"--1234567890123456\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--1234567890123456--\r\n"),
    "03_single_part":        mp(b"BOUND", b"--BOUND\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nAlice\r\n--BOUND--\r\n"),
    "04_multi_parts":        mp(b"BOUND", b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--BOUND\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--BOUND--\r\n"),
    "05_file_part":          mp(b"BOUND", b"--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\ndata\r\n--BOUND--\r\n"),
    "06_missing_closing":    mp(b"BOUND", b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nval\r\n"),
    "07_missing_crlf":       mp(b"BOUND", b"--BOUND\nContent-Disposition: form-data; name=\"a\"\n\nval\n--BOUND--\n"),
    "08_empty_part":         mp(b"BOUND", b"--BOUND\r\nContent-Disposition: form-data; name=\"empty\"\r\n\r\n\r\n--BOUND--\r\n"),
    "09_no_disposition":     mp(b"BOUND", b"--BOUND\r\nContent-Type: text/plain\r\n\r\norphaned data\r\n--BOUND--\r\n"),
    "10_boundary_in_body":   mp(b"BOUND", b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\ntext contains --BOUND here\r\n--BOUND--\r\n"),
    "11_binary_payload":     mp(b"BOUND", b"--BOUND\r\nContent-Disposition: form-data; name=\"bin\"\r\n\r\n\x00\x01\x02\xff\xfe\r\n--BOUND--\r\n"),
    "12_quoted_boundary":    mp(b"BOUND", b"--BOUND\r\nContent-Type: multipart/form-data; boundary=\"BOUND\"\r\n\r\nval\r\n--BOUND--\r\n"),
    "13_extra_headers":      mp(b"BOUND", b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\nX-Custom: test\r\n\r\nval\r\n--BOUND--\r\n"),
    "14_spaces_in_header":   mp(b"BOUND", b"--BOUND\r\nContent-Disposition : form-data ; name = \"a\"\r\n\r\nval\r\n--BOUND--\r\n"),
    "15_leading_crlf":       mp(b"BOUND", b"\r\n--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nval\r\n--BOUND--\r\n"),
}

def write(target, seeds, expected):
    d = ROOT / "corpora" / target / "A"
    d.mkdir(parents=True, exist_ok=True)
    for f in d.iterdir():
        f.unlink()
    for name, data in seeds.items():
        assert len(data) < 2048, f"{name} is too big"
        (d / name).write_bytes(data)
    print(f"{target}: {len(seeds)} seeds (want {expected})")

if __name__ == "__main__":
    write("server_fuzzer", SERVER, 17)
    write("multipart_parser_fuzzer", MULTIPART, 15)
