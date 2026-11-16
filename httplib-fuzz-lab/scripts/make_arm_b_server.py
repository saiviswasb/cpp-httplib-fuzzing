#!/usr/bin/env python3
"""Generate arm-B seeds and dictionary for server_fuzzer.

Writes exactly 17 raw HTTP/1.1 request seeds into corpora/server_fuzzer/B/
(old files there are deleted first) and dicts/server_fuzzer/B.dict.
All seeds use exact CRLF line endings; each is < 2 KB.
"""
import gzip
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED_DIR = os.path.join(ROOT, "corpora", "server_fuzzer", "B")
DICT_PATH = os.path.join(ROOT, "dicts", "server_fuzzer", "B.dict")

CRLF = b"\r\n"


def req(start_line, headers, body=b""):
    """Build a raw request; headers is a list of (name, value) or raw lines."""
    out = start_line.encode() + CRLF
    for h in headers:
        out += (h.encode() if isinstance(h, str) else h) + CRLF
    return out + CRLF + body


def with_cl(start_line, headers, body):
    return req(start_line, headers + [f"Content-Length: {len(body)}"], body)


def seeds():
    s = {}

    # --- methods -----------------------------------------------------------
    s["01_get_basic"] = req("GET /index.html HTTP/1.1", [
        "Host: localhost:8080",
        "User-Agent: fuzz/1.0",
        "Accept: text/html, application/json;q=0.9, */*;q=0.1",
        "Accept-Encoding: gzip, br, zstd",
        "Connection: keep-alive",
    ])
    s["02_head_http10_keepalive"] = req("HEAD /status HTTP/1.0", [
        "Connection: keep-alive",
    ])
    s["03_options_asterisk"] = req("OPTIONS * HTTP/1.1", [
        "Host: example.com",
        "Access-Control-Request-Method: PUT",
        "Origin: http://example.org",
    ])

    # --- Content-Length edge values ---------------------------------------
    s["04_delete_cl_zero"] = req("DELETE /item/42 HTTP/1.1", [
        "Host: localhost",
        "Content-Length: 0",
    ])
    # Duplicate identical Content-Length with leading zeros (accepted).
    s["05_put_cl_dup_leading_zeros"] = req("PUT /data HTTP/1.1", [
        "Host: localhost",
        "Content-Type: application/octet-stream",
        "Content-Length: 0005",
        "Content-Length: 0005",
    ], b"hello")

    # --- chunked with extensions and trailers -----------------------------
    chunked_body = (
        b"5;name=val;flag\r\nhello\r\n"
        b"1A; ext=\"quoted;value\"\r\nabcdefghijklmnopqrstuvwxyz\r\n"
        b"0;last\r\n"
        b"X-Checksum: abc123\r\n"
        b"X-Trailer-Two: done\r\n"
        b"\r\n"
    )
    s["06_post_chunked_ext_trailers"] = req("POST /upload HTTP/1.1", [
        "Host: localhost",
        "Transfer-Encoding: chunked",
        "Trailer: X-Checksum, X-Trailer-Two",
        "Content-Type: text/plain",
    ], chunked_body)

    # --- Range (handler body is 16 bytes: "response content") -------------
    s["07_get_range_single"] = req("GET /file HTTP/1.1", [
        "Host: localhost", "Range: bytes=0-4"])
    s["08_get_range_multi"] = req("GET /file HTTP/1.1", [
        "Host: localhost", "Range: bytes=0-1,4-6,9-15"])
    s["09_get_range_suffix"] = req("GET /file HTTP/1.1", [
        "Host: localhost", "Range: bytes=-7"])
    s["10_get_range_open_ended"] = req("GET /file HTTP/1.1", [
        "Host: localhost", "Range: bytes=9-"])
    s["11_get_range_if_range"] = req("GET /file HTTP/1.1", [
        "Host: localhost",
        "Range: bytes=2-10",
        "If-Range: Wed, 21 Oct 2015 07:28:00 GMT",
        "If-None-Match: \"abc\"",
    ])

    # --- multipart/form-data ----------------------------------------------
    bnd = "----fuzzBoundary7MA4YWxk"
    mp = (
        f"--{bnd}\r\n"
        "Content-Disposition: form-data; name=\"field1\"\r\n"
        "\r\n"
        "value one\r\n"
        f"--{bnd}\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"a%20b.txt\"; "
        "filename*=UTF-8''a%C3%A9.txt\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "file contents\r\nline2\r\n"
        f"--{bnd}--\r\n"
    ).encode()
    s["12_post_multipart"] = with_cl("POST /form HTTP/1.1", [
        "Host: localhost",
        f"Content-Type: multipart/form-data; boundary={bnd}",
    ], mp)

    # --- gzip Content-Encoding (urlencoded so params get parsed) ----------
    gz = gzip.compress(b"a=1&b=hello%20world&c=%E2%82%AC&d", mtime=0)
    s["13_post_gzip_urlencoded"] = with_cl("POST /submit HTTP/1.1", [
        "Host: localhost",
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Encoding: gzip",
    ], gz)

    # --- Expect: 100-continue ---------------------------------------------
    s["14_post_expect_100_continue"] = with_cl("POST /big HTTP/1.1", [
        "Host: localhost",
        "Expect: 100-continue",
        "Content-Type: application/json",
    ], b'{"k":"v","n":[1,2,3]}')

    # --- percent-encoded path and query -----------------------------------
    s["15_get_percent_encoded"] = req(
        "GET /a%20b/%2e%2e/c%2Fd/%E2%82%AC?q=%41%42&x=a+b&e=%zz&empty=&k&arr=1&arr=2 HTTP/1.1",
        ["Host: localhost"])

    # --- malformed: obsolete line folding (rejected) ----------------------
    s["16_get_obs_fold"] = req("GET /fold HTTP/1.1", [
        "Host: localhost",
        "X-Folded: first part",
        " continued part",
        "\tand a tab continuation",
    ])

    # --- malformed: TE + non-zero CL smuggling attempt (rejected 400) -----
    s["17_post_te_cl_conflict"] = req("POST /smuggle HTTP/1.1", [
        "Host: localhost",
        "Content-Length: 6",
        "Transfer-Encoding: chunked",
    ], b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n")

    return s


DICT = [
    ("m_get", "GET "), ("m_head", "HEAD "), ("m_post", "POST "),
    ("m_put", "PUT "), ("m_delete", "DELETE "), ("m_options", "OPTIONS "),
    ("m_patch", "PATCH "), ("m_connect", "CONNECT "), ("m_trace", "TRACE "),
    ("m_pri", "PRI "),
    ("v11", " HTTP/1.1\\x0d\\x0a"), ("v10", " HTTP/1.0\\x0d\\x0a"),
    ("crlf", "\\x0d\\x0a"), ("crlfcrlf", "\\x0d\\x0a\\x0d\\x0a"),
    ("lf", "\\x0a"), ("nul", "\\x00"), ("sp", " "), ("tab", "\\x09"),
    ("h_host", "Host: "), ("h_cl", "Content-Length: "),
    ("h_te", "Transfer-Encoding: "), ("h_ct", "Content-Type: "),
    ("h_ce", "Content-Encoding: "), ("h_range", "Range: "),
    ("h_ifrange", "If-Range: "), ("h_expect", "Expect: "),
    ("h_conn", "Connection: "), ("h_trailer", "Trailer: "),
    ("h_accept", "Accept: "), ("h_xff", "X-Forwarded-For: "),
    ("h_upgrade", "Upgrade: websocket"),
    ("chunked", "chunked"), ("chunk_end", "0\\x0d\\x0a\\x0d\\x0a"),
    ("chunk_ext", ";ext=\\x22v\\x22"),
    ("gzip", "gzip"), ("deflate", "deflate"), ("br", "br"), ("zstd", "zstd"),
    ("gzip_magic", "\\x1f\\x8b\\x08\\x00"),
    ("continue", "100-continue"), ("close", "close"), ("keepalive", "keep-alive"),
    ("bytes", "bytes="), ("range_suffix", "bytes=-1"),
    ("range_multi", "0-0,1-"), ("big_num", "18446744073709551615"),
    ("mp_ct", "multipart/form-data; boundary="),
    ("form_ct", "application/x-www-form-urlencoded"),
    ("cd", "Content-Disposition: form-data; name=\\x22"),
    ("filename", "; filename=\\x22"), ("filename_star", "filename*=UTF-8''"),
    ("dashdash", "--"),
    ("pct_slash", "%2F"), ("pct_dot", "%2e%2e"), ("pct_nul", "%00"),
    ("pct_utf8", "%E2%82%AC"), ("query", "?a=1&b"),
    ("star", "*"), ("http_date", "Wed, 21 Oct 2015 07:28:00 GMT"),
    ("etag", "\\x22abc\\x22"),
]


def main():
    s = seeds()
    assert len(s) == 17, len(s)
    assert len(DICT) <= 60, len(DICT)

    os.makedirs(SEED_DIR, exist_ok=True)
    for name in os.listdir(SEED_DIR):
        p = os.path.join(SEED_DIR, name)
        if os.path.isfile(p) or os.path.islink(p):
            os.remove(p)

    for name, data in s.items():
        assert len(data) < 2048, (name, len(data))
        head = data.split(b"\r\n\r\n", 1)[0]
        assert b"\n" not in head.replace(b"\r\n", b""), name  # bare LF check
        with open(os.path.join(SEED_DIR, name), "wb") as f:
            f.write(data)

    os.makedirs(os.path.dirname(DICT_PATH), exist_ok=True)
    with open(DICT_PATH, "w") as f:
        for k, v in DICT:
            f.write(f'{k}="{v}"\n')

    for name in sorted(os.listdir(SEED_DIR)):
        print(f"{name}\t{os.path.getsize(os.path.join(SEED_DIR, name))}")
    print(f"{os.path.relpath(DICT_PATH, ROOT)}\t{len(DICT)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
