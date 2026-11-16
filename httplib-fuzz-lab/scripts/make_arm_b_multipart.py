#!/usr/bin/env python3
"""Generate arm-B seeds and dictionary for multipart_parser_fuzzer.

Harness input layout (test/fuzzing/multipart_parser_fuzzer.cc):
  data[0]                 boundary_len = data[0] % 16 + 1   (1..16)
  data[1 : 1+len]         raw boundary (no quote stripping, no 70-char cap)
  data[1+len :]           multipart body fed to FormDataParser::parse()
  data[1]                 (= boundary[0]) also picks the feed chunk size:
                          data[1] % 64 + 1
  If boundary_len + 1 >= size, boundary falls back to "----fuzzboundary" and
  the body starts at data[1]. Inputs must be 2..65536 bytes.

Writes exactly 15 seeds into corpora/multipart_parser_fuzzer/B/ (old files
deleted first) and dicts/multipart_parser_fuzzer/B.dict.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED_DIR = os.path.join(ROOT, "corpora", "multipart_parser_fuzzer", "B")
DICT_PATH = os.path.join(ROOT, "dicts", "multipart_parser_fuzzer", "B.dict")

CRLF = b"\r\n"


def seed(boundary: bytes, body: bytes) -> bytes:
    """Encode boundary + body in the harness's input format."""
    assert 1 <= len(boundary) <= 16, boundary
    out = bytes([len(boundary) - 1]) + boundary + body
    # Must not trigger the default-boundary fallback.
    assert len(boundary) + 1 < len(out), boundary
    return out


def chunk_size(data: bytes) -> int:
    return data[1] % 64 + 1


def part(boundary: bytes, headers, content: bytes) -> bytes:
    out = b"--" + boundary + CRLF
    for h in headers:
        out += h.encode() + CRLF
    return out + CRLF + content + CRLF


def close(boundary: bytes) -> bytes:
    return b"--" + boundary + b"--" + CRLF


def cd(params: str) -> str:
    return "Content-Disposition: form-data; " + params


def seeds():
    s = {}

    # 01 single text field, the canonical shape.
    b = b"AaB03x"
    s["01_single_field"] = seed(b, part(b, [cd('name="field1"')], b"value1")
                                + close(b))

    # 02 several parts: text fields + one with explicit Content-Type.
    b = b"sev3ral"
    s["02_several_parts"] = seed(b,
        part(b, [cd('name="a"')], b"alpha")
        + part(b, [cd('name="b"')], b"bravo\r\nsecond line")
        + part(b, [cd('name="c"'), "Content-Type: application/json"],
               b'{"k":[1,2,3]}')
        + close(b))

    # 03 file parts: filename, Content-Type, binary content.
    b = b"f1leB0undary"
    s["03_file_parts"] = seed(b,
        part(b, [cd('name="upload"; filename="report.txt"'),
                 "Content-Type: text/plain"], b"line1\r\nline2\r\n")
        + part(b, [cd('name="img"; filename="a.bin"'),
                   "Content-Type: application/octet-stream",
                   "Content-Transfer-Encoding: binary"],
               bytes(range(0, 32)) + b"\xff\xfe\r\r\n\n")
        + close(b))

    # 04 longest boundary the harness allows (16 bytes).
    b = b"----WebKitFormBo"
    s["04_long_boundary_16"] = seed(b,
        part(b, [cd('name="long"')], b"x" * 40) + close(b))

    # 05 "quoted" boundary: harness passes the quotes through literally, so
    # the body delimiter must include them too.
    b = b'"q=b;c d"'
    s["05_quoted_boundary_literal"] = seed(b,
        part(b, [cd('name="q"')], b"quoted boundary chars")
        + close(b))

    # 06 content containing near-copies of the delimiter that must NOT match.
    b = b"XYZ123"
    tricky = (b"--XYZ123 not after CRLF\r\n"
              b"\r\n--XYZ12\r\n"            # one byte short
              b"\r\n-XYZ123\r\n"            # one dash short
              b"\r\n--xyz123\r\n"           # wrong case
              b"\r\n--XYZ_123\r")           # interleaved byte, dangling CR
    s["06_boundary_lookalikes_in_content"] = seed(b,
        part(b, [cd('name="t"')], tricky + b" tail") + close(b))

    # 07 missing CRLF after the opening dash-boundary (state 0 never matches).
    b = b"nocrlf"
    s["07_missing_crlf_after_boundary"] = seed(b,
        b"--nocrlf" + cd('name="x"').encode() + CRLF + CRLF + b"data"
        + CRLF + close(b))

    # 08 missing blank line between part headers and content, and close
    # delimiter not preceded by CRLF.
    b = b"hdrEnd"
    s["08_missing_crlf_header_end"] = seed(b,
        b"--hdrEnd\r\n" + cd('name="h"').encode() + CRLF
        + b"Content-Type: text/plain\r\n"
        + b"content right after headers--hdrEnd--\r\n")

    # 09 Content-Disposition variants that are accepted.
    b = b"cdVar"
    s["09_disposition_variants"] = seed(b,
        part(b, ["content-disposition:FORM-DATA;name=bare"], b"1")
        + part(b, ["Content-Disposition:\t form-data;\tname=\"semi;colon\"; "
                   "filename=\"a\\\"b.txt\""], b"2")
        + part(b, [cd("name=\"u\"; filename=\"x.txt\"; "
                      "filename*=UTF-8''%E2%82%AC%20rates.txt")], b"3")
        + part(b, [cd('name="dup"; name="dup"; name="other"')], b"4")
        + part(b, ["Content-Disposition: attachment; name=\"ignored\"",
                   "CONTENT-TYPE:   text/html  "], b"5")
        + close(b))

    # 10 Content-Disposition variants that are rejected.
    b = b"cdBad"
    s["10_disposition_rejected"] = seed(b,
        part(b, [cd('filename="noname.txt"')], b"missing name")
        + part(b, [cd("name=\"x\"; filename*=ISO-8859-1''abc")], b"bad charset")
        + part(b, ["Bad Header Without Colon"], b"z")
        + close(b))

    # 11 empty parts: no headers at all, and empty content.
    b = b"empty"
    s["11_empty_parts"] = seed(b,
        b"--empty\r\n\r\n\r\n"                       # no headers, no content
        + part(b, [cd('name="e"')], b"")             # header, empty content
        + b"--empty\r\n\r\n\r\n"
        + close(b))

    # 12 missing closing boundary: body ends inside the last part.
    b = b"unclosed"
    s["12_missing_close_boundary"] = seed(b,
        part(b, [cd('name="a"')], b"first")
        + b"--unclosed\r\n" + cd('name="b"').encode() + CRLF + CRLF
        + b"truncated content with no final delimiter\r\n--unclo")

    # 13 one-byte boundary, preamble before and epilogue after.
    b = b"z"
    s["13_preamble_epilogue_1byte"] = seed(b,
        b"This is the preamble; it is ignored.\r\n"
        + part(b, [cd('name="p"')], b"zz--z inside")
        + b"--z--\r\nepilogue --z\r\n" + cd('name="late"').encode()
        + b"\r\n\r\nignored")

    # 14 transport padding / junk after a boundary (rejected in state 4).
    b = b"pad"
    s["14_junk_after_boundary"] = seed(b,
        part(b, [cd('name="a"')], b"ok")
        + b"--pad  \t\r\n" + cd('name="b"').encode() + b"\r\n\r\nx\r\n"
        + close(b))

    # 15 binary boundary with first byte 0x00 -> chunk size 1, so every
    # CRLF and delimiter is split across parse() calls.
    b = b"\x00\x01bin\xffB"
    s["15_binary_boundary_chunk1"] = seed(b,
        part(b, [cd('name="s"; filename="s.dat"'),
                 "Content-Type: application/octet-stream"],
             b"\r\n-\r\n--\x00\x01bin\xff" + b"\r" + b"\n")
        + close(b))

    return s


DICT = [
    ("dash2", "--"), ("crlf", "\\x0d\\x0a"), ("crlfcrlf", "\\x0d\\x0a\\x0d\\x0a"),
    ("crlf_dash2", "\\x0d\\x0a--"), ("close_tail", "--\\x0d\\x0a"),
    ("cr", "\\x0d"), ("lf", "\\x0a"), ("nul", "\\x00"), ("tab", "\\x09"),
    ("ff", "\\xff"),
    ("cd", "Content-Disposition:"), ("cd_lc", "content-disposition:"),
    ("cd_full", "Content-Disposition: form-data; "),
    ("form_data", "form-data;"), ("form_data_uc", "FORM-DATA;"),
    ("attachment", "attachment;"),
    ("name_q", "name=\\x22"), ("name_bare", "name="),
    ("filename_q", "filename=\\x22"), ("filename_star", "filename*="),
    ("utf8_pfx", "UTF-8''"), ("utf8_lc", "utf-8''"), ("iso_pfx", "ISO-8859-1''"),
    ("semi", "; "), ("semi_nosp", ";"), ("quote", "\\x22"),
    ("esc_quote", "\\x5c\\x22"), ("eq", "="), ("colon", ":"),
    ("ct", "Content-Type:"), ("ct_lc", "content-type:"),
    ("ct_text", "text/plain"), ("ct_oct", "application/octet-stream"),
    ("ct_json", "application/json"), ("ct_mixed", "multipart/mixed"),
    ("cte", "Content-Transfer-Encoding: binary"),
    ("pct_euro", "%E2%82%AC"), ("pct_sp", "%20"), ("pct_nul", "%00"),
    ("pct_slash", "%2F"), ("pct_bad", "%zz"), ("dotdot", "../"),
    ("b_aab", "AaB03x"), ("b_webkit", "----WebKitFormBo"),
    ("b_default", "----fuzzboundary"),
    ("dash_b_default", "------fuzzboundary\\x0d\\x0a"),
    ("q_name", "name=\\x22a\\x22"), ("q_fname", "filename=\\x22a.txt\\x22"),
    ("sp_tab", " \\x09"), ("x_hdr", "X-Custom: v"),
    ("len16", "\\x0f"), ("len1", "\\x00"),
]


def main():
    s = seeds()
    assert len(s) == 15, len(s)
    assert len(DICT) <= 60, len(DICT)

    os.makedirs(SEED_DIR, exist_ok=True)
    for name in os.listdir(SEED_DIR):
        p = os.path.join(SEED_DIR, name)
        if os.path.isfile(p) or os.path.islink(p):
            os.remove(p)

    for name, data in s.items():
        assert 2 <= len(data) <= 65536, (name, len(data))
        with open(os.path.join(SEED_DIR, name), "wb") as f:
            f.write(data)

    os.makedirs(os.path.dirname(DICT_PATH), exist_ok=True)
    with open(DICT_PATH, "w") as f:
        for k, v in DICT:
            f.write(f'{k}="{v}"\n')

    for name in sorted(os.listdir(SEED_DIR)):
        data = s[name]
        blen = data[0] % 16 + 1
        print(f"{name}\t{len(data)} bytes\tboundary_len={blen}\t"
              f"chunk={chunk_size(data)}")
    print(f"{os.path.relpath(DICT_PATH, ROOT)}\t{len(DICT)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
