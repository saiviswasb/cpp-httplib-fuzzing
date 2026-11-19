# AI Process Log

## Entry 1: Arm B seeds for server_fuzzer (2026-11-16)
- Tool: Claude Code v2.1.325, model Opus 5.5, Claude Pro, auto permission mode
- Prompt: asked for scripts/make_arm_b_server.py writing exactly 17 raw HTTP/1.1
  seeds + B.dict (max 60 entries); told to read only server_fuzzer.cc and httplib.h,
  and not docs/, results/ or corpora/ (to keep Arm B independent of Arm A and the gap report).
- What it did: read server_fuzzer.cc and parts of httplib.h (parse_request_line,
  process_request, range and header handling), then wrote the script and ran it.
  Output: 17 seeds (49-424 bytes), 60-entry dictionary.
- Useful findings by the AI: HTTP/1.1 needs exactly one Host header or the request is
  rejected; Range is only parsed for GET/HEAD and the handler body is 16 bytes, so
  ranges were kept in 0-15; obs-fold is rejected by httplib.
- Problems: one shell command failed (sed syntax error); the AI noticed and
  retried another way. It deleted 2 old Arm B files as instructed. It did not
  test the seeds against the fuzzer binary itself.
- How I checked: file count = 17; od -c shows CRLF line endings; dictionary lines
  validated with grep; initial coverage measured with afl-showmap (see Step 5 results).

## Entry 2: Arm B seeds for multipart_parser_fuzzer (2026-11-16)
- Tool: same session as Entry 1
- Prompt: same structure, 15 seeds, read only multipart_parser_fuzzer.cc and httplib.h
- What it did: discovered the harness input format (byte 0 = boundary length 1-16,
  then raw boundary, then body; byte 1 also sets the feed chunk size) and built
  all seeds in that format. Output: 15 seeds, 52-entry dictionary.
- Problems: its first draft of seed 06 accidentally contained the real delimiter
  inside the content (would end the part early). The AI caught and fixed this
  before running. It noted that quoted boundaries and the 70-character limit
  cannot be tested through this harness (parse_multipart_boundary is never called).
- Impact on the experiment: this format discovery showed my hand-written Arm A
  multipart seeds had to be checked for the same format (see Step C).
- How I checked: file count = 15; dictionary validated with grep; initial
  coverage measured with afl-showmap.

## Entry 3: AI review of hand-written Arm A (2026-11-16)
- Claude (chat) reviewed my Arm A script only for accidental errors: found 2 typos
  (missing \n in multipart seeds 08 and 11) and the too-small A dictionaries
  (replaced with upstream's standard server_fuzzer.dict, 210 entries).
- No seed ideas or seed contents were suggested by the AI. Arm A content is my own.
- Also found: the earlier "Arm A" folders were copies of upstream's corpus, not
  hand-written seeds, and the multipart ones were in the wrong input format.
  Moved to corpora/_old_arm_a/ and replaced.

## Entry 4: AI hypothesis tested and refuted (2026-11-19)
- Claude (chat) explained B's lead by 3 "gate" seeds (gzip, trailers, filename*).
- I tested it with an ablation (Bminus = B without those seeds, 3 runs x 2 h).
- Result: Bminus still reached all 16 B-only functions; only ~1.5% fewer server
  lines. The AI's explanation was wrong; the advantage is the dictionary plus
  the broader seed set. Lesson: AI analysis must be verified experimentally.
