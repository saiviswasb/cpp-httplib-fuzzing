#!/usr/bin/env python3
"""Triage every crash and hang of a campaign.

For each crashing input:
  1. replay it on out/afl/<target> (ASan + UBSan) and save the report,
  2. build a signature = bug type + top 3 stack frames (httplib.h frames
     preferred), so the same bug found 200 times counts as 1,
  3. minimize the smallest input per signature with afl-tmin.
Hangs are re-run with a long timeout to see if they reproduce.

Output: results/triage/<campaign>/
          TRIAGE.md           table for the report and the demo
          triage.json         machine-readable version
          <sig-id>/           report.txt, input (original), input.min

Usage (inside the container):  scripts/triage.py --name exp-01
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRAME = re.compile(r"^\s*#(\d+) 0x[0-9a-f]+ in (.+?) (/\S+?):(\d+)(?::\d+)?\s*$")
ASAN = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)(?: on .*?)?(?:\s|$)")
ASAN_ACCESS = re.compile(r"^(READ|WRITE) of size (\d+)", re.M)
UBSAN = re.compile(r"(\S+:\d+:\d+): runtime error: (.+)")
# Frames that belong to the sanitizer runtime, libc or the AFL++ driver.
SKIP_FUNCS = re.compile(r"^(__asan|__ubsan|__sanitizer|__interceptor|__libc|"
                        r"ExecuteFilesOnyByOne|main$|_start$)")
SKIP_FILES = re.compile(r"compiler-rt|sanitizer_common|aflpp_driver|libc\.so")
SAN_ENV = {
    "ASAN_OPTIONS": "symbolize=1:abort_on_error=1:detect_leaks=0:"
                    "allocator_may_return_null=1",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1:symbolize=1",
}


def replay(binary: Path, inp: Path, timeout: int) -> tuple[str, bool]:
    env = dict(os.environ, **SAN_ENV)
    try:
        r = subprocess.run([str(binary), str(inp)], env=env, capture_output=True,
                           text=True, errors="replace", timeout=timeout)
        return r.stdout + r.stderr, False
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"") + (e.stderr or b"")
        return out.decode(errors="replace") if isinstance(out, bytes) else out, True


def short_func(f: str) -> str:
    f = re.sub(r"\(.*", "", f)       # drop parameter list
    f = re.sub(r"<[^<>]*>", "", f)   # drop simple template args
    return f.replace("httplib::detail::", "detail::").replace("httplib::", "")


def signature(report: str) -> dict:
    kind, detail = "unknown-crash", ""
    m = ASAN.search(report)
    if m:
        kind = "asan:" + m.group(1)
        a = ASAN_ACCESS.search(report)
        if a:
            detail = f"{a.group(1)} of size {a.group(2)}"
    else:
        u = UBSAN.search(report)
        if u:
            kind = "ubsan"
            detail = u.group(2)[:120]
        elif "terminate called" in report or "uncaught exception" in report:
            kind = "uncaught-exception"
        elif "Assertion" in report:
            kind = "assertion"
    # Only the FIRST stack after the error line is the crash site. Later
    # stacks ("allocated by", "freed by") describe the memory, not the bug.
    frames, started = [], False
    lines = report.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if "ERROR: AddressSanitizer" in l or "runtime error:" in l), 0)
    for line in lines[start:]:
        fm = FRAME.match(line)
        if not fm:
            if started and line.strip() == "":
                break
            continue
        started = True
        func, file = short_func(fm.group(2)), fm.group(3)
        if SKIP_FUNCS.search(func) or SKIP_FILES.search(file):
            continue
        frames.append((func, Path(file).name, int(fm.group(4))))
    in_lib = [f for f in frames if f[1] == "httplib.h"]
    top = (in_lib or frames)[:3]
    key = kind + "|" + "|".join(f"{f[0]}:{f[2]}" for f in top)
    if kind == "ubsan" and not top:   # UBSan location is in the message itself
        u = UBSAN.search(report)
        key += "|" + (u.group(1) if u else "")
    return {"kind": kind, "detail": detail, "frames": top,
            "id": hashlib.sha1(key.encode()).hexdigest()[:8]}


def found_after(p: Path) -> int | None:
    m = re.search(r"time:(\d+)", p.name)
    return int(m.group(1)) // 1000 if m else None


def tmin(binary: Path, src: Path, dst: Path, crash: bool) -> int | None:
    env = dict(os.environ, AFL_NO_UI="1", **SAN_ENV)
    cmd = ["afl-tmin", "-i", str(src), "-o", str(dst)]
    if not crash:
        cmd += ["-H", "-t", "5000"]      # hang mode
    cmd += ["--", str(binary), "@@"]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=1800)
    return dst.stat().st_size if r.returncode == 0 and dst.exists() else None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="campaign name")
    ap.add_argument("--timeout", type=int, default=10, help="replay timeout (s)")
    ap.add_argument("--hang-timeout", type=int, default=30)
    ap.add_argument("--no-tmin", action="store_true")
    args = ap.parse_args()

    camp = ROOT / "results/campaigns" / args.name
    if not camp.is_dir():
        sys.exit(f"error: {camp} not found")
    out = ROOT / "results/triage" / args.name
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    crashes = sorted(camp.glob("*/*/run*/default/crashes/id:*"))
    hangs = sorted(camp.glob("*/*/run*/default/hangs/id:*"))
    print(f"[triage] {len(crashes)} crash inputs, {len(hangs)} hang inputs")

    groups: dict[str, dict] = {}
    for c in crashes:
        target, arm, run = c.parts[-6], c.parts[-5], c.parts[-4]
        binary = ROOT / "out/afl" / target
        report, timed_out = replay(binary, c, args.timeout)
        if timed_out:
            sig = {"kind": "timeout-on-replay", "detail": "", "frames": [],
                   "id": "to-" + target[:12]}
        elif "ERROR:" not in report and "runtime error" not in report \
                and "terminate called" not in report:
            sig = {"kind": "not-reproducible", "detail": "", "frames": [],
                   "id": "nr-" + target[:12]}
        else:
            sig = signature(report)
        sid = f"{target}-{sig['id']}"
        g = groups.setdefault(sid, {**sig, "sig": sid, "target": target,
                                    "hits": 0, "arms": set(), "runs": set(),
                                    "first_s": None, "inputs": [], "report": report})
        g["hits"] += 1
        g["arms"].add(arm)
        g["runs"].add(f"{arm}/{run}")
        t = found_after(c)
        if t is not None and (g["first_s"] is None or t < g["first_s"]):
            g["first_s"] = t
        g["inputs"].append(c)

    for g in groups.values():
        d = out / g["sig"]
        d.mkdir()
        smallest = min(g["inputs"], key=lambda p: p.stat().st_size)
        shutil.copy(smallest, d / "input")
        (d / "report.txt").write_text(g["report"])
        g["orig_size"] = smallest.stat().st_size
        g["min_size"] = None
        if not args.no_tmin and g["kind"] not in ("not-reproducible", "timeout-on-replay"):
            print(f"[tmin] {g['sig']} ({g['orig_size']} bytes)")
            g["min_size"] = tmin(ROOT / "out/afl" / g["target"], d / "input",
                                 d / "input.min", crash=True)

    hang_rows = []
    for h in hangs:
        target = h.parts[-6]
        _, timed_out = replay(ROOT / "out/afl" / target, h, args.hang_timeout)
        hang_rows.append({"target": target, "arm": h.parts[-5], "run": h.parts[-4],
                          "file": h.name, "reproduces": timed_out,
                          "size": h.stat().st_size})

    # ---------------------------------------------------------------- report
    L = [f"# Crash & hang triage: campaign `{args.name}`\n",
         f"- Crash inputs saved by AFL++: **{len(crashes)}**",
         f"- Unique crash signatures: **{len(groups)}** "
         "(bug type + top 3 stack frames, httplib.h frames preferred)",
         f"- Hang inputs: **{len(hangs)}**, reproducing with a "
         f"{args.hang_timeout}s timeout: **{sum(r['reproduces'] for r in hang_rows)}**\n"]
    if groups:
        L += ["## Unique crashes\n",
              "| ID | Target | Type | Detail | Top frames (httplib.h line) | Hits | "
              "Found in | First found | Size → min | Root cause (manual) | Status |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
        for g in sorted(groups.values(), key=lambda g: -g["hits"]):
            fr = "<br>".join(f"`{f[0]}` :{f[2]}" for f in g["frames"]) or "-"
            first = f"{g['first_s'] // 60} min" if g["first_s"] is not None else "?"
            mn = f"{g['orig_size']} → {g['min_size']}" if g["min_size"] else f"{g['orig_size']}"
            L.append(f"| `{g['sig']}` | {g['target']} | {g['kind']} | {g['detail']} | "
                     f"{fr} | {g['hits']} | {', '.join(sorted(g['runs']))} | {first} | "
                     f"{mn} | _todo_ | new |")
        L.append("\nFill in **Root cause** and **Status** by hand after reading each "
                 "`report.txt`. Claude Code can suggest a root cause; record whether "
                 "it was right in the AI process log.\n")
    else:
        L.append("## Unique crashes\n\nNo crashes. Report this together with the "
                 "total executions and run time from `summary.csv`.\n")
    if hang_rows:
        L += ["## Hangs\n", "| Target | Arm/run | File | Size | Reproduces |",
              "|---|---|---|---|---|"]
        for r in hang_rows:
            L.append(f"| {r['target']} | {r['arm']}/{r['run']} | `{r['file'][:40]}` | "
                     f"{r['size']} | {'yes' if r['reproduces'] else 'no'} |")
    (out / "TRIAGE.md").write_text("\n".join(L) + "\n")
    (out / "triage.json").write_text(json.dumps(
        [{k: (sorted(v) if isinstance(v, set) else v) for k, v in g.items()
          if k not in ("inputs", "report")} for g in groups.values()]
        + [{"hang": r} for r in hang_rows], indent=1, default=str))
    print(f"[triage] {len(groups)} unique -> {(out / 'TRIAGE.md').relative_to(ROOT)}")


if __name__ == "__main__":
    main()
