#!/usr/bin/env python3
"""Phase 5: analyze an A/B/C experiment campaign.

For every target and arm (3 runs each) this produces:
  1. Edge coverage over time, from AFL++'s own plot_data (mean + min/max band).
  2. Line coverage of httplib.h over time, measured with llvm-cov:
     every queue entry carries "time:<ms>" in its name, so each run's queue is
     split into time buckets, each bucket is replayed ONCE through out/cov/<t>,
     and the bucket profiles are merged cumulatively (bucket 0..k = coverage
     at checkpoint k). Cheap, and exact for the inputs AFL++ kept.
  3. Statistics on final coverage: mean, min-max range, Vargha-Delaney A12
     effect size and an exact Mann-Whitney U p-value (permutation test).
  4. Time to reach Arm A's final mean coverage (how much faster the other
     arms get to where A ends).
  5. Functions reached by one arm and never by another (union over runs).

Output: results/analysis/<name>/
          SUMMARY.md, edges_<target>.png, lines_<target>.png,
          timeseries.csv, final.csv, functions_diff_<target>.md

Usage (inside the container, after `pip install --break-system-packages matplotlib`):
  scripts/analyze_experiment.py --name exp-02
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
import re
import shutil
import statistics as st
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "third_party/cpp-httplib/httplib.h"
COLORS = {"A": "#1f77b4", "B": "#d62728", "C": "#2ca02c"}
LABELS = {"A": "A: hand-written", "B": "B: Claude Code", "C": "C: A+B (afl-cmin)"}


def tool(name: str) -> str:
    for c in (f"{name}-18", name):
        if shutil.which(c):
            return c
    sys.exit(f"error: {name} not found")


# --------------------------------------------------------------------- data
def read_plot_data(run: Path) -> list[tuple[float, int, int]]:
    """(minutes, edges_found, total_execs) rows from AFL++ plot_data."""
    f = run / "default" / "plot_data"
    if not f.exists():
        return []
    lines = f.read_text().splitlines()
    cols = [c.strip().lstrip("#").strip() for c in lines[0].split(",")]
    it, ie, ix = cols.index("relative_time"), cols.index("edges_found"), cols.index("total_execs")
    rows = []
    for ln in lines[1:]:
        p = [x.strip() for x in ln.split(",")]
        if len(p) == len(cols):
            rows.append((int(p[it]) / 60.0, int(p[ie]), int(p[ix])))
    return rows


def run_seconds(run: Path) -> int:
    f = run / "default" / "fuzzer_stats"
    for ln in f.read_text().splitlines() if f.exists() else []:
        if ln.startswith("run_time"):
            return int(ln.split(":")[1])
    return 0


def value_at(rows, minute):
    """Last value at or before `minute` (step function)."""
    v = None
    for t, e, _ in rows:
        if t <= minute + 1e-9:
            v = e
        else:
            break
    return v


# ---------------------------------------------------------- llvm-cov replay
def line_coverage_over_time(target, run, checkpoints, work, profdata, llvmcov):
    """Return ({minute: (covered, total)}, set_of_covered_function_names)."""
    q = run / "default" / "queue"
    entries = []
    for f in q.iterdir():
        if f.is_file() and f.name.startswith("id:"):
            m = re.search(r"time:(\d+)", f.name)
            entries.append(((int(m.group(1)) if m else 0) / 60000.0, f))
    binary = ROOT / "out/cov" / target
    wdir = Path(tempfile.mkdtemp(dir=work))
    raws = []
    prev = -1.0
    for k, cp in enumerate(checkpoints):
        bucket = [f for t, f in entries if prev < t <= cp or (k == 0 and t <= cp)]
        prev = cp
        bdir = wdir / f"b{k}"
        bdir.mkdir()
        for f in bucket:
            os.symlink(f.resolve(), bdir / f.name)
        raw = wdir / f"b{k}.profraw"
        env = dict(os.environ, LLVM_PROFILE_FILE=str(raw))
        subprocess.run([str(binary), str(bdir)], env=env, capture_output=True)
        if raw.exists():
            raws.append(raw)
    result, funcs = {}, set()
    for k, cp in enumerate(checkpoints):
        upto = [r for r in raws if int(r.stem[1:]) <= k]
        if not upto:
            continue
        pd = wdir / f"c{k}.profdata"
        subprocess.run([profdata, "merge", "-sparse", *map(str, upto), "-o", str(pd)],
                       check=True, capture_output=True)
        last = k == len(checkpoints) - 1
        args = [llvmcov, "export", str(binary), f"-instr-profile={pd}", str(HEADER)]
        if not last:
            args.insert(2, "-summary-only")
        js = json.loads(subprocess.run(args, check=True, capture_output=True,
                                       text=True).stdout)
        for fdata in js["data"][0]["files"]:
            if Path(fdata["filename"]).resolve() == HEADER.resolve():
                s = fdata["summary"]["lines"]
                result[cp] = (s["covered"], s["count"])
        if last:
            for fn in js["data"][0].get("functions", []):
                if fn["count"] > 0 and fn["filenames"] and \
                        Path(fn["filenames"][0]).resolve() == HEADER.resolve():
                    funcs.add(fn["name"])
    shutil.rmtree(wdir, ignore_errors=True)
    return result, funcs


def demangle(names: set[str]) -> dict[str, str]:
    if not names:
        return {}
    names = sorted(names)
    out = subprocess.run([tool("llvm-cxxfilt")], input="\n".join(names),
                         capture_output=True, text=True).stdout.splitlines()
    simple = {}
    for raw, dem in zip(names, out):
        s, depth, keep = dem, 0, []
        for ch in s:                       # drop template arguments
            if ch == "<":
                depth += 1
            elif ch == ">" and depth:
                depth -= 1
            elif depth == 0:
                keep.append(ch)
        s = "".join(keep)
        lam = "'lambda" in s
        s = s.split("(")[0].split()[-1] if s.split() else s
        s = s.replace("httplib::detail::", "detail::").replace("httplib::", "")
        simple[raw] = s + ("::<lambda>" if lam else "")
    return simple


# --------------------------------------------------------------- statistics
def a12(x, y):
    """Vargha-Delaney A12: probability that a value from x beats one from y."""
    wins = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a in x for b in y)
    return wins / (len(x) * len(y))


def mann_whitney_exact(x, y):
    """Two-sided exact p-value by enumerating all label permutations."""
    pooled = x + y
    n = len(x)

    def stat(idx):
        xs = [pooled[i] for i in idx]
        ys = [pooled[i] for i in range(len(pooled)) if i not in idx]
        return abs(a12(xs, ys) - 0.5)

    obs = abs(a12(x, y) - 0.5)
    combos = list(itertools.combinations(range(len(pooled)), n))
    extreme = sum(1 for c in combos if stat(set(c)) >= obs - 1e-12)
    return extreme / len(combos)


def fmt_stats(vals):
    return f"{st.mean(vals):.1f} ({min(vals)}–{max(vals)})"


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True)
    ap.add_argument("--checkpoints", default="0,1,2,5,10,15,20,30,45,60,75,90,105,120",
                    help="minutes at which line coverage is measured")
    ap.add_argument("--no-llvm", action="store_true", help="skip llvm-cov replay")
    args = ap.parse_args()

    camp = ROOT / "results/campaigns" / args.name
    out = ROOT / "results/analysis" / args.name
    out.mkdir(parents=True, exist_ok=True)
    work = out / ".work"
    work.mkdir(exist_ok=True)
    profdata, llvmcov = (None, None) if args.no_llvm else (tool("llvm-profdata"), tool("llvm-cov"))
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        plt = None
        print("[warn] matplotlib missing: no PNG plots "
              "(pip install --break-system-packages matplotlib)")

    targets = sorted(p.name for p in camp.iterdir() if p.is_dir())
    md = [f"# Experiment analysis: `{args.name}`\n",
          "Edges = AFL++ `edges_found`; lines = llvm-cov line coverage of "
          "`httplib.h` from replaying each run's queue through `out/cov/<target>`. "
          "Values are mean (min–max) over runs.\n"]
    ts_rows, final_rows = [], []

    for t in targets:
        arms = sorted(p.name for p in (camp / t).iterdir() if p.is_dir())
        runs = {a: sorted((camp / t / a).glob("run*")) for a in arms}
        dur = max(run_seconds(r) for a in arms for r in runs[a]) / 60.0
        cps = [float(c) for c in args.checkpoints.split(",") if float(c) < dur] + [dur]
        print(f"[{t}] arms {arms}, {dur:.0f} min, checkpoints {cps}")

        edges, lines, funcs, execs, fin_e, fin_l = {}, {}, {}, {}, {}, {}
        for a in arms:
            edges[a] = [read_plot_data(r) for r in runs[a]]
            fin_e[a] = [rows[-1][1] for rows in edges[a] if rows]
            execs[a] = [rows[-1][2] for rows in edges[a] if rows]
            lines[a], funcs[a] = [], set()
            if not args.no_llvm:
                for r in runs[a]:
                    lc, fs = line_coverage_over_time(t, r, cps, work, profdata, llvmcov)
                    lines[a].append(lc)
                    funcs[a] |= fs
                    print(f"  {a}/{r.name}: final lines {lc.get(cps[-1])}")
            fin_l[a] = [lc[cps[-1]][0] for lc in lines[a] if cps[-1] in lc]

        # ---- time series CSV + plots
        grid = sorted(set([round(x, 2) for x in cps] +
                          [m for m in range(1, int(dur) + 1)]))
        for a in arms:
            for m in grid:
                ev = [value_at(rows, m) for rows in edges[a]]
                ev = [v for v in ev if v is not None]
                lv = [lc[m][0] for lc in lines[a] if m in lc]
                ts_rows.append({"target": t, "arm": a, "minute": m,
                                "edges_mean": st.mean(ev) if ev else "",
                                "edges_min": min(ev) if ev else "",
                                "edges_max": max(ev) if ev else "",
                                "lines_mean": st.mean(lv) if lv else "",
                                "lines_min": min(lv) if lv else "",
                                "lines_max": max(lv) if lv else ""})
        if plt:
            for kind in ("edges", "lines"):
                fig, ax = plt.subplots(figsize=(7, 4.2))
                for a in arms:
                    rows = [r for r in ts_rows if r["target"] == t and r["arm"] == a
                            and r[f"{kind}_mean"] != ""]
                    if not rows:
                        continue
                    x = [r["minute"] for r in rows]
                    ax.plot(x, [r[f"{kind}_mean"] for r in rows], color=COLORS.get(a),
                            label=LABELS.get(a, a), linewidth=2)
                    ax.fill_between(x, [r[f"{kind}_min"] for r in rows],
                                    [r[f"{kind}_max"] for r in rows],
                                    color=COLORS.get(a), alpha=0.18, linewidth=0)
                ax.set_xlabel("Time (minutes)")
                ax.set_ylabel("Edges found (AFL++)" if kind == "edges"
                              else "Lines covered in httplib.h (llvm-cov)")
                ax.set_title(f"{t}: {kind} over time (mean, band = min–max of runs)")
                ax.grid(alpha=0.3)
                ax.legend(loc="lower right")
                fig.tight_layout()
                fig.savefig(out / f"{kind}_{t}.png", dpi=150)
                plt.close(fig)

        # ---- final table + stats
        md.append(f"## `{t}`\n")
        md.append(f"![edges](edges_{t}.png)\n")
        if not args.no_llvm:
            md.append(f"![lines](lines_{t}.png)\n")
        md.append("| Arm | Runs | Final edges | Final lines (httplib.h) | Total execs (M) |")
        md.append("|---|---|---|---|---|")
        for a in arms:
            fl = fmt_stats(fin_l[a]) if fin_l[a] else "-"
            ex = f"{st.mean(execs[a]) / 1e6:.1f} ({min(execs[a]) / 1e6:.1f}–{max(execs[a]) / 1e6:.1f})"
            md.append(f"| {LABELS.get(a, a)} | {len(runs[a])} | {fmt_stats(fin_e[a])} | {fl} | {ex} |")
            final_rows.append({"target": t, "arm": a, "edges": fin_e[a],
                               "lines": fin_l[a], "execs": execs[a]})
        md.append("")

        md.append("**Pairwise comparison of final coverage** (A12 = probability that "
                  "a run of the first arm beats a run of the second; 0.5 = no "
                  "difference, 1.0 = always better).\n")
        md.append("| Comparison | Metric | A12 | Exact Mann-Whitney p (two-sided) |")
        md.append("|---|---|---|---|")
        for x, y in itertools.combinations(arms, 2):
            for metric, d in (("edges", fin_e), ("lines", fin_l)):
                if d[x] and d[y]:
                    md.append(f"| {y} vs {x} | {metric} | {a12(d[y], d[x]):.2f} | "
                              f"{mann_whitney_exact(d[y], d[x]):.3f} |")
        n = len(runs[arms[0]])
        md.append(f"\nWith {n} runs per arm, the smallest possible two-sided p-value "
                  f"is {2 / len(list(itertools.combinations(range(2 * n), n))):.3f}, "
                  "so report A12 as the main effect size.\n")

        if "A" in arms:
            target_e = st.mean(fin_e["A"])
            md.append(f"**Time to reach Arm A's final mean coverage** "
                      f"({target_e:.0f} edges):\n")
            for a in arms:
                times = []
                for rows in edges[a]:
                    hit = next((tm for tm, e, _ in rows if e >= target_e), None)
                    times.append(hit)
                got = [x for x in times if x is not None]
                txt = (f"{st.mean(got):.1f} min (reached in {len(got)}/{len(times)} runs)"
                       if got else f"not reached in {len(times)} runs")
                md.append(f"- {LABELS.get(a, a)}: {txt}")
            md.append("")

        if not args.no_llvm and len(arms) > 1:
            names = demangle(set().union(*funcs.values()))
            diff = [f"# Functions reached by one arm but not another: `{t}`\n",
                    "Union over all runs of each arm. Function names simplified "
                    "(templates and parameters dropped).\n"]
            for x, y in itertools.permutations(arms, 2):
                only = sorted({names[f] for f in funcs[x] - funcs[y]})
                diff.append(f"## In {x} but never in {y}: {len(only)}\n")
                diff += [f"- `{s}`" for s in only] + [""]
            (out / f"functions_diff_{t}.md").write_text("\n".join(diff))
            md.append(f"Function-level differences: see "
                      f"[functions_diff_{t}.md](functions_diff_{t}.md).\n")
            for x, y in (("A", "B"), ("B", "A")):
                if x in funcs and y in funcs:
                    md.append(f"- Functions in {x} never reached by {y}: "
                              f"{len({names[f] for f in funcs[x] - funcs[y]})}")
            md.append("")

    with open(out / "timeseries.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(ts_rows[0].keys()))
        w.writeheader()
        w.writerows(ts_rows)
    with open(out / "final.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["target", "arm", "run", "edges", "lines", "execs"])
        for r in final_rows:
            for i, e in enumerate(r["edges"]):
                w.writerow([r["target"], r["arm"], i + 1, e,
                            r["lines"][i] if i < len(r["lines"]) else "",
                            r["execs"][i] if i < len(r["execs"]) else ""])
    (out / "SUMMARY.md").write_text("\n".join(md) + "\n")
    shutil.rmtree(work, ignore_errors=True)
    print(f"[done] {out.relative_to(ROOT)}/SUMMARY.md")


if __name__ == "__main__":
    main()
