#!/usr/bin/env python3
"""Run AFL++ fuzzing campaigns: a baseline crash hunt or the A/B/C experiment.

Each job = one afl-fuzz process, pinned to one CPU core, for a fixed time.
Jobs are queued and run --jobs at a time until all are done.

Seeds:  corpora/<target>/<arm>/          (required; for arm "baseline" the 5
                                           upstream targets fall back to
                                           upstream's corpus)
Dict:   dicts/<target>/<arm>.dict        (optional; arm "baseline" of
                                           server/client falls back to upstream's)
Output: results/campaigns/<name>/<target>/<arm>/run<k>/default/...
        results/campaigns/<name>/summary.csv

Examples (inside the Docker container, from the repo root):
  # show what would run, without running anything
  scripts/campaign.py --name baseline-01 --mode baseline --hours 4 --dry-run

  # crash hunt: every target once, 4 h each, 4 at a time
  scripts/campaign.py --name baseline-01 --mode baseline --hours 4

  # experiment: 2 targets x 3 arms x 3 runs, 2 h each
  scripts/campaign.py --name exp-01 --mode experiment \\
      --targets server_fuzzer multipart_parser_fuzzer --arms A B C --runs 3 --hours 2

  # after an interruption: skip finished jobs, restart unfinished ones
  scripts/campaign.py --name exp-01 --mode experiment ... --resume
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALL_TARGETS = ["server_fuzzer", "client_fuzzer", "header_parser_fuzzer",
               "url_parser_fuzzer", "multipart_parser_fuzzer",
               "websocket_frame_fuzzer", "chunked_decoder_fuzzer"]
UPSTREAM = ROOT / "third_party/cpp-httplib/test/fuzzing"
UPSTREAM_DICT_TARGETS = {"server_fuzzer", "client_fuzzer"}
# Only upstream's own targets may fall back to upstream's (HTTP) corpus.
# Custom targets parse other formats and must bring their own seeds.
UPSTREAM_TARGETS = {"server_fuzzer", "client_fuzzer", "header_parser_fuzzer",
                    "url_parser_fuzzer", "multipart_parser_fuzzer"}
STAT_FIELDS = ["run_time", "execs_done", "execs_per_sec", "corpus_count",
               "corpus_found", "edges_found", "total_edges", "bitmap_cvg",
               "saved_crashes", "saved_hangs", "stability"]
print_lock = threading.Lock()
CHECK_AFTER = 300   # seconds before the watchdog checks progress
MIN_EDGES = 10      # a run at or below this many edges is considered broken


def log(msg: str) -> None:
    with print_lock:
        print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def git_rev(path: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True).stdout.strip() or "?"
    except OSError:
        return "?"


def dir_digest(d: Path) -> str:
    """Hash of all seed file contents: proves which seeds a run used."""
    h = hashlib.sha256()
    for f in sorted(p for p in d.iterdir() if p.is_file()):
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()[:16]


def resolve_inputs(target: str, arm: str) -> tuple[Path, Path | None]:
    seeds = ROOT / "corpora" / target / arm
    if not seeds.is_dir() or not any(seeds.iterdir()):
        if arm == "baseline" and target in UPSTREAM_TARGETS:
            seeds = UPSTREAM / "corpus"
        else:
            sys.exit(f"error: no seeds in corpora/{target}/{arm}/ "
                     f"(custom targets need their own seeds there)")
    d = ROOT / "dicts" / target / f"{arm}.dict"
    if not d.exists():
        d = (UPSTREAM / "server_fuzzer.dict"
             if arm == "baseline" and target in UPSTREAM_DICT_TARGETS else None)
    return seeds, d


def cpu_governor() -> str:
    p = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    return p.read_text().strip() if p.exists() else "unknown"


def read_stats(run_dir: Path) -> dict:
    f = run_dir / "default" / "fuzzer_stats"
    out = {}
    if f.exists():
        for line in f.read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip() in STAT_FIELDS:
                    out[k.strip()] = v.strip()
    return out


def run_job(job: dict, seconds: int, cores: "queue.Queue[int]") -> dict:
    core = cores.get()
    try:
        run_dir: Path = job["dir"]
        if run_dir.exists():
            shutil.rmtree(run_dir)
        run_dir.mkdir(parents=True)
        cmd = ["afl-fuzz", "-i", str(job["seeds"]), "-o", str(run_dir),
               "-V", str(seconds), "-b", str(core), "-s", str(job["seed"])]
        if job["dict"]:
            cmd += ["-x", str(job["dict"])]
        cmd += ["--", str(ROOT / "out/afl" / job["target"])]
        env = dict(os.environ, AFL_NO_UI="1", AFL_SKIP_CPUFREQ="1",
                   AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1")
        meta = {k: str(v) for k, v in job.items() if k != "dir"}
        meta.update(core=core, seconds=seconds, cmd=" ".join(cmd),
                    started=dt.datetime.now().isoformat(timespec="seconds"),
                    seeds_sha256=dir_digest(job["seeds"]),
                    repo_commit=git_rev(ROOT),
                    httplib_commit=git_rev(ROOT / "third_party/cpp-httplib"),
                    cpu_governor=cpu_governor(), finished=False)
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=1))
        log(f"start  {job['label']} on core {core}")
        # Watchdog: a healthy run finds dozens of edges within minutes. If it
        # is still at <= MIN_EDGES after CHECK_AFTER seconds, the harness is not
        # receiving input (see baseline-01): stop it instead of wasting hours.
        reason = ""
        with open(run_dir / "afl.log", "w") as lf:
            p = subprocess.Popen(cmd, env=env, stdout=lf, stderr=subprocess.STDOUT)
            t0 = time.time()
            checked = False
            while p.poll() is None:
                time.sleep(5)
                if not checked and time.time() - t0 >= CHECK_AFTER:
                    checked = True
                    edges = int(read_stats(run_dir).get("edges_found", 0) or 0)
                    if edges <= MIN_EDGES:
                        reason = (f"watchdog: only {edges} edges after "
                                  f"{CHECK_AFTER}s, harness is not getting input")
                        p.terminate()
                if time.time() - t0 > seconds + 600:
                    reason = "killed: exceeded time limit"
                    p.kill()
            rc = p.wait()
        stats = read_stats(run_dir) if not reason else {}
        meta.update(finished=bool(stats), returncode=rc, failure=reason,
                    ended=dt.datetime.now().isoformat(timespec="seconds"))
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=1))
        if not stats:
            log(f"FAIL   {job['label']}: {reason or 'afl-fuzz did not start'}"
                f" (see {run_dir}/afl.log)")
        else:
            log(f"done   {job['label']}: edges {stats.get('edges_found')}, "
                f"crashes {stats.get('saved_crashes')}, "
                f"{stats.get('execs_per_sec')} exec/s")
        return {**job, **stats, "finished": bool(stats)}
    finally:
        cores.put(core)


def main() -> None:
    global CHECK_AFTER
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="campaign name, e.g. exp-01")
    ap.add_argument("--mode", choices=["baseline", "experiment"], required=True)
    ap.add_argument("--targets", nargs="+", default=ALL_TARGETS)
    ap.add_argument("--arms", nargs="+", default=["A", "B", "C"])
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--hours", type=float, default=2.0)
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1,
                    help="parallel afl-fuzz processes (default: nproc)")
    ap.add_argument("--resume", action="store_true",
                    help="keep finished runs, redo only unfinished ones")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check-after", type=int, default=CHECK_AFTER,
                    help="seconds before the stuck-run watchdog checks (default 300)")
    args = ap.parse_args()

    CHECK_AFTER = args.check_after
    arms = ["baseline"] if args.mode == "baseline" else args.arms
    runs = 1 if args.mode == "baseline" else args.runs
    seconds = int(args.hours * 3600)
    base = ROOT / "results/campaigns" / args.name

    # Run-major order (run1: every target/arm, then run2, ...) spreads any
    # drift in machine conditions evenly across the arms. Run k uses AFL++
    # random seed 1000+k in every arm, so arms are compared pairwise.
    jobs = []
    for k in range(1, runs + 1):
        for t in args.targets:
            b = ROOT / "out/afl" / t
            if not b.exists():
                sys.exit(f"error: out/afl/{t} missing; run scripts/build.sh")
            if b"##SIG_AFL_PERSISTENT##" not in b.read_bytes():
                sys.exit(f"error: out/afl/{t} has no AFL++ persistent driver; "
                         f"rebuild with scripts/build.sh (do not link cov_runner.cc)")
            for a in arms:
                seeds, d = resolve_inputs(t, a)
                jobs.append({"label": f"{t}/{a}/run{k}", "target": t, "arm": a,
                             "run": k, "seed": 1000 + k, "seeds": seeds, "dict": d,
                             "dir": base / t / a / f"run{k}"})

    todo = []
    for j in jobs:
        m = j["dir"] / "meta.json"
        if args.resume and m.exists() and json.loads(m.read_text()).get("finished"):
            continue
        todo.append(j)

    jobs_par = min(args.jobs, os.cpu_count() or 1)
    waves = -(-len(todo) // jobs_par) if todo else 0
    print(f"Campaign '{args.name}' ({args.mode}): {len(jobs)} jobs, "
          f"{len(todo)} to run, {jobs_par} in parallel, {args.hours} h each")
    print(f"Estimated wall time: {waves * args.hours:.1f} h ({waves} waves)")
    print(f"CPU governor: {cpu_governor()}  (want 'performance' for stable exec/s)\n")
    for j in todo:
        print(f"  {j['label']:45s} seeds={j['seeds'].relative_to(ROOT)} "
              f"({sum(1 for p in j['seeds'].iterdir() if p.is_file())} files) "
              f"dict={j['dict'].relative_to(ROOT) if j['dict'] else '-'}")
    if args.dry_run or not todo:
        return
    if not shutil.which("afl-fuzz"):
        sys.exit("error: afl-fuzz not on PATH")

    base.mkdir(parents=True, exist_ok=True)
    cores: queue.Queue[int] = queue.Queue()
    for c in range(jobs_par):
        cores.put(c)
    results = []
    threads = []
    lock = threading.Lock()

    def worker(job):
        r = run_job(job, seconds, cores)
        with lock:
            results.append(r)

    # Start a job whenever a core is free.
    sem = threading.Semaphore(jobs_par)
    for j in todo:
        sem.acquire()
        th = threading.Thread(target=lambda j=j: (worker(j), sem.release()))
        th.start()
        threads.append(th)
        time.sleep(2)  # stagger startup (calibration is CPU-heavy)
    for th in threads:
        th.join()

    # Summary over ALL jobs of the campaign (including earlier resumed ones).
    rows = []
    for j in jobs:
        st = read_stats(j["dir"])
        rows.append({"target": j["target"], "arm": j["arm"], "run": j["run"],
                     **{k: st.get(k, "") for k in STAT_FIELDS}})
    with open(base / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["target", "arm", "run", *STAT_FIELDS])
        w.writeheader()
        w.writerows(rows)
    failed = [r["label"] for r in results if not r.get("finished")]
    print(f"\nSummary -> {(base / 'summary.csv').relative_to(ROOT)}")
    if failed:
        print("FAILED jobs (re-run with --resume):", *failed, sep="\n  ")
        sys.exit(1)


if __name__ == "__main__":
    main()
