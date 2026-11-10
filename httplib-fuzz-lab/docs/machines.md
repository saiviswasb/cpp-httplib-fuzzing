# Which machine does what

The rule: **every experiment run happens on the Linux lab machine, inside the
Docker image.** The comparison between Arms A, B and C is only valid if all
runs share the same CPU, kernel, toolchain and duration. The Windows laptop
is for writing code, running quick checks, and everything that isn't a
measured fuzzing run.

| Work | Linux lab machine | Windows laptop |
|---|---|---|
| Docker image build, `fetch.sh`, `build.sh` | Yes | Optional (WSL2) |
| Smoke tests (60 s), harness compile checks | Yes | Yes (WSL2) |
| 2–4 h experiment runs (Arms A/B/C × runs) | **Only here** | Never |
| afl-cmin, afl-tmin, crash triage | Yes | Optional (WSL2) |
| Coverage replay (llvm-cov) | Yes | Optional (WSL2) |
| Writing harnesses, scripts, docs | | Yes (VS Code) |
| Claude Code sessions (Arm B seeds, triage help) | | Yes |
| GitHub issues, PRs, reviews | | Yes |
| Plots, report, slides, demo recording | | Yes |

## Why not run the experiment on the laptop
- The laptop sleeps, throttles under heat, and runs other programs. Any of
  these changes execs/sec, so the arms would no longer be comparable.
- AFL++ only runs on Linux. On Windows it runs inside WSL2, which adds a
  virtualization layer the lab machine doesn't have.

## Lab machine: one-time setup
```bash
nproc                       # cores decide how many runs can go in parallel
docker run --rm hello-world # checks Docker access (else ask IT for docker group)
# AFL++ needs crashes to go to a plain core file, not a crash-report helper:
echo core | sudo tee /proc/sys/kernel/core_pattern
```
Run long campaigns inside `tmux` so they survive an SSH disconnect.

## Laptop: one-time setup (optional WSL2)
```powershell
wsl --install -d Ubuntu-24.04
```
Then, inside Ubuntu, install Docker Desktop with WSL2 integration, or follow
the same apt steps as in `docker/Dockerfile`.
