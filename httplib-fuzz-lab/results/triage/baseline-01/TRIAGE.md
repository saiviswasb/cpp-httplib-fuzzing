> **INVALID RUN.** The fuzzing binaries were built with cov_runner.cc instead of the AFL++ driver, so every input reached only ~3 edges. Replaced by baseline-02.

# Crash & hang triage: campaign `baseline-01`

- Crash inputs saved by AFL++: **0**
- Unique crash signatures: **0** (bug type + top 3 stack frames, httplib.h frames preferred)
- Hang inputs: **0**, reproducing with a 30s timeout: **0**

## Unique crashes

No crashes. Report this together with the total executions and run time from `summary.csv`.

