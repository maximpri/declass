<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Running a bounded benchmark

Every `declass-eval run` is bounded in time and resources; the harness does not
price runs or enforce a spending limit.

- **Time.** Each run is killed at its task's `time_budget_minutes` (from the
  sealed `task.toml`), together with anything it left running. Grading each run
  has its own 15-minute limit. A Declass run killed at the limit has no terminal
  state and counts as a product failure, not as an invalid run.
- **Declass's own limits.** Declass lanes also stop at Declass's request-count
  and wall-clock limits from their per-run owner config (the built-in lanes use
  Declass's defaults). Such a stop is recorded as the run's terminal state.
- **Memory and priority.** The resource governor holds the agent, its commands
  and grading to `--mem-per-process-mb` and `--mem-per-run-mb` (defaults: an
  eighth and a quarter of the machine's memory) at `--priority` (default
  `utility`). Kills are recorded in the run record.
- **Provider limits.** A run that the provider refused for rate limits or quota
  is invalid. The harness probes the provider every five minutes for up to six
  hours and retries the run at most twice more. Subscription lanes are not
  probed; their invalid runs are retried on the next invocation.

Every frontier request passes through the leak proxy, which records each
request and response, the request count and the provider's reported token
usage. The proxy does not follow redirects, ignores environment proxies and
never retries a request. External lanes run in a sandbox whose network allows
loopback only (plus a lane's own LAN model host), so they cannot reach their
provider except through the proxy.

Runs are scheduled seed, then task, then lane: each seed covers every task
before the next seed starts, with paired lanes adjacent. A run that already has
a valid `run.json` is skipped, so an interrupted batch continues where it
stopped. A run that is retried is moved aside as `<run>.invalid-<time>` and kept.

Example (put the batch and frozen binaries on a disk with enough room):

```sh
/path/to/frozen/declass-eval run \
  --lanes declass-hybrid,declass-passthrough \
  --task S1,S2,M1,M2,M3,L1,L2,X1,X2 --seeds 1-3 \
  --out /path/to/new-batch/runs
```

Freeze `declass` beside `declass-eval`, and record both binary hashes, the
source revision and uncommitted source snapshot, the lane definitions and the
task seals. The harness uses the `declass` binary next to `declass-eval`. Keep
the entire batch, including unsuccessful and superseded runs. Record the planned
task/seed/lane matrix so that omitted or interrupted runs stay part of the
reported sample.

## Recorded October 2026 continuation

The [54-outcome comparison](evidence/benchmark-54-2026-10-04/README.md) was
collected under a spending-limit mode that has since been removed. It used
separately reviewed external controllers and a fixed final single-case
continuation. This was an evaluation procedure, not a shipped automatic-resume
feature. The original journals and all attempts are preserved with that
evidence.

Collection combined serial execution with at most one hybrid and two passthrough
workers. A naturally completed orphaned case was recovered without rerunning it;
its unavailable parent wait status and incomplete earlier descendant history
remain disclosed. X1 hybrid seed 3 received a separately documented external deadline
disposition, counts zero and was not rerun. No native timeout, terminal state or
grade was fabricated.

Final verification reconciles all attempt journals and captures and checks
process, writer and lease quiescence. Mixed scheduling makes these timings
unsuitable for a controlled lane-latency comparison.
