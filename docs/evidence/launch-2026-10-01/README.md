<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Original launch runs, October 1, 2026

Four synthetic billing runs recorded with Duet (Declass's earlier name) on macOS ARM64,
local date October 1 (America/Toronto), UTC October 2. Each used the unchanged
[fictional billing fixture](../../launch/billing-demo/README.md); the acceptance command was
`python3 -m unittest -v`. Capture source was commit `c9e1d5aaa427ad19b4650529f73079cbfe81c973`;
the first run used the development snapshot `a36cee764b355239a95fff7bd19e9ef7656d288e`.
The [demonstration guide](../../launch/DEMO.md#what-the-first-run-found) explains the failures
and fixes.

The raw recordings (audit logs, transcripts, terminal casts) were removed before publication because they contained session identifiers and local paths.

## Runs

| Run | Code state | Coding tests | Frontier requests | Complete planted values found |
| --- | --- | ---: | ---: | ---: |
| Before fixes (hybrid) | Development snapshot `a36cee7` | 4/4 | 4 | **36 occurrences of 13 values — failed** |
| Preview fix only (hybrid) | Diagnostic-preview fix | 4/4 | 4 | **9 occurrences — failed** |
| Both fixes (hybrid) | `c9e1d5a` | 4/4 | 4 | **0 of 13** |
| Top clearance | `c9e1d5a` | 4/4 | 0 (5 local requests) | not applicable |

Repeated appearances in conversation history count separately; they are not unique people or
secrets. The planted-value check scanned recorded request bodies for complete fixture values in
literal, base64, hex and URL-encoded forms. It does not observe provider receipt or all host
traffic, and it does not detect fragments or paraphrase.

- **Before fixes.** The disclosure report counted 4 requests, all changed by the outbound filter,
  with 3 name placeholders and 1 secret placeholder. A reserved-domain email matched an error
  keyword, so CSV fields entered a detector-only diagnostic preview. The audit chain still
  verified (8 records, anchor matched): integrity did not establish safe content. A regression
  test written for this case failed before the fix, reporting three planted values in the second
  request.
- **Preview fix only.** Short monetary values repeated by the local digest still reached the
  frontier. Structured-value checks followed.
- **Both fixes.** 4 requests filtered, 1 secret placeholder, 1 synthetic sample shown, 0 blocked
  sends. The audit verified with 8 records and a matching anchor, both with Declass's verifier and
  an independent script.
- **Tampered copy.** Changing only the final record's `model` field in a copy of the successful
  audit left the internal chain intact, but the original anchor rejected the rewritten head.
  The independent script also reported the mismatch. The source audit was not modified.
- **Top clearance.** Eight audit records with five model requests, all to the configured local
  endpoint, and no frontier requests; the audit verified against its anchor. It read code and
  tests, not the customer CSV.

## Retained files

| File | What it shows |
| --- | --- |
| [before-tests.txt](before-tests.txt) | One failing test before the repair |
| [after-tests.txt](after-tests.txt), [top-clearance-tests.txt](top-clearance-tests.txt) | 4/4 passing after each repair |
| [billing-fix.patch](billing-fix.patch), [top-clearance-fix.patch](top-clearance-fix.patch) | The identical one-line correction (zero context) |
| [hybrid-economics.json](hybrid-economics.json), [top-clearance-economics.json](top-clearance-economics.json) | Price source and local token accounting |
| [fast-gate.txt](fast-gate.txt) | Fast gate result for the capture source |

The day's test logs, removed with the recordings, showed the boundary crate passing 263 unit
tests and 6 integration tests, the configuration and sandbox suites passing (25, 25 and 5
tests), and the release build and Clippy completing without errors. Two CLI test runs each
failed one top-clearance pricing test
(`frontier_alias_uses_openrouter_price_and_unknown_models_stop_before_a_request`); the
[follow-up refresh](../launch-refresh-2026-10-01/README.md) reran the top-clearance suite and
all five tests passed.

## Endpoints and limits

The frontier identifier was `glm-5.3-flash`; the local alias `omlx-coding` ran on an
owner-allowlisted **plaintext LAN endpoint**, and its underlying weights were not verified.
Synthetic sensitive content crossed that LAN connection; these runs do not establish
same-device processing or encrypted transport. Command networking was off, subagents were
disabled, and the task/session frontier dollar caps were $0.30/$0.60.

The launch media rendered from these runs' PTY output were removed before publication
because they showed session identifiers and the LAN address.
