<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Follow-up billing run, October 1, 2026

A hybrid-mode Duet (Declass's earlier name) session on the unchanged
[fictional billing fixture](../../launch/billing-demo/README.md), recorded on macOS ARM64 at local
date October 1 (America/Toronto), UTC October 2. Capture source was commit
`c9e1d5aaa427ad19b4650529f73079cbfe81c973`. This is the
[demonstration guide's](../../launch/DEMO.md#verified-billing-run) verified billing run.

The raw recordings (audit logs, transcripts, terminal casts) were removed before publication because they contained session identifiers and local paths.

## Task

> Fix the billing total bug in billing.py. Read data/customers.csv through Duet to understand the schema, but keep actual customer values and the database credential local. Use structure or synthetic examples for reasoning. Run python3 -m unittest -v. Make the smallest code fix and summarize what changed.

## Result

| Check | Result |
| --- | --- |
| Before | One failing test out of four ([output](before-tests.txt)) |
| Fix | [One-line patch](billing-fix.patch): substring check replaced by `row["status"] == "active"` |
| After | 4/4 tests pass ([output](after-tests.txt)) |
| Complete planted values | **0 of 13** planted values in **5** recorded frontier requests |
| Requests | 5 frontier requests to `glm-5.3-flash`, 1 local digest request (567 input, 231 output tokens) |
| Audit integrity | Hash chain intact and matching its external anchor, by Declass's verifier and an independent script |
| Timing and cost | Coding turn 29.9 seconds; modeled frontier cost $0.0015 ([economics](economics.json)); local cost not accounted |
| Validation | [Validation record](validation.json): canary and audit checks exited as expected, the old negative control and a tampered copy were rejected, 5/5 top-clearance tests passed, and the [fast gate](fast-gate.txt) passed |

The outbound view retained schema, row count, status vocabulary and a customer-ID pattern while
withholding amounts. **Zero complete-value matches does not mean zero information disclosure.**
The model's recorded explanation incorrectly says “reactivated”; the fixture concerns
“inactive”. The patch and tests establish the correction, not the model's explanation.

The local alias `omlx-coding` ran on an owner-allowlisted plaintext LAN endpoint; its weights
were not verified. These records are not same-device or secure production transport evidence.
The screenshots, GIFs and replays rendered from this run were removed before publication
because they showed the session identifier, the LAN address and the maintainer's username.
