# Declass in Terminal: task results and audit checks

The [October 4 billing session](../evidence/billing-demo-2026-10-04/README.md) passed **4/4 tests**, with **zero matches for 13 complete planted values in four recorded frontier requests**.

An earlier follow-up billing run passed **4/4 tests**, with **zero matches for 13 complete planted values in five recorded frontier requests**. Earlier disclosure failures are summarized below. These synthetic demonstrations are historical evidence, not a paired benchmark or a guarantee of privacy.

Screenshots, GIFs and replays from these October 1–4 runs were removed before publication because they showed session identifiers, the local model's LAN address and the maintainer's username. The README's current demo is the [October 6 recording](../evidence/recorder-billing-2026-10-06/README.md).

## Verified billing run

The follow-up billing run repaired a substring status check that incorrectly included inactive accounts. It changed the comparison to equality and passed the required task check. The customer data and database password were fictional.

| Check | Result |
| --- | --- |
| Task and acceptance command | Hybrid mode, `python3 -m unittest -v`; the objective is in the [run summary](../evidence/launch-refresh-2026-10-01/README.md#task) |
| Coding result | One-line [patch](../evidence/launch-refresh-2026-10-01/billing-fix.patch); [one failing test before](../evidence/launch-refresh-2026-10-01/before-tests.txt), [4/4 passing after](../evidence/launch-refresh-2026-10-01/after-tests.txt) |
| Planted-value check | **0 matches / 13 complete values / 5 frontier requests** |
| Record integrity | The audit's hash chain verified with Declass's verifier and an independent script, and matched its external anchor |
| Build | Source `c9e1d5aaa427ad19b4650529f73079cbfe81c973`; [validation record](../evidence/launch-refresh-2026-10-01/validation.json) |

The coding turn took 29.9 seconds, with one local digest request and five frontier requests.

The outbound view retained schema, row count, status vocabulary and a customer-ID pattern while withholding amounts. **Zero complete-value matches does not mean zero information disclosure.** The model's recorded explanation also incorrectly says “reactivated”; the fixture concerns “inactive”. The patch and tests establish the correction, not the model's explanation.

The raw recordings (audit logs, transcripts, terminal casts) were removed before publication because they contained session identifiers and local paths. To inspect a complete audit, [reproduce the task](#reproduce-the-task) or [record a new demo](#record-a-new-demo) and check your own run offline:

```sh
python3 tools/check-launch-canaries.py \
  <workspace>/.declass/audit/<run-id>.jsonl \
  docs/launch/billing-demo
```

The canary checker reads recorded request bodies and checks complete fixture values in literal, base64, hex and URL-encoded forms. It does not establish provider receipt, cover every encoding or network path, or detect all fragments and paraphrases. [Receiving-endpoint transport tests](../../crates/declass-cli/tests/privacy_scenarios.rs) provide separate evidence.

## What the first run found

| Earlier run | Code state | Coding tests | Recorded planted-value occurrences |
| --- | --- | ---: | ---: |
| Before fixes | Development snapshot `a36cee7` | 4/4 | **36 — failed** |
| Preview fix only | Diagnostic-preview fix only | 4/4 | **9 — failed** |
| Both fixes | `c9e1d5a` | 4/4 | **0 observed** |

Each earlier run made four frontier requests. Repeated appearances in conversation history count separately; these are not unique people or secrets. The later five-request run above is a distinct run.

The first failure came from a diagnostic shortcut: a reserved-domain email matched an error keyword, causing arbitrary CSV fields to enter a detector-only preview. The audit still verified: integrity did not establish safe content. A regression test reproducing it failed before the fix, reporting three planted values in the second request. Diagnostic previews and their repeated-line fallback were then restricted to explicit `.log` files; a log extension alone still does not establish safe content.

The second failure came from short monetary values repeated by the local digest. Structured-value checks were added, including decoded forms, for indexed values of at least four characters under the existing 200,000-value cap. Fragments, unrecognized formats and semantic inference remain limitations.

The [original launch summary](../evidence/launch-2026-10-01/README.md) retains the tests, patches and disclosure counts for these runs. Earlier build and test notes are in the [historical validation](https://github.com/maximpri/duet/blob/9b0ac104ba6947e338ca3baacfd31de2c2823e83/docs/launch/VALIDATION.md).

## Audit integrity and a changed copy

The successful audit had eight records and a matching external anchor. As a negative control, a copy changed only the final record's `model` field. Its internal chain still verified, but the original anchor detected the changed head; an independent script reported the same mismatch. The source audit was not modified.

An anchor bundled with its log establishes consistency, not independent custody or authorship. For new runs, use Declass's verifier (`declass audit verify <run-id>`) and retain the owner-state anchor separately; an attacker controlling both can replace both. Audits and transcripts need access controls because local requests can contain raw sensitive content. Missing disclosure counts in sessions without a summary do not establish zero disclosure.

## Top clearance and endpoint scope

The separate top-clearance run repaired the same bug and passed 4/4 tests. Its eight audit records contain five model requests, all to the configured local endpoint, and no frontier requests. It read code and tests; this run did not demonstrate reading the customer CSV. It is not a frontier-parity evaluation or an independent network trace.

[Tests](../evidence/launch-2026-10-01/top-clearance-tests.txt) · [Patch](../evidence/launch-2026-10-01/top-clearance-fix.patch) · [Local token accounting](../evidence/launch-2026-10-01/top-clearance-economics.json)

These captures used `glm-5.3-flash` as the frontier identifier and `omlx-coding` on an owner-allowlisted **plaintext LAN endpoint** as the local alias. Underlying weights were not independently verified. Synthetic sensitive content crossed that LAN connection; the recordings do not establish same-device processing or encrypted transport. An older recorded “on this machine” phrase must be read with this limitation. Use approved endpoints and secured paths for real data.

Command networking was off, subagents were disabled, and that build's task/session frontier dollar caps were $0.30/$0.60. The frontier audit does not itself capture the local model's raw request body. These historical captures do not represent every later application revision.

## Reproduce the task

Configure your own approved endpoints using [the usage guide](../USAGE.md). From the repository root, copy the unchanged [synthetic fixture](billing-demo/README.md):

```sh
demo_dir=$(mktemp -d "${TMPDIR:-/tmp}/declass-billing.XXXXXX")
cp -R docs/launch/billing-demo/. "$demo_dir/"
cp "$demo_dir/env.example" "$demo_dir/.env"
git -C "$demo_dir" init
git -C "$demo_dir" add .
git -C "$demo_dir" commit -m 'Synthetic billing fixture'
cd "$demo_dir"
python3 -m unittest -v  # expected: one failure before the repair
declass --check 'python3 -m unittest -v'
```

Paste the [supplied prompt](billing-demo/prompt.txt). After completion, inspect Privacy and Changes, note the run ID in `/audit`, and check:

```sh
declass audit show <run-id>
declass audit verify <run-id>
declass audit disclosure <run-id>
python3 -m unittest -v
```

From the Declass checkout, run the canary checker against the new workspace's `.declass/audit/<run-id>.jsonl` and the original fixture. For a separate local-agent trial, start with a fresh fixture and set `declass config set --project clearance.required top`. Ask it to repair the bug using `billing.py` and `test_billing.py`, then confirm the recorded endpoints. Outputs and timing may differ.

## Record a new demo

[`tools/declass-recorder`](../../tools/declass-recorder/README.md) runs the real `declass` binary on a fresh copy of the billing fixture, types the task, and renders the recorded terminal bytes as a GIF, MP4 and stills. Each recording saves its cast, the tests before and after, and the planted-value check over every frontier request:

```sh
python3 tools/declass-recorder/record.py --install-deps
python3 tools/declass-recorder/record.py --out /tmp/declass-demo
```

Sped-up playback is labelled in the window. Playback length is not task duration. The cast, manifest and canary report name your run IDs and local paths, and the cast shows whatever the terminal showed; review all of it, rendered media included, before publishing.
