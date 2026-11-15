# Operating Declass with retained audit evidence

Declass keeps run data, audit logs and integrity anchors on the operator's machine.
These commands support local retention review, content-free audit exports and
health checks for an existing monitoring system. They do not contact a model or
send telemetry.

## Preview privacy before starting

From the project directory, run:

```sh
declass privacy
declass privacy --json
declass privacy --mode top-clearance
```

The same preview appears before a new terminal session starts. `/privacy` shows
its file-by-file rules, including the endpoints selected for that session.
A resumed session uses its saved endpoint choices.

The preview runs offline. It inspects file names and metadata, effective
configuration, installed plugin manifests and saved path classifications. It
never opens workspace file contents, calls a model or starts a tool server.
No run, audit or vault is created.

| Report field | Meaning |
| --- | --- |
| Local and frontier destinations | Origin, enabled status and endpoint trust decision, or `not set up` before a model is chosen; credentials and API paths are omitted |
| Command network | Off, approved registry hosts or unrestricted, after applying the selected mode |
| Web and MCP | Search origins, web-fetch host policy and remote tool-server origins; networked MCP is disabled in top clearance |
| Exceptions | Settings that loosen the defaults, with their configuration origin; values are omitted |
| File rules | Matching path rule or persistent classification for each inventoried file |

Files can be sealed, limited to interfaces, classified as sensitive, or subject
to runtime content checks. A file with no matching path rule is not a promise
that it contains no secrets. Declass checks content when using it. Top clearance
routes model work to the approved local endpoint; passthrough disables the
privacy boundary.

The inventory includes ignored files such as `.env`. Environment templates such
as `.env.example` are excluded from generic sensitive globs, but an explicit
protected-path rule still applies. Symlinks and special files are reported as
blocked and never followed. Files previously produced from sensitive data keep
their classification across runs and raw-history purges.

The report lists excluded state, build and dependency directories. It examines
at most 20,000 entries and 48 directory levels. An unreadable directory, a
non-UTF8 name, an entry that cannot be inspected or a limit makes the
inventory incomplete. Unavailable or unfinished derived-file classifications
are reported as unknown; they are never silently treated as public.

Exit 0 means the preview completed without reported exceptions or warnings.
Exit 1 means it completed with items to review, such as a model not set up yet
(`declass setup` chooses one). Exit 2 means the inventory is incomplete or an
enabled model endpoint is refused. A preview describes the observed
configuration and paths; runtime enforcement still checks each action.

Review endpoints with `declass doctor`. See the [security model](../SECURITY.md)
and [deployment evaluation](SECURE_BY_DESIGN.md#evaluate-your-deployment) for
endpoint trust and permitted disclosure. Retention and audit commands follow.

## See what an agent could send

```sh
declass exposure
declass exposure --all              # list every file with findings, not the first 25
declass exposure --json
declass exposure --sarif --output exposure.sarif   # SARIF for code scanning
declass exposure --fail-on error    # exit 1 only for a secret the cloud model would read
declass exposure --history          # also earlier file versions in git history
```

`declass exposure` reads the workspace on this machine, the files the privacy
preview lists, and runs Declass's pattern detectors for secrets and personal
data (and your `sensitivity.custom_patterns`) over them. For each file with
findings it reports how many values of each kind it found, where the first
ones are, and what Declass does with the file in hybrid mode under the current
path rules: read only by the local model, placeholders before any request,
interface only or sealed. Files that path rules cover but where nothing was
detected are counted. Detectors turned off in your configuration are not run,
and the report names them.

It does not run Declass's local-model checks or compare against values a run
has already seen, so names and paraphrased details are mostly not counted.
Overlapping matches count as one value, so counts are a lower bound.

It needs no model, API key or setup. It makes no network requests, starts no
tool server and creates no run, audit or vault. The report holds paths, counts
and positions (line and column); matched values, lines of content and hashes of
either are never displayed or written. Files over 2 MiB, binary files
(including UTF-16 text), symlinks and special files are counted as not read,
and the excluded directories (`.git`, `node_modules`, `target` and the like)
are named.

Detectors recognize known formats. A file with no findings can still hold
private information, and a count is not a measure of sensitivity.

Large repositories are read on every core while one thread lists them, and
memory holds the files with findings, not the whole tree. The report covers at
most 1,000,000 entries and 48 directory levels; reaching either, an unreadable
directory or a non-UTF8 name makes it incomplete.

### Levels and exit codes

Each finding has a level, from what Declass does with its file:

| Level | Finding |
| --- | --- |
| error | A secret in a file the cloud model reads (Declass replaces it with a placeholder) |
| warning | Personal data or a custom-pattern match in a file the cloud model reads |
| note | Any value in a file that path rules keep from the cloud model: `sensitivity.globs`, `sensitivity.protected_paths` or `ip.sealed` |

Files under `ip.interface_only` count as read: their signatures and public
constants are shown. `--fail-on` sets the level from which findings fail:
`note` (the default, any finding), `warning`, `error` or `never`.

| Exit | Meaning |
| --- | --- |
| 0 | The report is complete and nothing is at or above the `--fail-on` level |
| 1 | A finding is at or above it; or the command failed with an error message, and no report was written |
| 2 | The report is incomplete, whatever was found; a mistyped or unknown option also exits 2 |

To accept known findings, such as fake keys in test fixtures, keep those files
local: add them to `[sensitivity] protected_paths` in `.declass/config.toml`.
Their findings become notes, so `--fail-on warning` or `error` no longer fails
on them. The report still lists them, and in a run only your local model reads
them. There is no separate allowlist.

The same file can waive the gate: a pull request that adds `protected_paths =
["**"]` turns every finding into a note. When `--fail-on` gates CI, protect
`.declass/` with code owners or branch rules, or run the report with the base
branch's `.declass/`.

`--json` prints schema 2, which adds each finding's `level` and `positions`,
`fail_on`, `failing`, `limits` and, with `--history`, `history` to schema 1.

### SARIF for code scanning

`--sarif` prints the report as SARIF 2.1.0; with `--output FILE` it goes to the
file and the text report to standard output. There is one result per file and
kind of value, at the first value of that kind, with the count, the lines of
the first ten and what Declass does with the file. The level is the finding's
level above. The tool is `declass` with its version, and the run's category is
`declass-exposure`, so it never replaces `declass extensions verify` results.
A run holds at most 25,000 results, the most code scanning accepts: past that,
errors are kept first, then warnings, then notes, and the log says how many
were left out.

Rule ids are stable: `exposure/secret`, `exposure/email`, `exposure/phone`,
`exposure/card`, `exposure/national-id`, `exposure/iban`, `exposure/ip-address`,
`exposure/account-number`, `exposure/postal-address` and
`exposure/custom-pattern` (`exposure/name` and `exposure/protected-code` are
defined but this report does not produce them). Each rule's help says what the
kind is, what Declass does with such a file and how to accept a finding.

A result never holds a value, a line of content, an end column (which would
give a value's length) or a hash of any of them. Its partial fingerprint,
`declassExposure/v1`, is a SHA-256 of its path and rule only, so it keeps its
identity while lines move. GitHub's `upload-sarif` action adds a fingerprint
of its own to each result with a line: a hash it computes on the runner from
that line of the file in your checkout, which is how code scanning tracks
alerts across commits.

### Git history

`--history` also reads earlier file versions: every blob in the history of
the repository's refs that is not in the working tree, each once, under every
path it ever had in the workspace. It reports the values they hold that the
working tree does not, such as a key committed and removed since, by path, with
how many earlier versions hold them and whether the file was deleted. A blob or
value found at several paths counts at the one Declass would show most: a path
the cloud model reads before one a path rule keeps local. Values are compared in
memory by keyed hashes, never written; the report holds no commit or blob id.

Git runs through Declass's hardened runner, as for the git tools, and only
reads objects, refs and configuration (`rev-parse`, `rev-list`, `diff-tree`,
`cat-file`). It never reads a file of the working tree: git would then run any
clean filter the repository configures, even for a file that only looks
unchanged. Declass computes the working tree's blob ids itself, while it reads
the files, so their blobs are not read again.

It reads at most 100,000 blobs and 1,024 MiB (`--history-max-blobs`,
`--history-max-mib`); blobs over 2 MiB and binary blobs are not read. Reaching a
limit, or a name in history that is not UTF-8, makes the report incomplete. A
shallow clone holds only the history it fetched.

Declass's git tools classify each path's history by its rules now: a path that
is sensitive now is held locally in every revision, a sealed or interface-only
path's earlier versions are withheld, and any other path's are scanned like
public content, detected values replaced by placeholders. The levels follow:
history findings for sealed and interface-only paths are notes too. The history
lines of the report say what applies to each path. Commands cannot read `.git`.
Objects a partial clone lacks are counted as not read, never fetched. In SARIF,
a history result points at line 1 of the path, since an earlier version's lines
do not apply to the file now.

## Storage and retention

| Data | Location | Control |
|---|---|---|
| Raw requests, transcripts, handles, vault and write journal | Workspace `.declass/runs/<run>` | `data.retention_days`, default 14; explicitly remove with `declass purge` |
| Audit requests and security events | Workspace `.declass/audit/<run>.jsonl` | `data.audit_retention_days`, default 90; review with `declass audit retention` |
| Audit integrity anchors | Owner state directory `audit-anchors/` | Preserve separately from the workspace |
| Persistent derived-file classifications | Workspace `.declass/derived.json` and `.declass/derived.pending` | Preserved by purge; classification must remain while derived files exist |

Audit logs are sensitive storage. Hybrid requests contain what passed the
boundary; top-clearance requests can contain raw private material. Event fields
can include commands, paths and configuration values. `audit show --raw` is a
local investigation command, not a safe telemetry export.

Set the retention periods explicitly:

```sh
declass config set data.retention_days 30 --confirm
declass config set data.audit_retention_days 365 --confirm
declass audit retention
declass purge --dry-run
declass purge
```

The retention report uses both configured periods. It emits JSON and exits 1
when run data or audit logs are due for review, or a directory cannot be
inspected. It never removes data. Audit expiry is an **archive/review threshold**:
there is no automatic audit deletion. Decide where to preserve the full logs
and anchors under your organization's retention and access rules. A metadata
export cannot replace the original evidence or verify its chain.

Raw-run expiry uses the latest modification anywhere inside the run, including
nested transcript files. An old directory timestamp alone does not make an
active transcript eligible. Purge refuses an active workspace lock and refuses
symlinked run directories. Close the session before purging. `declass purge RUN_ID`
and `declass purge --all` intentionally remove selected raw data regardless of age;
add `--dry-run` to preview either. A project may shorten the raw retention
period, but only the owner controls audit retention.

Purge retains audit logs, owner anchors and persistent derived-file
classifications. It never turns deletion of raw history into declassification of
private output files. Review access to backups and filesystem snapshots
separately; removing a file is not a secure erase of those copies.

The owner state directory is `$DECLASS_CONFIG_HOME/state` when configured,
otherwise `$XDG_STATE_HOME/declass` or `~/.local/state/declass`. Keep its permissions and
backups separate from the workspace's. The anchors are local tamper evidence;
they do not protect against an operator or administrator who can rewrite both
the log and the owner state.

## Export metadata without request content

```sh
umask 077
declass audit export RUN_ID > audit-metadata.json
```

Export first verifies the exact snapshot against its hash chain and owner
anchor. It returns 0 only for an intact, fully anchored snapshot. A failed
verification returns 1 with an empty record list and a fixed status label.
Unknown or malformed records fail closed rather than being silently skipped.

Schema version 1 contains:

- `schema_version` and the fixed `kind` label `declass_audit_metadata`.
- `run`: a SHA-256 reference to the run ID, integrity status, record and byte
  counts, unanchored count and first/last timestamps.
- `records`: sequence number, timestamp, fixed request/event kind and admitted
  numeric or Boolean metrics. Request metrics are serialized body size and
  intervention count. Event metrics include counts, sizes, elapsed time,
  exit code and approval/review flags when present.

No stored string field is copied from a request or event. The allowlist omits
prompts, bodies, tool arguments, commands, raw URLs, hostnames, model names,
paths, configuration values, free-text reasons, user-supplied labels and content
digests. Event kinds come from Declass's fixed enum; metrics accept only named
numeric/Boolean fields. New event fields are not automatically exported.

Timestamps, activity counts and stable run references can still be
operationally sensitive. The output minimizes content disclosure; it is not an
anonymity guarantee. The run reference is `SHA256(UTF-8 run ID)` and can be
correlated with the local history when investigating an alert.

## Check integrity for an external alert

```sh
declass audit check
declass audit check RUN_ID
```

The workspace-wide command reads audit logs, raw-run directory names and the
owner anchor inventory. It can therefore report a missing audit file even when
its raw run directory has already been purged. The report uses fixed status
labels and hashed run references; it does not print raw errors, paths or event
content.

| Exit | Meaning |
|---|---|
| 0 | Every discovered or explicitly requested log is intact and fully anchored |
| 1 | Missing log/anchor, broken chain, rewritten or truncated history, unanchored tail, incomplete record, changing file, unsafe path, unreadable state or size/inventory limit |
| Other nonzero | Command invocation or operational failure; treat as an alert too |

An unanchored tail is reported even when its existing prefix matches the
anchor. It can result from an interrupted append. Reports do not repair logs,
re-anchor them, truncate partial records or overwrite evidence. Inspect locally
with `declass audit verify RUN_ID` and preserve the original files before recovery.
Concurrent writes can produce a transient `changed_during_check` or unanchored
status; repeat after the run has settled before treating it as tampering.

A snapshot is limited to 64 MiB; each anchor to 64 KiB; an inventory to 100,000
entries. Exceeding a limit produces nonzero status, not a healthy partial
report. Invalid owner anchor entries make the inventory incomplete and require
attention. Symlinks and nonregular audit files are refused.

An empty workspace with no known anchors has no runs to check. If your monitor
expects a particular run, pin its ID with `audit check RUN_ID`; it fails even
when both its log and anchor are absent. After moving a workspace, existing logs
still match portable anchors. An already-missing log cannot always be assigned
to the new workspace from its old recorded path; use the expected run ID in
that case. A monitor needs its own retained inventory to detect deletion of
both the evidence and its local baseline.

For a scheduler, save JSON privately and preserve the command's exit status:

```sh
#!/bin/sh
set -eu
umask 077
directory="$HOME/.local/state/declass-monitor"
mkdir -p "$directory"
temporary="$(mktemp "$directory/audit-health.XXXXXXXX")"
trap 'rm -f "$temporary"' EXIT HUP INT TERM
status=0
/absolute/path/to/declass audit check --workspace /path/to/workspace > "$temporary" || status=$?
mv "$temporary" "$directory/audit-health.json"
exit "$status"
```

Run this script from your scheduler and connect nonzero exit status to the
alerting system you already operate. Schedule `audit retention` separately to
track expiry review. Declass does not install a scheduler, transmit these reports,
manage organizational identities or replace a centralized evidence store.

After a hard kill or failed classification write, `.declass/derived.pending` makes
hybrid startup and preview refuse to continue. Review every potentially written
file locally, classify affected paths in the sensitivity policy or move/remove
the outputs, and preserve existing `.declass/derived.json` entries. Only after that
owner review should you remove the pending marker. Deleting the classification
manifest to unblock a run can declassify sensitive output.
