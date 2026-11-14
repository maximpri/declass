<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

## Unreleased

### Pin and verify extensions

- `declass extensions lock` pins skills and plugins by the content of every file they hold;
  `declass extensions verify` reports any that changed, are not pinned, or are pinned but gone,
  with exit codes and SARIF output for CI. A repository can commit `.declass/extensions.lock`
  to pin its own skills (`.agents/skills`, `.claude/skills` and the like), which other coding
  agents read too. Entries use ToolHive's lock file field names and content digest.
  [Details](docs/EXTENSIONS.md#pin-and-verify-extensions)
- Every run and session checks skills and plugins against their pins before loading them
  (`extensions.integrity`): `warn` (the default) says what changed, `enforce` leaves it out.
  Your own skills and plugins are pinned the first time they load; installing a plugin pins it.
  A loaded skill is sealed to the files that were checked.
- MCP servers are pinned too: the command line, the program it resolves to, the package and
  version a launcher such as `npx` runs, install directories you name, and every tool definition.
  A launcher without an exact version is named (`enforce` does not start it). A server that
  rewrites its tools after approval is caught at the next start, or during the run: Declass
  lists its tools again after a change notice and after its 1st, 2nd, 4th, 8th... call, and
  under `enforce` withholds the server for the rest of the run. `declass extensions lock
  mcp:<server>`, `verify --live`, `diff` and `forget` manage the pins.
- Advisories about extensions, in the OSV format: shipped with Declass (the first names the
  malicious `postmark-mcp` releases), your feeds (`extensions.advisory_urls`, fetched by
  `declass extensions advisories update`, never during a run; `--online` also asks osv.dev), and a
  project's `.declass/advisories/`. A malicious or revoked extension is left out in every mode.
- Signed plugins: a publisher signs a package with `ssh-keygen -Y sign -n declass-plugin` (over
  `declass plugins digest DIR`); `declass plugins install` checks it against the keys you list in
  `extension_signers`, `--require-signed` refuses unsigned packages, and the signer is pinned:
  another signer later needs `--allow-signer-change`.

### Files another tool runs later

- A write to a file that another tool runs or loads later is now noticed: an editor's tasks
  (`.vscode/tasks.json`), a direnv `.envrc`, a dev container, another coding agent's settings,
  MCP servers, skills or instructions, git and commit hooks, CI workflows, package scripts and
  build scripts. Those that run without a further step are asked about in any approval mode
  (`oversight.autorun_triggers = "ask"`, the default; a run without a terminal refuses them);
  the rest are recorded (`oversight.build_triggers = "note"`). Writes by commands are detected
  too. A run lists them when it ends, `declass triggers` lists them for every run, and the
  Changes panel marks them.
- New audit events: `file_write` (path and digests), `command_run` (digest, program, access,
  network, exit code, duration) and `trigger_written`. `declass audit events` exports a run's
  security events as JSON lines, with paths and commands hashed unless `--include-paths`, and
  `detections/sigma/` holds Sigma rules over them (they pass `sigma check`).

### Sandbox containment tests

- A probe (`declass-probe`, test-only) tries to get out of the sandbox: reading denied files, run
  state and Declass's sign-ins, writing outside the workspace and into `.git` and `.declass`,
  reaching the network, a local socket and the clipboard. It runs with no sandbox first (what
  works on this machine), then sandboxed with network off and on, on macOS and in the Linux
  matrix. A second test checks, side by side, what each kind of process may read: commands of
  every kind, MCP servers and language servers.

### Security

- **MCP and language servers can no longer read your credentials** (DECLASS-2026-040). Stdio MCP
  servers, language servers and the security review's reference lookup were not denied the
  credential stores in the home directory (`~/.ssh`, cloud, registry and git tokens, coding
  agents' logins, shell histories) or Declass's own sign-ins, as commands are. The sandbox now
  denies them to every process it starts, whatever the caller lists.
- **This can break a server that relied on one of them**, such as a cluster tool reading `~/.kube`,
  a GitHub server reading `~/.config/gh`, or `npx` with a private registry token in `~/.npmrc`. Let
  that server read what it needs in the owner config:
  `declass config set mcp.servers.<name>.read_home_secrets '[".kube"]' --confirm`. Entries must be
  on the sandbox's list ([SECURITY.md](SECURITY.md)); `declass doctor` warns about each exception.
  A native package cannot grant one.

### Apple-signed macOS releases

- `tools/release.sh --apple-identity` signs the macOS binary with a Developer ID Application
  certificate (hardened runtime, secure timestamp) before the checksums and SSH signature, and
  records the signer in `BUILDINFO.txt`. Other certificates are refused.
- `tools/package-dmg.sh --apple-identity --notary-profile` signs the disk image, notarizes it,
  staples the ticket and checks it with Gatekeeper before its checksum is made. It refuses a
  payload whose binary is not signed by the same identity.
- The disk-image installer reports the installed binary's Apple signature.
  [Details](docs/INSTALLATION.md#optional-apple-signing-and-notarization)

## 0.2.0 — 2026-10-06

The first release from this repository, and the first signed one. Release assets are signed with
the [Declass release key](docs/declass-release.pub); see [signed releases](docs/INSTALLATION.md#signed-releases).

### The local model checks what goes out

In hybrid mode the local model now judges, not only reads. Each check is on by default; a project
may turn one on but never off, and turning one off in your own config needs `--confirm`.
[Details](docs/USAGE.md#local-model-checks)

- **Disclosure judge** (`sensitivity.local_judge`): withholds paraphrased record details from local
  summaries, answers, briefs and explorer reports.
- **Question intent** (`sensitivity.question_intent`): a question aimed at one record or value, in
  any language, is answered as a question about format and structure.
- **Injection screen** (`sensitivity.injection_screen`): public files, web pages, MCP results and
  command output that address an AI agent are judged locally. A confirmed injection is marked as
  data and marks the run; `oversight.on_injection = "approve"` (the default) then asks before risky
  actions, web tools and MCP calls.
- **Outbound meaning** (`sensitivity.egress_meaning`): web and network MCP requests that carry facts
  the local model reported are refused; so is a request it could not check.
- **Content classification** (`sensitivity.classify_content`): public data files that hold real
  records are held as sensitive.
- **Operator text** (`sensitivity.operator_pii`): names and addresses in your task and messages
  become placeholders.
- **Local diff review** (`review.local_diff`): advisory findings at finish; a protected rewrite with
  exfiltration or a backdoor is refused.
- **Disclosure narrative** (`sensitivity.local_narrative`): an account, for you only, of what the
  frontier could have learned: `declass audit disclosure <run> --narrative`.
- Always on: local prompts are framed with tags a file cannot forge, local output reaches the
  frontier framed as data, and cited evidence lines are checked against the answer.
- `declass local-eval --suite judge,intent,injection,classify,review` measures your local model in
  these roles.

### ChatGPT plans

- `declass login chatgpt` signs in with a ChatGPT Plus or Pro plan in the browser, and
  `declass config preset chatgpt --confirm` sends the cloud model's requests through it.
  [Details](docs/USAGE.md#chatgpt-plan)

### Request limits replace cost tracking

- Dollar budgets, pricing settings and cost reports are removed. Sessions and runs are limited by
  frontier requests (`limits.frontier_requests`) and time. Retired `pricing.*` and `*_usd` settings
  still load, with a note.

### Setup

- **No default models.** The cloud and local endpoints and models start empty; nothing is sent
  until you choose them. Earlier versions defaulted to Z.ai GLM and a local `omlx-coding`.
- **Setup screen.** The first `declass` in a terminal (and `declass setup`) opens a full-screen
  setup: pick a cloud provider (API keys found in your environment are marked; ChatGPT plans sign in
  in the browser) and a local model (servers on this machine, or one at an address you allow),
  review who receives what, and save. API keys can be given as `$VARIABLE` or pasted; a pasted key
  is kept owner-only in Declass's credentials, never in the configuration.

### Upgrading

- If you relied on the old defaults, run `declass setup` (or set `frontier.base_url`,
  `frontier.model`, `frontier.api_key_env`, `local.base_url` and `local.model`).
- The local checks add local model time: about 5 seconds per question or outbound request and 8
  per judged output on a 27B model. Turn individual checks off with
  `declass config set <setting> false --confirm` if your model is slow.
- Rename `limits.*_usd` settings to request limits; the old keys are ignored.

## 0.1.0

The first public preview, published unsigned as Duet from the pre-rename repository
[maximpri/duet](https://github.com/maximpri/duet).
