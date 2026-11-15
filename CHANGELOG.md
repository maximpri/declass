<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

## 0.4.0 — not yet released

Use Declass from an editor, run `declass exposure` in CI, and close fourteen leak and isolation
classes that an adversarial review of the privacy boundary, the sandbox and the tool channels
found. A first run without models now says what to do.

### Use Declass from an editor (experimental)

- `declass acp` makes Declass the agent of an editor that hosts agents over the Agent Client
  Protocol (Zed, JetBrains IDEs, and Neovim and Emacs through their ACP plugins). Each thread is a
  session in its directory, with the same privacy boundary, sandbox, approvals, limits and audit
  as `declass`; threads keep their sessions, and `declass --resume <id>` continues one in a
  terminal once the editor has let go of the workspace.
- A file you @-mention becomes its path, never its content, so a `.env` is still read only by the
  local model. A web page the editor fetched (`http`, `https`) is checked like a fetched page,
  given to the cloud model as data and recorded as an `editor_attachment` audit event; anything
  else the editor attaches (rules, unsaved buffers, remote files) is declined, and you are told.
- Replies stream with placeholders restored and tool calls show their results and diffs, but a
  file Declass keeps from the cloud model is only named, however the path is spelled, and the
  editor is not told where it is. Security notices from the session (files it could not index,
  files a command made another tool run) appear in the thread, and approvals use the editor's
  permission dialog. MCP servers the editor offers are not started, and Declass never uses the
  editor's own file and terminal methods. Run `declass setup` in a terminal first.
  [Details](docs/USAGE.md#use-declass-from-an-editor)

### Exposure in CI

- `declass exposure --sarif` writes the report as SARIF 2.1.0 for GitHub code scanning and other
  SARIF tools: one result per file and kind of value, at the first value's line and column, with
  stable rule ids (`exposure/secret`, `exposure/email`, ...) and help that says what Declass does
  with such a file. No value, line of content or hash of either is in it. `--output FILE` writes
  JSON or SARIF to a file and prints the text report. The JSON report is schema 2.
- Findings have levels: a secret in a file the cloud model reads is an error, other values there
  warnings, values in files that path rules keep local notes. `--fail-on note|warning|error|never`
  sets what exits 1; to accept known findings such as test fixtures, keep those files local with
  `[sensitivity] protected_paths`. Exit 2 still means the report is incomplete.
- `--history` also reads earlier versions of files in git and reports, by path, the values only
  history holds, such as a key committed and removed since, within blob and byte limits. It runs
  no git command that reads the working tree, so no filter a repository configures runs, and a
  partial clone's missing objects are counted, never fetched.
- Large repositories: the report covers up to 1,000,000 entries (was 20,000), reads files on every
  core while the walk streams, and keeps only files with findings in memory. The detectors'
  screening set no longer falls back to a slow engine on data files and non-ASCII text; a sample
  of JSON and bundles that took 19.6 s of CPU takes 2.2 s, in runs as in the report.
- The repository is a GitHub Action: `uses: maximpri/declass@v0.4.0` installs a release after
  checking its signature against the key in the action's own commit, writes SARIF for
  `github/codeql-action/upload-sarif`, and on a pull request uses the base commit's
  `.declass/config.toml`, so a pull request cannot loosen its own gate.
  [Example workflow](examples/github/declass-exposure.yml)
  [Details](docs/OPERATIONS.md#see-what-an-agent-could-send)

### Security

An adversarial review of the sandbox and tool channels and of the boundary found these classes.
Each was demonstrated by a test that fails without its fix; [SECURITY.md](SECURITY.md) has the
details.

- **A command could move a file it may not read, and read it under another name**
  (DECLASS-2026-041, macOS). Seatbelt names paths, so `mv .env x` or moving a folder above a
  denied file, or the workspace itself, put it out of reach of every rule. Denied paths, the
  folders above them, the workspace and its scratch directory can no longer be renamed, removed
  or have their permissions changed by a sandboxed process; a folder Declass cannot list is
  denied whole, and every sensitive file is denied by name.
- **The file tools opened other spellings of a path** (DECLASS-2026-042, macOS). `.DECLASS/...`,
  `DATA/orders.csv` under a `data/**` rule or `.GIT/config` reached run state, sensitive data or
  git's configuration past the checks. Every path is resolved to its spelling on disk before any
  check, and rules compare names in Unicode NFC, so a file whose name macOS stores decomposed is
  protected however it is spelled.
- **Git history kept outside the workspace was readable by commands** (DECLASS-2026-043): in a
  linked worktree (`git worktree add`), in a subdirectory of a repository, or through borrowed
  object stores. It is hidden wherever git keeps it.
- **Processes outlived their command** (DECLASS-2026-044, macOS): `( cmd & )` escaped the
  end-of-command sweep. A command's whole process group now ends with it. A process that starts a
  session of its own can still survive (SECURITY.md, Known limits).
- **The egress proxy forwarded stray line breaks** (DECLASS-2026-045) inside request heads, which
  some servers read as another `Host` or another request. Such heads are refused.
- **A secret written into a config file stayed readable by commands** (DECLASS-2026-046). A
  placeholder written into a secret sink outside the sensitivity globs (`config/*.toml`) was
  restored into a file any command could print reversed or spaced out. Such a file is sensitive
  from the write on, and the write's result says so.
- **Multi-line `.env` values were read line by line** (DECLASS-2026-047), so parts of a private
  key or a JSON value were shown. Both views of `.env` files read values as dotenv does: a quoted
  value is withheld whole, whatever follows a line's first `=` is withheld whatever its key, and a
  placeholder written back restores the value with its quotes, comments and line ends.
- **Record keys were shown as schema** (DECLASS-2026-048): a JSON export keyed by user names
  showed them in structure views, outlines and samples. Keys are judged by where they stand;
  record names are `*`, while fields, environments, locales and package names stay visible.
- **Values in other Unicode forms passed every filter** (DECLASS-2026-049): a zero-width
  character inside a value, full-width or another script's digits, or a name composed where the
  data has it decomposed. Local output, the final check and the third-party check read text folded
  (NFKC, invisible characters removed), and a value folding reveals is replaced where it stands.
- **The audit log held values from command text and file names** (DECLASS-2026-050). Commands
  and paths in audit events show known values as placeholders and the rest as written.
- **`search` answered guesses about sensitive files** (DECLASS-2026-051): which of their lines a
  pattern matched, one guess per search. Sensitive files and protected source are not searched.
- **A headerless CSV's first record was shown as its column names** (DECLASS-2026-052).
- **Edit anchors answered guesses** (DECLASS-2026-053): an `edit_file` anchor in a sensitive file
  was matched against the real text, so a successful edit confirmed a guess. Anchors in a
  sensitive `.env`-style file match only what `read_file` showed; other sensitive files and
  protected source refuse anchor edits.
- **A write's result gave a restored secret's length** (DECLASS-2026-054). It reports the size of
  the text the cloud model wrote.

### First run and setup

- A run or session without a cloud model stops before anything starts, with one message: run
  `declass setup` (or use `--mode local-only`). A key variable that is not set is named, and a
  ChatGPT plan that is not signed in says `declass login chatgpt`. Before, `declass run` looked for
  a local server, recorded a failed run and printed its summary, or gave only local-server advice.
  In a terminal session the message is shown and the session stays open. `declass setup` without
  a terminal that finds nothing to set up says so and exits 1.
- `declass privacy` before setup says a model is "not set up" (exit 1), not "invalid origin ·
  refused" (exit 2).
- The setup screen keeps the selected row and the choices on screen in narrow terminals, scrolls
  a long review and saves only when all of it fits on screen, and returns to the chosen row on
  Esc; under `declass setup` it no longer says Enter starts Declass. Choosing a cloud model on the
  setup screen when your own configuration requires local-only work (as an earlier setup without
  a cloud model saves) offers to lift that requirement, never a project's or a policy's; it takes
  `y`.

### Fixes

- `declass doctor --help` and the Models screen said `--online` makes no model calls. It sends
  each model two short built-in prompts and two generated images, which a paid plan bills. Both
  now say so.
- In top clearance the work status names the local model, not "the frontier". A reply that the
  model also wrote as text is shown once.
- The workspace's Changes view showed the content of a sensitive file that the cloud model named
  under another spelling (`./data/...`, or `.ENV` on macOS). It is named only, as are files
  derived from sensitive data and protected source.
- `declass config set` shows how to quote a text value (`'"gpt-6"'`). Stale and missing help is
  filled in (session limits are requests and time, not dollars). Report paths show quotes as
  written. `declass exposure` in an empty directory says there was nothing to read.
  `declass history` says "1 turn".

### Upgrading

- On macOS, commands can no longer rename, remove or change the permissions of a file Declass
  denies them, a folder that holds one, the workspace or its scratch directory: `rm -rf data`,
  `mv config settings` and rotating denied logs fail part-way. Use the file tools, or run them
  yourself outside Declass. [Details](docs/USAGE.md#command-networking-and-troubleshooting)
- A server a command starts in the background (`npm run dev &`) stops when that command ends.
- A config file a secret is written into is sensitive from then on: commands that read it need
  `sensitive_data`, and `git_commit` refuses it.
- `search` no longer looks into sensitive files or protected source, and sensitive files other
  than `.env`-style ones are no longer edited by anchor; write them whole with `write_file`.
- `declass privacy` exits 1, not 2, when no model is set up. `declass exposure --json` is schema 2.

## 0.3.0 — 2026-11-14

Try Declass on a repository before setting anything up, pin the extensions it loads, and keep
credentials from every process it starts. Release tooling can now sign and notarize macOS builds
with an Apple Developer ID; the 0.3.0 disk images are not notarized yet.

### See what an agent could send

- `declass exposure` reads the repository on your machine with Declass's own detectors and
  reports, file by file, how many secrets and personal-data values a coding agent could send to a
  cloud model, and what Declass does with each file instead. It needs no model, API key or setup,
  makes no network requests and creates no run state. It shows counts, never values.
  `--json` and `--all` are available; exit 1 means findings were listed.
  [Details](docs/OPERATIONS.md#see-what-an-agent-could-send)

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

### Fixes

- With git 2.54 (Apple Git-157), a `git` command run through `run_command` failed with
  `fatal: error reading '.../.git'` and no pointer to the git tools, because that git no longer
  says "Operation not permitted" when the sandbox refuses `.git`. Declass now recognises it and
  points at `git_status`, `git_log` and the other git tools again.
- Tokio 1.53.3 (RUSTSEC-2026-0386, `AsyncFd`'s safe constructors). The Linux sandbox's network
  bridge now waits on its channel as a Tokio Unix socket instead of through `AsyncFd`.

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
