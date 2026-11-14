# Instructions, skills and plugins

Reuse repository conventions, add a repeatable workflow, or connect a tool server.
All three use Declass's existing privacy, permission and request-limit controls.

| Need | Use | When it is loaded |
|---|---|---|
| Build commands, layout and coding conventions | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `DECLASS.md` | At session start, with relevant directory rules on file access |
| A workflow such as code review | A directory containing `SKILL.md` | Short description first; instructions and resources when needed |
| Distribute skills, prompt commands and optional MCP servers | A native `declass-plugin.toml` package | After the owner installs and enables it |

These features are part of the development build. The compatibility and limits
below describe Declass's implementation, rather than every feature of another agent.

## Try the review example

From this checkout, after [installing Declass](INSTALLATION.md):

```sh
declass plugins inspect examples/plugins/quality-kit
declass plugins install examples/plugins/quality-kit
declass skills list
declass skills show quality-kit:code-review
declass
```

In the new workspace session, enter either:

```text
/skill quality-kit:code-review Review the uncommitted changes
/command quality-kit:review Review the uncommitted changes
```

The [example package](../examples/plugins/quality-kit/declass-plugin.toml) contains
one review skill and one prompt command. It has no scripts, credentials or MCP
servers. Reading or installing it makes no model request; using the workflow in a
session uses that session's configured models and limits.

## Repository instructions

Existing `AGENTS.md` files can describe build commands, tests and conventions;
this follows the purpose of the [AGENTS.md format](https://agents.md/).
Declass also reads `CLAUDE.md`, `GEMINI.md` and its own `DECLASS.md` as plain instruction
text. It does not interpret those products' settings formats.

At the repository root the order is:

1. `AGENTS.override.md`, when present; otherwise `AGENTS.md`.
2. `CLAUDE.md`.
3. `GEMINI.md`.
4. `.github/copilot-instructions.md`.
5. `DECLASS.md`.

Later files provide the more specific conventions within that directory. An
override replaces only `AGENTS.md`. An unreadable or withheld override does not
silently fall back to the replaced file. Within Declass's host rules, the precedence
is **the current user request, then owner instructions, then repository guidance**.
More specific repository directories take precedence over their ancestors, with
`DECLASS.md` last within a directory. File text cannot change Declass's security rules.

Your standing instructions live next to your owner configuration, normally
`~/.config/declass/`: `AGENTS.md` or its override, `CLAUDE.md`, `GEMINI.md`, then
`DECLASS.md`. These are loaded before the repository files. `DECLASS_CONFIG_HOME`
changes that directory; Declass does not search unrelated home directories for
standing instruction files.

### Directory scope and resume

Place a supported instruction file inside a directory to apply it to that
directory and its descendants. For `src/parser/token.rs`, Declass checks `src/` then
`src/parser/` when its `read_file`, `edit_file`, `write_file`, `edit_protected` or
`rename` tool names that file. Deeper rules take precedence. Copilot instructions
are root-only.

When a file operation reveals new rules, Declass returns the rules first and asks the
model to repeat the operation after reading them. Unchanged directory rules are
not repeatedly inserted; edits to those files refresh the relevant scope.
Declass instructs the model to read a file before changing it through a shell
command, so applicable guidance can be discovered. Shell paths and the other
files affected by a language-server rename are not automatically enumerated by
this guard. Keep indispensable project-wide guidance at the root.

Root instructions enter the opening message once and are replayed on resume.
Start a new session to pick up changed root instructions. Descendant rules are
checked again after resume or context is discarded. File references such as
`@other-file.md` remain ordinary text; they are not expanded automatically.

Each instruction file contributes at most 16 KiB. Combined root instructions are
capped at 64 KiB, and each scoped block at 32 KiB; omitted text is marked. Files
over 2 MiB, symlinks and nonregular files are refused. Project instructions pass
through repository path visibility and content filtering; owner instructions are
sanitized like operator messages. In hybrid mode, a sensitive value in an
instruction file does not gain permission to cross the outbound gate.

## Portable skills

A skill uses the standard directory layout and YAML-frontmatter-plus-Markdown
`SKILL.md` format. Resources can live beside it and load when needed. See the
[Agent Skills specification](https://agentskills.io/specification).

For example, create `.agents/skills/code-review/SKILL.md`:

```markdown
---
name: code-review
description: Review a diff for concrete regressions and verify findings with focused checks.
---

Review the requested changes and their callers. Report reproducible defects
with file and line references, then the checks performed and any coverage gaps.
```

The name must match the directory: 1–64 lowercase ASCII letters, digits or single
hyphens, without a leading or trailing hyphen. A description is required and can
contain up to 1,024 characters. Use plain or quoted strings; descriptions can also
use YAML `|` or `>` blocks. Declass parses these fields, not arbitrary YAML objects,
tags or aliases. Extra metadata is retained as content and grants no capabilities.

### Automatic discovery

Declass checks these roots in order. Each contains `<name>/SKILL.md` directories;
the first matching skill ID wins, and duplicates appear as diagnostics.

| Order | Root | Origin |
|---|---|---|
| 1 | `~/.config/declass/skills/`, or the skills directory beside the owner config | Owner |
| 2 | `~/.agents/skills/` | Owner |
| 3 | `~/.claude/skills/` | Owner |
| 4 | `~/.config/opencode/skills/` | Owner |
| 5 | `.declass/skills/` in the workspace | Project |
| 6 | `.agents/skills/` in the workspace | Project |
| 7 | `.claude/skills/` in the workspace | Project |
| 8 | `.opencode/skills/` in the workspace | Project |
| 9 | Skill roots declared by enabled installed plugins | Plugin |

When `DECLASS_CONFIG_HOME` is set, root 1 becomes `$DECLASS_CONFIG_HOME/skills/` and
the other owner-home roots (2–4) are skipped. Project roots still apply. Native
plugin skills have qualified IDs such as `quality-kit:code-review`, so they do
not shadow an unqualified `code-review`.

Use `declass skills list` or `/skills` to see what was found. Read a skill locally
with `declass skills show code-review`, or a bundled resource with
`declass skills show code-review references/checklist.md`. These terminal inspection
commands read local content for the operator; they are not previews of the
filtered content that a frontier model will receive.

### Activation and privacy

The model receives a bounded catalog of names and short descriptions. It can
request another catalog page with `list_skills`, then load instructions with
`load_skill`. Full instructions and referenced resources are kept out of the
initial catalog and tool schemas. Use `/skill code-review <task>` to select a
skill explicitly. Reopen the session after adding or changing skills so its
catalog is refreshed.

| Optional frontmatter | Declass behavior |
|---|---|
| `disable-model-invocation: true` | Hidden from model discovery and unavailable to `load_skill` until the operator invokes it with `/skill` |
| `user-invocable: false` | Rejects explicit `/skill` invocation; automatic model use remains available unless separately disabled |
| `allowed-tools`, `model`, `context`, hooks or other tool-specific fields | Retained as content; no tool grants, model switch, process launch or hook execution |

By default both automatic and explicit use are available. Authorization for an
explicit-only skill lasts for the running session and its delegates. On resume,
previously loaded text remains in the transcript, but loading that skill again
requires another explicit `/skill` invocation.

Project metadata and documents use the same path checks and filtered views as
repository files. Skills on paths hidden by policy are omitted from model
discovery and cannot be loaded by name. Visible sealed or sensitive skill files
receive the boundary's notices, handles or filtered views; their raw bodies are
withheld. Owner and installed-plugin content is sanitized like operator messages.
All frontier requests still pass the outbound gate. A loaded
document records an `instructions` audit event with its skill ID, byte count and
SHA-256 digest.

Discovery does not execute code or contact a server. Documents are bounded at
128 KiB, loads reject symlinks and path traversal, and each load rechecks the
discovered `SKILL.md` digest. Referenced text resources load relative to the skill
directory. A script named in a skill is not run by `load_skill`; any later command
uses Declass's existing tools, sandbox and approvals.

## Native plugin packages

A plugin is an owner-installed local directory with a versioned manifest:

```text
quality-kit/
├── declass-plugin.toml
├── skills/
│   └── code-review/
│       └── SKILL.md
└── commands/
    └── review.md
```

```toml
schema_version = 1
name = "quality-kit"
version = "0.1.0"
description = "Review code changes with reproducible findings and focused checks."
skills = ["skills"]
commands = "commands"
mcp = []
```

Names are lowercase slugs. Paths are relative and cannot traverse out of the
package. `skills` defaults to `["skills"]`, `commands` to `"commands"`, and `mcp`
to an empty list. Unknown manifest fields are rejected. Native packages currently
contribute skills, Markdown prompt commands and MCP servers.

### Install, update and remove

```sh
declass plugins inspect ./quality-kit   # inspect manifest, capabilities and content digest
declass plugins install ./quality-kit   # private snapshot; enabled for the next session
declass plugins list
declass plugins disable quality-kit    # disable for future sessions
declass plugins enable quality-kit     # verify pinned content, then enable
declass plugins remove quality-kit     # unregister; retain the snapshot for recovery
```

Installation accepts a local directory, with no install scripts, package-manager
calls, marketplace fetch or dependency installation. It rejects symlinks, special
files and traversal; limits include 512 files, 8 MiB per file and 32 MiB per
package. The private store is beside the owner configuration under `plugins/`.
Declass resolves the owner-selected configuration directory once, so macOS `/var`
aliases and linked configuration directories work. Symlinks within the plugin
store and source package are refused.
Package content, including its manifest, is pinned by SHA-256 and checked when
the installed package is loaded. This detects changed content; on its own it does
not prove the publisher's identity or code safety.

### Signed packages

A publisher can sign a package with an SSH key, using OpenSSH's own tools:

```sh
declass plugins digest ./quality-kit > digest.txt     # what is signed: the package's content digest
ssh-keygen -Y sign -n declass-plugin -f ~/.ssh/id_ed25519 digest.txt
mv digest.txt.sig ./quality-kit/declass-plugin.sig
```

You list the publishers you accept in `extension_signers` beside your Declass
config, in OpenSSH's `allowed_signers` format (Ed25519 keys):

```text
publisher@example.org namespaces="declass-plugin" ssh-ed25519 AAAAC3Nza...
```

`declass plugins install` then checks the signature. One that does not match the
package's content refuses it. One by a key you do not list counts as no signature;
`--require-signed` refuses both that and an unsigned package. The signer is
pinned with the package in your lock (`provenance.publicKey`); a later version
signed by another key, or unsigned, is refused unless you pass
`--allow-signer-change`.

To update, inspect and install the revised source directory again. Declass records a
new content snapshot rather than modifying the old one. Restart the session to
refresh its skill catalog and tool servers. Disabling or removing a package does
not erase instructions already loaded or terminate a server in an active session;
close that session to end its tool processes.

`/command quality-kit:review <arguments>` reads `commands/review.md` as task
guidance and appends the operator's arguments. It does not perform shell
substitution, expand `$ARGUMENTS`, or execute backticks. The model can choose
normal tools to carry out the request. Packaged commands do not implicitly
authorize a skill marked `disable-model-invocation`.

### Optional MCP tool servers

An installed package can declare one or more `[[mcp]]` entries. Inspecting and
installing the package does not start them; an enabled package contributes them
when a run or session starts. Every contributed setting is checked against
organization policy, then passed to Declass's existing MCP client.

For example, a package with an already reviewed `server.py` could declare:

```toml
[[mcp]]
name = "review"
command = "python3"
args = ["${DECLASS_PLUGIN_ROOT}/server.py"]
trust = "sensitive"
network = false
approve = "always"
timeout_seconds = 60
env = []
```

This is a manifest example, not a server included in `quality-kit`. Using an
interpreter needs no executable bit on the script. `${DECLASS_PLUGIN_ROOT}` expands
only in `command` and `args`, to the installed snapshot. Stdio servers run in the
command sandbox with the workspace as their working directory; extra environment
variables must be named in `env`. Like every sandboxed process, they cannot read the
credential stores in the home directory; a package cannot change that (only the
owner's own `[mcp.servers.<name>]` settings can, with `read_home_secrets`).

An HTTP server uses `url` instead of `command`. URLs require HTTPS, except HTTP
on loopback. Supply credential variable names through
`headers_env = ["Authorization=REVIEW_AUTH"]`; the variable holds the complete
header value. Never put credential values in a manifest. Choose exactly one of
`command` or `url`.

Plugin server defaults are `trust = "sensitive"`, `network = false`,
`approve = "always"` and a 60-second timeout. Approval behavior follows the
session's oversight mode: `always` asks for each call under `risky`, `all` asks
for every tool call, and `off` does not ask. Result filtering and outbound
argument checks still apply. In top clearance, HTTP servers and stdio servers
declared with network access are not started. See the
[MCP controls](USAGE.md#coding-with-declass-the-workspace) and
[security model](../SECURITY.md) for transport, sandbox and data-handling details.

### Workspace controls

Both extension features are enabled by default. A repository can disable them:

```sh
declass config set --project extensions.skills_enabled false
declass config set --project extensions.plugins_enabled false
```

Disabling skills removes skill discovery, including plugin skills. Disabling
plugins removes package contributions; ordinary project and owner skills still
work. Repository configuration cannot install or enable owner packages, loosen
these controls, or grant permissions through an instruction file.

## Pin and verify extensions

A skill or plugin can change after you reviewed it: an update, a sync from
another tool, or a malicious edit to a bundled file the model loads later.
`declass extensions` records what each one must be, and checks it.

```sh
declass extensions                    # what is installed and whether it is pinned
declass extensions lock               # pin your own skills and installed plugins
declass extensions lock --project     # pin this repository's skills
declass extensions verify             # compare everything with its pin
```

There are two lock files:

- **Yours**, `extensions.lock` beside your Declass config, pins the skills in
  your own skill directories and your installed plugins.
- **The project's**, `.declass/extensions.lock`, pins the repository's own
  skills: those under `.declass/skills`, `.agents/skills`, `.claude/skills` and
  `.opencode/skills`, which other coding agents read too. Commit it
  (`git add -f .declass/extensions.lock`; Declass keeps `.declass/` out of git by
  default). It can only add requirements: it cannot pin anything outside the
  repository, and nothing in it starts a program.

A pin covers every file in the skill or plugin directory, not only `SKILL.md`.
Its `contentDigest` is computed as ToolHive computes it, and the entries use
ToolHive's lock file field names, so the same files give the same digest in
both tools. Links inside a skill directory are not covered by any digest;
`verify` lists them.

`lock` refuses to replace a pin whose skill or plugin changed. Review the
change, then run it again with `--update`. Installing a plugin pins it, and
removing one removes its pin.

### When a session starts

Every run and session checks its skills and plugins against the pins before
anything loads them. `extensions.integrity` decides what happens to one that
differs:

| Setting | A changed skill or plugin |
|---|---|
| `warn` (default) | Loaded; the session says how it differs |
| `enforce` | Left out; the model is told it is unavailable. An unusable lock file stops the run |
| `off` | Not checked |

A repository can raise the setting for everyone who works in it
(`declass config set --project extensions.integrity enforce`), never lower it.

The first time a run loads one of your own skills or plugins, it is pinned in
your lock (`extensions.integrity_first_use`, on by default), so a later change
is noticed. A project's skills are never pinned this way: they follow the
project's lock. With a project lock, a project skill it does not list counts
as changed; without one, project skills load as before.

What a session loads is what was checked: each skill is sealed to the files
it was hashed from, so a file added or edited after the session started is
refused when the model asks for it. Every check that did not simply match is
an `extension_integrity` audit event, and each run records an
`integrity_summary`. Pins written to your lock are recorded in your settings
change log.

### MCP servers

A tool server is pinned by what decides its behaviour:

- the command line, as configured;
- the program it resolves to, by content digest;
- the package a launcher runs (`npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx run`,
  `docker run`, `go run`) and its version;
- any install directories you name, by content (`--root`);
- every tool it lists: each tool's definition (description, schemas,
  annotations; everything but `_meta`) as canonical JSON, by digest.

Your servers are pinned the first time a run starts them, or now:

```sh
declass extensions lock mcp:files                    # starts it in the sandbox and records it
declass extensions lock mcp:files --root ~/.local/mcp/files   # also its install directory
declass extensions verify --live                     # start each server and compare its tools
declass extensions diff mcp:files                    # the definitions that changed, side by side
declass extensions forget mcp:files                  # remove the pin
```

A launcher without an exact version (`npx -y @acme/files-mcp`) runs whatever
the registry serves that day, so no pin says what code runs: `verify` names
it (`DX004`), a run warns, and `enforce` does not start it. Pin a version
(`@acme/files-mcp@1.4.2`).

When a run starts, a server whose program, package, directories or tools
differ from its pin is reported (`warn`) or not started and its tools not
offered (`enforce`). A server can also change its tools later, as the
Deadbugz campaign did after a few calls: Declass lists a server's tools again
after it announces a change, after its HTTP session is established again, and
after its 1st, 2nd, 4th, 8th... call. If they differ from what was offered at
the start, it is a `toolset_changed` audit event, and under `enforce` the
server's tools, including the answer to that call, are withheld for the rest
of the run. The definitions the model was given never change during a run.

A project can pin its servers' command line, package and tools too
(`declass extensions lock --project mcp:files`), not where they are installed
on one machine.

Limits: a pin of an interpreter (`node`, `python3`) says little about the
script it runs; pin the script's directory with `--root`. An HTTP server is
pinned by its URL and its tools only.

### Advisories

Some extensions are known to be malicious, such as the `postmark-mcp` npm
package from version 1.0.16, which copied every email it sent to an outside
address. Declass reads advisories in the [OSV](https://ossf.github.io/osv-schema/)
format and matches them against what is installed:

- those shipped with Declass;
- your feeds, fetched when you ask (never during a run):

  ```sh
  declass config set extensions.advisory_urls '["https://example.org/extensions.json"]' --confirm
  declass extensions advisories update            # fetch them
  declass extensions advisories update --online   # also ask osv.dev about your servers' packages
  declass extensions advisories                   # what is known, and how old it is
  ```

- a project's own, in `.declass/advisories/*.json`.

A record matches by package and version (npm, PyPI, crates.io, Go), and
Declass's own block in `database_specific.declass` can name what has no
registry: `contentDigests` (skills and plugins), `toolDigests` and
`toolsetDigests` (MCP tool definitions) and `serverUrls`. A malicious-package
record (`MAL-` ID or alias) or one with `"action": "revoke"` leaves the
extension out in every mode, `warn` too; any other record is reported.
`verify` reports both (`DX003`), and feeds older than
`extensions.advisory_max_age_days` (30) as out of date (`DX008`). With
`--online`, osv.dev learns the names and versions of the packages your
servers run.

### In CI

`verify` starts nothing and needs no model or API key:

```sh
declass extensions verify --project-only --strict --format sarif --output declass-extensions.sarif
```

It exits 0 when everything matches, 1 with warnings (such as a project skill
that is not pinned) and 2 with errors (a changed or unreadable skill, an
unusable lock file). `--strict` treats warnings as errors. Findings have stable
rule IDs: `DX001` content differs from the pin, `DX002` not pinned, `DX003`
revoked or vulnerable (an advisory), `DX004` a
launcher without a pinned version, `DX006` a server's tools differ from its
pin (`--live`), `DX007` the lock file cannot be used, `DX008` advisory feeds
out of date, `DX009` pinned but no longer installed. JSON (`--format json`) and SARIF are for other programs and
code-scanning tools.

## Compatibility at a glance

| Existing format or feature | Declass support |
|---|---|
| `AGENTS.md` / `AGENTS.override.md` | Root and directory scope, using Declass's ordering and limits above |
| `CLAUDE.md`, `GEMINI.md`, `DECLASS.md` | Plain instruction text at root and directory scope; no automatic `@file` includes |
| `.github/copilot-instructions.md` | Repository root only; `.github/instructions/*.instructions.md` globs are not interpreted |
| Standard `SKILL.md` with `name`, `description` and Markdown | Supported, with lazy text-resource loading and the parser limits above |
| Claude-style invocation flags | `disable-model-invocation` and `user-invocable` are enforced as documented above |
| Claude Code plugin manifests and marketplaces | Not imported; adapt portable skills and commands into `declass-plugin.toml` |
| Foreign Claude/DeepSeek plugin ABIs, hooks, install scripts or runtime APIs | Not executed or emulated; choosing a model provider does not add a plugin runtime |
| Native Declass skills and prompt commands | Supported through local package installation |
| MCP stdio / streamable HTTP | Supported through owner configuration or a native package, with Declass's security controls |
| Native plugin dependency resolution, automatic updates or marketplace | Not implemented |
| Native plugin signing | SSH signatures (`ssh-keygen -Y sign -n declass-plugin`), checked at install against `extension_signers` |
| ToolHive `toolhive.lock.yaml` | Same entry field names and the same `contentDigest` algorithm; Declass's lock is TOML in its own file |

Claude Code defines a separate plugin manifest and runtime, including hooks and
other components; those features require explicit adaptation. See its
[official plugin manifest reference](https://code.claude.com/docs/en/plugins-reference).
Declass's portable-skill support does not imply compatibility with that plugin runtime.

## Verification

The [local validation record](evidence/extensions-validation-2026-10-01.md)
includes test counts, plugin lifecycle checks and environment limitations.
Quality claims for this extension-enabled prompt still require task benchmarks.
