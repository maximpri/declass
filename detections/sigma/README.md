<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Detection rules for Declass's audit events

[Sigma](https://sigmahq.io) rules over the security events Declass records in each run's audit
log. Export the events as JSON lines and send them to your SIEM:

```sh
declass audit events            # every run in this workspace
declass audit events <run>      # one run
declass audit events --include-paths   # file paths, commands and destinations as written
```

Each line is one event, flat: `product` (`declass`), `service` (`audit`), `run` (the run ID),
`seq`, `time` (RFC 3339), `kind`, and the event's own fields. Request bodies are never exported.
Without `--include-paths`, the values of `path`, `paths`, `command`, `derived_files`, `origin` and
`destination` are replaced by `sha256:` and their digest, so the same file or command still
correlates across events.

The rules use `logsource: product: declass, service: audit`. Convert them with
[sigma-cli](https://github.com/SigmaHQ/sigma-cli) and the pipeline in `pipelines/declass.yml`,
which maps that log source to events whose `product` field is `declass`:

```sh
# Rules first, then the correlations that refer to them (pySigma resolves references in order).
sigma convert -t <your backend> -p pipelines/declass.yml \
  $(grep -L '^correlation:' declass/*.yml) $(grep -l '^correlation:' declass/*.yml)
```

The rules pass `sigma check` and convert with pySigma 0.11 to Splunk; a backend without
correlation support converts only the single-event rules.

| Rule | Fires on | Level |
|---|---|---|
| `declass_autorun_trigger_written` | the agent created or changed a file another tool runs without asking (`.vscode/tasks.json`, `.envrc`, `.mcp.json`, another agent's settings, `AGENTS.md`) | medium |
| `declass_autorun_trigger_by_command` | the same, written by a command rather than the file tools (which can ask first) | high |
| `declass_injection_then_autorun_trigger` | prompt injection read, then an autorun file written in the same run (correlation) | critical |
| `declass_extension_left_out` | a skill, plugin or MCP server left out: changed since pinned, or revoked | high |
| `declass_mcp_toolset_changed` | an MCP server changed its tool definitions during a run | high |
| `declass_mcp_server_refused` | an MCP server refused at start by its pin or an advisory | medium |
| `declass_outbound_refused_burst` | five or more refused sends to third parties within ten minutes (correlation) | high |

The fields each event kind carries are described in `crates/declass-boundary/src/audit.rs`
(`AuditEvent`).
