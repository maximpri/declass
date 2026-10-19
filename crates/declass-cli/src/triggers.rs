// SPDX-License-Identifier: GPL-3.0-or-later
//! Files another tool runs later that a run created or changed (an editor's
//! tasks, a direnv `.envrc`, another coding agent's settings, a git hook, a
//! package script: `declass_fs::triggers`), read back from the runs' audit
//! logs: listed when a run ends, and by `declass triggers`.

use anyhow::Result;
use declass_boundary::audit::{AuditEvent, Line, read};
use std::collections::BTreeMap;
use std::path::Path;

/// One file, as the latest event about it in a run says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Changed {
    pub path: String,
    /// `tool` or `command`.
    pub by: String,
    /// `autorun` or `on_use`.
    pub tier: String,
    pub runner: String,
}

/// The files the run whose audit log is `log` changed, by path.
pub(crate) fn changed_in(log: &Path) -> Vec<Changed> {
    let mut by_path = BTreeMap::new();
    for line in read(log).unwrap_or_default() {
        if let Line::Event(e) = line
            && let AuditEvent::TriggerWritten {
                path,
                by,
                tier,
                runner,
                ..
            } = e.event
        {
            by_path.insert(
                path.clone(),
                Changed {
                    path,
                    by,
                    tier,
                    runner,
                },
            );
        }
    }
    by_path.into_values().collect()
}

/// The lines to show when a run ends (none when it changed no such file).
pub(crate) fn report(log: &Path) -> Vec<String> {
    let changed = changed_in(log);
    if changed.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "This run changed {} file(s) that another tool runs later; review them before it does:",
        changed.len()
    )];
    for c in &changed {
        lines.push(format!(
            "  {}{}  ({}; written by {})",
            c.path,
            if c.tier == "autorun" {
                "  runs without asking"
            } else {
                ""
            },
            c.runner,
            if c.by == "command" {
                "a command"
            } else {
                "the agent"
            }
        ));
    }
    lines
}

/// `declass triggers`: every such file the workspace's runs changed, newest
/// run first.
pub(crate) fn list(ws: &Path, json: bool) -> Result<i32> {
    let dir = ws.join(".declass/audit");
    let mut logs: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                .collect()
        })
        .unwrap_or_default();
    logs.sort();
    logs.reverse();
    let runs: Vec<(String, Vec<Changed>)> = logs
        .iter()
        .map(|log| {
            (
                log.file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                changed_in(log),
            )
        })
        .filter(|(_, changed)| !changed.is_empty())
        .collect();
    if json {
        let list: Vec<serde_json::Value> = runs
            .iter()
            .flat_map(|(run, changed)| {
                changed.iter().map(move |c| {
                    serde_json::json!({
                        "run": run,
                        "path": c.path,
                        "by": c.by,
                        "tier": c.tier,
                        "runner": c.runner,
                    })
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(0);
    }
    if runs.is_empty() {
        println!("No run in this workspace changed a file that another tool runs later.");
        return Ok(0);
    }
    let mut out = String::new();
    for (run, changed) in &runs {
        out.push_str(&format!("run {run}\n"));
        for c in changed {
            out.push_str(&format!(
                "  {:<8} {}  ({}; by {})\n",
                if c.tier == "autorun" {
                    "autorun"
                } else {
                    "on use"
                },
                c.path,
                c.runner,
                c.by
            ));
        }
    }
    print!("{}", declass_tui::term::safe(&out));
    Ok(0)
}
