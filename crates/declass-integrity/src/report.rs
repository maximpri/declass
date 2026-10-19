// SPDX-License-Identifier: GPL-3.0-or-later
//! What a verification found, for people (text), programs (JSON) and code
//! scanning (SARIF 2.1.0).

use serde_json::{Value, json};

/// Stable rule identifiers: CI configurations and SARIF viewers key on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// The files, executable or install directory differ from the pin.
    DigestMismatch,
    /// Loaded, but nothing pins it.
    Unpinned,
    /// An advisory feed revokes it.
    Revoked,
    /// A launcher runs whatever version a registry serves now.
    FloatingLauncher,
    /// Signed by someone other than the pinned signer.
    SignerChanged,
    /// The server's tool definitions differ from the pinned ones.
    ToolsetChanged,
    /// The lock file cannot be read or breaks a rule.
    InvalidLock,
    /// The advisory feeds were not updated recently.
    StaleAdvisories,
    /// Pinned, but no longer installed or configured.
    PinnedMissing,
}

impl Rule {
    pub const ALL: [Rule; 9] = [
        Rule::DigestMismatch,
        Rule::Unpinned,
        Rule::Revoked,
        Rule::FloatingLauncher,
        Rule::SignerChanged,
        Rule::ToolsetChanged,
        Rule::InvalidLock,
        Rule::StaleAdvisories,
        Rule::PinnedMissing,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Rule::DigestMismatch => "DX001",
            Rule::Unpinned => "DX002",
            Rule::Revoked => "DX003",
            Rule::FloatingLauncher => "DX004",
            Rule::SignerChanged => "DX005",
            Rule::ToolsetChanged => "DX006",
            Rule::InvalidLock => "DX007",
            Rule::StaleAdvisories => "DX008",
            Rule::PinnedMissing => "DX009",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Rule::DigestMismatch => "DigestMismatch",
            Rule::Unpinned => "Unpinned",
            Rule::Revoked => "Revoked",
            Rule::FloatingLauncher => "FloatingLauncher",
            Rule::SignerChanged => "SignerChanged",
            Rule::ToolsetChanged => "ToolsetChanged",
            Rule::InvalidLock => "InvalidLock",
            Rule::StaleAdvisories => "StaleAdvisories",
            Rule::PinnedMissing => "PinnedMissing",
        }
    }

    fn summary(self) -> &'static str {
        match self {
            Rule::DigestMismatch => "An extension's content differs from its pin",
            Rule::Unpinned => "An extension is loaded without a pin",
            Rule::Revoked => "An advisory revokes an extension",
            Rule::FloatingLauncher => "An MCP server is launched without a pinned version",
            Rule::SignerChanged => "An extension is signed by a different signer",
            Rule::ToolsetChanged => "An MCP server's tool definitions changed",
            Rule::InvalidLock => "A lock file cannot be used",
            Rule::StaleAdvisories => "Advisory feeds are out of date",
            Rule::PinnedMissing => "A pinned extension is missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Note,
    Warning,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Note => "note",
            Level::Warning => "warning",
            Level::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: Rule,
    pub level: Level,
    /// `skill`, `plugin`, `mcp` or `lock`.
    pub kind: &'static str,
    /// The extension's name, or the lock file's path.
    pub id: String,
    pub message: String,
    /// A file the finding is about (relative to the workspace when inside it).
    pub location: Option<String>,
}

/// The exit code for `findings`: 2 with an error (or, under `strict`, a
/// warning), 1 with a warning, else 0. Notes never fail.
pub fn exit_code(findings: &[Finding], strict: bool) -> i32 {
    match findings.iter().map(|f| f.level).max() {
        Some(Level::Error) => 2,
        Some(Level::Warning) if strict => 2,
        Some(Level::Warning) => 1,
        _ => 0,
    }
}

pub fn to_json(findings: &[Finding], checked: usize) -> Value {
    json!({
        "checked": checked,
        "findings": findings.iter().map(|f| json!({
            "rule": f.rule.id(),
            "level": f.level.as_str(),
            "kind": f.kind,
            "id": f.id,
            "message": f.message,
            "location": f.location,
        })).collect::<Vec<_>>(),
    })
}

/// A SARIF 2.1.0 log with one run.
pub fn to_sarif(findings: &[Finding], version: &str) -> Value {
    let rules: Vec<Value> = Rule::ALL
        .iter()
        .map(|r| {
            json!({
                "id": r.id(),
                "name": r.name(),
                "shortDescription": {"text": r.summary()},
            })
        })
        .collect();
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let mut result = json!({
                "ruleId": f.rule.id(),
                "ruleIndex": Rule::ALL.iter().position(|r| *r == f.rule).unwrap_or(0),
                "level": f.level.as_str(),
                "message": {"text": format!("{} {}: {}", f.kind, f.id, f.message)},
            });
            if let Some(uri) = &f.location {
                result["locations"] = json!([{
                    "physicalLocation": {"artifactLocation": {"uri": uri}}
                }]);
            }
            result
        })
        .collect();
    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "declass",
                "version": version,
                "informationUri": "https://github.com/maximpri/declass",
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: Rule, level: Level) -> Finding {
        Finding {
            rule,
            level,
            kind: "skill",
            id: "code-review".into(),
            message: "content differs from the pin".into(),
            location: Some(".agents/skills/code-review/SKILL.md".into()),
        }
    }

    #[test]
    fn exit_codes_follow_the_worst_finding() {
        assert_eq!(exit_code(&[], false), 0);
        assert_eq!(exit_code(&[finding(Rule::Unpinned, Level::Note)], false), 0);
        assert_eq!(exit_code(&[finding(Rule::Unpinned, Level::Note)], true), 0);
        assert_eq!(
            exit_code(&[finding(Rule::Unpinned, Level::Warning)], false),
            1
        );
        assert_eq!(
            exit_code(&[finding(Rule::Unpinned, Level::Warning)], true),
            2
        );
        assert_eq!(
            exit_code(
                &[
                    finding(Rule::Unpinned, Level::Warning),
                    finding(Rule::DigestMismatch, Level::Error)
                ],
                false
            ),
            2
        );
    }

    #[test]
    fn sarif_names_every_rule_and_points_at_the_file() {
        let log = to_sarif(&[finding(Rule::DigestMismatch, Level::Error)], "0.3.0");
        let run = &log["runs"][0];
        let ids: Vec<&str> = run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), Rule::ALL.len());
        assert_eq!(ids[0], "DX001");
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "DX001");
        assert_eq!(result["ruleIndex"], 0);
        assert_eq!(result["level"], "error");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            ".agents/skills/code-review/SKILL.md"
        );
        let json = to_json(&[finding(Rule::DigestMismatch, Level::Error)], 3);
        assert_eq!(json["checked"], 3);
        assert_eq!(json["findings"][0]["rule"], "DX001");
    }
}
