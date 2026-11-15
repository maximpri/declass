// SPDX-License-Identifier: GPL-3.0-or-later
//! The exposure report as SARIF 2.1.0, for GitHub code scanning and other
//! SARIF tools.
//!
//! One result per file and kind of value, at the first value of that kind,
//! with the count and what Declass does with the file. Nothing in a result
//! comes from a value: no snippet, no line of content, no hash of either, no
//! end column (which would give a value's length). The partial fingerprint is
//! a digest of where the result is from, its path and its rule, so a result
//! keeps its identity while the file's lines move.
//!
//! GitHub's upload action fingerprints results that have a line itself, from
//! the file on the runner (docs/OPERATIONS.md says so).

use super::{Exposed, Level, Position, Report, kind_name, level};
use declass_boundary::detect::Kind;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Results GitHub code scanning accepts in one run; a log with more is
/// refused whole.
const MAX_RESULTS: usize = 25_000;

/// Where the documentation of the report and its rules is.
const HELP_URI: &str =
    "https://github.com/maximpri/declass/blob/main/docs/OPERATIONS.md#see-what-an-agent-could-send";

/// One rule per kind of value. The ids are stable: alerts and CI
/// configurations key on them.
struct Rule {
    kind: Kind,
    id: &'static str,
    name: &'static str,
    what: &'static str,
}

const RULES: [Rule; 12] = [
    Rule {
        kind: Kind::Secret,
        id: "exposure/secret",
        name: "Secret",
        what: "A credential the secret detectors recognize: a provider key or token format, a private key, a password in a URL, a value assigned to a password, token or key setting, a match of the imported gitleaks rules, or a high-entropy token.",
    },
    Rule {
        kind: Kind::Email,
        id: "exposure/email",
        name: "EmailAddress",
        what: "An email address. Addresses at reserved example domains (example.com, .test and the like) are not counted.",
    },
    Rule {
        kind: Kind::Phone,
        id: "exposure/phone",
        name: "PhoneNumber",
        what: "A phone number: US formats, international numbers with a country code, and national numbers labelled as phone numbers.",
    },
    Rule {
        kind: Kind::Card,
        id: "exposure/card",
        name: "CardNumber",
        what: "A payment card number: it passes the Luhn check and starts as a card network's numbers do, or a label calls it a card number.",
    },
    Rule {
        kind: Kind::NationalId,
        id: "exposure/national-id",
        name: "NationalId",
        what: "A national identifier, with its check where it has one: a US Social Security number, UK National Insurance number, German tax ID, French NIR, Spanish DNI or NIE, Italian codice fiscale or Dutch BSN, or a number labelled as an ID, passport or licence.",
    },
    Rule {
        kind: Kind::Iban,
        id: "exposure/iban",
        name: "Iban",
        what: "An IBAN of a registry country, with the country's length and a valid mod-97 check.",
    },
    Rule {
        kind: Kind::Ip,
        id: "exposure/ip-address",
        name: "IpAddress",
        what: "An IPv4 or IPv6 address. Loopback and broadcast addresses are not counted.",
    },
    Rule {
        kind: Kind::Name,
        id: "exposure/name",
        name: "PersonName",
        what: "A person's name. The pattern detectors in this report do not look for names; Declass finds them with the local model during a run.",
    },
    Rule {
        kind: Kind::Data,
        id: "exposure/custom-pattern",
        name: "CustomPatternMatch",
        what: "A match of one of the regular expressions in sensitivity.custom_patterns: values the project or owner declared sensitive.",
    },
    Rule {
        kind: Kind::Code,
        id: "exposure/protected-code",
        name: "ProtectedCode",
        what: "A fragment of protected source code. This report does not look for it.",
    },
    Rule {
        kind: Kind::Account,
        id: "exposure/account-number",
        name: "AccountNumber",
        what: "A bank account or routing number, recognized by its label.",
    },
    Rule {
        kind: Kind::Address,
        id: "exposure/postal-address",
        name: "PostalAddress",
        what: "A postal address in a labelled field.",
    },
];

/// What a finding means and what to do about it, for the rule's help.
const LEVELS: &str = "Levels follow what Declass does with the file under its path rules. \
Note: sensitivity.globs, sensitivity.protected_paths or ip.sealed keep the file's content from \
the cloud model; only the local model reads it, or the cloud model only learns it exists. \
Error (a secret) or warning (anything else): the cloud model reads the file, ip.interface_only \
signatures and public constants included, with the values Declass detects replaced by \
placeholders before any request.";

const ACCEPT: &str = "To accept a file's findings, keep it local: add its path to [sensitivity] \
protected_paths in .declass/config.toml, and its findings become notes. A real secret should be \
removed and rotated; it stays readable in git history.";

fn help(r: &Rule) -> Value {
    json!({
        "text": format!(
            "{} Found by `declass exposure`, which reads the repository offline and reports counts and positions, never a value. {LEVELS} {ACCEPT}",
            r.what
        ),
        "markdown": format!(
            "{}\n\nFound by `declass exposure`, which reads the repository offline and reports counts and positions, never a value.\n\n\
    **Levels.** {LEVELS}\n\n**What to do.** {ACCEPT}\n\n[How the report works]({HELP_URI})",
            r.what
        ),
    })
}

fn rules() -> Vec<Value> {
    RULES
        .iter()
        .map(|r| {
            let default = if r.kind == Kind::Secret {
                Level::Error
            } else {
                Level::Warning
            };
            json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": {"text": format!("{} a coding agent could send to a cloud model", r.name_text())},
                "fullDescription": {"text": r.what},
                "help": help(r),
                "helpUri": HELP_URI,
                "defaultConfiguration": {"level": default.as_str()},
                "properties": {"tags": ["privacy", if r.kind == Kind::Secret { "secret" } else { "personal-data" }]},
            })
        })
        .collect()
}

impl Rule {
    fn name_text(&self) -> &'static str {
        match self.kind {
            Kind::Secret => "A secret",
            Kind::Email => "An email address",
            Kind::Phone => "A phone number",
            Kind::Card => "A card number",
            Kind::NationalId => "A national ID",
            Kind::Iban => "An IBAN",
            Kind::Ip => "An IP address",
            Kind::Name => "A person's name",
            Kind::Data => "A custom-pattern match",
            Kind::Code => "Protected code",
            Kind::Account => "An account number",
            Kind::Address => "A postal address",
        }
    }
}

/// A path as a relative URI reference: unreserved characters and `/` as
/// they are, every other byte percent-encoded.
fn uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A digest of where a result is from, its path and its rule: never of content.
fn fingerprint(source: &str, path: &str, rule: &str) -> String {
    let mut h = Sha256::new();
    for part in ["declass-exposure/v1", source, path, rule] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    hex::encode(h.finalize())
}

fn lines(positions: &[Position], count: usize) -> String {
    let lines: Vec<String> = {
        let mut l: Vec<u32> = positions.iter().map(|p| p.line).collect();
        l.dedup();
        l.iter().map(u32::to_string).collect()
    };
    match lines.as_slice() {
        [] => String::new(),
        [one] if count == 1 => format!(", on line {one}"),
        [one] => format!(", on line {one}"),
        many => {
            let shown = if count > positions.len() {
                format!("{} (first {} shown)", many.join(", "), positions.len())
            } else {
                let (last, rest) = many.split_last().expect("two or more");
                format!("{} and {last}", rest.join(", "))
            };
            format!(", on lines {shown}")
        }
    }
}

fn location(path: &str, position: Position) -> Value {
    json!([{
        "physicalLocation": {
            "artifactLocation": {"uri": uri(path), "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": position.line, "startColumn": position.column},
        }
    }])
}

fn tree_results(exposed: &[Exposed], out: &mut Vec<(Level, Value)>) {
    let mut files: Vec<&Exposed> = exposed.iter().collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    for e in files {
        for (index, r) in RULES.iter().enumerate() {
            let tag = r.kind.tag();
            let Some(&count) = e.found.get(tag) else {
                continue;
            };
            let positions = e.positions.get(tag).map_or(&[][..], Vec::as_slice);
            let first = positions
                .first()
                .copied()
                .unwrap_or(Position { line: 1, column: 1 });
            let level = level(r.kind, e.disposition);
            out.push((level, json!({
                "ruleId": r.id,
                "ruleIndex": index,
                "level": level.as_str(),
                "message": {"text": format!(
                    "{} a coding agent could send to a cloud model{}. With Declass: {} ({}).",
                    kind_name(r.kind, count),
                    lines(positions, count),
                    e.declass,
                    e.rule
                )},
                "locations": location(&e.path, first),
                "partialFingerprints": {"declassExposure/v1": fingerprint("tree", &e.path, r.id)},
                "properties": {"count": count, "disposition": e.disposition, "pathRule": e.rule},
            })));
        }
    }
}

fn history_results(history: &super::history::History, out: &mut Vec<(Level, Value)>) {
    for e in &history.exposed {
        for (index, r) in RULES.iter().enumerate() {
            let Some(&count) = e.found.get(r.kind.tag()) else {
                continue;
            };
            let versions = if e.versions == 1 {
                "1 earlier version".to_owned()
            } else {
                format!("{} earlier versions", e.versions)
            };
            let level = super::history::history_level(r.kind, e.disposition);
            out.push((level, json!({
                "ruleId": r.id,
                "ruleIndex": index,
                "level": level.as_str(),
                "message": {"text": format!(
                    "{} in git history ({versions}{}) and not in the working tree; an agent could read them through history. With Declass: {} ({}); its git tools classify history by the path's current rules.",
                    kind_name(r.kind, count),
                    if e.deleted { ", file since deleted" } else { "" },
                    e.declass,
                    e.rule
                )},
                // Lines of an earlier version do not apply to the file now.
                "locations": location(&e.path, Position { line: 1, column: 1 }),
                "partialFingerprints": {"declassExposure/v1": fingerprint("history", &e.path, r.id)},
                "properties": {"count": count, "versions": e.versions, "deleted": e.deleted, "disposition": e.disposition, "pathRule": e.rule, "history": true},
            })));
        }
    }
}

/// A SARIF 2.1.0 log with one run.
pub(super) fn log(report: &Report, version: &str) -> Value {
    log_with(report, version, MAX_RESULTS)
}

/// [`log`], with at most `max` results.
fn log_with(report: &Report, version: &str, max: usize) -> Value {
    let mut results = Vec::new();
    tree_results(&report.exposed, &mut results);
    if let Some(history) = &report.history {
        history_results(history, &mut results);
    }
    let mut notes = Vec::new();
    let all = results.len();
    if all > max {
        // The most severe first; within a level, the order above.
        results.sort_by_key(|(level, _)| std::cmp::Reverse(*level));
        results.truncate(max);
        notes.push(json!({
            "level": "warning",
            "message": {"text": format!(
                "{} of {all} results are left out: code scanning accepts {max} in a run. Errors come first, then warnings, then notes; the text and JSON reports list every file.",
                all - max
            )},
        }));
    }
    let results: Vec<Value> = results.into_iter().map(|(_, result)| result).collect();
    if !report.complete {
        notes.push(json!({
            "level": "error",
            "message": {"text": "The report is incomplete: a limit was reached, or a directory, a name, derived classifications or git history could not be read. Files it did not reach have no results."},
        }));
    }
    if !report.detectors_off.is_empty() {
        notes.push(json!({
            "level": "warning",
            "message": {"text": format!("Detectors turned off in the configuration were not run: {}.", report.detectors_off.join(", "))},
        }));
    }
    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "declass",
                "version": version,
                "semanticVersion": version,
                "informationUri": "https://github.com/maximpri/declass",
                "rules": rules(),
            }},
            // Its own category, so it never replaces `declass extensions verify` results.
            "automationDetails": {"id": "declass-exposure/"},
            "columnKind": "unicodeCodePoints",
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": notes,
            }],
            "properties": {
                "complete": report.complete,
                "filesScanned": report.files_scanned,
                "failOn": report.fail_on,
                "failing": report.failing,
            },
            "results": results,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_stable_and_every_kind_has_one() {
        let ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
        assert_eq!(
            ids,
            [
                "exposure/secret",
                "exposure/email",
                "exposure/phone",
                "exposure/card",
                "exposure/national-id",
                "exposure/iban",
                "exposure/ip-address",
                "exposure/name",
                "exposure/custom-pattern",
                "exposure/protected-code",
                "exposure/account-number",
                "exposure/postal-address",
            ]
        );
        for kind in Kind::ALL {
            assert_eq!(
                RULES.iter().filter(|r| r.kind == kind).count(),
                1,
                "{kind:?}"
            );
        }
        for r in rules() {
            for field in ["shortDescription", "fullDescription"] {
                let text = r[field]["text"].as_str().unwrap();
                assert!(!text.is_empty() && text.len() <= 1024, "{field}: {text}");
            }
            assert!(!r["help"]["text"].as_str().unwrap().is_empty());
        }
    }

    #[test]
    fn uris_are_relative_references_and_fingerprints_depend_on_path_and_rule_only() {
        assert_eq!(uri("src/app.py"), "src/app.py");
        assert_eq!(uri("app/[id]/page one.tsx"), "app/%5Bid%5D/page%20one.tsx");
        assert_eq!(uri("dö.txt"), "d%C3%B6.txt");
        let a = fingerprint("tree", "src/a.py", "exposure/secret");
        assert_eq!(a, fingerprint("tree", "src/a.py", "exposure/secret"));
        assert_ne!(a, fingerprint("tree", "src/a.py", "exposure/email"));
        assert_ne!(a, fingerprint("history", "src/a.py", "exposure/secret"));
        assert_ne!(a, fingerprint("tree", "src/b.py", "exposure/secret"));
    }

    #[test]
    fn a_log_past_the_limit_keeps_the_most_severe_results_and_says_so() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let key = concat!("sk_", "live_Rx7KpW2mNq9TzL4vB8cH3dYsJf");
        std::fs::write(ws.join(".env"), format!("STRIPE_KEY={key}\n")).unwrap();
        std::fs::write(ws.join("a.md"), "Ask jordan.reyes@corpmail.co\n").unwrap();
        std::fs::write(ws.join("b.py"), format!("API_KEY = \"{key}\"\n")).unwrap();
        let owner = temp.path().join("owner.toml");
        std::fs::write(&owner, "").unwrap();
        let cfg = declass_config::Config::load(&owner, None).unwrap();
        let r = super::super::collect(&ws, &cfg, &super::super::Options::default()).unwrap();
        let whole = log(&r, "1.0.0");
        assert_eq!(whole["runs"][0]["results"].as_array().unwrap().len(), 3);
        let capped = log_with(&r, "1.0.0", 2);
        let run = &capped["runs"][0];
        let levels: Vec<&str> = run["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        assert_eq!(levels, ["error", "warning"], "the note is left out");
        let note = run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
            .as_str()
            .unwrap();
        assert!(note.starts_with("1 of 3 results are left out"), "{note}");
    }

    #[test]
    fn messages_list_lines_and_say_when_only_the_first_are_shown() {
        let p = |line| Position { line, column: 1 };
        assert_eq!(lines(&[p(4)], 1), ", on line 4");
        assert_eq!(lines(&[p(4), p(17)], 2), ", on lines 4 and 17");
        assert_eq!(lines(&[p(4), p(4), p(9)], 3), ", on lines 4 and 9");
        assert_eq!(lines(&[p(1), p(2)], 240), ", on lines 1, 2 (first 2 shown)");
    }
}
