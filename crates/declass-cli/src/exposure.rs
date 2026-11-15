// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline exposure report: what a coding agent that reads this workspace could
//! send to a cloud model, and what Declass does with each file instead.
//!
//! Files are read on this machine with the boundary's own detectors; nothing is
//! sent, no model or tool server is started and no run state is created. The
//! report holds counts by kind and paths, never a matched value.
use crate::{Mode, policy, privacy};
use anyhow::Result;
use declass_boundary::detect::{self, CustomPatterns, Detectors, Kind};
use declass_config::Config;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Larger files are listed as not scanned rather than read in part.
const MAX_BYTES: u64 = 2 * 1024 * 1024;
/// A NUL byte in the first block marks a binary file.
const BINARY_PROBE: usize = 8192;

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
    /// List every file with findings (by default the first 25 are shown).
    #[arg(long)]
    all: bool,
}

#[derive(Serialize)]
pub(crate) struct Report {
    schema: u32,
    scope: &'static str,
    complete: bool,
    files_scanned: usize,
    /// Kind tag → values found, over every scanned file.
    totals: BTreeMap<&'static str, usize>,
    exposed: Vec<Exposed>,
    /// Files without findings that path rules keep from the cloud model anyway.
    kept_by_rule: usize,
    not_scanned: NotScanned,
    /// Detectors turned off in the configuration; their kinds were not looked for.
    detectors_off: Vec<&'static str>,
    excluded_directories: &'static [&'static str],
}

#[derive(Serialize)]
struct Exposed {
    path: String,
    /// Kind tag → values found in this file.
    found: BTreeMap<&'static str, usize>,
    disposition: &'static str,
    rule: String,
    declass: &'static str,
}

#[derive(Serialize, Default)]
struct NotScanned {
    too_large: usize,
    /// A NUL byte in the first 8 KiB: binary, or text in UTF-16.
    binary: usize,
    unreadable: usize,
    /// Symlinks and special files, which are never followed or opened.
    not_followed: usize,
}

fn kind_name(kind: Kind, n: usize) -> String {
    let (one, many) = match kind {
        Kind::Secret => ("secret", "secrets"),
        Kind::Email => ("email address", "email addresses"),
        Kind::Phone => ("phone number", "phone numbers"),
        Kind::Card => ("card number", "card numbers"),
        Kind::NationalId => ("national ID", "national IDs"),
        Kind::Iban => ("IBAN", "IBANs"),
        Kind::Ip => ("IP address", "IP addresses"),
        Kind::Name => ("name", "names"),
        Kind::Data => ("custom-pattern match", "custom-pattern matches"),
        Kind::Code => ("protected code fragment", "protected code fragments"),
        Kind::Account => ("account number", "account numbers"),
        Kind::Address => ("postal address", "postal addresses"),
    };
    format!("{n} {}", if n == 1 { one } else { many })
}

fn tag_kind(tag: &str) -> Option<Kind> {
    Kind::ALL.into_iter().find(|k| k.tag() == tag)
}

/// What Declass does with a file under the given disposition.
fn declass_action(disposition: &str) -> &'static str {
    match disposition {
        "sealed" => "the cloud model only learns the file exists",
        "interface-only" => "the cloud model sees signatures, not bodies",
        "sensitive" => "read by your local model, not sent to the cloud model",
        "content-checks" => "values replaced with placeholders before any request",
        _ => "classification unknown; review local state",
    }
}

/// Values found in `text`, by kind, with overlapping matches counted once.
fn count(text: &str, path: &str, d: Detectors, custom: &CustomPatterns) -> BTreeMap<Kind, usize> {
    let mut all = detect::scan_each_in(text, d, Some(path));
    all.extend(custom.find(text));
    all.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
    // Overlapping matches are one value; it is a secret if any match says so
    // (a URL password also looks like an email address).
    let mut out = BTreeMap::new();
    let mut group: Option<(Kind, usize)> = None;
    for f in all {
        match &mut group {
            Some((kind, end)) if f.start < *end => {
                *end = (*end).max(f.end);
                if f.kind == Kind::Secret {
                    *kind = Kind::Secret;
                }
            }
            _ => {
                if let Some((kind, _)) = group.replace((f.kind, f.end)) {
                    *out.entry(kind).or_insert(0) += 1;
                }
            }
        }
    }
    if let Some((kind, _)) = group {
        *out.entry(kind).or_insert(0) += 1;
    }
    out
}

enum Outcome {
    TooLarge,
    Binary,
    Unreadable,
    Read(BTreeMap<Kind, usize>),
}

fn read_one(ws: &Path, path: &str, d: Detectors, custom: &CustomPatterns) -> Outcome {
    let bytes = match declass_fs::read_file(ws, Path::new(path), MAX_BYTES) {
        Ok(b) => b,
        Err(declass_fs::FsError::Io {
            op: "read",
            message,
            ..
        }) if message.starts_with("file exceeds") => {
            return Outcome::TooLarge;
        }
        Err(_) => return Outcome::Unreadable,
    };
    if bytes[..bytes.len().min(BINARY_PROBE)].contains(&0) {
        return Outcome::Binary;
    }
    Outcome::Read(count(&String::from_utf8_lossy(&bytes), path, d, custom))
}

/// Reads and scans `files` on every available core; outcomes keep their order.
fn read_all(
    ws: &Path,
    files: &[privacy::FileRule],
    d: Detectors,
    custom: &CustomPatterns,
) -> Vec<Outcome> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(16);
    // Workers take the next file from a shared counter, so one directory of
    // large files does not hold up the rest.
    let next = AtomicUsize::new(0);
    let mut out: Vec<Option<Outcome>> = files.iter().map(|_| None).collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(f) = files.get(i) else { break };
                        done.push((i, read_one(ws, &f.path, d, custom)));
                    }
                    done
                })
            })
            .collect();
        for h in handles {
            for (i, outcome) in h.join().unwrap_or_default() {
                out[i] = Some(outcome);
            }
        }
    });
    // A file whose worker failed is reported unread, never given another's outcome.
    out.into_iter()
        .map(|o| o.unwrap_or(Outcome::Unreadable))
        .collect()
}

pub(crate) fn collect(ws: &Path, cfg: &Config) -> Result<Report> {
    let p = policy(cfg)?;
    let detectors = Detectors {
        secrets: p.detect_secrets,
        pii: p.detect_pii,
        entropy: p.detect_entropy,
    };
    let custom = CustomPatterns::compile(&p.custom_patterns).map_err(anyhow::Error::msg)?;
    let inventory = privacy::inventory(ws, &p, Mode::Hybrid)?;
    let detectors_off = [
        ("secrets", detectors.secrets),
        ("personal data", detectors.pii),
        ("high-entropy strings", detectors.entropy),
    ]
    .into_iter()
    .filter(|(_, on)| !on)
    .map(|(name, _)| name)
    .collect();
    let mut report = Report {
        schema: 1,
        scope: "Read on this machine with Declass's pattern detectors and custom patterns, not its \
                local-model checks or the values a run has already seen; nothing was sent and no model \
                was used. What Declass does with each file is for hybrid mode with the current path rules. \
                Counts only, with overlapping matches counted once: no value is shown. Excluded \
                directories, symlinks and special files are not read.",
        complete: inventory.complete,
        files_scanned: 0,
        totals: BTreeMap::new(),
        exposed: Vec::new(),
        kept_by_rule: 0,
        not_scanned: NotScanned::default(),
        detectors_off,
        excluded_directories: privacy::SKIPPED,
    };
    let (blocked, files): (Vec<_>, Vec<_>) = inventory
        .files
        .into_iter()
        .partition(|f| f.disposition == "blocked");
    report.not_scanned.not_followed = blocked.len();
    let outcomes = read_all(ws, &files, detectors, &custom);
    for (file, outcome) in files.into_iter().zip(outcomes) {
        let found = match outcome {
            Outcome::TooLarge => {
                report.not_scanned.too_large += 1;
                continue;
            }
            Outcome::Binary => {
                report.not_scanned.binary += 1;
                continue;
            }
            Outcome::Unreadable => {
                report.not_scanned.unreadable += 1;
                continue;
            }
            Outcome::Read(found) => found,
        };
        report.files_scanned += 1;
        if found.is_empty() {
            if matches!(file.disposition, "sensitive" | "sealed" | "interface-only") {
                report.kept_by_rule += 1;
            }
            continue;
        }
        let found: BTreeMap<&'static str, usize> =
            found.into_iter().map(|(k, n)| (k.tag(), n)).collect();
        for (tag, n) in &found {
            *report.totals.entry(tag).or_insert(0) += n;
        }
        report.exposed.push(Exposed {
            path: file.path,
            found,
            declass: declass_action(file.disposition),
            disposition: file.disposition,
            rule: file.rule,
        });
    }
    // Most values first, then by path.
    report.exposed.sort_by(|a, b| {
        let total = |e: &Exposed| e.found.values().sum::<usize>();
        total(b).cmp(&total(a)).then_with(|| a.path.cmp(&b.path))
    });
    Ok(report)
}

/// The kinds found, secrets first and then by count; beyond `limit` kinds the
/// rest are summed.
fn describe(found: &BTreeMap<&'static str, usize>, limit: usize) -> String {
    let mut kinds: Vec<(Kind, usize)> = found
        .iter()
        .filter_map(|(t, n)| tag_kind(t).map(|k| (k, *n)))
        .collect();
    kinds.sort_by_key(|(k, n)| (*k != Kind::Secret, std::cmp::Reverse(*n), *k));
    let mut parts: Vec<String> = kinds
        .iter()
        .take(limit)
        .map(|(k, n)| kind_name(*k, *n))
        .collect();
    let rest: usize = kinds.iter().skip(limit).map(|(_, n)| n).sum();
    if rest > 0 {
        parts.push(format!(
            "{rest} other {}",
            if rest == 1 { "value" } else { "values" }
        ));
    }
    parts.join(", ")
}

impl Report {
    pub(crate) fn render(&self, all: bool) -> String {
        let shown = if all { usize::MAX } else { 25 };
        let mut lines = vec![format!(
            "Exposure · {} files read on this machine · nothing was sent",
            self.files_scanned
        )];
        let n = &self.not_scanned;
        let unread = n.too_large + n.binary + n.unreadable + n.not_followed;
        if self.exposed.is_empty() {
            lines.push(String::new());
            if self.files_scanned == 0 && unread == 0 {
                lines.push(
                    "No files to read here: the directory is empty, or holds only directories that are not searched."
                        .into(),
                );
            } else if self.detectors_off.is_empty() {
                lines.push(
                    "No secrets or personal data found by Declass's pattern detectors.".into(),
                );
            } else {
                lines.push(format!(
                    "Nothing found, but these detectors are turned off and were not run: {}.",
                    self.detectors_off.join(", ")
                ));
            }
        } else {
            let files = |n: usize| if n == 1 { "file" } else { "files" };
            lines.push(String::new());
            lines.push(format!(
                "Without a privacy boundary, a coding agent could send {} in {} {} to a cloud model.",
                describe(&self.totals, 4),
                self.exposed.len(),
                files(self.exposed.len())
            ));
            let with = |d: &[&str]| {
                self.exposed
                    .iter()
                    .filter(|e| d.contains(&e.disposition))
                    .count()
            };
            let mut parts = Vec::new();
            for (n, what) in [
                (with(&["sensitive"]), "read only by your local model"),
                (
                    with(&["content-checks"]),
                    "with values replaced by placeholders",
                ),
                (
                    with(&["interface-only", "sealed"]),
                    "limited to interfaces or sealed",
                ),
                (with(&["unknown"]), "of unknown classification"),
            ] {
                if n > 0 {
                    parts.push(format!("{n} {}", what));
                }
            }
            lines.push(format!(
                "With Declass in hybrid mode: {}.",
                parts.join(", ")
            ));
            if !self.detectors_off.is_empty() {
                lines.push(format!(
                    "Turned off and not run: {}.",
                    self.detectors_off.join(", ")
                ));
            }
            lines.push(String::new());
            for e in self.exposed.iter().take(shown) {
                lines.push(format!("  {}", privacy::shown(&e.path)));
                lines.push(format!("    found:   {}", describe(&e.found, usize::MAX)));
                lines.push(format!(
                    "    declass: {} ({})",
                    e.declass,
                    privacy::shown(&e.rule)
                ));
            }
            if self.exposed.len() > shown {
                lines.push(format!(
                    "  … and {} more (--all lists them)",
                    self.exposed.len() - shown
                ));
            }
        }
        if self.kept_by_rule > 0 {
            lines.push(String::new());
            lines.push(format!(
                "{} more {} with no detected values {} covered by path rules (local only, interfaces only or sealed).",
                self.kept_by_rule,
                if self.kept_by_rule == 1 {
                    "file"
                } else {
                    "files"
                },
                if self.kept_by_rule == 1 { "is" } else { "are" }
            ));
        }
        if unread > 0 {
            lines.push(format!(
                "Not read: {} over {} MiB, {} binary or UTF-16, {} unreadable, {} symlinks or special files.",
                n.too_large,
                MAX_BYTES / (1024 * 1024),
                n.binary,
                n.unreadable,
                n.not_followed
            ));
        }
        lines.push(format!(
            "Not searched: {}.",
            self.excluded_directories.join(", ")
        ));
        if !self.complete {
            lines.push(
                "Attention: inventory incomplete (entry or depth limit, unreadable directory or non-UTF8 name)."
                    .into(),
            );
        }
        lines.push(String::new());
        lines.push(
            "Values are never shown. Pattern detectors find known formats; Declass's local-model checks are not part of this report. A clean report does not prove a file holds nothing private."
                .into(),
        );
        lines.push(
            "Path rules: declass privacy · protect more: [sensitivity] protected_paths in .declass/config.toml"
                .into(),
        );
        declass_tui::term::safe(&lines.join("\n"))
    }

    fn code(&self) -> i32 {
        if !self.complete {
            2
        } else if !self.exposed.is_empty() {
            1
        } else {
            0
        }
    }
}

pub(crate) fn run(ws: &Path, args: Args, cfg: &Config) -> Result<i32> {
    let report = collect(ws, cfg)?;
    println!(
        "{}",
        if args.json {
            serde_json::to_string_pretty(&report)?
        } else {
            report.render(args.all)
        }
    );
    Ok(report.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path, text: &str) -> Config {
        let owner = root.join("owner.toml");
        std::fs::write(&owner, text).unwrap();
        Config::load(&owner, None).unwrap()
    }

    const KEY: &str = concat!("sk_", "live_Rx7KpW2mNq9TzL4vB8cH3dYsJf");
    const EMAIL: &str = "jordan.reyes@corpmail.co";

    fn workspace() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir_all(ws.join("data")).unwrap();
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(ws.join(".env"), format!("STRIPE_SECRET_KEY={KEY}\n")).unwrap();
        std::fs::write(ws.join("data/customers.csv"), format!("email\n{EMAIL}\n")).unwrap();
        std::fs::write(
            ws.join("src/settings.py"),
            format!("STRIPE_KEY = \"{KEY}\"\n"),
        )
        .unwrap();
        std::fs::write(
            ws.join("src/clean.py"),
            "def add(a, b):\n    return a + b\n",
        )
        .unwrap();
        std::fs::write(ws.join("data/blank.csv"), "id\n").unwrap();
        std::fs::write(ws.join("image.bin"), b"\x89PNG\0\0\0secret").unwrap();
        std::os::unix::fs::symlink(ws.join(".env"), ws.join("env-link")).unwrap();
        temp
    }

    #[test]
    fn values_are_counted_never_reported_and_each_file_says_what_declass_does() {
        let temp = workspace();
        let ws = temp.path().join("ws");
        let cfg = config(temp.path(), "");
        let r = collect(&ws, &cfg).unwrap();
        let file = |p: &str| r.exposed.iter().find(|e| e.path == p).unwrap();
        assert_eq!(file(".env").disposition, "sensitive");
        assert_eq!(file(".env").found.get("secret"), Some(&1));
        assert_eq!(file("data/customers.csv").found.get("email"), Some(&1));
        assert_eq!(file("src/settings.py").disposition, "content-checks");
        assert_eq!(
            file("src/settings.py").declass,
            "values replaced with placeholders before any request"
        );
        assert!(r.exposed.iter().all(|e| e.path != "src/clean.py"));
        assert_eq!(r.kept_by_rule, 1, "data/blank.csv");
        assert_eq!(r.not_scanned.binary, 1);
        assert_eq!(r.not_scanned.not_followed, 1, "the symlink");
        assert!(
            r.render(true)
                .contains("2 read only by your local model, 1 with values replaced")
        );
        assert!(r.complete);
        assert_eq!(r.code(), 1);
        let json = serde_json::to_string(&r).unwrap();
        let text = r.render(true);
        for value in [KEY, EMAIL, "4eC39", "jordan"] {
            assert!(!json.contains(value), "{value} in JSON");
            assert!(!text.contains(value), "{value} in text");
        }
        assert!(!ws.join(".declass").exists(), "no run state is created");
    }

    #[test]
    fn a_url_password_that_looks_like_an_email_counts_as_a_secret() {
        let found = count(
            "DATABASE_URL=postgres://shop:Tr0ub4dorPass@db.internal:5432/shop\n",
            ".env",
            Detectors::default(),
            &CustomPatterns::default(),
        );
        assert_eq!(found.get(&Kind::Secret), Some(&1));
        assert_eq!(found.get(&Kind::Email), None);
    }

    #[test]
    fn a_clean_workspace_exits_zero_and_custom_patterns_count() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir(&ws).unwrap();
        std::fs::write(ws.join("notes.txt"), "ticket ACME-000123 is open\n").unwrap();
        let clean = collect(&ws, &config(temp.path(), "")).unwrap();
        assert!(clean.exposed.is_empty());
        assert_eq!(clean.code(), 0);
        assert!(
            clean
                .render(false)
                .contains("No secrets or personal data found")
        );
        // Nothing to read is not the same as nothing found.
        let empty = temp.path().join("empty");
        std::fs::create_dir_all(empty.join("node_modules")).unwrap();
        let none = collect(&empty, &config(temp.path(), "")).unwrap();
        assert_eq!(none.code(), 0);
        assert!(
            none.render(false).contains("No files to read here"),
            "{}",
            none.render(false)
        );
        let custom = collect(
            &ws,
            &config(
                temp.path(),
                "[sensitivity]\ncustom_patterns = ['ACME-[0-9]{6}']\n",
            ),
        )
        .unwrap();
        assert_eq!(custom.totals.get("data"), Some(&1));
        std::fs::write(ws.join("key.txt"), format!("API_TOKEN={KEY}\n")).unwrap();
        let off = collect(
            &ws,
            &config(
                temp.path(),
                "[sensitivity]\ndetect_secrets = false\ndetect_entropy = false\n",
            ),
        )
        .unwrap();
        assert!(off.exposed.is_empty());
        assert!(
            off.render(false)
                .contains("turned off and were not run: secrets")
        );
    }

    #[test]
    fn names_are_escaped_and_oversized_files_are_listed_not_read() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir(&ws).unwrap();
        std::fs::write(ws.join("x\u{1b}[2J.env"), format!("API_TOKEN={KEY}\n")).unwrap();
        let big = format!("TOKEN={KEY}\n").repeat((MAX_BYTES as usize / 20) + 1);
        std::fs::write(ws.join("big.log"), big).unwrap();
        // Quotes are shown as they are; a line break or tab in a name is escaped.
        for name in ["it's \"quoted\".txt", "tab\there.txt", "two\nlines.txt"] {
            std::fs::write(ws.join(name), format!("token: {KEY}\n")).unwrap();
        }
        let r = collect(&ws, &config(temp.path(), "")).unwrap();
        assert_eq!(r.not_scanned.too_large, 1);
        let text = r.render(true);
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("\n  it's \"quoted\".txt\n"), "{text}");
        assert!(text.contains("\n  tab\\there.txt\n"), "{text}");
        assert!(text.contains("\n  two\\nlines.txt\n"), "{text}");
    }
}
