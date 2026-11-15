// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline exposure report: what a coding agent that reads this workspace could
//! send to a cloud model, and what Declass does with each file instead.
//!
//! Files are read on this machine with the boundary's own detectors; nothing is
//! sent, no model or tool server is started and no run state is created. The
//! report holds paths, counts by kind and positions, never a matched value or
//! anything computed from one. `--history` also reads earlier file versions
//! from git ([`history`]); `--sarif` writes the report for code scanning
//! ([`sarif`]).
//!
//! The walk streams: one thread lists the workspace without following links
//! and hands each directory's files, with the directory's open handle, to
//! workers on every core, so memory holds the files with findings, not the
//! whole tree.
use crate::{Mode, policy, privacy};
use anyhow::{Context, Result};
use declass_boundary::detect::{self, CustomPatterns, Detectors, Kind};
use declass_config::Config;
use rustix::fs::{FileType, Mode as FsMode, OFlags};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::hash::{BuildHasher, RandomState};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

mod history;
mod sarif;

/// Larger files are listed as not scanned rather than read in part.
const MAX_BYTES: u64 = 2 * 1024 * 1024;
/// A NUL byte in the first block marks a binary file.
const BINARY_PROBE: usize = 8192;
/// What the walk may visit: large repositories fit, a runaway tree is
/// reported incomplete.
const LIMITS: privacy::Limits = privacy::Limits {
    entries: 1_000_000,
    depth: 48,
};
/// Positions kept per file and kind; the count covers every value.
const POSITIONS: usize = 10;
/// Files a worker takes at a time.
const CHUNK: usize = 64;
/// Values remembered from the working tree for `--history` (keyed hashes
/// in memory only); past this, history may count a value the tree also holds.
const MAX_REMEMBERED: usize = 4_000_000;

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Print the report as JSON.
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    /// Print the report as SARIF 2.1.0, for GitHub code scanning and other
    /// SARIF tools: one result per file and kind of value, with positions,
    /// never a value.
    #[arg(long)]
    sarif: bool,
    /// Write the report to this file; with --json or --sarif the text report
    /// is printed as well.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// List every file with findings (by default the first 25 are shown).
    #[arg(long)]
    all: bool,
    /// Exit 1 only for a finding at this level or above. To accept a file's
    /// findings, keep it local with [sensitivity] protected_paths: they become
    /// notes.
    #[arg(long, value_enum, value_name = "LEVEL", default_value_t = FailOn::Note)]
    fail_on: FailOn,
    /// Also read earlier file versions: blobs reachable from the repository's
    /// refs that are not in the working tree. Counts values the working tree
    /// does not hold.
    #[arg(long)]
    history: bool,
    /// With --history: read at most this many blobs.
    #[arg(
        long,
        value_name = "N",
        default_value_t = 100_000,
        requires = "history"
    )]
    history_max_blobs: usize,
    /// With --history: read at most this many MiB of blobs.
    #[arg(long, value_name = "MIB", default_value_t = 1024, requires = "history")]
    history_max_mib: u64,
}

/// How much a finding matters, as code scanning shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Level {
    /// A value in a file that path rules keep from the cloud model.
    Note,
    /// Personal data or a custom-pattern match in a file the cloud model reads.
    Warning,
    /// A secret in a file the cloud model reads.
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Note => "note",
            Level::Warning => "warning",
            Level::Error => "error",
        }
    }
}

/// The level from which findings fail (`--fail-on`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FailOn {
    /// Any finding (the default).
    Note,
    /// Any finding in a file the cloud model reads.
    Warning,
    /// A secret in a file the cloud model reads.
    Error,
    /// No finding; an incomplete report still exits 2.
    Never,
}

impl FailOn {
    fn fails(self, level: Level) -> bool {
        match self {
            FailOn::Note => true,
            FailOn::Warning => level >= Level::Warning,
            FailOn::Error => level >= Level::Error,
            FailOn::Never => false,
        }
    }
}

/// A finding's level: a file the cloud model never reads (sensitive or
/// sealed) holds notes; elsewhere a secret is an error and anything else a
/// warning. Interface-only files count as read: their public constants are
/// shown.
fn level(kind: Kind, disposition: &str) -> Level {
    if matches!(disposition, "sensitive" | "sealed") {
        Level::Note
    } else if kind == Kind::Secret {
        Level::Error
    } else {
        Level::Warning
    }
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
    /// The walk's bounds; reaching one makes the report incomplete.
    limits: Bounds,
    /// Findings at this level or above fail (exit 1).
    fail_on: FailOn,
    /// Files (and history paths) with such a finding.
    failing: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    history: Option<history::History>,
}

#[derive(Serialize)]
struct Bounds {
    entries: usize,
    depth: usize,
    file_bytes: u64,
}

#[derive(Serialize)]
pub(crate) struct Exposed {
    path: String,
    /// Kind tag → values found in this file.
    found: BTreeMap<&'static str, usize>,
    /// Kind tag → where the first values of that kind start (at most 10).
    positions: BTreeMap<&'static str, Vec<Position>>,
    /// The highest level of this file's findings.
    level: Level,
    disposition: &'static str,
    rule: String,
    declass: &'static str,
}

/// A position in a file: 1-based line, and column in characters.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Position {
    line: u32,
    column: u32,
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
        "interface-only" => {
            "the cloud model sees signatures and public constants, not bodies; values replaced with placeholders"
        }
        "sensitive" => "read by your local model, not sent to the cloud model",
        "content-checks" => "values replaced with placeholders before any request",
        _ => "classification unknown; review local state",
    }
}

/// One value: overlapping matches merged, a secret if any of them says so
/// (a URL password also looks like an email address).
struct Value {
    kind: Kind,
    start: usize,
    end: usize,
}

/// The detectors this report runs.
pub(crate) struct Scanner {
    detectors: Detectors,
    custom: CustomPatterns,
}

impl Scanner {
    /// The values in `text`, in order.
    fn values(&self, text: &str, path: &str) -> Vec<Value> {
        let mut all = detect::scan_each_in(text, self.detectors, Some(path));
        all.extend(self.custom.find(text));
        all.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
        let mut out: Vec<Value> = Vec::new();
        for f in all {
            match out.last_mut() {
                Some(v) if f.start < v.end => {
                    v.end = v.end.max(f.end);
                    if f.kind == Kind::Secret {
                        v.kind = Kind::Secret;
                    }
                }
                _ => out.push(Value {
                    kind: f.kind,
                    start: f.start,
                    end: f.end,
                }),
            }
        }
        out
    }
}

/// Counts by kind, and where the first values of each kind start.
fn locate(text: &str, values: &[Value]) -> BTreeMap<Kind, (usize, Vec<Position>)> {
    let bytes = text.as_bytes();
    let mut out: BTreeMap<Kind, (usize, Vec<Position>)> = BTreeMap::new();
    let (mut line, mut line_start, mut at) = (1u32, 0usize, 0usize);
    for v in values {
        let (count, positions) = out.entry(v.kind).or_default();
        *count += 1;
        if positions.len() >= POSITIONS || v.start < at || v.start > bytes.len() {
            continue;
        }
        for (i, b) in bytes[at..v.start].iter().enumerate() {
            if *b == b'\n' {
                line = line.saturating_add(1);
                line_start = at + i + 1;
            }
        }
        at = v.start;
        // Characters, counted by the bytes that start one.
        let chars = bytes[line_start..v.start]
            .iter()
            .filter(|b| (**b & 0xC0) != 0x80)
            .count();
        positions.push(Position {
            line,
            column: u32::try_from(chars + 1).unwrap_or(u32::MAX),
        });
    }
    out
}

/// What `--history` needs to know of the working tree: keyed hashes of the
/// values it holds, so history counts only values it does not, and the git
/// ids of its files, so their blobs are not read again. In memory only: never
/// written or shown, and the key is new in every process.
pub(crate) struct Remembered {
    hasher: RandomState,
    seen: Mutex<HashSet<u64>>,
    full: AtomicBool,
    /// How the repository names blobs (`None`: no repository).
    format: Option<history::Format>,
    blobs: Mutex<HashSet<u128>>,
}

impl Remembered {
    fn new(format: Option<history::Format>) -> Self {
        Self {
            hasher: RandomState::new(),
            seen: Mutex::new(HashSet::new()),
            full: AtomicBool::new(false),
            format,
            blobs: Mutex::new(HashSet::new()),
        }
    }

    /// Records the id git would give a file holding `bytes`.
    fn add_blob(&self, bytes: &[u8]) {
        if let Some(format) = self.format {
            let id = format.blob_id(bytes);
            self.blobs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id);
        }
    }

    fn key(&self, value: &str) -> u64 {
        self.hasher.hash_one(value)
    }

    fn add(&self, keys: impl IntoIterator<Item = u64>) {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        for key in keys {
            if seen.len() >= MAX_REMEMBERED {
                self.full.store(true, Ordering::Relaxed);
                return;
            }
            seen.insert(key);
        }
    }

    /// What was remembered, read-only once the working tree is read.
    fn into_seen(self) -> Seen {
        Seen {
            complete: !self.full.into_inner(),
            keys: self
                .seen
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner),
            hasher: self.hasher,
            blobs: self
                .blobs
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner),
        }
    }
}

/// The working tree's values and blob ids, as [`Remembered`] kept them.
pub(crate) struct Seen {
    hasher: RandomState,
    keys: HashSet<u64>,
    /// Whether every working-tree value was remembered.
    complete: bool,
    blobs: HashSet<u128>,
}

impl Seen {
    fn key(&self, value: &str) -> u64 {
        self.hasher.hash_one(value)
    }

    fn contains(&self, key: u64) -> bool {
        self.keys.contains(&key)
    }

    /// Whether a working-tree file holds exactly this blob.
    fn has_blob(&self, id: u128) -> bool {
        self.blobs.contains(&id)
    }
}

enum Outcome {
    TooLarge,
    /// The bytes of a binary file (for its blob id), not scanned.
    Binary(Vec<u8>),
    Unreadable,
    Read(Vec<u8>),
}

/// Reads a regular file in the directory `dir` without following a link
/// (a file replaced since the walk listed it is reported unreadable).
fn read_at(dir: &OwnedFd, name: &OsStr) -> Outcome {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let Ok(fd) = rustix::fs::openat(dir, name, flags, FsMode::empty()) else {
        return Outcome::Unreadable;
    };
    let Ok(stat) = rustix::fs::fstat(&fd) else {
        return Outcome::Unreadable;
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Outcome::Unreadable;
    }
    let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
    if size > MAX_BYTES {
        return Outcome::TooLarge;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    if std::fs::File::from(fd)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return Outcome::Unreadable;
    }
    if bytes.len() as u64 > MAX_BYTES {
        Outcome::TooLarge
    } else if bytes[..bytes.len().min(BINARY_PROBE)].contains(&0) {
        Outcome::Binary(bytes)
    } else {
        Outcome::Read(bytes)
    }
}

/// A file the walk listed.
struct Listed {
    name: OsString,
    path: String,
}

/// Files of one directory, for one worker.
struct Chunk {
    dir: Arc<OwnedFd>,
    files: Vec<Listed>,
}

/// What every worker shares.
struct Job<'a> {
    classifier: &'a privacy::Classifier<'a>,
    scanner: &'a Scanner,
    remember: Option<&'a Remembered>,
}

/// What one worker found.
#[derive(Default)]
struct Part {
    files_scanned: usize,
    kept_by_rule: usize,
    not_scanned: NotScanned,
    exposed: Vec<Exposed>,
    /// A file's scan failed unexpectedly; it is counted unreadable.
    failed: bool,
}

impl Part {
    fn add(&mut self, job: &Job<'_>, dir: &OwnedFd, file: Listed) {
        let Job {
            classifier,
            scanner,
            remember,
        } = job;
        let bytes = match read_at(dir, &file.name) {
            Outcome::TooLarge => return self.not_scanned.too_large += 1,
            Outcome::Binary(bytes) => {
                if let Some(remember) = remember {
                    remember.add_blob(&bytes);
                }
                return self.not_scanned.binary += 1;
            }
            Outcome::Unreadable => return self.not_scanned.unreadable += 1,
            Outcome::Read(bytes) => bytes,
        };
        if let Some(remember) = remember {
            remember.add_blob(&bytes);
        }
        let text = String::from_utf8_lossy(&bytes);
        let values = scanner.values(&text, &file.path);
        let (disposition, rule) = classifier.classify(&file.path);
        if let Some(remember) = remember {
            remember.add(
                values
                    .iter()
                    .filter_map(|v| text.get(v.start..v.end))
                    .map(|value| remember.key(value)),
            );
        }
        self.files_scanned += 1;
        if values.is_empty() {
            if matches!(disposition, "sensitive" | "sealed" | "interface-only") {
                self.kept_by_rule += 1;
            }
            return;
        }
        let located = locate(&text, &values);
        let level = located
            .keys()
            .map(|k| level(*k, disposition))
            .max()
            .unwrap_or(Level::Note);
        self.exposed.push(Exposed {
            found: located.iter().map(|(k, (n, _))| (k.tag(), *n)).collect(),
            positions: located
                .into_iter()
                .map(|(k, (_, p))| (k.tag(), p))
                .collect(),
            level,
            declass: declass_action(disposition),
            disposition,
            rule,
            path: file.path,
        });
    }

    fn merge(&mut self, other: Part) {
        self.files_scanned += other.files_scanned;
        self.kept_by_rule += other.kept_by_rule;
        self.not_scanned.too_large += other.not_scanned.too_large;
        self.not_scanned.binary += other.not_scanned.binary;
        self.not_scanned.unreadable += other.not_scanned.unreadable;
        self.not_scanned.not_followed += other.not_scanned.not_followed;
        self.exposed.extend(other.exposed);
        self.failed |= other.failed;
    }
}

/// Lists the workspace on this thread and reads and scans its files on every
/// available core. Returns what was found and whether the walk was complete.
fn scan_tree(
    ws: &Path,
    classifier: &privacy::Classifier<'_>,
    scanner: &Scanner,
    remember: Option<&Remembered>,
) -> Result<(Part, bool)> {
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(16);
    let job = Job {
        classifier,
        scanner,
        remember,
    };
    // Bounded, so open directory handles and listed files stay few.
    let (tx, rx) = std::sync::mpsc::sync_channel::<Chunk>(workers * 2);
    let rx = Mutex::new(rx);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut part = Part::default();
                    loop {
                        let next = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                        let Ok(chunk) = next else { break };
                        for file in chunk.files {
                            // A file whose scan panics is counted unreadable;
                            // the worker goes on with the rest.
                            let scanned =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    let mut one = Part::default();
                                    one.add(&job, &chunk.dir, file);
                                    one
                                }));
                            match scanned {
                                Ok(one) => part.merge(one),
                                Err(_) => {
                                    part.not_scanned.unreadable += 1;
                                    part.failed = true;
                                }
                            }
                        }
                    }
                    part
                })
            })
            .collect();
        let mut pending: Option<Chunk> = None;
        let mut not_followed = 0;
        let walked = privacy::walk(ws, LIMITS, &mut |entry| match entry {
            privacy::Entry::Other { .. } => not_followed += 1,
            privacy::Entry::File { path, name, dir } => {
                if pending
                    .as_ref()
                    .is_some_and(|c| !Arc::ptr_eq(&c.dir, dir) || c.files.len() >= CHUNK)
                    && let Some(full) = pending.take()
                {
                    // Workers outlive the walk, so a send only waits.
                    let _ = tx.send(full);
                }
                pending
                    .get_or_insert_with(|| Chunk {
                        dir: Arc::clone(dir),
                        files: Vec::with_capacity(CHUNK),
                    })
                    .files
                    .push(Listed {
                        name: name.to_owned(),
                        path: path.to_owned(),
                    });
            }
        });
        if let Some(last) = pending.take() {
            let _ = tx.send(last);
        }
        drop(tx);
        let mut all = Part::default();
        all.not_scanned.not_followed = not_followed;
        for handle in handles {
            match handle.join() {
                Ok(part) => all.merge(part),
                Err(_) => all.failed = true,
            }
        }
        let complete = walked?;
        Ok((all, complete))
    })
}

/// What `collect` reports beyond the working tree.
pub(crate) struct Options {
    pub(crate) fail_on: FailOn,
    pub(crate) history: Option<history::Limits>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            fail_on: FailOn::Note,
            history: None,
        }
    }
}

pub(crate) fn collect(ws: &Path, cfg: &Config, options: &Options) -> Result<Report> {
    let p = policy(cfg)?;
    let scanner = Scanner {
        detectors: Detectors {
            secrets: p.detect_secrets,
            pii: p.detect_pii,
            entropy: p.detect_entropy,
        },
        custom: CustomPatterns::compile(&p.custom_patterns).map_err(anyhow::Error::msg)?,
    };
    let detectors_off = [
        ("secrets", scanner.detectors.secrets),
        ("personal data", scanner.detectors.pii),
        ("high-entropy strings", scanner.detectors.entropy),
    ]
    .into_iter()
    .filter(|(_, on)| !on)
    .map(|(name, _)| name)
    .collect();
    let classifier = privacy::Classifier::new(ws, &p, Mode::Hybrid);
    let remember = options
        .history
        .is_some()
        .then(|| Remembered::new(history::object_format(ws)));
    let (tree, walked) = scan_tree(ws, &classifier, &scanner, remember.as_ref())?;
    let history = match (options.history, remember) {
        (Some(limits), Some(remember)) => Some(history::scan(
            ws,
            &classifier,
            &scanner,
            &remember.into_seen(),
            limits,
        )),
        _ => None,
    };
    let mut report = Report {
        schema: 2,
        scope: "Read on this machine with Declass's pattern detectors and custom patterns, not its \
                local-model checks or the values a run has already seen; nothing was sent and no model \
                was used. What Declass does with each file is for hybrid mode with the current path rules. \
                Counts and positions only, with overlapping matches counted once: no value is shown. \
                Excluded directories, symlinks and special files are not read.",
        complete: walked
            && classifier.derived_known()
            && !tree.failed
            && history.as_ref().is_none_or(|h| h.complete),
        files_scanned: tree.files_scanned,
        totals: BTreeMap::new(),
        exposed: tree.exposed,
        kept_by_rule: tree.kept_by_rule,
        not_scanned: tree.not_scanned,
        detectors_off,
        excluded_directories: privacy::SKIPPED,
        limits: Bounds {
            entries: LIMITS.entries,
            depth: LIMITS.depth,
            file_bytes: MAX_BYTES,
        },
        fail_on: options.fail_on,
        failing: 0,
        history,
    };
    for e in &report.exposed {
        for (tag, n) in &e.found {
            *report.totals.entry(tag).or_insert(0) += n;
        }
    }
    // Most values first, then by path.
    report.exposed.sort_by(|a, b| {
        let total = |e: &Exposed| e.found.values().sum::<usize>();
        total(b).cmp(&total(a)).then_with(|| a.path.cmp(&b.path))
    });
    let history_levels = report
        .history
        .iter()
        .flat_map(|h| h.exposed.iter().map(|e| e.level));
    report.failing = report
        .exposed
        .iter()
        .map(|e| e.level)
        .chain(history_levels)
        .filter(|l| options.fail_on.fails(*l))
        .count();
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
        if let Some(history) = &self.history {
            lines.push(String::new());
            history.render(&mut lines, shown);
        }
        if !self.complete {
            lines.push(format!(
                "Attention: incomplete (more than {} entries or {} directory levels, an unreadable directory, a non-UTF8 name, unreadable derived classifications{}).",
                self.limits.entries,
                self.limits.depth,
                if self.history.is_some() {
                    ", or git history not fully read"
                } else {
                    ""
                }
            ));
        }
        if self.fail_on != FailOn::Note {
            lines.push(match self.fail_on {
                FailOn::Never => "Findings do not fail (--fail-on never).".into(),
                level => format!(
                    "{} {} at or above --fail-on {} ({}).",
                    self.failing,
                    if self.failing == 1 { "file" } else { "files" },
                    match level {
                        FailOn::Error => "error",
                        _ => "warning",
                    },
                    match level {
                        FailOn::Error => "secrets in files the cloud model reads",
                        _ => "values in files the cloud model reads",
                    }
                ),
            });
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
        } else if self.failing > 0 {
            1
        } else {
            0
        }
    }
}

pub(crate) fn run(ws: &Path, args: Args, cfg: &Config) -> Result<i32> {
    let options = Options {
        fail_on: args.fail_on,
        history: args.history.then(|| history::Limits {
            blobs: args.history_max_blobs,
            bytes: args.history_max_mib.saturating_mul(1024 * 1024),
        }),
    };
    let report = collect(ws, cfg, &options)?;
    let text = report.render(args.all);
    let out = if args.sarif {
        serde_json::to_string_pretty(&sarif::log(&report, env!("CARGO_PKG_VERSION")))?
    } else if args.json {
        serde_json::to_string_pretty(&report)?
    } else {
        text.clone()
    };
    match &args.output {
        Some(path) => {
            std::fs::write(path, format!("{out}\n"))
                .with_context(|| format!("writing the report to {}", path.display()))?;
            if args.json || args.sarif {
                println!("{text}");
            }
        }
        None => println!("{out}"),
    }
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

    fn report(ws: &Path, cfg: &Config) -> Report {
        collect(ws, cfg, &Options::default()).unwrap()
    }

    fn scanner() -> Scanner {
        Scanner {
            detectors: Detectors::default(),
            custom: CustomPatterns::default(),
        }
    }

    fn count(text: &str, path: &str) -> BTreeMap<Kind, usize> {
        locate(text, &scanner().values(text, path))
            .into_iter()
            .map(|(k, (n, _))| (k, n))
            .collect()
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
        let r = report(&ws, &cfg);
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
        );
        assert_eq!(found.get(&Kind::Secret), Some(&1));
        assert_eq!(found.get(&Kind::Email), None);
    }

    #[test]
    fn positions_are_lines_and_character_columns_of_the_first_values() {
        let text = format!("a\nxx é {KEY}\n\n{EMAIL} and {EMAIL}\n");
        let located = locate(&text, &scanner().values(&text, "notes.txt"));
        assert_eq!(located[&Kind::Secret].0, 1);
        assert_eq!(
            located[&Kind::Secret].1,
            [Position { line: 2, column: 6 }],
            "é is one character"
        );
        assert_eq!(located[&Kind::Email].0, 2);
        assert_eq!(
            located[&Kind::Email].1,
            [
                Position { line: 4, column: 1 },
                Position {
                    line: 4,
                    column: EMAIL.len() as u32 + 6
                }
            ]
        );
        let many = format!("{EMAIL}\n").repeat(POSITIONS + 5);
        let located = locate(&many, &scanner().values(&many, "list.txt"));
        assert_eq!(located[&Kind::Email].0, POSITIONS + 5, "every value counts");
        assert_eq!(
            located[&Kind::Email].1.len(),
            POSITIONS,
            "positions are capped"
        );
        assert_eq!(
            located[&Kind::Email].1[POSITIONS - 1].line,
            POSITIONS as u32
        );
    }

    #[test]
    fn a_clean_workspace_exits_zero_and_custom_patterns_count() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir(&ws).unwrap();
        std::fs::write(ws.join("notes.txt"), "ticket ACME-000123 is open\n").unwrap();
        let clean = report(&ws, &config(temp.path(), ""));
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
        let none = report(&empty, &config(temp.path(), ""));
        assert_eq!(none.code(), 0);
        assert!(
            none.render(false).contains("No files to read here"),
            "{}",
            none.render(false)
        );
        let custom = report(
            &ws,
            &config(
                temp.path(),
                "[sensitivity]\ncustom_patterns = ['ACME-[0-9]{6}']\n",
            ),
        );
        assert_eq!(custom.totals.get("data"), Some(&1));
        std::fs::write(ws.join("key.txt"), format!("API_TOKEN={KEY}\n")).unwrap();
        let off = report(
            &ws,
            &config(
                temp.path(),
                "[sensitivity]\ndetect_secrets = false\ndetect_entropy = false\n",
            ),
        );
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
        let r = report(&ws, &config(temp.path(), ""));
        assert_eq!(r.not_scanned.too_large, 1);
        let text = r.render(true);
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("\n  it's \"quoted\".txt\n"), "{text}");
        assert!(text.contains("\n  tab\\there.txt\n"), "{text}");
        assert!(text.contains("\n  two\\nlines.txt\n"), "{text}");
    }

    #[test]
    fn a_file_replaced_after_the_walk_is_unreadable_never_followed() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("plain.txt"), "hello\n").unwrap();
        std::os::unix::fs::symlink("/etc/hosts", temp.path().join("link")).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(temp.path().join("pipe"))
                .status()
                .unwrap()
                .success()
        );
        let dir = rustix::fs::open(
            temp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            FsMode::empty(),
        )
        .unwrap();
        assert!(
            matches!(read_at(&dir, OsStr::new("plain.txt")), Outcome::Read(b) if b == b"hello\n")
        );
        for name in ["link", "pipe", "gone"] {
            assert!(
                matches!(read_at(&dir, OsStr::new(name)), Outcome::Unreadable),
                "{name}"
            );
        }
    }

    #[test]
    fn levels_follow_path_rules_and_fail_on_sets_what_fails() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir_all(ws.join("tests/fixtures")).unwrap();
        std::fs::create_dir_all(ws.join("docs")).unwrap();
        std::fs::create_dir_all(ws.join("lib")).unwrap();
        std::fs::write(ws.join(".env"), format!("API_TOKEN={KEY}\n")).unwrap();
        std::fs::write(
            ws.join("tests/fixtures/keys.txt"),
            format!("token: {KEY}\n"),
        )
        .unwrap();
        std::fs::write(ws.join("docs/team.md"), format!("Ask {EMAIL}\n")).unwrap();
        std::fs::write(ws.join("lib/client.py"), format!("API_KEY = \"{KEY}\"\n")).unwrap();
        let run = |cfg: &str, fail_on| {
            collect(
                &ws,
                &config(temp.path(), cfg),
                &Options {
                    fail_on,
                    history: None,
                },
            )
            .unwrap()
        };
        let level_of = |r: &Report, p: &str| r.exposed.iter().find(|e| e.path == p).unwrap().level;
        let interface = "[ip]\ninterface_only = ['lib/**']\n";
        let r = run(interface, FailOn::Note);
        assert_eq!(level_of(&r, ".env"), Level::Note, "sensitive: kept local");
        assert_eq!(level_of(&r, "tests/fixtures/keys.txt"), Level::Error);
        assert_eq!(level_of(&r, "docs/team.md"), Level::Warning);
        assert_eq!(
            level_of(&r, "lib/client.py"),
            Level::Error,
            "an interface-only file's public constants are shown"
        );
        assert_eq!((r.failing, r.code()), (4, 1));
        for (fail_on, failing, code) in [
            (FailOn::Warning, 3, 1),
            (FailOn::Error, 2, 1),
            (FailOn::Never, 0, 0),
        ] {
            let r = run(interface, fail_on);
            assert_eq!((r.failing, r.code()), (failing, code), "{fail_on:?}");
            assert_eq!(r.exposed.len(), 4, "every file is listed whatever fails");
        }
        assert!(
            run("", FailOn::Error)
                .render(false)
                .contains("2 files at or above --fail-on error")
        );
        // Accepting known findings: keep those files local.
        let accept = "[sensitivity]\nprotected_paths = ['tests/fixtures/**', 'lib/**']\n";
        let accepted = run(accept, FailOn::Warning);
        assert_eq!(level_of(&accepted, "tests/fixtures/keys.txt"), Level::Note);
        assert_eq!(
            (accepted.failing, accepted.code()),
            (1, 1),
            "docs/team.md still fails"
        );
        let accepted = run(accept, FailOn::Error);
        assert_eq!((accepted.failing, accepted.code()), (0, 0));
        assert_eq!(
            accepted.exposed.len(),
            4,
            "accepted findings are still listed"
        );
    }

    #[test]
    fn sarif_has_a_rule_per_kind_a_result_per_file_and_kind_and_positions() {
        let temp = workspace();
        let ws = temp.path().join("ws");
        std::fs::write(
            ws.join("src/contacts.py"),
            format!("# owner\nOWNER = \"{EMAIL}\"\nBACKUP = \"{EMAIL}\"\n"),
        )
        .unwrap();
        let r = report(&ws, &config(temp.path(), ""));
        let log = sarif::log(&r, "9.8.7");
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        let driver = &run["tool"]["driver"];
        assert_eq!(driver["name"], "declass");
        assert_eq!(driver["version"], "9.8.7");
        assert_eq!(driver["semanticVersion"], "9.8.7");
        let rules = driver["rules"].as_array().unwrap();
        assert_eq!(rules.len(), Kind::ALL.len());
        assert_eq!(run["automationDetails"]["id"], "declass-exposure/");
        let results = run["results"].as_array().unwrap();
        let find = |path: &str, rule: &str| {
            results
                .iter()
                .find(|x| {
                    x["ruleId"] == rule
                        && x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == path
                })
                .unwrap_or_else(|| panic!("{path} {rule}"))
        };
        let contacts = find("src/contacts.py", "exposure/email");
        assert_eq!(contacts["level"], "warning");
        assert_eq!(contacts["properties"]["count"], 2);
        let region = &contacts["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 2);
        assert_eq!(region["startColumn"], 10);
        assert!(region.get("endColumn").is_none() && region.get("snippet").is_none());
        let index = usize::try_from(contacts["ruleIndex"].as_u64().unwrap()).unwrap();
        assert_eq!(rules[index]["id"], "exposure/email");
        let message = contacts["message"]["text"].as_str().unwrap();
        assert!(
            message.contains(
                "2 email addresses a coding agent could send to a cloud model, on lines 2 and 3"
            ),
            "{message}"
        );
        assert_eq!(find(".env", "exposure/secret")["level"], "note");
        assert_eq!(find("src/settings.py", "exposure/secret")["level"], "error");
        let fingerprints: HashSet<&str> = results
            .iter()
            .map(|x| {
                x["partialFingerprints"]["declassExposure/v1"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        assert_eq!(fingerprints.len(), results.len(), "one identity per result");
        assert!(results.iter().all(|x| {
            x["partialFingerprints"]
                .get("primaryLocationLineHash")
                .is_none()
        }));
        // Deterministic: the same tree gives the same log.
        assert_eq!(
            log,
            sarif::log(&report(&ws, &config(temp.path(), "")), "9.8.7")
        );
    }

    /// Runs git in `ws` through declass-git's runner.
    fn git(ws: &Path, args: &[&str]) -> String {
        let out = declass_git::Git::locate()
            .unwrap()
            .run(ws, args, &[], None)
            .unwrap();
        String::from_utf8(out).unwrap().trim().to_owned()
    }

    #[test]
    fn no_value_and_no_encoding_or_hash_of_one_reaches_any_output() {
        use declass_boundary::testing::canary::{Canaries, Options as CanaryOptions};
        use sha2::{Digest, Sha256};
        const REMOVED: &str = concat!("xoxb-", "8817361945-ZqW7rT2nV9kLpX4m");
        const DELETED: &str = concat!("glpat-", "Hk3vR8nQ2wT6yZ1pL9sD");
        let phone = "+1 (415) 555-0199";
        let card = "4539 1488 0343 6467";
        let iban = "DE89 3704 0044 0532 0130 00";
        let ssn = "538-41-2976";
        let ip = "203.0.113.41";
        let custom = "ACME-004217";
        let password = "Tr0ub4dorPass";
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        for dir in ["src", "data", "lib", "docs", "config"] {
            std::fs::create_dir_all(ws.join(dir)).unwrap();
        }
        git(&ws, &["init", "-q"]);
        std::fs::write(
            ws.join("config/old.py"),
            format!("SLACK_TOKEN = \"{REMOVED}\"\n"),
        )
        .unwrap();
        std::fs::write(
            ws.join("config/.env.ci"),
            format!("GITLAB_TOKEN={DELETED}\n"),
        )
        .unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "keys"]);
        let removed_blob = git(&ws, &["rev-parse", "HEAD:config/old.py"]);
        let deleted_blob = git(&ws, &["rev-parse", "HEAD:config/.env.ci"]);
        std::fs::write(ws.join("config/old.py"), "SLACK_TOKEN = None\n").unwrap();
        std::fs::remove_file(ws.join("config/.env.ci")).unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "rotate"]);
        let files = [
            (
                ".env",
                format!(
                    "STRIPE_KEY={KEY}\nDATABASE_URL=postgres://shop:{password}@db.internal:5432/shop\n"
                ),
            ),
            (
                "src/settings.py",
                format!(
                    "API_KEY = \"{KEY}\"\nOWNER = \"{EMAIL}\"\nPHONE = \"{phone}\"\nHOST = \"{ip}\"\n"
                ),
            ),
            (
                "data/customers.csv",
                format!("email,card,iban,ssn\n{EMAIL},{card},{iban},{ssn}\n"),
            ),
            ("lib/billing.py", format!("SIGNING_KEY = \"{KEY}\"\n")),
            ("docs/tickets.md", format!("See {custom} and {EMAIL}.\n")),
        ];
        for (path, body) in &files {
            std::fs::write(ws.join(path), body).unwrap();
        }
        let cfg = config(
            temp.path(),
            "[sensitivity]\ncustom_patterns = ['ACME-[0-9]{6}']\n[ip]\ninterface_only = ['lib/**']\n",
        );
        let r = collect(
            &ws,
            &cfg,
            &Options {
                fail_on: FailOn::Warning,
                history: Some(history::Limits {
                    blobs: 1000,
                    bytes: 1 << 30,
                }),
            },
        )
        .unwrap();
        // The values were found, so their absence below means something.
        for kind in [
            "secret", "email", "phone", "card", "iban", "id", "ip", "data",
        ] {
            assert!(
                r.totals.contains_key(kind),
                "{kind} not found: {:?}",
                r.totals
            );
        }
        assert_eq!(
            r.history.as_ref().unwrap().totals.get("secret"),
            Some(&2),
            "both history keys"
        );
        let canaries = [
            KEY, EMAIL, phone, card, iban, ssn, ip, custom, password, REMOVED, DELETED,
        ];
        let checker = Canaries::with_options(
            canaries,
            CanaryOptions {
                // Shorter digit runs occur in counts and positions by chance.
                digit_min: 8,
                ..CanaryOptions::default()
            },
        );
        let mut hashes: Vec<String> = canaries
            .iter()
            .map(|c| hex::encode(Sha256::digest(c.as_bytes())))
            .collect();
        hashes.extend(
            files
                .iter()
                .map(|(_, body)| hex::encode(Sha256::digest(body.as_bytes()))),
        );
        let blobs = [
            removed_blob,
            deleted_blob,
            git(&ws, &["hash-object", "src/settings.py"]),
            git(&ws, &["hash-object", ".env"]),
        ];
        let outputs = [
            ("JSON", serde_json::to_string_pretty(&r).unwrap()),
            ("text", r.render(true)),
            (
                "SARIF",
                serde_json::to_string_pretty(&sarif::log(&r, env!("CARGO_PKG_VERSION"))).unwrap(),
            ),
        ];
        for (format, output) in &outputs {
            let found = checker.find(output);
            assert!(found.is_empty(), "{format}: {found:?}");
            let lower = output.to_ascii_lowercase();
            for digest in hashes.iter().chain(&blobs) {
                assert!(!lower.contains(digest.as_str()), "{format} holds a digest");
            }
            for (path, body) in &files {
                for line in body.lines() {
                    assert!(!output.contains(line), "{format} holds a line of {path}");
                }
            }
        }
        assert!(!ws.join(".declass").exists());
    }

    /// The git tools withhold an interface-only path's earlier versions whole,
    /// so what only they hold is a note, unlike the file read now.
    #[test]
    fn history_of_interface_only_source_is_a_note() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir_all(ws.join("lib")).unwrap();
        git(&ws, &["init", "-q"]);
        std::fs::write(ws.join("lib/pricing.py"), format!("API_KEY = \"{KEY}\"\n")).unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "one"]);
        std::fs::write(ws.join("lib/pricing.py"), "API_KEY = None\n").unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "two"]);
        let r = collect(
            &ws,
            &config(temp.path(), "[ip]\ninterface_only = ['lib/**']\n"),
            &Options {
                fail_on: FailOn::Warning,
                history: Some(history::Limits {
                    blobs: 1000,
                    bytes: 1 << 30,
                }),
            },
        )
        .unwrap();
        let e = &r.history.as_ref().unwrap().exposed[0];
        assert_eq!((e.path.as_str(), e.level), ("lib/pricing.py", Level::Note));
        assert_eq!(
            e.declass,
            "its earlier versions are withheld from the cloud model"
        );
        assert_eq!((r.failing, r.code()), (0, 0));
        let log = sarif::log(&r, "1.0.0");
        let result = &log["runs"][0]["results"][0];
        assert_eq!(result["properties"]["history"], true);
        assert_eq!(result["level"], "note");
    }

    /// Rules match history as runtime matches paths, both names in Unicode
    /// normalization form C: git stores `données/` composed, and a rule
    /// written decomposed (as a name copied from a decomposed folder is)
    /// names the same folder.
    #[test]
    fn history_under_a_rule_in_the_other_unicode_form_is_kept_local() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        let dir = ws.join("donn\u{e9}es");
        std::fs::create_dir_all(&dir).unwrap();
        git(&ws, &["init", "-q"]);
        std::fs::write(dir.join("app.py"), format!("API_KEY = \"{KEY}\"\n")).unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "one"]);
        std::fs::write(dir.join("app.py"), "API_KEY = None\n").unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "two"]);
        let r = collect(
            &ws,
            &config(
                temp.path(),
                "[sensitivity]\nprotected_paths = ['donne\u{301}es/**']\n",
            ),
            &Options {
                fail_on: FailOn::Warning,
                history: Some(history::Limits {
                    blobs: 1000,
                    bytes: 1 << 30,
                }),
            },
        )
        .unwrap();
        let e = &r.history.as_ref().unwrap().exposed[0];
        assert_eq!(e.level, Level::Note, "{}: {}", e.path, e.rule);
        assert_eq!((r.failing, r.code()), (0, 0));
    }

    #[test]
    fn history_counts_values_only_earlier_versions_hold() {
        const OLD: &str = concat!("ghp_", "Qz8vW3nL5kR2xT7mY4pB9cH6dJ1sF0aGeU2i");
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir_all(ws.join("src")).unwrap();
        git(&ws, &["init", "-q"]);
        std::fs::write(ws.join(".env.production"), format!("API_TOKEN={OLD}\n")).unwrap();
        std::fs::write(ws.join("src/app.py"), format!("KEY = \"{KEY}\"\n")).unwrap();
        std::fs::write(
            ws.join("src/old.py"),
            format!("TOKEN = \"{OLD}\"\nOWNER = \"{EMAIL}\"\n"),
        )
        .unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "one"]);
        std::fs::remove_file(ws.join(".env.production")).unwrap();
        std::fs::write(ws.join("src/old.py"), format!("OWNER = \"{EMAIL}\"\n")).unwrap();
        git(&ws, &["add", "-A"]);
        git(&ws, &["commit", "-q", "-m", "two"]);
        let cfg = config(temp.path(), "");
        let options = |blobs| Options {
            fail_on: FailOn::Note,
            history: Some(history::Limits {
                blobs,
                bytes: 1 << 30,
            }),
        };
        let r = collect(&ws, &cfg, &options(1000)).unwrap();
        let h = r.history.as_ref().unwrap();
        assert!(h.complete && r.complete);
        // The old token counts once, where the cloud model would read it
        // (src/old.py, not the sensitive .env.production); the email is still
        // in the working tree, so history adds nothing.
        assert_eq!(h.totals.get("secret"), Some(&1), "{:?}", h.totals);
        assert_eq!(h.totals.get("email"), None);
        assert_eq!(h.exposed.len(), 1);
        let e = &h.exposed[0];
        assert_eq!((e.path.as_str(), e.versions), ("src/old.py", 1));
        assert!(!e.deleted);
        assert_eq!((e.disposition, e.level), ("content-checks", Level::Error));
        let text = r.render(true);
        assert!(text.contains("Git history · "), "{text}");
        assert!(!text.contains(OLD));
        assert!(!serde_json::to_string(&r).unwrap().contains(OLD));
        // A blob limit leaves the report incomplete.
        let limited = collect(&ws, &cfg, &options(1)).unwrap();
        assert!(!limited.complete);
        assert_eq!(limited.code(), 2);
        // Code scanning is told the run did not see everything.
        let log = sarif::log(&limited, "1.0.0");
        let notice = &log["runs"][0]["invocations"][0]["toolExecutionNotifications"][0];
        assert_eq!(notice["level"], "error");
        assert!(
            notice["message"]["text"]
                .as_str()
                .unwrap()
                .starts_with("The report is incomplete")
        );
        assert_eq!(log["runs"][0]["properties"]["complete"], false);
        // Outside a repository there is no history to read.
        let plain = temp.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        let none = collect(&plain, &cfg, &options(1000)).unwrap();
        assert!(none.complete);
        assert!(none.render(false).contains("not a git repository"));
    }
}
