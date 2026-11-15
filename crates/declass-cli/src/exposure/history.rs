// SPDX-License-Identifier: GPL-3.0-or-later
//! `declass exposure --history`: values that earlier file versions in git
//! hold and the working tree does not, such as a key committed and removed
//! since, or a deleted customer export.
//!
//! Every (blob, path) pair in the history of every ref is listed with
//! `rev-list --all` into `diff-tree --stdin`: each commit's changes against
//! each of its parents, a first commit's files whole. A blob is read once (by
//! id) and reported under the path where Declass would show it most: the
//! first path the cloud model reads, else the first path in the workspace. A
//! blob whose id is a working-tree file's (computed here while the tree was
//! read) is not read again. Contents come from `cat-file --batch` within
//! `Limits` and are scanned on every core. A value counts once, and only when
//! the working tree does not hold it: values are compared by keyed hashes
//! that stay in memory.
//!
//! No git command here reads a file of the working tree (`status`,
//! `diff-files` and `hash-object` do, and a repository's clean filter then
//! runs): git reads only objects, refs and configuration, through
//! declass-git's hardened runner, and never fetches. Each path is classified
//! by its rules now, as Declass's git tools classify history (ARCHITECTURE.md
//! §5.7). Nothing is written and nothing leaves this machine.
use super::{BINARY_PROBE, Level, MAX_BYTES, Scanner, Seen, declass_action, describe, level};
use crate::privacy;
use declass_git::Git;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Mutex, PoisonError};

/// How much history a report reads.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) blobs: usize,
    pub(crate) bytes: u64,
}

#[derive(Serialize)]
pub(crate) struct History {
    scope: &'static str,
    /// False when git could not be run, a name could not be read or a limit
    /// was reached.
    pub(super) complete: bool,
    /// Why no history was read, when none was.
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable: Option<&'static str>,
    limits: LimitsOut,
    /// Blobs in history and not in the working tree (when a limit was
    /// reached: as many as were listed).
    blobs_listed: usize,
    blobs_read: usize,
    bytes_read: u64,
    not_read: NotRead,
    /// False when the working tree held too many values to remember them
    /// all: history may then count a value the working tree also holds.
    working_tree_values_known: bool,
    /// Kind tag → values found in history and not in the working tree.
    pub(super) totals: BTreeMap<&'static str, usize>,
    pub(super) exposed: Vec<Exposed>,
}

#[derive(Serialize)]
struct LimitsOut {
    blobs: usize,
    bytes: u64,
    blob_bytes: u64,
}

#[derive(Serialize, Default)]
struct NotRead {
    too_large: usize,
    /// A NUL byte in the first 8 KiB: binary, or text in UTF-16.
    binary: usize,
    /// Past the blob or byte limit.
    over_limit: usize,
    /// Listed but not in this clone (a partial clone).
    missing: usize,
    /// Names that are not UTF-8: no rule can be proven for them.
    names: usize,
}

#[derive(Serialize)]
pub(crate) struct Exposed {
    pub(super) path: String,
    /// The path is not in the working tree now.
    pub(super) deleted: bool,
    /// Earlier versions of the path holding values the working tree does not.
    pub(super) versions: usize,
    /// Kind tag → values in those versions and not in the working tree, each once.
    pub(super) found: BTreeMap<&'static str, usize>,
    pub(super) level: Level,
    pub(super) disposition: &'static str,
    pub(super) rule: String,
    pub(super) declass: &'static str,
}

/// Git never fetches an object this clone lacks (a partial clone's): it is
/// counted as missing instead. Transports are refused by the runner anyway.
const NO_FETCH: &[(&str, &str)] = &[("GIT_NO_LAZY_FETCH", "1")];

const SCOPE: &str = "Blobs in the history of the repository's refs and not in the working tree, \
each read once on this machine through git, under the path where Declass would show it most; \
values the working tree also holds are not counted again. Each path is classified by its rules \
now, as Declass's git tools classify history.";

/// How git names this repository's objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Sha1,
    Sha256,
}

impl Format {
    /// The first 16 bytes of the id git gives a blob holding `bytes`. Computed
    /// here, never by git (which would run the repository's filters on the
    /// file), and kept in memory only.
    pub(super) fn blob_id(self, bytes: &[u8]) -> u128 {
        let algorithm = match self {
            Format::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            Format::Sha256 => &ring::digest::SHA256,
        };
        let mut digest = ring::digest::Context::new(algorithm);
        digest.update(format!("blob {}\0", bytes.len()).as_bytes());
        digest.update(bytes);
        let mut first = [0u8; 16];
        first.copy_from_slice(&digest.finish().as_ref()[..16]);
        u128::from_be_bytes(first)
    }
}

/// The first 16 bytes of a hex object id, as [`Format::blob_id`] keeps them.
fn id_of(oid: &str) -> Option<u128> {
    u128::from_str_radix(oid.get(..32)?, 16).ok()
}

/// How the repository holding `ws` names its objects; `None` when there is
/// no repository or no git.
pub(super) fn object_format(ws: &Path) -> Option<Format> {
    let git = Git::locate().ok()?;
    if !git.is_repository(ws) {
        return None;
    }
    let out = git
        .run(ws, &["rev-parse", "--show-object-format"], NO_FETCH, None)
        .ok()?;
    // Git before 2.29 knows only SHA-1, and not this option either.
    Some(if out.trim_ascii() == b"sha256" {
        Format::Sha256
    } else {
        Format::Sha1
    })
}

/// Why reading history stopped.
enum Stop {
    /// There is no history to read (complete).
    None(&'static str),
    /// History could not be read (incomplete).
    Failed(&'static str),
}

pub(super) fn scan(
    ws: &Path,
    classifier: &privacy::Classifier<'_>,
    scanner: &Scanner,
    seen: &Seen,
    limits: Limits,
) -> History {
    let mut history = History {
        scope: SCOPE,
        complete: true,
        unavailable: None,
        limits: LimitsOut {
            blobs: limits.blobs,
            bytes: limits.bytes,
            blob_bytes: MAX_BYTES,
        },
        blobs_listed: 0,
        blobs_read: 0,
        bytes_read: 0,
        not_read: NotRead::default(),
        working_tree_values_known: seen.complete,
        totals: BTreeMap::new(),
        exposed: Vec::new(),
    };
    match read(ws, classifier, scanner, seen, limits, &mut history) {
        Ok(()) => {}
        Err(Stop::None(reason)) => history.unavailable = Some(reason),
        Err(Stop::Failed(reason)) => {
            history.unavailable = Some(reason);
            history.complete = false;
        }
    }
    history
}

fn is_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether a path from history is one the working tree's walk would read.
fn walkable(path: &str) -> bool {
    !declass_fs::is_reserved(Path::new(path))
        && !path
            .split('/')
            .any(|part| part.is_empty() || privacy::SKIPPED.contains(&part))
}

/// Stops a child that is no longer read and reaps it.
fn stop(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Feeds `oids` to a `cat-file` child on another thread, so its output can be
/// read meanwhile without either side waiting on the other.
fn feed<'s>(
    scope: &'s std::thread::Scope<'s, '_>,
    child: &mut Child,
    oids: Vec<&'s str>,
) -> Option<std::thread::ScopedJoinHandle<'s, ()>> {
    let mut stdin = child.stdin.take()?;
    Some(scope.spawn(move || {
        let mut input = std::io::BufWriter::new(&mut stdin);
        for oid in oids {
            if writeln!(input, "{oid}").is_err() {
                return;
            }
        }
        let _ = input.flush();
    }))
}

/// A blob to read: within the size and byte limits.
struct Selected<'a> {
    oid: &'a str,
    path: &'a str,
    size: u64,
    read: bool,
}

/// A blob history holds and the working tree does not, with the path it is
/// reported under.
struct Candidate {
    oid: String,
    path: String,
    /// The path is one the cloud model reads (no path rule keeps it local).
    read: bool,
}

fn read(
    ws: &Path,
    classifier: &privacy::Classifier<'_>,
    scanner: &Scanner,
    seen: &Seen,
    limits: Limits,
    history: &mut History,
) -> Result<(), Stop> {
    let git = Git::locate().map_err(|_| Stop::Failed("git is not installed"))?;
    if !git.is_repository(ws) {
        return Err(Stop::None("not a git repository"));
    }
    let prefix = git
        .run(ws, &["rev-parse", "--show-prefix"], NO_FETCH, None)
        .map_err(|_| Stop::Failed("git could not read the repository"))?;
    let prefix = String::from_utf8(prefix)
        .map_err(|_| Stop::Failed("the workspace's name in the repository is not UTF-8"))?;
    let candidates = list(
        &git,
        ws,
        prefix.trim_end_matches('\n'),
        classifier,
        seen,
        limits,
        history,
    )?;

    // Sizes first, so blobs over the size or byte limit are never read.
    let sizes = sizes(&git, ws, &candidates)?;
    let mut selected: Vec<Selected<'_>> = Vec::new();
    let mut budget = limits.bytes;
    for c in &candidates {
        let Some(&size) = sizes.get(c.oid.as_str()) else {
            // Not in this clone (a partial clone): not read, never fetched.
            history.not_read.missing += 1;
            history.complete = false;
            continue;
        };
        if size > MAX_BYTES {
            history.not_read.too_large += 1;
        } else if size > budget {
            history.not_read.over_limit += 1;
            history.complete = false;
        } else {
            budget -= size;
            selected.push(Selected {
                oid: &c.oid,
                path: &c.path,
                size,
                read: c.read,
            });
        }
    }

    let found = contents(&git, ws, scanner, seen, &selected, history)?;
    tally(ws, classifier, &selected, found, history);
    Ok(())
}

/// Every (blob, path) pair in the history of every ref, each blob once, in
/// the order git lists them, at most `limits.blobs` of them.
fn list(
    git: &Git,
    ws: &Path,
    prefix: &str,
    classifier: &privacy::Classifier<'_>,
    seen: &Seen,
    limits: Limits,
    history: &mut History,
) -> Result<Vec<Candidate>, Stop> {
    const FAILED: Stop = Stop::Failed("git could not list the history");
    let mut commits = git
        .spawn(ws, &["rev-list", "--all"], NO_FETCH)
        .map_err(|_| FAILED)?;
    drop(commits.stdin.take());
    // Raw changes only (modes, ids, names): no content is compared, so no
    // textconv or external diff applies.
    let mut changes = match git.spawn(
        ws,
        &[
            "diff-tree",
            "--stdin",
            "-r",
            "-m",
            "--root",
            "--no-renames",
            "--no-abbrev",
            "-z",
        ],
        NO_FETCH,
    ) {
        Ok(child) => child,
        Err(_) => {
            stop(commits);
            return Err(FAILED);
        }
    };
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    // Path → whether the cloud model reads it: each path classified once.
    let mut reads: HashMap<String, bool> = HashMap::new();
    let mut limited = false;
    let pumped = std::thread::scope(|scope| {
        // The commits into diff-tree, on another thread.
        let (from, to) = (commits.stdout.take(), changes.stdin.take());
        let pump = scope.spawn(move || match (from, to) {
            (Some(mut from), Some(mut to)) => std::io::copy(&mut from, &mut to).is_ok(),
            _ => false,
        });
        if let Some(out) = changes.stdout.take() {
            let mut tokens = BufReader::new(out).split(0);
            // `:<mode> <mode> <oid> <oid> <status>` and then the name; a
            // commit's id alone before its changes.
            while let Some(Ok(token)) = tokens.next() {
                let Some(meta) = token.strip_prefix(b":") else {
                    continue;
                };
                let Some(Ok(name)) = tokens.next() else { break };
                let fields: Vec<&[u8]> = meta.split(|b| *b == b' ').collect();
                let [_, mode, _, oid, status] = fields.as_slice() else {
                    continue;
                };
                // A file's new content: not a deletion, a link or a submodule.
                if !matches!(*mode, b"100644" | b"100755")
                    || !matches!(status.first(), Some(b'A' | b'M' | b'T'))
                {
                    continue;
                }
                let Ok(oid) = std::str::from_utf8(oid) else {
                    continue;
                };
                let Ok(name) = String::from_utf8(name) else {
                    // As in the walk: a name no rule can be proven for.
                    history.not_read.names += 1;
                    history.complete = false;
                    continue;
                };
                let Some(path) = name.strip_prefix(prefix) else {
                    continue;
                };
                if !is_oid(oid) || !walkable(path) || id_of(oid).is_some_and(|id| seen.has_blob(id))
                {
                    continue;
                }
                let read = *reads.entry(path.to_owned()).or_insert_with(|| {
                    matches!(classifier.classify(path).0, "content-checks" | "unknown")
                });
                match index.get(oid) {
                    Some(&i) => {
                        let c = &mut candidates[i];
                        if read && !c.read {
                            path.clone_into(&mut c.path);
                            c.read = true;
                        }
                    }
                    None if candidates.len() >= limits.blobs => {
                        limited = true;
                        break;
                    }
                    None => {
                        index.insert(oid.to_owned(), candidates.len());
                        candidates.push(Candidate {
                            oid: oid.to_owned(),
                            path: path.to_owned(),
                            read,
                        });
                    }
                }
            }
        }
        if limited {
            // Unblocks the pump, which may wait on either pipe.
            let _ = changes.kill();
            let _ = commits.kill();
        }
        pump.join().unwrap_or(false)
    });
    if limited {
        stop(changes);
        stop(commits);
        history.complete = false;
    } else {
        if !pumped {
            // rev-list may wait on a pipe nobody reads any more.
            let _ = commits.kill();
        }
        let listed = commits.wait().is_ok_and(|s| s.success());
        let changed = changes.wait().is_ok_and(|s| s.success());
        if !(pumped && listed && changed) {
            return Err(FAILED);
        }
    }
    history.blobs_listed = candidates.len();
    Ok(candidates)
}

/// Each candidate's size, from `git cat-file --batch-check`.
fn sizes<'a>(
    git: &Git,
    ws: &Path,
    candidates: &'a [Candidate],
) -> Result<HashMap<&'a str, u64>, Stop> {
    const FAILED: Stop = Stop::Failed("git could not read blob sizes");
    let mut child = git
        .spawn(
            ws,
            &["cat-file", "--batch-check=%(objectname) %(objectsize)"],
            NO_FETCH,
        )
        .map_err(|_| FAILED)?;
    let by_oid: HashSet<&'a str> = candidates.iter().map(|c| c.oid.as_str()).collect();
    let mut sizes = HashMap::with_capacity(candidates.len());
    let ok = std::thread::scope(|scope| {
        let writer = feed(
            scope,
            &mut child,
            candidates.iter().map(|c| c.oid.as_str()).collect(),
        );
        let mut read = true;
        if let Some(out) = child.stdout.take() {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else {
                    read = false;
                    break;
                };
                // `<oid> <size>`, or `<oid> missing`.
                let mut fields = line.split(' ');
                let (Some(oid), Some(size)) = (fields.next(), fields.next()) else {
                    continue;
                };
                if let (Some(key), Ok(size)) = (by_oid.get(oid), size.parse::<u64>()) {
                    sizes.insert(*key, size);
                }
            }
        } else {
            read = false;
        }
        if !read {
            // The writer may wait on a full pipe that is no longer read.
            let _ = child.kill();
        }
        read && writer.is_some_and(|w| w.join().is_ok())
    });
    let exited = child.wait().is_ok_and(|s| s.success());
    if ok && exited { Ok(sizes) } else { Err(FAILED) }
}

/// What one blob holds that the working tree does not: kinds and keyed
/// hashes of its values, each once.
struct Blob {
    index: usize,
    values: Vec<(declass_boundary::detect::Kind, u64)>,
}

/// Reads the selected blobs from `git cat-file --batch` and scans them on
/// every core. Returns the blobs holding values the working tree does not,
/// in no particular order.
fn contents(
    git: &Git,
    ws: &Path,
    scanner: &Scanner,
    seen: &Seen,
    selected: &[Selected<'_>],
    history: &mut History,
) -> Result<Vec<Blob>, Stop> {
    if selected.is_empty() {
        return Ok(Vec::new());
    }
    let mut child = git
        .spawn(ws, &["cat-file", "--batch"], NO_FETCH)
        .map_err(|_| Stop::Failed("git could not read blobs"))?;
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(16);
    // Bounded: few blobs of at most 2 MiB wait in memory.
    let (tx, rx) = sync_channel::<(usize, Vec<u8>)>(workers * 2);
    let rx: Mutex<Receiver<(usize, Vec<u8>)>> = Mutex::new(rx);
    let found: Mutex<Vec<Blob>> = Mutex::new(Vec::new());
    let binary = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let (read_ok, bytes_read, blobs_read) = std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let next = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                    let Ok((index, bytes)) = next else { break };
                    if bytes[..bytes.len().min(BINARY_PROBE)].contains(&0) {
                        binary.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let text = String::from_utf8_lossy(&bytes);
                        let mut keys = HashSet::new();
                        scanner
                            .values(&text, selected[index].path)
                            .into_iter()
                            .filter_map(|v| {
                                let key = seen.key(text.get(v.start..v.end)?);
                                (keys.insert(key) && !seen.contains(key)).then_some((v.kind, key))
                            })
                            .collect::<Vec<_>>()
                    }));
                    match scanned {
                        Ok(values) if values.is_empty() => {}
                        Ok(values) => found
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(Blob { index, values }),
                        Err(_) => failed.store(true, Ordering::Relaxed),
                    }
                }
            });
        }
        let writer = feed(scope, &mut child, selected.iter().map(|s| s.oid).collect());
        let mut ok = writer.is_some();
        let (mut bytes_read, mut blobs_read) = (0u64, 0usize);
        if let Some(out) = child.stdout.take() {
            let mut out = BufReader::new(out);
            for (index, Selected { oid, size, .. }) in selected.iter().enumerate() {
                // `<oid> blob <size>`, the content, then a newline.
                let mut header = String::new();
                if out.read_line(&mut header).unwrap_or(0) == 0 {
                    ok = false;
                    break;
                }
                let mut fields = header.trim_end().split(' ');
                if fields.next() != Some(*oid)
                    || fields.next() != Some("blob")
                    || fields.next().and_then(|s| s.parse::<u64>().ok()) != Some(*size)
                {
                    ok = false;
                    break;
                }
                let mut bytes = vec![0; usize::try_from(*size).unwrap_or(0)];
                let mut newline = [0u8; 1];
                if out.read_exact(&mut bytes).is_err() || out.read_exact(&mut newline).is_err() {
                    ok = false;
                    break;
                }
                bytes_read += size;
                blobs_read += 1;
                if tx.send((index, bytes)).is_err() {
                    ok = false;
                    break;
                }
            }
        } else {
            ok = false;
        }
        drop(tx);
        if !ok {
            // The writer may wait on a full pipe that is no longer read.
            let _ = child.kill();
        }
        if let Some(writer) = writer {
            ok &= writer.join().is_ok();
        }
        (ok, bytes_read, blobs_read)
    });
    let exited = child.wait().is_ok_and(|s| s.success());
    let binary = binary.into_inner();
    history.bytes_read = bytes_read;
    history.blobs_read = blobs_read.saturating_sub(binary);
    history.not_read.binary = binary;
    if !(read_ok && exited) || failed.into_inner() {
        return Err(Stop::Failed("git could not read every blob"));
    }
    Ok(found.into_inner().unwrap_or_else(PoisonError::into_inner))
}

/// What Declass's git tools do with a path's earlier versions (SECURITY.md,
/// "Git tools"): unlike a file read now, an interface-only path's history is
/// withheld whole.
fn history_action(disposition: &str) -> &'static str {
    match disposition {
        "sealed" => "its history never reaches the cloud model",
        "interface-only" => "its earlier versions are withheld from the cloud model",
        other => declass_action(other),
    }
}

/// A history finding's level: notes where the git tools keep the history
/// local or withhold it.
pub(super) fn history_level(kind: declass_boundary::detect::Kind, disposition: &str) -> Level {
    if disposition == "interface-only" {
        Level::Note
    } else {
        level(kind, disposition)
    }
}

/// Counts each value once, and only when the working tree does not hold it;
/// groups what is left by path. A value in several blobs counts where the
/// cloud model would read it, if anywhere, else in the first listed.
fn tally(
    ws: &Path,
    classifier: &privacy::Classifier<'_>,
    selected: &[Selected<'_>],
    mut found: Vec<Blob>,
    history: &mut History,
) {
    found.sort_by_key(|b| (!selected[b.index].read, b.index));
    let mut counted = HashSet::new();
    let mut by_path: BTreeMap<&str, (usize, BTreeMap<&'static str, usize>)> = BTreeMap::new();
    for blob in found {
        let mut new: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (kind, key) in blob.values {
            if counted.insert(key) {
                *new.entry(kind.tag()).or_insert(0) += 1;
            }
        }
        if new.is_empty() {
            continue;
        }
        let entry = by_path.entry(selected[blob.index].path).or_default();
        entry.0 += 1;
        for (tag, n) in new {
            *entry.1.entry(tag).or_insert(0) += n;
            *history.totals.entry(tag).or_insert(0) += n;
        }
    }
    for (path, (versions, found)) in by_path {
        let (disposition, rule) = classifier.classify(path);
        let level = found
            .keys()
            .filter_map(|t| super::tag_kind(t))
            .map(|k| history_level(k, disposition))
            .max()
            .unwrap_or(Level::Note);
        history.exposed.push(Exposed {
            path: path.to_owned(),
            deleted: std::fs::symlink_metadata(ws.join(path)).is_err(),
            versions,
            found,
            level,
            declass: history_action(disposition),
            disposition,
            rule,
        });
    }
    history.exposed.sort_by(|a, b| {
        let total = |e: &Exposed| e.found.values().sum::<usize>();
        total(b).cmp(&total(a)).then_with(|| a.path.cmp(&b.path))
    });
}

impl History {
    pub(super) fn render(&self, lines: &mut Vec<String>, shown: usize) {
        if let Some(reason) = self.unavailable {
            lines.push(format!("Git history: not read ({reason})."));
            return;
        }
        lines.push(format!(
            "Git history · {} earlier file {} read on this machine · limits {} blobs, {} MiB{}",
            self.blobs_read,
            if self.blobs_read == 1 {
                "version"
            } else {
                "versions"
            },
            self.limits.blobs,
            self.limits.bytes / (1024 * 1024),
            if self.complete {
                ""
            } else {
                " · not all read"
            }
        ));
        if self.exposed.is_empty() {
            lines.push("No values in history beyond those in the working tree.".into());
        } else {
            lines.push(format!(
                "An agent that reads history could also send {} that the working tree no longer holds, from {} {}.",
                describe(&self.totals, 4),
                self.exposed.len(),
                if self.exposed.len() == 1 {
                    "path"
                } else {
                    "paths"
                }
            ));
            lines.push(String::new());
            for e in self.exposed.iter().take(shown) {
                lines.push(format!(
                    "  {}{}",
                    privacy::shown(&e.path),
                    if e.deleted { " (deleted)" } else { "" }
                ));
                lines.push(format!(
                    "    found:   {} in {} earlier {}",
                    describe(&e.found, usize::MAX),
                    e.versions,
                    if e.versions == 1 {
                        "version"
                    } else {
                        "versions"
                    }
                ));
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
        let n = &self.not_read;
        if n.too_large + n.binary + n.over_limit + n.missing + n.names > 0 {
            lines.push(format!(
                "Not read from history: {} over {} MiB, {} binary or UTF-16, {} past the limits ({} blobs, {} MiB), {} not in this clone, {} under names that are not UTF-8.",
                n.too_large,
                MAX_BYTES / (1024 * 1024),
                n.binary,
                n.over_limit,
                self.limits.blobs,
                self.limits.bytes / (1024 * 1024),
                n.missing,
                n.names
            ));
        }
        if !self.working_tree_values_known {
            lines.push(
                "The working tree holds too many values to remember: history may repeat some."
                    .into(),
            );
        }
        lines.push(
            "Declass's git tools classify history by each path's rules now; commands cannot read .git."
                .into(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::{FailOn, Options, Report, collect};
    use declass_config::Config;

    const OLD: &str = concat!("ghp_", "Qz8vW3nL5kR2xT7mY4pB9cH6dJ1sF0aGeU2i");
    const OTHER: &str = concat!("xoxb-", "8817361945-ZqW7rT2nV9kLpX4m");

    /// Git through declass-git's runner, as the report runs it.
    fn git(dir: &Path, args: &[&str]) -> String {
        git_with(dir, args, &[])
    }

    fn git_with(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
        let out = Git::locate().unwrap().run(dir, args, env, None).unwrap();
        String::from_utf8(out).unwrap().trim().to_owned()
    }

    fn write(dir: &Path, path: &str, text: &str) {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }

    fn commit(dir: &Path, message: &str) {
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-q", "-m", message]);
    }

    fn report(ws: &Path, owner: &Path, blobs: usize, bytes: u64) -> Report {
        let file = owner.join("owner.toml");
        std::fs::write(&file, "").unwrap();
        let cfg = Config::load(&file, None).unwrap();
        let options = Options {
            fail_on: FailOn::Note,
            history: Some(Limits { blobs, bytes }),
        };
        collect(ws, &cfg, &options).unwrap()
    }

    fn history(r: &Report) -> &History {
        r.history.as_ref().unwrap()
    }

    /// Git lists each blob once, under the first path it meets; the report
    /// must find it under any other path too: when the first is outside the
    /// workspace (another project of a monorepo) or in a directory the walk
    /// skips.
    #[test]
    fn a_blob_is_found_under_any_of_its_paths() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        let file = format!("TOKEN = \"{OLD}\"\n");
        for path in [".venv/lib/config.py", "aa/config.py", "zz/config.py"] {
            write(&repo, path, &file);
        }
        commit(&repo, "add");
        for path in [".venv/lib/config.py", "aa/config.py", "zz/config.py"] {
            write(&repo, path, "TOKEN = None\n");
        }
        commit(&repo, "remove");
        // .venv/lib/config.py comes first, and .venv is not searched.
        let root = report(&repo, temp.path(), 1000, 1 << 30);
        let h = history(&root);
        assert!(h.complete);
        assert_eq!(h.totals.get("secret"), Some(&1), "{:?}", h.totals);
        assert_eq!(h.exposed.len(), 1);
        assert_eq!(h.exposed[0].path, "aa/config.py");
        // From zz/, the first path (aa/config.py) is outside the workspace.
        let project = report(&repo.join("zz"), temp.path(), 1000, 1 << 30);
        let h = history(&project);
        assert!(h.complete);
        assert_eq!(h.exposed.len(), 1);
        assert_eq!(h.exposed[0].path, "config.py");
        assert_eq!(h.exposed[0].level, Level::Error);
    }

    /// A blob a path rule keeps local at one path and the cloud model reads at
    /// another counts where it is read, at that path's level.
    #[test]
    fn the_path_the_cloud_model_reads_decides() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        let rows = "email\njordan.reyes@corpmail.co\n";
        write(&repo, "data/export.csv", rows);
        write(&repo, "tests/export.txt", rows);
        commit(&repo, "add");
        std::fs::remove_file(repo.join("data/export.csv")).unwrap();
        std::fs::remove_file(repo.join("tests/export.txt")).unwrap();
        write(&repo, "README.md", "nothing\n");
        commit(&repo, "remove");
        let r = report(&repo, temp.path(), 1000, 1 << 30);
        let e = &history(&r).exposed[0];
        assert_eq!(e.path, "tests/export.txt", "not data/export.csv (local)");
        assert_eq!((e.disposition, e.level), ("content-checks", Level::Warning));
        assert!(e.deleted);
    }

    #[test]
    fn values_count_once_and_limits_leave_the_report_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        write(&repo, "src/a.py", &format!("TOKEN = \"{OLD}\"\n"));
        commit(&repo, "one");
        write(&repo, "src/a.py", &format!("TOKEN = \"{OLD}\"\n# two\n"));
        commit(&repo, "two");
        write(&repo, "src/a.py", &format!("TOKEN = \"{OTHER}\"\n"));
        commit(&repo, "three");
        write(&repo, "src/a.py", "TOKEN = None\n");
        commit(&repo, "four");
        let all = report(&repo, temp.path(), 1000, 1 << 30);
        let h = history(&all);
        assert!(h.complete && all.complete);
        assert_eq!(
            (h.blobs_listed, h.blobs_read),
            (3, 3),
            "the current blob is not read"
        );
        // OLD is in two versions and counts once.
        assert_eq!(h.totals.get("secret"), Some(&2));
        assert_eq!(h.exposed[0].versions, 2);
        let blobs = report(&repo, temp.path(), 1, 1 << 30);
        assert!(!history(&blobs).complete && !blobs.complete);
        assert_eq!(history(&blobs).blobs_listed, 1);
        assert_eq!(blobs.code(), 2);
        let bytes = report(&repo, temp.path(), 1000, 1);
        let h = history(&bytes);
        assert!(!h.complete);
        assert_eq!((h.not_read.over_limit, h.blobs_read), (3, 0));
    }

    /// A partial clone lacks most blobs of its history: they are counted as
    /// not read, and nothing is fetched to read them.
    #[test]
    fn a_partial_clone_is_incomplete_and_never_fetches() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        git(&source, &["init", "-q"]);
        write(&source, "src/a.py", &format!("TOKEN = \"{OLD}\"\n"));
        commit(&source, "one");
        write(&source, "src/a.py", "TOKEN = None\n");
        commit(&source, "two");
        git(&source, &["config", "uploadpack.allowFilter", "true"]);
        let clone = temp.path().join("clone");
        // Plain git, with the file transport allowed: Declass's runner refuses
        // every transport.
        let made = std::process::Command::new(Git::locate().unwrap().binary())
            .args(["-c", "protocol.file.allow=always", "clone", "-q"])
            .args(["--no-local", "--filter=blob:none"])
            .arg(format!("file://{}", source.display()))
            .arg(&clone)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", temp.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(made.success());
        let missing = || {
            git_with(
                &clone,
                &["rev-list", "--objects", "--all", "--missing=print"],
                &[("GIT_NO_LAZY_FETCH", "1")],
            )
            .lines()
            .filter(|l| l.starts_with('?'))
            .count()
        };
        let before = missing();
        assert!(before > 0, "the clone holds every blob");
        let r = report(&clone, temp.path(), 1000, 1 << 30);
        let h = history(&r);
        assert!(!h.complete && !r.complete);
        assert!(h.not_read.missing > 0);
        assert_eq!(missing(), before, "a blob was fetched");
    }

    /// A clean filter in `.git/config` runs whenever git hashes a working-tree
    /// file, as it does to check a racily clean index entry (same size and
    /// time as when it was staged). Reading history never asks git to.
    #[test]
    fn no_filter_runs_even_for_a_racily_clean_file() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        write(&repo, "notes.txt", "aaaa\n");
        commit(&repo, "one");
        let marker = temp.path().join("filter-ran");
        git(&repo, &["config", "core.trustctime", "false"]);
        git(
            &repo,
            &[
                "config",
                "filter.probe.clean",
                &format!("touch '{}'; cat", marker.display()),
            ],
        );
        write(&repo, ".git/info/attributes", "* filter=probe\n");
        // Other content, same size, and the time the index entry holds; the
        // index itself written in that instant: racily clean.
        let staged = std::fs::metadata(repo.join("notes.txt"))
            .unwrap()
            .modified()
            .unwrap();
        std::fs::write(repo.join("notes.txt"), "bbbb\n").unwrap();
        for file in ["notes.txt", ".git/index"] {
            std::fs::File::options()
                .write(true)
                .open(repo.join(file))
                .unwrap()
                .set_modified(staged)
                .unwrap();
        }
        // Git itself hashes the file to look at it, and the filter runs.
        git(&repo, &["diff-files", "--name-only"]);
        if !marker.exists() {
            eprintln!("this git does not treat the entry as racily clean; nothing to check");
            return;
        }
        std::fs::remove_file(&marker).unwrap();
        let r = report(&repo, temp.path(), 1000, 1 << 30);
        assert!(history(&r).complete);
        assert!(!marker.exists(), "a filter the repository configures ran");
    }

    #[test]
    fn blob_ids_are_gits() {
        // `printf 'hello\n' | git hash-object --stdin` and the same with
        // `--object-format=sha256`.
        assert_eq!(
            Format::Sha1.blob_id(b"hello\n"),
            id_of("ce013625030ba8dba906f756967f9e9ca394464a").unwrap()
        );
        assert_eq!(
            Format::Sha256.blob_id(b"hello\n"),
            id_of("2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4").unwrap()
        );
        assert_eq!(id_of("ce01"), None);
    }
}
