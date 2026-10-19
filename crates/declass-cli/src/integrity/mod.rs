// SPDX-License-Identifier: GPL-3.0-or-later
//! Pins for extensions (`declass extensions`): what is installed, what the
//! lock files say it must be, and how they differ.
//!
//! The owner's lock (`extensions.lock` beside the owner config) pins the
//! owner's skills and installed plugins. A project's lock
//! (`.declass/extensions.lock`, committed) pins the project's own skills, the
//! ones under `.agents/skills`, `.claude/skills` and the like that every
//! coding agent reads, so a check in CI catches a change to them whichever
//! agent would load it.

pub(crate) mod cmd;
pub(crate) mod feeds;

use anyhow::{Context, Result, bail};
use declass_boundary::audit::{AuditEvent, AuditHandle};
use declass_extensions::{Catalog, Origin, Skill};
use declass_integrity::lock::{
    Entry, Executable, Kind, Lock, McpServer, Package, Scope, ServerInfo, ToolsetPin, Transport,
};
use declass_integrity::osv::{Hit, Index, Severity};
use declass_integrity::report::{Finding, Level, Rule};
use declass_integrity::{Sha256Digest, launcher, toolset, tree};
use declass_mcp::{Launch, ServerConfig};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The owner's lock file.
pub(crate) fn owner_lock_path() -> PathBuf {
    declass_config::owner_config_path().with_file_name("extensions.lock")
}

/// A project's lock file.
pub(crate) fn project_lock_path(ws: &Path) -> PathBuf {
    ws.join(".declass/extensions.lock")
}

/// A lock file as read.
pub(crate) enum Loaded {
    Missing,
    Valid(Lock),
    Invalid(String),
}

impl Loaded {
    pub(crate) fn read(path: &Path, scope: Scope) -> Loaded {
        match std::fs::read_to_string(path) {
            Ok(text) => match Lock::parse(&text, scope) {
                Ok(lock) => Loaded::Valid(lock),
                Err(e) => Loaded::Invalid(e.to_string()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Missing,
            Err(e) => Loaded::Invalid(e.to_string()),
        }
    }

    fn lock(&self) -> Option<&Lock> {
        match self {
            Loaded::Valid(lock) => Some(lock),
            _ => None,
        }
    }
}

/// An installed skill or plugin.
#[derive(Debug, Clone)]
pub(crate) struct Item {
    pub kind: Kind,
    /// Skill ID or plugin name.
    pub name: String,
    /// The lock file `source`: `project:<path>`, `owner:<path>`, `plugin:<name>`
    /// or `owner-store`.
    pub source: String,
    /// The lock that pins it: a project's skills in the project's.
    pub scope: Scope,
    pub version: Option<String>,
    /// Where it is, as reports show it.
    pub location: String,
    /// The plugin store digest; for a skill, its content digest.
    pub digest: Result<String, String>,
    pub content: Result<Sha256Digest, String>,
    /// Links and special files its digest does not cover.
    pub uncovered: Vec<String>,
}

impl Item {
    pub(crate) fn id(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.name)
    }

    /// The pin for what is installed now; `None` when it cannot be read.
    pub(crate) fn entry(&self, explicit: bool) -> Option<Entry> {
        let content = *self.content.as_ref().ok()?;
        Some(Entry {
            name: self.name.clone(),
            version: self.version.clone(),
            source: self.source.clone(),
            digest: self.digest.clone().ok()?,
            content_digest: Some(content),
            unsigned: true,
            explicit,
            ..Entry::default()
        })
    }
}

/// `path` with the home directory written `~`.
fn shown(path: &Path) -> String {
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty())
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

/// The item for a discovered skill, and the files it was hashed from (to
/// seal the catalog with); `None` for a skill inside a plugin, which the
/// plugin's own pin covers.
fn skill_item(ws: &Path, canonical_ws: &Path, skill: &Skill) -> Option<(Item, Option<tree::Scan>)> {
    let (scope, source, location) = match skill.origin {
        Origin::Project => {
            let rel = skill
                .root
                .strip_prefix(canonical_ws)
                .or_else(|_| skill.root.strip_prefix(ws))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| skill.root.display().to_string());
            (Scope::Project, format!("project:{rel}"), rel)
        }
        Origin::Owner => {
            let at = shown(&skill.root);
            (Scope::Owner, format!("owner:{at}"), at)
        }
        Origin::Plugin => return None,
    };
    let (content, uncovered, scan) = match tree::scan(&skill.root, tree::Limits::PACKAGE) {
        Ok(scan) => (
            scan.content_digest().map_err(|e| e.to_string()),
            scan.skipped.clone(),
            Some(scan),
        ),
        Err(e) => (Err(e.to_string()), Vec::new(), None),
    };
    let item = Item {
        kind: Kind::Skill,
        name: skill.id.clone(),
        source,
        scope,
        version: None,
        location,
        digest: content
            .as_ref()
            .map(ToString::to_string)
            .map_err(Clone::clone),
        content,
        uncovered,
    };
    Some((item, scan))
}

fn plugin_item(p: &crate::plugins::Package) -> Item {
    Item {
        kind: Kind::Plugin,
        name: p.manifest.name.clone(),
        source: "owner-store".into(),
        scope: Scope::Owner,
        version: Some(p.manifest.version.clone()),
        location: shown(&p.root),
        digest: Ok(format!("sha256:{}", p.digest)),
        content: crate::plugins::content_digest(p).map_err(|e| format!("{e:#}")),
        uncovered: Vec::new(),
    }
}

/// Everything installed that a lock can pin: skills in every root Declass
/// reads (whether or not this workspace enables them) and the installed
/// plugins (a plugin's skills are covered by its pin). With `project_only`,
/// the project's own skills alone.
pub(crate) fn inventory(ws: &Path, project_only: bool) -> Result<(Vec<Item>, Vec<String>)> {
    let mut roots = crate::extensions::roots(ws);
    let packages = if project_only {
        roots.retain(|r| r.origin == Origin::Project);
        Vec::new()
    } else {
        crate::plugins::packages(&crate::plugins::store()?)?
    };
    let mut items = Vec::new();
    let mut notes = Vec::new();
    for package in packages {
        match package {
            Ok(p) => items.push(plugin_item(&p)),
            Err(e) => notes.push(format!("an installed plugin cannot be read: {e:#}")),
        }
    }
    let catalog = Catalog::discover(&roots);
    notes.extend(catalog.diagnostics().iter().cloned());
    let canonical_ws = ws.canonicalize().unwrap_or_else(|_| ws.to_path_buf());
    items.extend(
        catalog
            .skills()
            .iter()
            .filter_map(|skill| skill_item(ws, &canonical_ws, skill))
            .map(|(item, _)| item),
    );
    items.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    Ok((items, notes))
}

/// How an item stands against its lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum State {
    Pinned,
    /// Pinned, but found elsewhere or with other content: (pinned, now).
    Changed(String, String),
    /// Its lock has no entry for it.
    Unpinned,
    /// Its lock cannot be read; nothing can be said.
    LockInvalid,
    /// Its files cannot be read.
    Unreadable(String),
}

pub(crate) fn state(item: &Item, lock: &Loaded) -> State {
    let lock = match lock {
        Loaded::Valid(lock) => lock,
        Loaded::Invalid(_) => return State::LockInvalid,
        Loaded::Missing => return State::Unpinned,
    };
    let Some(pin) = lock.entry(item.kind, &item.name) else {
        return State::Unpinned;
    };
    if pin.source != item.source {
        return State::Changed(pin.source.clone(), item.source.clone());
    }
    let content = match &item.content {
        Ok(c) => c,
        Err(e) => return State::Unreadable(e.clone()),
    };
    match &pin.content_digest {
        Some(pinned) if pinned != content => {
            return State::Changed(pinned.to_string(), content.to_string());
        }
        _ => {}
    }
    // A plugin's store digest too; a skill's digest is its content digest.
    if item.kind == Kind::Plugin
        && let Ok(digest) = &item.digest
        && *digest != pin.digest
    {
        return State::Changed(pin.digest.clone(), digest.clone());
    }
    State::Pinned
}

/// Every finding for `items` against the two locks.
pub(crate) fn verify(
    items: &[Item],
    owner: &Loaded,
    project: &Loaded,
    project_only: bool,
    paths: (&str, &str),
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (loaded, path, skip) in [(project, paths.1, false), (owner, paths.0, project_only)] {
        if let (Loaded::Invalid(why), false) = (loaded, skip) {
            findings.push(Finding {
                rule: Rule::InvalidLock,
                level: Level::Error,
                kind: "lock",
                id: path.to_owned(),
                message: format!("cannot be used: {why}"),
                location: Some(path.to_owned()),
            });
        }
    }
    for item in items {
        if project_only && item.scope != Scope::Project {
            continue;
        }
        let (lock, which) = match item.scope {
            Scope::Project => (project, "the project lock"),
            Scope::Owner => (owner, "the owner lock"),
        };
        let finding = |rule, level, message: String| Finding {
            rule,
            level,
            kind: item.kind.as_str(),
            id: item.name.clone(),
            message,
            location: Some(item.location.clone()),
        };
        match state(item, lock) {
            State::Pinned | State::LockInvalid => {}
            State::Changed(pinned, now) => findings.push(finding(
                Rule::DigestMismatch,
                Level::Error,
                format!("differs from {which}: pinned {pinned}, now {now}"),
            )),
            State::Unreadable(why) => findings.push(finding(
                Rule::DigestMismatch,
                Level::Error,
                format!("cannot be checked against {which}: {why}"),
            )),
            State::Unpinned => {
                let level = match lock {
                    Loaded::Valid(_) => Level::Warning,
                    _ => Level::Note,
                };
                let message = match lock {
                    Loaded::Valid(_) => format!("not pinned in {which}"),
                    _ => format!("not pinned ({which} does not exist yet)"),
                };
                findings.push(finding(Rule::Unpinned, level, message));
            }
        }
        if !item.uncovered.is_empty() {
            findings.push(finding(
                Rule::Unpinned,
                Level::Note,
                format!(
                    "links or special files no digest covers: {}",
                    item.uncovered.join(", ")
                ),
            ));
        }
    }
    // Pins of what is no longer there.
    for (loaded, scope, path) in [
        (project, Scope::Project, paths.1),
        (owner, Scope::Owner, paths.0),
    ] {
        if project_only && scope == Scope::Owner {
            continue;
        }
        let Some(lock) = loaded.lock() else { continue };
        for kind in [Kind::Skill, Kind::Plugin] {
            for pin in lock.entries(kind) {
                let present = items
                    .iter()
                    .any(|i| i.kind == kind && i.name == pin.name && i.scope == scope);
                if !present {
                    findings.push(Finding {
                        rule: Rule::PinnedMissing,
                        level: Level::Warning,
                        kind: kind.as_str(),
                        id: pin.name.clone(),
                        message: format!("pinned at {} but not installed", pin.source),
                        location: Some(path.to_owned()),
                    });
                }
            }
        }
    }
    findings
}

/// Everything installed, checked against both lock files: how many were
/// checked, the findings, and notes from discovery.
pub(crate) fn check_all(
    ws: &Path,
    cfg: Option<&declass_config::Config>,
    project_only: bool,
) -> Result<(usize, Vec<Finding>, Vec<String>)> {
    let owner_path = owner_lock_path();
    let project_path = project_lock_path(ws);
    let owner = Loaded::read(&owner_path, Scope::Owner);
    let project = Loaded::read(&project_path, Scope::Project);
    let (items, notes) = inventory(ws, project_only)?;
    let project_shown = project_path
        .strip_prefix(ws)
        .unwrap_or(&project_path)
        .display()
        .to_string();
    let owner_shown = owner_path.display().to_string();
    let mut findings = verify(
        &items,
        &owner,
        &project,
        project_only,
        (&owner_shown, &project_shown),
    );
    let mut checked = items
        .iter()
        .filter(|i| !project_only || i.scope == Scope::Project)
        .count();
    let known = feeds::known(ws);
    let mut notes = notes;
    notes.extend(known.notes.iter().cloned());
    for item in &items {
        if project_only && item.scope != Scope::Project {
            continue;
        }
        if let Ok(content) = &item.content {
            findings.extend(advisory_findings(
                item.kind,
                &item.name,
                &known.index.content(content),
                Some(item.location.clone()),
            ));
        }
    }
    if let (Some(cfg), false) = (cfg, project_only) {
        let servers = configured_servers(cfg)?;
        checked += servers.len();
        findings.extend(server_findings(
            ws,
            &servers,
            &owner,
            &project,
            &owner_shown,
        ));
        for s in &servers {
            let mut hits = Vec::new();
            match &s.launch {
                Launch::Command { command, args } => {
                    let argv: Vec<String> = std::iter::once(command.clone())
                        .chain(args.iter().cloned())
                        .collect();
                    if let Some(l) = launcher::classify(&argv) {
                        hits.extend(known.index.package(
                            &l.package.registry_type,
                            &l.package.identifier,
                            l.package.version.as_deref(),
                        ));
                    }
                }
                Launch::Url(u) => hits.extend(known.index.url(u)),
            }
            if let Some(t) = owner
                .lock()
                .and_then(|l| l.mcp(&s.name))
                .and_then(|p| p.toolset.as_ref())
            {
                hits.extend(known.index.tools(&t.digest, t.tools.iter()));
            }
            hits.sort_by_key(|h| std::cmp::Reverse(h.severity));
            findings.extend(advisory_findings(Kind::Mcp, &s.name, &hits, None));
        }
        if let Some(why) = feeds::stale(&known, cfg)? {
            findings.push(Finding {
                rule: Rule::StaleAdvisories,
                level: Level::Warning,
                kind: "advisories",
                id: "feeds".into(),
                message: why,
                location: None,
            });
        }
    }
    Ok((checked, findings, notes))
}

/// A finding for the worst of `hits` about one extension.
fn advisory_findings(
    kind: Kind,
    name: &str,
    hits: &[Hit],
    location: Option<String>,
) -> Vec<Finding> {
    hits.first()
        .map(|worst| Finding {
            rule: Rule::Revoked,
            level: if worst.severity == Severity::Revoked {
                Level::Error
            } else {
                Level::Warning
            },
            kind: kind.as_str(),
            id: name.to_owned(),
            message: format!(
                "{} by {}: {} ({})",
                if worst.severity == Severity::Revoked {
                    "revoked"
                } else {
                    "a known vulnerability"
                },
                worst.id,
                worst.summary,
                worst.matched
            ),
            location,
        })
        .into_iter()
        .collect()
}

/// Every MCP server a run could start: the owner's (enabled or not) and the
/// enabled plugins'.
pub(crate) fn configured_servers(cfg: &declass_config::Config) -> Result<Vec<ServerConfig>> {
    let mut servers: Vec<ServerConfig> = crate::mcp::configured(cfg)
        .into_iter()
        .filter_map(|(_, s)| s.ok().map(|(server, _)| server))
        .collect();
    if cfg.bool("extensions.plugins_enabled")? {
        let packages = crate::plugins::active_packages(&crate::plugins::store()?)?;
        servers.extend(crate::plugins::servers(&packages, cfg)?);
    }
    Ok(servers)
}

/// Writes `lock` to `path` (scope `scope`), atomically and owner-only.
pub(crate) fn save(path: &Path, lock: &Lock, scope: Scope) -> Result<()> {
    lock.check(scope)
        .with_context(|| format!("refusing to write an invalid lock to {}", path.display()))?;
    if let Some(parent) = path.parent() {
        declass_fs::private::ensure_private_dir(parent)?;
    }
    declass_fs::private::write_private(path, lock.render().as_bytes())?;
    Ok(())
}

/// Records pins written to the owner's lock in the owner's change log
/// (`config-audit.jsonl`, hash-chained): `by` is `lock`, `lock_update`,
/// `install` or `first_use`. A project lock is a file in the repository; its history is
/// the repository's.
pub(crate) fn record_pins(pins: &[(Kind, Entry)], by: &str) -> Result<()> {
    if pins.is_empty() {
        return Ok(());
    }
    let path = crate::config_audit_path();
    if let Some(parent) = path.parent() {
        declass_fs::private::ensure_private_dir(parent)?;
    }
    let mut log = declass_boundary::audit::AuditLog::open(&path)?;
    for (kind, entry) in pins {
        log.event(AuditEvent::ExtensionPinned {
            extension: kind.as_str().into(),
            id: entry.name.clone(),
            digest: entry
                .content_digest
                .map(|d| d.to_string())
                .unwrap_or_else(|| entry.digest.clone()),
            by: by.into(),
        })?;
    }
    Ok(())
}

/// Records a pin removed from the owner's lock (`by` = `forget`, no digest).
pub(crate) fn record_forgotten(kind: Kind, name: &str) -> Result<()> {
    let path = crate::config_audit_path();
    if let Some(parent) = path.parent() {
        declass_fs::private::ensure_private_dir(parent)?;
    }
    declass_boundary::audit::AuditLog::open(&path)?.event(AuditEvent::ExtensionPinned {
        extension: kind.as_str().into(),
        id: name.to_owned(),
        digest: String::new(),
        by: "forget".into(),
    })?;
    Ok(())
}

/// Takes the owner lock's writer guard (one writer at a time across
/// processes), held until dropped.
pub(crate) fn writer_guard(path: &Path) -> Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        declass_fs::private::ensure_private_dir(parent)?;
    }
    let guard = declass_fs::private::open_lock(&path.with_file_name(".extensions.lock.guard"))?;
    rustix::fs::flock(&guard, rustix::fs::FlockOperation::LockExclusive)?;
    Ok(guard)
}

/// Refuses a plugin whose signer differs from the one pinned for it (a
/// signed package that is now unsigned, or signed by another key), unless
/// `allow_change`.
pub(crate) fn check_signer(
    name: &str,
    signer: Option<&declass_integrity::sshsig::Signer>,
    allow_change: bool,
) -> Result<()> {
    let Loaded::Valid(lock) = Loaded::read(&owner_lock_path(), Scope::Owner) else {
        return Ok(());
    };
    let pinned = lock
        .entry(Kind::Plugin, name)
        .and_then(|e| e.provenance.as_ref())
        .map(|p| p.public_key.clone())
        .filter(|k| !k.is_empty());
    let now = signer.map(|s| s.key.lock_form());
    match (pinned, now) {
        (Some(p), now) if Some(&p) != now.as_ref() && !allow_change => bail!(
            "plugin {name} was signed by {p} when pinned and is now {}; review why, then run again with --allow-signer-change",
            now.map_or("unsigned".to_owned(), |k| format!("signed by {k}"))
        ),
        _ => Ok(()),
    }
}

/// Installing a plugin is the owner's approval of its content: pin it in
/// the owner's lock (replacing an earlier version's pin), with its signer.
pub(crate) fn pin_installed_plugin(
    package: &crate::plugins::Package,
    signer: Option<&declass_integrity::sshsig::Signer>,
) -> Result<()> {
    let item = plugin_item(package);
    let mut entry = item
        .entry(true)
        .with_context(|| format!("cannot pin plugin {}", item.name))?;
    if let Some(s) = signer {
        entry.unsigned = false;
        entry.provenance = Some(declass_integrity::lock::Provenance {
            public_key: s.key.lock_form(),
            ..declass_integrity::lock::Provenance::default()
        });
    }
    let path = owner_lock_path();
    let _guard = writer_guard(&path)?;
    let mut lock = match Loaded::read(&path, Scope::Owner) {
        Loaded::Missing => Lock::new(),
        Loaded::Valid(lock) => lock,
        Loaded::Invalid(why) => bail!(
            "installed, but {} cannot be used to pin it ({why}); fix or remove it",
            path.display()
        ),
    };
    if lock.entry(Kind::Plugin, &entry.name) == Some(&entry) {
        return Ok(());
    }
    lock.upsert(Kind::Plugin, entry.clone());
    save(&path, &lock, Scope::Owner)?;
    record_pins(&[(Kind::Plugin, entry)], "install")
}

/// Removing a plugin removes its pin; a pin of nothing would only be noise.
pub(crate) fn unpin_plugin(name: &str) -> Result<()> {
    let path = owner_lock_path();
    let _guard = writer_guard(&path)?;
    let Loaded::Valid(mut lock) = Loaded::read(&path, Scope::Owner) else {
        return Ok(());
    };
    if lock.remove(Kind::Plugin, name) {
        save(&path, &lock, Scope::Owner)?;
    }
    Ok(())
}

/// What a run or session does about pins (`extensions.integrity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Warn,
    Enforce,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Warn => "warn",
            Mode::Enforce => "enforce",
        }
    }
}

/// What to do with one extension when a run or session starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Load,
    /// Not pinned yet: pin it in the owner's lock, then load it.
    PinAndLoad,
    /// Load it and say how it differs.
    Warn,
    LeaveOut,
}

/// The decision for an extension of `scope` in `state`. A project's skill
/// without a project lock is loaded quietly: the repository chose not to pin
/// it, and its text is treated as untrusted project content anyway.
pub(crate) fn decide(
    mode: Mode,
    first_use: bool,
    scope: Scope,
    state: &State,
    lock_exists: bool,
) -> Action {
    let differs = match mode {
        Mode::Warn => Action::Warn,
        Mode::Enforce => Action::LeaveOut,
    };
    match state {
        State::Pinned => Action::Load,
        State::Changed(..) | State::Unreadable(_) | State::LockInvalid => differs,
        State::Unpinned => match scope {
            Scope::Owner if first_use => Action::PinAndLoad,
            Scope::Owner => differs,
            Scope::Project if lock_exists => differs,
            Scope::Project => Action::Load,
        },
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    verified: u64,
    first_use: u64,
    warned: u64,
    left_out: u64,
}

/// What a stdio server's launch looked like when it was checked.
#[derive(Debug, Clone)]
pub(crate) struct Launched {
    command: Vec<String>,
    executable: Option<Executable>,
    package: Option<Package>,
}

/// What the checks of one run found, as they happen (servers start in
/// parallel).
#[derive(Debug, Default)]
struct Tally {
    pins: Vec<(Kind, Entry)>,
    mcp_pins: Vec<McpServer>,
    /// Stdio servers seen unpinned at launch, by name: their pin is complete
    /// once their tools are listed.
    first_launch: BTreeMap<String, Launched>,
    /// The tools each server offered at its start, by name.
    offered: BTreeMap<String, Sha256Digest>,
    counts: Counts,
    notes: Vec<String>,
}

/// Checks a run's or session's skills, plugins and MCP servers against
/// their pins before anything uses them (`extensions.integrity`).
pub(crate) struct Gate {
    mode: Mode,
    first_use: bool,
    ws: PathBuf,
    owner_path: PathBuf,
    owner: Loaded,
    project: Loaded,
    /// What advisory feeds say (`declass extensions advisories`), as last
    /// fetched: never fetched during a run.
    advisories: Index,
    audit: Option<AuditHandle>,
    tally: Mutex<Tally>,
}

impl Gate {
    /// `None` with `extensions.integrity = "off"`. Under `enforce`, a lock
    /// file that cannot be used stops the run: nothing could be checked.
    pub(crate) fn new(
        ws: &Path,
        cfg: &declass_config::Config,
        audit: Option<AuditHandle>,
    ) -> Result<Option<Gate>> {
        let mode = match cfg.str("extensions.integrity")?.as_str() {
            "enforce" => Mode::Enforce,
            "warn" => Mode::Warn,
            _ => return Ok(None),
        };
        let owner_path = owner_lock_path();
        let owner = Loaded::read(&owner_path, Scope::Owner);
        let project_path = project_lock_path(ws);
        let project = Loaded::read(&project_path, Scope::Project);
        let mut tally = Tally::default();
        for (path, loaded) in [(&owner_path, &owner), (&project_path, &project)] {
            if let Loaded::Invalid(why) = loaded {
                if mode == Mode::Enforce {
                    bail!(
                        "extensions.integrity is \"enforce\", but {} cannot be used ({why}); fix it, or check with `declass extensions verify`",
                        path.display()
                    );
                }
                tally
                    .notes
                    .push(format!("{} cannot be used: {why}", path.display()));
            }
        }
        let known = feeds::known(ws);
        tally.notes.extend(known.notes);
        Ok(Some(Gate {
            mode,
            first_use: cfg.bool("extensions.integrity_first_use")?,
            ws: ws.to_path_buf(),
            owner_path,
            owner,
            project,
            advisories: known.index,
            audit,
            tally: Mutex::new(tally),
        }))
    }

    fn tally(&self) -> std::sync::MutexGuard<'_, Tally> {
        self.tally
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Decides for one extension in `state` against the lock of `scope`;
    /// notes and records anything but a plain match. A first-use pin is the
    /// caller's to take.
    fn judge(&self, kind: Kind, name: &str, scope: Scope, state: &State) -> Action {
        let (lock, which) = match scope {
            Scope::Project => (&self.project, "the project lock"),
            Scope::Owner => (&self.owner, "your lock"),
        };
        let lock_exists = matches!(lock, Loaded::Valid(_));
        let action = decide(self.mode, self.first_use, scope, state, lock_exists);
        let id = format!("{}:{name}", kind.as_str());
        let (outcome, expected, observed) = match state {
            State::Changed(pinned, now) => ("changed", Some(pinned.clone()), Some(now.clone())),
            State::Unreadable(why) => ("unreadable", None, Some(why.clone())),
            State::LockInvalid => ("lock_unusable", None, None),
            State::Unpinned if action == Action::PinAndLoad => ("pinned_first_use", None, None),
            State::Unpinned => ("unpinned", None, None),
            State::Pinned => ("pinned", None, None),
        };
        {
            let mut t = self.tally();
            match action {
                Action::Load if *state == State::Pinned => t.counts.verified += 1,
                Action::Load | Action::PinAndLoad => {}
                Action::Warn => {
                    t.counts.warned += 1;
                    t.notes.push(format!("{id} {}", describe(state, which)));
                }
                Action::LeaveOut => {
                    t.counts.left_out += 1;
                    t.notes
                        .push(format!("{id} was left out: it {}", describe(state, which)));
                }
            }
        }
        if action != Action::Load
            && let Some(audit) = &self.audit
        {
            audit.record(AuditEvent::ExtensionIntegrity {
                extension: kind.as_str().into(),
                id: name.to_owned(),
                outcome: outcome.into(),
                expected,
                observed,
                action: if action == Action::LeaveOut {
                    "left_out"
                } else {
                    "loaded"
                }
                .into(),
            });
        }
        action
    }

    /// What advisories say about an extension: one revoked (malicious, or
    /// withdrawn by its publisher) may not be used in any mode; one with a
    /// known vulnerability is reported. Whether it may be used.
    fn advised(&self, kind: Kind, name: &str, hits: &[Hit]) -> bool {
        let Some(worst) = hits.first() else {
            return true;
        };
        let revoked = worst.severity == Severity::Revoked;
        let id = format!("{}:{name}", kind.as_str());
        {
            let mut t = self.tally();
            if revoked {
                t.counts.left_out += 1;
                t.notes.push(format!(
                    "{id} was left out: revoked by {} ({}; {})",
                    worst.id, worst.summary, worst.matched
                ));
            } else {
                t.counts.warned += 1;
                t.notes.push(format!(
                    "{id} has a known vulnerability: {} ({}; {})",
                    worst.id, worst.summary, worst.matched
                ));
            }
        }
        if let Some(audit) = &self.audit {
            audit.record(AuditEvent::ExtensionIntegrity {
                extension: kind.as_str().into(),
                id: name.to_owned(),
                outcome: if revoked { "revoked" } else { "vulnerable" }.into(),
                expected: None,
                observed: Some(worst.id.clone()),
                action: if revoked { "left_out" } else { "loaded" }.into(),
            });
        }
        !revoked
    }

    /// Whether a skill or plugin may load; pins it on first use.
    fn admit(&self, item: &Item) -> bool {
        if let Ok(content) = &item.content
            && !self.advised(item.kind, &item.name, &self.advisories.content(content))
        {
            return false;
        }
        let lock = match item.scope {
            Scope::Project => &self.project,
            Scope::Owner => &self.owner,
        };
        let state = state(item, lock);
        match self.judge(item.kind, &item.name, item.scope, &state) {
            Action::LeaveOut => false,
            Action::PinAndLoad => {
                let mut t = self.tally();
                match item.entry(false) {
                    Some(entry) => {
                        t.pins.push((item.kind, entry));
                        t.counts.first_use += 1;
                    }
                    None => t
                        .notes
                        .push(format!("{} cannot be read to pin it", item.id())),
                }
                true
            }
            Action::Load | Action::Warn => true,
        }
    }

    /// The installed plugins that may load.
    pub(crate) fn plugins(
        &self,
        packages: Vec<crate::plugins::Package>,
    ) -> Vec<crate::plugins::Package> {
        packages
            .into_iter()
            .filter(|p| self.admit(&plugin_item(p)))
            .collect()
    }

    /// Leaves out the skills that may not load and seals the rest to the
    /// files they were checked with. Skills inside an admitted plugin are
    /// covered by its pin and sealed too.
    pub(crate) fn skills(&self, catalog: &mut Catalog) {
        let canonical_ws = self
            .ws
            .canonicalize()
            .unwrap_or_else(|_| self.ws.to_path_buf());
        let skills: Vec<Skill> = catalog.skills().to_vec();
        for skill in &skills {
            let (admitted, scan) = match skill_item(&self.ws, &canonical_ws, skill) {
                Some((item, scan)) => (self.admit(&item), scan),
                None => (true, tree::scan(&skill.root, tree::Limits::PACKAGE).ok()),
            };
            if !admitted {
                catalog.remove(
                    &skill.id,
                    "it differs from its pin (`declass extensions verify`)",
                );
                continue;
            }
            if let Some(scan) = scan {
                catalog.seal(
                    &skill.id,
                    scan.files
                        .into_iter()
                        .map(|(path, hash)| (path, hex::encode(hash)))
                        .collect(),
                );
            }
        }
    }

    /// Writes pins taken on first use, records the summary and returns the
    /// lines to show the operator (none when everything matched). What is
    /// checked later in the run (servers listing their tools again) goes to
    /// the audit log only.
    pub(crate) fn finish(&self) -> Result<Vec<String>> {
        let tally = {
            let mut t = self.tally();
            Tally {
                pins: std::mem::take(&mut t.pins),
                mcp_pins: std::mem::take(&mut t.mcp_pins),
                first_launch: BTreeMap::new(),
                offered: BTreeMap::new(),
                counts: std::mem::take(&mut t.counts),
                notes: std::mem::take(&mut t.notes),
            }
        };
        if !tally.pins.is_empty() || !tally.mcp_pins.is_empty() {
            let _guard = writer_guard(&self.owner_path)?;
            // Another session may have pinned meanwhile: add only what is
            // still missing, never replace a pin.
            let mut lock = match Loaded::read(&self.owner_path, Scope::Owner) {
                Loaded::Valid(lock) => lock,
                Loaded::Missing => Lock::new(),
                Loaded::Invalid(_) => return Ok(tally.notes),
            };
            let mut written = Vec::new();
            for (kind, entry) in &tally.pins {
                if lock.entry(*kind, &entry.name).is_none() {
                    lock.upsert(*kind, entry.clone());
                    written.push((*kind, entry.clone()));
                }
            }
            let mut servers = Vec::new();
            for server in &tally.mcp_pins {
                if lock.mcp(&server.name).is_none() {
                    lock.upsert_mcp(server.clone());
                    servers.push(server.clone());
                }
            }
            if !written.is_empty() || !servers.is_empty() {
                save(&self.owner_path, &lock, Scope::Owner)?;
                record_pins(&written, "first_use")?;
                record_server_pins(&servers, "first_use")?;
            }
        }
        if let Some(audit) = &self.audit {
            audit.record(AuditEvent::IntegritySummary {
                mode: self.mode.as_str().into(),
                verified: tally.counts.verified,
                first_use: tally.counts.first_use,
                warned: tally.counts.warned,
                left_out: tally.counts.left_out,
            });
        }
        let mut lines = Vec::new();
        if tally.counts.first_use > 0 {
            lines.push(format!(
                "extensions: pinned {} extension(s) on first use in {}",
                tally.counts.first_use,
                self.owner_path.display()
            ));
        }
        lines.extend(tally.notes.into_iter().map(|n| format!("extensions: {n}")));
        Ok(lines)
    }
}

/// The launch of a stdio server as it would run: its command line, the
/// program it resolves to (relative to the workspace, else on `PATH`) and
/// that program's digest, and the package a launcher in it runs.
fn observe_launch(ws: &Path, argv: &[String]) -> (Launched, Option<PathBuf>, Option<String>) {
    let program = argv.first().map(String::as_str).unwrap_or_default();
    let resolved = if program.contains('/') && !Path::new(program).is_absolute() {
        Some(ws.join(program)).filter(|p| p.is_file())
    } else {
        declass_lsp::servers::resolve(program, std::env::var_os("PATH").as_deref())
    };
    let mut problem = None;
    let executable =
        resolved
            .as_ref()
            .and_then(|path| match tree::file_digest(path, MAX_EXECUTABLE) {
                Ok(sha256) => Some(Executable {
                    path: path
                        .canonicalize()
                        .unwrap_or_else(|_| path.clone())
                        .display()
                        .to_string(),
                    sha256,
                }),
                Err(e) => {
                    problem = Some(format!("its program cannot be read: {e}"));
                    None
                }
            });
    let launch = launcher::classify(argv);
    if let Some(l) = launch.as_ref().filter(|l| l.floating) {
        problem = Some(format!(
            "`{}` runs {} without a pinned version, so the registry decides what runs (pin one, e.g. {}@<version>)",
            l.launcher, l.package.identifier, l.package.identifier
        ));
    }
    (
        Launched {
            command: argv.to_vec(),
            executable,
            package: launch.map(|l| l.package),
        },
        resolved,
        problem,
    )
}

/// The largest program hashed.
const MAX_EXECUTABLE: u64 = 1024 * 1024 * 1024;

/// How a server's launch differs from `pin` (owner lock: everything; a
/// project lock pins no executables or directories).
pub(crate) fn launch_differences(pin: &McpServer, seen: &Launched) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if !pin.command.is_empty() && pin.command != seen.command {
        out.push((
            format!("command {}", pin.command.join(" ")),
            format!("command {}", seen.command.join(" ")),
        ));
    }
    if let Some(p) = &pin.executable {
        match &seen.executable {
            Some(e) if e.path == p.path && e.sha256 == p.sha256 => {}
            Some(e) => out.push((
                format!("program {} {}", p.path, p.sha256),
                format!("program {} {}", e.path, e.sha256),
            )),
            None => out.push((format!("program {}", p.path), "no readable program".into())),
        }
    }
    if let Some(p) = &pin.package
        && seen.package.as_ref() != Some(p)
    {
        out.push((
            format!(
                "package {}@{}",
                p.identifier,
                p.version.clone().unwrap_or_default()
            ),
            match &seen.package {
                Some(s) => format!(
                    "package {}@{}",
                    s.identifier,
                    s.version.clone().unwrap_or_default()
                ),
                None => "no package".into(),
            },
        ));
    }
    for root in &pin.roots {
        let now = tree::scan(Path::new(&root.path), tree::Limits::INSTALL)
            .map_err(|e| e.to_string())
            .and_then(|s| s.content_digest().map_err(|e| e.to_string()));
        match now {
            Ok(d) if d == root.content_digest => {}
            Ok(d) => out.push((
                format!("directory {} {}", root.path, root.content_digest),
                format!("directory {} {d}", root.path),
            )),
            Err(e) => out.push((
                format!("directory {} {}", root.path, root.content_digest),
                format!("directory {} unreadable: {e}", root.path),
            )),
        }
    }
    out
}

fn state_of(differences: Vec<(String, String)>, pinned: bool) -> State {
    if differences.is_empty() {
        if pinned {
            State::Pinned
        } else {
            State::Unpinned
        }
    } else {
        let (a, b): (Vec<String>, Vec<String>) = differences.into_iter().unzip();
        State::Changed(a.join("; "), b.join("; "))
    }
}

impl declass_agent::mcp::Admission for Gate {
    fn launch(&self, cfg: &ServerConfig, argv: Vec<String>) -> Result<Vec<String>, String> {
        let (seen, resolved, problem) = observe_launch(&self.ws, &argv);
        if let Some(p) = &seen.package {
            let hits =
                self.advisories
                    .package(&p.registry_type, &p.identifier, p.version.as_deref());
            if !self.advised(Kind::Mcp, &cfg.name, &hits) {
                return Err(format!(
                    "it runs {}@{}, which an advisory revokes ({})",
                    p.identifier,
                    p.version.clone().unwrap_or_default(),
                    hits[0].id
                ));
            }
        }
        let owner_pin = self.owner.lock().and_then(|l| l.mcp(&cfg.name));
        let project_pin = self.project.lock().and_then(|l| l.mcp(&cfg.name));
        // The project's requirements first: it may only add them.
        if let Some(pin) = project_pin {
            let state = state_of(launch_differences(pin, &seen), true);
            if self.judge(Kind::Mcp, &cfg.name, Scope::Project, &state) == Action::LeaveOut {
                return Err(format!(
                    "it differs from the project lock: {}",
                    detail(&state)
                ));
            }
        }
        if let Some(problem) = problem {
            let floating = State::Unreadable(problem.clone());
            if self.judge(Kind::Mcp, &cfg.name, Scope::Owner, &floating) == Action::LeaveOut {
                return Err(problem);
            }
        }
        let state = match owner_pin {
            Some(pin) => state_of(launch_differences(pin, &seen), true),
            None => State::Unpinned,
        };
        match self.judge(Kind::Mcp, &cfg.name, Scope::Owner, &state) {
            Action::LeaveOut => {
                return Err(format!("it differs from your lock: {}", detail(&state)));
            }
            Action::PinAndLoad => {
                self.tally().first_launch.insert(cfg.name.clone(), seen);
            }
            Action::Load | Action::Warn => {}
        }
        // Run what was checked, not a later lookup on PATH.
        let mut argv = argv;
        if let (Some(first), Some(path)) = (argv.first_mut(), resolved) {
            *first = path.display().to_string();
        }
        Ok(argv)
    }

    fn tools(
        &self,
        cfg: &ServerConfig,
        listing: &declass_agent::mcp::Listing<'_>,
    ) -> Result<(), String> {
        let raw: Vec<serde_json::Value> = listing.tools.iter().map(|t| t.raw.clone()).collect();
        let observed = toolset::toolset(&raw);
        keep_observed(&cfg.name, &raw, &observed);
        let url = match &cfg.launch {
            Launch::Url(u) => Some(u.clone()),
            Launch::Command { .. } => None,
        };
        let mut hits = self
            .advisories
            .tools(&observed.digest, observed.tools.iter());
        if let Some(u) = &url {
            hits.extend(self.advisories.url(u));
        }
        hits.sort_by_key(|h| std::cmp::Reverse(h.severity));
        if !self.advised(Kind::Mcp, &cfg.name, &hits) {
            return Err(format!("an advisory revokes it ({})", hits[0].id));
        }
        let differences = |pin: &McpServer| {
            let mut out = Vec::new();
            if let (Some(pinned), Some(now)) = (&pin.url, &url)
                && pinned != now
            {
                out.push((format!("url {pinned}"), format!("url {now}")));
            }
            if let Some(t) = &pin.toolset
                && t.digest != observed.digest
            {
                let c = toolset::changes(&t.tools, &observed.tools);
                out.push((
                    format!("tools {}", t.digest),
                    format!(
                        "tools {} (changed: {}; added: {}; removed: {})",
                        observed.digest,
                        listed(&c.changed),
                        listed(&c.added),
                        listed(&c.removed)
                    ),
                ));
            }
            out
        };
        if let Some(pin) = self.project.lock().and_then(|l| l.mcp(&cfg.name)) {
            let state = state_of(differences(pin), true);
            if self.judge(Kind::Mcp, &cfg.name, Scope::Project, &state) == Action::LeaveOut {
                return Err(format!(
                    "its tools differ from the project lock: {}",
                    detail(&state)
                ));
            }
        }
        match self.owner.lock().and_then(|l| l.mcp(&cfg.name)) {
            Some(pin) => {
                let state = state_of(differences(pin), true);
                if self.judge(Kind::Mcp, &cfg.name, Scope::Owner, &state) == Action::LeaveOut {
                    return Err(format!(
                        "its tools differ from your lock: {}",
                        detail(&state)
                    ));
                }
            }
            None => {
                // A stdio server was judged at launch; an HTTP server is
                // judged here, once.
                let first = match &cfg.launch {
                    Launch::Command { .. } => self.tally().first_launch.remove(&cfg.name),
                    Launch::Url(_) => {
                        match self.judge(Kind::Mcp, &cfg.name, Scope::Owner, &State::Unpinned) {
                            Action::LeaveOut => {
                                return Err("it is not pinned in your lock".into());
                            }
                            Action::PinAndLoad => Some(Launched {
                                command: Vec::new(),
                                executable: None,
                                package: None,
                            }),
                            _ => None,
                        }
                    }
                };
                if let Some(seen) = first {
                    let pin = server_pin(cfg, seen, listing, &observed, false);
                    let mut t = self.tally();
                    t.mcp_pins.push(pin);
                    t.counts.first_use += 1;
                }
            }
        }
        self.tally()
            .offered
            .insert(cfg.name.clone(), observed.digest);
        Ok(())
    }

    fn relisted(
        &self,
        cfg: &ServerConfig,
        listing: &declass_agent::mcp::Listing<'_>,
        trigger: &str,
    ) -> bool {
        let raw: Vec<serde_json::Value> = listing.tools.iter().map(|t| t.raw.clone()).collect();
        let observed = toolset::toolset(&raw);
        let Some(offered) = self.tally().offered.get(&cfg.name).copied() else {
            return true;
        };
        if offered == observed.digest {
            return true;
        }
        keep_observed(&cfg.name, &raw, &observed);
        let withhold = self.mode == Mode::Enforce;
        if let Some(audit) = &self.audit {
            audit.record(AuditEvent::ToolsetChanged {
                server: cfg.name.clone(),
                offered: offered.to_string(),
                observed: observed.digest.to_string(),
                trigger: trigger.into(),
                action: if withhold { "withheld" } else { "noted" }.into(),
            });
        }
        !withhold
    }
}

/// The pin of a server as it was seen.
pub(crate) fn server_pin(
    cfg: &ServerConfig,
    seen: Launched,
    listing: &declass_agent::mcp::Listing<'_>,
    observed: &toolset::Toolset,
    explicit: bool,
) -> McpServer {
    let (transport, url) = match &cfg.launch {
        Launch::Url(u) => (Transport::Http, Some(u.clone())),
        Launch::Command { .. } => (Transport::Stdio, None),
    };
    McpServer {
        name: cfg.name.clone(),
        source: if cfg.name.starts_with("p_") {
            "plugin".into()
        } else {
            "owner-config".into()
        },
        transport,
        command: seen.command,
        url,
        executable: seen.executable,
        roots: Vec::new(),
        package: seen.package,
        server_info: (!listing.server_name.is_empty()).then(|| ServerInfo {
            name: listing.server_name.to_owned(),
            version: (!listing.server_version.is_empty())
                .then(|| listing.server_version.to_owned()),
        }),
        toolset: Some(ToolsetPin {
            algorithm: toolset::ALGORITHM.into(),
            digest: observed.digest,
            protocol_version: (!listing.protocol_version.is_empty())
                .then(|| listing.protocol_version.to_owned()),
            tools: observed.tools.clone(),
        }),
        explicit,
    }
}

pub(crate) fn listed(names: &[String]) -> String {
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

fn detail(state: &State) -> String {
    match state {
        State::Changed(pinned, now) => format!("pinned {pinned}, now {now}"),
        State::Unreadable(why) => why.clone(),
        _ => String::new(),
    }
}

/// Where the tool definitions servers listed are kept, by server.
pub(crate) fn observed_dir(server: &str) -> PathBuf {
    declass_config::owner_state_dir()
        .join("integrity/toolsets")
        .join(&hex::encode(Sha256Digest::of(server.as_bytes()).0)[..16])
}

/// How many listings of each server are kept.
const KEEP_OBSERVED: usize = 5;

/// Keeps what a server listed (for `declass extensions diff`), owner-only;
/// the oldest beyond the last [`KEEP_OBSERVED`] are removed. Best effort.
fn keep_observed(server: &str, raw: &[serde_json::Value], observed: &toolset::Toolset) {
    let dir = observed_dir(server);
    if declass_fs::private::ensure_private_dir(&dir).is_err() {
        return;
    }
    let body = serde_json::json!({
        "server": server,
        "algorithm": toolset::ALGORITHM,
        "digest": observed.digest.to_string(),
        "tools": raw,
    });
    let name = format!("{}.json", hex::encode(observed.digest.0));
    let Ok(text) = serde_json::to_vec_pretty(&body) else {
        return;
    };
    let _ = declass_fs::private::write_private(&dir.join(name), &text);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    files.sort();
    let excess = files.len().saturating_sub(KEEP_OBSERVED);
    for (_, path) in files.into_iter().take(excess) {
        let _ = std::fs::remove_file(path);
    }
}

/// Records pins of MCP servers in the owner's change log.
pub(crate) fn record_server_pins(servers: &[McpServer], by: &str) -> Result<()> {
    if servers.is_empty() {
        return Ok(());
    }
    let path = crate::config_audit_path();
    if let Some(parent) = path.parent() {
        declass_fs::private::ensure_private_dir(parent)?;
    }
    let mut log = declass_boundary::audit::AuditLog::open(&path)?;
    for s in servers {
        log.event(AuditEvent::ExtensionPinned {
            extension: Kind::Mcp.as_str().into(),
            id: s.name.clone(),
            digest: s
                .toolset
                .as_ref()
                .map(|t| t.digest.to_string())
                .unwrap_or_default(),
            by: by.into(),
        })?;
    }
    Ok(())
}

fn describe(state: &State, which: &str) -> String {
    match state {
        State::Changed(pinned, now) => {
            format!("differs from {which} (pinned {pinned}, now {now})")
        }
        State::Unreadable(why) => format!("cannot be checked against {which}: {why}"),
        State::Unpinned => format!("is not pinned in {which}"),
        State::LockInvalid => format!("cannot be checked: {which} cannot be used"),
        State::Pinned => format!("matches {which}"),
    }
}

/// Admits every server and records how each launched and what it listed,
/// as pins (`declass extensions lock mcp:<name>`, `verify --live`).
pub(crate) struct Recorder {
    ws: PathBuf,
    explicit: bool,
    launched: Mutex<BTreeMap<String, Launched>>,
    seen: Mutex<BTreeMap<String, McpServer>>,
}

impl Recorder {
    pub(crate) fn new(ws: &Path, explicit: bool) -> Self {
        Recorder {
            ws: ws.to_path_buf(),
            explicit,
            launched: Mutex::default(),
            seen: Mutex::default(),
        }
    }

    /// Each server that started and listed its tools, as its pin.
    pub(crate) fn pins(&self) -> BTreeMap<String, McpServer> {
        std::mem::take(
            &mut self
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

impl declass_agent::mcp::Admission for Recorder {
    fn launch(&self, cfg: &ServerConfig, argv: Vec<String>) -> Result<Vec<String>, String> {
        let (seen, resolved, _) = observe_launch(&self.ws, &argv);
        self.launched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(cfg.name.clone(), seen);
        let mut argv = argv;
        if let (Some(first), Some(path)) = (argv.first_mut(), resolved) {
            *first = path.display().to_string();
        }
        Ok(argv)
    }

    fn tools(
        &self,
        cfg: &ServerConfig,
        listing: &declass_agent::mcp::Listing<'_>,
    ) -> Result<(), String> {
        let raw: Vec<serde_json::Value> = listing.tools.iter().map(|t| t.raw.clone()).collect();
        let observed = toolset::toolset(&raw);
        keep_observed(&cfg.name, &raw, &observed);
        let seen = self
            .launched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&cfg.name)
            .unwrap_or(Launched {
                command: Vec::new(),
                executable: None,
                package: None,
            });
        let pin = server_pin(cfg, seen, listing, &observed, self.explicit);
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(cfg.name.clone(), pin);
        Ok(())
    }
}

/// How a server pinned in `lock` differs from how it starts now, without
/// starting it: its command line, program, package and pinned directories
/// (tool definitions need the server running: `verify --live`).
pub(crate) fn server_findings(
    ws: &Path,
    servers: &[ServerConfig],
    owner: &Loaded,
    project: &Loaded,
    owner_shown: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let finding = |rule, level, name: &str, message: String| Finding {
        rule,
        level,
        kind: "mcp",
        id: name.to_owned(),
        message,
        location: None,
    };
    for cfg in servers {
        let Launch::Command { command, args } = &cfg.launch else {
            continue;
        };
        let argv: Vec<String> = std::iter::once(command.clone())
            .chain(args.iter().cloned())
            .collect();
        let (seen, _, problem) = observe_launch(ws, &argv);
        if let Some(problem) = problem {
            findings.push(finding(
                Rule::FloatingLauncher,
                Level::Warning,
                &cfg.name,
                problem,
            ));
        }
        for (loaded, which) in [(project, "the project lock"), (owner, "your lock")] {
            if let Some(pin) = loaded.lock().and_then(|l| l.mcp(&cfg.name)) {
                let d = launch_differences(pin, &seen);
                if !d.is_empty() {
                    findings.push(finding(
                        Rule::DigestMismatch,
                        Level::Error,
                        &cfg.name,
                        format!("differs from {which}: {}", detail(&state_of(d, true))),
                    ));
                }
            }
        }
        if owner.lock().is_some_and(|l| l.mcp(&cfg.name).is_none()) {
            findings.push(finding(
                Rule::Unpinned,
                Level::Warning,
                &cfg.name,
                "not pinned in your lock (pinned on first use, or with `declass extensions lock mcp:<name>`)".into(),
            ));
        }
    }
    if let Some(lock) = owner.lock() {
        for pin in &lock.mcp_servers {
            if !servers.iter().any(|s| s.name == pin.name) {
                findings.push(Finding {
                    rule: Rule::PinnedMissing,
                    level: Level::Warning,
                    kind: "mcp",
                    id: pin.name.clone(),
                    message: "pinned but not configured".into(),
                    location: Some(owner_shown.to_owned()),
                });
            }
        }
    }
    findings
}

/// How the tools servers list now differ from their pins (`verify --live`).
pub(crate) fn toolset_findings(
    pins: &BTreeMap<String, McpServer>,
    owner: &Loaded,
    project: &Loaded,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (name, now) in pins {
        let Some(observed) = &now.toolset else {
            continue;
        };
        for (loaded, which) in [(project, "the project lock"), (owner, "your lock")] {
            let Some(pinned) = loaded
                .lock()
                .and_then(|l| l.mcp(name))
                .and_then(|p| p.toolset.as_ref())
            else {
                continue;
            };
            if pinned.digest != observed.digest {
                let c = toolset::changes(&pinned.tools, &observed.tools);
                findings.push(Finding {
                    rule: Rule::ToolsetChanged,
                    level: Level::Error,
                    kind: "mcp",
                    id: name.clone(),
                    message: format!(
                        "its tools differ from {which} (changed: {}; added: {}; removed: {}); `declass extensions diff mcp:{name}` shows them",
                        listed(&c.changed),
                        listed(&c.added),
                        listed(&c.removed)
                    ),
                    location: None,
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_follow_the_mode_the_scope_and_the_lock() {
        use Action::*;
        let changed = State::Changed("a".into(), "b".into());
        let cases = [
            // mode, first use, scope, state, lock exists → action
            (Mode::Warn, true, Scope::Owner, State::Pinned, true, Load),
            (
                Mode::Enforce,
                true,
                Scope::Project,
                State::Pinned,
                true,
                Load,
            ),
            (Mode::Warn, true, Scope::Owner, changed.clone(), true, Warn),
            (
                Mode::Enforce,
                true,
                Scope::Owner,
                changed.clone(),
                true,
                LeaveOut,
            ),
            (
                Mode::Enforce,
                true,
                Scope::Project,
                changed.clone(),
                true,
                LeaveOut,
            ),
            (
                Mode::Enforce,
                true,
                Scope::Owner,
                State::Unreadable("x".into()),
                true,
                LeaveOut,
            ),
            // Your own extensions are pinned the first time, unless that is off.
            (
                Mode::Warn,
                true,
                Scope::Owner,
                State::Unpinned,
                false,
                PinAndLoad,
            ),
            (
                Mode::Enforce,
                true,
                Scope::Owner,
                State::Unpinned,
                true,
                PinAndLoad,
            ),
            (Mode::Warn, false, Scope::Owner, State::Unpinned, true, Warn),
            (
                Mode::Enforce,
                false,
                Scope::Owner,
                State::Unpinned,
                true,
                LeaveOut,
            ),
            // A project's skills: never pinned on first use; held to its
            // lock when it has one.
            (
                Mode::Enforce,
                true,
                Scope::Project,
                State::Unpinned,
                true,
                LeaveOut,
            ),
            (
                Mode::Warn,
                true,
                Scope::Project,
                State::Unpinned,
                true,
                Warn,
            ),
            (
                Mode::Enforce,
                true,
                Scope::Project,
                State::Unpinned,
                false,
                Load,
            ),
            (
                Mode::Warn,
                true,
                Scope::Owner,
                State::LockInvalid,
                false,
                Warn,
            ),
        ];
        for (mode, first_use, scope, state, exists, want) in cases {
            assert_eq!(
                decide(mode, first_use, scope, &state, exists),
                want,
                "{mode:?} {first_use} {scope:?} {state:?} {exists}"
            );
        }
    }
}
