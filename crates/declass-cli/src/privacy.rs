// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline policy preview. Workspace files are classified from names and metadata;
//! neither contents nor model clients are opened.
use crate::{Mode, policy};
use anyhow::Result;
use declass_boundary::policy::{Policy, glob_match, is_env_template};
use declass_config::Config;
use declass_provider::{Role, endpoint::ApprovedEndpoint};
use rustix::fs::{AtFlags, Dir, FileType, Mode as FsMode, OFlags};
use serde::Serialize;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How much of the workspace a walk may visit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// Entries of every kind, directories and skipped directories included.
    pub(crate) entries: usize,
    /// Directory levels below the workspace.
    pub(crate) depth: usize,
}

/// The preview's bounds (docs/OPERATIONS.md, "Preview privacy before starting").
const PREVIEW: Limits = Limits {
    entries: 20_000,
    depth: 48,
};
pub(crate) const SKIPPED: &[&str] = &[
    ".git",
    ".declass",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
];
const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
    /// Preview this mode; clearance.required still applies.
    #[arg(long, value_enum)]
    mode: Option<Mode>,
}

#[derive(Serialize)]
pub(crate) struct Report {
    schema: u32,
    mode: &'static str,
    scope: &'static str,
    complete: bool,
    destinations: Vec<Destination>,
    command_network: String,
    command_registries: Vec<String>,
    web_enabled: bool,
    web_fetch: &'static str,
    web_private_hosts: Vec<String>,
    search_origins: Vec<String>,
    mcp: Vec<Mcp>,
    exceptions: Vec<Exception>,
    excluded_directories: &'static [&'static str],
    files: Vec<FileRule>,
    warnings: Vec<String>,
}
#[derive(Serialize)]
struct Destination {
    role: &'static str,
    origin: Option<String>,
    enabled: bool,
    admitted: bool,
    trust: &'static str,
}
#[derive(Serialize)]
struct Mcp {
    name: String,
    origin: Option<String>,
    network: bool,
    enabled: bool,
    valid: bool,
}
#[derive(Serialize)]
struct Exception {
    setting: &'static str,
    origin: String,
}
#[derive(Serialize)]
pub(crate) struct FileRule {
    pub(crate) path: String,
    pub(crate) disposition: &'static str,
    pub(crate) rule: String,
}

/// `text` (a path or a rule) for one line of a report: control and invisible
/// characters escaped as `escape_debug` writes them, so a name can neither
/// start a line of its own nor hide, and quotes left as they are.
pub(crate) fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(['\'', '"']) {
        out.extend(rest[..i].escape_debug());
        out.push_str(&rest[i..=i]);
        rest = &rest[i + 1..];
    }
    out.extend(rest.escape_debug());
    out
}

fn origin(raw: &str) -> Option<String> {
    url::Url::parse(raw)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .map(|u| u.origin().ascii_serialization())
}
fn mcp_origin(server: &declass_mcp::ServerConfig) -> Option<String> {
    match &server.launch {
        declass_mcp::Launch::Url(url) => origin(url),
        _ => None,
    }
}
fn search_origins(cfg: &Config, ws: &Path, frontier_url: &str) -> Result<Vec<String>> {
    use declass_web::search::Backend;
    let key_env = cfg.str("frontier.api_key_env")?;
    let choice = crate::web::choose(
        cfg,
        Some(crate::web::Frontier {
            base_url: frontier_url,
            key_env: &key_env,
        }),
        &|name| std::env::var(name).ok(),
        ws,
    )?;
    let mut origins = match choice.backend {
        Some(Backend::Native(n)) => n
            .sources
            .iter()
            .map(|s| s.endpoint.origin().ascii_serialization())
            .collect(),
        Some(
            Backend::Zai { endpoint, .. }
            | Backend::ZaiPlan { endpoint, .. }
            | Backend::Brave { endpoint, .. }
            | Backend::Wikipedia { endpoint },
        ) => vec![endpoint.origin().ascii_serialization()],
        Some(Backend::Searxng { base }) => vec![base.origin().ascii_serialization()],
        None => Vec::new(),
    };
    origins.sort();
    origins.dedup();
    Ok(origins)
}
/// The trust of a role whose endpoint nobody chose yet (there is no default):
/// nothing to refuse, and nothing that would be contacted.
const NOT_SET_UP: &str = "not set up";

fn endpoint(raw: &str, role: Role, enabled: bool) -> Destination {
    let local = matches!(role, Role::Local { .. });
    if raw.trim().is_empty() {
        return Destination {
            role: if local { "local" } else { "frontier" },
            origin: None,
            enabled,
            admitted: false,
            trust: NOT_SET_UP,
        };
    }
    let admitted = ApprovedEndpoint::new(raw, &role).is_ok();
    // Never echo URL credentials, query strings, fragments or API path segments.
    let origin = origin(raw);
    let trust = if !admitted {
        "refused"
    } else if !local {
        "frontier provider"
    } else {
        let Role::Local {
            allowlist,
            allow_plaintext,
        } = &role
        else {
            unreachable!()
        };
        declass_provider::endpoint::check_local_endpoint(raw, allowlist, *allow_plaintext)
            .map(|t| t.as_str())
            .unwrap_or("refused")
    };
    Destination {
        role: if local { "local" } else { "frontier" },
        origin,
        enabled,
        admitted,
        trust,
    }
}

fn classify(path: &Path, p: &Policy, mode: Mode) -> (&'static str, String) {
    if mode == Mode::Passthrough {
        return ("unfiltered", "privacy boundary disabled".into());
    }
    if mode == Mode::TopClearance {
        return ("local-only", "top-clearance mode".into());
    }
    let name = path.to_string_lossy();
    for (setting, globs, disposition) in [
        ("ip.sealed", &p.sealed, "sealed"),
        ("ip.interface_only", &p.interface_only, "interface-only"),
        (
            "sensitivity.protected_paths",
            &p.protected_paths,
            "sensitive",
        ),
        ("sensitivity.globs", &p.sensitive_globs, "sensitive"),
    ] {
        if setting == "sensitivity.globs" && is_env_template(path) {
            continue;
        }
        if let Some(glob) = globs.iter().find(|g| glob_match(g, &name)) {
            return (disposition, format!("{setting}: {glob}"));
        }
    }
    (
        "content-checks",
        if is_env_template(path) {
            "environment template; runtime content checks apply"
        } else {
            "runtime content checks apply"
        }
        .into(),
    )
}

/// One entry a walk found.
pub(crate) enum Entry<'a> {
    /// A regular file, with the directory that holds it, opened without
    /// following links from the workspace root down.
    File {
        path: &'a str,
        name: &'a OsStr,
        dir: &'a Arc<OwnedFd>,
    },
    /// A symlink or special file: listed, never followed or opened.
    Other { path: &'a str },
}

struct Walker<'v> {
    limits: Limits,
    seen: usize,
    complete: bool,
    visit: &'v mut dyn FnMut(Entry<'_>),
}

impl Walker<'_> {
    fn walk(&mut self, fd: &Arc<OwnedFd>, parent: &Path, depth: usize) -> std::io::Result<()> {
        if depth > self.limits.depth {
            self.complete = false;
            return Ok(());
        }
        for entry in Dir::read_from(&**fd)? {
            let entry = entry?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            self.seen += 1;
            if self.seen > self.limits.entries {
                self.complete = false;
                break;
            }
            let name = OsStr::from_bytes(raw);
            let path = parent.join(name);
            // Fail visibly on non-UTF8 names: lossy names cannot prove which rule matched.
            let Some(text) = path.to_str() else {
                self.complete = false;
                continue;
            };
            // The directory entry's type when the filesystem records it, else
            // the entry itself (never what a link points to).
            let kind = match entry.file_type() {
                FileType::Unknown => {
                    match rustix::fs::statat(&**fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                        Ok(s) => FileType::from_raw_mode(s.st_mode),
                        Err(_) => {
                            self.complete = false;
                            continue;
                        }
                    }
                }
                known => known,
            };
            if kind == FileType::Directory {
                if SKIPPED.contains(&name.to_str().unwrap_or_default()) {
                    continue;
                }
                match rustix::fs::openat(&**fd, name, DIR_FLAGS, FsMode::empty()) {
                    Ok(child) => {
                        if self.walk(&Arc::new(child), &path, depth + 1).is_err() {
                            self.complete = false;
                        }
                    }
                    Err(_) => self.complete = false,
                }
                continue;
            }
            (self.visit)(if kind == FileType::RegularFile {
                Entry::File {
                    path: text,
                    name,
                    dir: fd,
                }
            } else {
                Entry::Other { path: text }
            });
        }
        Ok(())
    }
}

/// Visits the workspace's files without following links or entering the
/// excluded directories, within `limits`. Names and metadata only: no file is
/// opened. Returns whether the walk was complete (no limit reached, no
/// unreadable directory, no non-UTF8 name).
pub(crate) fn walk(ws: &Path, limits: Limits, visit: &mut dyn FnMut(Entry<'_>)) -> Result<bool> {
    let root = Arc::new(rustix::fs::open(ws, DIR_FLAGS, FsMode::empty())?);
    let mut walker = Walker {
        limits,
        seen: 0,
        complete: true,
        visit,
    };
    if walker.walk(&root, Path::new(""), 0).is_err() {
        walker.complete = false;
    }
    Ok(walker.complete)
}

/// The rule for a workspace path: path rules, then the persistent
/// classification of files derived from sensitive data.
pub(crate) struct Classifier<'a> {
    policy: &'a Policy,
    mode: Mode,
    /// Derived files, or `None` when their classification cannot be read.
    derived: Option<HashSet<PathBuf>>,
}

impl<'a> Classifier<'a> {
    pub(crate) fn new(ws: &Path, policy: &'a Policy, mode: Mode) -> Self {
        Self {
            policy,
            mode,
            derived: declass_boundary::derived::workspace_paths(ws).ok(),
        }
    }

    /// False when derived-file classifications could not be read: files
    /// without a path rule are then of unknown classification.
    pub(crate) fn derived_known(&self) -> bool {
        self.derived.is_some()
    }

    pub(crate) fn classify(&self, path: &str) -> (&'static str, String) {
        let (disposition, rule) = classify(Path::new(path), self.policy, self.mode);
        if disposition != "content-checks" {
            return (disposition, rule);
        }
        match &self.derived {
            Some(paths) if self.mode == Mode::Hybrid && paths.contains(Path::new(path)) => (
                "sensitive",
                "persistent classification: derived from sensitive data".into(),
            ),
            Some(_) => (disposition, rule),
            None => (
                "unknown",
                "derived classification unavailable; run startup requires recovery".into(),
            ),
        }
    }
}

/// The workspace's files with the rule that applies to each, sorted by path,
/// and whether the walk was complete. Names and metadata only: no file is opened.
pub(crate) struct Files {
    pub(crate) files: Vec<FileRule>,
    pub(crate) complete: bool,
    /// False when derived-file classifications could not be read.
    pub(crate) derived_known: bool,
}

pub(crate) fn inventory(ws: &Path, p: &Policy, mode: Mode) -> Result<Files> {
    let classifier = Classifier::new(ws, p, mode);
    let mut files = Vec::new();
    let complete = walk(ws, PREVIEW, &mut |entry| {
        files.push(match entry {
            Entry::File { path, .. } => {
                let (disposition, rule) = classifier.classify(path);
                FileRule {
                    path: path.to_owned(),
                    disposition,
                    rule,
                }
            }
            Entry::Other { path } => FileRule {
                path: path.to_owned(),
                disposition: "blocked",
                rule: "symlink or special file; not followed".into(),
            },
        })
    })?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Files {
        files,
        complete: complete && classifier.derived_known(),
        derived_known: classifier.derived_known(),
    })
}

pub(crate) fn collect(
    ws: &Path,
    cfg: &Config,
    mode: Mode,
    frontier_override: Option<&str>,
    local_override: Option<&str>,
) -> Result<Report> {
    let p = policy(cfg)?;
    let mut inventory = inventory(ws, &p, mode)?;
    let top = mode == Mode::TopClearance;
    let local_url = cfg.str("local.base_url")?;
    let frontier_url = cfg.str("frontier.base_url")?;
    let destinations = vec![
        endpoint(
            local_override.unwrap_or(&local_url),
            Role::Local {
                allowlist: cfg.list("local.allowlist")?,
                allow_plaintext: cfg.bool("local.allow_plaintext")?,
            },
            mode != Mode::Passthrough && cfg.bool("local.enabled")?,
        ),
        endpoint(
            frontier_override.unwrap_or(&frontier_url),
            Role::Frontier,
            !top,
        ),
    ];
    let mut mcp = crate::mcp::configured(cfg)
        .into_iter()
        .map(|(name, server)| match server {
            Ok((s, enabled)) => {
                let network = crate::mcp::reaches_network(&s);
                Mcp {
                    name,
                    origin: mcp_origin(&s),
                    network,
                    enabled: enabled && !(top && network),
                    valid: true,
                }
            }
            Err(_) => Mcp {
                name,
                origin: None,
                network: false,
                enabled: false,
                valid: false,
            },
        })
        .collect::<Vec<_>>();
    // Read installed plugin manifests, but never start their servers or load skills.
    let plugin_servers = if cfg.bool("extensions.plugins_enabled")? {
        crate::plugins::store()
            .and_then(|root| crate::plugins::active_packages(&root))
            .and_then(|packages| crate::plugins::servers(&packages, cfg))
    } else {
        Ok(Vec::new())
    };
    let plugin_error = plugin_servers.is_err();
    if let Ok(servers) = plugin_servers {
        for server in servers {
            let network = crate::mcp::reaches_network(&server);
            mcp.push(Mcp {
                origin: mcp_origin(&server),
                name: server.name,
                network,
                enabled: !(top && network),
                valid: true,
            });
        }
    }
    let exceptions = declass_config::REGISTRY
        .iter()
        .filter(|s| {
            !declass_config::is_template(s.key) && s.direction != declass_config::Direction::Any
        })
        .filter(|s| cfg.origin(s.key) != Some(declass_config::Origin::Default))
        .filter_map(|s| {
            let default = toml::from_str::<toml::Table>(&format!("v = {}", s.default))
                .ok()?
                .remove("v")?;
            declass_config::loosening(s, &default, cfg.value(s.key).ok()?)?;
            Some(Exception {
                setting: s.key,
                origin: format!("{:?}", cfg.origin(s.key)?),
            })
        })
        .collect();
    let mut warnings = Vec::new();
    if plugin_error {
        inventory.complete = false;
        warnings.push("Installed plugin server policies could not be inspected.".into());
    }
    if !inventory.derived_known {
        warnings.push("Derived-file classifications are unavailable or a sensitive command is pending; review local state before starting a run.".into());
    }
    if !inventory.complete {
        warnings.push("Inventory incomplete: entry/depth limit, unreadable directory, changed entry or non-UTF8 name.".into());
    }
    for d in &destinations {
        if d.enabled && d.trust == NOT_SET_UP {
            warnings.push(format!(
                "No {} model is set up yet: `declass setup` chooses one.",
                if d.role == "local" { "local" } else { "cloud" }
            ));
        } else if d.enabled && !d.admitted {
            warnings.push(format!(
                "{} endpoint is refused by current endpoint policy.",
                d.role
            ));
        }
        if d.enabled && d.trust == "allowlisted-plaintext-opted-in" {
            warnings.push(
                "Sensitive model traffic uses an owner-approved remote endpoint over plain HTTP."
                    .into(),
            );
        }
    }
    if mcp.iter().any(|s| !s.valid) {
        warnings.push("An MCP server configuration is invalid.".into());
    }
    if mode == Mode::Passthrough {
        warnings
            .push("Passthrough sends content to the frontier without the privacy boundary.".into());
    }
    if crate::local_enabled(cfg, mode).is_err() {
        inventory.complete = false;
        warnings
            .push("The selected mode or local PII checks require an enabled local model.".into());
    }
    let command_network = if top {
        "off".into()
    } else {
        cfg.str("sandbox.network")?
    };
    if command_network == "all" {
        warnings.push("Commands have unrestricted network access.".into());
    }
    let mut command_registries = if command_network == "registries" {
        cfg.list("sandbox.registries")?
    } else {
        Vec::new()
    };
    if declass_egress::Hosts::parse(&command_registries).is_err() {
        inventory.complete = false;
        command_registries.clear();
        warnings.push("Command registry rules are invalid.".into());
    }
    let web_enabled = !top && cfg.bool("web.enabled")?;
    let mut web_private_hosts = if web_enabled {
        cfg.list("web.allowlist_private")?
    } else {
        Vec::new()
    };
    if declass_web::guard::Allowlist::parse(&web_private_hosts).is_err() {
        inventory.complete = false;
        web_private_hosts.clear();
        warnings.push("Private web host rules are invalid.".into());
    }
    let search_origins = if web_enabled {
        match search_origins(cfg, ws, frontier_override.unwrap_or(&frontier_url)) {
            Ok(origins) => origins,
            Err(_) => {
                inventory.complete = false;
                warnings.push("Search destination selection is invalid.".into());
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    Ok(Report {
        schema: 1,
        mode: mode.as_str(),
        scope: "Path-policy preview, including ignored files. Workspace file contents are not scanned; local classification and plugin metadata are read. No network requests are made. Content checks run when Declass uses a file. Excluded directories are not inventoried.",
        complete: inventory.complete,
        destinations,
        command_network,
        command_registries,
        web_enabled,
        web_fetch: if web_enabled {
            "public HTTP(S) hosts selected at runtime, plus the explicit private-host allowlist; metadata addresses refused"
        } else {
            "disabled"
        },
        web_private_hosts,
        search_origins,
        mcp,
        exceptions,
        excluded_directories: SKIPPED,
        files: inventory.files,
        warnings,
    })
}

impl Report {
    pub(crate) fn render(&self, include_files: bool) -> String {
        let mut lines = vec![
            format!("Privacy · {} · {} paths", self.mode, self.files.len()),
            self.scope.into(),
        ];
        for d in &self.destinations {
            let enabled = if d.enabled { "enabled" } else { "disabled" };
            lines.push(if d.trust == NOT_SET_UP {
                format!("{}: {NOT_SET_UP} · {enabled}", d.role)
            } else {
                format!(
                    "{}: {} · {enabled} · {}",
                    d.role,
                    d.origin.as_deref().unwrap_or("invalid origin"),
                    d.trust
                )
            });
        }
        lines.push(format!(
            "Commands: {} network · web tools: {}",
            self.command_network,
            if self.web_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
        if !self.command_registries.is_empty() {
            lines.push(format!(
                "Command registries: {}",
                self.command_registries.join(", ")
            ));
        }
        lines.push(format!("Web fetch: {}", self.web_fetch));
        if !self.web_private_hosts.is_empty() {
            lines.push(format!(
                "Private web allowlist: {}",
                self.web_private_hosts.join(", ")
            ));
        }
        if !self.search_origins.is_empty() {
            lines.push(format!(
                "Search destinations: {}",
                self.search_origins.join(", ")
            ));
        }
        for m in &self.mcp {
            lines.push(format!(
                "MCP {}: {} · {} · network {}",
                m.name,
                if m.enabled { "enabled" } else { "disabled" },
                m.origin.as_deref().unwrap_or("local process"),
                m.network
            ));
        }
        for e in &self.exceptions {
            lines.push(format!("Exception: {} ({})", e.setting, e.origin));
        }
        for w in &self.warnings {
            lines.push(format!("Attention: {w}"));
        }
        lines.push(format!(
            "Excluded directories: {}",
            self.excluded_directories.join(", ")
        ));
        if include_files {
            for f in &self.files {
                lines.push(format!(
                    "{} · {} · {}",
                    shown(&f.path),
                    f.disposition,
                    shown(&f.rule)
                ));
            }
        } else {
            lines.push(
                "/privacy shows file rules; declass privacy --json exports this offline preview."
                    .into(),
            );
        }
        declass_tui::term::safe(&lines.join("\n"))
    }
    fn code(&self) -> i32 {
        // An endpoint nobody chose is a warning: nothing would be sent to it.
        let refused = |d: &Destination| d.enabled && !d.admitted && d.trust != NOT_SET_UP;
        if !self.complete || self.destinations.iter().any(refused) {
            2
        } else if !self.warnings.is_empty() || !self.exceptions.is_empty() {
            1
        } else {
            0
        }
    }
}
pub(crate) fn run(ws: &Path, args: Args, cfg: &Config) -> Result<i32> {
    let mode = crate::overrides::resolve_mode(cfg, args.mode, false)?;
    let report = collect(ws, cfg, mode, None, None)?;
    println!(
        "{}",
        if args.json {
            serde_json::to_string_pretty(&report)?
        } else {
            report.render(true)
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
    #[test]
    fn ignored_sensitive_files_templates_and_links_are_reported_without_reading() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir(&ws).unwrap();
        let cfg = config(temp.path(), "");
        for name in [".env", ".env.example", "ordinary.txt"] {
            std::fs::write(ws.join(name), "CANARY_CONTENT_MUST_NOT_APPEAR").unwrap();
        }
        std::fs::write(ws.join(".gitignore"), ".env\n").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", ws.join("link")).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(ws.join("pipe"))
                .status()
                .unwrap()
                .success()
        );
        let r = collect(&ws, &cfg, Mode::Hybrid, None, None).unwrap();
        let disposition = |name| r.files.iter().find(|f| f.path == name).unwrap().disposition;
        assert_eq!(disposition(".env"), "sensitive");
        assert_eq!(disposition(".env.example"), "content-checks");
        assert_eq!(disposition("pipe"), "blocked");
        assert_eq!(disposition("link"), "blocked");
        assert!(
            !serde_json::to_string(&r)
                .unwrap()
                .contains("CANARY_CONTENT")
        );
        assert!(!ws.join(".declass").exists());
        assert!(r.complete);
    }
    #[test]
    fn endpoint_secrets_are_never_displayed_and_top_clearance_disables_cloud() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = config(temp.path(), "");
        let r = collect(
            temp.path(),
            &cfg,
            Mode::TopClearance,
            Some("https://user:SECRET@api.example/v1/PRIVATE?token=KEY"),
            None,
        )
        .unwrap();
        let text = serde_json::to_string(&r).unwrap();
        for secret in ["SECRET", "PRIVATE", "KEY"] {
            assert!(!text.contains(secret));
        }
        assert!(!r.destinations[1].enabled);
        assert!(!r.destinations[1].admitted);
        assert_eq!(r.command_network, "off");
        assert!(!r.web_enabled);
    }
    #[test]
    fn models_nobody_chose_are_not_set_up_rather_than_refused() {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir(&ws).unwrap();
        std::fs::write(ws.join("main.py"), "print(1)\n").unwrap();
        let cfg = config(temp.path(), "[extensions]\nplugins_enabled = false\n");
        let r = collect(&ws, &cfg, Mode::Hybrid, None, None).unwrap();
        for d in &r.destinations {
            assert_eq!(d.trust, NOT_SET_UP, "{}", d.role);
            assert!(!d.admitted);
        }
        let text = r.render(true);
        assert!(text.contains("frontier: not set up · enabled"), "{text}");
        assert!(text.contains("No cloud model is set up yet: `declass setup`"));
        assert!(!text.contains("invalid origin") && !text.contains("refused by"));
        // A warning to act on, not the exit code of a refused endpoint.
        assert_eq!(r.code(), 1);
        // A chosen endpoint the policy refuses still is one.
        let refused = config(
            temp.path(),
            "[extensions]\nplugins_enabled = false\n[local]\nbase_url = \"http://192.0.2.1:9/v1\"\n",
        );
        let r = collect(&ws, &refused, Mode::Hybrid, None, None).unwrap();
        assert_eq!(r.destinations[0].trust, "refused");
        assert_eq!(r.code(), 2);
    }

    #[test]
    fn runtime_routes_match_passthrough_and_top_clearance() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = config(
            temp.path(),
            "[web.search]\nbackend = 'wikipedia'\n[extensions]\nplugins_enabled = false\n",
        );
        let passthrough = collect(temp.path(), &cfg, Mode::Passthrough, None, None).unwrap();
        assert!(!passthrough.destinations[0].enabled);
        assert!(passthrough.destinations[1].enabled);
        assert_eq!(passthrough.search_origins, vec!["https://en.wikipedia.org"]);
        assert!(!passthrough.command_registries.is_empty());
        let top = collect(temp.path(), &cfg, Mode::TopClearance, None, None).unwrap();
        assert!(top.search_origins.is_empty());
        assert!(top.command_registries.is_empty());
        assert!(top.web_private_hosts.is_empty());
    }

    #[test]
    fn the_walk_visits_every_file_once_and_says_when_a_limit_cuts_it_short() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("a/b/c")).unwrap();
        std::fs::create_dir_all(temp.path().join("node_modules/pkg")).unwrap();
        for name in [
            "one",
            "two",
            "a/three",
            "a/b/c/four",
            "node_modules/pkg/x.js",
        ] {
            std::fs::write(temp.path().join(name), "").unwrap();
        }
        std::os::unix::fs::symlink("/etc/hosts", temp.path().join("a/link")).unwrap();
        let (mut files, mut other) = (Vec::new(), Vec::new());
        let complete = walk(
            temp.path(),
            Limits {
                entries: 100,
                depth: 48,
            },
            &mut |e| match e {
                Entry::File { path, .. } => files.push(path.to_owned()),
                Entry::Other { path } => other.push(path.to_owned()),
            },
        )
        .unwrap();
        assert!(complete);
        files.sort();
        assert_eq!(files, ["a/b/c/four", "a/three", "one", "two"]);
        assert_eq!(other, ["a/link"]);
        for limits in [
            Limits {
                entries: 2,
                depth: 48,
            },
            Limits {
                entries: 100,
                depth: 1,
            },
        ] {
            assert!(
                !walk(temp.path(), limits, &mut |_| {}).unwrap(),
                "{limits:?}"
            );
        }
    }

    #[test]
    fn ip_precedence_and_explicit_template_protection() {
        let p = Policy {
            sealed: vec!["private/**".into()],
            interface_only: vec!["**/*.rs".into()],
            protected_paths: vec![".env.example".into()],
            ..Policy::default()
        };
        assert_eq!(
            classify(Path::new("private/lib.rs"), &p, Mode::Hybrid).0,
            "sealed"
        );
        assert_eq!(
            classify(Path::new(".env.example"), &p, Mode::Hybrid).0,
            "sensitive"
        );
    }
    #[test]
    fn symlink_root_is_refused_and_terminal_names_are_escaped() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = config(temp.path(), "");
        std::os::unix::fs::symlink(temp.path(), temp.path().join("link")).unwrap();
        assert!(collect(&temp.path().join("link"), &cfg, Mode::Hybrid, None, None).is_err());
        std::fs::write(temp.path().join("escape\u{1b}[2J"), "").unwrap();
        std::fs::write(temp.path().join("name\nforged-route"), "").unwrap();
        let rendered = collect(temp.path(), &cfg, Mode::Hybrid, None, None)
            .unwrap()
            .render(true);
        assert!(rendered.contains("name\\nforged-route"));
        assert!(
            !collect(temp.path(), &cfg, Mode::Hybrid, None, None)
                .unwrap()
                .render(true)
                .contains('\u{1b}')
        );
    }
}
