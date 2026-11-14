// SPDX-License-Identifier: GPL-3.0-or-later
//! `declass extensions`: show, pin and verify extensions.

use super::{
    Item, Launched, Loaded, Recorder, State, configured_servers, inventory, launch_differences,
    observed_dir, owner_lock_path, project_lock_path, state, toolset_findings,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use declass_config::Config;
use declass_integrity::lock::{Kind, Lock, McpServer, Root, Scope};
use declass_integrity::report::{self, Finding};
use declass_integrity::{toolset, tree};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum Action {
    /// List installed skills and plugins and whether a lock pins them.
    Status {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Pin what is installed now: every skill and plugin, or the IDs given
    /// (skill:<id>, plugin:<name>, mcp:<server>; a server is started to
    /// record its tools).
    Lock {
        /// Pin in the project's .declass/extensions.lock instead of yours.
        #[arg(long)]
        project: bool,
        /// Replace pins whose extension changed (review the change first).
        #[arg(long)]
        update: bool,
        /// With one mcp:<server>: also pin this install directory by content
        /// (repeatable), such as where its package is installed.
        #[arg(long)]
        root: Vec<PathBuf>,
        ids: Vec<String>,
    },
    /// Check installed extensions against the lock files; exits 0 when
    /// everything matches, 1 with warnings, 2 with errors. Starts nothing and
    /// needs no model or key (unless --live), so it can run in CI.
    Verify {
        /// Only the project's skills and lock (what a repository checks in CI).
        #[arg(long)]
        project_only: bool,
        /// Treat warnings (such as an unpinned project skill) as errors.
        #[arg(long)]
        strict: bool,
        /// Also start each MCP server (in the sandbox) and compare the tools
        /// it lists with its pin.
        #[arg(long)]
        live: bool,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Write the report here instead of standard output.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Show how the tools an MCP server last listed differ from its pin.
    Diff { id: String },
    /// Remove a pin (skill:<id>, plugin:<name>, mcp:<server>).
    Forget {
        /// From the project's lock instead of yours.
        #[arg(long)]
        project: bool,
        id: String,
    },
    /// Advisory feeds about extensions (OSV format): what revokes or warns
    /// about a skill, plugin or MCP server.
    Advisories {
        #[command(subcommand)]
        action: Option<AdvisoriesAction>,
    },
}

#[derive(Debug, clap::Subcommand)]
pub(crate) enum AdvisoriesAction {
    /// How many advisories are known, from where, and when they were fetched.
    List,
    /// Fetch the feeds in extensions.advisory_urls; with --online also ask
    /// osv.dev about the packages your MCP servers run (it then learns their
    /// names and versions).
    Update {
        #[arg(long)]
        online: bool,
    },
}

pub(crate) async fn run(ws: &Path, cfg: &Config, action: Action) -> Result<i32> {
    match action {
        Action::Status { json } => status(ws, json),
        Action::Lock {
            project,
            update,
            root,
            ids,
        } => {
            let servers: Vec<String> = ids
                .iter()
                .filter_map(|id| id.strip_prefix("mcp:").map(str::to_owned))
                .collect();
            let others: Vec<String> = ids
                .iter()
                .filter(|id| !id.starts_with("mcp:"))
                .cloned()
                .collect();
            ensure!(
                root.is_empty() || servers.len() == 1,
                "--root pins the install directories of one server; name one mcp:<server>"
            );
            let mut code = 0;
            if !others.is_empty() || servers.is_empty() {
                code = lock(ws, project, update, &others)?;
            }
            if !servers.is_empty() && code == 0 {
                code = lock_servers(ws, cfg, project, update, &root, &servers).await?;
            }
            Ok(code)
        }
        Action::Verify {
            project_only,
            strict,
            live,
            format,
            output,
        } => {
            check(
                ws,
                cfg,
                project_only,
                strict,
                live,
                format,
                output.as_deref(),
            )
            .await
        }
        Action::Diff { id } => diff(&id),
        Action::Forget { project, id } => forget(ws, project, &id),
        Action::Advisories { action } => match action.unwrap_or(AdvisoriesAction::List) {
            AdvisoriesAction::List => advisories(ws, cfg),
            AdvisoriesAction::Update { online } => {
                for line in super::feeds::update(cfg, online).await? {
                    println!("{}", safe(&line));
                }
                advisories(ws, cfg)
            }
        },
    }
}

fn advisories(ws: &Path, cfg: &Config) -> Result<i32> {
    let known = super::feeds::known(ws);
    let mut out = format!(
        "{} advisory(ies) known (shipped with Declass, fetched into {}, and the project's .declass/advisories/).\n",
        known.index.len(),
        super::feeds::cache_dir().display()
    );
    match known.fetched {
        Some(when) => {
            let days = std::time::SystemTime::now()
                .duration_since(when)
                .map_or(0, |d| d.as_secs() / 86_400);
            out.push_str(&format!("Feeds last fetched {days} day(s) ago.\n"));
        }
        None => out.push_str("No feed fetched yet (`declass extensions advisories update`).\n"),
    }
    if let Some(why) = super::feeds::stale(&known, cfg)? {
        out.push_str(&format!("Out of date: {why}\n"));
    }
    for note in &known.notes {
        out.push_str(&format!("Note: {note}\n"));
    }
    print!("{}", safe(&out));
    Ok(0)
}

fn locks(ws: &Path) -> (PathBuf, Loaded, PathBuf, Loaded) {
    let owner = owner_lock_path();
    let project = project_lock_path(ws);
    let owner_lock = Loaded::read(&owner, Scope::Owner);
    let project_lock = Loaded::read(&project, Scope::Project);
    (owner, owner_lock, project, project_lock)
}

fn safe(s: &str) -> String {
    declass_tui::term::safe(s)
}

fn status(ws: &Path, json: bool) -> Result<i32> {
    let (_, owner, _, project) = locks(ws);
    let (items, notes) = inventory(ws, false)?;
    let label = |item: &Item| -> String {
        let lock = match item.scope {
            Scope::Project => &project,
            Scope::Owner => &owner,
        };
        match state(item, lock) {
            State::Pinned => "pinned".to_owned(),
            State::Changed(..) => "CHANGED".to_owned(),
            State::Unpinned => "unpinned".to_owned(),
            State::LockInvalid => "lock unreadable".to_owned(),
            State::Unreadable(why) => format!("unreadable: {why}"),
        }
    };
    let servers: Vec<&McpServer> = match &owner {
        Loaded::Valid(l) => l.mcp_servers.iter().collect(),
        _ => Vec::new(),
    };
    if json {
        let list: Vec<serde_json::Value> = items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "id": item.id(),
                    "scope": match item.scope { Scope::Project => "project", Scope::Owner => "owner" },
                    "source": item.source,
                    "state": label(item),
                    "contentDigest": item.content.as_ref().ok().map(ToString::to_string),
                })
            })
            .collect();
        let pinned_servers: Vec<serde_json::Value> = servers
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": format!("mcp:{}", s.name),
                    "toolset": s.toolset.as_ref().map(|t| t.digest.to_string()),
                    "tools": s.toolset.as_ref().map_or(0, |t| t.tools.len()),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "extensions": list,
                "mcpServers": pinned_servers,
                "notes": notes,
            }))?
        );
        return Ok(0);
    }
    let (owner_path, _, project_path, _) = locks(ws);
    let mut out = format!(
        "Owner lock: {}\nProject lock: {}\n",
        lock_summary(&owner_path, &owner),
        lock_summary(&project_path, &project)
    );
    if items.is_empty() {
        out.push_str("No skills or plugins installed.\n");
    }
    for item in &items {
        out.push_str(&format!(
            "{:<10} {}  ({})\n",
            label(item),
            item.id(),
            item.source
        ));
    }
    for s in servers {
        out.push_str(&format!(
            "{:<10} mcp:{}  ({} tool(s))\n",
            "pinned",
            s.name,
            s.toolset.as_ref().map_or(0, |t| t.tools.len())
        ));
    }
    for note in &notes {
        out.push_str(&format!("Note: {note}\n"));
    }
    print!("{}", safe(&out));
    Ok(0)
}

fn lock_summary(path: &Path, lock: &Loaded) -> String {
    match lock {
        Loaded::Missing => format!("{} (none)", path.display()),
        Loaded::Valid(l) => format!("{} ({} pins)", path.display(), l.len()),
        Loaded::Invalid(why) => format!("{} (unusable: {why})", path.display()),
    }
}

fn scope_of(project: bool) -> Scope {
    if project {
        Scope::Project
    } else {
        Scope::Owner
    }
}

fn lock_path(ws: &Path, scope: Scope) -> PathBuf {
    match scope {
        Scope::Project => project_lock_path(ws),
        Scope::Owner => owner_lock_path(),
    }
}

/// The lock at `path` for writing (under the writer guard the caller holds).
fn writable(path: &Path, scope: Scope) -> Result<Lock> {
    match Loaded::read(path, scope) {
        Loaded::Missing => Ok(Lock::new()),
        Loaded::Valid(l) => Ok(l),
        Loaded::Invalid(why) => bail!(
            "{} cannot be used ({why}); fix or remove it first",
            path.display()
        ),
    }
}

fn commit_hint(ws: &Path, path: &Path) {
    println!(
        "Commit it so CI and teammates check the same pins: git add -f {}\n(Declass keeps .declass/ out of git by default.)",
        path.strip_prefix(ws).unwrap_or(path).display()
    );
}

fn lock(ws: &Path, project: bool, update: bool, ids: &[String]) -> Result<i32> {
    let scope = scope_of(project);
    let path = lock_path(ws, scope);
    let (items, _) = inventory(ws, project)?;
    let mut selected: Vec<&Item> = items.iter().filter(|i| i.scope == scope).collect();
    if !ids.is_empty() {
        for id in ids {
            if !selected.iter().any(|i| i.id() == *id) {
                bail!(
                    "{} is not installed in {} scope (IDs are skill:<id>, plugin:<name> or mcp:<server>; `declass extensions status` lists them)",
                    safe(id),
                    if project { "the project" } else { "the owner" }
                );
            }
        }
        selected.retain(|i| ids.contains(&i.id()));
    }
    // Only one writer at a time; read the current lock under the guard.
    let _guard = super::writer_guard(&path)?;
    let mut lock = writable(&path, scope)?;
    let (mut pinned, mut unchanged, mut refused) = (Vec::new(), 0, Vec::new());
    for item in selected {
        let Some(entry) = item.entry(true) else {
            refused.push(format!(
                "{}: cannot be read ({})",
                item.id(),
                item.content.as_ref().err().cloned().unwrap_or_default()
            ));
            continue;
        };
        match lock.entry(item.kind, &item.name) {
            Some(old)
                if old.content_digest == entry.content_digest
                    && old.digest == entry.digest
                    && old.source == entry.source =>
            {
                unchanged += 1;
                continue;
            }
            Some(old) if !update => {
                refused.push(format!(
                    "{} changed since it was pinned ({} {} → {} {}); review it, then run again with --update",
                    item.id(),
                    old.source,
                    old.content_digest.map(|d| d.to_string()).unwrap_or_default(),
                    entry.source,
                    entry.content_digest.map(|d| d.to_string()).unwrap_or_default(),
                ));
                continue;
            }
            _ => {}
        }
        let replaced = lock.upsert(item.kind, entry.clone()).is_some();
        pinned.push((item.kind, entry, replaced));
    }
    if !refused.is_empty() {
        eprintln!("{}", safe(&refused.join("\n")));
        eprintln!("Nothing was written.");
        return Ok(2);
    }
    if !pinned.is_empty() {
        super::save(&path, &lock, scope)?;
        if scope == Scope::Owner {
            for (kind, entry, replaced) in &pinned {
                super::record_pins(
                    &[(*kind, entry.clone())],
                    if *replaced { "lock_update" } else { "lock" },
                )?;
            }
        }
    }
    println!(
        "{} pinned, {unchanged} unchanged in {}",
        pinned.len(),
        path.display()
    );
    if project && !pinned.is_empty() {
        commit_hint(ws, &path);
    }
    if ids.is_empty() && !project {
        println!(
            "MCP servers are pinned the first time a run starts them, or now with: declass extensions lock mcp:<server>"
        );
    }
    Ok(0)
}

/// Starts each named server in the sandbox, records how it launched and
/// what it listed, and pins that.
async fn lock_servers(
    ws: &Path,
    cfg: &Config,
    project: bool,
    update: bool,
    roots: &[PathBuf],
    names: &[String],
) -> Result<i32> {
    let scope = scope_of(project);
    let path = lock_path(ws, scope);
    let all = configured_servers(cfg)?;
    let chosen = names
        .iter()
        .map(|n| {
            all.iter()
                .find(|s| s.name == *n)
                .cloned()
                .ok_or_else(|| anyhow!("no MCP server `{}` is configured", safe(n)))
        })
        .collect::<Result<Vec<_>>>()?;
    let recorder = std::sync::Arc::new(Recorder::new(ws, true));
    let reports = crate::mcp::inspect(cfg, ws, &chosen, Some(recorder.clone()))
        .await
        .map_err(|e| anyhow!("servers cannot start: {e}"))?;
    for r in &reports {
        if let Err(e) = &r.result {
            bail!("MCP server `{}` did not start: {}", r.name, safe(e));
        }
    }
    let mut seen = recorder.pins();
    if let [name] = names {
        for root in roots {
            let root = root
                .canonicalize()
                .with_context(|| format!("{}", root.display()))?;
            let digest = tree::scan(&root, tree::Limits::INSTALL)?.content_digest()?;
            if let Some(pin) = seen.get_mut(name) {
                pin.roots.push(Root {
                    path: root.display().to_string(),
                    content_digest: digest,
                });
            }
        }
    }
    if scope == Scope::Project {
        // A project pins what every machine shares: the command line, the
        // package, the tools; not where things are installed here.
        for pin in seen.values_mut() {
            pin.executable = None;
            pin.roots.clear();
        }
    }
    let _guard = super::writer_guard(&path)?;
    let mut lock = writable(&path, scope)?;
    let (mut pinned, mut unchanged, mut refused) = (Vec::new(), 0, Vec::new());
    for name in names {
        let Some(new) = seen.remove(name) else {
            refused.push(format!("mcp:{name}: listed no tools"));
            continue;
        };
        match lock.mcp(name) {
            Some(old) if same_server(old, &new) => {
                unchanged += 1;
                continue;
            }
            Some(old) if !update => {
                refused.push(format!(
                    "mcp:{name} changed since it was pinned ({}); review it (`declass extensions diff mcp:{name}`), then run again with --update",
                    server_changes(old, &new)
                ));
                continue;
            }
            Some(_) => pinned.push((new.clone(), true)),
            None => pinned.push((new.clone(), false)),
        }
        lock.upsert_mcp(new);
    }
    if !refused.is_empty() {
        eprintln!("{}", safe(&refused.join("\n")));
        eprintln!("Nothing was written.");
        return Ok(2);
    }
    if !pinned.is_empty() {
        super::save(&path, &lock, scope)?;
        if scope == Scope::Owner {
            for (server, replaced) in &pinned {
                super::record_server_pins(
                    std::slice::from_ref(server),
                    if *replaced { "lock_update" } else { "lock" },
                )?;
            }
        }
    }
    println!(
        "{} MCP server(s) pinned, {unchanged} unchanged in {}",
        pinned.len(),
        path.display()
    );
    if project && !pinned.is_empty() {
        commit_hint(ws, &path);
    }
    Ok(0)
}

/// The same pin, whoever took it.
fn same_server(a: &McpServer, b: &McpServer) -> bool {
    McpServer {
        explicit: false,
        ..a.clone()
    } == McpServer {
        explicit: false,
        ..b.clone()
    }
}

fn server_changes(old: &McpServer, new: &McpServer) -> String {
    let seen = Launched {
        command: new.command.clone(),
        executable: new.executable.clone(),
        package: new.package.clone(),
    };
    let mut parts: Vec<String> = launch_differences(old, &seen)
        .into_iter()
        .map(|(a, b)| format!("{a} → {b}"))
        .collect();
    if let (Some(a), Some(b)) = (&old.toolset, &new.toolset)
        && a.digest != b.digest
    {
        let c = toolset::changes(&a.tools, &b.tools);
        parts.push(format!(
            "tools changed: {}; added: {}; removed: {}",
            super::listed(&c.changed),
            super::listed(&c.added),
            super::listed(&c.removed)
        ));
    }
    if parts.is_empty() {
        "its server information".into()
    } else {
        parts.join("; ")
    }
}

#[allow(clippy::too_many_arguments)]
async fn check(
    ws: &Path,
    cfg: &Config,
    project_only: bool,
    strict: bool,
    live: bool,
    format: Format,
    output: Option<&Path>,
) -> Result<i32> {
    let (mut checked, mut findings, mut notes) = super::check_all(ws, Some(cfg), project_only)?;
    if live && !project_only {
        // What a run would start: enabled servers and the enabled plugins'.
        let mut servers = crate::mcp::for_run(cfg)?;
        if cfg.bool("extensions.plugins_enabled")? {
            let packages = crate::plugins::active_packages(&crate::plugins::store()?)?;
            servers.extend(crate::plugins::servers(&packages, cfg)?);
        }
        let recorder = std::sync::Arc::new(Recorder::new(ws, false));
        match crate::mcp::inspect(cfg, ws, &servers, Some(recorder.clone())).await {
            Ok(reports) => {
                for r in reports {
                    if let Err(e) = r.result {
                        notes.push(format!("MCP server `{}` did not start: {e}", r.name));
                    }
                }
                let (_, owner, _, project) = locks(ws);
                let pins = recorder.pins();
                checked += pins.len();
                findings.extend(toolset_findings(&pins, &owner, &project));
            }
            Err(e) => notes.push(format!("MCP servers cannot start: {e}")),
        }
    }
    let text = match format {
        Format::Text => render_text(&findings, checked, &notes),
        Format::Json => serde_json::to_string_pretty(&report::to_json(&findings, checked))? + "\n",
        Format::Sarif => {
            serde_json::to_string_pretty(&report::to_sarif(&findings, env!("CARGO_PKG_VERSION")))?
                + "\n"
        }
    };
    match output {
        Some(path) => {
            std::fs::write(path, &text)?;
            if format != Format::Text {
                print!("{}", render_text(&findings, checked, &notes));
            }
        }
        None if format == Format::Text => print!("{}", safe(&text)),
        None => print!("{text}"),
    }
    Ok(report::exit_code(&findings, strict))
}

fn render_text(findings: &[Finding], checked: usize, notes: &[String]) -> String {
    let mut out = String::new();
    for f in findings {
        out.push_str(&format!(
            "{:<7} {} {} {}: {}\n",
            f.level.as_str(),
            f.rule.id(),
            f.kind,
            f.id,
            f.message
        ));
    }
    for note in notes {
        out.push_str(&format!("note    {note}\n"));
    }
    out.push_str(&format!(
        "{} finding(s) in {checked} extension(s) checked.\n",
        findings.len()
    ));
    declass_tui::term::safe(&out)
}

/// A listing kept by [`super::observed_dir`]: each tool by name.
fn listing(path: &Path) -> Result<BTreeMap<String, serde_json::Value>> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(v["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| {
            (
                t.get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                t.clone(),
            )
        })
        .collect())
}

fn diff(id: &str) -> Result<i32> {
    let name = id
        .strip_prefix("mcp:")
        .context("diff compares an MCP server's tools with its pin: mcp:<server>")?;
    let Loaded::Valid(lock) = Loaded::read(&owner_lock_path(), Scope::Owner) else {
        bail!("your lock cannot be read; nothing is pinned to compare with");
    };
    let pinned = lock
        .mcp(name)
        .and_then(|p| p.toolset.clone())
        .with_context(|| format!("mcp:{} has no pinned tools", safe(name)))?;
    let dir = observed_dir(name);
    let mut kept: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&dir)
        .with_context(|| format!("no listing of mcp:{} has been kept", safe(name)))?
        .flatten()
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    kept.sort();
    let (_, latest) = kept
        .last()
        .with_context(|| format!("no listing of mcp:{} has been kept", safe(name)))?;
    let now = listing(latest)?;
    let observed: BTreeMap<String, declass_integrity::Sha256Digest> = now
        .iter()
        .map(|(n, t)| (n.clone(), toolset::tool_digest(t)))
        .collect();
    let changes = toolset::changes(&pinned.tools, &observed);
    if changes.is_empty() {
        println!("mcp:{name}: the tools it last listed match its pin.");
        return Ok(0);
    }
    let before = listing(&dir.join(format!("{}.json", hex::encode(pinned.digest.0)))).ok();
    let pretty = |v: &serde_json::Value| serde_json::to_string_pretty(v).unwrap_or_default();
    let mut out = format!("mcp:{name}: what it last listed differs from its pin.\n");
    for tool in &changes.changed {
        out.push_str(&format!("\nchanged: {tool}\n"));
        match before.as_ref().and_then(|b| b.get(tool)) {
            Some(old) => out.push_str(&format!("--- pinned\n{}\n", pretty(old))),
            None => out.push_str("--- pinned (definition not kept; its digest differs)\n"),
        }
        out.push_str(&format!("+++ listed\n{}\n", pretty(&now[tool])));
    }
    for tool in &changes.added {
        out.push_str(&format!("\nadded: {tool}\n{}\n", pretty(&now[tool])));
    }
    for tool in &changes.removed {
        out.push_str(&format!("\nremoved: {tool}\n"));
    }
    out.push_str(&format!(
        "\nIf the change is expected: declass extensions lock --update mcp:{name}\n"
    ));
    print!("{}", safe(&out));
    Ok(1)
}

fn forget(ws: &Path, project: bool, id: &str) -> Result<i32> {
    let scope = scope_of(project);
    let path = lock_path(ws, scope);
    let (kind, name) = match id.split_once(':') {
        Some(("skill", n)) => (Kind::Skill, n),
        Some(("plugin", n)) => (Kind::Plugin, n),
        Some(("mcp", n)) => (Kind::Mcp, n),
        _ => bail!("IDs are skill:<id>, plugin:<name> or mcp:<server>"),
    };
    let _guard = super::writer_guard(&path)?;
    let mut lock = writable(&path, scope)?;
    if !lock.remove(kind, name) {
        println!("{} is not pinned in {}", safe(id), path.display());
        return Ok(1);
    }
    super::save(&path, &lock, scope)?;
    if scope == Scope::Owner {
        super::record_forgotten(kind, name)?;
    }
    println!("{} unpinned in {}", safe(id), path.display());
    Ok(0)
}
