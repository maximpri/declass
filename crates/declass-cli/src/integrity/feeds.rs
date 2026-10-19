// SPDX-License-Identifier: GPL-3.0-or-later
//! Advisory feeds about extensions (`declass extensions advisories`), in the
//! OSV format: the advisories shipped with Declass, the owner's feeds
//! (`extensions.advisory_urls`) as last fetched, osv.dev's answers about the
//! packages the owner's MCP servers run (only with `--online`), and a
//! project's own (`.declass/advisories/*.json`). Feeds are fetched only by
//! `update`; a run reads what was fetched and never contacts a feed.

use anyhow::{Context, Result, anyhow, bail, ensure};
use declass_boundary::third_party::Outgoing;
use declass_boundary::view::{PassThrough, Presenter};
use declass_integrity::osv::{self, Index, MAX_FEED_BYTES};
use declass_integrity::{Sha256Digest, launcher};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The advisories shipped with this build.
const SHIPPED: &str = include_str!("../../advisories/extensions.json");

/// Where fetched feeds are kept.
pub(crate) fn cache_dir() -> PathBuf {
    declass_config::owner_state_dir().join("integrity/advisories")
}

/// The advisories known on this machine, and notes about any that could not
/// be read.
pub(crate) struct Known {
    pub index: Index,
    pub notes: Vec<String>,
    /// When the owner's feeds were last fetched (`None`: never, or none
    /// configured).
    pub fetched: Option<SystemTime>,
}

/// Every advisory known here. Never fetches.
pub(crate) fn known(ws: &Path) -> Known {
    let mut advisories = osv::parse_feed(SHIPPED).unwrap_or_default();
    let mut notes = Vec::new();
    let mut fetched = None;
    for (dir, whose) in [
        (cache_dir(), "fetched"),
        (ws.join(".declass/advisories"), "project"),
    ] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        for path in files {
            if whose == "fetched"
                && let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified())
            {
                fetched = Some(fetched.map_or(modified, |f: SystemTime| f.min(modified)));
            }
            match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|t| osv::parse_feed(&t).map_err(|e| e.to_string()))
            {
                Ok(list) => advisories.extend(list),
                Err(e) => notes.push(format!(
                    "{whose} advisories {} cannot be read: {e}",
                    path.display()
                )),
            }
        }
    }
    Known {
        index: Index::new(advisories),
        notes,
        fetched,
    }
}

/// Whether the fetched feeds are older than `max_age` (only when the owner
/// has feeds).
pub(crate) fn stale(known: &Known, cfg: &declass_config::Config) -> Result<Option<String>> {
    let urls = cfg.list("extensions.advisory_urls")?;
    let days = cfg.int("extensions.advisory_max_age_days")? as u64;
    if urls.is_empty() && known.fetched.is_none() {
        return Ok(None);
    }
    let age = known
        .fetched
        .and_then(|f| SystemTime::now().duration_since(f).ok());
    Ok(match age {
        None => Some("never fetched (`declass extensions advisories update`)".into()),
        Some(a) if a > Duration::from_secs(days * 86_400) => Some(format!(
            "last fetched {} day(s) ago (extensions.advisory_max_age_days = {days})",
            a.as_secs() / 86_400
        )),
        Some(_) => None,
    })
}

fn client() -> Result<declass_net::Client> {
    declass_net::Client::new(declass_net::Options {
        timeout: Some(Duration::from_secs(60)),
        user_agent: Some(concat!("declass/", env!("CARGO_PKG_VERSION"))),
        ..declass_net::Options::default()
    })
    .map_err(|e| anyhow!("{e}"))
}

/// One request through the product's checked client; the body, bounded.
async fn fetch(client: &declass_net::Client, request: Outgoing) -> Result<String> {
    let url = request.url.clone();
    let host = url.host_str().unwrap_or_default().to_owned();
    let checked = PassThrough { max_bytes: 0 }
        .outbound_guard()
        .check("extension advisories", &host, request)
        .map_err(|r| anyhow!("{}", r.reason))?;
    let mut response = client
        .send(&checked, &declass_net::Credentials::new(Vec::new()))
        .await
        .with_context(|| format!("{url}"))?;
    ensure!(
        response.status() == 200,
        "{url}: HTTP {}",
        response.status()
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.with_context(|| format!("{url}"))? {
        bytes.extend_from_slice(&chunk);
        ensure!(
            bytes.len() <= MAX_FEED_BYTES,
            "{url}: larger than {MAX_FEED_BYTES} bytes"
        );
    }
    String::from_utf8(bytes).with_context(|| format!("{url}: not UTF-8"))
}

fn keep(name: &str, text: &str) -> Result<()> {
    let dir = cache_dir();
    declass_fs::private::ensure_private_dir(&dir)?;
    declass_fs::private::write_private(&dir.join(name), text.as_bytes())?;
    Ok(())
}

/// The packages the owner's MCP servers run with a pinned version, as osv.dev
/// queries.
fn queries(servers: &[declass_mcp::ServerConfig]) -> Vec<Value> {
    servers
        .iter()
        .filter_map(|s| match &s.launch {
            declass_mcp::Launch::Command { command, args } => {
                let argv: Vec<String> = std::iter::once(command.clone())
                    .chain(args.iter().cloned())
                    .collect();
                launcher::classify(&argv)
            }
            declass_mcp::Launch::Url(_) => None,
        })
        .filter_map(|l| {
            let ecosystem = osv::ecosystem_of(&l.package.registry_type)?;
            let version = l.package.version.filter(|_| !l.floating)?;
            Some(json!({
                "package": {"ecosystem": ecosystem, "name": l.package.identifier},
                "version": version,
            }))
        })
        .collect()
}

/// Fetches the owner's feeds (and, `online`, asks osv.dev about the
/// packages the owner's servers run); returns what was done, line by line.
pub(crate) async fn update(cfg: &declass_config::Config, online: bool) -> Result<Vec<String>> {
    let urls = cfg.list("extensions.advisory_urls")?;
    if urls.is_empty() && !online {
        bail!(
            "no feeds configured: set extensions.advisory_urls (owner config, --confirm), or ask osv.dev with --online"
        );
    }
    let client = client()?;
    let mut lines = Vec::new();
    for url in &urls {
        let parsed = declass_mcp::check_url(url).map_err(|e| anyhow!("{url}: {e}"))?;
        let text = fetch(&client, Outgoing::get(parsed)).await?;
        let n = osv::parse_feed(&text)
            .map_err(|e| anyhow!("{url}: {e}"))?
            .len();
        keep(
            &format!(
                "feed-{}.json",
                &hex::encode(Sha256Digest::of(url.as_bytes()).0)[..16]
            ),
            &text,
        )?;
        lines.push(format!("{url}: {n} advisory(ies)"));
    }
    if online {
        let servers = super::configured_servers(cfg)?;
        let queries = queries(&servers);
        let mut records = Vec::new();
        if !queries.is_empty() {
            let base = url::Url::parse("https://api.osv.dev/v1/").expect("a valid URL");
            let answer = fetch(
                &client,
                Outgoing::post_json(base.join("querybatch")?, json!({"queries": queries})),
            )
            .await?;
            let answer: Value = serde_json::from_str(&answer)?;
            let mut ids: Vec<String> = answer["results"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|r| r["vulns"].as_array().cloned().unwrap_or_default())
                .filter_map(|v| v["id"].as_str().map(str::to_owned))
                .collect();
            ids.sort();
            ids.dedup();
            for id in ids {
                let record =
                    fetch(&client, Outgoing::get(base.join(&format!("vulns/{id}"))?)).await?;
                records.push(serde_json::from_str::<Value>(&record)?);
            }
        }
        keep("osv-dev.json", &serde_json::to_string(&records)?)?;
        lines.push(format!(
            "osv.dev: {} package(s) asked about, {} advisory(ies) about them",
            queries.len(),
            records.len()
        ));
    }
    Ok(lines)
}
