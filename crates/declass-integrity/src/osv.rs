// SPDX-License-Identifier: GPL-3.0-or-later
//! Advisories about extensions, in the OSV format: a record names packages
//! (ecosystem, name, versions or ranges), and Declass's own block in
//! `database_specific.declass` names what has no registry: content digests
//! of skills and plugins, digests of tool definitions and tool sets, and
//! server URLs.
//!
//! A malicious-package record (`MAL-` ID or alias) or one marked
//! `"action": "revoke"` revokes what it names: it is refused in every mode.
//! Any other record is a vulnerability: reported, not refused. Withdrawn
//! records count for nothing.

use crate::digest::Sha256Digest;
use serde::Deserialize;
use serde_json::Value;

/// Largest feed read.
pub const MAX_FEED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    #[error("the feed exceeds {MAX_FEED_BYTES} bytes")]
    TooLarge,
    #[error("not an OSV record, list of records or {{\"vulns\": [...]}}: {0}")]
    Format(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Reported (a known vulnerability).
    Vulnerable,
    /// Refused in every mode (malicious, or revoked by its publisher).
    Revoked,
}

/// What an advisory names, in the forms Declass can match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: Option<Severity>,
    pub packages: Vec<Affected>,
    pub content_digests: Vec<Sha256Digest>,
    pub tool_digests: Vec<Sha256Digest>,
    pub toolset_digests: Vec<Sha256Digest>,
    pub server_urls: Vec<String>,
}

/// A package and the versions an advisory covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affected {
    /// OSV ecosystem name (`npm`, `PyPI`, `crates.io`, `Go`, ...).
    pub ecosystem: String,
    pub name: String,
    pub versions: Vec<String>,
    /// SEMVER ranges: (introduced, fixed or last affected (inclusive)).
    pub ranges: Vec<(String, Bound)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    Open,
    Fixed(String),
    LastAffected(String),
}

#[derive(Deserialize)]
struct RawRecord {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    affected: Vec<RawAffected>,
    #[serde(default)]
    database_specific: Option<Value>,
}

#[derive(Deserialize)]
struct RawAffected {
    #[serde(default)]
    package: Option<RawPackage>,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ranges: Vec<RawRange>,
}

#[derive(Deserialize)]
struct RawPackage {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct RawRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<Value>,
}

/// Every advisory in `text`: one OSV record, an array of them, or an OSV
/// API answer (`{"vulns": [...]}`). Withdrawn records are left out; a record
/// that cannot be read is an error, so a broken feed is noticed.
pub fn parse_feed(text: &str) -> Result<Vec<Advisory>, FeedError> {
    if text.len() > MAX_FEED_BYTES {
        return Err(FeedError::TooLarge);
    }
    let v: Value = serde_json::from_str(text).map_err(|e| FeedError::Format(e.to_string()))?;
    let records = match v {
        Value::Array(items) => items,
        Value::Object(ref m) if m.contains_key("vulns") => {
            m["vulns"].as_array().cloned().unwrap_or_default()
        }
        Value::Object(_) => vec![v],
        _ => return Err(FeedError::Format("neither an object nor an array".into())),
    };
    let mut out = Vec::new();
    for r in records {
        let raw: RawRecord =
            serde_json::from_value(r).map_err(|e| FeedError::Format(e.to_string()))?;
        if raw.withdrawn.is_some() {
            continue;
        }
        out.push(advisory(raw));
    }
    Ok(out)
}

fn digests(v: Option<&Value>) -> Vec<Sha256Digest> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|s| s.parse().ok())
        .collect()
}

fn advisory(raw: RawRecord) -> Advisory {
    let declass = raw
        .database_specific
        .as_ref()
        .and_then(|d| d.get("declass"));
    let revoke = declass
        .and_then(|d| d.get("action"))
        .and_then(Value::as_str)
        == Some("revoke");
    let malicious = std::iter::once(&raw.id)
        .chain(&raw.aliases)
        .any(|id| id.starts_with("MAL-"));
    let packages = raw
        .affected
        .into_iter()
        .filter_map(|a| {
            let p = a.package?;
            let ranges = a
                .ranges
                .into_iter()
                .filter(|r| r.kind == "SEMVER" || r.kind == "ECOSYSTEM")
                .flat_map(|r| ranges(&r.events))
                .collect();
            Some(Affected {
                ecosystem: p.ecosystem,
                name: p.name,
                versions: a.versions,
                ranges,
            })
        })
        .collect();
    Advisory {
        severity: Some(if revoke || malicious {
            Severity::Revoked
        } else {
            Severity::Vulnerable
        }),
        packages,
        content_digests: digests(declass.and_then(|d| d.get("contentDigests"))),
        tool_digests: digests(declass.and_then(|d| d.get("toolDigests"))),
        toolset_digests: digests(declass.and_then(|d| d.get("toolsetDigests"))),
        server_urls: declass
            .and_then(|d| d.get("serverUrls"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        id: raw.id,
        aliases: raw.aliases,
        summary: raw.summary,
    }
}

/// OSV range events in order: each `introduced` opens a range that the next
/// `fixed` or `last_affected` closes.
fn ranges(events: &[Value]) -> Vec<(String, Bound)> {
    let mut out = Vec::new();
    let mut open: Option<String> = None;
    for e in events {
        let field = |k: &str| e.get(k).and_then(Value::as_str).map(str::to_owned);
        if let Some(v) = field("introduced") {
            if let Some(start) = open.take() {
                out.push((start, Bound::Open));
            }
            open = Some(v);
        } else if let Some(v) = field("fixed") {
            if let Some(start) = open.take() {
                out.push((start, Bound::Fixed(v)));
            }
        } else if let Some(v) = field("last_affected")
            && let Some(start) = open.take()
        {
            out.push((start, Bound::LastAffected(v)));
        }
    }
    if let Some(start) = open {
        out.push((start, Bound::Open));
    }
    out
}

/// The OSV ecosystem of an MCP registry `registryType`.
pub fn ecosystem_of(registry_type: &str) -> Option<&'static str> {
    Some(match registry_type {
        "npm" => "npm",
        "pypi" => "PyPI",
        "cargo" => "crates.io",
        "go" => "Go",
        "nuget" => "NuGet",
        _ => return None,
    })
}

fn semver(v: &str) -> Option<semver::Version> {
    semver::Version::parse(v.trim_start_matches('v')).ok()
}

impl Affected {
    /// Whether `version` of this package is covered. A range bound that is
    /// not a version (`introduced: "0"` means from the start) is read as
    /// such; a version that cannot be compared is covered only when listed.
    pub fn covers(&self, version: &str) -> bool {
        if self.versions.iter().any(|v| v == version) {
            return true;
        }
        let Some(v) = semver(version) else {
            return false;
        };
        self.ranges.iter().any(|(start, end)| {
            let from = start == "0" || semver(start).is_some_and(|s| v >= s);
            let to = match end {
                Bound::Open => true,
                Bound::Fixed(f) => semver(f).is_some_and(|f| v < f),
                Bound::LastAffected(l) => semver(l).is_some_and(|l| v <= l),
            };
            from && to
        })
    }
}

/// What an advisory said about one extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: String,
    pub severity: Severity,
    pub summary: String,
    /// What matched: `package npm postmark-mcp@1.0.16`, `content`, `tool note`, ...
    pub matched: String,
}

/// Everything known about extensions, from every feed read.
#[derive(Debug, Clone, Default)]
pub struct Index {
    advisories: Vec<Advisory>,
}

impl Index {
    pub fn new(advisories: Vec<Advisory>) -> Self {
        Index { advisories }
    }

    pub fn len(&self) -> usize {
        self.advisories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.advisories.is_empty()
    }

    fn hits(&self, matched: impl Fn(&Advisory) -> Option<String>) -> Vec<Hit> {
        let mut out: Vec<Hit> = self
            .advisories
            .iter()
            .filter_map(|a| {
                matched(a).map(|m| Hit {
                    id: a.id.clone(),
                    severity: a.severity.unwrap_or(Severity::Vulnerable),
                    summary: a.summary.clone(),
                    matched: m,
                })
            })
            .collect();
        out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
        out.dedup_by(|a, b| a.id == b.id);
        out
    }

    /// Advisories about a package version (`registry_type` as the MCP
    /// registry names it, `version` as pinned; none without a version).
    pub fn package(&self, registry_type: &str, name: &str, version: Option<&str>) -> Vec<Hit> {
        let Some(ecosystem) = ecosystem_of(registry_type) else {
            return Vec::new();
        };
        self.hits(|a| {
            a.packages
                .iter()
                .find(|p| {
                    p.ecosystem == ecosystem
                        && p.name == name
                        && version.is_some_and(|v| p.covers(v))
                })
                .map(|_| format!("package {ecosystem} {name}@{}", version.unwrap_or_default()))
        })
    }

    /// Advisories about content with `digest` (a skill or plugin).
    pub fn content(&self, digest: &Sha256Digest) -> Vec<Hit> {
        self.hits(|a| {
            a.content_digests
                .contains(digest)
                .then(|| "content".to_owned())
        })
    }

    /// Advisories about a server's tools: the set, or any one tool.
    pub fn tools<'a>(
        &self,
        toolset: &Sha256Digest,
        tools: impl IntoIterator<Item = (&'a String, &'a Sha256Digest)> + Clone,
    ) -> Vec<Hit> {
        self.hits(|a| {
            if a.toolset_digests.contains(toolset) {
                return Some("tool set".to_owned());
            }
            tools
                .clone()
                .into_iter()
                .find(|(_, d)| a.tool_digests.contains(d))
                .map(|(name, _)| format!("tool {name}"))
        })
    }

    /// Advisories about a server URL (by prefix).
    pub fn url(&self, url: &str) -> Vec<Hit> {
        self.hits(|a| {
            a.server_urls
                .iter()
                .find(|u| !u.is_empty() && url.starts_with(u.as_str()))
                .map(|u| format!("url {u}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of OSV's record of the postmark-mcp package (malicious
    /// from 1.0.16, no fixed version), as osv.dev serves it.
    const POSTMARK: &str = r#"{
      "schema_version": "1.7.3",
      "id": "MAL-2025-47604",
      "summary": "Malicious code in postmark-mcp (npm)",
      "modified": "2025-09-26T04:14:45Z",
      "published": "2025-09-26T04:14:45Z",
      "affected": [{
        "package": {"name": "postmark-mcp", "ecosystem": "npm", "purl": "pkg:npm/postmark-mcp"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.16"}]}]
      }]
    }"#;

    #[test]
    fn a_malicious_package_record_revokes_every_version_it_covers() {
        let index = Index::new(parse_feed(POSTMARK).unwrap());
        let hit = &index.package("npm", "postmark-mcp", Some("1.0.16"))[0];
        assert_eq!(hit.id, "MAL-2025-47604");
        assert_eq!(hit.severity, Severity::Revoked);
        assert_eq!(hit.matched, "package npm postmark-mcp@1.0.16");
        assert_eq!(
            index.package("npm", "postmark-mcp", Some("1.0.20")).len(),
            1
        );
        // Before the malicious release, another package, another ecosystem,
        // or no pinned version: nothing.
        assert!(
            index
                .package("npm", "postmark-mcp", Some("1.0.15"))
                .is_empty()
        );
        assert!(index.package("npm", "postmark", Some("1.0.16")).is_empty());
        assert!(
            index
                .package("pypi", "postmark-mcp", Some("1.0.16"))
                .is_empty()
        );
        assert!(index.package("npm", "postmark-mcp", None).is_empty());
    }

    #[test]
    fn ranges_listed_versions_and_withdrawn_records() {
        let feed = r#"{"vulns": [
          {"id": "GHSA-1", "summary": "Path traversal",
           "affected": [{"package": {"ecosystem": "PyPI", "name": "mcp-server-git"},
             "versions": ["0.5.0"],
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.6.2"}]},
                        {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.1.0"}]}]}]},
          {"id": "GHSA-2", "withdrawn": "2026-01-01T00:00:00Z",
           "affected": [{"package": {"ecosystem": "PyPI", "name": "mcp-server-git"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
        ]}"#;
        let index = Index::new(parse_feed(feed).unwrap());
        assert_eq!(index.len(), 1);
        let hit = |v: &str| index.package("pypi", "mcp-server-git", Some(v));
        assert_eq!(hit("0.6.1")[0].severity, Severity::Vulnerable);
        assert!(hit("0.6.2").is_empty());
        assert!(!hit("1.1.0").is_empty() && hit("1.1.1").is_empty());
        assert!(!hit("0.5.0").is_empty());
    }

    #[test]
    fn declass_records_name_skills_tools_and_servers_by_digest() {
        let content = Sha256Digest::of(b"skill");
        let tool = Sha256Digest::of(b"tool");
        let feed = format!(
            r#"[{{"id": "DECLASS-EXT-2026-0001", "summary": "Skill that exfiltrates keys",
                 "database_specific": {{"declass": {{"action": "revoke",
                   "contentDigests": ["{content}"], "toolDigests": ["{tool}"],
                   "serverUrls": ["https://evil.example/mcp"]}}}}}}]"#
        );
        let index = Index::new(parse_feed(&feed).unwrap());
        assert_eq!(index.content(&content)[0].severity, Severity::Revoked);
        assert!(index.content(&Sha256Digest::of(b"other")).is_empty());
        let name = "note".to_owned();
        let hits = index.tools(&Sha256Digest::of(b"set"), [(&name, &tool)]);
        assert_eq!(hits[0].matched, "tool note");
        assert_eq!(
            index.url("https://evil.example/mcp/v2")[0].matched,
            "url https://evil.example/mcp"
        );
        assert!(index.url("https://good.example/mcp").is_empty());
    }

    #[test]
    fn a_broken_feed_is_an_error() {
        assert!(parse_feed("not json").is_err());
        assert!(parse_feed("[{\"summary\": \"no id\"}]").is_err());
        assert!(parse_feed("42").is_err());
    }
}
