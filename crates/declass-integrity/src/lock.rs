// SPDX-License-Identifier: GPL-3.0-or-later
//! The extension lock file: what each skill, plugin and MCP server must be.
//!
//! TOML, version 1. Skills and plugins use the field names of ToolHive's
//! lock file entries (`name`, `version`, `source`, `resolvedReference`,
//! `digest`, `contentDigest`, `provenance`, `unsigned`, `requiredBy`,
//! `explicit`) and the same content digest, so a pin means the same thing in
//! both. `mcpServers` is Declass's own section.
//!
//! Two scopes: the owner's lock (`~/.config/declass/extensions.lock`) pins
//! what the owner installed and configured; a project's lock
//! (`.declass/extensions.lock`, committed) may only add requirements, so it
//! names nothing tied to one machine (executables, install directories,
//! skills outside the project).

use crate::digest::Sha256Digest;
use crate::toolset;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The lock file version this build reads and writes.
pub const VERSION: u32 = 1;
/// Largest lock file read.
pub const MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most entries in one lock file, over every kind.
pub const MAX_ENTRIES: usize = 10_000;

const HEADER: &str = "# Declass extension lock. Written by `declass extensions`; \
review changes like code.\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Owner,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Skill,
    Plugin,
    Mcp,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Skill => "skill",
            Kind::Plugin => "plugin",
            Kind::Mcp => "mcp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
    #[error("the lock file exceeds {MAX_BYTES} bytes")]
    TooLarge,
    #[error("the lock file is not valid TOML: {0}")]
    Syntax(String),
    #[error("unsupported lock file version {0} (this build reads version {VERSION})")]
    Version(u32),
    #[error("the lock file has more than {MAX_ENTRIES} entries")]
    TooManyEntries,
    #[error("{kind} {name:?}: {problem}")]
    Entry {
        kind: &'static str,
        name: String,
        problem: String,
    },
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<Entry>,
    #[serde(default, rename = "mcpServers", skip_serializing_if = "Vec::is_empty")]
    pub mcp_servers: Vec<McpServer>,
}

/// A pinned skill or plugin (ToolHive's entry fields).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    /// The skill's ID or the plugin's name; unique within its kind.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Where it was found or installed from: `project:<path in the
    /// workspace>`, `owner:<path>` (`~/` for the home directory),
    /// `plugin:<name>` (a skill inside a plugin), or what an install named.
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_reference: Option<String>,
    /// The installed artifact: Declass's plugin store digest, a content
    /// digest for a local skill, or (ToolHive) an OCI digest or git commit.
    pub digest: String,
    /// The files as installed ([`crate::content`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// No signature, accepted by the owner.
    #[serde(default, skip_serializing_if = "is_false")]
    pub unsigned: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_by: Vec<String>,
    /// Pinned on purpose (`lock`, `approve`, an install), not on first use.
    #[serde(default, skip_serializing_if = "is_false")]
    pub explicit: bool,
}

/// Who signed it: a key (`publicKey`) or a certificate identity
/// (`signerIdentity` and `certIssuer`), never both.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signer_identity: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert_issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigstore_url: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub provisional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Stdio,
    Http,
}

/// A pinned MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpServer {
    /// The server's name in the owner config (or a plugin's server name).
    pub name: String,
    /// `owner-config` or `plugin:<name>`.
    pub source: String,
    pub transport: Transport,
    /// A stdio server's program and arguments, as configured.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The program the command resolved to, and its digest (owner lock only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<Executable>,
    /// Install directories pinned by content (owner lock only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<Root>,
    /// The package a launcher runs, as a registry names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
    /// `serverInfo` from the server's `initialize` answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_info: Option<ServerInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolset: Option<ToolsetPin>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub explicit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Executable {
    pub path: String,
    pub sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Root {
    pub path: String,
    pub content_digest: Sha256Digest,
}

/// Field names of the MCP registry's `server.json` packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Package {
    pub registry_type: String,
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolsetPin {
    pub algorithm: String,
    pub digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(default)]
    pub tools: BTreeMap<String, Sha256Digest>,
}

impl Lock {
    pub fn new() -> Self {
        Lock {
            version: VERSION,
            ..Lock::default()
        }
    }

    /// Reads and checks a lock file's text for `scope`.
    pub fn parse(text: &str, scope: Scope) -> Result<Lock, LockError> {
        if text.len() > MAX_BYTES {
            return Err(LockError::TooLarge);
        }
        // The version first, so a newer file says so rather than failing on
        // a field this build does not know.
        let table: toml::Table = text
            .parse()
            .map_err(|e: toml::de::Error| LockError::Syntax(e.message().to_owned()))?;
        match table.get("version").and_then(toml::Value::as_integer) {
            Some(v) if v == i64::from(VERSION) => {}
            Some(v) => return Err(LockError::Version(u32::try_from(v).unwrap_or(u32::MAX))),
            None => return Err(LockError::Syntax("missing `version`".into())),
        }
        let lock: Lock = toml::from_str(text)
            .map_err(|e: toml::de::Error| LockError::Syntax(e.message().to_owned()))?;
        lock.check(scope)?;
        Ok(lock)
    }

    /// The file's text: entries sorted by name, so diffs stay small.
    pub fn render(&self) -> String {
        let mut sorted = self.clone();
        sorted.skills.sort_by(|a, b| a.name.cmp(&b.name));
        sorted.plugins.sort_by(|a, b| a.name.cmp(&b.name));
        sorted.mcp_servers.sort_by(|a, b| a.name.cmp(&b.name));
        let body = toml::to_string(&sorted).unwrap_or_default();
        format!("{HEADER}{body}")
    }

    pub fn entries(&self, kind: Kind) -> &[Entry] {
        match kind {
            Kind::Skill => &self.skills,
            Kind::Plugin => &self.plugins,
            Kind::Mcp => &[],
        }
    }

    pub fn entry(&self, kind: Kind, name: &str) -> Option<&Entry> {
        self.entries(kind).iter().find(|e| e.name == name)
    }

    pub fn mcp(&self, name: &str) -> Option<&McpServer> {
        self.mcp_servers.iter().find(|s| s.name == name)
    }

    /// Adds `entry` to `kind` (skills or plugins), replacing the entry of the
    /// same name; returns the one it replaced.
    pub fn upsert(&mut self, kind: Kind, entry: Entry) -> Option<Entry> {
        let list = match kind {
            Kind::Skill => &mut self.skills,
            Kind::Plugin => &mut self.plugins,
            Kind::Mcp => return None,
        };
        match list.iter_mut().find(|e| e.name == entry.name) {
            Some(old) => Some(std::mem::replace(old, entry)),
            None => {
                list.push(entry);
                None
            }
        }
    }

    pub fn upsert_mcp(&mut self, server: McpServer) -> Option<McpServer> {
        match self.mcp_servers.iter_mut().find(|s| s.name == server.name) {
            Some(old) => Some(std::mem::replace(old, server)),
            None => {
                self.mcp_servers.push(server);
                None
            }
        }
    }

    /// Removes the pin of `name` in `kind`; whether there was one.
    pub fn remove(&mut self, kind: Kind, name: &str) -> bool {
        let before = self.len();
        match kind {
            Kind::Skill => self.skills.retain(|e| e.name != name),
            Kind::Plugin => self.plugins.retain(|e| e.name != name),
            Kind::Mcp => self.mcp_servers.retain(|s| s.name != name),
        }
        self.len() < before
    }

    pub fn len(&self) -> usize {
        self.skills.len() + self.plugins.len() + self.mcp_servers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every rule a lock file of `scope` must follow.
    pub fn check(&self, scope: Scope) -> Result<(), LockError> {
        if self.version != VERSION {
            return Err(LockError::Version(self.version));
        }
        if self.len() > MAX_ENTRIES {
            return Err(LockError::TooManyEntries);
        }
        for (kind, list) in [(Kind::Skill, &self.skills), (Kind::Plugin, &self.plugins)] {
            let mut seen = std::collections::BTreeSet::new();
            for e in list {
                let bad = |problem: &str| LockError::Entry {
                    kind: kind.as_str(),
                    name: shorten(&e.name),
                    problem: problem.to_owned(),
                };
                check_text(&e.name, 256).map_err(|p| bad(&format!("name {p}")))?;
                if !seen.insert(e.name.as_str()) {
                    return Err(bad("listed twice"));
                }
                check_text(&e.source, 4096).map_err(|p| bad(&format!("source {p}")))?;
                check_token(&e.digest).map_err(|p| bad(&format!("digest {p}")))?;
                if let Some(p) = &e.provenance {
                    if e.unsigned {
                        return Err(bad("both signed (provenance) and unsigned"));
                    }
                    let keyless = !p.signer_identity.is_empty() || !p.cert_issuer.is_empty();
                    match (keyless, p.public_key.is_empty()) {
                        (true, false) => {
                            return Err(bad(
                                "provenance names both a key and a certificate identity",
                            ));
                        }
                        (false, true) => return Err(bad("provenance names no signer")),
                        (true, true)
                            if p.signer_identity.is_empty() || p.cert_issuer.is_empty() =>
                        {
                            return Err(bad("provenance needs both signerIdentity and certIssuer"));
                        }
                        (false, false) => check_token(&p.public_key)
                            .map_err(|q| bad(&format!("publicKey {q}")))?,
                        _ => {}
                    }
                }
                if scope == Scope::Project && kind == Kind::Skill {
                    let path = e.source.strip_prefix("project:").ok_or_else(|| {
                        bad("a project lock pins only the project's own skills (source = \"project:<path>\")")
                    })?;
                    crate::content::normalize(path)
                        .ok()
                        .filter(|n| n == path)
                        .ok_or_else(|| bad("source must be a relative path inside the project"))?;
                }
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.mcp_servers {
            let bad = |problem: &str| LockError::Entry {
                kind: Kind::Mcp.as_str(),
                name: shorten(&s.name),
                problem: problem.to_owned(),
            };
            check_text(&s.name, 64).map_err(|p| bad(&format!("name {p}")))?;
            if !seen.insert(s.name.as_str()) {
                return Err(bad("listed twice"));
            }
            check_text(&s.source, 256).map_err(|p| bad(&format!("source {p}")))?;
            match (s.transport, s.command.is_empty(), &s.url) {
                (Transport::Stdio, false, None) | (Transport::Http, true, Some(_)) => {}
                (Transport::Stdio, _, _) => {
                    return Err(bad("a stdio server pins a command and no url"));
                }
                (Transport::Http, _, _) => {
                    return Err(bad("an HTTP server pins a url and no command"));
                }
            }
            if let Some(t) = &s.toolset
                && t.algorithm != toolset::ALGORITHM
            {
                return Err(bad(&format!(
                    "unknown toolset algorithm {:?} (this build uses {})",
                    shorten(&t.algorithm),
                    toolset::ALGORITHM
                )));
            }
            if scope == Scope::Project && (s.executable.is_some() || !s.roots.is_empty()) {
                return Err(bad(
                    "a project lock does not pin executables or install directories (they differ between machines)",
                ));
            }
        }
        Ok(())
    }
}

/// Non-empty, at most `max` bytes, no control characters.
fn check_text(s: &str, max: usize) -> Result<(), &'static str> {
    if s.is_empty() {
        Err("is empty")
    } else if s.len() > max {
        Err("is too long")
    } else if s.chars().any(char::is_control) {
        Err("holds a control character")
    } else {
        Ok(())
    }
}

/// [`check_text`] and no whitespace either.
fn check_token(s: &str) -> Result<(), &'static str> {
    check_text(s, 4096)?;
    if s.chars().any(char::is_whitespace) {
        Err("holds whitespace")
    } else {
        Ok(())
    }
}

fn shorten(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:79d1b89c9733bc5a3c51bd715612a85ab13add6933cb9aa7cc1ae44fd5d181a3";

    fn skill(name: &str, source: &str) -> Entry {
        Entry {
            name: name.into(),
            source: source.into(),
            digest: D.into(),
            content_digest: Some(D.parse().unwrap()),
            unsigned: true,
            explicit: true,
            ..Entry::default()
        }
    }

    fn server() -> McpServer {
        McpServer {
            name: "files".into(),
            source: "owner-config".into(),
            transport: Transport::Stdio,
            command: vec!["npx".into(), "-y".into(), "@acme/files-mcp@1.4.2".into()],
            url: None,
            executable: Some(Executable {
                path: "/opt/homebrew/bin/npx".into(),
                sha256: D.parse().unwrap(),
            }),
            roots: vec![],
            package: Some(Package {
                registry_type: "npm".into(),
                identifier: "@acme/files-mcp".into(),
                version: Some("1.4.2".into()),
                file_sha256: None,
            }),
            server_info: Some(ServerInfo {
                name: "files".into(),
                version: Some("1.4.2".into()),
            }),
            toolset: Some(ToolsetPin {
                algorithm: toolset::ALGORITHM.into(),
                digest: D.parse().unwrap(),
                protocol_version: Some("2025-06-18".into()),
                tools: BTreeMap::from([("read file".into(), D.parse().unwrap())]),
            }),
            explicit: false,
        }
    }

    #[test]
    fn a_lock_round_trips_sorted() {
        let mut lock = Lock::new();
        lock.upsert(Kind::Skill, skill("zeta", "project:.agents/skills/zeta"));
        lock.upsert(Kind::Skill, skill("alpha", "owner:~/.claude/skills/alpha"));
        lock.upsert(
            Kind::Plugin,
            Entry {
                provenance: Some(Provenance {
                    public_key: "ssh-ed25519:AAAAC3NzaC1lZDI1NTE5AAAAI".into(),
                    ..Provenance::default()
                }),
                unsigned: false,
                version: Some("1.0".into()),
                ..skill("quality-kit", "owner-store")
            },
        );
        lock.upsert_mcp(server());
        let text = lock.render();
        assert!(text.starts_with("# Declass extension lock."), "{text}");
        assert!(
            text.find("name = \"alpha\"") < text.find("name = \"zeta\""),
            "{text}"
        );
        assert!(text.contains("contentDigest = \"sha256:"), "{text}");
        assert!(text.contains("[mcpServers.toolset.tools]"), "{text}");
        let back = Lock::parse(&text, Scope::Owner).unwrap();
        assert_eq!(back.render(), text);
        assert_eq!(
            back.entry(Kind::Skill, "alpha").unwrap().source,
            "owner:~/.claude/skills/alpha"
        );
        assert_eq!(back.mcp("files").unwrap(), &server());
        // Replacing and removing by name.
        let old = lock
            .upsert(Kind::Skill, skill("zeta", "project:.claude/skills/zeta"))
            .unwrap();
        assert_eq!(old.source, "project:.agents/skills/zeta");
        assert!(lock.remove(Kind::Skill, "zeta"));
        assert!(!lock.remove(Kind::Skill, "zeta"));
    }

    #[test]
    fn versions_unknown_fields_and_bad_entries_are_refused() {
        assert_eq!(
            Lock::parse("version = 2\n", Scope::Owner),
            Err(LockError::Version(2))
        );
        assert!(matches!(
            Lock::parse("[[skills]]\nname = \"x\"\n", Scope::Owner),
            Err(LockError::Syntax(_))
        ));
        let unknown = "version = 1\n[[skills]]\nname = \"x\"\nsource = \"s\"\ndigest = \"d\"\ncolor = \"red\"\n";
        assert!(matches!(
            Lock::parse(unknown, Scope::Owner),
            Err(LockError::Syntax(_))
        ));
        let bad_digest = "version = 1\n[[skills]]\nname = \"x\"\nsource = \"s\"\ndigest = \"d\"\ncontentDigest = \"sha256:12\"\n";
        assert!(matches!(
            Lock::parse(bad_digest, Scope::Owner),
            Err(LockError::Syntax(_))
        ));
        let cases: Vec<(Lock, &str)> = vec![
            {
                let mut l = Lock::new();
                l.skills = vec![skill("x", "project:a"), skill("x", "project:b")];
                (l, "listed twice")
            },
            {
                let mut l = Lock::new();
                l.skills = vec![Entry {
                    provenance: Some(Provenance {
                        public_key: "k".into(),
                        ..Provenance::default()
                    }),
                    ..skill("x", "project:a")
                }];
                (l, "both signed")
            },
            {
                let mut l = Lock::new();
                l.skills = vec![Entry {
                    provenance: Some(Provenance {
                        public_key: "k".into(),
                        signer_identity: "ci.yml".into(),
                        cert_issuer: "https://token.actions.githubusercontent.com".into(),
                        ..Provenance::default()
                    }),
                    unsigned: false,
                    ..skill("x", "project:a")
                }];
                (l, "both a key and a certificate")
            },
            {
                let mut l = Lock::new();
                l.skills = vec![Entry {
                    digest: "sha256:a b".into(),
                    ..skill("x", "project:a")
                }];
                (l, "whitespace")
            },
            {
                let mut l = Lock::new();
                l.mcp_servers = vec![McpServer {
                    url: Some("https://x".into()),
                    ..server()
                }];
                (l, "a stdio server pins a command and no url")
            },
        ];
        for (lock, problem) in cases {
            let e = Lock::parse(&lock.render(), Scope::Owner)
                .unwrap_err()
                .to_string();
            assert!(e.contains(problem), "{problem}: {e}");
        }
    }

    #[test]
    fn a_project_lock_names_nothing_tied_to_one_machine() {
        let mut lock = Lock::new();
        lock.skills = vec![skill("x", "project:.agents/skills/x")];
        assert!(Lock::parse(&lock.render(), Scope::Project).is_ok());
        for source in [
            "owner:~/.claude/skills/x",
            "project:/etc/x",
            "project:../x",
            "project:./.agents/skills/x",
        ] {
            lock.skills = vec![skill("x", source)];
            assert!(
                Lock::parse(&lock.render(), Scope::Project).is_err(),
                "{source}"
            );
            assert!(
                Lock::parse(&lock.render(), Scope::Owner).is_ok(),
                "{source}"
            );
        }
        lock.skills.clear();
        lock.mcp_servers = vec![server()];
        let e = Lock::parse(&lock.render(), Scope::Project)
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not pin executables"), "{e}");
        lock.mcp_servers[0].executable = None;
        assert!(Lock::parse(&lock.render(), Scope::Project).is_ok());
    }
}
