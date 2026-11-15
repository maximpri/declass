// SPDX-License-Identifier: GPL-3.0-or-later
//! Which content is sensitive, by where it came from.

use crate::reencoded::nfc;
use std::path::Path;

/// Glob over `/`-separated paths: `*` and `?` stay within a segment, `**`
/// matches any number of segments. A pattern without `/` matches the file name
/// at any depth.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    fn seg(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => seg(&p[1..], s) || (!s.is_empty() && seg(p, &s[1..])),
            (Some(b'?'), Some(_)) => seg(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => seg(&p[1..], &s[1..]),
            _ => false,
        }
    }
    fn walk(p: &[&str], s: &[&str]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(&"**") => walk(&p[1..], s) || (!s.is_empty() && walk(p, &s[1..])),
            Some(pat) => {
                !s.is_empty() && seg(pat.as_bytes(), s[0].as_bytes()) && walk(&p[1..], &s[1..])
            }
        }
    }
    let split = |x: &str| -> Vec<String> {
        x.split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let p = split(pattern);
    let s = split(path);
    let p: Vec<&str> = p.iter().map(String::as_str).collect();
    let s: Vec<&str> = s.iter().map(String::as_str).collect();
    if !pattern.contains('/') {
        return s
            .last()
            .is_some_and(|name| seg(pattern.as_bytes(), name.as_bytes()));
    }
    walk(&p, &s)
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub sensitive_globs: Vec<String>,
    pub protected_paths: Vec<String>,
    pub command_output_sensitive: bool,
    pub raw_ok_commands: Vec<String>,
    pub secret_sinks: Vec<String>,
    pub detect_secrets: bool,
    pub detect_pii: bool,
    pub detect_entropy: bool,
    /// The owner's and project's own detectors (`sensitivity.custom_patterns`).
    pub custom_patterns: Vec<String>,
    pub bulky_tokens: usize,
    /// Brief the frontier on the sensitive files at run start (needs a local model).
    pub local_brief: bool,
    /// The local model marks names and postal addresses in the free text of
    /// public content (`sensitivity.local_pii_pass`; needs a local model).
    pub local_pii_pass: bool,
    /// Threshold for a public file the model explicitly read (`0` disables offloading).
    pub bulky_file_tokens: usize,
    /// Test, build and install output the frontier may be shown is condensed
    /// (`context.condense_output`; [`crate::condense`]).
    pub condense_output: bool,
    /// Source the frontier sees as signatures only (`ip.interface_only`).
    pub interface_only: Vec<String>,
    /// Source whose content the frontier never sees (`ip.sealed`).
    pub sealed: Vec<String>,
    /// The local model reads images (`local.vision`): images the frontier may
    /// not see are described by it instead of refused.
    pub local_vision: bool,
    /// `images.to_frontier`: which images the frontier may receive itself.
    pub images_to_frontier: crate::images::ToFrontier,
    /// Structure views, synthetic samples, masked output and the probe
    /// budget for short output of commands that read sensitive data.
    pub structure: StructureSettings,
    /// Checks the local model makes on what leaves and what comes in.
    pub local_checks: LocalChecks,
}

/// The local model's checks (`sensitivity.*`; each needs a local model).
/// The default runs none; `declass` reads the shipped values, all on.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalChecks {
    /// Withhold what a local summary or answer reveals of specific records
    /// (`sensitivity.local_judge`).
    pub judge: bool,
    /// Classify frontier questions; targeted ones become probes
    /// (`sensitivity.question_intent`).
    pub question_intent: bool,
    /// Screen what the frontier reads for prompt injection
    /// (`sensitivity.injection_screen`).
    pub injection_screen: bool,
    /// Refuse third-party requests that carry what was learned from
    /// sensitive data (`sensitivity.egress_meaning`).
    pub egress_meaning: bool,
    /// Hold public files that are real data as sensitive
    /// (`sensitivity.classify_content`).
    pub classify_content: bool,
    /// Write the owner's disclosure narrative at the end of a run
    /// (`sensitivity.local_narrative`).
    pub narrative: bool,
    /// Mark names and addresses in the operator's text
    /// (`sensitivity.operator_pii`).
    pub operator_pii: bool,
    /// Review edit_protected rewrites before they are written
    /// (`review.local_diff`).
    pub review_protected: bool,
}

/// What the frontier is shown of the structure of sensitive data (see
/// [`crate::structure`]). The default shows nothing new and sets no probe
/// budget; `declass` reads the shipped values from the configuration.
#[derive(Debug, Clone, Default)]
pub struct StructureSettings {
    /// Structure views of sensitive content, a structure outline in the task
    /// note and masked output of commands that read sensitive data
    /// (`sensitivity.structure_views`).
    pub views: bool,
    /// Records a synthetic sample may hold (`sensitivity.synthetic_rows`);
    /// 0: none are made.
    pub synthetic_rows: usize,
    /// Small numbers masked output may show as written over a run
    /// (`sensitivity.masked_numbers`).
    pub masked_numbers: u32,
    /// Short outputs of commands that read sensitive data shown over a run
    /// (`sensitivity.output_probes`); `None`: no budget.
    pub output_probes: Option<u32>,
}

/// How much of a protected source file the frontier may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpLevel {
    /// Signatures, types, doc comments and public constants; bodies withheld.
    InterfaceOnly,
    /// Existence only.
    Sealed,
}

/// [`glob_match`] with both sides in normalization form C ([`nfc`]), for
/// the rules that protect a path (sensitive, protected, interface-only,
/// sealed): a file system that compares names regardless of normalization
/// (macOS's) may store decomposed (`e` and a combining accent) a name a rule
/// writes composed (`é`), so what a rule protects is matched in one form.
/// Rules that allow something (secret sinks) keep matching as written.
fn protects(pattern: &str, path: &str) -> bool {
    glob_match(&nfc(pattern), path)
}

/// What a path rule makes the paths it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// `ip.sealed`: the file's existence only.
    Sealed,
    /// `ip.interface_only`: its interface, bodies withheld.
    InterfaceOnly,
    /// `sensitivity.protected_paths`: sensitive, never a fixture.
    Protected,
    /// `sensitivity.globs`: sensitive (environment templates excepted).
    Sensitive,
}

/// A rule of the policy that protects a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRule<'a> {
    /// The setting it is written in (`ip.sealed`, `sensitivity.globs`, ...).
    pub setting: &'static str,
    /// The rule as written.
    pub glob: &'a str,
    pub kind: RuleKind,
}

impl Policy {
    /// Every rule that protects `path`, as runtime matches them (names in
    /// normalization form C, [`protects`]), sealed first, then
    /// interface-only, protected paths and sensitivity globs (which leave
    /// environment templates alone). Runtime's answers
    /// ([`Policy::is_sensitive_path`], [`Policy::ip_level`]) and the reports'
    /// (`declass privacy`, `declass exposure`, the settings' path tester)
    /// all read rules here, so they cannot disagree about a path.
    pub fn rules_for<'a>(&'a self, path: &Path) -> Vec<PathRule<'a>> {
        let p = path.to_string_lossy();
        let p = nfc(&p);
        let template = is_env_template(path);
        [
            ("ip.sealed", &self.sealed, RuleKind::Sealed),
            (
                "ip.interface_only",
                &self.interface_only,
                RuleKind::InterfaceOnly,
            ),
            (
                "sensitivity.protected_paths",
                &self.protected_paths,
                RuleKind::Protected,
            ),
            (
                "sensitivity.globs",
                &self.sensitive_globs,
                RuleKind::Sensitive,
            ),
        ]
        .into_iter()
        .filter(|(_, _, kind)| !(template && *kind == RuleKind::Sensitive))
        .flat_map(|(setting, globs, kind)| {
            globs
                .iter()
                .filter(|g| protects(g, &p))
                .map(move |g| PathRule {
                    setting,
                    glob: g.as_str(),
                    kind,
                })
                .collect::<Vec<_>>()
        })
        .collect()
    }

    /// The first rule that protects `path` ([`Policy::rules_for`]), or
    /// `None`: runtime's content checks decide.
    pub fn rule_for<'a>(&'a self, path: &Path) -> Option<PathRule<'a>> {
        self.rules_for(path).into_iter().next()
    }

    pub fn is_sensitive_path(&self, path: &Path) -> bool {
        self.rules_for(path)
            .iter()
            .any(|r| matches!(r.kind, RuleKind::Protected | RuleKind::Sensitive))
    }

    /// The IP level of `path`; Sealed wins when both lists match.
    pub fn ip_level(&self, path: &Path) -> Option<IpLevel> {
        self.rules_for(path).iter().find_map(|r| match r.kind {
            RuleKind::Sealed => Some(IpLevel::Sealed),
            RuleKind::InterfaceOnly => Some(IpLevel::InterfaceOnly),
            _ => None,
        })
    }

    /// Whether any path is protected by an IP level.
    pub fn has_ip(&self) -> bool {
        !self.interface_only.is_empty() || !self.sealed.is_empty()
    }

    pub fn is_secret_sink(&self, path: &Path) -> bool {
        let p = path.to_string_lossy();
        self.secret_sinks.iter().any(|g| glob_match(g, &p))
    }

    /// Commands whose output may be shown raw (after scanning), by prefix.
    pub fn command_is_raw_ok(&self, command: &str) -> bool {
        let c = command.trim();
        self.raw_ok_commands
            .iter()
            .any(|ok| c == ok || c.starts_with(&format!("{ok} ")))
    }
}

/// Key=value style files whose values are the sensitive part (structure is safe to show).
pub fn is_secret_bearing(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    !is_env_template(path)
        && (name.starts_with(".env")
            || name.ends_with(".env")
            || name.contains("secret")
            || name.contains("credential"))
}

/// A committed template of an environment file (`.env.example`,
/// `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults`): made to be
/// shared, it holds placeholders and defaults, so it is public content
/// (still scanned: a real key committed in one is found as in any file).
pub fn is_env_template(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    const TEMPLATES: &[&str] = &["example", "sample", "template", "dist", "defaults"];
    name.starts_with(".env")
        && name
            .rsplit('.')
            .next()
            .is_some_and(|last| TEMPLATES.contains(&last))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_names_anywhere_and_paths_exactly() {
        assert!(glob_match(".env*", ".env"));
        assert!(glob_match(".env*", "services/api/.env.prod"));
        assert!(glob_match("*.csv", "data/customers.csv"));
        assert!(glob_match("data/**", "data/statements/a.csv"));
        assert!(glob_match("logs/**", "logs/prod.log"));
        assert!(!glob_match("logs/**", "src/logs.rs"));
        assert!(glob_match("src/pricing/**", "src/pricing/engine.rs"));
        assert!(!glob_match("*.log", "src/log.rs"));
    }

    #[test]
    fn env_templates_are_public_and_env_files_are_not() {
        let p = Policy {
            sensitive_globs: vec![".env*".into(), "**/.env*".into()],
            ..Policy::default()
        };
        for public in [
            ".env.example",
            "services/api/.env.sample",
            ".env.template",
            ".env.production.example",
            ".env.dist",
            ".env.defaults",
        ] {
            assert!(!p.is_sensitive_path(Path::new(public)), "{public}");
            assert!(!is_secret_bearing(Path::new(public)), "{public}");
        }
        for secret in [
            ".env",
            ".env.local",
            "services/api/.env.prod",
            ".env.examples.bak",
        ] {
            assert!(p.is_sensitive_path(Path::new(secret)), "{secret}");
            assert!(is_secret_bearing(Path::new(secret)), "{secret}");
        }
        // A template the owner protects stays protected.
        let p = Policy {
            protected_paths: vec![".env.example".into()],
            ..p
        };
        assert!(p.is_sensitive_path(Path::new(".env.example")));
    }

    #[test]
    fn ip_levels_come_from_their_globs_and_sealed_wins() {
        let p = Policy {
            interface_only: vec!["src/pricing/**".into()],
            sealed: vec!["src/pricing/secret_*.rs".into()],
            ..Policy::default()
        };
        assert_eq!(
            p.ip_level(Path::new("src/pricing/engine.rs")),
            Some(IpLevel::InterfaceOnly)
        );
        assert_eq!(
            p.ip_level(Path::new("src/pricing/secret_table.rs")),
            Some(IpLevel::Sealed)
        );
        assert_eq!(p.ip_level(Path::new("src/invoice.rs")), None);
        assert!(p.has_ip() && !Policy::default().has_ip());
        assert!(!p.is_sensitive_path(Path::new("src/pricing/engine.rs")));
    }

    #[test]
    fn protecting_rules_match_a_name_in_either_unicode_form() {
        // macOS keeps a name decomposed (NFD) when a program wrote it so,
        // while git and rules write it composed (NFC); it is one file.
        let (nfc, nfd) = ("donn\u{e9}es", "donne\u{301}es");
        let p = Policy {
            sensitive_globs: vec![format!("{nfc}/**"), "*.csv".into()],
            sealed: vec![format!("{nfd}/mod\u{e8}le.py")],
            secret_sinks: vec![format!("{nfc}/.env")],
            ..Policy::default()
        };
        for path in [format!("{nfc}/clients.json"), format!("{nfd}/clients.json")] {
            assert!(p.is_sensitive_path(Path::new(&path)), "{path:?}");
        }
        for path in [
            format!("{nfd}/mode\u{300}le.py"),
            format!("{nfc}/mod\u{e8}le.py"),
        ] {
            assert_eq!(
                p.ip_level(Path::new(&path)),
                Some(IpLevel::Sealed),
                "{path:?}"
            );
        }
        // A rule that allows something matches only as written.
        assert!(!p.is_secret_sink(Path::new(&format!("{nfd}/.env"))));
        assert!(p.is_secret_sink(Path::new(&format!("{nfc}/.env"))));
    }

    #[test]
    fn the_rule_a_path_is_reported_under_is_the_one_runtime_applies() {
        // The reports read the first rule; runtime answers from all of
        // them: for every path, in either form, the two agree.
        let (nfc, nfd) = ("donn\u{e9}es", "donne\u{301}es");
        let p = Policy {
            protected_paths: vec![format!("{nfc}/**")],
            sensitive_globs: vec![format!("{nfd}-raw/**"), ".env*".into()],
            sealed: vec!["src/mod\u{e8}le.py".into()],
            interface_only: vec!["src/**".into()],
            ..Policy::default()
        };
        for (path, setting) in [
            (
                format!("{nfc}/clients.json"),
                Some("sensitivity.protected_paths"),
            ),
            (
                format!("{nfd}/clients.json"),
                Some("sensitivity.protected_paths"),
            ),
            (format!("{nfc}-raw/x.txt"), Some("sensitivity.globs")),
            (format!("{nfd}-raw/x.txt"), Some("sensitivity.globs")),
            ("src/mode\u{300}le.py".to_owned(), Some("ip.sealed")),
            ("src/mod\u{e8}le.py".to_owned(), Some("ip.sealed")),
            ("src/lib.rs".to_owned(), Some("ip.interface_only")),
            (".env.example".to_owned(), None),
            (".env".to_owned(), Some("sensitivity.globs")),
            ("README.md".to_owned(), None),
        ] {
            let path = Path::new(&path);
            let rule = p.rule_for(path);
            assert_eq!(rule.map(|r| r.setting), setting, "{path:?}");
            assert_eq!(
                rule.is_some(),
                p.is_sensitive_path(path) || p.ip_level(path).is_some(),
                "{path:?}"
            );
        }
    }

    #[test]
    fn raw_ok_commands_match_by_prefix() {
        let p = Policy {
            raw_ok_commands: vec!["cargo check".into()],
            ..Policy::default()
        };
        assert!(p.command_is_raw_ok("cargo check --offline"));
        assert!(!p.command_is_raw_ok("cargo checkout"));
        assert!(!p.command_is_raw_ok("cat .env"));
    }
}
