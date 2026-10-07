// SPDX-License-Identifier: GPL-3.0-or-later
//! The setup screen's backend ([`declass_tui::setup`]): what it finds, the
//! models it lists, the ChatGPT sign-in, and saving through the audited
//! owner-config path. Nothing here prints: the screen owns the terminal.

use crate::config_audit_path;
use crate::setup::{bootstrap_ports, key_present, model_score};
use anyhow::Result;
use declass_boundary::audit::record_config_change;
use declass_config::{Config, Target};
use declass_provider::backends::{self, FRONTIER_PRESETS};
use declass_provider::endpoint::{ApprovedEndpoint, is_loopback_host};
use declass_provider::{Dialect, Role};
use declass_tui::setup::{
    CloudProvider, Found, KeySource, LocalChoice, LocalServer, Outcome, Plan, SetupBackend, UrlInfo,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use toml::Value;

struct Backend {
    cfg: Mutex<Config>,
    runtime: tokio::runtime::Handle,
    /// Each provider's model listing, for its models' vision capability.
    listings: Mutex<HashMap<String, serde_json::Value>>,
}

/// Runs the setup screen on this terminal. The configuration is saved (by the
/// screen, after its review) or left untouched.
pub async fn run(cfg: Config) -> Result<Outcome> {
    let backend = Arc::new(Backend {
        cfg: Mutex::new(cfg),
        runtime: tokio::runtime::Handle::current(),
        listings: Mutex::default(),
    });
    Ok(tokio::task::spawn_blocking(move || declass_tui::setup::run(backend)).await??)
}

/// `~/…` for a path under the home directory.
fn shown(path: &std::path::Path) -> String {
    match std::env::var_os("HOME").map(std::path::PathBuf::from) {
        Some(home) if path.starts_with(&home) => {
            format!("~/{}", path.strip_prefix(&home).unwrap_or(path).display())
        }
        _ => path.display().to_string(),
    }
}

/// `ids` with `first` (when listed) first, then by suitability.
fn ranked(mut ids: Vec<String>, first: Option<&str>) -> Vec<String> {
    ids.sort_by(|a, b| {
        let lead = |id: &String| Some(id.as_str()) == first;
        lead(b)
            .cmp(&lead(a))
            .then(model_score(b).cmp(&model_score(a)))
            .then(a.cmp(b))
    });
    ids.dedup();
    ids
}

impl SetupBackend for Backend {
    fn scan(&self) -> Found {
        let signed_in = crate::plan_signed_in();
        let providers = FRONTIER_PRESETS
            .iter()
            .map(|p| {
                let plan = p.auth == "chatgpt";
                CloudProvider {
                    name: p.name.into(),
                    label: p.label.into(),
                    key_env: if plan {
                        String::new()
                    } else {
                        p.api_key_env.into()
                    },
                    key_found: !plan && key_present(p.api_key_env),
                    plan,
                    signed_in: plan && signed_in,
                    default_model: p.model.into(),
                    host: url::Url::parse(p.base_url)
                        .ok()
                        .and_then(|u| u.host_str().map(str::to_owned))
                        .unwrap_or_default(),
                }
            })
            .collect();
        let servers = self
            .runtime
            .block_on(backends::discover_loopback(
                &bootstrap_ports(),
                Duration::from_millis(1500),
            ))
            .into_iter()
            .map(|s| LocalServer {
                base_url: s.base_url,
                backend: s.backend.unwrap_or("OpenAI-compatible server").into(),
                models: ranked(s.models, None),
                api_key_env: s.api_key_env.map(str::to_owned),
            })
            .collect();
        let mut warnings = Vec::new();
        if let Err(e) = declass_sandbox::detect() {
            warnings.push(format!(
                "The command sandbox is unavailable ({e}); on Linux, install bubblewrap."
            ));
        }
        Found {
            providers,
            servers,
            config_path: shown(&self.cfg.lock().unwrap().owner_path),
            warnings,
        }
    }

    fn cloud_models(&self, provider: &str, key: Option<&KeySource>) -> Result<Vec<String>, String> {
        let p = backends::frontier_preset(provider).ok_or("unknown provider")?;
        if p.auth == "chatgpt" {
            use declass_provider::chatgpt;
            use declass_provider::client::TokenSource as _;
            return self.runtime.block_on(async {
                let session =
                    chatgpt::PlanSession::new(crate::chatgpt_store(), chatgpt::Issuer::openai());
                let token = session.token().await.map_err(|e| e.message)?;
                let models = chatgpt::list_models(&token, chatgpt::API_BASE)
                    .await
                    .map_err(|e| e.message)?;
                Ok(ranked(
                    models.into_iter().map(|m| m.slug).collect(),
                    Some(p.model),
                ))
            });
        }
        let key = key_value(key, p.api_key_env)?;
        let dialect = Dialect::parse(p.dialect).ok_or("unsupported dialect")?;
        let listing = self
            .runtime
            .block_on(backends::list_frontier_models(
                p.base_url,
                dialect,
                Some(&key),
                Duration::from_secs(8),
            ))
            .map_err(|e| match e.as_str() {
                "HTTP 401" | "HTTP 403" => format!("{} rejected the key ({e})", p.label),
                _ => e,
            })?;
        let ids = backends::agent_model_ids(&listing);
        self.listings.lock().unwrap().insert(p.name.into(), listing);
        Ok(ranked(ids, Some(p.model)))
    }

    fn sign_in(&self, show: Box<dyn Fn(String) + Send>) -> Result<String, String> {
        use declass_provider::chatgpt;
        self.runtime.block_on(async {
            let store = crate::chatgpt_store();
            let pending = chatgpt::begin(&store, &chatgpt::Issuer::openai())
                .await
                .map_err(|e| format!("{e:#}"))?;
            show(pending.display_url().to_string());
            crate::login::open_browser(pending.url());
            let signed = pending
                .finish(crate::login::SIGN_IN_WAIT)
                .await
                .map_err(|e| format!("{e:#}"))?;
            if !signed.account.plan_enabled() {
                return Err(
                    "plan use isn't enabled for Declass; sign in again and allow it".into(),
                );
            }
            Ok(signed
                .account
                .email
                .clone()
                .unwrap_or_else(|| signed.account.subject.clone()))
        })
    }

    fn check_url(&self, url: &str) -> Result<UrlInfo, String> {
        let parsed = url::Url::parse(url).map_err(|e| format!("{url} is not an address: {e}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("use an http:// or https:// address".into());
        }
        let host = parsed.host_str().ok_or("the address names no host")?;
        let port = parsed.port_or_known_default().unwrap_or(80);
        Ok(UrlInfo {
            host_port: format!("{host}:{port}"),
            loopback: is_loopback_host(host),
            plaintext: parsed.scheme() == "http",
        })
    }

    fn local_models(&self, choice: &LocalChoice) -> Result<Vec<String>, String> {
        let (mut allowlist, allow_plaintext) = {
            let cfg = self.cfg.lock().unwrap();
            (
                cfg.list("local.allowlist").map_err(|e| e.to_string())?,
                cfg.bool("local.allow_plaintext")
                    .map_err(|e| e.to_string())?,
            )
        };
        allowlist.extend(choice.allow_host.clone());
        let endpoint = ApprovedEndpoint::new(
            &choice.base_url,
            &Role::Local {
                allowlist,
                allow_plaintext: allow_plaintext || choice.plaintext,
            },
        )
        .map_err(|e| e.message)?;
        let key = match &choice.key {
            Some(k) => Some(key_value(Some(k), "")?),
            None => None,
        };
        let listing = self.runtime.block_on(backends::list_models(
            &endpoint,
            key.as_deref(),
            Duration::from_secs(8),
        ))?;
        Ok(ranked(backends::agent_model_ids(&listing), None))
    }

    fn save(&self, plan: &Plan) -> Result<Vec<String>, String> {
        let mut cfg = self.cfg.lock().unwrap();
        // A pasted key goes to the credentials, never to the configuration.
        let pasted = [
            ("frontier", plan.cloud.as_ref().and_then(|c| c.key.as_ref())),
            ("local", plan.local.as_ref().and_then(|c| c.key.as_ref())),
        ];
        for (role, key) in pasted {
            if let Some(KeySource::Pasted(secret)) = key {
                crate::save_key(role, secret.expose()).map_err(|e| format!("{e:#}"))?;
            }
        }
        let changes =
            changes(&cfg, plan, &self.listings.lock().unwrap()).map_err(|e| format!("{e:#}"))?;
        apply(&mut cfg, &changes).map_err(|e| format!("{e:#}"))
    }
}

/// The key itself: a pasted one, the variable `$NAME` names, or (none given)
/// the provider's own variable `fallback`.
fn key_value(key: Option<&KeySource>, fallback: &str) -> Result<String, String> {
    match key {
        Some(KeySource::Pasted(secret)) => Ok(secret.expose().trim().to_owned()),
        Some(KeySource::Env(name)) => {
            std::env::var(name).map_err(|_| format!("${name} is not set"))
        }
        None => std::env::var(fallback).map_err(|_| format!("${fallback} is not set")),
    }
}

/// The owner settings that carry out `plan`.
fn changes(
    cfg: &Config,
    plan: &Plan,
    listings: &HashMap<String, serde_json::Value>,
) -> Result<Vec<(&'static str, Value)>> {
    let mut out: Vec<(&'static str, Value)> = Vec::new();
    let text = |s: &str| Value::String(s.to_owned());
    match &plan.cloud {
        Some(choice) => {
            let p = backends::frontier_preset(&choice.provider)
                .ok_or_else(|| anyhow::anyhow!("unknown provider {}", choice.provider))?;
            let vision = listings
                .get(p.name)
                .and_then(|l| backends::model_vision_capability(l, &choice.model))
                .unwrap_or(choice.model == p.model && p.vision);
            let (key_env, saved) = match (&choice.key, p.auth) {
                (_, "chatgpt") => (String::new(), false),
                (Some(KeySource::Pasted(_)), _) => (String::new(), true),
                (Some(KeySource::Env(name)), _) => (name.clone(), false),
                (None, _) => (p.api_key_env.to_owned(), false),
            };
            out.extend([
                ("frontier.base_url", text(p.base_url)),
                ("frontier.model", text(&choice.model)),
                ("frontier.api_key_env", text(&key_env)),
                ("frontier.api_key_saved", Value::Boolean(saved)),
                ("frontier.dialect", text(p.dialect)),
                ("frontier.vision", Value::Boolean(vision)),
                ("frontier.auth", text(p.auth)),
            ]);
        }
        // No cloud model: every session and run is top clearance.
        None => out.push(("clearance.required", text("top"))),
    }
    match &plan.local {
        Some(choice) => {
            if !cfg.bool("local.enabled")? {
                out.push(("local.enabled", Value::Boolean(true)));
            }
            out.extend([
                ("local.base_url", text(&choice.base_url)),
                ("local.model", text(&choice.model)),
                (
                    "local.api_key_env",
                    text(match &choice.key {
                        Some(KeySource::Env(name)) => name,
                        _ => "",
                    }),
                ),
                (
                    "local.api_key_saved",
                    Value::Boolean(matches!(choice.key, Some(KeySource::Pasted(_)))),
                ),
            ]);
            if let Some(host) = &choice.allow_host {
                let mut allow = cfg.list("local.allowlist")?;
                if !allow.contains(host) {
                    allow.push(host.clone());
                }
                out.push((
                    "local.allowlist",
                    Value::Array(allow.into_iter().map(Value::String).collect()),
                ));
            }
            if choice.plaintext {
                out.push(("local.allow_plaintext", Value::Boolean(true)));
            }
        }
        None => out.push(("local.enabled", Value::Boolean(false))),
    }
    Ok(out)
}

/// Applies `changes` to the owner config, each recorded in the config audit
/// log; the operator confirmed them on the review screen.
fn apply(cfg: &mut Config, changes: &[(&str, Value)]) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for (key, new) in changes {
        let change = cfg.apply(Target::Owner, key, new.clone(), true)?;
        record_config_change(&config_audit_path(), &change, Target::Owner, true)?;
        lines.push(format!("{key} = {}", cfg.value(key)?));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> (tempfile::TempDir, Config) {
        let d = tempfile::tempdir().unwrap();
        let owner = d.path().join("config.toml");
        let cfg = Config::load(&owner, None).unwrap();
        (d, cfg)
    }

    #[test]
    fn a_plan_becomes_owner_settings_and_skips_are_explicit() {
        let (_d, cfg) = config();
        let plan = Plan {
            cloud: Some(declass_tui::setup::CloudChoice {
                provider: "anthropic".into(),
                label: "Anthropic".into(),
                model: "claude-x".into(),
                key: None,
            }),
            local: None,
        };
        let c = changes(&cfg, &plan, &HashMap::new()).unwrap();
        let get = |k: &str| c.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone());
        assert_eq!(
            get("frontier.model"),
            Some(Value::String("claude-x".into()))
        );
        assert_eq!(
            get("frontier.api_key_env"),
            Some(Value::String("ANTHROPIC_API_KEY".into()))
        );
        assert_eq!(get("local.enabled"), Some(Value::Boolean(false)));
        let plan = Plan {
            cloud: None,
            local: Some(LocalChoice {
                base_url: "http://192.0.2.7:8080/v1".into(),
                model: "m".into(),
                key: Some(KeySource::Env("PATH".into())),
                allow_host: Some("192.0.2.7:8080".into()),
                plaintext: true,
            }),
        };
        let c = changes(&cfg, &plan, &HashMap::new()).unwrap();
        let get = |k: &str| c.iter().find(|(key, _)| *key == k).map(|(_, v)| v.clone());
        assert_eq!(get("clearance.required"), Some(Value::String("top".into())));
        assert_eq!(
            get("local.allowlist"),
            Some(Value::Array(vec![Value::String("192.0.2.7:8080".into())]))
        );
        assert_eq!(get("local.allow_plaintext"), Some(Value::Boolean(true)));
    }

    #[test]
    fn suggested_models_come_first() {
        let ids = vec!["b-preview".into(), "a".into(), "coder-x".into()];
        assert_eq!(ranked(ids.clone(), Some("a"))[0], "a");
        assert_eq!(ranked(ids, None)[0], "coder-x");
    }
}
