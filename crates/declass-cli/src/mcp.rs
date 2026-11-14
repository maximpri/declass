// SPDX-License-Identifier: GPL-3.0-or-later
//! MCP servers from the owner's configuration (`[mcp.servers.<name>]`).

use anyhow::{Result, bail};
use declass_config::Config;
use declass_mcp::{Approve, Launch, ServerConfig, Trust};
use std::time::Duration;

/// The template key that names every configured server.
const SERVERS: &str = "mcp.servers.*.command";

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// One server's configuration, checked.
pub fn server(cfg: &Config, name: &str) -> Result<(ServerConfig, bool)> {
    let key = |field: &str| format!("mcp.servers.{name}.{field}");
    let command = cfg.str(&key("command"))?;
    let url = cfg.str(&key("url"))?;
    let launch = match (command.trim(), url.trim()) {
        ("", "") => bail!("MCP server `{name}`: set either command or url"),
        (c, "") => Launch::Command {
            command: c.to_owned(),
            args: cfg.list(&key("args"))?,
        },
        ("", u) => {
            declass_mcp::check_url(u).map_err(|e| anyhow::anyhow!("MCP server `{name}`: {e}"))?;
            Launch::Url(u.to_owned())
        }
        _ => bail!("MCP server `{name}`: set command or url, not both"),
    };
    let env = cfg.list(&key("env"))?;
    if let Some(bad) = env.iter().find(|v| !valid_env_name(v)) {
        bail!("MCP server `{name}`: {bad:?} is not an environment variable name");
    }
    let mut headers_env = Vec::new();
    for entry in cfg.list(&key("headers_env"))? {
        match entry.split_once('=') {
            Some((h, v)) if !h.trim().is_empty() && valid_env_name(v.trim()) => {
                headers_env.push((h.trim().to_owned(), v.trim().to_owned()));
            }
            _ => bail!(
                "MCP server `{name}`: headers_env entries are `Header=VARIABLE`, not {entry:?}"
            ),
        }
    }
    let read_home_secrets = cfg.list(&key("read_home_secrets"))?;
    if let Some(bad) = read_home_secrets
        .iter()
        .find(|e| !declass_sandbox::HOME_SECRETS.contains(&e.as_str()))
    {
        bail!(
            "MCP server `{name}`: read_home_secrets entries name credential stores the sandbox denies (such as \".kube\"), not {bad:?}"
        );
    }
    let trust = match cfg.str(&key("trust"))?.as_str() {
        "sensitive" => Trust::Sensitive,
        _ => Trust::Public,
    };
    let approve = match cfg.str(&key("approve"))?.as_str() {
        "auto" => Approve::Auto,
        "always" => Approve::Always,
        _ => Approve::Writes,
    };
    let server = ServerConfig {
        name: name.to_owned(),
        launch,
        env,
        headers_env,
        trust,
        network: cfg.bool(&key("network"))?,
        read_home_secrets,
        approve,
        timeout: Duration::from_secs(cfg.int(&key("timeout_seconds"))?.max(1) as u64),
    };
    Ok((server, cfg.bool(&key("enabled"))?))
}

/// Every configured server with whether it is enabled, by name.
pub fn configured(cfg: &Config) -> Vec<(String, Result<(ServerConfig, bool)>)> {
    cfg.instances(SERVERS)
        .into_iter()
        .map(|name| {
            let s = server(cfg, &name);
            (name, s)
        })
        .collect()
}

/// The enabled servers for a run; any configuration error stops the run.
pub fn for_run(cfg: &Config) -> Result<Vec<ServerConfig>> {
    let mut out = Vec::new();
    for (_, s) in configured(cfg) {
        let (server, enabled) = s?;
        if enabled {
            out.push(server);
        }
    }
    Ok(out)
}

/// Starts the enabled servers for a run or session (see `declass_agent::mcp`);
/// `None` when none are configured. `presenter` is the engine in hybrid mode.
/// In top clearance only servers that cannot reach the network start: stdio
/// programs whose sandbox has no network (see [`reaches_network`]).
#[allow(clippy::too_many_arguments)]
pub async fn start(
    cfg: &Config,
    ws: &std::path::Path,
    run_dir: &std::path::Path,
    sandbox: declass_sandbox::SandboxKind,
    presenter: Option<&dyn declass_boundary::view::Presenter>,
    audit: &declass_boundary::audit::AuditHandle,
    top_clearance: bool,
    plugin_servers: Vec<ServerConfig>,
    admission: Option<std::sync::Arc<dyn declass_agent::mcp::Admission>>,
) -> Result<Option<std::sync::Arc<declass_agent::mcp::Hub>>> {
    let mut servers = for_run(cfg)?;
    for server in plugin_servers {
        if servers.iter().any(|s| s.name == server.name) {
            bail!(
                "plugin MCP server {} collides with a configured server",
                server.name
            );
        }
        servers.push(server);
    }
    if top_clearance {
        servers.retain(|s| {
            let reaches = reaches_network(s);
            if reaches {
                eprintln!(
                    "top clearance: MCP server `{}` is not started (it {reaches_how}; data sent to it could leave this machine)",
                    s.name,
                    reaches_how = match s.launch {
                        Launch::Url(_) => "is reached over HTTP",
                        Launch::Command { .. } => "has network (network = true)",
                    }
                );
            }
            !reaches
        });
    }
    if servers.is_empty() {
        return Ok(None);
    }
    let passthrough = declass_boundary::view::PassThrough { max_bytes: 60_000 };
    let hub = declass_agent::mcp::Hub::start(
        &servers,
        &declass_agent::mcp::Setup {
            workspace: ws,
            run_dir,
            sandbox,
            presenter: presenter.unwrap_or(&passthrough),
            audit: Some(audit),
            admission,
        },
    )
    .await;
    for r in hub.reports() {
        match &r.result {
            Ok(n) => eprintln!("MCP server `{}` ({}): {n} tool(s)", r.name, r.transport),
            Err(e) => eprintln!(
                "warning: MCP server `{}` ({}) is unavailable: {e}",
                r.name, r.transport
            ),
        }
    }
    Ok(Some(std::sync::Arc::new(hub)))
}

/// Starts `servers` as a run would (the sandbox, a run's hidden paths from
/// an engine over the configured policy; no local model, nothing leaves
/// this machine), lists their tools, and stops them: `declass doctor` and
/// `declass extensions`. `admission` sees each launch and listing.
pub(crate) async fn inspect(
    cfg: &Config,
    ws: &std::path::Path,
    servers: &[ServerConfig],
    admission: Option<std::sync::Arc<dyn declass_agent::mcp::Admission>>,
) -> Result<Vec<declass_agent::mcp::ServerReport>, String> {
    let sandbox = declass_sandbox::detect().map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir().join(format!("declass-inspect-{}", uuid::Uuid::new_v4()));
    let engine = crate::policy(cfg)
        .map_err(|e| e.to_string())
        .and_then(|p| {
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            declass_boundary::engine::Engine::open_for_inspection(ws, &dir, p)
                .map_err(|e| e.to_string())
        })?;
    let workspace = ws.canonicalize().unwrap_or_else(|_| ws.to_path_buf());
    let reports = declass_agent::mcp::probe(
        servers,
        &declass_agent::mcp::Setup {
            workspace: &workspace,
            run_dir: &dir,
            sandbox,
            presenter: engine.as_ref(),
            audit: None,
            admission,
        },
    )
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(reports)
}

/// Whether what is sent to a server could leave this machine: it is reached
/// over HTTP (a loopback URL too: whatever listens there may forward it), or
/// its sandbox has network.
pub fn reaches_network(s: &ServerConfig) -> bool {
    matches!(s.launch, Launch::Url(_)) || s.network
}

/// Ends the servers' sessions and stops their processes.
pub async fn stop(run_cfg: &declass_agent::RunConfig) {
    if let Some(hub) = &run_cfg.mcp {
        hub.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured_with(server: &str) -> Vec<(String, Result<(ServerConfig, bool)>)> {
        let dir = tempfile::tempdir().unwrap();
        let owner = dir.path().join("owner.toml");
        std::fs::write(&owner, server).unwrap();
        configured(&Config::load(&owner, None).unwrap())
    }

    #[test]
    fn a_server_may_read_only_listed_credential_stores() {
        let ok = configured_with(
            "[mcp.servers.k8s]\ncommand = \"kubectl-mcp\"\nread_home_secrets = [\".kube\", \".config/gh\"]\n",
        );
        let (server, enabled) = ok[0].1.as_ref().unwrap();
        assert!(enabled);
        assert_eq!(server.read_home_secrets, [".kube", ".config/gh"]);
        // Only entries of the sandbox's list: anything else would read as an
        // exception that changes nothing (or a path outside the list).
        for bad in ["\"~/.kube\"", "\"/etc/passwd\"", "\".kube/config\""] {
            let refused = configured_with(&format!(
                "[mcp.servers.k8s]\ncommand = \"kubectl-mcp\"\nread_home_secrets = [{bad}]\n"
            ));
            let e = refused[0].1.as_ref().unwrap_err().to_string();
            assert!(e.contains("read_home_secrets"), "{bad}: {e}");
        }
        // Not set: none.
        let none = configured_with("[mcp.servers.files]\ncommand = \"files-mcp\"\n");
        assert!(none[0].1.as_ref().unwrap().0.read_home_secrets.is_empty());
    }
}
