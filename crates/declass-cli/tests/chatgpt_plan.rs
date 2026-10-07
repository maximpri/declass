// SPDX-License-Identifier: GPL-3.0-or-later
//! ChatGPT plan usage through the binary, offline: the preset, `doctor`,
//! `login --status`, and the rule that the sign-in goes only to OpenAI's
//! public API. Sign-in itself is tested against a scripted authorization
//! server in `declass_provider::chatgpt`.

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

struct Env {
    _dir: tempfile::TempDir,
    home: PathBuf,
    ws: PathBuf,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (home, ws) = (root.join("owner"), root.join("ws"));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&ws).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&ws)
            .status()
            .unwrap()
            .success()
    );
    Env {
        _dir: dir,
        home,
        ws,
    }
}

fn declass(e: &Env, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_declass"))
        .args(args)
        .arg("--workspace")
        .arg(&e.ws)
        .env("DECLASS_CONFIG_HOME", &e.home)
        .env_remove("ZAI_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("DECLASS_LOCAL_PORTS")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn get(e: &Env, key: &str) -> String {
    let o = declass(e, &["config", "get", key]);
    assert!(o.status.success(), "{}", text(&o));
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

const PLAN_CONFIG: &str = "[frontier]\nauth = \"chatgpt\"\nbase_url = \"https://api.openai.com/v1\"\nmodel = \"gpt-6.1-sol\"\ndialect = \"responses\"\napi_key_env = \"\"\n";

/// A saved sign-in, as `declass login chatgpt` writes it.
fn signed_in(e: &Env, scopes: &[&str]) {
    let dir = e.home.join("credentials").join("chatgpt");
    std::fs::create_dir_all(&dir).unwrap();
    let account = json!({
        "issuer": "https://auth.openai.com",
        "client_id": "oaiapp_test",
        "ext_agent_host_id": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "subject": "user-1",
        "email": "dev@example.com",
        "id_token": "secret-id-token",
        "access_token": "secret-access-token",
        "refresh_token": "secret-refresh-token",
        "expires_at": 4_102_444_800i64,
        "scopes": scopes,
    });
    std::fs::write(dir.join("account.json"), account.to_string()).unwrap();
}

fn doctor(e: &Env) -> (String, Value) {
    let o = declass(e, &["doctor", "--json"]);
    let all = text(&o);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("{all}"));
    (all, v)
}

fn check<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} check in {report}"))
}

#[test]
fn the_chatgpt_preset_signs_in_instead_of_naming_a_key() {
    let e = env();
    let o = declass(&e, &["config", "preset"]);
    assert!(text(&o).contains("chatgpt") && text(&o).contains("(declass login)"));

    let o = declass(&e, &["config", "preset", "chatgpt", "--confirm"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("declass login chatgpt"), "{}", text(&o));
    assert_eq!(get(&e, "frontier.auth"), "\"chatgpt\"");
    assert_eq!(
        get(&e, "frontier.base_url"),
        "\"https://api.openai.com/v1\""
    );
    assert_eq!(get(&e, "frontier.dialect"), "\"responses\"");
    assert_eq!(get(&e, "frontier.api_key_env"), "\"\"");

    // An API-key preset switches the credential back.
    let o = declass(&e, &["config", "preset", "openai", "--confirm"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(get(&e, "frontier.auth"), "\"api_key\"");
    assert_eq!(get(&e, "frontier.api_key_env"), "\"OPENAI_API_KEY\"");
}

#[test]
fn doctor_checks_the_sign_in_and_never_shows_a_token() {
    let e = env();
    std::fs::write(e.home.join("config.toml"), PLAN_CONFIG).unwrap();
    let (_, report) = doctor(&e);
    let c = check(&report, "frontier sign-in");
    assert_eq!(c["status"], "fail");
    assert!(c["fix"].as_str().unwrap().contains("declass login chatgpt"));

    signed_in(
        &e,
        &[
            "chatgpt.tokens.use.direct",
            "email",
            "offline_access",
            "openid",
        ],
    );
    let (all, report) = doctor(&e);
    let c = check(&report, "frontier sign-in");
    assert_eq!(c["status"], "pass", "{c}");
    assert!(c["detail"].as_str().unwrap().contains("dev@example.com"));
    assert!(!all.contains("secret-"), "{all}");

    // A grant without plan usage cannot make requests.
    signed_in(&e, &["email", "offline_access", "openid"]);
    let (_, report) = doctor(&e);
    let c = check(&report, "frontier sign-in");
    assert_eq!(c["status"], "fail");
    assert!(
        c["detail"].as_str().unwrap().contains("isn't allowed"),
        "{c}"
    );
}

#[test]
fn the_sign_in_is_never_sent_to_another_endpoint() {
    let e = env();
    std::fs::write(
        e.home.join("config.toml"),
        PLAN_CONFIG.replace(
            "https://api.openai.com/v1",
            "https://api.z.ai/api/coding/paas/v4",
        ),
    )
    .unwrap();
    signed_in(&e, &["chatgpt.tokens.use.direct"]);
    let (_, report) = doctor(&e);
    let c = check(&report, "frontier sign-in");
    assert_eq!(c["status"], "fail");
    assert!(c["fix"].as_str().unwrap().contains("preset chatgpt"));

    // A run that overrides the endpoint stops before any request.
    std::fs::write(e.home.join("config.toml"), PLAN_CONFIG).unwrap();
    let o = declass(
        &e,
        &[
            "run",
            "--mode",
            "passthrough",
            "--no-privacy",
            "--frontier-url",
            "https://frontier.example/v1",
            "say hi",
        ],
    );
    assert!(!o.status.success());
    assert!(
        text(&o).contains("sends the ChatGPT sign-in only to https://api.openai.com/v1"),
        "{}",
        text(&o)
    );
    assert!(!text(&o).contains("secret-"));
}

#[test]
fn login_status_reports_the_sign_in_without_contacting_anyone() {
    let e = env();
    let o = declass(&e, &["login", "--status"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("not signed in"));

    std::fs::write(e.home.join("config.toml"), PLAN_CONFIG).unwrap();
    let o = declass(&e, &["login", "chatgpt", "--status"]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "in use but not signed in: {}",
        text(&o)
    );

    signed_in(&e, &["chatgpt.tokens.use.direct", "email"]);
    let o = declass(&e, &["login", "--status"]);
    assert!(o.status.success(), "{}", text(&o));
    let out = text(&o);
    assert!(out.contains("signed in as dev@example.com"), "{out}");
    assert!(out.contains("uses this plan") && out.contains("chatgpt.com/settings/usage"));
    assert!(!out.contains("secret-"));
}
