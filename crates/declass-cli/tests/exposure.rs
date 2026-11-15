// SPDX-License-Identifier: GPL-3.0-or-later
//! `declass exposure` as CI runs it: SARIF and JSON written to a file with the
//! text report on standard output, exit codes chosen by `--fail-on`, findings
//! accepted through path rules, git history, and never a value, a line of
//! content or a hash of either in any output. Offline: nothing listens for it
//! and no run state is created.
use declass_boundary::testing::canary::{Canaries, Options};
use serde_json::Value;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const KEY: &str = concat!("sk_", "live_Wq4rT8yU2iO6pA1sD5fG9hJ3k");
const OLD_KEY: &str = concat!("ghp_", "Lm3nB7vC1xZ5qW9eR2tY6uI0oP4aS8dF3gH7");
const EMAIL: &str = "marisol.quintero@harbor-ledger.net";
const CARD: &str = "4024 0071 9896 4305";

struct Project {
    _tmp: tempfile::TempDir,
    ws: PathBuf,
    owner: PathBuf,
    out: PathBuf,
}

impl Project {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("project");
        let owner = tmp.path().join("owner");
        for dir in [
            ws.join("src"),
            ws.join("docs"),
            ws.join("data"),
            owner.clone(),
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(ws.join(".env"), format!("STRIPE_KEY={KEY}\n")).unwrap();
        std::fs::write(
            ws.join("src/settings.py"),
            format!("\nPAYMENTS_KEY = \"{KEY}\"\n"),
        )
        .unwrap();
        std::fs::write(ws.join("docs/team.md"), format!("Ask {EMAIL}.\n")).unwrap();
        std::fs::write(ws.join("data/cards.csv"), format!("card\n{CARD}\n")).unwrap();
        let out = tmp.path().join("report");
        Self {
            _tmp: tmp,
            ws,
            owner,
            out,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_declass"))
            .arg("--workspace")
            .arg(&self.ws)
            .arg("exposure")
            .args(args)
            .env("DECLASS_CONFIG_HOME", &self.owner)
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    fn written(&self) -> String {
        std::fs::read_to_string(&self.out).unwrap()
    }

    fn git(&self, args: &[&str]) {
        declass_git::Git::locate()
            .unwrap()
            .run(&self.ws, args, &[], None)
            .unwrap();
    }
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn assert_no_value(what: &str, text: &str) {
    let found = Canaries::with_options(
        [KEY, OLD_KEY, EMAIL, CARD],
        Options {
            digit_min: 8,
            ..Options::default()
        },
    )
    .find(text);
    assert!(found.is_empty(), "{what}: {found:?}");
    for line in [
        format!("STRIPE_KEY={KEY}"),
        format!("PAYMENTS_KEY = \"{KEY}\""),
    ] {
        assert!(!text.contains(&line), "{what} holds a line of content");
    }
}

#[test]
fn sarif_for_code_scanning_and_exit_codes_for_ci() {
    let p = Project::new();
    // Endpoints are configured, but nothing should ever connect to them.
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let url = format!("http://{}/v1", trap.local_addr().unwrap());
    std::fs::write(
        p.owner.join("config.toml"),
        format!("[local]\nbase_url = {url:?}\n[frontier]\nbase_url = {url:?}\n"),
    )
    .unwrap();
    let out = p.out.to_str().unwrap();

    // SARIF to a file, the text report on standard output.
    let run = p.run(&["--sarif", "--output", out]);
    assert_eq!(code(&run), 1, "{}", String::from_utf8_lossy(&run.stderr));
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(stdout.starts_with("Exposure · "), "{stdout}");
    assert_no_value("text", &stdout);
    let sarif = p.written();
    assert_no_value("SARIF", &sarif);
    let log: Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(log["version"], "2.1.0");
    assert_eq!(log["runs"][0]["tool"]["driver"]["name"], "declass");
    assert_eq!(
        log["runs"][0]["tool"]["driver"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    let results = log["runs"][0]["results"].as_array().unwrap();
    let settings = results
        .iter()
        .find(|r| {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/settings.py"
        })
        .unwrap();
    assert_eq!(settings["ruleId"], "exposure/secret");
    assert_eq!(settings["level"], "error");
    assert_eq!(
        settings["locations"][0]["physicalLocation"]["region"]["startLine"],
        2
    );

    // JSON and plain stdout carry no value either.
    let json = p.run(&["--json"]);
    assert_eq!(code(&json), 1);
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["schema"], 2);
    assert_eq!(report["fail_on"], "note");
    assert_eq!(report["failing"], 4);
    assert_no_value("JSON", &String::from_utf8(json.stdout).unwrap());

    // What fails is chosen by level.
    let fails = |args: &[&str]| code(&p.run(args));
    assert_eq!(fails(&["--fail-on", "error"]), 1, "a secret in src/");
    assert_eq!(fails(&["--fail-on", "never"]), 0);

    // Accepting findings: keep the files local with a project path rule.
    std::fs::create_dir_all(p.ws.join(".declass")).unwrap();
    std::fs::write(
        p.ws.join(".declass/config.toml"),
        "[sensitivity]\nprotected_paths = [\"src/**\"]\n",
    )
    .unwrap();
    assert_eq!(fails(&["--fail-on", "error"]), 0);
    assert_eq!(fails(&["--fail-on", "warning"]), 1, "docs/team.md");
    let text = p.run(&["--fail-on", "warning"]);
    assert!(
        String::from_utf8(text.stdout)
            .unwrap()
            .contains("1 file at or above --fail-on warning")
    );

    // Usage errors are clap's (exit 2) and write nothing.
    std::fs::remove_file(&p.out).unwrap();
    assert_eq!(fails(&["--json", "--sarif", "--output", out]), 2);
    assert_eq!(fails(&["--history-max-blobs", "5"]), 2, "needs --history");
    assert!(!p.out.exists());

    // Offline, and no run state.
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!p.ws.join(".declass/runs").exists());
    assert!(!p.ws.join(".declass/audit").exists());
}

#[test]
fn an_unreadable_directory_makes_the_report_incomplete() {
    use std::os::unix::fs::PermissionsExt;
    let p = Project::new();
    let locked = p.ws.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable = std::fs::read_dir(&locked).is_ok();
    let run = p.run(&["--fail-on", "never"]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    if readable {
        // A superuser reads it anyway: nothing to test.
        return;
    }
    assert_eq!(code(&run), 2, "incomplete, whatever --fail-on says");
    assert!(
        String::from_utf8(run.stdout)
            .unwrap()
            .contains("Attention: incomplete")
    );
}

#[test]
fn history_reports_a_removed_key_without_showing_it() {
    let p = Project::new();
    p.git(&["init", "-q"]);
    std::fs::write(
        p.ws.join("src/legacy.py"),
        format!("GITHUB_TOKEN = \"{OLD_KEY}\"\n"),
    )
    .unwrap();
    p.git(&["add", "-A"]);
    p.git(&["commit", "-q", "-m", "legacy client"]);
    std::fs::remove_file(p.ws.join("src/legacy.py")).unwrap();
    p.git(&["add", "-A"]);
    p.git(&["commit", "-q", "-m", "remove legacy client"]);
    let out = p.out.to_str().unwrap();

    let run = p.run(&["--history", "--json", "--output", out]);
    assert_eq!(code(&run), 1, "{}", String::from_utf8_lossy(&run.stderr));
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(stdout.contains("Git history · "), "{stdout}");
    assert!(stdout.contains("src/legacy.py (deleted)"), "{stdout}");
    let json = p.written();
    assert_no_value("history JSON", &json);
    assert_no_value("history text", &stdout);
    let report: Value = serde_json::from_str(&json).unwrap();
    let history = &report["history"];
    assert_eq!(history["complete"], true);
    assert_eq!(history["exposed"][0]["path"], "src/legacy.py");
    assert_eq!(history["exposed"][0]["deleted"], true);
    assert_eq!(history["exposed"][0]["found"]["secret"], 1);
    assert_eq!(history["exposed"][0]["level"], "error");

    let run = p.run(&["--history", "--sarif", "--output", out]);
    assert_eq!(code(&run), 1);
    let sarif = p.written();
    assert_no_value("history SARIF", &sarif);
    let log: Value = serde_json::from_str(&sarif).unwrap();
    assert!(
        log["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["properties"]["history"] == true
                && r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    == "src/legacy.py")
    );
    // A limit that cuts history short is an incomplete report.
    assert_eq!(
        code(&p.run(&[
            "--history",
            "--history-max-blobs",
            "0",
            "--fail-on",
            "never"
        ])),
        2
    );
    assert!(!Path::new(&p.ws.join(".declass")).exists());
}
