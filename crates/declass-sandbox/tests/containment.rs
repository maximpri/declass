// SPDX-License-Identifier: GPL-3.0-or-later
//! The sandbox from the inside: a probe (`declass-probe`) tries to read what
//! it may not, write outside the workspace and into git's and Declass's
//! state, reach the network, a local socket and the clipboard, first with no
//! sandbox (what works on this machine at all) and then sandboxed with
//! network off and with network on. Each attempt is held to a declared
//! outcome; one the control could not make either (no DNS, no clipboard
//! here) proves nothing and is skipped. Known gaps are declared as such.
//! Run on Linux with `tools/linux-check.sh`.
#![cfg(any(target_os = "macos", target_os = "linux"))]

use declass_sandbox::{Network, SandboxKind, Spec};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

const KIND: SandboxKind = if cfg!(target_os = "linux") {
    SandboxKind::Bubblewrap
} else {
    SandboxKind::Seatbelt
};

static SIGN_INS: OnceLock<PathBuf> = OnceLock::new();

fn sign_ins() -> Vec<PathBuf> {
    SIGN_INS.get().cloned().into_iter().collect()
}

/// What an attempt must come to: blocked, or escaped (allowed, or a gap
/// declared here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Blocked,
    Escaped,
}

/// Runs the probe with `args`, sandboxed by `spec` or (None) not at all;
/// each attempt's outcome by `probe target`.
async fn probe(spec: Option<&Spec>, args: &[String]) -> BTreeMap<String, (String, String)> {
    let program = env!("CARGO_BIN_EXE_declass-probe").to_owned();
    let stdout = match spec {
        Some(spec) => {
            let argv: Vec<String> = std::iter::once(program)
                .chain(args.iter().cloned())
                .collect();
            let o = declass_sandbox::run(KIND, spec, &argv, &spec.workspace)
                .await
                .unwrap();
            String::from_utf8_lossy(&o.stdout).into_owned()
        }
        None => {
            let o = std::process::Command::new(program)
                .args(args)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).into_owned()
        }
    };
    stdout
        .lines()
        .map(|l| {
            let field = |k: &str| {
                let at = l.find(&format!("\"{k}\":\"")).unwrap() + k.len() + 4;
                l[at..].split('"').next().unwrap().to_owned()
            };
            (
                format!("{} {}", field("probe"), field("target")),
                (field("outcome"), field("detail")),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_sandboxed_process_stays_inside_with_network_off_and_on() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().canonicalize().unwrap();
    let (ws, outside, home) = (root.join("ws"), root.join("outside"), root.join("home"));
    for dir in [
        ws.join("src"),
        ws.join("data"),
        ws.join(".git/hooks"),
        ws.join(".declass/runs/r"),
        outside.clone(),
        home.clone(),
    ] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let files = [
        (ws.join("src/lib.rs"), "pub fn a() {}\n"),
        (ws.join("data/customers.csv"), "id,email\n1,a@b.example\n"),
        (ws.join(".git/config"), "[core]\n"),
        (
            ws.join(".declass/runs/r/vault.json"),
            "{\"secret\":\"v\"}\n",
        ),
        (home.join(".zshrc"), "export PATH\n"),
        (outside.join("token"), "sign-in token\n"),
    ];
    for (path, text) in &files {
        std::fs::write(path, text).unwrap();
    }
    // As Declass registers its own sign-ins.
    SIGN_INS.set(outside.join("token")).unwrap();
    declass_sandbox::deny_to_every_process(sign_ins);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || for _ in listener.incoming() {});
    // A local service's socket (an SSH agent, a container daemon).
    let socket = outside.join("agent.sock");
    let unix = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || for _ in unix.incoming() {});

    let s = |p: &Path| p.display().to_string();
    let mut args: Vec<(String, String, Want, Want)> = vec![
        // (flag, target, network off, network on)
        (
            "--read".into(),
            s(&ws.join("src/lib.rs")),
            Want::Escaped,
            Want::Escaped,
        ),
        (
            "--read".into(),
            s(&ws.join("data/customers.csv")),
            Want::Blocked,
            Want::Blocked,
        ),
        (
            "--read".into(),
            s(&ws.join(".declass/runs/r/vault.json")),
            Want::Blocked,
            Want::Blocked,
        ),
        (
            "--read".into(),
            s(&outside.join("token")),
            Want::Blocked,
            Want::Blocked,
        ),
        (
            "--write".into(),
            s(&ws.join("notes.txt")),
            Want::Escaped,
            Want::Escaped,
        ),
        (
            "--write".into(),
            s(&outside.join("planted")),
            Want::Blocked,
            Want::Blocked,
        ),
        (
            "--write".into(),
            s(&home.join(".zshrc")),
            Want::Blocked,
            Want::Blocked,
        ),
        (
            "--write".into(),
            s(&ws.join(".git/hooks/pre-commit")),
            Want::Blocked,
            Want::Blocked,
        ),
        (
            "--write".into(),
            s(&ws.join(".git/config")),
            Want::Blocked,
            Want::Blocked,
        ),
        (
            "--write".into(),
            s(&ws.join(".declass").join("planted")),
            Want::Blocked,
            Want::Blocked,
        ),
        (
            "--tcp".into(),
            format!("127.0.0.1:{port}"),
            Want::Blocked,
            Want::Escaped,
        ),
        (
            "--tcp".into(),
            "1.1.1.1:443".into(),
            Want::Blocked,
            Want::Escaped,
        ),
        (
            "--resolve".into(),
            "example.com".into(),
            Want::Blocked,
            Want::Escaped,
        ),
        // Known gap, network on: a local socket outside the workspace is
        // reachable under Seatbelt (`network*` covers Unix sockets), so a
        // server with network can talk to an SSH agent or a container daemon.
        // Under bubblewrap the directory is not mounted in the sandbox.
        (
            "--unix".into(),
            s(&socket),
            Want::Blocked,
            if cfg!(target_os = "macos") {
                Want::Escaped
            } else {
                Want::Blocked
            },
        ),
    ];
    if cfg!(target_os = "macos") {
        args.push((
            "--exec".into(),
            "/usr/bin/pbpaste".into(),
            Want::Blocked,
            Want::Blocked,
        ));
    }
    let flat: Vec<String> = args
        .iter()
        .flat_map(|(f, t, ..)| [f.clone(), t.clone()])
        .collect();
    let control = probe(None, &flat).await;
    // The control wrote these; start the sandboxed runs from the same state.
    for (path, text) in &files {
        std::fs::write(path, text).unwrap();
    }
    for p in [
        ws.join("notes.txt"),
        outside.join("planted"),
        ws.join(".git/hooks/pre-commit"),
        ws.join(".declass").join("planted"),
    ] {
        let _ = std::fs::remove_file(p);
    }
    let mut failures = Vec::new();
    for (network, on) in [(Network::Off, false), (Network::All, true)] {
        let spec = Spec {
            workspace: ws.clone(),
            scratch: root.join(if on { "scratch-on" } else { "scratch-off" }),
            network,
            timeout: Duration::from_secs(60),
            output_cap: 64 * 1024,
            spill_file: None,
            extra_env: vec![],
            deny_read: vec![ws.join("data")],
            readable_home_secrets: Vec::new(),
            read_only: false,
        };
        let got = probe(Some(&spec), &flat).await;
        for (flag, target, off, with) in &args {
            let key = format!("{} {target}", flag.trim_start_matches("--"));
            if control.get(&key).map(|(o, _)| o.as_str()) != Some("escaped") {
                continue; // Not possible on this machine at all.
            }
            let want = if on { *with } else { *off };
            let (outcome, detail) = got.get(&key).cloned().unwrap_or_default();
            let ok = match want {
                Want::Blocked => outcome == "blocked",
                Want::Escaped => outcome == "escaped",
            };
            if !ok {
                failures.push(format!(
                    "network {}: {key}: {outcome} ({detail}), wanted {want:?}",
                    if on { "on" } else { "off" }
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
