// SPDX-License-Identifier: GPL-3.0-or-later
//! The local model's checks through the binary, offline: the owner's
//! disclosure narrative (`declass audit disclosure --narrative`) and the
//! suites of `declass local-eval`. The checks themselves are tested in
//! `declass_boundary::engine::checks`.

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

#[test]
fn the_narrative_is_printed_for_the_owner_when_a_run_wrote_one() {
    let e = env();
    let run = e.ws.join(".declass/runs/20261006-120000-abcdef");
    std::fs::create_dir_all(&run).unwrap();
    let o = declass(
        &e,
        &[
            "audit",
            "disclosure",
            "20261006-120000-abcdef",
            "--narrative",
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("no disclosure narrative"), "{}", text(&o));
    std::fs::write(
        run.join("disclosure-narrative.md"),
        "# What the frontier could have learned\n\nOnly the CSV's columns.\n",
    )
    .unwrap();
    let o = declass(
        &e,
        &[
            "audit",
            "disclosure",
            "20261006-120000-abcdef",
            "--narrative",
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("Only the CSV's columns."));
    // --narrative and --json are different reports.
    let o = declass(
        &e,
        &[
            "audit",
            "disclosure",
            "20261006-120000-abcdef",
            "--narrative",
            "--json",
        ],
    );
    assert!(!o.status.success());
}

#[test]
fn local_eval_names_its_suites() {
    let e = env();
    let o = declass(&e, &["local-eval", "--suite", "judge,bogus"]);
    assert!(!o.status.success());
    let out = text(&o);
    assert!(
        out.contains("unknown suite bogus") && out.contains("judge, intent, injection"),
        "{out}"
    );
}
