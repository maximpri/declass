// SPDX-License-Identifier: GPL-3.0-or-later
//! What each kind of sandboxed process may read, side by side: ordinary,
//! read-only, check and sensitive-data commands, MCP stdio servers and
//! language servers. Each row is built by the code that builds that
//! process's sandbox; then one real process per row reads a path the program
//! registered as never readable, which every row must refuse.

use crate::tools::{
    Access, command_deny_read, command_pin_readable, hidden_from_processes, sensitive_scratch,
};
use declass_boundary::engine::Engine;
use declass_boundary::policy::Policy;
use declass_boundary::view::Presenter;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A workspace with sensitive data, interface-only (protected) source and
/// ordinary source.
struct Workspace {
    _dir: tempfile::TempDir,
    ws: PathBuf,
    run: PathBuf,
    engine: std::sync::Arc<Engine>,
}

fn workspace() -> Workspace {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (ws, run) = (root.join("ws"), root.join("run"));
    std::fs::create_dir_all(ws.join("data")).unwrap();
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(ws.join("data/customers.csv"), "id,email\n1,a@b.example\n").unwrap();
    std::fs::write(ws.join("src/pricing.rs"), "pub fn price() -> u32 { 42 }\n").unwrap();
    std::fs::write(ws.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
    let engine = Engine::open(
        &run,
        Policy {
            sensitive_globs: vec!["data/**".into()],
            interface_only: vec!["src/pricing.rs".into()],
            ..Policy::default()
        },
        None,
    )
    .unwrap();
    Workspace {
        _dir: dir,
        ws,
        run,
        engine,
    }
}

/// What a row's own list says about one path: denied (`true`) or not.
fn denies(list: &[PathBuf], path: &Path) -> bool {
    list.iter().any(|d| path.starts_with(d))
}

#[test]
fn every_kind_of_process_is_held_to_its_declared_reads() {
    let w = workspace();
    let p: &dyn Presenter = w.engine.as_ref();
    let data = w.ws.join("data/customers.csv");
    let protected = w.ws.join("src/pricing.rs");
    let source = w.ws.join("src/lib.rs");
    let scratch = sensitive_scratch(&w.run).join("x");
    let rows: Vec<(&str, Vec<PathBuf>)> = vec![
        (
            "ordinary command",
            command_deny_read(p, &w.ws, &w.run, Access::Ordinary).0,
        ),
        (
            "read-only command",
            command_deny_read(p, &w.ws, &w.run, Access::ReadOnly).0,
        ),
        (
            "check",
            command_deny_read(p, &w.ws, &w.run, Access::Checks).0,
        ),
        (
            "sensitive_data command",
            command_deny_read(p, &w.ws, &w.run, Access::SensitiveData).0,
        ),
        ("MCP stdio server", hidden_from_processes(p, &w.ws, &w.run)),
        (
            "language server",
            crate::code_nav::server_hidden(p, &w.ws, &w.run),
        ),
    ];
    // Declared: (sensitive data, protected source, the sensitive commands'
    // TMPDIR, ordinary source). The sandbox adds run state and the
    // credential stores to every row (checked below).
    let declared = [
        ("ordinary command", (true, true, true, false)),
        ("read-only command", (true, true, true, false)),
        ("check", (true, false, true, false)),
        ("sensitive_data command", (false, false, false, false)),
        ("MCP stdio server", (true, true, true, false)),
        ("language server", (true, false, true, false)),
    ];
    for ((name, list), (declared_name, want)) in rows.iter().zip(declared) {
        assert_eq!(*name, declared_name);
        let got = (
            denies(list, &data),
            denies(list, &protected),
            denies(list, &scratch),
            denies(list, &source),
        );
        assert_eq!(got, want, "{name}: {list:?}");
    }
    // Checks may read protected source, so they get no network.
    assert!(command_deny_read(p, &w.ws, &w.run, Access::Checks).1);
}

#[test]
fn what_a_process_may_read_and_others_may_not_is_held_in_place() {
    // A command that reads what the next ordinary command may not must not
    // be able to rename it: the next command's deny list names it there.
    let w = workspace();
    let p: &dyn Presenter = w.engine.as_ref();
    let data = w.ws.join("data");
    let protected = w.ws.join("src/pricing.rs");
    let source = w.ws.join("src/lib.rs");
    let pins = |a| command_pin_readable(p, &w.ws, a);
    for access in [Access::Ordinary, Access::ReadOnly] {
        assert!(pins(access).is_empty());
    }
    let sensitive = pins(Access::SensitiveData);
    assert!(denies(&sensitive, &data) && denies(&sensitive, &protected));
    assert!(!denies(&sensitive, &source));
    // A check reads protected source, but not sensitive data.
    let checks = pins(Access::Checks);
    assert!(denies(&checks, &protected));
    assert!(!denies(&checks, &data) && !denies(&checks, &source));
}

static NEVER: OnceLock<PathBuf> = OnceLock::new();

fn never() -> Vec<PathBuf> {
    NEVER.get().cloned().into_iter().collect()
}

/// One real process per row: a path the program registered as never
/// readable is refused to each, whatever its own list says.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn every_kind_of_process_is_denied_what_the_program_registered() {
    let w = workspace();
    let p: &dyn Presenter = w.engine.as_ref();
    let secret = w.ws.join("sign-ins/token");
    std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
    std::fs::write(&secret, "tok-5512\n").unwrap();
    NEVER.set(secret.parent().unwrap().to_path_buf()).unwrap();
    declass_sandbox::deny_to_every_process(never);
    let kind = declass_sandbox::detect().unwrap();
    let lists = [
        command_deny_read(p, &w.ws, &w.run, Access::Ordinary).0,
        command_deny_read(p, &w.ws, &w.run, Access::Checks).0,
        command_deny_read(p, &w.ws, &w.run, Access::SensitiveData).0,
        hidden_from_processes(p, &w.ws, &w.run),
        crate::code_nav::server_hidden(p, &w.ws, &w.run),
    ];
    for (i, deny_read) in lists.into_iter().enumerate() {
        let spec = declass_sandbox::Spec {
            workspace: w.ws.clone(),
            scratch: w.run.join(format!("scratch-{i}")),
            network: declass_sandbox::Network::Off,
            timeout: std::time::Duration::from_secs(20),
            output_cap: 4096,
            spill_file: None,
            extra_env: Vec::new(),
            deny_read,
            readable_home_secrets: Vec::new(),
            pin_readable: Vec::new(),
            read_only: false,
        };
        let out = declass_sandbox::run(
            kind,
            &spec,
            &[
                "/bin/sh".into(),
                "-c".into(),
                "cat sign-ins/token; echo done".into(),
            ],
            &w.ws,
        )
        .await
        .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("done") && !text.contains("tok-5512"),
            "row {i}: {text}"
        );
    }
}
