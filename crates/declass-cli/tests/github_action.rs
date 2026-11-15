// SPDX-License-Identifier: GPL-3.0-or-later
//! The GitHub Action's steps (`tools/github-action.sh`, run by `action.yml`)
//! outside GitHub. The exposure step runs the built `declass`; the install
//! step runs from a copy of the checkout whose installer is a stub, so nothing
//! is downloaded. What stays untested here: the real download and signature
//! check on GitHub's runners, and code scanning accepting the upload.
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn executable(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

struct Runner {
    tmp: tempfile::TempDir,
}

impl Runner {
    fn new() -> Self {
        let runner = Self {
            tmp: tempfile::tempdir().unwrap(),
        };
        for dir in ["temp", "owner", "project/src", "project/docs"] {
            std::fs::create_dir_all(runner.path(dir)).unwrap();
        }
        std::fs::write(
            runner.path("project/src/settings.py"),
            concat!("PAYMENTS_KEY = \"sk_", "live_Wq4rT8yU2iO6pA1sD5fG9hJ3k\"\n"),
        )
        .unwrap();
        std::fs::write(
            runner.path("project/docs/team.md"),
            "Ask marisol.quintero@harbor-ledger.net.\n",
        )
        .unwrap();
        runner
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().join(rel)
    }

    /// `declass` as a release of `version` reports itself; the built binary does the work.
    fn declass(&self, version: &str) -> PathBuf {
        let wrapper = self.path(&format!("bin-{version}/declass"));
        executable(
            &wrapper,
            &format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'declass {version}'; exit 0; fi\nexec '{}' \"$@\"\n",
                env!("CARGO_BIN_EXE_declass")
            ),
        );
        wrapper
    }

    fn step(&self, script: &Path, step: &str, env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new("bash");
        cmd.arg(script)
            .arg(step)
            .current_dir(self.path("project"))
            .env("RUNNER_TEMP", self.path("temp"))
            .env("GITHUB_OUTPUT", self.path("output"))
            .env("GITHUB_STEP_SUMMARY", self.path("summary"))
            .env("GITHUB_ENV", self.path("env"))
            .env("GITHUB_PATH", self.path("ghpath"))
            .env("DECLASS_CONFIG_HOME", self.path("owner"))
            .env_remove("DECLASS_VERSION");
        for name in [
            "EXPOSURE_PATH",
            "EXPOSURE_SARIF",
            "EXPOSURE_FAIL_ON",
            "EXPOSURE_HISTORY",
            "EXPOSURE_PROJECT_CONFIG",
            "EXPOSURE_BASE_SHA",
        ] {
            cmd.env_remove(name);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path(rel)).unwrap_or_default()
    }
}

#[test]
fn the_exposure_step_writes_sarif_sets_outputs_and_fails_as_asked() {
    let r = Runner::new();
    let script = repo().join("tools/github-action.sh");
    let declass = r.declass("0.4.0");
    let declass = declass.to_str().unwrap();
    let run = |fail_on: &str| {
        r.step(
            &script,
            "exposure",
            &[
                ("DECLASS_BIN", declass),
                ("EXPOSURE_SARIF", "reports/exposure.sarif"),
                ("EXPOSURE_FAIL_ON", fail_on),
            ],
        )
    };

    let out = run("never");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("Exposure · "));
    let sarif: Value = serde_json::from_str(&r.read("project/reports/exposure.sarif")).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(
        r.read("output"),
        "sarif-file=reports/exposure.sarif\nexit-code=0\n"
    );
    let summary = r.read("summary");
    assert!(summary.starts_with("### Declass exposure\n\n```text\nExposure · "));
    assert!(!summary.contains("sk_live") && !summary.contains("marisol"));

    // A secret in a file the cloud model reads fails at error; the report is still written.
    let out = run("error");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("::error title=Declass exposure::findings at or above --fail-on error")
    );
    assert!(r.path("project/reports/exposure.sarif").exists());
    assert!(r.read("output").ends_with("exit-code=1\n"));

    // Bad inputs are refused before declass runs.
    for (key, value, message) in [
        ("EXPOSURE_FAIL_ON", "sometimes", "fail-on must be"),
        ("EXPOSURE_HISTORY", "yes", "history must be true or false"),
        (
            "EXPOSURE_SARIF",
            "a\nb.sarif",
            "sarif-file must be one line",
        ),
    ] {
        let out = r.step(
            &script,
            "exposure",
            &[("DECLASS_BIN", declass), (key, value)],
        );
        assert_eq!(out.status.code(), Some(1));
        assert!(text(&out).contains(message), "{}", text(&out));
    }

    // A report that cannot be written leaves no stale one behind to upload.
    std::fs::create_dir_all(r.path("project/.declass")).unwrap();
    std::fs::write(
        r.path("project/.declass/config.toml"),
        "[sensitivity]\ncustom_patterns = ['(']\n",
    )
    .unwrap();
    let out = run("never");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out).contains("declass exposure wrote no report"),
        "{}",
        text(&out)
    );
    assert!(!r.path("project/reports/exposure.sarif").exists());

    // An older Declass is named, not run.
    let old = r.declass("0.3.0");
    let out = r.step(
        &script,
        "exposure",
        &[("DECLASS_BIN", old.to_str().unwrap())],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out).contains("needs Declass 0.4.0 or later; this is declass 0.3.0"),
        "{}",
        text(&out)
    );
}

#[test]
fn the_install_step_pins_the_signer_from_the_checkout_and_refuses_old_releases() {
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("ssh-keygen is not installed; skipped");
        return;
    }
    let r = Runner::new();
    // A copy of the checkout whose installer only records what it was asked.
    let action = r.path("action");
    std::fs::create_dir_all(action.join("docs")).unwrap();
    executable(
        &action.join("tools/github-action.sh"),
        &std::fs::read_to_string(repo().join("tools/github-action.sh")).unwrap(),
    );
    std::fs::copy(
        repo().join("docs/declass-release.pub"),
        action.join("docs/declass-release.pub"),
    )
    .unwrap();
    std::fs::write(
        action.join("Cargo.toml"),
        "[workspace.package]\nversion = \"0.4.1\"\n",
    )
    .unwrap();
    executable(
        &action.join("tools/install-release.sh"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$RUNNER_TEMP/installer-args\"\n\
         printf '%s\\n' \"$DECLASS_INSTALL_DIR\" > \"$RUNNER_TEMP/installer-dir\"\n\
         mkdir -p \"$DECLASS_INSTALL_DIR\"\n\
         printf '#!/bin/sh\\necho \"declass %s\"\\n' \"$1\" > \"$DECLASS_INSTALL_DIR/declass\"\n\
         chmod 755 \"$DECLASS_INSTALL_DIR/declass\"\n",
    );
    let script = action.join("tools/github-action.sh");

    // Empty version: the checkout's own.
    let out = r.step(&script, "install", &[("DECLASS_VERSION", "")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let dir = r.path("temp/declass-action");
    assert_eq!(
        r.read("temp/installer-args").trim(),
        format!(
            "0.4.1 --signers {} --no-modify-path",
            dir.join("allowed_signers").display()
        )
    );
    let key = std::fs::read_to_string(repo().join("docs/declass-release.pub")).unwrap();
    let mut fields = key.split_whitespace();
    let (kind, data) = (fields.next().unwrap(), fields.next().unwrap());
    assert_eq!(
        std::fs::read_to_string(dir.join("allowed_signers")).unwrap(),
        format!("declass-release namespaces=\"declass-release\" {kind} {data}\n")
    );
    assert_eq!(
        r.read("env"),
        format!("DECLASS_BIN={}\n", dir.join("bin/declass").display())
    );
    assert_eq!(r.read("ghpath"), format!("{}\n", dir.join("bin").display()));
    assert!(text(&out).contains("Installed declass 0.4.1"));

    // Too old, or not a version: refused before anything is downloaded. A
    // pre-release comes before its release, as in semantic versioning.
    for (version, message) in [
        (
            "0.3.0",
            "needs Declass 0.4.0 or later; version 0.3.0 is older",
        ),
        (
            "0.4.0-rc.1",
            "needs Declass 0.4.0 or later; version 0.4.0-rc.1 is older",
        ),
        ("latest", "version must be a release number"),
        ("1.0.0; touch x", "version must be a release number"),
        // A line break cannot start a workflow command of its own.
        (
            "9.9\n::warning::injected",
            "not '9.9%0A::warning::injected'",
        ),
    ] {
        std::fs::remove_file(r.path("temp/installer-args")).unwrap_or_default();
        let out = r.step(&script, "install", &[("DECLASS_VERSION", version)]);
        assert_eq!(out.status.code(), Some(1), "{version}");
        assert!(text(&out).contains(message), "{version}: {}", text(&out));
        assert!(
            !r.path("temp/installer-args").exists(),
            "{version}: installer ran"
        );
        assert!(
            !text(&out).lines().any(|l| l.starts_with("::warning")),
            "{}",
            text(&out)
        );
    }

    // An action commit from before the release with --sarif says why.
    std::fs::write(
        action.join("Cargo.toml"),
        "[workspace.package]\nversion = \"0.3.0\"\n",
    )
    .unwrap();
    let out = r.step(&script, "install", &[("DECLASS_VERSION", "")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out).contains(
            "this action's commit is Declass 0.3.0, and declass exposure --sarif arrived in 0.4.0: use the action from a release tag (maximpri/declass@v0.4.0 or later)"
        ),
        "{}",
        text(&out)
    );

    // Another signer in the checkout is refused.
    let other = r.path("other");
    let made = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "someone else", "-f"])
        .arg(&other)
        .output()
        .unwrap();
    assert!(made.status.success());
    std::fs::copy(
        other.with_extension("pub"),
        action.join("docs/declass-release.pub"),
    )
    .unwrap();
    let out = r.step(&script, "install", &[("DECLASS_VERSION", "0.4.1")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out).contains("is not the Declass release key"),
        "{}",
        text(&out)
    );
}

/// A file name the report prints could be a workflow command (`::warning::`,
/// `::add-mask::`, `::stop-commands::`), and the runner trims leading spaces:
/// the report is printed where the runner reads no command.
#[test]
fn nothing_the_report_prints_can_act_as_a_workflow_command() {
    let r = Runner::new();
    let script = repo().join("tools/github-action.sh");
    std::fs::write(
        r.path("project/src/::warning::pwned.py"),
        concat!("API_KEY = \"sk_", "live_Wq4rT8yU2iO6pA1sD5fG9hJ3k\"\n"),
    )
    .unwrap();
    let declass = r.declass("0.4.0");
    let run = || {
        r.step(
            &script,
            "exposure",
            &[("DECLASS_BIN", declass.to_str().unwrap())],
        )
    };
    let out = run();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    let stop = lines
        .iter()
        .position(|l| l.starts_with("::stop-commands::"))
        .expect("commands are stopped");
    let token = &lines[stop]["::stop-commands::".len()..];
    assert!(token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit()));
    let resume = lines
        .iter()
        .position(|l| *l == format!("::{token}::"))
        .expect("commands are resumed");
    let named = lines
        .iter()
        .position(|l| l.contains("::warning::pwned"))
        .expect("the file is listed");
    assert!(stop < named && named < resume, "{stdout}");
    for (i, line) in lines.iter().enumerate() {
        assert!(
            (stop..=resume).contains(&i) || !line.trim_start().starts_with("::"),
            "a workflow command outside the report's block: {line}"
        );
    }
    // A new token each run: no file can name the one that resumes commands.
    let again = String::from_utf8(run().stdout).unwrap();
    assert!(!again.contains(&format!("::{token}::")));
}

/// A pull request that loosens `.declass/config.toml` does not loosen its own
/// gate: by default the step uses the base commit's.
#[test]
fn a_pull_request_cannot_waive_its_own_gate() {
    let r = Runner::new();
    let script = repo().join("tools/github-action.sh");
    let project = r.path("project");
    let git = |args: &[&str]| {
        let out = declass_git::Git::locate()
            .unwrap()
            .run(&project, args, &[], None)
            .unwrap();
        String::from_utf8(out).unwrap().trim().to_owned()
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "base"]);
    let base = git(&["rev-parse", "HEAD"]);
    let waiver = "[sensitivity]\nprotected_paths = [\"**\"]\n";
    std::fs::create_dir_all(project.join(".declass")).unwrap();
    std::fs::write(project.join(".declass/config.toml"), waiver).unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "keep everything local"]);
    let declass = r.declass("0.4.0");
    let step = |extra: &[(&str, &str)]| {
        let mut env = vec![
            ("DECLASS_BIN", declass.to_str().unwrap()),
            ("EXPOSURE_FAIL_ON", "error"),
            ("EXPOSURE_BASE_SHA", base.as_str()),
        ];
        env.extend_from_slice(extra);
        r.step(&script, "exposure", &env)
    };
    let held = step(&[]);
    assert_eq!(held.status.code(), Some(1), "{}", text(&held));
    // The checkout's own .declass/ is back as it was.
    let config = || std::fs::read_to_string(project.join(".declass/config.toml")).unwrap();
    assert_eq!(config(), waiver);
    // Asked for, the checkout's configuration applies.
    let waived = step(&[("EXPOSURE_PROJECT_CONFIG", "checkout")]);
    assert_eq!(waived.status.code(), Some(0), "{}", text(&waived));
    // A base commit the checkout lacks is refused, with what to do.
    let lacking = step(&[(
        "EXPOSURE_BASE_SHA",
        "0123456789abcdef0123456789abcdef01234567",
    )]);
    assert_eq!(lacking.status.code(), Some(1));
    assert!(
        text(&lacking).contains("base commit is not in this checkout"),
        "{}",
        text(&lacking)
    );
    assert_eq!(config(), waiver);
}
