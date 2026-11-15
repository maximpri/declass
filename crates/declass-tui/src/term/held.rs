// SPDX-License-Identifier: GPL-3.0-or-later
//! Which files the operator's views name and never show: the content of a
//! write or an edit (with placeholders restored), or a file's place for an
//! editor to open. The workspace and an editor (`declass acp`) share one
//! rule, so neither shows what the other holds.
//!
//! A path is judged as the file tools open it, not as the frontier wrote it:
//! `./data/customers.csv`, `.ENV` or `DATA/…` where the file system ignores
//! letter case, or a name in the other Unicode form, is the file it opens
//! (`declass_fs::resolve_relative`). It is also judged folded, as a file
//! system that ignores case compares names, so a new file whose name only
//! differs in case from what the boundary holds back is held too.

use declass_boundary::view::Presenter;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Whether a view names a path (as the frontier wrote it) and never shows
/// its content or its place.
pub type Held = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// [`Held`] for the workspace `ws`, where `holds_back` is the boundary's
/// rule for a workspace-relative path. Declass's own state (`.declass`,
/// `.git`) is held, and so is a path the tools would not open (absolute,
/// with `..`, or one that does not resolve).
pub fn held(ws: PathBuf, holds_back: impl Fn(&Path) -> bool + Send + Sync + 'static) -> Held {
    Arc::new(move |raw: &str| {
        let Ok(rel) = declass_fs::resolve_relative(&ws, raw) else {
            return true;
        };
        let folded = PathBuf::from(declass_fs::fold_name(&rel.to_string_lossy()));
        [rel.as_path(), folded.as_path()]
            .into_iter()
            .any(|p| declass_fs::is_reserved(p) || holds_back(p))
    })
}

/// The boundary's rule, as a session's presenter applies it: sensitive (by
/// policy, or derived from sensitive data during the run) or protected
/// source (sealed or interface-only).
pub fn holds_back(presenter: &dyn Presenter, path: &Path) -> bool {
    presenter.path_sensitive(path) || presenter.protection(path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use declass_boundary::policy::{IpLevel, Policy};
    use declass_boundary::view::Source;

    /// A presenter that holds what `policy` makes sensitive or protected, and
    /// one file derived from sensitive data.
    struct Boundary(Policy);

    impl Presenter for Boundary {
        fn present(&self, _: &Source, bytes: &[u8]) -> String {
            String::from_utf8_lossy(bytes).into_owned()
        }
        fn path_sensitive(&self, path: &Path) -> bool {
            self.0.is_sensitive_path(path) || path == Path::new("out/report.txt")
        }
        fn protection(&self, path: &Path) -> Option<IpLevel> {
            self.0.ip_level(path)
        }
    }

    #[test]
    fn a_path_is_judged_as_the_tools_open_it() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().canonicalize().unwrap();
        for dir in ["data", "src", "out", "pricing", "donne\u{301}es"] {
            std::fs::create_dir_all(ws.join(dir)).unwrap();
        }
        for file in [
            ".env",
            "data/customers.csv",
            "src/lib.rs",
            "out/report.txt",
            "pricing/engine.rs",
            "donne\u{301}es/clients.json",
        ] {
            std::fs::write(ws.join(file), "").unwrap();
        }
        let boundary = Arc::new(Boundary(Policy {
            sensitive_globs: vec![".env*".into(), "data/**".into(), "donn\u{e9}es/**".into()],
            sealed: vec!["pricing/**".into()],
            ..Policy::default()
        }));
        let holds = held(ws.clone(), move |p| holds_back(boundary.as_ref(), p));
        for raw in [
            ".env",
            "./.env",
            ".ENV",
            ".Env.local",
            "data/customers.csv",
            "./data/customers.csv",
            "data/./customers.csv",
            "DATA/customers.csv",
            "Data/Customers.CSV",
            "data/new.csv",
            // Derived from sensitive data during the run.
            "out/report.txt",
            "./out/report.txt",
            // Protected source.
            "pricing/engine.rs",
            "PRICING/engine.rs",
            // The other Unicode form of a sensitive folder's name.
            "donn\u{e9}es/clients.json",
            "donne\u{301}es/clients.json",
            // Declass's own state, and what the tools would not open.
            ".declass/vault.json",
            ".git/config",
            "../outside.txt",
            "src/../.env",
            "/etc/passwd",
            "",
        ] {
            assert!(holds(raw), "{raw:?} is shown");
        }
        let written = ws.join("src/lib.rs").display().to_string();
        for raw in [
            "src/lib.rs",
            "./src/lib.rs",
            "SRC/lib.rs",
            "notes.txt",
            "out/other.txt",
        ] {
            assert!(!holds(raw), "{raw:?} is held");
        }
        // A path as written from the file system's root is not the tools'.
        assert!(holds(&written));
    }
}
