// SPDX-License-Identifier: GPL-3.0-or-later
//! Where a workspace's git history is kept, found as git finds it, without
//! running git.
//!
//! The history (committed copies of every file, sensitive ones included) is
//! usually `.git` at the workspace root. It is elsewhere when the workspace
//! is a subdirectory of a repository (`.git` is in a folder above it), a
//! linked worktree (`git worktree add`: `.git` is a file naming a directory
//! inside the main repository's `.git`, which shares that repository's
//! objects through `commondir`), a submodule, or a repository made with
//! `--separate-git-dir`.

use std::path::{Path, PathBuf};

/// The directories a `.git` entry stands for: the directory itself, or for a
/// `.git` file (`gitdir: <path>`) the directory it names and the common
/// directory that one shares (`commondir`). Paths are resolved (canonical);
/// ones that do not exist are left out.
pub fn named_by(dot_git: &Path) -> Vec<PathBuf> {
    let Ok(meta) = std::fs::metadata(dot_git) else {
        return Vec::new();
    };
    let git_dir = if meta.is_dir() {
        dot_git.to_path_buf()
    } else {
        let Some(target) = std::fs::read_to_string(dot_git).ok().and_then(|text| {
            text.lines()
                .next()?
                .strip_prefix("gitdir:")
                .map(|t| t.trim().to_owned())
        }) else {
            return Vec::new();
        };
        match dot_git.parent() {
            Some(dir) => dir.join(target),
            None => PathBuf::from(target),
        }
    };
    let Ok(git_dir) = git_dir.canonicalize() else {
        return Vec::new();
    };
    let common = std::fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .and_then(|c| git_dir.join(c.trim()).canonicalize().ok());
    let mut out = vec![git_dir];
    out.extend(common.filter(|c| !out.iter().any(|d| c.starts_with(d))));
    out
}

/// The git directories holding the history of the repository `workspace` is
/// in: those of the nearest `.git` at the workspace or above it, as git's
/// own discovery finds it. Empty outside a repository.
pub fn history_dirs(workspace: &Path) -> Vec<PathBuf> {
    workspace
        .ancestors()
        .map(|dir| dir.join(".git"))
        .find(|dot_git| dot_git.symlink_metadata().is_ok())
        .map(|dot_git| named_by(&dot_git))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_found_above_the_workspace_and_through_git_files() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let main = root.join("main");
        let common = main.join(".git");
        let linked = common.join("worktrees/wt");
        std::fs::create_dir_all(main.join("app/src")).unwrap();
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(linked.join("commondir"), "../..\n").unwrap();
        // A subdirectory of the repository, at any depth.
        assert_eq!(history_dirs(&main.join("app/src")), vec![common.clone()]);
        assert_eq!(history_dirs(&main), vec![common.clone()]);
        // A linked worktree: its own directory and the shared one.
        let wt = root.join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", linked.display())).unwrap();
        assert_eq!(history_dirs(&wt), vec![linked.clone(), common.clone()]);
        // A relative `gitdir` (submodules write one) is relative to the file.
        let sub = main.join("vendor/lib");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(common.join("modules/lib")).unwrap();
        std::fs::write(sub.join(".git"), "gitdir: ../../.git/modules/lib\n").unwrap();
        assert_eq!(history_dirs(&sub), vec![common.join("modules/lib")]);
        // Outside any repository, and a malformed `.git` file.
        let plain = root.join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        assert!(history_dirs(&plain).is_empty());
        std::fs::write(plain.join(".git"), "not a pointer\n").unwrap();
        assert!(history_dirs(&plain).is_empty());
    }
}
