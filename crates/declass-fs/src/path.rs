// SPDX-License-Identifier: GPL-3.0-or-later
//! Lexical validation of model-supplied paths.

use crate::error::FsError;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Directories no tool may write, at any depth.
pub const RESERVED: [&str; 2] = [".git", ".declass"];

/// `name` folded the way a case-insensitive file system compares names, as
/// far as that can make it ASCII: ASCII letters in lower case, and the other
/// characters whose Unicode case folding is made of ASCII letters (`ſ` is
/// `s`; `ß` and `ẞ` are `ss`; the Kelvin sign is `k`; the `ff`, `fi`, `fl`,
/// `ffi`, `ffl` and `st` ligatures). macOS's default volumes (APFS, HFS+)
/// fold this way: `.DECLASS`, `.declaſs` and `.declaß` all open `.declass`.
/// Every other character is kept as it is: no fold turns it into ASCII.
pub fn fold_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            'ſ' => out.push('s'),
            'ß' | 'ẞ' => out.push_str("ss"),
            '\u{212A}' => out.push('k'),
            'ﬀ' => out.push_str("ff"),
            'ﬁ' => out.push_str("fi"),
            'ﬂ' => out.push_str("fl"),
            'ﬃ' => out.push_str("ffi"),
            'ﬄ' => out.push_str("ffl"),
            'ﬅ' | 'ﬆ' => out.push_str("st"),
            c => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

/// Whether a file system may take `name` for `.git` or `.declass`: it is
/// one of them in any spelling [`fold_name`] equates.
pub fn is_reserved_name(name: &OsStr) -> bool {
    match name.to_str() {
        Some(n) => RESERVED.contains(&fold_name(n).as_str()),
        None => RESERVED.iter().any(|r| name == *r),
    }
}

/// Normalizes a workspace-relative path: no absolute paths, no `..`, no empty
/// components. `.` components are dropped.
pub fn normalize_relative(input: &str) -> Result<PathBuf, FsError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(FsError::Outside(input.to_owned()));
    }
    let mut out = PathBuf::new();
    for c in Path::new(trimmed).components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FsError::Outside(input.to_owned()));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(FsError::Outside(input.to_owned()));
    }
    Ok(out)
}

/// Whether `rel` is inside a reserved directory, in any spelling a file
/// system may take for it ([`is_reserved_name`]).
pub fn is_reserved(rel: &Path) -> bool {
    rel.components()
        .any(|c| matches!(c, Component::Normal(p) if is_reserved_name(p)))
}

/// Normalizes a path that a tool intends to write.
pub fn writable_relative(input: &str) -> Result<PathBuf, FsError> {
    let rel = normalize_relative(input)?;
    if is_reserved(&rel) {
        return Err(FsError::Reserved(input.to_owned()));
    }
    Ok(rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_rejects_escapes() {
        assert_eq!(
            normalize_relative("./src//lib.rs").unwrap(),
            PathBuf::from("src/lib.rs")
        );
        for bad in ["", "/etc/passwd", "../x", "a/../../b", ".", "  "] {
            assert!(normalize_relative(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn reserved_directories_at_any_depth() {
        assert!(writable_relative(".git/config").is_err());
        assert!(writable_relative("vendor/lib/.git/hooks/pre-commit").is_err());
        assert!(writable_relative(".declass/runs/x").is_err());
        assert!(writable_relative("src/.gitignore").is_ok());
        assert!(writable_relative("docs/declass.md").is_ok());
    }

    #[test]
    fn reserved_directories_in_every_spelling_a_file_system_equates() {
        // Each of these opens `.git` or `.declass` on APFS (measured).
        for path in [
            ".GIT/config",
            "sub/.Git/hooks/pre-commit",
            ".DECLASS/runs/r1/vault.json",
            ".Declass/config.toml",
            ".declaſs/x",
            ".declaſſ/x",
            ".declaß/x",
            ".declaẞ/x",
        ] {
            assert!(is_reserved(Path::new(path)), "{path}");
            assert!(writable_relative(path).is_err(), "{path}");
        }
        // These are other names on APFS too.
        for path in [
            ".g\u{131}t/x",
            ".gi\u{200d}t/x",
            ".git /x",
            "\u{ff0e}declass/x",
            ".gitignore",
            ".github/workflows/ci.yml",
        ] {
            assert!(!is_reserved(Path::new(path)), "{path}");
        }
        assert_eq!(fold_name("Stra\u{df}e-\u{212a}\u{fb01}"), "strasse-kfi");
    }
}
