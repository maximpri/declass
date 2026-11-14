// SPDX-License-Identifier: GPL-3.0-or-later
//! The content digest of a set of files, computed exactly as ToolHive's lock
//! file pins it (`contentDigest`, a frozen algorithm), so the same files give
//! the same digest in both: each path in slash form, files sorted by path
//! byte by byte, and for each file its path, a NUL byte, the 32-byte SHA-256
//! of its content and a newline fed into one SHA-256. Only content counts:
//! file modes and timestamps do not.

use crate::digest::Sha256Digest;
use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentError {
    #[error("a content digest needs at least one file")]
    Empty,
    #[error("invalid file path in a content digest: {0:?}")]
    Path(String),
}

/// `path` as the digest names it: leading `./` removed. Refused: an empty
/// path, `..` as a component at either end or inside, an absolute path, and
/// control bytes (NUL and newline delimit the digested fields, so a path
/// holding them could reproduce another file set's bytes). As in ToolHive
/// on Unix, a backslash is an ordinary character.
pub fn normalize(path: &str) -> Result<String, ContentError> {
    let mut p = path;
    while let Some(rest) = p.strip_prefix("./") {
        p = rest;
    }
    if p.is_empty()
        || p == ".."
        || p.starts_with("../")
        || p.contains("/../")
        || p.ends_with("/..")
        || p.starts_with('/')
        || p.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err(ContentError::Path(path.chars().take(200).collect()));
    }
    Ok(p.to_owned())
}

/// The digest of `files`, given as (path, SHA-256 of the content), in any
/// order.
pub fn content_digest<'a>(
    files: impl IntoIterator<Item = (&'a str, [u8; 32])>,
) -> Result<Sha256Digest, ContentError> {
    let mut normalized = files
        .into_iter()
        .map(|(path, hash)| normalize(path).map(|p| (p, hash)))
        .collect::<Result<Vec<_>, _>>()?;
    if normalized.is_empty() {
        return Err(ContentError::Empty);
    }
    // Stable: equal paths (ToolHive does not refuse them) keep their order.
    normalized.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut h = Sha256::new();
    for (path, hash) in &normalized {
        h.update(path.as_bytes());
        h.update([0]);
        h.update(hash);
        h.update(b"\n");
    }
    Ok(Sha256Digest(h.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(files: &[(&str, &[u8])]) -> Result<String, ContentError> {
        content_digest(
            files
                .iter()
                .map(|(p, c)| (*p, Sha256Digest::of(c).0))
                .collect::<Vec<_>>(),
        )
        .map(|d| d.to_string())
    }

    /// ToolHive's golden vectors (pkg/skills/lockfile/contentdigest_test.go):
    /// a change here breaks every lock file that pins a skill.
    #[test]
    fn matches_toolhives_golden_vectors() {
        assert_eq!(
            digest(&[("a.txt", b"hello world")]).unwrap(),
            "sha256:79d1b89c9733bc5a3c51bd715612a85ab13add6933cb9aa7cc1ae44fd5d181a3"
        );
        assert_eq!(
            digest(&[("SKILL.md", b"# Skill"), ("refs/guide.md", b"guide")]).unwrap(),
            "sha256:9b46342aaebede490f12bf67a5ecb4be507c7684ee5e11a0511b54c701f464bd"
        );
    }

    #[test]
    fn order_and_dot_slash_do_not_matter_content_does() {
        let a = digest(&[("SKILL.md", b"# Skill"), ("refs/guide.md", b"guide")]).unwrap();
        let b = digest(&[("refs/guide.md", b"guide"), ("././SKILL.md", b"# Skill")]).unwrap();
        assert_eq!(a, b);
        assert_ne!(
            digest(&[("a.txt", b"v1")]).unwrap(),
            digest(&[("a.txt", b"v2")]).unwrap()
        );
    }

    #[test]
    fn refuses_empty_sets_traversal_and_control_bytes() {
        assert_eq!(digest(&[]), Err(ContentError::Empty));
        for p in [
            "",
            "..",
            "../escape.txt",
            "a/../../escape.txt",
            "a/..",
            "/abs/path.txt",
            "a\0b.txt",
            "a\nb.txt",
            "a\x7fb.txt",
        ] {
            assert!(
                matches!(digest(&[(p, b"x")]), Err(ContentError::Path(_))),
                "{p:?}"
            );
        }
        // One crafted path that would reproduce two files' bytes.
        let x = Sha256Digest::of(b"hello world").0;
        let mut forged = b"x\0".to_vec();
        forged.extend_from_slice(&x);
        forged.extend_from_slice(b"\ny");
        let forged = String::from_utf8_lossy(&forged).into_owned();
        assert!(digest(&[(forged.as_str(), b"second file content")]).is_err());
    }
}
