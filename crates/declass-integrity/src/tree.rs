// SPDX-License-Identifier: GPL-3.0-or-later
//! Hashes every regular file under a directory, for content digests.
//!
//! The walk never follows a link: the directory itself must not be one, and
//! inside it links and special files are skipped (and reported), as
//! ToolHive's digest skips them. Each file is opened from its parent's handle
//! without following links, so a directory swapped for a link during the
//! walk cannot lead outside. Names must be UTF-8. Limits bound the number of
//! files, their total size and the depth.

use crate::content::{self, ContentError};
use crate::digest::Sha256Digest;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub files: usize,
    pub bytes: u64,
    pub depth: usize,
}

impl Limits {
    /// A skill or plugin: small text trees.
    pub const PACKAGE: Limits = Limits {
        files: 4096,
        bytes: 64 * 1024 * 1024,
        depth: 32,
    };
    /// An MCP server's install directory (dependencies included).
    pub const INSTALL: Limits = Limits {
        files: 200_000,
        bytes: 4 * 1024 * 1024 * 1024,
        depth: 64,
    };
}

#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("{0} is not a directory (or is a link)")]
    NotDirectory(String),
    #[error("more than {0} files")]
    TooManyFiles(usize),
    #[error("more than {0} bytes")]
    TooLarge(u64),
    #[error("nested deeper than {0} directories")]
    TooDeep(usize),
    #[error("a file name is not UTF-8 under {0}")]
    NotUtf8(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

/// The regular files under a directory: relative path (slash-separated) to
/// the SHA-256 of the content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    pub files: BTreeMap<String, [u8; 32]>,
    /// Links and special files, which no digest covers.
    pub skipped: Vec<String>,
    pub bytes: u64,
}

impl Scan {
    /// The content digest of the files (ToolHive's algorithm).
    pub fn content_digest(&self) -> Result<Sha256Digest, ContentError> {
        content::content_digest(self.files.iter().map(|(p, h)| (p.as_str(), *h)))
    }
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Hashes the tree at `root` within `limits`.
pub fn scan(root: &Path, limits: Limits) -> Result<Scan, TreeError> {
    let shown = || root.display().to_string();
    let io = |source: std::io::Error| TreeError::Io {
        path: shown(),
        source,
    };
    let dir: File = match rustix::fs::open(root, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => fd.into(),
        Err(rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {
            return Err(TreeError::NotDirectory(shown()));
        }
        Err(e) => return Err(io(e.into())),
    };
    let mut scan = Scan::default();
    let mut todo = vec![(dir, String::new(), 0usize)];
    while let Some((dir, prefix, depth)) = todo.pop() {
        if depth > limits.depth {
            return Err(TreeError::TooDeep(limits.depth));
        }
        let at = |name: &str| {
            if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            }
        };
        let err = |rel: &str, source: std::io::Error| TreeError::Io {
            path: format!("{}/{rel}", shown()),
            source,
        };
        for entry in Dir::read_from(&dir).map_err(|e| err(&prefix, e.into()))? {
            let entry = entry.map_err(|e| err(&prefix, e.into()))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let name = std::str::from_utf8(name)
                .map_err(|_| TreeError::NotUtf8(format!("{}/{prefix}", shown())))?;
            let rel = at(name);
            let stat = rustix::fs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| err(&rel, e.into()))?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    let child: File = rustix::fs::openat(&dir, name, DIR_FLAGS, Mode::empty())
                        .map_err(|e| err(&rel, e.into()))?
                        .into();
                    todo.push((child, rel, depth + 1));
                }
                FileType::RegularFile => {
                    if scan.files.len() >= limits.files {
                        return Err(TreeError::TooManyFiles(limits.files));
                    }
                    let left = limits.bytes.saturating_sub(scan.bytes);
                    let hash =
                        hash_file(&dir, name, left, &mut scan.bytes).map_err(|e| match e {
                            Hashing::Limit => TreeError::TooLarge(limits.bytes),
                            Hashing::Io(source) => err(&rel, source),
                        })?;
                    scan.files.insert(rel, hash);
                }
                _ => scan.skipped.push(rel),
            }
        }
    }
    scan.skipped.sort();
    Ok(scan)
}

/// The SHA-256 of the regular file at `path` (a link is followed to its
/// target first; the target is then opened without following links), at
/// most `max` bytes.
pub fn file_digest(path: &Path, max: u64) -> Result<Sha256Digest, TreeError> {
    let target = path.canonicalize().map_err(|source| TreeError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
        return Err(TreeError::NotDirectory(target.display().to_string()));
    };
    let name = name
        .to_str()
        .ok_or_else(|| TreeError::NotUtf8(target.display().to_string()))?;
    let dir: File = rustix::fs::open(parent, DIR_FLAGS, Mode::empty())
        .map_err(|e| TreeError::Io {
            path: parent.display().to_string(),
            source: e.into(),
        })?
        .into();
    let mut total = 0;
    hash_file(&dir, name, max, &mut total)
        .map(Sha256Digest)
        .map_err(|e| match e {
            Hashing::Limit => TreeError::TooLarge(max),
            Hashing::Io(source) => TreeError::Io {
                path: target.display().to_string(),
                source,
            },
        })
}

enum Hashing {
    Limit,
    Io(std::io::Error),
}

/// Streams one file (opened without following a link, refused unless it is
/// still a regular file) into SHA-256, adding its size to `total`.
fn hash_file(parent: &File, name: &str, left: u64, total: &mut u64) -> Result<[u8; 32], Hashing> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file: File = rustix::fs::openat(parent, name, flags, Mode::empty())
        .map_err(|e| Hashing::Io(e.into()))?
        .into();
    let stat = rustix::fs::fstat(&file).map_err(|e| Hashing::Io(e.into()))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(Hashing::Io(std::io::Error::other(
            "replaced by something other than a file during the walk",
        )));
    }
    let mut h = Sha256::new();
    let mut read = 0u64;
    let mut chunk = vec![0u8; 64 * 1024];
    let mut file = file.take(left.saturating_add(1));
    loop {
        let n = file.read(&mut chunk).map_err(Hashing::Io)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > left {
            return Err(Hashing::Limit);
        }
        h.update(&chunk[..n]);
    }
    *total += read;
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("SKILL.md"), "# Skill").unwrap();
        std::fs::create_dir_all(d.path().join("refs")).unwrap();
        std::fs::write(d.path().join("refs/guide.md"), "guide").unwrap();
        d
    }

    #[test]
    fn a_tree_digests_like_toolhives_file_list() {
        let d = tree();
        let scan = scan(d.path(), Limits::PACKAGE).unwrap();
        assert_eq!(
            scan.files.keys().collect::<Vec<_>>(),
            ["SKILL.md", "refs/guide.md"]
        );
        assert_eq!(scan.bytes, 12);
        assert_eq!(
            scan.content_digest().unwrap().to_string(),
            "sha256:9b46342aaebede490f12bf67a5ecb4be507c7684ee5e11a0511b54c701f464bd"
        );
    }

    #[test]
    fn links_are_skipped_and_reported_never_followed() {
        use std::os::unix::fs::symlink;
        let d = tree();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "s3cret").unwrap();
        symlink(outside.path().join("secret"), d.path().join("refs/link")).unwrap();
        symlink(outside.path(), d.path().join("dirlink")).unwrap();
        let scan = scan(d.path(), Limits::PACKAGE).unwrap();
        assert_eq!(scan.skipped, ["dirlink", "refs/link"]);
        assert_eq!(scan.files.len(), 2);
        // The directory itself may not be a link.
        let link = outside.path().join("tree-link");
        symlink(d.path(), &link).unwrap();
        assert!(matches!(
            super::scan(&link, Limits::PACKAGE),
            Err(TreeError::NotDirectory(_))
        ));
    }

    #[test]
    fn a_file_is_hashed_at_its_link_target() {
        use std::os::unix::fs::symlink;
        let d = tree();
        let file = d.path().join("SKILL.md");
        symlink(&file, d.path().join("link")).unwrap();
        let want = Sha256Digest::of(b"# Skill");
        assert_eq!(file_digest(&file, 1024).unwrap(), want);
        assert_eq!(file_digest(&d.path().join("link"), 1024).unwrap(), want);
        assert!(matches!(file_digest(&file, 3), Err(TreeError::TooLarge(3))));
        assert!(file_digest(d.path(), 1024).is_err());
    }

    #[test]
    fn limits_are_enforced() {
        let d = tree();
        let small = |files, bytes, depth| Limits {
            files,
            bytes,
            depth,
        };
        assert!(matches!(
            scan(d.path(), small(1, 1024, 8)),
            Err(TreeError::TooManyFiles(1))
        ));
        assert!(matches!(
            scan(d.path(), small(10, 10, 8)),
            Err(TreeError::TooLarge(10))
        ));
        assert!(matches!(
            scan(d.path(), small(10, 1024, 0)),
            Err(TreeError::TooDeep(0))
        ));
        assert!(scan(d.path(), small(2, 12, 1)).is_ok());
    }
}
