// SPDX-License-Identifier: GPL-3.0-or-later
//! Parent-directory handles opened without following links.
//!
//! Every component is opened with `openat(O_NOFOLLOW)` from the workspace root,
//! so a symlink planted anywhere on the path cannot redirect a read or write.
//!
//! A file system that compares names regardless of letter case or Unicode
//! normalization (macOS's default) opens `.DECLASS/vault.json` as
//! `.declass/vault.json`, `DATA/orders.csv` as `data/orders.csv`, and a name
//! written composed (NFC `é`) as the entry stored decomposed (NFD `é`).
//! Checks made on a path as written must see the name the file system opens,
//! so callers [`resolve`] a path to the spelling its folders list before
//! checking it; as a backstop, under a workspace root every existing component
//! must be spelled exactly as listed, or it is refused.

use crate::error::FsError;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub struct PinnedParent {
    dir: File,
    name: OsString,
    path: PathBuf,
}

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

impl PinnedParent {
    /// Opens the parent of `rel` under `root`. With `create`, missing parent
    /// directories are created (mode 0755). Under a workspace root, a
    /// component spelled otherwise than its folder lists it is refused (see
    /// the module documentation); a path from the file system root (`/`, the
    /// owner's own files outside any workspace) is opened as written.
    pub fn open(root: &Path, rel: &Path, create: bool) -> Result<Self, FsError> {
        let name = rel
            .file_name()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| FsError::Outside(rel.display().to_string()))?
            .to_owned();
        let root_fd = rustix::fs::open(root, DIR_FLAGS, Mode::empty())
            .map_err(|e| FsError::io("open workspace root", root, e))?;
        let checked = root != Path::new("/");
        let mut dir: File = root_fd.into();
        let mut shown = root.to_path_buf();
        if let Some(parent) = rel.parent() {
            for c in parent.components() {
                let Component::Normal(part) = c else {
                    return Err(FsError::Outside(rel.display().to_string()));
                };
                shown.push(part);
                let child = open_child(&dir, part, &shown, create)?;
                if checked {
                    check_spelling(&dir, part, &shown)?;
                }
                dir = child;
            }
        }
        let path = root.join(rel);
        if checked {
            check_spelling(&dir, &name, &path)?;
        }
        Ok(Self { dir, name, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_type(&self) -> Result<Option<FileType>, FsError> {
        match rustix::fs::statat(&self.dir, &self.name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => Ok(Some(FileType::from_raw_mode(st.st_mode))),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(e) => Err(FsError::io("inspect", &self.path, e)),
        }
    }

    /// Opens the leaf for reading; refuses links, FIFOs and directories.
    pub fn open_read(&self) -> Result<File, FsError> {
        match self.file_type()? {
            Some(FileType::RegularFile) => {}
            Some(FileType::Symlink) => return Err(FsError::Symlink(self.path.clone())),
            Some(_) => return Err(FsError::NotAFile(self.path.display().to_string())),
            None => return Err(FsError::io("open", &self.path, "no such file")),
        }
        let fd = rustix::fs::openat(
            &self.dir,
            &self.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| FsError::io("open", &self.path, e))?;
        Ok(fd.into())
    }

    pub fn create_temp(&self, name: &OsStr, mode: u32) -> Result<File, FsError> {
        let fd = rustix::fs::openat(
            &self.dir,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode as _),
        )
        .map_err(|e| FsError::io("create temporary file", &self.path, e))?;
        Ok(fd.into())
    }

    pub fn rename_into_place(&self, temp: &OsStr) -> Result<(), FsError> {
        rustix::fs::renameat(&self.dir, temp, &self.dir, &self.name)
            .map_err(|e| FsError::io("replace", &self.path, e))
    }

    pub fn remove(&self) -> Result<(), FsError> {
        rustix::fs::unlinkat(&self.dir, &self.name, AtFlags::empty())
            .map_err(|e| FsError::io("remove", &self.path, e))
    }

    pub fn remove_temp(&self, temp: &OsStr) {
        let _ = rustix::fs::unlinkat(&self.dir, temp, AtFlags::empty());
    }

    pub fn sync(&self) -> Result<(), FsError> {
        rustix::fs::fsync(&self.dir).map_err(|e| FsError::io("sync directory", &self.path, e))
    }
}

fn open_child(parent: &File, name: &OsStr, shown: &Path, create: bool) -> Result<File, FsError> {
    match rustix::fs::openat(parent, name, DIR_FLAGS, Mode::empty()) {
        Ok(fd) => Ok(fd.into()),
        Err(rustix::io::Errno::NOENT) if create => {
            match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(FsError::io("create directory", shown, e)),
            }
            rustix::fs::openat(parent, name, DIR_FLAGS, Mode::empty())
                .map(Into::into)
                .map_err(|e| classify(parent, name, shown, e))
        }
        Err(e) => Err(classify(parent, name, shown, e)),
    }
}

/// A directory as last listed: its device, inode and modification and change
/// times, which adding, removing or renaming an entry changes.
type ListingKey = (u64, u64, i64, i64, i64, i64);

/// Names of recently listed directories, so that reading many files of one
/// large directory (a search) lists it once, not once per file.
static LISTINGS: std::sync::Mutex<Option<HashMap<ListingKey, HashSet<Vec<u8>>>>> =
    std::sync::Mutex::new(None);

/// Directories whose names are kept at once; past it the cache starts over.
const LISTINGS_KEPT: usize = 32;

/// How `parent` lists the entry `name` opens (whose inode is `ino`): `name`
/// itself when listed so, else the listed name of that inode (preferring one
/// that differs from `name` only in letter case, for hard links). `None`
/// when no listed name has that inode.
fn listed_name(
    parent: &File,
    name: &OsStr,
    ino: u64,
    shown: &Path,
) -> Result<Option<OsString>, FsError> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let dir = rustix::fs::fstat(parent).map_err(|e| FsError::io("inspect", shown, e))?;
    #[allow(clippy::unnecessary_cast)] // the field types differ between platforms
    let key: ListingKey = (
        dir.st_dev as u64,
        dir.st_ino as u64,
        dir.st_mtime as i64,
        dir.st_mtime_nsec as i64,
        dir.st_ctime as i64,
        dir.st_ctime_nsec as i64,
    );
    let mut cache = LISTINGS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cache
        .as_ref()
        .and_then(|c| c.get(&key))
        .is_some_and(|names| names.contains(name.as_bytes()))
    {
        return Ok(Some(name.to_owned()));
    }
    let list = |e| FsError::io("list directory", shown, e);
    let folded = name.to_str().map(crate::fold_name);
    let mut names = HashSet::new();
    let mut same_inode: Option<Vec<u8>> = None;
    for entry in rustix::fs::Dir::read_from(parent).map_err(list)? {
        let entry = entry.map_err(list)?;
        let listed = entry.file_name().to_bytes();
        if entry.ino() == ino {
            let closer = folded.is_some()
                && std::str::from_utf8(listed).ok().map(crate::fold_name) == folded;
            if same_inode.is_none() || closer {
                same_inode = Some(listed.to_vec());
            }
        }
        names.insert(listed.to_vec());
    }
    let exact = names.contains(name.as_bytes());
    let kept = cache.get_or_insert_with(Default::default);
    if kept.len() >= LISTINGS_KEPT {
        kept.clear();
    }
    kept.insert(key, names);
    Ok(if exact {
        Some(name.to_owned())
    } else {
        same_inode.map(OsString::from_vec)
    })
}

/// Refuses `name` when it opens an existing entry of `parent` that the
/// directory lists under another spelling (see the module documentation). A
/// name that does not exist yet is created as written: nothing to check.
fn check_spelling(parent: &File, name: &OsStr, shown: &Path) -> Result<(), FsError> {
    let st = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(FsError::io("inspect", shown, e)),
    };
    #[allow(clippy::unnecessary_cast)] // the field types differ between platforms
    let ino = st.st_ino as u64;
    match listed_name(parent, name, ino, shown)? {
        Some(listed) if listed == name => Ok(()),
        listed => Err(FsError::Spelling {
            path: shown.display().to_string(),
            on_disk: listed.map_or_else(
                || "a name its directory does not list".into(),
                |l| l.to_string_lossy().into_owned(),
            ),
        }),
    }
}

/// `rel` (relative and normalized, [`crate::normalize_relative`]) with every
/// component that exists under `root` spelled as its folder lists it: the
/// name the file system opens for it, whatever letter case or Unicode
/// normalization it was written in (see the module documentation). What
/// follows a component that does not exist yet (a path to create), a file
/// or a symbolic link is kept as written: the open that follows refuses
/// what is not a directory, and links are never followed.
pub fn resolve(root: &Path, rel: &Path) -> Result<PathBuf, FsError> {
    let mut dir: File = rustix::fs::open(root, DIR_FLAGS, Mode::empty())
        .map_err(|e| FsError::io("open workspace root", root, e))?
        .into();
    let mut out = PathBuf::new();
    let mut parts = rel.components();
    while let Some(c) = parts.next() {
        let Component::Normal(part) = c else {
            return Err(FsError::Outside(rel.display().to_string()));
        };
        let shown = root.join(&out).join(part);
        let st = match rustix::fs::statat(&dir, part, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => {
                out.push(part);
                out.extend(parts);
                return Ok(out);
            }
            Err(e) => return Err(FsError::io("inspect", &shown, e)),
        };
        #[allow(clippy::unnecessary_cast)] // the field types differ between platforms
        let listed = listed_name(&dir, part, st.st_ino as u64, &shown)?.ok_or_else(|| {
            FsError::Spelling {
                path: shown.display().to_string(),
                on_disk: "a name its directory does not list".into(),
            }
        })?;
        out.push(&listed);
        if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
            out.extend(parts);
            return Ok(out);
        }
        if parts.clone().next().is_some() {
            dir = rustix::fs::openat(&dir, &listed, DIR_FLAGS, Mode::empty())
                .map(Into::into)
                .map_err(|e| classify(&dir, &listed, &shown, e))?;
        }
    }
    Ok(out)
}

/// [`resolve`] for many paths under one root, each folder listed once. A
/// path every component of which its folder lists exactly (the usual case)
/// costs no system call beyond the listings; any other is [`resolve`]d.
pub struct Spellings {
    root: PathBuf,
    listed: HashMap<PathBuf, Option<HashSet<OsString>>>,
}

impl Spellings {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            listed: HashMap::new(),
        }
    }

    /// `rel` spelled as on disk (see [`resolve`]).
    pub fn resolve(&mut self, rel: &Path) -> Result<PathBuf, FsError> {
        let mut parent = PathBuf::new();
        for c in rel.components() {
            let Component::Normal(name) = c else {
                return resolve(&self.root, rel);
            };
            let root = &self.root;
            let names = self.listed.entry(parent.clone()).or_insert_with(|| {
                std::fs::read_dir(root.join(&parent))
                    .ok()
                    .map(|d| d.flatten().map(|e| e.file_name()).collect())
            });
            if !names.as_ref().is_some_and(|n| n.contains(name)) {
                return resolve(&self.root, rel);
            }
            parent.push(name);
        }
        Ok(rel.to_path_buf())
    }
}

fn classify(parent: &File, name: &OsStr, shown: &Path, e: rustix::io::Errno) -> FsError {
    let is_link = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|st| FileType::from_raw_mode(st.st_mode) == FileType::Symlink);
    if is_link {
        FsError::Symlink(shown.to_path_buf())
    } else if e == rustix::io::Errno::NOTDIR {
        FsError::NotAFile(shown.display().to_string())
    } else {
        FsError::io("open directory", shown, e)
    }
}
