// SPDX-License-Identifier: GPL-3.0-or-later
//! Parent-directory handles opened without following links.
//!
//! Every component is opened with `openat(O_NOFOLLOW)` from the workspace root,
//! so a symlink planted anywhere on the path cannot redirect a read or write.
//! Every existing component must also be spelled exactly as its directory
//! lists it: a case-insensitive file system (macOS's default) opens
//! `.DECLASS/vault.json` or `DATA/orders.csv` as `.declass/...` and
//! `data/...`, which the callers' checks, made on the name as written, would
//! not recognise.

use crate::error::FsError;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
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
    /// directories are created (mode 0755).
    pub fn open(root: &Path, rel: &Path, create: bool) -> Result<Self, FsError> {
        let name = rel
            .file_name()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| FsError::Outside(rel.display().to_string()))?
            .to_owned();
        let root_fd = rustix::fs::open(root, DIR_FLAGS, Mode::empty())
            .map_err(|e| FsError::io("open workspace root", root, e))?;
        let mut dir: File = root_fd.into();
        let mut shown = root.to_path_buf();
        if let Some(parent) = rel.parent() {
            for c in parent.components() {
                let Component::Normal(part) = c else {
                    return Err(FsError::Outside(rel.display().to_string()));
                };
                shown.push(part);
                let child = open_child(&dir, part, &shown, create)?;
                check_spelling(&dir, part, &shown)?;
                dir = child;
            }
        }
        let path = root.join(rel);
        check_spelling(&dir, &name, &path)?;
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
static LISTINGS: std::sync::Mutex<
    Option<std::collections::HashMap<ListingKey, std::collections::HashSet<Vec<u8>>>>,
> = std::sync::Mutex::new(None);

/// Directories whose names are kept at once; past it the cache starts over.
const LISTINGS_KEPT: usize = 32;

/// Refuses `name` when it opens an existing entry of `parent` that the
/// directory lists under another spelling (see the module documentation). A
/// name that does not exist yet is created as written: nothing to check.
fn check_spelling(parent: &File, name: &OsStr, shown: &Path) -> Result<(), FsError> {
    use std::os::unix::ffi::OsStrExt;
    let st = match rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(FsError::io("inspect", shown, e)),
    };
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
        return Ok(());
    }
    let list = |e| FsError::io("list directory", shown, e);
    let mut names = std::collections::HashSet::new();
    let mut listed_as = None;
    for entry in rustix::fs::Dir::read_from(parent).map_err(list)? {
        let entry = entry.map_err(list)?;
        let listed = entry.file_name().to_bytes();
        if entry.ino() == st.st_ino && listed != name.as_bytes() {
            listed_as = Some(String::from_utf8_lossy(listed).into_owned());
        }
        names.insert(listed.to_vec());
    }
    let exact = names.contains(name.as_bytes());
    let kept = cache.get_or_insert_with(Default::default);
    if kept.len() >= LISTINGS_KEPT {
        kept.clear();
    }
    kept.insert(key, names);
    if exact {
        return Ok(());
    }
    Err(FsError::Spelling {
        path: shown.display().to_string(),
        on_disk: listed_as.unwrap_or_else(|| "a name its directory does not list".into()),
    })
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
