// SPDX-License-Identifier: GPL-3.0-or-later
//! Handle-relative workspace I/O, atomic durable writes, locks and the .declass path registry.

pub mod error;
pub mod fault;
pub mod gitdir;
pub mod host;
pub mod lock;
pub mod ops;
pub mod path;
pub mod pinned;
pub mod private;
pub mod registry;
pub mod triggers;

pub use error::FsError;
pub use ops::{
    Precondition, WriteReceipt, atomic_write, read_file, read_optional, remove_file, restore,
    sha256_hex,
};
pub use path::{fold_name, is_reserved, is_reserved_name, normalize_relative, writable_relative};
pub use pinned::{Spellings, resolve};

/// [`normalize_relative`], spelled as the file system lists it under `root`
/// ([`resolve`]): the path every check on it, and the open, must agree on.
pub fn resolve_relative(
    root: &std::path::Path,
    input: &str,
) -> Result<std::path::PathBuf, FsError> {
    resolve(root, &normalize_relative(input)?)
}

/// [`writable_relative`], spelled as the file system lists it under `root`:
/// refused when reserved as written or as resolved.
pub fn resolve_writable(
    root: &std::path::Path,
    input: &str,
) -> Result<std::path::PathBuf, FsError> {
    let rel = resolve(root, &writable_relative(input)?)?;
    if is_reserved(&rel) {
        return Err(FsError::Reserved(input.to_owned()));
    }
    Ok(rel)
}
