// SPDX-License-Identifier: GPL-3.0-or-later
//! An API key kept in a file only its owner can read (`declass setup` saves a
//! pasted key there instead of in the configuration). It is read for each
//! request, so replacing the file takes effect without a restart, and it is
//! never logged or shown.

use crate::client::TokenSource;
use crate::error::{ErrorKind, ProviderError};
use futures_util::future::BoxFuture;
use std::path::PathBuf;

#[derive(Clone)]
pub struct SavedKey {
    path: PathBuf,
}

impl std::fmt::Debug for SavedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SavedKey")
            .field("path", &self.path)
            .finish()
    }
}

impl SavedKey {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The key, trimmed; an error that names the file, never its content.
    pub fn read(&self) -> Result<String, ProviderError> {
        let key = std::fs::read_to_string(&self.path).map_err(|e| {
            ProviderError::new(
                ErrorKind::Auth,
                format!(
                    "the saved API key ({}) cannot be read: {e}; run `declass setup` to save it again",
                    self.path.display()
                ),
            )
        })?;
        let key = key.trim().to_owned();
        if key.is_empty() {
            return Err(ProviderError::new(
                ErrorKind::Auth,
                format!(
                    "the saved API key ({}) is empty; run `declass setup` to save it again",
                    self.path.display()
                ),
            ));
        }
        Ok(key)
    }
}

impl TokenSource for SavedKey {
    fn token(&self) -> BoxFuture<'_, Result<String, ProviderError>> {
        Box::pin(async move { self.read() })
    }

    fn refused(&self, _: &str) -> BoxFuture<'_, Result<(), ProviderError>> {
        Box::pin(async move {
            Err(ProviderError::new(
                ErrorKind::Auth,
                "the server refused the saved API key; run `declass setup` to save the right one",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_key_is_read_trimmed_and_errors_never_show_it() {
        let dir = std::env::temp_dir().join(format!("declass-saved-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api_key");
        std::fs::write(&path, "local-key-1\n").unwrap();
        let key = SavedKey::new(path.clone());
        assert_eq!(key.token().await.unwrap(), "local-key-1");
        assert!(!format!("{key:?}").contains("local-key-1"));
        let refused = key.refused("local-key-1").await.unwrap_err();
        assert!(!refused.message.contains("local-key-1"));
        std::fs::write(&path, " \n").unwrap();
        assert!(key.token().await.unwrap_err().message.contains("empty"));
        std::fs::remove_file(&path).unwrap();
        assert!(key.token().await.is_err());
        let _ = std::fs::remove_dir(&dir);
    }
}
