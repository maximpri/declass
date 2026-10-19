// SPDX-License-Identifier: GPL-3.0-or-later
//! SHA-256 digests as lock files write them: `sha256:` and 64 lowercase hex
//! digits.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::str::FromStr;

/// What every digest string starts with.
pub const PREFIX: &str = "sha256:";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    /// The digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{PREFIX}{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a digest (`sha256:` and 64 lowercase hex digits): {0:?}")]
pub struct BadDigest(pub String);

impl FromStr for Sha256Digest {
    type Err = BadDigest;

    fn from_str(s: &str) -> Result<Self, BadDigest> {
        let bad = || BadDigest(s.chars().take(80).collect());
        let hex_digits = s.strip_prefix(PREFIX).ok_or_else(bad)?;
        if hex_digits.len() != 64
            || !hex_digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex_digits, &mut out).map_err(|_| bad())?;
        Ok(Self(out))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_round_trip_and_reject_other_spellings() {
        let d = Sha256Digest::of(b"hello world");
        let text = d.to_string();
        assert_eq!(
            text,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(text.parse::<Sha256Digest>().unwrap(), d);
        for bad in [
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            "sha256:B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9",
            "sha256:b94d",
            "sha512:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcdeg",
        ] {
            assert!(bad.parse::<Sha256Digest>().is_err(), "{bad}");
        }
    }
}
