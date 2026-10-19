// SPDX-License-Identifier: GPL-3.0-or-later
//! OpenSSH signatures (`ssh-keygen -Y sign`, the SSHSIG format) made with
//! Ed25519 keys, and `allowed_signers` files: a publisher signs what a
//! package is, and the owner lists whose keys to accept.
//!
//! What is signed is not the message itself but the SSHSIG blob: the magic
//! `SSHSIG`, the namespace, a reserved string, the hash algorithm and the
//! message's hash (SHA-256 or SHA-512), each length-prefixed. The namespace
//! keeps a signature made for one purpose from being accepted for another.

use base64::Engine as _;
use sha2::{Digest as _, Sha256, Sha512};

const MAGIC: &[u8] = b"SSHSIG";
const KEY_TYPE: &str = "ssh-ed25519";
const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigError {
    #[error("not an SSH signature (`ssh-keygen -Y sign` output)")]
    Format,
    #[error("unsupported signature: {0} (Ed25519 keys only)")]
    Unsupported(String),
    #[error("signed for {found:?}, not for {wanted:?}")]
    Namespace { wanted: String, found: String },
    #[error("the signature does not match the content")]
    Invalid,
}

/// An Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// The key's wire form (`string "ssh-ed25519", string key`).
    fn blob(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put(&mut b, KEY_TYPE.as_bytes());
        put(&mut b, &self.0);
        b
    }

    /// As `authorized_keys` writes it: `ssh-ed25519 AAAA...`.
    pub fn openssh(&self) -> String {
        format!(
            "{KEY_TYPE} {}",
            base64::engine::general_purpose::STANDARD.encode(self.blob())
        )
    }

    /// As a lock file records it (no whitespace): `ssh-ed25519:AAAA...`.
    pub fn lock_form(&self) -> String {
        self.openssh().replacen(' ', ":", 1)
    }

    /// Reads `ssh-ed25519 AAAA...` or the lock form.
    pub fn parse(text: &str) -> Option<PublicKey> {
        let (kind, b64) = text.trim().split_once([' ', ':'])?;
        if kind != KEY_TYPE {
            return None;
        }
        let blob = base64::engine::general_purpose::STANDARD
            .decode(b64.split_whitespace().next()?)
            .ok()?;
        key_from_blob(&blob)
    }
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Reads length-prefixed strings off the front of a buffer.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

fn key_from_blob(blob: &[u8]) -> Option<PublicKey> {
    let mut r = Reader(blob);
    if r.string()? != KEY_TYPE.as_bytes() {
        return None;
    }
    let key: [u8; 32] = r.string()?.try_into().ok()?;
    r.0.is_empty().then_some(PublicKey(key))
}

/// Verifies `armored` (an `ssh-keygen -Y sign` signature) over `message`,
/// made in `namespace`; returns the key that made it. Whether that key may
/// sign is the caller's to decide ([`allowed`]).
pub fn verify(armored: &str, message: &[u8], namespace: &str) -> Result<PublicKey, SigError> {
    let body: String = armored
        .trim()
        .strip_prefix(BEGIN)
        .and_then(|s| s.strip_suffix(END))
        .ok_or(SigError::Format)?
        .split_whitespace()
        .collect();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| SigError::Format)?;
    let mut r = Reader(&raw);
    if r.take(MAGIC.len()) != Some(MAGIC) || r.u32() != Some(1) {
        return Err(SigError::Format);
    }
    let key_blob = r.string().ok_or(SigError::Format)?;
    let found = r.string().ok_or(SigError::Format)?;
    let reserved = r.string().ok_or(SigError::Format)?;
    let hash = r.string().ok_or(SigError::Format)?;
    let signature = r.string().ok_or(SigError::Format)?;
    if !r.0.is_empty() {
        return Err(SigError::Format);
    }
    let key = key_from_blob(key_blob).ok_or_else(|| {
        SigError::Unsupported(
            String::from_utf8_lossy(Reader(key_blob).string().unwrap_or_default()).into_owned(),
        )
    })?;
    if found != namespace.as_bytes() {
        return Err(SigError::Namespace {
            wanted: namespace.to_owned(),
            found: String::from_utf8_lossy(found).into_owned(),
        });
    }
    let digest = match hash {
        b"sha512" => Sha512::digest(message).to_vec(),
        b"sha256" => Sha256::digest(message).to_vec(),
        other => {
            return Err(SigError::Unsupported(
                String::from_utf8_lossy(other).into_owned(),
            ));
        }
    };
    let mut r = Reader(signature);
    if r.string() != Some(KEY_TYPE.as_bytes()) {
        return Err(SigError::Unsupported("signature type".into()));
    }
    let sig = r.string().ok_or(SigError::Format)?;
    let mut signed = MAGIC.to_vec();
    put(&mut signed, found);
    put(&mut signed, reserved);
    put(&mut signed, hash);
    put(&mut signed, &digest);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.0)
        .verify(&signed, sig)
        .map_err(|_| SigError::Invalid)?;
    Ok(key)
}

/// One line of an `allowed_signers` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub principals: Vec<String>,
    /// `namespaces="..."`; `None`: any.
    pub namespaces: Option<Vec<String>>,
    pub key: PublicKey,
}

/// The Ed25519 signers in an `allowed_signers` file (`ssh-keygen(1)`,
/// ALLOWED SIGNERS). Lines with other key types, certificate authorities or
/// validity windows are left out: this verifier does not check them.
pub fn allowed_signers(text: &str) -> Vec<Signer> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (principals, rest) = line.split_once(char::is_whitespace)?;
            let rest = rest.trim_start();
            // Options come before the key type, when there are any.
            let (options, key) = if rest.starts_with(KEY_TYPE) {
                ("", rest)
            } else {
                let at = rest.find(KEY_TYPE)?;
                (rest[..at].trim(), &rest[at..])
            };
            let mut namespaces = None;
            for option in options.split(',').map(str::trim).filter(|o| !o.is_empty()) {
                match option.split_once('=') {
                    Some(("namespaces", v)) => {
                        namespaces = Some(
                            v.trim_matches('"')
                                .split(',')
                                .map(|n| n.trim().to_owned())
                                .collect(),
                        );
                    }
                    // cert-authority, valid-after, valid-before: not checked here.
                    _ => return None,
                }
            }
            Some(Signer {
                principals: principals.split(',').map(str::to_owned).collect(),
                namespaces,
                key: PublicKey::parse(key)?,
            })
        })
        .collect()
}

/// The first signer in `signers` with `key` that may sign in `namespace`.
pub fn allowed<'a>(signers: &'a [Signer], key: &PublicKey, namespace: &str) -> Option<&'a Signer> {
    signers.iter().find(|s| {
        s.key == *key
            && s.namespaces
                .as_ref()
                .is_none_or(|n| n.iter().any(|n| n == namespace))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with OpenSSH: `ssh-keygen -Y sign -n declass-plugin -f key msg`.
    const PUBLISHER: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAO+nC9vBf0lcRqQzW+zyLPiqqVwPTyHvrYeIuO1YLQ";
    const OTHER: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNUHglE6PkUSnHUwgh79hGAWNX+jSElSd1rdp93/UVy";
    const MESSAGE: &[u8] =
        b"sha256:9b46342aaebede490f12bf67a5ecb4be507c7684ee5e11a0511b54c701f464bd\n";
    const SIGNED: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgQA76cL28F/SVxGpDNb7PIs+Kqp
XA9PIe+th4i47VgtAAAAAOZGVjbGFzcy1wbHVnaW4AAAAAAAAABnNoYTUxMgAAAFMAAAAL
c3NoLWVkMjU1MTkAAABADeqiUdksQ2/0gSaj/oupcdL8Va45rVR687IhOsgkyws+HhqngG
aA9aVWCrFKr+uExW9iDTpAYxAyH+C4gzgsDg==
-----END SSH SIGNATURE-----
";
    const BY_OTHER: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgM1QeCUTo+RRKcdTCCHv2EYBY1f
6NISVJ3Wt2n3f9RXIAAAAOZGVjbGFzcy1wbHVnaW4AAAAAAAAABnNoYTUxMgAAAFMAAAAL
c3NoLWVkMjU1MTkAAABAK97LuAD8uIf5z9Tr77cvxp8lj+jGJPEYCxV1Z0bjPvb76k4qBj
8Th/Jaa2YsAEj3Wla3AKYNiyjsIlQJ6oCrAA==
-----END SSH SIGNATURE-----
";
    const OTHER_NAMESPACE: &str = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgQA76cL28F/SVxGpDNb7PIs+Kqp
XA9PIe+th4i47VgtAAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEBPRNWvr7Vde66HhCdUnTpFgk+IxYsBsw5fW9LrHMotE/Xfk37gNNPu++2/KkkNHn
OOW+2ge0u2gisPxRbyqVYJ
-----END SSH SIGNATURE-----
";

    #[test]
    fn an_openssh_signature_verifies_and_names_its_key() {
        let key = verify(SIGNED, MESSAGE, "declass-plugin").unwrap();
        assert_eq!(key, PublicKey::parse(PUBLISHER).unwrap());
        assert_eq!(key.openssh(), PUBLISHER);
        assert_eq!(PublicKey::parse(&key.lock_form()), Some(key));
        assert!(!key.lock_form().contains(' '));
    }

    #[test]
    fn other_content_another_namespace_or_a_broken_signature_fail() {
        assert_eq!(
            verify(SIGNED, b"sha256:0000\n", "declass-plugin"),
            Err(SigError::Invalid)
        );
        assert!(matches!(
            verify(OTHER_NAMESPACE, MESSAGE, "declass-plugin"),
            Err(SigError::Namespace { .. })
        ));
        assert_eq!(
            verify("not a signature", MESSAGE, "declass-plugin"),
            Err(SigError::Format)
        );
        let broken = SIGNED.replace("aA9aVWCrFKr", "aA9aVWCrFKs");
        assert!(verify(&broken, MESSAGE, "declass-plugin").is_err());
    }

    #[test]
    fn only_listed_signers_for_the_namespace_are_allowed() {
        let file = format!(
            "# publishers\npublisher@example.test namespaces=\"declass-plugin\" {PUBLISHER}\n\
             files@example.test namespaces=\"file\" {OTHER}\n\
             ca@example.test cert-authority {OTHER}\n\
             rsa@example.test ssh-rsa AAAAB3NzaC1yc2E\n"
        );
        let signers = allowed_signers(&file);
        assert_eq!(signers.len(), 2);
        let publisher = verify(SIGNED, MESSAGE, "declass-plugin").unwrap();
        let other = verify(BY_OTHER, MESSAGE, "declass-plugin").unwrap();
        assert_eq!(
            allowed(&signers, &publisher, "declass-plugin")
                .unwrap()
                .principals,
            ["publisher@example.test"]
        );
        // Listed, but not for this namespace.
        assert!(allowed(&signers, &other, "declass-plugin").is_none());
        assert!(allowed(&signers, &other, "file").is_some());
    }
}
