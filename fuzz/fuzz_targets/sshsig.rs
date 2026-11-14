// SPDX-License-Identifier: GPL-3.0-or-later
//! Package signatures and allowed_signers files (a package's signature is
//! whatever its publisher put in it): never panic.
#![no_main]

use declass_integrity::sshsig::{allowed, allowed_signers, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let armored = format!("-----BEGIN SSH SIGNATURE-----\n{text}\n-----END SSH SIGNATURE-----");
    for candidate in [text.as_ref(), armored.as_str()] {
        if let Ok(key) = verify(candidate, data, "declass-plugin") {
            let _ = key.openssh();
            let signers = allowed_signers(&text);
            let _ = allowed(&signers, &key, "declass-plugin");
        }
    }
    let _ = allowed_signers(&text);
});
