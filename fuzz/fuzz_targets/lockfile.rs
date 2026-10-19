// SPDX-License-Identifier: GPL-3.0-or-later
//! Extension lock files (a project's is written by whoever commits it): never
//! panic, and what parses renders to text that parses to the same lock.
#![no_main]

use declass_integrity::lock::{Lock, Scope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for scope in [Scope::Owner, Scope::Project] {
        if let Ok(lock) = Lock::parse(&text, scope) {
            let rendered = lock.render();
            let again = Lock::parse(&rendered, scope).expect("a rendered lock parses");
            assert_eq!(again.render(), rendered);
        }
    }
});
