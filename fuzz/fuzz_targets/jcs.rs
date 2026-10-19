// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical JSON of tool definitions a server sends: never panic, the
//! canonical form is valid JSON, and canonicalizing it again changes nothing.
#![no_main]

use declass_integrity::jcs::canonical;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let once = canonical(&value);
    let parsed: Value = serde_json::from_slice(&once).expect("canonical JSON parses");
    assert_eq!(canonical(&parsed), once);
});
