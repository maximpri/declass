// SPDX-License-Identifier: GPL-3.0-or-later
//! Advisory feeds (fetched from configured URLs or osv.dev, or committed in a
//! project): never panic, and matching what parsed never panics either.
#![no_main]

use declass_integrity::Sha256Digest;
use declass_integrity::osv::{Index, parse_feed};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(advisories) = parse_feed(&text) {
        let index = Index::new(advisories);
        let d = Sha256Digest::of(data);
        let name = "t".to_owned();
        for version in ["0", "1.0.16", "v2.3.4-rc.1", "not a version", ""] {
            let _ = index.package("npm", "postmark-mcp", Some(version));
            let _ = index.package("pypi", &text, Some(version));
        }
        let _ = index.content(&d);
        let _ = index.tools(&d, [(&name, &d)]);
        let _ = index.url(&text);
    }
});
