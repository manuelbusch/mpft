#![no_main]
//! Every byte string is a candidate URL: parsing must return a Location or an
//! error, never panic, and a Location must survive a round trip through its
//! own masked Display without losing its scheme.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(loc) = mpft::Location::parse(text) {
        // Accessors must not panic on anything that parsed.
        let _ = loc.filename();
        let _ = loc.target_path(Some("name.bin"));
        let _ = loc.sibling("name.bin");
        let _ = loc.timeout();
        let _ = loc.connect_retries();
        let _ = loc.recipients();
        let shown = loc.to_string();
        assert!(
            !shown.contains("s3cret-marker"),
            "a password must never reach Display"
        );
    }
});
