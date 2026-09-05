#![no_main]
//! Checksum files come from the far side of a transfer, so their parser sees
//! whatever the remote wrote.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Some((hex, name)) = mpt::hash::parse_sidecar(text) {
        assert!(hex.len() >= 32, "{hex:?}");
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{hex:?}");
        assert_eq!(hex, hex.to_ascii_lowercase());
        assert!(!name.starts_with('*'), "{name:?}");
    }
});
