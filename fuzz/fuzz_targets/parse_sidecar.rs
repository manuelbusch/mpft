#![no_main]
//! Checksum files come from the far side of a transfer, so their parser sees
//! whatever the remote wrote.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for (algo, name, bare) in [
        (mpt::hash::HashAlgo::Sha256, "report.pdf", false),
        (mpt::hash::HashAlgo::Sha512, "x", true),
    ] {
        if let Ok(hex) = mpt::hash::sidecar_digest(text, algo, name, bare) {
            assert_eq!(hex.len(), algo.hex_len(), "{hex:?}");
            assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{hex:?}");
            assert_eq!(hex, hex.to_ascii_lowercase());
        }
    }
    // The signing time comes out of the same file, so its parser sees
    // whatever the remote wrote as well.
    let _ = mpt::hash::parse_signed_at(text);
});
