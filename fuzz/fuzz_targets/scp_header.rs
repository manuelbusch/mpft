#![no_main]
//! The SCP `C` header is the first thing a remote scp sends us.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok((_size, name)) = mpt::protocols::ssh::scp::parse_c_header(text) {
        assert!(!name.is_empty());
        assert!(!name.ends_with('\n') && !name.ends_with('\r'), "{name:?}");
    }
});
