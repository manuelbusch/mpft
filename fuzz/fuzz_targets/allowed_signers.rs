#![no_main]
//! The trust file for signature verification is user input as well: a broken
//! line must be an error, never a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = mpft::sign::ssh::AllowedSigners::parse(text);
});
