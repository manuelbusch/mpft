#![no_main]

use libfuzzer_sys::fuzz_target;
use mpft::batch::jobs::{Format, parse};

// A job list may come from another program; parsing it must never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse(text, Format::Lines);
        let _ = mpft::batch::jobs::detect(None, text);
    }
});
