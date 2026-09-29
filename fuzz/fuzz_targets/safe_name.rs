#![no_main]
//! A name that `safe_name` accepts must be a single, harmless path component:
//! no separators, no traversal, no control characters.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(name) = mpft::location::safe_name(text) {
        assert!(!name.is_empty());
        assert!(!name.contains('/'), "{name:?}");
        assert!(!name.contains('\\'), "{name:?}");
        assert!(name != "." && name != "..", "{name:?}");
        assert!(!name.chars().any(|c| c.is_control()), "{name:?}");
        // Idempotent: feeding the result back in changes nothing.
        assert_eq!(mpft::location::safe_name(&name).unwrap(), name);
    }
});
