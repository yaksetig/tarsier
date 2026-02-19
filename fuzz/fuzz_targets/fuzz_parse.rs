#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // The parser must never panic on any input.
        let _ = tarsier_dsl::parse(s, "fuzz.trs");
    }
});
