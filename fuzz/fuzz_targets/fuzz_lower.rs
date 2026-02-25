#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(program) = tarsier_dsl::parse(s, "fuzz.trs") {
            let _ = tarsier_ir::lowering::lower(&program);
        }
    }
});
