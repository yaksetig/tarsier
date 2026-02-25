#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(program) = tarsier_dsl::parse(s, "fuzz.trs") {
            if let Ok(ta) = tarsier_ir::lowering::lower(&program) {
                let property = tarsier_ir::properties::extract_agreement_property(&ta);
                let cs = tarsier_ir::counter_system::CounterSystem::new(ta);
                // Attempt BMC encoding at small depth; skip solving.
                let _ = tarsier_smt::encoder::encode_bmc(&cs, &property, 3);
            }
        }
    }
});
