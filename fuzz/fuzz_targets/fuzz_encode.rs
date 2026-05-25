#![no_main]
use tarsier_dsl::ast::{Program, PropertyKind};

use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_BYTES: usize = 4096;

fn should_skip_for_bmc_encoder(program: &Program) -> bool {
    let protocol = &program.protocol.node;
    let has_liveness_property = protocol
        .properties
        .iter()
        .any(|property| property.node.kind == PropertyKind::Liveness);

    // This target exercises safety BMC encoding. Liveness and crypto-object
    // lowering are covered by dedicated paths and can allocate heavily from
    // arbitrary corpus mutations before the encoder is reached.
    has_liveness_property || !protocol.crypto_objects.is_empty()
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }

    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(program) = tarsier_dsl::parse(s, "fuzz.trs") {
            if should_skip_for_bmc_encoder(&program) {
                return;
            }

            if let Ok(ta) = tarsier_ir::lowering::lower(&program) {
                let property = tarsier_ir::properties::extract_agreement_property(&ta);
                let cs = tarsier_ir::abstraction::abstract_to_counter_system(ta);
                // Attempt BMC encoding at small depth; skip solving.
                let _ = tarsier_smt::encoder::encode_bmc(&cs, &property, 3);
            }
        }
    }
});
