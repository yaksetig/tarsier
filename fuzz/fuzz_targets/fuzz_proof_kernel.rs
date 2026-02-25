#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Attempt to parse arbitrary input as certificate metadata JSON.
        // The deserializer must never panic on any input.
        if let Ok(metadata) =
            serde_json::from_str::<tarsier_proof_kernel::CertificateMetadata>(s)
        {
            // If parsing succeeds, exercise hash computation and validation.
            let _ = tarsier_proof_kernel::compute_bundle_sha256(&metadata);
        }
    }
    // Also exercise raw SHA-256 hashing on arbitrary bytes.
    let _ = tarsier_proof_kernel::sha256_hex_bytes(data);
});
