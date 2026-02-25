#![allow(dead_code)]

use tarsier_engine::pipeline::{PipelineOptions, ProofEngine, SolverChoice, SoundnessMode};

pub fn load_example(name: &str) -> String {
    let path = format!("{}/../../examples/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load {path}: {e}"))
}

pub fn load_library_examples() -> Vec<(String, String)> {
    let library_dir = format!("{}/../../examples/library", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&library_dir)
        .unwrap_or_else(|e| panic!("Failed to read {library_dir}: {e}"))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("trs"))
        .collect();
    files.sort();

    files
        .into_iter()
        .map(|path| {
            let file = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown.trs")
                .to_string();
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
            (file, src)
        })
        .collect()
}

pub fn load_library_example(name: &str) -> String {
    let path = format!(
        "{}/../../examples/library/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load {path}: {e}"))
}

pub fn load_library_manifest() -> String {
    let path = format!(
        "{}/../../examples/library/cert_suite.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to load {path}: {e}"))
}

pub fn verify_options(depth: usize, soundness: SoundnessMode) -> PipelineOptions {
    PipelineOptions {
        solver: SolverChoice::Z3,
        max_depth: depth,
        timeout_secs: 60,
        dump_smt: None,
        soundness,
        proof_engine: ProofEngine::KInduction,
    }
}

pub fn add_identity_selective_overlay_for_replica(source: &str) -> String {
    let mut out = source.to_string();
    if !out.contains("network: identity_selective;") {
        let faithful_block = "\n        auth: signed;\n        network: identity_selective;\n        equivocation: full;\n        delivery: per_recipient;\n        faults: per_recipient;";
        if out.contains("values: sign;") {
            out = out.replacen(
                "values: sign;",
                &format!("values: sign;{}", faithful_block),
                1,
            );
        } else {
            out = out.replacen(
                "bound: f;",
                &format!("bound: f;{}", faithful_block),
                1,
            );
        }
    }
    if !out.contains("identity Replica:") {
        out = out.replacen(
            "    message ",
            "    identity Replica: role key replica_key;\n\n    message ",
            1,
        );
    }
    out
}

