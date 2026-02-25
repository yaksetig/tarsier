// Command handler for: Codegen
//
// Generates implementation code from a verified .trs protocol model.
// Validates certificate bundle integrity before code generation unless
// --allow-unverified is specified.

use std::fs;
use std::path::PathBuf;

use miette::IntoDiagnostic;

use tarsier_proof_kernel::{check_bundle_integrity, sha256_hex_bytes};

use super::helpers::sandbox_read_source;
use crate::obligations_all_unsat;

/// Run the `codegen` CLI command.
///
/// Parses the protocol source, validates an optional certificate bundle,
/// and emits generated Rust or Go code into the requested output directory.
pub(crate) fn run_codegen_command(
    file: PathBuf,
    target: String,
    output: PathBuf,
    require_cert: Option<PathBuf>,
    allow_unverified: bool,
) -> miette::Result<()> {
    let verified: bool;
    let cert_ref: String;

    if let Some(cert_path) = &require_cert {
        let integrity = check_bundle_integrity(cert_path).into_diagnostic()?;
        if !integrity.is_ok() {
            let issues: Vec<String> = integrity
                .issues
                .iter()
                .map(|i| format!("[{}] {}", i.code, i.message))
                .collect();
            miette::bail!(
                "Certificate bundle integrity check failed:\n{}",
                issues.join("\n")
            );
        }
        if !obligations_all_unsat(&integrity.metadata) {
            miette::bail!(
                "Certificate bundle has non-UNSAT obligations. \
                 All proof obligations must be UNSAT before generating code."
            );
        }
        println!(
            "Certificate verified: {} (all obligations UNSAT)",
            cert_path.display()
        );
        verified = true;
        cert_ref = cert_path.display().to_string();
    } else if allow_unverified {
        eprintln!(
            "Warning: generating code without certificate verification (--allow-unverified). \
             Generated artifacts will be marked as UNVERIFIED_CODEGEN."
        );
        verified = false;
        cert_ref = "none".to_string();
    } else {
        miette::bail!(
            "Codegen requires a certificate bundle by default.\n\
             Use --require-cert <path> to provide a verified certificate bundle, or\n\
             use --allow-unverified to bypass (artifacts will be marked unverified)."
        );
    }

    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let program =
        tarsier_dsl::parse(&source, &filename).map_err(|e| miette::miette!("Parse error: {e}"))?;

    let codegen_target = match target.to_lowercase().as_str() {
        "rust" | "rs" => tarsier_codegen::CodegenTarget::Rust,
        "go" | "golang" => tarsier_codegen::CodegenTarget::Go,
        other => {
            return Err(miette::miette!(
                "Unknown codegen target '{}'. Use rust | go.",
                other
            ));
        }
    };

    // Compute provenance fields
    let model_sha256 = sha256_hex_bytes(source.as_bytes());
    let options_desc = format!("target={},allow_unverified={}", target, allow_unverified);
    let options_sha256 = sha256_hex_bytes(options_desc.as_bytes());
    let provenance = tarsier_codegen::ProvenanceInfo {
        model_sha256,
        options_sha256,
        certificate_ref: cert_ref,
        verified,
        audit_tag: if !verified {
            Some("UNVERIFIED_CODEGEN".to_string())
        } else {
            None
        },
    };

    let code = tarsier_codegen::generate_with_provenance(&program, codegen_target, &provenance)
        .map_err(|e| miette::miette!("Codegen error: {e}"))?;

    let protocol_name = program.protocol.node.name.clone();
    let ext = match codegen_target {
        tarsier_codegen::CodegenTarget::Rust => "rs",
        tarsier_codegen::CodegenTarget::Go => "go",
    };
    let out_file = output.join(format!(
        "{}.{ext}",
        protocol_name.to_lowercase().replace(' ', "_")
    ));

    if let Some(parent) = out_file.parent() {
        fs::create_dir_all(parent).into_diagnostic()?;
    }
    fs::write(&out_file, &code).into_diagnostic()?;
    println!(
        "Generated {} code written to {}",
        target,
        out_file.display()
    );

    Ok(())
}
