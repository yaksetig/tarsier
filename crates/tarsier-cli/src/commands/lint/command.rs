// Lint command entrypoint.

use std::path::PathBuf;

use miette::IntoDiagnostic;

use crate::commands::helpers::{
    parse_output_format, parse_soundness_mode, report_with_exit_code, sandbox_read_source,
};
use crate::{CliNetworkSemanticsMode, OutputFormat};

use super::pipeline::lint_protocol_file;
use super::render::render_lint_text;

pub(crate) fn run_lint_command(
    file: PathBuf,
    soundness: String,
    format: String,
    out: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let soundness = parse_soundness_mode(&soundness)?;
    crate::validate_cli_network_semantics_mode(&source, &filename, soundness, cli_network_mode)?;
    let output_format = parse_output_format(&format)?;
    let report = lint_protocol_file(&source, &filename, soundness);
    let report_json_value = serde_json::to_value(&report).into_diagnostic()?;
    let report_json = serde_json::to_string_pretty(&report_json_value).into_diagnostic()?;

    if let Some(path) = out {
        crate::write_json_artifact(&path, &report_json_value)?;
        println!("Lint report written to {}", path.display());
    }

    match output_format {
        OutputFormat::Text => println!("{}", render_lint_text(&report)),
        OutputFormat::Json => println!("{report_json}"),
    }

    if report.issues.iter().any(|i| i.severity == "error") {
        return Err(report_with_exit_code(2, "Lint found one or more errors."));
    }

    Ok(())
}
