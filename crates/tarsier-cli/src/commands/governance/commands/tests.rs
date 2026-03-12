use super::*;
use std::path::Path;

// -- GovernancePipelineCommandArgs --

#[test]
fn governance_pipeline_args_clone() {
    let args = GovernancePipelineCommandArgs {
        file: PathBuf::from("test.trs"),
        cert_manifest: PathBuf::from("manifest.json"),
        conformance_manifest: PathBuf::from("conformance.json"),
        benchmark_report: None,
        solver: "z3".into(),
        depth: 10,
        k: 12,
        timeout: 60,
        soundness: "strict".into(),
        format: "text".into(),
        out: None,
        cli_network_mode: CliNetworkSemanticsMode::Dsl,
        por_mode: "full".into(),
    };
    let cloned = args.clone();
    assert_eq!(cloned.file, PathBuf::from("test.trs"));
    assert_eq!(cloned.solver, "z3");
    assert_eq!(cloned.depth, 10);
    assert_eq!(cloned.k, 12);
    assert_eq!(cloned.timeout, 60);
    assert!(cloned.benchmark_report.is_none());
    assert!(cloned.out.is_none());
}

#[test]
fn governance_pipeline_args_with_benchmark() {
    let args = GovernancePipelineCommandArgs {
        file: PathBuf::from("test.trs"),
        cert_manifest: PathBuf::from("manifest.json"),
        conformance_manifest: PathBuf::from("conformance.json"),
        benchmark_report: Some(PathBuf::from("bench.json")),
        solver: "cvc5".into(),
        depth: 20,
        k: 24,
        timeout: 120,
        soundness: "permissive".into(),
        format: "json".into(),
        out: Some(PathBuf::from("output.json")),
        cli_network_mode: CliNetworkSemanticsMode::Faithful,
        por_mode: "static".into(),
    };
    assert_eq!(
        args.benchmark_report.as_deref(),
        Some(Path::new("bench.json"))
    );
    assert_eq!(args.out.as_deref(), Some(Path::new("output.json")));
    assert_eq!(args.cli_network_mode, CliNetworkSemanticsMode::Faithful);
}

#[test]
fn governance_pipeline_args_debug() {
    let args = GovernancePipelineCommandArgs {
        file: PathBuf::from("test.trs"),
        cert_manifest: PathBuf::from("m.json"),
        conformance_manifest: PathBuf::from("c.json"),
        benchmark_report: None,
        solver: "z3".into(),
        depth: 10,
        k: 12,
        timeout: 60,
        soundness: "strict".into(),
        format: "text".into(),
        out: None,
        cli_network_mode: CliNetworkSemanticsMode::Dsl,
        por_mode: "full".into(),
    };
    let debug_str = format!("{:?}", args);
    assert!(debug_str.contains("GovernancePipelineCommandArgs"));
    assert!(debug_str.contains("test.trs"));
}
