use std::path::{Path, PathBuf};

use miette::IntoDiagnostic;

use crate::commands::helpers::{
    parse_analysis_mode, parse_fairness_mode, parse_output_format, parse_solver_choice,
    parse_soundness_mode, report_with_exit_code, sandbox_read_source,
};
use crate::{
    validate_cli_network_semantics_mode, CliNetworkSemanticsMode, LayerRunCfg, OutputFormat,
};

use super::{render_analysis_text, run_analysis};

pub(crate) struct AnalyzeCommandArgs<'a> {
    pub(crate) file: &'a Path,
    pub(crate) goal: Option<String>,
    pub(crate) profile: &'a str,
    pub(crate) advanced: bool,
    pub(crate) mode: Option<String>,
    pub(crate) solver: Option<String>,
    pub(crate) depth: Option<usize>,
    pub(crate) k: Option<usize>,
    pub(crate) timeout: Option<u64>,
    pub(crate) soundness: Option<String>,
    pub(crate) fairness: Option<String>,
    pub(crate) portfolio: bool,
    pub(crate) format: &'a str,
    pub(crate) report_out: Option<&'a Path>,
    pub(crate) cli_network_mode: CliNetworkSemanticsMode,
    pub(crate) por_mode: &'a str,
}

#[derive(Clone, Copy)]
struct ProfileDefaults<'a> {
    depth: usize,
    k: usize,
    timeout: u64,
    soundness: &'a str,
    fairness: &'a str,
    solver: &'a str,
}

fn enforce_beginner_advanced_gating(
    file: &Path,
    profile: &str,
    advanced: bool,
    mode: &Option<String>,
    solver: &Option<String>,
    depth: Option<usize>,
    k: Option<usize>,
    timeout: Option<u64>,
    soundness: &Option<String>,
    fairness: &Option<String>,
) -> miette::Result<()> {
    let is_beginner = profile == "beginner";
    if !is_beginner || advanced {
        return Ok(());
    }

    let advanced_flags_used: Vec<&str> = [
        mode.as_deref().map(|_| "--mode"),
        solver.as_deref().map(|_| "--solver"),
        depth.map(|_| "--depth"),
        k.map(|_| "--k"),
        timeout.map(|_| "--timeout"),
        soundness.as_deref().map(|_| "--soundness"),
        fairness.as_deref().map(|_| "--fairness"),
    ]
    .into_iter()
    .flatten()
    .collect();

    if advanced_flags_used.is_empty() {
        return Ok(());
    }

    Err(miette::miette!(
        "{} {} advanced-only in beginner profile.\nHint: Use --advanced to unlock, or use --profile pro for full control.\nExample: tarsier analyze {} --advanced --depth 20",
        advanced_flags_used.join(", "),
        if advanced_flags_used.len() == 1 {
            "is"
        } else {
            "are"
        },
        file.display()
    ))
}

fn resolve_effective_mode(
    goal: &Option<String>,
    mode: Option<String>,
    profile: &str,
) -> miette::Result<String> {
    if let Some(goal_str) = goal {
        return Ok(match goal_str.as_str() {
            "bughunt" => "quick",
            "safety" => "proof",
            "safety+liveness" => "proof",
            "release" => "audit",
            other => {
                return Err(miette::miette!(
                    "Unknown goal '{other}'. Valid goals: bughunt, safety, safety+liveness, release"
                ));
            }
        }
        .to_string());
    }

    Ok(mode.unwrap_or_else(|| match profile {
        "beginner" => "standard".to_string(),
        "governance" => "audit".to_string(),
        "ci-fast" => "quick".to_string(),
        "ci-proof" => "proof".to_string(),
        "release-gate" => "audit".to_string(),
        _ => "standard".to_string(),
    }))
}

fn profile_defaults(profile: &str) -> ProfileDefaults<'static> {
    match profile {
        "beginner" => ProfileDefaults {
            depth: 6,
            k: 10,
            timeout: 120,
            soundness: "strict",
            fairness: "weak",
            solver: "z3",
        },
        "governance" => ProfileDefaults {
            depth: 10,
            k: 12,
            timeout: 300,
            soundness: "strict",
            fairness: "weak",
            solver: "z3",
        },
        "ci-fast" => ProfileDefaults {
            depth: 4,
            k: 6,
            timeout: 60,
            soundness: "strict",
            fairness: "weak",
            solver: "z3",
        },
        "ci-proof" => ProfileDefaults {
            depth: 10,
            k: 12,
            timeout: 300,
            soundness: "strict",
            fairness: "weak",
            solver: "z3",
        },
        "release-gate" => ProfileDefaults {
            depth: 12,
            k: 14,
            timeout: 600,
            soundness: "strict",
            fairness: "weak",
            solver: "z3",
        },
        _ => ProfileDefaults {
            depth: 10,
            k: 12,
            timeout: 300,
            soundness: "strict",
            fairness: "weak",
            solver: "z3",
        },
    }
}

fn cert_dir_from_report_out(report_out: Option<&Path>) -> Option<PathBuf> {
    report_out
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
}

pub(crate) fn run_analyze_command(args: AnalyzeCommandArgs<'_>) -> miette::Result<()> {
    let AnalyzeCommandArgs {
        file,
        mut goal,
        profile,
        advanced,
        mode,
        solver,
        depth,
        k,
        timeout,
        soundness,
        fairness,
        portfolio,
        format,
        report_out,
        cli_network_mode,
        por_mode,
    } = args;

    let source = sandbox_read_source(file)?;
    let filename = file.display().to_string();

    enforce_beginner_advanced_gating(
        file, profile, advanced, &mode, &solver, depth, k, timeout, &soundness, &fairness,
    )?;

    if profile == "release-gate" && goal.is_none() {
        goal = Some("release".to_string());
    }

    let effective_mode_str = resolve_effective_mode(&goal, mode, profile)?;
    let defaults = profile_defaults(profile);

    let eff_mode = parse_analysis_mode(&effective_mode_str)?;
    let eff_solver = parse_solver_choice(solver.as_deref().unwrap_or(defaults.solver))?;
    let eff_soundness = parse_soundness_mode(soundness.as_deref().unwrap_or(defaults.soundness))?;
    validate_cli_network_semantics_mode(&source, &filename, eff_soundness, cli_network_mode)?;
    let eff_fairness = parse_fairness_mode(fairness.as_deref().unwrap_or(defaults.fairness))?;
    let output_format = parse_output_format(format)?;
    let cfg = LayerRunCfg {
        solver: eff_solver,
        depth: depth.unwrap_or(defaults.depth),
        k: k.unwrap_or(defaults.k),
        timeout: timeout.unwrap_or(defaults.timeout),
        soundness: eff_soundness,
        fairness: eff_fairness,
        cegar_iters: 0,
        portfolio: portfolio || profile == "release-gate",
    };

    let cert_dir = cert_dir_from_report_out(report_out);
    let safety_only = goal.as_deref() == Some("safety");
    let report = run_analysis(
        &source,
        &filename,
        eff_mode,
        cfg,
        cli_network_mode,
        cert_dir.as_deref(),
        por_mode,
        safety_only,
    );

    let json_report = serde_json::to_string_pretty(&report).into_diagnostic()?;
    if let Some(path) = report_out {
        std::fs::write(path, &json_report).into_diagnostic()?;
    }

    #[cfg(feature = "governance")]
    {
        let is_release_goal = goal.as_deref() == Some("release");
        let is_gov_profile = matches!(profile, "governance" | "release-gate");
        if is_release_goal || is_gov_profile {
            if let Some(ro_path) = report_out {
                let gov_bundle =
                    crate::build_governance_bundle(&report, &source, ro_path, &json_report)?;
                let gov_json = serde_json::to_string_pretty(&gov_bundle).into_diagnostic()?;
                let gov_path = ro_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("governance-bundle.json");
                std::fs::write(&gov_path, &gov_json).into_diagnostic()?;
            }
        }
    }

    match output_format {
        OutputFormat::Text => println!("{}", render_analysis_text(&report)),
        OutputFormat::Json => println!("{json_report}"),
    }

    if report.overall != "pass" {
        return Err(report_with_exit_code(
            2,
            format!("Analysis reported overall='{}'.", report.overall),
        ));
    }

    Ok(())
}
