// Command handlers for: Visualize, Explore, DebugCex
//
// Counterexample visualization, interactive exploration, and trace debugging.

use std::fs;
use std::path::PathBuf;

use miette::IntoDiagnostic;
use serde_json::json;

use tarsier_engine::pipeline::{FairnessMode, PipelineOptions, SoundnessMode};
use tarsier_engine::result::{
    FairLivenessResult, LivenessResult, UnboundedFairLivenessResult, UnboundedSafetyResult,
    VerificationResult,
};
use tarsier_engine::visualization::{
    config_snapshot, render_trace_markdown, render_trace_mermaid, render_trace_timeline,
};
use tarsier_ir::counter_system::Trace;
use tarsier_ir::threshold_automaton::ThresholdAutomaton;

use super::helpers::*;
use crate::{
    detect_prove_auto_target, trace_details, validate_cli_network_semantics_mode,
    CliNetworkSemanticsMode, ProveAutoTarget, VisualizeCheck, VisualizeFormat,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub(crate) struct VisualizedCounterexample {
    pub(crate) trace: Trace,
    pub(crate) loop_start: Option<usize>,
    pub(crate) result_output: String,
    pub(crate) check: VisualizeCheck,
}

pub(crate) type ParsedCounterMetadata = (String, String, Option<String>, Vec<(String, String)>);

#[derive(Default)]
pub(crate) struct DebugFilter {
    pub(crate) sender_role: Option<String>,
    pub(crate) recipient_role: Option<String>,
    pub(crate) message_family: Option<String>,
    pub(crate) kind: Option<String>,
    pub(crate) payload_variant: Option<String>,
    pub(crate) payload_field: Option<(String, String)>,
    pub(crate) auth: Option<String>,
}

impl DebugFilter {
    pub(crate) fn matches(&self, d: &tarsier_ir::counter_system::MessageDeliveryEvent) -> bool {
        if let Some(ref role) = self.sender_role {
            if !d.sender.role.eq_ignore_ascii_case(role) {
                return false;
            }
        }
        if let Some(ref role) = self.recipient_role {
            if !d.recipient.role.eq_ignore_ascii_case(role) {
                return false;
            }
        }
        if let Some(ref family) = self.message_family {
            if !d.payload.family.eq_ignore_ascii_case(family) {
                return false;
            }
        }
        if let Some(ref kind) = self.kind {
            let kind_str = format!("{:?}", d.kind);
            if !kind_str.eq_ignore_ascii_case(kind) {
                return false;
            }
        }
        if let Some(ref variant) = self.payload_variant {
            if !d
                .payload
                .variant
                .to_ascii_lowercase()
                .contains(&variant.to_ascii_lowercase())
            {
                return false;
            }
        }
        if let Some((ref key, ref value)) = self.payload_field {
            let has_match = d
                .payload
                .fields
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case(key) && v.eq_ignore_ascii_case(value));
            if !has_match {
                return false;
            }
        }
        if let Some(ref auth_filter_raw) = self.auth {
            let auth_filter = auth_filter_raw.trim().to_ascii_lowercase();
            if !auth_filter.is_empty() {
                let provenance = format!("{:?}", d.auth.provenance).to_ascii_lowercase();
                let key_owner = d
                    .auth
                    .key_owner_role
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let signature_key = d
                    .auth
                    .signature_key
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let auth_matches = match auth_filter.as_str() {
                    "authenticated" => d.auth.authenticated_channel,
                    "unauthenticated" => !d.auth.authenticated_channel,
                    "compromised" => d.auth.key_compromised,
                    "uncompromised" => !d.auth.key_compromised,
                    _ => {
                        provenance.contains(&auth_filter)
                            || key_owner.contains(&auth_filter)
                            || signature_key.contains(&auth_filter)
                    }
                };
                if !auth_matches {
                    return false;
                }
            }
        }
        true
    }

    pub(crate) fn is_active(&self) -> bool {
        self.sender_role.is_some()
            || self.recipient_role.is_some()
            || self.message_family.is_some()
            || self.kind.is_some()
            || self.payload_variant.is_some()
            || self.payload_field.is_some()
            || self.auth.is_some()
    }

    pub(crate) fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref v) = self.sender_role {
            parts.push(format!("sender={v}"));
        }
        if let Some(ref v) = self.recipient_role {
            parts.push(format!("recipient={v}"));
        }
        if let Some(ref v) = self.message_family {
            parts.push(format!("message={v}"));
        }
        if let Some(ref v) = self.kind {
            parts.push(format!("kind={v}"));
        }
        if let Some(ref v) = self.payload_variant {
            parts.push(format!("variant~={v}"));
        }
        if let Some((ref key, ref value)) = self.payload_field {
            parts.push(format!("field:{key}={value}"));
        }
        if let Some(ref v) = self.auth {
            parts.push(format!("auth~={v}"));
        }
        if parts.is_empty() {
            "(none)".into()
        } else {
            parts.join(", ")
        }
    }
}

// ---------------------------------------------------------------------------
// Crypto-replay helpers
// ---------------------------------------------------------------------------

pub(crate) fn parse_counter_metadata_for_crypto(
    counter_name: &str,
) -> Option<ParsedCounterMetadata> {
    let stripped = counter_name.strip_prefix("cnt_")?;
    let (family_part, recipient_part) = stripped.split_once('@').unwrap_or((stripped, "*"));
    let channel = recipient_part
        .split_once('[')
        .map(|(recipient, _)| recipient)
        .unwrap_or(recipient_part);
    let (recipient_channel, sender_channel) = channel
        .split_once("<-")
        .map(|(recipient, sender)| (recipient.to_string(), Some(sender.to_string())))
        .unwrap_or_else(|| (channel.to_string(), None));
    let family = family_part
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(family_part)
        .to_string();
    let fields: Vec<(String, String)> = stripped
        .split_once('[')
        .and_then(|(_, rest)| rest.strip_suffix(']'))
        .map(|field_blob| {
            field_blob
                .split(',')
                .filter_map(|entry| {
                    let (k, v) = entry.split_once('=')?;
                    Some((k.trim().to_string(), v.trim().to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    Some((family, recipient_channel, sender_channel, fields))
}

pub(crate) fn sender_role_from_channel(sender_channel: Option<&str>) -> Option<&str> {
    sender_channel.map(|sender| {
        sender
            .split_once('#')
            .map(|(role, _)| role)
            .unwrap_or(sender)
    })
}

pub(crate) fn eval_threshold_lc(
    lc: &tarsier_ir::threshold_automaton::LinearCombination,
    params: &[i64],
) -> i64 {
    let mut value = lc.constant;
    for (coeff, pid) in &lc.terms {
        value += coeff * params.get(*pid).copied().unwrap_or(0);
    }
    value
}

pub(crate) fn crypto_replay_summary(
    ta: &ThresholdAutomaton,
    pre_config: &tarsier_ir::counter_system::Configuration,
    delivery: &tarsier_ir::counter_system::MessageDeliveryEvent,
) -> Option<String> {
    let spec = ta.crypto_objects.get(&delivery.payload.family)?;
    let recipient_channel = delivery
        .recipient
        .process
        .as_ref()
        .map(|pid| format!("{}#{pid}", delivery.recipient.role))
        .unwrap_or_else(|| delivery.recipient.role.clone());
    let mut witness_vars = Vec::new();
    for (var_id, shared) in ta.shared_vars.iter().enumerate() {
        if shared.kind != tarsier_ir::threshold_automaton::SharedVarKind::MessageCounter {
            continue;
        }
        let Some((family, recipient, sender_channel, fields)) =
            parse_counter_metadata_for_crypto(&shared.name)
        else {
            continue;
        };
        if family != spec.source_message || recipient != recipient_channel {
            continue;
        }
        if fields != delivery.payload.fields {
            continue;
        }
        if let Some(expected_role) = spec.signer_role.as_deref() {
            if sender_role_from_channel(sender_channel.as_deref()) != Some(expected_role) {
                continue;
            }
        }
        witness_vars.push(var_id);
    }
    let observed = witness_vars
        .iter()
        .filter(|var_id| pre_config.gamma.get(**var_id).copied().unwrap_or(0) > 0)
        .count() as i64;
    let required = eval_threshold_lc(&spec.threshold, &pre_config.params);
    Some(format!(
        "crypto={} source={} signer={} threshold={} observed_distinct={} required={} conflicts={}",
        spec.kind,
        spec.source_message,
        spec.signer_role.as_deref().unwrap_or("-"),
        spec.threshold,
        observed,
        required,
        spec.conflict_policy
    ))
}

// ---------------------------------------------------------------------------
// Trace debugger
// ---------------------------------------------------------------------------

pub(crate) fn print_replay_state(
    trace: &Trace,
    index: usize,
    loop_start: Option<usize>,
    ta: Option<&ThresholdAutomaton>,
    filter: &DebugFilter,
) {
    println!("----------------------------------------");
    println!("Counterexample Replay");
    if index == 0 {
        println!("Step 0 (initial)");
        if let Some(ta) = ta {
            print!("{}", config_snapshot(&trace.initial_config, ta));
        } else {
            println!("kappa: {:?}", trace.initial_config.kappa);
            println!("gamma: {:?}", trace.initial_config.gamma);
        }
    } else {
        let step = &trace.steps[index - 1];
        let pre_config = if index == 1 {
            &trace.initial_config
        } else {
            &trace.steps[index - 2].config
        };
        println!(
            "Step {}: rule r{} (delta={})",
            index, step.rule_id, step.delta
        );
        if step.deliveries.is_empty() {
            println!("deliveries: (none)");
        } else {
            let matching: Vec<_> = step
                .deliveries
                .iter()
                .filter(|d| filter.matches(d))
                .collect();
            let hidden = step.deliveries.len() - matching.len();
            if matching.is_empty() && hidden > 0 {
                println!("deliveries: ({hidden} hidden by filter)");
            } else {
                println!("deliveries:");
                for d in &matching {
                    println!(
                        "  - kind={:?} sender={}#{} recipient={}#{} value={} fields={} auth={} provenance={:?}",
                        d.kind,
                        d.sender.role,
                        d.sender.process.as_deref().unwrap_or("-"),
                        d.recipient.role,
                        d.recipient.process.as_deref().unwrap_or("-"),
                        d.payload.family,
                        if d.payload.fields.is_empty() {
                            "(none)".into()
                        } else {
                            d.payload
                                .fields
                                .iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        },
                        if d.auth.authenticated_channel {
                            "authenticated"
                        } else {
                            "unauthenticated"
                        },
                        d.auth.provenance
                    );
                    if let Some(ta) = ta {
                        if let Some(summary) = crypto_replay_summary(ta, pre_config, d) {
                            println!("    {summary}");
                        }
                    }
                }
                if hidden > 0 {
                    println!("  ({hidden} deliveries hidden by filter)");
                }
            }
        }
        if let Some(ta) = ta {
            print!("{}", config_snapshot(&step.config, ta));
        } else {
            println!("kappa: {:?}", step.config.kappa);
            println!("gamma: {:?}", step.config.gamma);
        }
    }
    if let Some(ls) = loop_start {
        println!("Lasso loop starts at step {ls}");
    }
    if filter.is_active() {
        println!("Active filters: {}", filter.summary());
    }
    println!(
        "Use: n (next), p (prev), j <k>, fs/fr/fm/fk/fv/ff/fa/fc/fl (filter), h (help), q (quit)"
    );
}

pub(crate) fn run_trace_debugger(
    trace: &Trace,
    loop_start: Option<usize>,
    ta: Option<&ThresholdAutomaton>,
    initial_filter: DebugFilter,
) -> miette::Result<()> {
    use std::io::{self, Write};
    let mut index = 0usize;
    let max_index = trace.steps.len();
    let mut filter = initial_filter;
    if filter.is_active() {
        println!("Pre-set filters: {}", filter.summary());
    }
    print_replay_state(trace, index, loop_start, ta, &filter);

    loop {
        print!("debug> ");
        io::stdout().flush().into_diagnostic()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line).into_diagnostic()? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "n" || trimmed == "next" {
            if index < max_index {
                index += 1;
            }
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if trimmed == "p" || trimmed == "prev" {
            index = index.saturating_sub(1);
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if trimmed == "q" || trimmed == "quit" || trimmed == "exit" {
            break;
        }
        if trimmed == "h" || trimmed == "help" {
            println!("Commands:");
            println!("  n|next       - advance to next step");
            println!("  p|prev       - go back to previous step");
            println!("  j <k>        - jump to step k");
            println!("  fs <role>    - filter deliveries by sender role");
            println!("  fr <role>    - filter deliveries by recipient role");
            println!("  fm <family>  - filter deliveries by message family");
            println!(
                "  fk <kind>    - filter deliveries by kind (send/deliver/drop/forge/equivocate)"
            );
            println!("  fv <text>    - filter deliveries by payload variant substring");
            println!("  ff <k=v>     - filter deliveries by payload field equality");
            println!(
                "  fa <auth>    - filter auth metadata (authenticated|unauthenticated|compromised|uncompromised|OwnedKey/ByzantineSigner)"
            );
            println!("  fc           - clear all filters");
            println!("  fl           - list active filters");
            println!("  h|help       - show this help");
            println!("  q|quit       - exit debugger");
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("j ") {
            match rest.trim().parse::<usize>() {
                Ok(k) if k <= max_index => {
                    index = k;
                    print_replay_state(trace, index, loop_start, ta, &filter);
                }
                _ => {
                    println!("Invalid jump target. Expected 0..{max_index}.");
                }
            }
            continue;
        }
        // Filter commands
        if let Some(rest) = trimmed.strip_prefix("fs ") {
            filter.sender_role = Some(rest.trim().to_string());
            println!("Filter: sender={}", rest.trim());
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fr ") {
            filter.recipient_role = Some(rest.trim().to_string());
            println!("Filter: recipient={}", rest.trim());
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fm ") {
            filter.message_family = Some(rest.trim().to_string());
            println!("Filter: message={}", rest.trim());
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fk ") {
            filter.kind = Some(rest.trim().to_string());
            println!("Filter: kind={}", rest.trim());
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fv ") {
            let needle = rest.trim();
            if needle.is_empty() {
                println!("Usage: fv <text>");
            } else {
                filter.payload_variant = Some(needle.to_string());
                println!("Filter: variant~={needle}");
                print_replay_state(trace, index, loop_start, ta, &filter);
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("ff ") {
            let spec = rest.trim();
            let Some((key_raw, value_raw)) = spec.split_once('=') else {
                println!("Invalid field filter. Usage: ff <field=value>");
                continue;
            };
            let key = key_raw.trim();
            let value = value_raw.trim();
            if key.is_empty() || value.is_empty() {
                println!("Invalid field filter. Usage: ff <field=value>");
                continue;
            }
            filter.payload_field = Some((key.to_string(), value.to_string()));
            println!("Filter: field:{key}={value}");
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fa ") {
            let auth = rest.trim();
            if auth.is_empty() {
                println!("Usage: fa <authenticated|unauthenticated|compromised|uncompromised|OwnedKey|ByzantineSigner>");
            } else {
                filter.auth = Some(auth.to_string());
                println!("Filter: auth~={auth}");
                print_replay_state(trace, index, loop_start, ta, &filter);
            }
            continue;
        }
        if trimmed == "fc" {
            filter = DebugFilter::default();
            println!("All filters cleared.");
            print_replay_state(trace, index, loop_start, ta, &filter);
            continue;
        }
        if trimmed == "fl" {
            if filter.is_active() {
                println!("Active filters: {}", filter.summary());
            } else {
                println!("No active filters.");
            }
            continue;
        }
        println!("Unknown command: {trimmed}. Type 'h' for help.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Visualization output helpers
// ---------------------------------------------------------------------------

pub(crate) fn write_visualization_output(
    output: &str,
    out: Option<&PathBuf>,
) -> miette::Result<()> {
    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).into_diagnostic()?;
        }
        std::fs::write(path, output).into_diagnostic()?;
        println!("Visualization written to {}", path.display());
    } else {
        println!("{output}");
    }
    Ok(())
}

pub(crate) fn find_counterexample_for_visualization(
    source: &str,
    filename: &str,
    check: VisualizeCheck,
    options: &PipelineOptions,
    fairness: FairnessMode,
) -> miette::Result<VisualizedCounterexample> {
    match check {
        VisualizeCheck::Verify => {
            let result =
                tarsier_engine::pipeline::verify(source, filename, options).into_diagnostic()?;
            let output = format!("{result}");
            match result {
                VerificationResult::Unsafe { trace } => Ok(VisualizedCounterexample {
                    trace,
                    loop_start: None,
                    result_output: output,
                    check,
                }),
                _ => {
                    println!("{output}");
                    miette::bail!(
                        "No counterexample trace available for check=verify (result was not UNSAFE)."
                    );
                }
            }
        }
        VisualizeCheck::Liveness => {
            let result = tarsier_engine::pipeline::check_liveness(source, filename, options)
                .into_diagnostic()?;
            let output = format!("{result}");
            match result {
                LivenessResult::NotLive { trace } => Ok(VisualizedCounterexample {
                    trace,
                    loop_start: None,
                    result_output: output,
                    check,
                }),
                _ => {
                    println!("{output}");
                    miette::bail!(
                        "No counterexample trace available for check=liveness (result was not NOT LIVE)."
                    );
                }
            }
        }
        VisualizeCheck::FairLiveness => {
            let result = tarsier_engine::pipeline::check_fair_liveness_with_mode(
                source, filename, options, fairness,
            )
            .into_diagnostic()?;
            let output = format!("{result}");
            match result {
                FairLivenessResult::FairCycleFound {
                    loop_start, trace, ..
                } => Ok(VisualizedCounterexample {
                    trace,
                    loop_start: Some(loop_start),
                    result_output: output,
                    check,
                }),
                _ => {
                    println!("{output}");
                    miette::bail!(
                        "No counterexample trace available for check=fair-liveness (result was not FAIR CYCLE FOUND)."
                    );
                }
            }
        }
        VisualizeCheck::Prove => {
            if detect_prove_auto_target(source, filename)? == ProveAutoTarget::FairLiveness {
                let result = tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                    source, filename, options, fairness,
                )
                .into_diagnostic()?;
                let output = format!("{result}");
                match result {
                    UnboundedFairLivenessResult::FairCycleFound {
                        loop_start, trace, ..
                    } => Ok(VisualizedCounterexample {
                        trace,
                        loop_start: Some(loop_start),
                        result_output: output,
                        check,
                    }),
                    _ => {
                        println!("{output}");
                        miette::bail!(
                            "No counterexample trace available for check=prove (auto-dispatched to liveness proof; result was not FAIR CYCLE FOUND)."
                        );
                    }
                }
            } else {
                let result = tarsier_engine::pipeline::prove_safety(source, filename, options)
                    .into_diagnostic()?;
                let output = format!("{result}");
                match result {
                    UnboundedSafetyResult::Unsafe { trace } => Ok(VisualizedCounterexample {
                        trace,
                        loop_start: None,
                        result_output: output,
                        check,
                    }),
                    _ => {
                        println!("{output}");
                        miette::bail!(
                            "No counterexample trace available for check=prove (result was not UNSAFE)."
                        );
                    }
                }
            }
        }
        VisualizeCheck::ProveFair => {
            let result = tarsier_engine::pipeline::prove_fair_liveness_with_mode(
                source, filename, options, fairness,
            )
            .into_diagnostic()?;
            let output = format!("{result}");
            match result {
                UnboundedFairLivenessResult::FairCycleFound {
                    loop_start, trace, ..
                } => Ok(VisualizedCounterexample {
                    trace,
                    loop_start: Some(loop_start),
                    result_output: output,
                    check,
                }),
                _ => {
                    println!("{output}");
                    miette::bail!(
                        "No counterexample trace available for check=prove-fair (result was not FAIR CYCLE FOUND)."
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// Handler for the `parse` subcommand.
///
/// Parses a `.trs` file and pretty-prints the AST.
pub(crate) fn run_parse_command(file: PathBuf) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();

    match tarsier_dsl::parse(&source, &filename) {
        Ok(program) => {
            println!("{:#?}", program);
        }
        Err(e) => {
            eprintln!("Parse error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Handler for the `show-ta` subcommand.
///
/// Parses and lowers a protocol file, then prints the threshold automaton.
pub(crate) fn run_show_ta_command(
    file: PathBuf,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    validate_cli_network_semantics_mode(
        &source,
        &filename,
        SoundnessMode::Strict,
        cli_network_mode,
    )?;

    match tarsier_engine::pipeline::show_ta(&source, &filename) {
        Ok(output) => {
            print!("{output}");
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}

/// Handler for the `export-dot` subcommand.
///
/// Exports the threshold automaton as a Graphviz DOT graph, optionally
/// rendering to SVG via the `dot` command.
pub(crate) fn run_export_dot_command(
    file: PathBuf,
    cluster: bool,
    svg: bool,
    out: Option<PathBuf>,
) -> miette::Result<()> {
    use std::io::Write;
    use tarsier_engine::visualization::{render_automaton_dot, DotRenderOptions};

    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();

    let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;

    let opts = DotRenderOptions {
        cluster_by_phase: cluster,
        ..DotRenderOptions::default()
    };
    let dot_source = render_automaton_dot(&ta, &opts);

    if svg {
        // Pipe through `dot -Tsvg`
        let mut child = std::process::Command::new("dot")
            .args(["-Tsvg"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| miette::miette!("Failed to run `dot`: {e}. Install graphviz."))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(dot_source.as_bytes()).into_diagnostic()?;
        } else {
            return Err(miette::miette!(
                "Failed to pipe DOT source into `dot` (stdin unavailable)."
            ));
        }

        let output = child.wait_with_output().into_diagnostic()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(miette::miette!("dot command failed: {stderr}"));
        }

        if let Some(ref out_path) = out {
            fs::write(out_path, &output.stdout).into_diagnostic()?;
            eprintln!("SVG written to {}", out_path.display());
        } else {
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
    } else if let Some(ref out_path) = out {
        fs::write(out_path, &dot_source).into_diagnostic()?;
        eprintln!("DOT written to {}", out_path.display());
    } else {
        print!("{dot_source}");
    }
    Ok(())
}

/// Handler for the `export-ta` subcommand.
///
/// Exports the threshold automaton in ByMC `.ta` format.
pub(crate) fn run_export_ta_command(file: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();

    let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;
    let ta_text = tarsier_engine::export_ta::export_ta_for_program(&ta, &program);

    match out {
        Some(ref out_path) => {
            fs::write(out_path, &ta_text).into_diagnostic()?;
            eprintln!("ByMC .ta written to {}", out_path.display());
        }
        None => print!("{ta_text}"),
    }
    Ok(())
}

/// Handler for the `visualize` subcommand.
///
/// Runs the requested analysis, extracts a counterexample trace, and renders
/// it in the requested format (timeline, mermaid, markdown, or JSON).
/// Optionally writes a multi-format bundle directory.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_visualize_command(
    file: PathBuf,
    check: String,
    solver: String,
    depth: usize,
    k: usize,
    timeout: u64,
    soundness: String,
    fairness: String,
    engine: String,
    format: String,
    out: Option<PathBuf>,
    bundle: Option<PathBuf>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();

    let check = parse_visualize_check(&check);
    let format = parse_visualize_format(&format);
    let fairness = parse_fairness_mode(&fairness);
    let soundness = parse_soundness_mode(&soundness);
    validate_cli_network_semantics_mode(&source, &filename, soundness, cli_network_mode)?;
    let solver = parse_solver_choice(&solver);
    let engine = parse_proof_engine(&engine);

    let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
    let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;

    let mut options = PipelineOptions {
        solver,
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt: None,
        soundness,
        proof_engine: engine,
    };
    if matches!(check, VisualizeCheck::Prove | VisualizeCheck::ProveFair) {
        options.max_depth = k;
    }

    let cex = find_counterexample_for_visualization(&source, &filename, check, &options, fairness)?;

    let timeline = render_trace_timeline(&cex.trace, &ta, cex.loop_start);
    let mermaid = render_trace_mermaid(&cex.trace, &ta, cex.loop_start);
    let title = format!(
        "Counterexample Visualization ({})",
        visualize_check_name(cex.check)
    );

    // Bundle export: write all formats into a directory
    if let Some(ref bundle_dir) = bundle {
        fs::create_dir_all(bundle_dir).into_diagnostic()?;
        fs::write(bundle_dir.join("timeline.txt"), &timeline).into_diagnostic()?;
        fs::write(bundle_dir.join("msc.mermaid"), &mermaid).into_diagnostic()?;
        let markdown = render_trace_markdown(&title, &cex.trace, &ta, cex.loop_start);
        fs::write(bundle_dir.join("report.md"), &markdown).into_diagnostic()?;
        let json_output = serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "kind": visualize_check_name(cex.check),
            "loop_start": cex.loop_start,
            "result": cex.result_output,
            "trace": trace_details(&cex.trace),
        }))
        .into_diagnostic()?;
        fs::write(bundle_dir.join("trace.json"), &json_output).into_diagnostic()?;
        let metadata = serde_json::to_string_pretty(&json!({
            "protocol_file": filename,
            "check": visualize_check_name(cex.check),
            "result": cex.result_output,
            "loop_start": cex.loop_start,
        }))
        .into_diagnostic()?;
        fs::write(bundle_dir.join("metadata.json"), &metadata).into_diagnostic()?;
        println!(
            "Bundle written to {} (timeline.txt, msc.mermaid, report.md, trace.json, metadata.json)",
            bundle_dir.display()
        );
    }

    let output = match format {
        VisualizeFormat::Timeline => timeline,
        VisualizeFormat::Mermaid => mermaid,
        VisualizeFormat::Markdown => render_trace_markdown(&title, &cex.trace, &ta, cex.loop_start),
        VisualizeFormat::Json => serde_json::to_string_pretty(&json!({
            "schema_version": 1,
            "kind": visualize_check_name(cex.check),
            "format": visualize_format_name(format),
            "loop_start": cex.loop_start,
            "result": cex.result_output,
            "timeline": timeline,
            "mermaid": mermaid,
            "trace": trace_details(&cex.trace),
        }))
        .into_diagnostic()?,
    };

    write_visualization_output(&output, out.as_ref())?;
    Ok(())
}

/// Handler for the `explore` subcommand.
///
/// Launches the interactive TUI counterexample trace explorer.  Accepts an
/// optional `--trace-json` path to load a pre-existing trace instead of
/// running the analysis.
pub(crate) fn run_explore_command(
    file: PathBuf,
    solver: String,
    depth: usize,
    timeout: u64,
    trace_json: Option<PathBuf>,
) -> miette::Result<()> {
    if let Some(json_path) = trace_json {
        let json_data = std::fs::read_to_string(&json_path).into_diagnostic()?;
        let trace: Trace = serde_json::from_str(&json_data).into_diagnostic()?;
        let source = sandbox_read_source(&file)?;
        let filename = file.display().to_string();
        let ta = match tarsier_engine::pipeline::parse(&source, &filename) {
            Ok(program) => tarsier_engine::pipeline::lower(&program).ok(),
            Err(_) => None,
        };
        crate::tui::run_explorer(trace, ta, None)?;
    } else {
        let source = sandbox_read_source(&file)?;
        let filename = file.display().to_string();
        let solver_choice = parse_solver_choice(&solver);

        let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;
        let ta = tarsier_engine::pipeline::lower(&program).into_diagnostic()?;

        let options = PipelineOptions {
            solver: solver_choice,
            max_depth: depth,
            timeout_secs: timeout,
            soundness: SoundnessMode::Strict,
            ..PipelineOptions::default()
        };

        match tarsier_engine::pipeline::verify(&source, &filename, &options) {
            Ok(result) => match result {
                VerificationResult::Unsafe { trace, .. } => {
                    crate::tui::run_explorer(trace, Some(ta), None)?;
                }
                VerificationResult::Safe { .. } => {
                    eprintln!("Protocol is safe at depth {depth} — no counterexample to explore.");
                }
                _ => {
                    eprintln!("Verification result has no counterexample trace to explore.");
                }
            },
            Err(e) => {
                eprintln!("Verification error: {e}");
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// Handler for the `debug-cex` subcommand.
///
/// Runs the requested analysis, extracts a counterexample, and enters the
/// interactive trace debugger with optional pre-set delivery filters.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_debug_cex_command(
    file: PathBuf,
    check: String,
    solver: String,
    depth: usize,
    k: usize,
    timeout: u64,
    soundness: String,
    fairness: String,
    engine: String,
    filter_sender: Option<String>,
    filter_recipient: Option<String>,
    filter_message: Option<String>,
    filter_kind: Option<String>,
    filter_variant: Option<String>,
    filter_auth: Option<String>,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();
    let check = parse_visualize_check(&check);
    let fairness = parse_fairness_mode(&fairness);
    let soundness = parse_soundness_mode(&soundness);
    validate_cli_network_semantics_mode(&source, &filename, soundness, cli_network_mode)?;
    let solver = parse_solver_choice(&solver);
    let engine = parse_proof_engine(&engine);

    let mut options = PipelineOptions {
        solver,
        max_depth: depth,
        timeout_secs: timeout,
        dump_smt: None,
        soundness,
        proof_engine: engine,
    };
    if matches!(check, VisualizeCheck::Prove | VisualizeCheck::ProveFair) {
        options.max_depth = k;
    }

    let ta = tarsier_engine::pipeline::parse(&source, &filename)
        .ok()
        .and_then(|prog| tarsier_engine::pipeline::lower(&prog).ok());

    let initial_filter = DebugFilter {
        sender_role: filter_sender,
        recipient_role: filter_recipient,
        message_family: filter_message,
        kind: filter_kind,
        payload_variant: filter_variant,
        payload_field: None,
        auth: filter_auth,
    };

    let cex = find_counterexample_for_visualization(&source, &filename, check, &options, fairness)?;
    println!("{}", cex.result_output);
    run_trace_debugger(&cex.trace, cex.loop_start, ta.as_ref(), initial_filter)?;
    Ok(())
}
