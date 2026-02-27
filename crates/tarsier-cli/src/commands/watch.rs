// Command handler for: Watch
//
// Watches a `.trs` file for changes and re-runs the prove pipeline
// automatically, providing a fast feedback loop during protocol development.

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use miette::IntoDiagnostic;
use notify::{RecursiveMode, Watcher};

use crate::CliNetworkSemanticsMode;

/// Debounce window: ignore rapid successive events within this duration.
const DEBOUNCE_MS: u64 = 500;

/// Run verification once and print the result with colored status.
///
/// Returns `Ok(true)` when verification completed (regardless of verdict),
/// `Ok(false)` should not normally occur, and `Err` on hard failures that
/// we still want to display rather than crash the watcher.
#[allow(clippy::too_many_arguments)]
fn run_once(
    file: &std::path::Path,
    solver: &str,
    k: usize,
    timeout: u64,
    soundness: &str,
    engine: &str,
    fairness: &str,
    portfolio: bool,
    format: &str,
    cli_network_mode: CliNetworkSemanticsMode,
) {
    let result = super::prove::run_prove_command(
        file.to_path_buf(),
        solver.to_string(),
        k,
        timeout,
        soundness.to_string(),
        engine.to_string(),
        fairness.to_string(),
        None, // cert_out — not applicable in watch mode
        0,    // cegar_iters — keep it simple
        None, // cegar_report_out
        portfolio,
        format.to_string(),
        cli_network_mode,
    );

    match result {
        Ok(()) => {
            // The prove command already printed its own output.
            // Print a green status footer.
            eprintln!("\x1b[32m[watch] Verification run completed.\x1b[0m");
        }
        Err(e) => {
            eprintln!("\x1b[31m[watch] Verification error: {e}\x1b[0m");
        }
    }
}

/// Print a separator header with timestamp before each run.
fn print_run_header() {
    let now = chrono_free_timestamp();
    eprintln!();
    eprintln!("\x1b[1m{}\x1b[0m", "=".repeat(60));
    eprintln!("\x1b[1m[watch] Re-running verification at {now}\x1b[0m");
    eprintln!("\x1b[1m{}\x1b[0m", "=".repeat(60));
    eprintln!();
}

/// Produce a human-readable timestamp without pulling in the `chrono` crate.
fn chrono_free_timestamp() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple HH:MM:SS UTC representation.
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02} UTC")
}

/// Entry point for `tarsier watch`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_watch_command(
    file: PathBuf,
    solver: String,
    k: usize,
    timeout: u64,
    soundness: String,
    engine: String,
    fairness: String,
    portfolio: bool,
    format: String,
    cli_network_mode: CliNetworkSemanticsMode,
) -> miette::Result<()> {
    // Resolve the watched path to an absolute canonical form so the watcher
    // picks up renames / atomic-save patterns that editors use.
    let canonical = file.canonicalize().into_diagnostic()?;
    let watch_dir = canonical
        .parent()
        .ok_or_else(|| miette::miette!("Cannot determine parent directory of {}", file.display()))?
        .to_path_buf();

    eprintln!(
        "\x1b[1;36m[watch] Watching {} for changes (Ctrl+C to stop)\x1b[0m",
        file.display()
    );
    eprintln!();

    // ---------- initial run ----------
    print_run_header();
    run_once(
        &file,
        &solver,
        k,
        timeout,
        &soundness,
        &engine,
        &fairness,
        portfolio,
        &format,
        cli_network_mode,
    );

    // ---------- set up file watcher ----------
    let (tx, rx) = mpsc::channel();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        // We only care that *something* changed; the debounce logic in the
        // main loop coalesces multiple events.
        if let Ok(event) = res {
            // Filter to modification / create / rename events on .trs files.
            use notify::EventKind;
            match event.kind {
                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) => {
                    let dominated_by_trs = event
                        .paths
                        .iter()
                        .any(|p| p.extension().map(|ext| ext == "trs").unwrap_or(false));
                    if dominated_by_trs {
                        let _ = tx.send(());
                    }
                }
                _ => {}
            }
        }
    })
    .into_diagnostic()?;

    // Watch the directory containing the file so we also pick up sibling
    // imports that might live alongside the main file.
    watcher
        .watch(&watch_dir, RecursiveMode::NonRecursive)
        .into_diagnostic()?;

    // ---------- main event loop ----------
    let debounce = Duration::from_millis(DEBOUNCE_MS);
    while rx.recv().is_ok() {
        // Drain any additional events that arrived within the debounce window.
        let deadline = Instant::now() + debounce;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok(()) => { /* keep draining */ }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Ok(());
                }
            }
        }

        // Clear screen (ANSI escape) and re-run.
        eprint!("\x1b[2J\x1b[H");
        print_run_header();
        run_once(
            &file,
            &solver,
            k,
            timeout,
            &soundness,
            &engine,
            &fairness,
            portfolio,
            &format,
            cli_network_mode,
        );
    }

    Ok(())
}
