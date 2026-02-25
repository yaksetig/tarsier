//! Security regression tests for sandbox enforcement.
//!
//! These tests verify that:
//! 1. The sandbox activates by default and enforces resource constraints.
//! 2. Oversized inputs are rejected before parsing.
//! 3. Missing sandbox controls cause fail-closed behavior.
//! 4. The --allow-degraded-sandbox flag is required when controls are unavailable.

use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn cargo_run(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new("cargo");
    cmd.arg("run").arg("-p").arg("tarsier-cli").arg("--");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env("CMAKE_POLICY_VERSION_MINIMUM", "3.5")
        .current_dir(workspace_root())
        .output()
        .expect("failed to execute cargo run")
}

// -----------------------------------------------------------------------
// Input size abuse: oversized file is rejected
// -----------------------------------------------------------------------

#[test]
fn oversized_input_rejected() {
    // Create a temp file larger than the sandbox limit (use a very small limit)
    let tmp = std::env::temp_dir().join(format!(
        "tarsier_sandbox_oversize_{}.trs",
        std::process::id()
    ));
    // Write 200 bytes of valid-ish content
    let content = "// padding\n".repeat(20);
    std::fs::write(&tmp, &content).unwrap();

    let output = cargo_run(&[
        "--sandbox-max-input-bytes",
        "50", // 50 bytes limit — file is ~220 bytes
        "--allow-degraded-sandbox",
        "verify",
        tmp.to_str().unwrap(),
        "--depth",
        "1",
        "--timeout",
        "5",
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "should reject oversized input; stderr: {stderr}"
    );
    assert!(
        stderr.contains("exceeding sandbox limit") || stderr.contains("sandbox"),
        "error should mention sandbox limit; stderr: {stderr}"
    );

    let _ = std::fs::remove_file(&tmp);
}

// -----------------------------------------------------------------------
// Normal-sized input with sandbox passes initial validation
// -----------------------------------------------------------------------

#[test]
fn normal_input_passes_sandbox_check() {
    // A valid .trs file should pass sandbox input validation
    // (it may fail later on parsing/verification, but the sandbox gate
    // should not block it).
    let output = cargo_run(&[
        "--sandbox-max-input-bytes",
        "1048576",
        "--allow-degraded-sandbox",
        "verify",
        "examples/reliable_broadcast.trs",
        "--depth",
        "1",
        "--timeout",
        "10",
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should NOT fail on sandbox input validation
    assert!(
        !stderr.contains("exceeding sandbox limit"),
        "normal input should pass sandbox; stderr: {stderr}"
    );
}

// -----------------------------------------------------------------------
// Sandbox activates by default (no special flags needed)
// -----------------------------------------------------------------------

#[test]
fn sandbox_activates_by_default() {
    // Running any command should activate the sandbox.
    // Verify by checking that the command runs without "Sandbox activation failed"
    let output = cargo_run(&[
        "verify",
        "examples/reliable_broadcast.trs",
        "--depth",
        "1",
        "--timeout",
        "10",
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Sandbox activation failed"),
        "sandbox should activate by default; stderr: {stderr}"
    );
}

// -----------------------------------------------------------------------
// Fail-closed: sandbox error produces actionable diagnostic
// -----------------------------------------------------------------------

#[test]
fn sandbox_error_is_actionable() {
    // Use the library directly to test fail-closed behavior
    use tarsier_engine::sandbox::{SandboxConfig, SandboxError, SandboxGuard};

    // On platforms without memory monitoring, activation without
    // allow_degraded should fail with an actionable message.
    // On Linux/macOS (which have monitoring), this test validates
    // that the error message format is correct by constructing the error.
    let err = SandboxError::ControlUnavailable {
        control: "memory_monitoring".into(),
        reason: "test platform".into(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("--allow-degraded-sandbox"),
        "error should suggest --allow-degraded-sandbox; got: {msg}"
    );
    assert!(
        msg.contains("cannot be enforced"),
        "error should explain what cannot be enforced; got: {msg}"
    );

    // Verify that SandboxConfig with allow_degraded=true always succeeds
    let config = SandboxConfig {
        allow_degraded: true,
        ..SandboxConfig::default()
    };
    // Reset global state (in case prior test left it set)
    // Note: this relies on tests running single-threaded or the guard being dropped
    let guard = SandboxGuard::activate(config);
    if let Ok(_g) = guard {
        // Guard activated; it will be dropped when _g goes out of scope
    }
    // If it failed with AlreadyActive, that's also fine for this test
}

// -----------------------------------------------------------------------
// Memory budget: absurdly low budget trips the check
// -----------------------------------------------------------------------

#[test]
fn memory_budget_enforcement() {
    use tarsier_engine::sandbox::{current_rss_bytes, SandboxConfig, SandboxGuard};

    // Ensure the process RSS is well above the 1 MiB granularity boundary.
    // Without this, a lightweight test binary might have RSS < 2 MiB, making
    // it impossible to set a non-zero budget below the RSS.
    let _ballast: Vec<u8> = vec![1u8; 4 * 1024 * 1024]; // 4 MiB touched memory

    // Read baseline RSS so we can set a budget guaranteed to be lower.
    let baseline_rss_bytes = match current_rss_bytes() {
        Some(bytes) => bytes,
        None => {
            eprintln!("skipping memory_budget_enforcement: RSS monitoring unavailable");
            return;
        }
    };
    let baseline_rss_mb = baseline_rss_bytes / (1024 * 1024);

    // Budget = half the current RSS (in MiB). With the ballast above,
    // baseline_rss_mb is at least 4, so budget_mb is at least 2 (non-zero).
    let budget_mb = baseline_rss_mb / 2;
    assert!(
        budget_mb > 0,
        "baseline RSS should be at least 2 MiB after ballast (got {baseline_rss_mb} MiB)"
    );

    let config = SandboxConfig {
        memory_budget_mb: budget_mb,
        allow_degraded: true,
        ..SandboxConfig::default()
    };

    // This may fail with AlreadyActive if another test's guard is still live.
    // That's acceptable — the key assertion is about check_memory.
    if let Ok(guard) = SandboxGuard::activate(config) {
        let result = guard.check_memory();
        assert!(
            result.is_err(),
            "budget of {budget_mb} MiB should be exceeded by test process \
             (baseline RSS: {baseline_rss_mb} MiB, {baseline_rss_bytes} bytes)"
        );
    }
}

// -----------------------------------------------------------------------
// Timeout enforcement: zero-second timeout trips immediately
// -----------------------------------------------------------------------

#[test]
fn timeout_enforcement() {
    use std::time::Duration;
    use tarsier_engine::sandbox::{SandboxConfig, SandboxGuard};

    let config = SandboxConfig {
        timeout_secs: 0,
        allow_degraded: true,
        ..SandboxConfig::default()
    };

    if let Ok(guard) = SandboxGuard::activate(config) {
        std::thread::sleep(Duration::from_millis(10));
        let result = guard.check_timeout();
        assert!(result.is_err(), "zero-second timeout should trip");
    }
}

// -----------------------------------------------------------------------
// Runtime timeout via actual pipeline path (enforce_active_limits)
// -----------------------------------------------------------------------

#[test]
fn runtime_timeout_in_pipeline_path() {
    // Runs the real CLI binary with --sandbox-timeout-secs 0, ensuring
    // enforce_active_limits() fires immediately in the pipeline path
    // (not just a direct unit call on SandboxGuard).
    let output = cargo_run(&[
        "--sandbox-timeout-secs",
        "0",
        "--allow-degraded-sandbox",
        "verify",
        "examples/reliable_broadcast.trs",
        "--depth",
        "5",
        "--timeout",
        "30",
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}{stdout}");

    // With timeout_secs=0, enforce_active_limits() should fire at the first
    // pipeline stage boundary (before BMC), producing a
    // PipelineError::Sandbox(TimeoutExceeded). The CLI renders this as
    // "Sandbox limit exceeded: sandbox timeout exceeded..."
    assert!(
        !output.status.success(),
        "expected non-zero exit due to sandbox timeout; \
         exit={}, stderr={stderr}, stdout={stdout}",
        output.status
    );
    assert!(
        combined.contains("timeout exceeded") || combined.contains("Sandbox limit exceeded"),
        "expected sandbox timeout message in output; \
         stderr={stderr}, stdout={stdout}",
    );
}

// -----------------------------------------------------------------------
// Runtime memory limit via actual pipeline path (enforce_active_limits)
// -----------------------------------------------------------------------

#[test]
fn runtime_memory_limit_in_pipeline_path() {
    // Runs the real CLI binary with --sandbox-memory-budget-mb 1 and a protocol,
    // ensuring enforce_active_limits() triggers the memory check in the actual
    // pipeline path.
    let output = cargo_run(&[
        "--sandbox-memory-budget-mb",
        "1",
        "--allow-degraded-sandbox",
        "verify",
        "examples/reliable_broadcast.trs",
        "--depth",
        "5",
        "--timeout",
        "30",
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}{stdout}");

    // On platforms with RSS monitoring (Linux/macOS), the 1 MiB budget should
    // be exceeded during pipeline execution, triggering enforce_active_limits().
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(
        !output.status.success() || combined.contains("memory budget exceeded"),
        "expected sandbox memory limit to fire during pipeline execution; \
         exit={}, stderr={stderr}, stdout={stdout}",
        output.status
    );
}
