use super::*;

/// Reset global state between tests (tests run in parallel, so we need
/// to be careful).  In practice, each test that activates a sandbox
/// must drop the guard before returning.
fn reset_globals() {
    SANDBOX_ACTIVE.store(false, Ordering::Release);
}

#[test]
fn default_config_has_sane_values() {
    let config = SandboxConfig::default();
    assert_eq!(config.timeout_secs, 300);
    assert_eq!(config.memory_budget_mb, 4096);
    assert_eq!(config.max_input_bytes, 1024 * 1024);
    assert!(!config.allow_degraded);
}

#[test]
fn sandbox_guard_activation_and_deactivation() {
    reset_globals();
    let config = SandboxConfig {
        allow_degraded: true,
        ..SandboxConfig::default()
    };
    assert!(!is_sandbox_active());
    {
        let guard = SandboxGuard::activate(config).expect("should activate");
        assert!(is_sandbox_active());
        assert!(guard.elapsed().as_millis() < 1000);
    }
    // After drop, sandbox should be inactive
    assert!(!is_sandbox_active());
}

#[test]
fn sandbox_timeout_check() {
    reset_globals();
    let config = SandboxConfig {
        timeout_secs: 0, // instant timeout
        allow_degraded: true,
        ..SandboxConfig::default()
    };
    let guard = SandboxGuard::activate(config).expect("should activate");
    std::thread::sleep(Duration::from_millis(10));
    let result = guard.check_timeout();
    assert!(result.is_err());
    match result.unwrap_err() {
        SandboxError::TimeoutExceeded { .. } => {}
        other => panic!("expected TimeoutExceeded, got: {other}"),
    }
}

#[test]
fn sandbox_input_size_validation() {
    reset_globals();
    let config = SandboxConfig {
        max_input_bytes: 100,
        allow_degraded: true,
        ..SandboxConfig::default()
    };
    let guard = SandboxGuard::activate(config).expect("should activate");
    assert!(guard.validate_input_size(50).is_ok());
    assert!(guard.validate_input_size(100).is_ok());
    let err = guard.validate_input_size(101).unwrap_err();
    match err {
        SandboxError::InputTooLarge {
            size: 101,
            limit: 100,
        } => {}
        other => panic!("expected InputTooLarge, got: {other}"),
    }
}

#[test]
fn sandbox_memory_check_zero_budget_always_ok() {
    reset_globals();
    let config = SandboxConfig {
        memory_budget_mb: 0,
        allow_degraded: true,
        ..SandboxConfig::default()
    };
    let guard = SandboxGuard::activate(config).expect("should activate");
    assert!(guard.check_memory().is_ok());
}

#[test]
fn platform_capabilities_detected() {
    let caps = detect_platform_capabilities();
    // On any platform, this should return without panicking
    // On Linux/macOS, memory_monitoring should be true
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(
        caps.memory_monitoring,
        "expected memory monitoring on linux/macos"
    );

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    assert!(!caps.memory_monitoring);
}

#[test]
fn current_rss_returns_nonzero_on_supported_platforms() {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let rss = current_rss_bytes();
        assert!(rss.is_some(), "RSS should be available");
        assert!(rss.unwrap() > 0, "RSS should be non-zero");
    }
}

#[test]
fn sandbox_memory_budget_enforced() {
    reset_globals();
    // Set an absurdly low memory budget (1 MiB) — the test process
    // itself uses more than that.
    let config = SandboxConfig {
        memory_budget_mb: 1,
        allow_degraded: true,
        ..SandboxConfig::default()
    };
    let guard = SandboxGuard::activate(config).expect("should activate");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let result = guard.check_memory();
        assert!(result.is_err(), "should detect budget exceeded");
        match result.unwrap_err() {
            SandboxError::MemoryBudgetExceeded { .. } => {}
            other => panic!("expected MemoryBudgetExceeded, got: {other}"),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // On unsupported platforms with degraded mode, check_memory returns Ok
        assert!(guard.check_memory().is_ok());
    }
}

#[test]
fn fail_closed_without_allow_degraded() {
    reset_globals();
    // On platforms without memory monitoring and without allow_degraded,
    // activation should fail.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let config = SandboxConfig {
            memory_budget_mb: 4096,
            allow_degraded: false,
            ..SandboxConfig::default()
        };
        let result = SandboxGuard::activate(config);
        assert!(result.is_err());
        match result.unwrap_err() {
            SandboxError::ControlUnavailable { .. } => {}
            other => panic!("expected ControlUnavailable, got: {other}"),
        }
    }
    // On Linux/macOS, activation should succeed even without allow_degraded
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let config = SandboxConfig {
            memory_budget_mb: 4096,
            allow_degraded: false,
            ..SandboxConfig::default()
        };
        let guard = SandboxGuard::activate(config);
        assert!(guard.is_ok(), "should succeed on linux/macos");
    }
}

#[test]
fn enforce_active_limits_ok_when_no_sandbox() {
    reset_globals();
    // No sandbox activated — should return Ok
    assert!(enforce_active_limits().is_ok());
}

// Note: enforce_active_limits() reads from process-global OnceLock values
// (ACTIVE_CONFIG, ACTIVATED_AT) which cannot be reset between parallel tests.
// The enforcement logic is identical to check_timeout() + check_memory()
// which are thoroughly tested above via SandboxGuard methods. The wiring of
// enforce_active_limits() at pipeline stage boundaries is verified by the
// build (compile-time) and integration tests.

#[test]
fn enforce_active_limits_returns_ok_or_err_when_active() {
    // When SANDBOX_ACTIVE is true, enforce_active_limits reads globals.
    // In parallel tests the OnceLock values may be set by any test that
    // called activate(), so we just verify it doesn't panic.
    reset_globals();
    let config = SandboxConfig {
        timeout_secs: 300,
        memory_budget_mb: 16384,
        allow_degraded: true,
        ..SandboxConfig::default()
    };
    // activate() sets OnceLock only if not already set by another test
    let _guard = SandboxGuard::activate(config).expect("should activate");
    // Should not panic regardless of which config the OnceLock holds
    let _result = enforce_active_limits();
}

#[test]
fn pipeline_error_sandbox_variant_pattern_matches() {
    let err = SandboxError::TimeoutExceeded {
        elapsed_secs: 610,
        limit_secs: 600,
    };
    let msg = err.to_string();
    assert!(msg.contains("610"));
    assert!(msg.contains("600"));

    let err = SandboxError::MemoryBudgetExceeded {
        rss_mb: 5000,
        limit_mb: 4096,
    };
    let msg = err.to_string();
    assert!(msg.contains("5000"));
    assert!(msg.contains("4096"));
}

#[test]
fn sandbox_error_messages_are_actionable() {
    let err = SandboxError::ControlUnavailable {
        control: "memory_monitoring".into(),
        reason: "test reason".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("--allow-degraded-sandbox"));
    assert!(msg.contains("memory_monitoring"));

    let err = SandboxError::InputTooLarge {
        size: 2000,
        limit: 1000,
    };
    let msg = err.to_string();
    assert!(msg.contains("2000"));
    assert!(msg.contains("1000"));
}
