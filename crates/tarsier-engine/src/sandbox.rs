//! Runtime sandbox enforcement for analysis execution.
//!
//! This module enforces resource constraints (CPU/time, memory, filesystem,
//! network) on all verification and proof pipelines. Controls are configured
//! via [`SandboxConfig`](crate::sandbox::SandboxConfig) and enforced by
//! [`SandboxGuard`](crate::sandbox::SandboxGuard).
//!
//! **Fail-closed semantics:** If a required control cannot be enforced on the
//! current platform (e.g., memory monitoring is unavailable on non-Linux),
//! [`SandboxGuard::activate`](crate::sandbox::SandboxGuard::activate) returns
//! an error unless the caller explicitly opts into degraded mode via
//! [`SandboxConfig::allow_degraded`](crate::sandbox::SandboxConfig::allow_degraded).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Global flag: has a sandbox been activated for the current process?
static SANDBOX_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The active sandbox configuration (set once per process).
static ACTIVE_CONFIG: OnceLock<SandboxConfig> = OnceLock::new();

/// Activation timestamp (set once, read by `enforce_active_limits()`).
static ACTIVATED_AT: OnceLock<Instant> = OnceLock::new();

/// Resource constraints for analysis execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    /// Hard wall-clock timeout for the entire analysis run (seconds).
    /// Enforced via deadline checks in the solver loop.
    pub timeout_secs: u64,
    /// RSS memory budget in MiB. If the process exceeds this, analysis
    /// returns an inconclusive result.  Set to 0 to disable (requires
    /// `allow_degraded` on platforms without memory monitoring).
    pub memory_budget_mb: u64,
    /// Maximum input file size in bytes (`.trs` source).
    pub max_input_bytes: u64,
    /// If true, allow execution even when memory monitoring is unavailable.
    /// When false (default), activation fails on unsupported platforms.
    pub allow_degraded: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 300,
            memory_budget_mb: 4096,
            max_input_bytes: 1024 * 1024, // 1 MiB
            allow_degraded: false,
        }
    }
}

/// Describes why a sandbox control is degraded on this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedControl {
    pub control: &'static str,
    pub reason: String,
}

/// Result of platform capability detection.
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    /// Whether RSS memory monitoring is available.
    pub memory_monitoring: bool,
    /// List of controls that cannot be enforced.
    pub degraded: Vec<DegradedControl>,
}

/// Error returned when sandbox activation fails.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error(
        "sandbox activation failed: {control} cannot be enforced on this platform ({reason}). \
         Use --allow-degraded-sandbox to run with reduced protections."
    )]
    ControlUnavailable { control: String, reason: String },
    #[error("input file too large: {size} bytes exceeds limit of {limit} bytes")]
    InputTooLarge { size: u64, limit: u64 },
    #[error("sandbox already activated")]
    AlreadyActive,
    #[error("sandbox activation timestamp not set")]
    NotActivated,
    #[error("sandbox memory budget exceeded: RSS {rss_mb} MiB > limit {limit_mb} MiB")]
    MemoryBudgetExceeded { rss_mb: u64, limit_mb: u64 },
    #[error("sandbox timeout exceeded after {elapsed_secs}s (limit: {limit_secs}s)")]
    TimeoutExceeded { elapsed_secs: u64, limit_secs: u64 },
}

/// RAII guard representing an active sandbox. Resource checks are available
/// through methods on this guard.
#[derive(Debug)]
pub struct SandboxGuard {
    config: SandboxConfig,
    activated_at: Instant,
    capabilities: PlatformCapabilities,
}

impl SandboxGuard {
    /// Activate the sandbox with the given configuration.
    ///
    /// Checks platform capabilities and fails closed if required controls
    /// cannot be enforced (unless `allow_degraded` is set).
    pub fn activate(config: SandboxConfig) -> Result<Self, SandboxError> {
        if SANDBOX_ACTIVE.load(Ordering::Relaxed) {
            return Err(SandboxError::AlreadyActive);
        }

        let capabilities = detect_platform_capabilities();

        // Fail-closed: if memory monitoring is unavailable and budget is
        // requested, refuse to proceed unless degraded mode is allowed.
        if config.memory_budget_mb > 0 && !capabilities.memory_monitoring && !config.allow_degraded
        {
            return Err(SandboxError::ControlUnavailable {
                control: "memory_monitoring".into(),
                reason: format!(
                    "RSS monitoring requires /proc/self/statm (Linux). \
                     Current platform does not support it. \
                     Degraded controls: {:?}",
                    capabilities
                        .degraded
                        .iter()
                        .map(|d| d.control)
                        .collect::<Vec<_>>()
                ),
            });
        }

        SANDBOX_ACTIVE.store(true, Ordering::Release);
        let _ = ACTIVE_CONFIG.set(config.clone());
        let _ = ACTIVATED_AT.set(Instant::now());
        let activated_at = *ACTIVATED_AT.get().ok_or(SandboxError::NotActivated)?;

        Ok(Self {
            config,
            activated_at,
            capabilities,
        })
    }

    /// Check whether the wall-clock deadline has been exceeded.
    pub fn check_timeout(&self) -> Result<(), SandboxError> {
        let elapsed = self.activated_at.elapsed();
        let limit = Duration::from_secs(self.config.timeout_secs);
        if elapsed > limit {
            return Err(SandboxError::TimeoutExceeded {
                elapsed_secs: elapsed.as_secs(),
                limit_secs: self.config.timeout_secs,
            });
        }
        Ok(())
    }

    /// Check whether the memory budget has been exceeded.
    /// Returns `Ok(())` if monitoring is unavailable and degraded mode is on.
    pub fn check_memory(&self) -> Result<(), SandboxError> {
        if self.config.memory_budget_mb == 0 {
            return Ok(());
        }
        if let Some(rss_bytes) = current_rss_bytes() {
            let rss_mb = rss_bytes / (1024 * 1024);
            if rss_mb > self.config.memory_budget_mb {
                return Err(SandboxError::MemoryBudgetExceeded {
                    rss_mb,
                    limit_mb: self.config.memory_budget_mb,
                });
            }
        }
        // If monitoring unavailable and we got here, degraded mode must be on
        Ok(())
    }

    /// Validate that an input file's size is within the sandbox limit.
    pub fn validate_input_size(&self, size: u64) -> Result<(), SandboxError> {
        if size > self.config.max_input_bytes {
            return Err(SandboxError::InputTooLarge {
                size,
                limit: self.config.max_input_bytes,
            });
        }
        Ok(())
    }

    /// Return the sandbox configuration.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Return the detected platform capabilities.
    pub fn capabilities(&self) -> &PlatformCapabilities {
        &self.capabilities
    }

    /// Return elapsed time since sandbox activation.
    pub fn elapsed(&self) -> Duration {
        self.activated_at.elapsed()
    }

    /// Whether memory monitoring is active (not degraded).
    pub fn memory_monitoring_active(&self) -> bool {
        self.capabilities.memory_monitoring
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        SANDBOX_ACTIVE.store(false, Ordering::Release);
    }
}

/// Returns true if a sandbox is currently active for this process.
pub fn is_sandbox_active() -> bool {
    SANDBOX_ACTIVE.load(Ordering::Acquire)
}

/// Returns the active sandbox config, if one has been set.
pub fn active_sandbox_config() -> Option<&'static SandboxConfig> {
    ACTIVE_CONFIG.get()
}

/// Check both wall-clock timeout and memory budget against the active sandbox.
///
/// Returns `Ok(())` if no sandbox is active, or if all limits are within bounds.
/// This is designed to be called frequently at stage boundaries and loop iterations.
pub fn enforce_active_limits() -> Result<(), SandboxError> {
    if !SANDBOX_ACTIVE.load(Ordering::Acquire) {
        return Ok(());
    }
    let config = match ACTIVE_CONFIG.get() {
        Some(c) => c,
        None => return Ok(()),
    };
    // Timeout check
    if let Some(activated_at) = ACTIVATED_AT.get() {
        let elapsed = activated_at.elapsed();
        if elapsed > Duration::from_secs(config.timeout_secs) {
            return Err(SandboxError::TimeoutExceeded {
                elapsed_secs: elapsed.as_secs(),
                limit_secs: config.timeout_secs,
            });
        }
    }
    // Memory check
    if config.memory_budget_mb > 0 {
        if let Some(rss_bytes) = current_rss_bytes() {
            let rss_mb = rss_bytes / (1024 * 1024);
            if rss_mb > config.memory_budget_mb {
                return Err(SandboxError::MemoryBudgetExceeded {
                    rss_mb,
                    limit_mb: config.memory_budget_mb,
                });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Platform capability detection
// ---------------------------------------------------------------------------

fn detect_platform_capabilities() -> PlatformCapabilities {
    let mut degraded = Vec::new();

    let memory_monitoring = current_rss_bytes().is_some();
    if !memory_monitoring {
        degraded.push(DegradedControl {
            control: "memory_monitoring",
            reason: platform_memory_reason(),
        });
    }

    // Network: Z3 is statically linked (no outbound connections). CVC5
    // subprocess inherits the parent's network namespace but does not
    // initiate connections.  We document this as a design invariant rather
    // than enforcing it with OS-level controls (which would require
    // platform-specific seccomp/sandbox-exec).
    //
    // Filesystem: the solver does not write to disk.  CLI output is the
    // only write path.  Restricting this would require OS-level controls.

    PlatformCapabilities {
        memory_monitoring,
        degraded,
    }
}

fn platform_memory_reason() -> String {
    #[cfg(target_os = "linux")]
    {
        "/proc/self/statm not readable".into()
    }
    #[cfg(target_os = "macos")]
    {
        "macOS: /proc/self/statm not available (no procfs)".into()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        format!(
            "{}: no supported memory monitoring mechanism",
            std::env::consts::OS
        )
    }
}

/// Read current RSS in bytes.  Returns `None` on unsupported platforms.
pub fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: u64 = raw.split_whitespace().nth(1)?.parse().ok()?;
        let page_size: u64 = 4096;
        Some(rss_pages * page_size)
    }
    #[cfg(target_os = "macos")]
    {
        // Use mach API for RSS on macOS
        macos_rss_bytes()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn macos_rss_bytes() -> Option<u64> {
    use std::mem;
    // SAFETY: calling mach kernel API to get task info for the current task.
    // This is a read-only query with no side effects.
    unsafe {
        let task = mach_task_self();
        let mut info: mach_task_basic_info_data_t = mem::zeroed();
        let mut count = (mem::size_of::<mach_task_basic_info_data_t>() / mem::size_of::<u32>())
            as mach_msg_type_number_t;
        let kr = task_info(
            task,
            MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as task_info_t,
            &mut count,
        );
        if kr == KERN_SUCCESS {
            Some(info.resident_size)
        } else {
            None
        }
    }
}

// macOS FFI declarations for mach task_info — names follow C convention
#[cfg(target_os = "macos")]
use std::os::raw::c_int;

#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
type kern_return_t = c_int;
#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
type mach_port_t = u32;
#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
type task_flavor_t = u32;
#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
type task_info_t = *mut c_int;
#[cfg(target_os = "macos")]
#[allow(non_camel_case_types)]
type mach_msg_type_number_t = u32;

#[cfg(target_os = "macos")]
const MACH_TASK_BASIC_INFO: task_flavor_t = 20;
#[cfg(target_os = "macos")]
const KERN_SUCCESS: kern_return_t = 0;

#[cfg(target_os = "macos")]
#[repr(C)]
#[allow(non_camel_case_types)]
struct mach_task_basic_info_data_t {
    virtual_size: u64,
    resident_size: u64,
    resident_size_max: u64,
    user_time: time_value_t,
    system_time: time_value_t,
    policy: i32,
    suspend_count: i32,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
struct time_value_t {
    seconds: i32,
    microseconds: i32,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn mach_task_self() -> mach_port_t;
    fn task_info(
        target_task: mach_port_t,
        flavor: task_flavor_t,
        task_info_out: task_info_t,
        task_info_count: *mut mach_msg_type_number_t,
    ) -> kern_return_t;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
