use std::fmt::Write;

/// Generate the `TraceRecorder` trait and `NoopRecorder` implementation
/// as Rust source code to be included in generated skeleton output.
pub fn generate_trace_recorder_trait() -> String {
    let mut out = String::new();

    writeln!(out, "/// Trait for recording protocol execution traces.").unwrap();
    writeln!(out, "///").unwrap();
    writeln!(
        out,
        "/// Implement this trait to capture runtime traces for conformance checking"
    )
    .unwrap();
    writeln!(
        out,
        "/// against the verified model. Use `NoopRecorder` in production."
    )
    .unwrap();
    writeln!(out, "pub trait TraceRecorder {{").unwrap();
    writeln!(
        out,
        "    fn record_init(&mut self, process_id: u64, location: &str);"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_transition(&mut self, process_id: u64, from: &str, to: &str);"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_send(&mut self, process_id: u64, msg_type: &str, fields: &[(&str, &str)]);"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_receive(&mut self, process_id: u64, msg_type: &str, from: u64, fields: &[(&str, &str)]);"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_decide(&mut self, process_id: u64, value: &str);"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_var_update(&mut self, process_id: u64, var: &str, value: &str);"
    )
    .unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "/// No-op recorder for production use (zero overhead)."
    )
    .unwrap();
    writeln!(out, "pub struct NoopRecorder;").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "impl TraceRecorder for NoopRecorder {{").unwrap();
    writeln!(
        out,
        "    fn record_init(&mut self, _process_id: u64, _location: &str) {{}}"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_transition(&mut self, _process_id: u64, _from: &str, _to: &str) {{}}"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_send(&mut self, _process_id: u64, _msg_type: &str, _fields: &[(&str, &str)]) {{}}"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_receive(&mut self, _process_id: u64, _msg_type: &str, _from: u64, _fields: &[(&str, &str)]) {{}}"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_decide(&mut self, _process_id: u64, _value: &str) {{}}"
    )
    .unwrap();
    writeln!(
        out,
        "    fn record_var_update(&mut self, _process_id: u64, _var: &str, _value: &str) {{}}"
    )
    .unwrap();
    writeln!(out, "}}").unwrap();

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_recorder_trait_in_generated_code() {
        let code = generate_trace_recorder_trait();
        assert!(code.contains("pub trait TraceRecorder"));
        assert!(code.contains("fn record_init"));
        assert!(code.contains("fn record_transition"));
        assert!(code.contains("fn record_send"));
        assert!(code.contains("fn record_receive"));
        assert!(code.contains("fn record_decide"));
        assert!(code.contains("fn record_var_update"));
    }

    #[test]
    fn test_noop_recorder_compiles() {
        let code = generate_trace_recorder_trait();
        assert!(code.contains("pub struct NoopRecorder"));
        assert!(code.contains("impl TraceRecorder for NoopRecorder"));
        // All methods should have no-op implementations
        assert!(code.contains("_process_id"));
    }
}
