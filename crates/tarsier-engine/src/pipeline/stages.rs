//! Trait-based pipeline stages for composable, testable execution flows.

use super::{
    abstract_to_cs, lower, parse, CounterSystem, PipelineError, ThresholdAutomaton,
};
use tarsier_dsl::ast;

/// Single pipeline stage that transforms `Input` into `Output`.
pub trait PipelineStage<Input> {
    type Output;

    /// Stable stage label for diagnostics/testing.
    fn name(&self) -> &'static str;

    /// Execute this stage.
    fn run(&self, input: Input) -> Result<Self::Output, PipelineError>;
}

/// Composition of two stages where the first output feeds the second input.
#[derive(Debug, Clone)]
pub struct ComposedStage<First, Second> {
    first: First,
    second: Second,
}

impl<Input, Mid, Out, First, Second> PipelineStage<Input> for ComposedStage<First, Second>
where
    First: PipelineStage<Input, Output = Mid>,
    Second: PipelineStage<Mid, Output = Out>,
{
    type Output = Out;

    fn name(&self) -> &'static str {
        "composed"
    }

    fn run(&self, input: Input) -> Result<Self::Output, PipelineError> {
        let mid = self.first.run(input)?;
        self.second.run(mid)
    }
}

/// Extension trait for fluent stage composition.
pub trait PipelineStageExt<Input>: PipelineStage<Input> + Sized {
    fn then<Next>(self, next: Next) -> ComposedStage<Self, Next>
    where
        Next: PipelineStage<Self::Output>,
    {
        ComposedStage {
            first: self,
            second: next,
        }
    }
}

impl<Input, Stage> PipelineStageExt<Input> for Stage where Stage: PipelineStage<Input> {}

/// Parse stage input.
#[derive(Debug, Clone, Copy)]
pub struct ParseInput<'a> {
    pub source: &'a str,
    pub filename: &'a str,
}

/// Stage wrapper for [`parse`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ParseStage;

impl<'a> PipelineStage<ParseInput<'a>> for ParseStage {
    type Output = ast::Program;

    fn name(&self) -> &'static str {
        "parse"
    }

    fn run(&self, input: ParseInput<'a>) -> Result<Self::Output, PipelineError> {
        parse(input.source, input.filename)
    }
}

/// Stage wrapper for [`lower`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LowerStage;

impl PipelineStage<ast::Program> for LowerStage {
    type Output = ThresholdAutomaton;

    fn name(&self) -> &'static str {
        "lower"
    }

    fn run(&self, input: ast::Program) -> Result<Self::Output, PipelineError> {
        lower(&input)
    }
}

/// Stage wrapper for [`abstract_to_cs`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AbstractStage;

impl PipelineStage<ThresholdAutomaton> for AbstractStage {
    type Output = CounterSystem;

    fn name(&self) -> &'static str {
        "abstract_to_cs"
    }

    fn run(&self, input: ThresholdAutomaton) -> Result<Self::Output, PipelineError> {
        Ok(abstract_to_cs(input))
    }
}

/// Canonical parse -> lower -> abstract stage pipeline.
pub fn parse_lower_abstract(source: &str, filename: &str) -> Result<CounterSystem, PipelineError> {
    ParseStage
        .then(LowerStage)
        .then(AbstractStage)
        .run(ParseInput { source, filename })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::PipelineError;
    use std::cell::Cell;

    #[derive(Debug, Clone, Copy)]
    struct AddOneStage;

    impl PipelineStage<i64> for AddOneStage {
        type Output = i64;

        fn name(&self) -> &'static str {
            "add_one"
        }

        fn run(&self, input: i64) -> Result<Self::Output, PipelineError> {
            Ok(input + 1)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct TimesTwoStage;

    impl PipelineStage<i64> for TimesTwoStage {
        type Output = i64;

        fn name(&self) -> &'static str {
            "times_two"
        }

        fn run(&self, input: i64) -> Result<Self::Output, PipelineError> {
            Ok(input * 2)
        }
    }

    struct FailingStage;

    impl PipelineStage<i64> for FailingStage {
        type Output = i64;

        fn name(&self) -> &'static str {
            "failing"
        }

        fn run(&self, _input: i64) -> Result<Self::Output, PipelineError> {
            Err(PipelineError::Property("synthetic failure".into()))
        }
    }

    struct ProbeStage<'a> {
        called: &'a Cell<bool>,
    }

    impl PipelineStage<i64> for ProbeStage<'_> {
        type Output = i64;

        fn name(&self) -> &'static str {
            "probe"
        }

        fn run(&self, input: i64) -> Result<Self::Output, PipelineError> {
            self.called.set(true);
            Ok(input)
        }
    }

    #[test]
    fn composed_stage_transforms_values_in_sequence() {
        let pipeline = AddOneStage.then(TimesTwoStage);
        let out = pipeline.run(10).expect("composition should succeed");
        assert_eq!(out, 22);
    }

    #[test]
    fn composed_stage_short_circuits_on_error() {
        let called = Cell::new(false);
        let pipeline = FailingStage.then(ProbeStage { called: &called });
        let err = pipeline.run(10).expect_err("pipeline should fail");
        assert!(matches!(err, PipelineError::Property(_)));
        assert!(
            !called.get(),
            "second stage must not run after first-stage failure"
        );
    }

    #[test]
    fn parse_lower_abstract_builds_counter_system() {
        let src = r#"
protocol Tiny {
    params n, t;
    resilience: n > 3*t;
    message Vote;
    role Replica {
        init start;
        phase start {}
    }
}
"#;
        let cs = parse_lower_abstract(src, "tiny.trs").expect("pipeline should succeed");
        assert_eq!(cs.num_locations(), 1);
        assert_eq!(cs.num_shared_vars(), 1);
        assert_eq!(cs.num_rules(), 0);
    }
}

