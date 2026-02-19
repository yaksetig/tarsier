use std::collections::HashSet;
use tarsier_dsl::ast::{CmpOp, Expr, LinearExpr, VarType};

use crate::CodegenTarget;

/// Convert a name to PascalCase (e.g., "my_role" -> "MyRole", "pre_prepare" -> "PrePrepare").
pub fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(c) => {
                    let mut result = c.to_uppercase().to_string();
                    result.extend(chars);
                    result
                }
                None => String::new(),
            }
        })
        .collect()
}

/// Convert a name to snake_case (e.g., "MyRole" -> "my_role", "PrePrepare" -> "pre_prepare").
pub fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.extend(c.to_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

/// Map a DSL variable type to its Rust type string.
pub fn rust_type(ty: &VarType) -> &'static str {
    match ty {
        VarType::Bool => "bool",
        VarType::Nat => "u64",
        VarType::Int => "i64",
        VarType::Enum(_) => "u64", // enums represented as u64 in generated code
    }
}

/// Map a DSL variable type to its Go type string.
pub fn go_type(ty: &VarType) -> &'static str {
    match ty {
        VarType::Bool => "bool",
        VarType::Nat => "uint64",
        VarType::Int => "int64",
        VarType::Enum(_) => "uint64",
    }
}

/// Render a LinearExpr to a code string.
/// Parameter names are looked up via `params` set and prefixed with the appropriate accessor.
pub fn render_linear_expr(
    expr: &LinearExpr,
    params: &HashSet<String>,
    target: CodegenTarget,
) -> String {
    match expr {
        LinearExpr::Const(c) => c.to_string(),
        LinearExpr::Var(v) => var_accessor(v, params, target),
        LinearExpr::Add(l, r) => {
            let left = render_linear_expr(l, params, target);
            let right = render_linear_expr(r, params, target);
            format!("({left} + {right})")
        }
        LinearExpr::Sub(l, r) => {
            let left = render_linear_expr(l, params, target);
            let right = render_linear_expr(r, params, target);
            format!("({left} - {right})")
        }
        LinearExpr::Mul(c, e) => {
            let inner = render_linear_expr(e, params, target);
            format!("({c} * {inner})")
        }
    }
}

/// Render a general Expr to a code string.
pub fn render_expr(expr: &Expr, params: &HashSet<String>, target: CodegenTarget) -> String {
    match expr {
        Expr::IntLit(n) => n.to_string(),
        Expr::BoolLit(b) => b.to_string(),
        Expr::Var(v) => var_accessor(v, params, target),
        Expr::Add(l, r) => {
            let left = render_expr(l, params, target);
            let right = render_expr(r, params, target);
            format!("({left} + {right})")
        }
        Expr::Sub(l, r) => {
            let left = render_expr(l, params, target);
            let right = render_expr(r, params, target);
            format!("({left} - {right})")
        }
        Expr::Mul(l, r) => {
            let left = render_expr(l, params, target);
            let right = render_expr(r, params, target);
            format!("({left} * {right})")
        }
        Expr::Div(l, r) => {
            let left = render_expr(l, params, target);
            let right = render_expr(r, params, target);
            format!("({left} / {right})")
        }
        Expr::Not(e) => {
            let inner = render_expr(e, params, target);
            format!("!{inner}")
        }
        Expr::Neg(e) => {
            let inner = render_expr(e, params, target);
            match target {
                CodegenTarget::Rust => format!("(-({inner} as i64) as u64)"),
                CodegenTarget::Go => format!("(-int64({inner})"),
            }
        }
    }
}

/// Render a CmpOp to its code string (same for both Rust and Go).
pub fn render_cmp_op(op: &CmpOp) -> &'static str {
    match op {
        CmpOp::Ge => ">=",
        CmpOp::Le => "<=",
        CmpOp::Gt => ">",
        CmpOp::Lt => "<",
        CmpOp::Eq => "==",
        CmpOp::Ne => "!=",
    }
}

/// Produce a variable accessor string, distinguishing parameters from local state vars.
fn var_accessor(name: &str, params: &HashSet<String>, target: CodegenTarget) -> String {
    if params.contains(name) {
        match target {
            CodegenTarget::Rust => format!("config.{name}"),
            CodegenTarget::Go => format!("config.{}", to_pascal_case(name)),
        }
    } else {
        match target {
            CodegenTarget::Rust => format!("self.{name}"),
            CodegenTarget::Go => format!("s.{}", to_pascal_case(name)),
        }
    }
}

/// Collect parameter names from the protocol into a HashSet.
pub fn collect_param_names(params: &[tarsier_dsl::ast::ParamDef]) -> HashSet<String> {
    params.iter().map(|p| p.name.clone()).collect()
}

/// Check if any role in the protocol uses distinct-sender guards.
pub fn uses_distinct_guards(protocol: &tarsier_dsl::ast::ProtocolDecl) -> bool {
    use tarsier_dsl::ast::GuardExpr;
    fn check(guard: &GuardExpr) -> bool {
        match guard {
            GuardExpr::Threshold(tg) => tg.distinct,
            GuardExpr::And(a, b) | GuardExpr::Or(a, b) => check(a) || check(b),
            _ => false,
        }
    }
    protocol.roles.iter().any(|role| {
        role.node
            .phases
            .iter()
            .any(|phase| phase.node.transitions.iter().any(|t| check(&t.node.guard)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("hello"), "Hello");
        assert_eq!(to_pascal_case("hello_world"), "HelloWorld");
        assert_eq!(to_pascal_case("pre_prepare"), "PrePrepare");
        assert_eq!(to_pascal_case("a"), "A");
        assert_eq!(to_pascal_case("ABC"), "ABC");
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("Hello"), "hello");
        assert_eq!(to_snake_case("HelloWorld"), "hello_world");
        assert_eq!(to_snake_case("PrePrepare"), "pre_prepare");
        assert_eq!(to_snake_case("abc"), "abc");
    }

    #[test]
    fn test_rust_type_mapping() {
        assert_eq!(rust_type(&VarType::Bool), "bool");
        assert_eq!(rust_type(&VarType::Nat), "u64");
        assert_eq!(rust_type(&VarType::Int), "i64");
    }

    #[test]
    fn test_go_type_mapping() {
        assert_eq!(go_type(&VarType::Bool), "bool");
        assert_eq!(go_type(&VarType::Nat), "uint64");
        assert_eq!(go_type(&VarType::Int), "int64");
    }

    #[test]
    fn test_render_linear_expr() {
        let params: HashSet<String> = ["n", "t", "f"].iter().map(|s| s.to_string()).collect();

        // 2*t+1
        let expr = LinearExpr::Add(
            Box::new(LinearExpr::Mul(2, Box::new(LinearExpr::Var("t".into())))),
            Box::new(LinearExpr::Const(1)),
        );
        let result = render_linear_expr(&expr, &params, CodegenTarget::Rust);
        assert_eq!(result, "((2 * config.t) + 1)");
    }

    #[test]
    fn test_render_expr_with_params_and_locals() {
        let params: HashSet<String> = ["n"].iter().map(|s| s.to_string()).collect();

        let expr = Expr::Var("n".into());
        assert_eq!(render_expr(&expr, &params, CodegenTarget::Rust), "config.n");

        let expr = Expr::Var("decided".into());
        assert_eq!(
            render_expr(&expr, &params, CodegenTarget::Rust),
            "self.decided"
        );
    }

    #[test]
    fn test_render_cmp_op() {
        assert_eq!(render_cmp_op(&CmpOp::Ge), ">=");
        assert_eq!(render_cmp_op(&CmpOp::Eq), "==");
        assert_eq!(render_cmp_op(&CmpOp::Ne), "!=");
    }
}
