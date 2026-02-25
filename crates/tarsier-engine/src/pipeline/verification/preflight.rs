//\! Guard analysis, protocol queries, preflight validation.

use std::collections::HashSet;

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipelineCommand {
    Verify,
    VerifyAllProperties,
    Liveness,
}

pub(crate) fn guard_uses_threshold(guard: &ast::GuardExpr) -> bool {
    match guard {
        ast::GuardExpr::Threshold(_) => true,
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            guard_uses_threshold(lhs) || guard_uses_threshold(rhs)
        }
        _ => false,
    }
}

pub(crate) fn guard_uses_distinct_threshold(guard: &ast::GuardExpr) -> bool {
    match guard {
        ast::GuardExpr::Threshold(tg) => tg.distinct,
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            guard_uses_distinct_threshold(lhs) || guard_uses_distinct_threshold(rhs)
        }
        _ => false,
    }
}

pub(crate) fn collect_distinct_roles_from_guard(guard: &ast::GuardExpr, out: &mut HashSet<String>) {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            if tg.distinct {
                if let Some(role) = &tg.distinct_role {
                    out.insert(role.clone());
                }
            }
        }
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            collect_distinct_roles_from_guard(lhs, out);
            collect_distinct_roles_from_guard(rhs, out);
        }
        _ => {}
    }
}

pub(crate) fn collect_distinct_messages_from_guard(
    guard: &ast::GuardExpr,
    out: &mut HashSet<String>,
) {
    match guard {
        ast::GuardExpr::Threshold(tg) => {
            if tg.distinct {
                out.insert(tg.message_type.clone());
            }
        }
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            collect_distinct_messages_from_guard(lhs, out);
            collect_distinct_messages_from_guard(rhs, out);
        }
        _ => {}
    }
}

pub(crate) fn guard_has_non_monotone_threshold(guard: &ast::GuardExpr) -> bool {
    match guard {
        ast::GuardExpr::Threshold(tg) => !matches!(tg.op, ast::CmpOp::Ge | ast::CmpOp::Gt),
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            guard_has_non_monotone_threshold(lhs) || guard_has_non_monotone_threshold(rhs)
        }
        _ => false,
    }
}

pub(crate) fn protocol_uses_thresholds(program: &ast::Program) -> bool {
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase
                .node
                .transitions
                .iter()
                .any(|tr| guard_uses_threshold(&tr.node.guard))
        })
    })
}

pub(crate) fn protocol_uses_distinct_thresholds(program: &ast::Program) -> bool {
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase
                .node
                .transitions
                .iter()
                .any(|tr| guard_uses_distinct_threshold(&tr.node.guard))
        })
    })
}

pub(crate) fn protocol_distinct_roles(program: &ast::Program) -> HashSet<String> {
    let mut roles = HashSet::new();
    for role in &program.protocol.node.roles {
        for phase in &role.node.phases {
            for tr in &phase.node.transitions {
                collect_distinct_roles_from_guard(&tr.node.guard, &mut roles);
            }
        }
    }
    roles
}

pub(crate) fn protocol_distinct_messages(program: &ast::Program) -> HashSet<String> {
    let mut messages = HashSet::new();
    for role in &program.protocol.node.roles {
        for phase in &role.node.phases {
            for tr in &phase.node.transitions {
                collect_distinct_messages_from_guard(&tr.node.guard, &mut messages);
            }
        }
    }
    messages
}

pub(crate) fn protocol_crypto_objects_referenced(program: &ast::Program) -> HashSet<String> {
    let mut referenced = HashSet::new();
    for role in &program.protocol.node.roles {
        for phase in &role.node.phases {
            for tr in &phase.node.transitions {
                // Collect from actions
                for action in &tr.node.actions {
                    match action {
                        ast::Action::FormCryptoObject { object_name, .. }
                        | ast::Action::LockCryptoObject { object_name, .. }
                        | ast::Action::JustifyCryptoObject { object_name, .. } => {
                            referenced.insert(object_name.clone());
                        }
                        _ => {}
                    }
                }
                // Collect from guard
                collect_crypto_objects_from_guard(&tr.node.guard, &mut referenced);
            }
        }
    }
    referenced
}

pub(crate) fn collect_crypto_objects_from_guard(guard: &ast::GuardExpr, out: &mut HashSet<String>) {
    match guard {
        ast::GuardExpr::HasCryptoObject { object_name, .. } => {
            out.insert(object_name.clone());
        }
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            collect_crypto_objects_from_guard(lhs, out);
            collect_crypto_objects_from_guard(rhs, out);
        }
        _ => {}
    }
}

pub(crate) fn guard_has_crypto_check(guard: &ast::GuardExpr, target: &str) -> bool {
    match guard {
        ast::GuardExpr::HasCryptoObject { object_name, .. } => object_name == target,
        ast::GuardExpr::And(lhs, rhs) | ast::GuardExpr::Or(lhs, rhs) => {
            guard_has_crypto_check(lhs, target) || guard_has_crypto_check(rhs, target)
        }
        _ => false,
    }
}

pub(crate) fn effective_message_authenticated(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_auth: &str,
) -> bool {
    if let Some(ch) = proto.channels.iter().find(|c| c.message == msg) {
        return matches!(ch.auth, ast::ChannelAuthMode::Authenticated);
    }
    global_auth == "signed"
}

pub(crate) fn effective_message_non_equivocating(
    proto: &ast::ProtocolDecl,
    msg: &str,
    global_equivocation: &str,
) -> bool {
    if let Some(eq) = proto
        .equivocation_policies
        .iter()
        .find(|e| e.message == msg)
    {
        return matches!(eq.mode, ast::EquivocationPolicyMode::None);
    }
    global_equivocation == "none"
}

pub(crate) fn protocol_has_non_monotone_thresholds(program: &ast::Program) -> bool {
    program.protocol.node.roles.iter().any(|role| {
        role.node.phases.iter().any(|phase| {
            phase
                .node
                .transitions
                .iter()
                .any(|tr| guard_has_non_monotone_threshold(&tr.node.guard))
        })
    })
}

pub(crate) fn strict_preflight_validate(
    program: &ast::Program,
    command: PipelineCommand,
) -> Result<(), PipelineError> {
    let proto = &program.protocol.node;
    let mut issues: Vec<String> = Vec::new();

    let has_n = proto.parameters.iter().any(|p| p.name == "n");
    let has_t = proto.parameters.iter().any(|p| p.name == "t");
    if !has_n {
        issues.push("Missing required parameter `n`.".into());
    }
    if !has_t {
        issues.push("Missing required parameter `t`.".into());
    }
    if proto.resilience.is_none() {
        issues.push("Missing resilience declaration.".into());
    }

    for role in &proto.roles {
        for v in &role.node.vars {
            if matches!(v.ty, ast::VarType::Nat | ast::VarType::Int) && v.range.is_none() {
                issues.push(format!(
                    "Unbounded local variable '{}.{}' is not allowed in strict mode; add `in a..b`.",
                    role.node.name, v.name
                ));
            }
        }
    }

    let uses_thresholds = protocol_uses_thresholds(program);
    let uses_distinct_thresholds = protocol_uses_distinct_thresholds(program);
    let mut has_adv_model = false;
    let mut has_adv_bound = false;
    let mut timing_partial = false;
    let mut has_gst = false;
    let mut auth_mode = "none";
    let mut has_auth_field = false;
    let mut adv_model: Option<String> = None;
    let mut equivocation_mode: Option<String> = None;
    let mut network_mode = "classic";
    for item in &proto.adversary {
        if item.key == "model"
            && (item.value == "byzantine" || item.value == "crash" || item.value == "omission")
        {
            has_adv_model = true;
            adv_model = Some(item.value.clone());
        }
        if item.key == "bound" {
            has_adv_bound = true;
        }
        if item.key == "timing"
            && (item.value == "partial_synchrony" || item.value == "partial_sync")
        {
            timing_partial = true;
        }
        if item.key == "gst" {
            has_gst = true;
        }
        if item.key == "equivocation" {
            equivocation_mode = Some(item.value.clone());
        }
        if item.key == "auth" || item.key == "authentication" {
            auth_mode = item.value.as_str();
            has_auth_field = true;
        }
        if item.key == "network" || item.key == "network_semantics" {
            network_mode = item.value.as_str();
        }
    }

    if uses_thresholds && !has_adv_model {
        issues.push(
            "Threshold protocols in strict mode require `adversary { model: byzantine|crash|omission; ... }`."
                .into(),
        );
    }
    if (uses_thresholds || has_adv_model) && !has_adv_bound {
        issues.push(
            "Strict mode requires `adversary { bound: <param>; }` when faults are modeled.".into(),
        );
    }

    let faithful_network = matches!(
        network_mode,
        "identity_selective" | "cohort_selective" | "process_selective"
    );
    if faithful_network {
        let role_names: HashSet<String> = proto.roles.iter().map(|r| r.node.name.clone()).collect();
        let identity_roles: HashSet<String> =
            proto.identities.iter().map(|id| id.role.clone()).collect();
        let mut missing_identity_roles: Vec<String> =
            role_names.difference(&identity_roles).cloned().collect();
        missing_identity_roles.sort();
        if !missing_identity_roles.is_empty() {
            issues.push(format!(
                "Faithful network mode in strict mode requires explicit `identity` declarations \
                 for every role. Missing: {}.",
                missing_identity_roles.join(", ")
            ));
        }
        let mut missing_identity_key_roles: Vec<String> = proto
            .identities
            .iter()
            .filter(|id| id.key.is_none())
            .map(|id| id.role.clone())
            .collect();
        missing_identity_key_roles.sort();
        missing_identity_key_roles.dedup();
        if !missing_identity_key_roles.is_empty() {
            issues.push(format!(
                "Faithful network mode in strict mode requires explicit identity keys. \
                 Add `key <name>` for roles: {}.",
                missing_identity_key_roles.join(", ")
            ));
        }
        if network_mode == "process_selective" {
            let mut non_process_roles: Vec<String> = proto
                .identities
                .iter()
                .filter(|id| id.scope != ast::IdentityScope::Process)
                .map(|id| id.role.clone())
                .collect();
            non_process_roles.sort();
            non_process_roles.dedup();
            if !non_process_roles.is_empty() {
                issues.push(format!(
                    "`network: process_selective` in strict mode requires \
                     `identity <Role>: process(<id-var>)` for every role. Non-process identities: {}.",
                    non_process_roles.join(", ")
                ));
            }

            // 5b: Warn if pid variable has a literal range that may not cover the full population
            for id_decl in &proto.identities {
                if id_decl.scope == ast::IdentityScope::Process {
                    if let Some(ref pid_var_name) = id_decl.process_var {
                        let role_decl = proto.roles.iter().find(|r| r.node.name == id_decl.role);
                        if let Some(role) = role_decl {
                            let var_decl = role.node.vars.iter().find(|v| v.name == *pid_var_name);
                            if let Some(v) = var_decl {
                                if let Some(ref range) = v.range {
                                    // Literal range — check that the parametric population `n` is
                                    // not obviously larger than the pid domain.
                                    let domain_size = (range.max - range.min + 1).max(0);
                                    if domain_size <= 1 {
                                        issues.push(format!(
                                            "`process_selective` pid variable `{}.{}` has literal range \
                                             {}..{} (domain size {domain_size}), which may not cover the \
                                             full population. Consider a parametric pid domain for \
                                             cutoff generality.",
                                            id_decl.role, pid_var_name, range.min, range.max
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let channel_covered: HashSet<String> =
            proto.channels.iter().map(|c| c.message.clone()).collect();
        let mut missing_channel_auth: Vec<String> = proto
            .messages
            .iter()
            .map(|m| m.name.clone())
            .filter(|m| !channel_covered.contains(m))
            .collect();
        missing_channel_auth.sort();
        if !has_auth_field && !missing_channel_auth.is_empty() {
            issues.push(format!(
                "Faithful network mode in strict mode requires explicit authentication semantics. \
                 Add global `adversary {{ auth: signed|none; }}` or message channels for: {}.",
                missing_channel_auth.join(", ")
            ));
        }

        // 3a: Check for declared messages with no send action in faithful mode
        let mut sent_message_types: HashSet<String> = HashSet::new();
        for role in &proto.roles {
            for phase in &role.node.phases {
                for tr in &phase.node.transitions {
                    for action in &tr.node.actions {
                        if let ast::Action::Send { message_type, .. } = action {
                            sent_message_types.insert(message_type.clone());
                        }
                    }
                }
            }
        }
        let mut unsent_messages: Vec<String> = proto
            .messages
            .iter()
            .map(|m| m.name.clone())
            .filter(|m| !sent_message_types.contains(m))
            .collect();
        unsent_messages.sort();
        if !unsent_messages.is_empty() {
            eprintln!(
                "Warning: Faithful network in strict mode: declared messages with no `send` action: {}. \
                 Delivery counters will only increment via adversary injection.",
                unsent_messages.join(", ")
            );
        }

        // 3b: Check for missing equivocation policy in Byzantine faithful mode
        if adv_model.as_deref() == Some("byzantine") {
            let equivocation_policy_covered: HashSet<String> = proto
                .equivocation_policies
                .iter()
                .map(|ep| ep.message.clone())
                .collect();
            let has_global_equivocation = equivocation_mode.is_some();
            if !has_global_equivocation {
                let mut missing_equivocation: Vec<String> = proto
                    .messages
                    .iter()
                    .map(|m| m.name.clone())
                    .filter(|m| !equivocation_policy_covered.contains(m))
                    .collect();
                missing_equivocation.sort();
                if !missing_equivocation.is_empty() {
                    issues.push(format!(
                        "Byzantine faithful network in strict mode requires explicit equivocation policy. \
                         Add `adversary {{ equivocation: full|none; }}` or per-message `equivocation` for: {}.",
                        missing_equivocation.join(", ")
                    ));
                }
            }
        }

        // 3c: Check for missing delivery/fault scope in faithful mode
        let has_delivery_scope = proto.adversary.iter().any(|item| item.key == "delivery");
        let has_faults_scope = proto.adversary.iter().any(|item| item.key == "faults");
        let mut missing_scopes: Vec<&str> = Vec::new();
        if !has_delivery_scope {
            missing_scopes.push("delivery");
        }
        if !has_faults_scope {
            missing_scopes.push("faults");
        }
        if !missing_scopes.is_empty() {
            issues.push(format!(
                "Faithful network in strict mode requires explicit adversary scopes: {}. \
                 Add `adversary {{ delivery: per_recipient|global; faults: per_recipient|global; }}`.",
                missing_scopes.join(", ")
            ));
        }
    }

    if uses_thresholds {
        if timing_partial && !has_gst {
            issues.push(
                "Partial synchrony in strict mode requires `adversary { gst: <param>; }`.".into(),
            );
        }
        if uses_distinct_thresholds {
            let unauthenticated_msgs: Vec<String> = protocol_distinct_messages(program)
                .into_iter()
                .filter(|msg| !effective_message_authenticated(proto, msg, auth_mode))
                .collect();
            if !unauthenticated_msgs.is_empty() {
                issues.push(format!(
                    "Distinct-sender thresholds require authenticated sender identities in strict mode. \
                     Add `adversary {{ auth: signed; }}` or per-message `channel <Msg>: authenticated;` for: {}.",
                    unauthenticated_msgs.join(", ")
                ));
            }
        }
        if uses_distinct_thresholds {
            let role_count = proto.roles.len();
            for role_name in protocol_distinct_roles(program) {
                let param_name = format!("n_{}", role_name.to_lowercase());
                let has_role_population = proto.parameters.iter().any(|p| p.name == param_name);
                if !has_role_population && role_count > 1 {
                    issues.push(format!(
                        "Distinct sender domain role `{role_name}` needs population parameter `{param_name}` in strict mode."
                    ));
                }
            }
        }
        if adv_model.as_deref() == Some("byzantine")
            && equivocation_mode.as_deref().unwrap_or("full") != "none"
            && protocol_has_non_monotone_thresholds(program)
        {
            issues.push(
                "Byzantine full-equivocation in strict mode requires monotone threshold guards (`received ... >=` or `>`). Use monotone guards or set `adversary { equivocation: none; }`."
                    .into(),
            );
        }
    }

    // --- Crypto object strict-mode checks ---

    // Check 1: Orphaned crypto objects (declared but never referenced)
    if !proto.crypto_objects.is_empty() {
        let declared: HashSet<String> = proto
            .crypto_objects
            .iter()
            .map(|c| c.name.clone())
            .collect();
        let referenced = protocol_crypto_objects_referenced(program);
        let mut orphaned: Vec<String> = declared.difference(&referenced).cloned().collect();
        orphaned.sort();
        if !orphaned.is_empty() {
            issues.push(format!(
                "Crypto objects declared but never used in any form/lock/justify/has action: {}.",
                orphaned.join(", ")
            ));
        }
    }

    // Check 2: Exclusive conflict + equivocation soundness
    for co in &proto.crypto_objects {
        if co.conflict_policy == ast::CryptoConflictPolicy::Exclusive {
            let global_eq = equivocation_mode.as_deref().unwrap_or("full");
            if global_eq != "none" {
                issues.push(format!(
                    "Crypto object '{}' declares 'conflicts exclusive' but equivocation policy is not 'none'. \
                     For conflict-exclusion soundness, set 'adversary {{ equivocation: none; }}'.",
                    co.name
                ));
            }
        }
    }

    // Check 3: Unauthenticated crypto source in faithful mode
    if faithful_network {
        for co in &proto.crypto_objects {
            if !effective_message_authenticated(proto, &co.source_message, auth_mode) {
                issues.push(format!(
                    "Crypto object '{}' source message '{}' is unauthenticated in faithful network mode. \
                     Non-forgeability requires authenticated source messages.",
                    co.name, co.source_message
                ));
            }
        }
    }

    // Check 4: Lock/Justify without Has-guard (warning, non-blocking)
    for role in &proto.roles {
        for phase in &role.node.phases {
            for tr in &phase.node.transitions {
                for action in &tr.node.actions {
                    let obj_name = match action {
                        ast::Action::LockCryptoObject { object_name, .. }
                        | ast::Action::JustifyCryptoObject { object_name, .. } => {
                            Some(object_name.as_str())
                        }
                        _ => None,
                    };
                    if let Some(name) = obj_name {
                        if !guard_has_crypto_check(&tr.node.guard, name) {
                            eprintln!(
                                "Warning: Transition in role '{}' phase '{}' uses lock/justify for '{}' \
                                 without explicit 'has {}(...)' guard.",
                                role.node.name, phase.node.name, name, name
                            );
                        }
                    }
                }
            }
        }
    }

    if command == PipelineCommand::Verify {
        let safety_count = proto
            .properties
            .iter()
            .filter(|p| is_safety_property_kind(p.node.kind))
            .count();
        if safety_count != 1 {
            issues.push(
                "Strict mode requires exactly one safety property declaration for `verify`.".into(),
            );
        }
    }

    if !issues.is_empty() {
        return Err(PipelineError::Validation(issues.join(" ")));
    }
    Ok(())
}

pub(crate) fn preflight_validate(
    program: &ast::Program,
    options: &PipelineOptions,
    command: PipelineCommand,
) -> Result<(), PipelineError> {
    if options.soundness == SoundnessMode::Strict {
        strict_preflight_validate(program, command)
    } else {
        Ok(())
    }
}

/// V2-04: Model completeness warning (non-blocking).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CompletenessWarning {
    pub code: String,
    pub message: String,
    pub hint: String,
}

/// V2-04: Run model completeness preflight checks and return warnings (not errors).
pub fn completeness_preflight(program: &ast::Program) -> Vec<CompletenessWarning> {
    let proto = &program.protocol.node;
    let mut warnings = Vec::new();

    // Check: missing identity declarations
    let role_names: std::collections::HashSet<String> =
        proto.roles.iter().map(|r| r.node.name.clone()).collect();
    let identity_roles: std::collections::HashSet<String> =
        proto.identities.iter().map(|id| id.role.clone()).collect();
    let mut missing_identity: Vec<String> =
        role_names.difference(&identity_roles).cloned().collect();
    missing_identity.sort();
    if !missing_identity.is_empty() {
        warnings.push(CompletenessWarning {
            code: "missing_identity".to_string(),
            message: format!(
                "No identity declaration for roles: {}.",
                missing_identity.join(", ")
            ),
            hint: "Add `identity <Role>: process(<id>) key <key>;` for faithful network modeling."
                .to_string(),
        });
    }

    // Check: missing auth semantics
    let has_auth = proto
        .adversary
        .iter()
        .any(|item| item.key == "auth" || item.key == "authentication");
    if !has_auth && !proto.messages.is_empty() {
        warnings.push(CompletenessWarning {
            code: "missing_auth".to_string(),
            message: "No authentication semantics declared.".to_string(),
            hint: "Add `adversary { auth: signed; }` for sender-authenticated modeling."
                .to_string(),
        });
    }

    // Check: missing equivocation policy
    let adv_is_byzantine = proto
        .adversary
        .iter()
        .any(|item| item.key == "model" && item.value == "byzantine");
    let has_equivocation = proto
        .adversary
        .iter()
        .any(|item| item.key == "equivocation");
    if adv_is_byzantine && !has_equivocation && proto.equivocation_policies.is_empty() {
        warnings.push(CompletenessWarning {
            code: "missing_equivocation".to_string(),
            message: "Byzantine model without explicit equivocation policy.".to_string(),
            hint: "Add `adversary { equivocation: full|none; }` to specify equivocation behavior."
                .to_string(),
        });
    }

    // Check: missing fairness declaration
    let has_fairness = proto.adversary.iter().any(|item| item.key == "fairness");
    if !has_fairness {
        warnings.push(CompletenessWarning {
            code: "missing_fairness".to_string(),
            message: "No fairness assumption declared.".to_string(),
            hint: "Liveness checks use weak fairness by default. Add explicit fairness if needed."
                .to_string(),
        });
    }

    // Check: missing GST with partial_synchrony timing
    let timing_partial = proto.adversary.iter().any(|item| {
        item.key == "timing" && (item.value == "partial_synchrony" || item.value == "partial_sync")
    });
    let has_gst = proto.adversary.iter().any(|item| item.key == "gst");
    if timing_partial && !has_gst {
        warnings.push(CompletenessWarning {
            code: "missing_gst".to_string(),
            message: "Partial synchrony declared without GST parameter.".to_string(),
            hint: "Add `adversary { gst: <param>; }` for partial synchrony semantics.".to_string(),
        });
    }

    // Check: missing adversary bound
    let has_adv_bound = proto.adversary.iter().any(|item| item.key == "bound");
    let has_adv_model = proto.adversary.iter().any(|item| {
        item.key == "model"
            && (item.value == "byzantine" || item.value == "crash" || item.value == "omission")
    });
    if has_adv_model && !has_adv_bound {
        warnings.push(CompletenessWarning {
            code: "missing_adversary_bound".to_string(),
            message: "Adversary model declared without fault bound parameter.".to_string(),
            hint: "Add `adversary { bound: f; }` to bound fault injection.".to_string(),
        });
    }

    // Check: missing resilience
    if proto.resilience.is_none() {
        warnings.push(CompletenessWarning {
            code: "missing_resilience".to_string(),
            message: "No resilience declaration.".to_string(),
            hint: "Add `resilience: n = 3*f + 1;` or similar constraint.".to_string(),
        });
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a simple ThresholdGuard for testing
    fn make_threshold_guard(
        msg: &str,
        op: ast::CmpOp,
        distinct: bool,
        distinct_role: Option<&str>,
    ) -> ast::ThresholdGuard {
        ast::ThresholdGuard {
            op,
            threshold: ast::LinearExpr::Const(1),
            message_type: msg.to_string(),
            message_args: vec![],
            distinct,
            distinct_role: distinct_role.map(|s| s.to_string()),
        }
    }

    #[test]
    fn guard_uses_threshold_on_threshold_guard() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Ge,
            false,
            None,
        ));
        assert!(guard_uses_threshold(&guard));
    }

    #[test]
    fn guard_uses_threshold_on_bool_guard() {
        let guard = ast::GuardExpr::BoolVar("ready".into());
        assert!(!guard_uses_threshold(&guard));
    }

    #[test]
    fn guard_uses_threshold_nested_and() {
        let inner = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Ge,
            false,
            None,
        ));
        let guard = ast::GuardExpr::And(
            Box::new(ast::GuardExpr::BoolVar("x".into())),
            Box::new(inner),
        );
        assert!(guard_uses_threshold(&guard));
    }

    #[test]
    fn guard_uses_distinct_threshold_true() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Ge,
            true,
            Some("Validator"),
        ));
        assert!(guard_uses_distinct_threshold(&guard));
    }

    #[test]
    fn guard_uses_distinct_threshold_false_when_not_distinct() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Ge,
            false,
            None,
        ));
        assert!(!guard_uses_distinct_threshold(&guard));
    }

    #[test]
    fn collect_distinct_roles_from_guard_collects_role() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Ge,
            true,
            Some("Validator"),
        ));
        let mut roles = HashSet::new();
        collect_distinct_roles_from_guard(&guard, &mut roles);
        assert!(roles.contains("Validator"));
        assert_eq!(roles.len(), 1);
    }

    #[test]
    fn collect_distinct_roles_empty_when_not_distinct() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Ge,
            false,
            None,
        ));
        let mut roles = HashSet::new();
        collect_distinct_roles_from_guard(&guard, &mut roles);
        assert!(roles.is_empty());
    }

    #[test]
    fn collect_distinct_messages_from_guard_collects_msg() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Prepare",
            ast::CmpOp::Ge,
            true,
            None,
        ));
        let mut messages = HashSet::new();
        collect_distinct_messages_from_guard(&guard, &mut messages);
        assert!(messages.contains("Prepare"));
    }

    #[test]
    fn collect_distinct_messages_empty_when_not_distinct() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Prepare",
            ast::CmpOp::Ge,
            false,
            None,
        ));
        let mut messages = HashSet::new();
        collect_distinct_messages_from_guard(&guard, &mut messages);
        assert!(messages.is_empty());
    }

    #[test]
    fn guard_has_non_monotone_threshold_le_is_non_monotone() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Le,
            false,
            None,
        ));
        assert!(guard_has_non_monotone_threshold(&guard));
    }

    #[test]
    fn guard_has_non_monotone_threshold_ge_is_monotone() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Ge,
            false,
            None,
        ));
        assert!(!guard_has_non_monotone_threshold(&guard));
    }

    #[test]
    fn guard_has_non_monotone_threshold_gt_is_monotone() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Gt,
            false,
            None,
        ));
        assert!(!guard_has_non_monotone_threshold(&guard));
    }

    #[test]
    fn guard_has_non_monotone_eq_is_non_monotone() {
        let guard = ast::GuardExpr::Threshold(make_threshold_guard(
            "Vote",
            ast::CmpOp::Eq,
            false,
            None,
        ));
        assert!(guard_has_non_monotone_threshold(&guard));
    }

    #[test]
    fn collect_crypto_objects_from_guard_basic() {
        let guard = ast::GuardExpr::HasCryptoObject {
            object_name: "cert".to_string(),
            object_args: vec![],
        };
        let mut out = HashSet::new();
        collect_crypto_objects_from_guard(&guard, &mut out);
        assert!(out.contains("cert"));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn collect_crypto_objects_nested_or() {
        let left = ast::GuardExpr::HasCryptoObject {
            object_name: "cert_a".to_string(),
            object_args: vec![],
        };
        let right = ast::GuardExpr::HasCryptoObject {
            object_name: "cert_b".to_string(),
            object_args: vec![],
        };
        let guard = ast::GuardExpr::Or(Box::new(left), Box::new(right));
        let mut out = HashSet::new();
        collect_crypto_objects_from_guard(&guard, &mut out);
        assert!(out.contains("cert_a"));
        assert!(out.contains("cert_b"));
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn guard_has_crypto_check_matches() {
        let guard = ast::GuardExpr::HasCryptoObject {
            object_name: "cert".to_string(),
            object_args: vec![],
        };
        assert!(guard_has_crypto_check(&guard, "cert"));
        assert!(!guard_has_crypto_check(&guard, "other"));
    }

    #[test]
    fn effective_message_authenticated_via_channel() {
        let proto = ast::ProtocolDecl {
            name: "Test".into(),
            imports: vec![],
            modules: vec![],
            enums: vec![],
            parameters: vec![],
            resilience: None,
            pacemaker: None,
            adversary: vec![],
            identities: vec![],
            channels: vec![ast::ChannelDecl {
                message: "Vote".into(),
                auth: ast::ChannelAuthMode::Authenticated,
                span: ast::Span::new(0, 0),
            }],
            equivocation_policies: vec![],
            committees: vec![],
            messages: vec![],
            crypto_objects: vec![],
            roles: vec![],
            properties: vec![],
        };
        assert!(effective_message_authenticated(&proto, "Vote", "none"));
        assert!(!effective_message_authenticated(&proto, "Other", "none"));
    }

    #[test]
    fn effective_message_authenticated_via_global_auth() {
        let proto = ast::ProtocolDecl {
            name: "Test".into(),
            imports: vec![],
            modules: vec![],
            enums: vec![],
            parameters: vec![],
            resilience: None,
            pacemaker: None,
            adversary: vec![],
            identities: vec![],
            channels: vec![],
            equivocation_policies: vec![],
            committees: vec![],
            messages: vec![],
            crypto_objects: vec![],
            roles: vec![],
            properties: vec![],
        };
        assert!(effective_message_authenticated(&proto, "Vote", "signed"));
        assert!(!effective_message_authenticated(&proto, "Vote", "none"));
    }

    #[test]
    fn effective_message_non_equivocating_via_policy() {
        let proto = ast::ProtocolDecl {
            name: "Test".into(),
            imports: vec![],
            modules: vec![],
            enums: vec![],
            parameters: vec![],
            resilience: None,
            pacemaker: None,
            adversary: vec![],
            identities: vec![],
            channels: vec![],
            equivocation_policies: vec![ast::EquivocationDecl {
                message: "Vote".into(),
                mode: ast::EquivocationPolicyMode::None,
                span: ast::Span::new(0, 0),
            }],
            committees: vec![],
            messages: vec![],
            crypto_objects: vec![],
            roles: vec![],
            properties: vec![],
        };
        assert!(effective_message_non_equivocating(
            &proto, "Vote", "full"
        ));
        // Message not covered by policy falls back to global
        assert!(!effective_message_non_equivocating(
            &proto, "Other", "full"
        ));
    }

    #[test]
    fn effective_message_non_equivocating_via_global() {
        let proto = ast::ProtocolDecl {
            name: "Test".into(),
            imports: vec![],
            modules: vec![],
            enums: vec![],
            parameters: vec![],
            resilience: None,
            pacemaker: None,
            adversary: vec![],
            identities: vec![],
            channels: vec![],
            equivocation_policies: vec![],
            committees: vec![],
            messages: vec![],
            crypto_objects: vec![],
            roles: vec![],
            properties: vec![],
        };
        assert!(effective_message_non_equivocating(
            &proto, "Vote", "none"
        ));
        assert!(!effective_message_non_equivocating(
            &proto, "Vote", "full"
        ));
    }

    #[test]
    fn pipeline_command_eq() {
        assert!(PipelineCommand::Verify == PipelineCommand::Verify);
        assert!(PipelineCommand::Verify != PipelineCommand::Liveness);
        assert!(PipelineCommand::Liveness == PipelineCommand::Liveness);
        assert!(
            PipelineCommand::VerifyAllProperties != PipelineCommand::Verify
        );
    }
}
