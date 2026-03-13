// Faithful-network suggestion helpers.

pub(crate) fn faithful_identity_decl_snippet(
    role: &str,
    scope: tarsier_dsl::ast::IdentityScope,
    process_var: Option<&str>,
    key: &str,
) -> String {
    match scope {
        tarsier_dsl::ast::IdentityScope::Role => {
            format!("identity {role}: role key {key};")
        }
        tarsier_dsl::ast::IdentityScope::Process => format!(
            "identity {role}: process({}) key {key};",
            process_var.unwrap_or("pid")
        ),
    }
}

pub(crate) fn suggested_identity_scope_for_network(
    network_mode: &str,
) -> (tarsier_dsl::ast::IdentityScope, Option<&'static str>) {
    if network_mode == "process_selective" {
        (tarsier_dsl::ast::IdentityScope::Process, Some("pid"))
    } else {
        (tarsier_dsl::ast::IdentityScope::Role, None)
    }
}

pub(crate) fn faithful_missing_identity_suggestion(
    missing_roles: &[String],
    network_mode: &str,
) -> Option<String> {
    if missing_roles.is_empty() {
        return None;
    }
    let (scope, process_var) = suggested_identity_scope_for_network(network_mode);
    let mut lines = Vec::new();
    lines.push("Add these identity declarations:".to_string());
    for role in missing_roles {
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!(
            "  {}",
            faithful_identity_decl_snippet(role, scope, process_var, &key)
        ));
    }
    Some(lines.join("\n"))
}

pub(crate) fn faithful_missing_identity_key_suggestion(
    proto: &tarsier_dsl::ast::ProtocolDecl,
    roles_without_key: &[String],
    network_mode: &str,
) -> Option<String> {
    if roles_without_key.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Add explicit keys to these identity declarations:".to_string());
    for role in roles_without_key {
        let scope = proto
            .identities
            .iter()
            .find(|id| id.role == *role)
            .map(|id| id.scope)
            .unwrap_or_else(|| suggested_identity_scope_for_network(network_mode).0);
        let process_var = proto
            .identities
            .iter()
            .find(|id| id.role == *role)
            .and_then(|id| id.process_var.as_deref())
            .or_else(|| suggested_identity_scope_for_network(network_mode).1);
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!(
            "  {}",
            faithful_identity_decl_snippet(role, scope, process_var, &key)
        ));
    }
    Some(lines.join("\n"))
}

pub(crate) fn faithful_missing_process_identity_suggestion(roles: &[String]) -> Option<String> {
    if roles.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Use process-scoped identities for these roles:".to_string());
    for role in roles {
        let key = format!("{}_key", role.to_lowercase());
        lines.push(format!("  identity {role}: process(pid) key {key};"));
    }
    Some(lines.join("\n"))
}

pub(crate) fn faithful_missing_auth_suggestion(messages: &[String]) -> Option<String> {
    if messages.is_empty() {
        return None;
    }
    let mut lines = Vec::new();
    lines.push("Choose one auth strategy for faithful proofs:".to_string());
    lines.push("  Option A: adversary { auth: signed; }".to_string());
    lines.push("  Option B: add per-message channels:".to_string());
    for msg in messages {
        lines.push(format!("    channel {msg}: authenticated;"));
    }
    Some(lines.join("\n"))
}

pub(crate) fn faithful_missing_equivocation_suggestion() -> Option<String> {
    Some(
        "Declare an explicit policy: `adversary { equivocation: full; }` (over-approx) \
or `adversary { equivocation: none; }` (non-equivocating)."
            .to_string(),
    )
}

pub(crate) fn faithful_proof_scaffold_suggestion(
    proto: &tarsier_dsl::ast::ProtocolDecl,
    network_mode: &str,
) -> String {
    let role_names: std::collections::HashSet<String> =
        proto.roles.iter().map(|r| r.node.name.clone()).collect();
    let identity_roles: std::collections::HashSet<String> =
        proto.identities.iter().map(|id| id.role.clone()).collect();
    let mut missing_identity_roles: Vec<String> =
        role_names.difference(&identity_roles).cloned().collect();
    missing_identity_roles.sort();
    let channel_covered: std::collections::HashSet<String> =
        proto.channels.iter().map(|c| c.message.clone()).collect();
    let mut missing_auth_messages: Vec<String> = proto
        .messages
        .iter()
        .map(|m| m.name.clone())
        .filter(|m| !channel_covered.contains(m))
        .collect();
    missing_auth_messages.sort();
    let mut lines = Vec::new();
    lines.push("Use faithful-proof baseline:".to_string());
    lines.push("  adversary { network: process_selective; auth: signed; }".to_string());
    if let Some(s) =
        faithful_missing_identity_suggestion(&missing_identity_roles, "process_selective")
    {
        lines.push(s);
    }
    if let Some(s) = faithful_missing_auth_suggestion(&missing_auth_messages) {
        lines.push(s);
    }
    if lines.len() == 1 {
        lines.push(format!(
            "  (network currently `{network_mode}`; add the adversary line above to switch to faithful semantics)"
        ));
    }
    lines.join("\n")
}
