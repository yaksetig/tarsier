// Command handler for: ComposeCheck
//
// Compositional verification — lowers each module independently and checks
// the assume/guarantee contract graph.

use std::path::PathBuf;

use miette::IntoDiagnostic;

use super::helpers::sandbox_read_source;

/// Handler for the `compose-check` subcommand.
///
/// Parses a multi-module protocol, lowers each module independently, builds
/// assume/guarantee contracts, and checks compositional soundness.
pub(crate) fn run_compose_check_command(file: PathBuf) -> miette::Result<()> {
    let source = sandbox_read_source(&file)?;
    let filename = file.display().to_string();

    let program = tarsier_engine::pipeline::parse(&source, &filename).into_diagnostic()?;

    if program.protocol.node.modules.is_empty() {
        eprintln!("No module declarations found in {}.", filename);
        eprintln!("Compositional verification requires `module {{ ... }}` blocks.");
        std::process::exit(1);
    }

    // Lower each module independently
    let mut modules = Vec::new();
    for module_decl in &program.protocol.node.modules {
        // Build a mini program from the module's items
        let module_program = tarsier_dsl::ast::Program {
            protocol: tarsier_dsl::ast::Spanned::new(
                tarsier_dsl::ast::ProtocolDecl {
                    name: module_decl.name.clone(),
                    imports: Vec::new(),
                    modules: Vec::new(),
                    enums: Vec::new(),
                    parameters: module_decl.items.parameters.clone(),
                    resilience: module_decl.items.resilience.clone(),
                    pacemaker: None,
                    adversary: module_decl.items.adversary.clone(),
                    identities: Vec::new(),
                    channels: Vec::new(),
                    equivocation_policies: Vec::new(),
                    committees: Vec::new(),
                    messages: module_decl.items.messages.clone(),
                    crypto_objects: Vec::new(),
                    roles: module_decl.items.roles.clone(),
                    properties: module_decl.items.properties.clone(),
                },
                module_decl.span,
            ),
        };

        match tarsier_engine::pipeline::lower(&module_program) {
            Ok(ta) => {
                let interface = if let Some(iface) = &module_decl.interface {
                    tarsier_ir::composition::ModuleContract {
                        assumptions: iface
                            .assumptions
                            .iter()
                            .map(|a| {
                                tarsier_ir::lowering::lower_interface_assumption(a, &ta)
                                    .unwrap_or_else(|e| {
                                        eprintln!(
                                            "Warning: could not lower assumption in module '{}': {e}",
                                            module_decl.name
                                        );
                                        tarsier_ir::composition::Assumption::ParameterConstraint {
                                            lhs: tarsier_ir::threshold_automaton::LinearCombination::constant(0),
                                            op: tarsier_ir::threshold_automaton::CmpOp::Ge,
                                            rhs: tarsier_ir::threshold_automaton::LinearCombination::constant(0),
                                        }
                                    })
                            })
                            .collect(),
                        guarantees: iface
                            .guarantees
                            .iter()
                            .map(|g| {
                                tarsier_ir::composition::Guarantee::Safety(
                                    g.property_name.clone(),
                                )
                            })
                            .collect(),
                    }
                } else {
                    tarsier_ir::composition::ModuleContract {
                        assumptions: Vec::new(),
                        guarantees: Vec::new(),
                    }
                };

                modules.push(tarsier_ir::composition::Module {
                    name: module_decl.name.clone(),
                    automaton: ta,
                    interface,
                });
            }
            Err(e) => {
                eprintln!("Error lowering module '{}': {e}", module_decl.name);
                std::process::exit(1);
            }
        }
    }

    let result = tarsier_engine::compositional::check_module_composition(&modules);
    match result {
        tarsier_engine::compositional::CompositionalResult::ContractsValid { module_results } => {
            println!("Composition check: CONTRACTS VALID");
            println!("Modules: {}", modules.len());
            for (name, desc) in &module_results {
                println!("  {} -> {}", name, desc);
            }
            println!("\nNote: contract graph is valid. Run `tarsier verify` on each module separately to discharge safety proofs.");
        }
        tarsier_engine::compositional::CompositionalResult::CompositionError(msg) => {
            println!("Composition check: INVALID");
            println!("{msg}");
            std::process::exit(1);
        }
    }
    Ok(())
}
