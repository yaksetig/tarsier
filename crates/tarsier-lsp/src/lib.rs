#![doc = include_str!("../README.md")]

//! Language Server Protocol implementation for the Tarsier DSL.
//!
//! Provides IDE features (diagnostics, hover, go-to-definition, completions)
//! for `.trs` protocol specification files via the LSP protocol.

mod code_actions;
mod completion;
mod diagnostics;
mod folding;
mod formatting;
mod hover;
mod inlay_hints;
mod navigation;
mod semantic_tokens;
mod symbol_analysis;
mod utils;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tower_lsp::jsonrpc::{Error, Result};
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

use tarsier_dsl::ast::Program;

use code_actions::{build_code_actions, build_document_symbols};
use completion::{build_completions, infer_cursor_context};
use diagnostics::{collect_lowering_diagnostics, parse_error_diagnostics, push_unique_diagnostic};
use folding::build_folding_ranges;
#[cfg(test)]
use formatting::ranges_overlap;
use formatting::{compute_minimal_edits, format_document_text, format_range_text};
use hover::{hover_for_user_defined, keyword_docs};
use inlay_hints::build_inlay_hints;
use navigation::{
    as_goto_definition_response, collect_reference_spans_for_target,
    collect_workspace_symbol_information, dedup_and_sort_locations,
    dedup_and_sort_workspace_symbols, definition_locations, definition_spans_for_name,
    has_target_definition, reference_locations, resolve_symbol_target, target_reference_locations,
};
use semantic_tokens::{build_semantic_tokens, semantic_tokens_legend};
use symbol_analysis::collect_symbol_occurrences;
use utils::{apply_incremental_change, offset_to_range, position_to_offset, word_at_position};

// ---------------------------------------------------------------------------
// Document state
// ---------------------------------------------------------------------------

struct DocumentState {
    source: String,
    #[allow(dead_code)]
    version: i32,
    /// Cached successful parse result (AST + parse diagnostics).
    parsed: Option<(Program, Vec<tarsier_dsl::errors::ParseDiagnostic>)>,
}

#[derive(Debug, Clone)]
struct SymbolDocument {
    uri: Url,
    source: String,
    program: Program,
}

const MAX_IMPORT_TRAVERSAL_DEPTH: usize = 8;
const MAX_WORKSPACE_SYMBOL_FILES: usize = 512;
const MAX_WORKSPACE_SCAN_DEPTH: usize = 6;
const MAX_WORKSPACE_SYMBOL_RESULTS: usize = 256;

// ---------------------------------------------------------------------------
// Definition info (for goto-definition / references)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DefinitionKind {
    Message,
    Role,
    Phase,
    Param,
    Var,
    Property,
    Enum,
}

#[derive(Debug, Clone)]
struct DefinitionInfo {
    name: String,
    #[cfg_attr(not(test), allow(dead_code))]
    kind: DefinitionKind,
    start: usize,
    end: usize,
    #[cfg_attr(not(test), allow(dead_code))]
    parent: Option<String>,
}

mod reference_parser {
    use pest_derive::Parser;

    #[derive(Parser)]
    #[grammar = "../../tarsier-dsl/src/grammar.pest"]
    pub struct TarsierReferenceParser;
}

use reference_parser::Rule as ReferenceRule;
type ReferencePair<'a> = pest::iterators::Pair<'a, ReferenceRule>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SymbolTarget {
    name: String,
    kind: DefinitionKind,
    parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SymbolOccurrence {
    name: String,
    kind: DefinitionKind,
    parent: Option<String>,
    start: usize,
    end: usize,
    declaration: bool,
}

#[derive(Debug, Default, Clone)]
struct SymbolTables {
    params: HashSet<String>,
    roles: HashSet<String>,
    role_vars: HashMap<String, HashSet<String>>,
    role_phases: HashMap<String, HashSet<String>>,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// LSP backend implementation for `.trs` files.
pub struct TarsierLspBackend {
    client: Client,
    documents: RwLock<HashMap<Url, DocumentState>>,
    /// Workspace root directories captured from InitializeParams.
    workspace_roots: RwLock<Vec<PathBuf>>,
    /// Cached workspace-global symbol documents for cross-file navigation.
    /// Populated lazily on the first navigation request, then incrementally
    /// maintained on did_open / did_change / did_close.
    workspace_index: RwLock<HashMap<Url, SymbolDocument>>,
    /// Whether the workspace index has been initially populated.
    workspace_index_ready: RwLock<bool>,
}

impl TarsierLspBackend {
    /// Construct a new backend bound to the given LSP client.
    ///
    /// # Parameters
    /// - `client`: The `tower_lsp` client used to publish diagnostics and notifications.
    ///
    /// # Returns
    /// A backend instance with an empty in-memory document cache.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: RwLock::new(HashMap::new()),
            workspace_roots: RwLock::new(Vec::new()),
            workspace_index: RwLock::new(HashMap::new()),
            workspace_index_ready: RwLock::new(false),
        }
    }

    /// Run diagnostics and cache the parse result.
    fn diagnose_and_cache(&self, uri: &Url, text: &str) -> Vec<Diagnostic> {
        let filename = uri
            .path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("untitled.trs");

        let mut diagnostics = Vec::new();

        match tarsier_dsl::parse_with_diagnostics(text, filename) {
            Ok((program, parse_diags)) => {
                // Parse diagnostics (warnings)
                for diag in &parse_diags {
                    let range = diag
                        .span
                        .as_ref()
                        .and_then(|s| offset_to_range(text, s.start, s.end))
                        .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
                    push_unique_diagnostic(
                        &mut diagnostics,
                        Diagnostic {
                            range,
                            severity: Some(DiagnosticSeverity::WARNING),
                            source: Some("tarsier".into()),
                            code: Some(NumberOrString::String(diag.code.clone())),
                            message: diag.message.clone(),
                            ..Default::default()
                        },
                    );
                }

                // Lowering diagnostics:
                // 1) collect structural checks in one pass (multi-error),
                // 2) keep lower_with_source fallback for deeper first-error diagnostics.
                for diag in collect_lowering_diagnostics(&program, text, filename) {
                    push_unique_diagnostic(&mut diagnostics, diag);
                }

                // Cache parse result
                {
                    if let Ok(mut docs) = self.documents.write() {
                        if let Some(state) = docs.get_mut(uri) {
                            state.parsed = Some((program, parse_diags));
                        }
                    }
                }
            }
            Err(e) => {
                for diag in parse_error_diagnostics(&e, text) {
                    push_unique_diagnostic(&mut diagnostics, diag);
                }

                // Clear cached parse
                {
                    if let Ok(mut docs) = self.documents.write() {
                        if let Some(state) = docs.get_mut(uri) {
                            state.parsed = None;
                        }
                    }
                }
            }
        }

        diagnostics
    }

    fn snapshot_document(&self, uri: &Url) -> Option<(String, Option<Program>)> {
        let docs = self.documents.read().ok()?;
        let state = docs.get(uri)?;
        let parsed = state.parsed.as_ref().map(|(program, _)| program.clone());
        Some((state.source.clone(), parsed))
    }

    fn load_symbol_document(&self, uri: &Url) -> Option<SymbolDocument> {
        if let Some((source, parsed_program)) = self.snapshot_document(uri) {
            let filename = uri
                .path_segments()
                .and_then(|mut s| s.next_back())
                .unwrap_or("untitled.trs");
            let program = match parsed_program {
                Some(program) => program,
                None => tarsier_dsl::parse_with_diagnostics(&source, filename)
                    .ok()
                    .map(|(program, _)| program)?,
            };
            return Some(SymbolDocument {
                uri: uri.clone(),
                source,
                program,
            });
        }

        let path = uri.to_file_path().ok()?;
        let source = std::fs::read_to_string(path).ok()?;
        let filename = uri
            .path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("untitled.trs");
        let (program, _) = tarsier_dsl::parse_with_diagnostics(&source, filename).ok()?;
        Some(SymbolDocument {
            uri: uri.clone(),
            source,
            program,
        })
    }

    fn collect_import_documents(
        &self,
        root_uri: &Url,
        root_program: &Program,
    ) -> Vec<SymbolDocument> {
        let mut out = Vec::new();
        let mut visited: HashSet<Url> = HashSet::new();
        let mut queue: VecDeque<(Url, Program, usize)> = VecDeque::new();

        visited.insert(root_uri.clone());
        queue.push_back((root_uri.clone(), root_program.clone(), 0));

        while let Some((current_uri, current_program, depth)) = queue.pop_front() {
            if depth >= MAX_IMPORT_TRAVERSAL_DEPTH {
                continue;
            }

            for import in &current_program.protocol.node.imports {
                let Some(import_uri) = resolve_import_uri(&current_uri, &import.path) else {
                    continue;
                };
                if !visited.insert(import_uri.clone()) {
                    continue;
                }

                let Some(import_doc) = self.load_symbol_document(&import_uri) else {
                    continue;
                };
                queue.push_back((
                    import_doc.uri.clone(),
                    import_doc.program.clone(),
                    depth + 1,
                ));
                out.push(import_doc);
            }
        }

        out
    }

    fn collect_workspace_symbol_documents(&self) -> Vec<SymbolDocument> {
        let open_uris: Vec<Url> = {
            let Ok(docs) = self.documents.read() else {
                return Vec::new();
            };
            docs.keys().cloned().collect()
        };

        let mut by_uri: HashMap<Url, SymbolDocument> = HashMap::new();
        let mut queue: VecDeque<SymbolDocument> = VecDeque::new();

        for uri in &open_uris {
            if let Some(doc) = self.load_symbol_document(uri) {
                if by_uri.insert(uri.clone(), doc.clone()).is_none() {
                    queue.push_back(doc);
                }
            }
        }

        while let Some(doc) = queue.pop_front() {
            for import_doc in self.collect_import_documents(&doc.uri, &doc.program) {
                if by_uri.contains_key(&import_doc.uri) {
                    continue;
                }
                let uri = import_doc.uri.clone();
                by_uri.insert(uri, import_doc.clone());
                queue.push_back(import_doc);
            }
        }

        let mut roots = workspace_roots_from_uris(&open_uris);
        if roots.is_empty() {
            if let Ok(cwd) = std::env::current_dir() {
                roots.push(cwd);
            }
        }

        for root in roots {
            let files = discover_workspace_trs_files(
                &root,
                MAX_WORKSPACE_SYMBOL_FILES.saturating_sub(by_uri.len()),
                MAX_WORKSPACE_SCAN_DEPTH,
            );
            for file in files {
                if by_uri.len() >= MAX_WORKSPACE_SYMBOL_FILES {
                    break;
                }
                let Ok(uri) = Url::from_file_path(file) else {
                    continue;
                };
                if by_uri.contains_key(&uri) {
                    continue;
                }
                if let Some(doc) = self.load_symbol_document(&uri) {
                    by_uri.insert(uri, doc);
                }
            }
            if by_uri.len() >= MAX_WORKSPACE_SYMBOL_FILES {
                break;
            }
        }

        let mut docs: Vec<SymbolDocument> = by_uri.into_values().collect();
        docs.sort_by_key(|d| d.uri.to_string());
        docs
    }

    /// Ensure the workspace index is populated (lazily on first call).
    /// Scans workspace roots for .trs files and parses them.
    fn ensure_workspace_index(&self) {
        {
            if let Ok(ready) = self.workspace_index_ready.read() {
                if *ready {
                    return;
                }
            }
        }

        let roots: Vec<PathBuf> = {
            let Ok(wr) = self.workspace_roots.read() else {
                return;
            };
            if wr.is_empty() {
                // Fallback: derive roots from open documents
                let open_uris: Vec<Url> = self
                    .documents
                    .read()
                    .map(|docs| docs.keys().cloned().collect())
                    .unwrap_or_default();
                let mut fallback = workspace_roots_from_uris(&open_uris);
                if fallback.is_empty() {
                    if let Ok(cwd) = std::env::current_dir() {
                        fallback.push(cwd);
                    }
                }
                fallback
            } else {
                wr.clone()
            }
        };

        let mut by_uri: HashMap<Url, SymbolDocument> = HashMap::new();

        // First: include all open documents (they take precedence)
        if let Ok(docs) = self.documents.read() {
            for (uri, state) in docs.iter() {
                if let Some(ref parsed) = state.parsed {
                    by_uri.insert(
                        uri.clone(),
                        SymbolDocument {
                            uri: uri.clone(),
                            source: state.source.clone(),
                            program: parsed.0.clone(),
                        },
                    );
                }
            }
        }

        // Second: scan workspace roots for .trs files
        for root in roots {
            let files = discover_workspace_trs_files(
                &root,
                MAX_WORKSPACE_SYMBOL_FILES.saturating_sub(by_uri.len()),
                MAX_WORKSPACE_SCAN_DEPTH,
            );
            for file in files {
                if by_uri.len() >= MAX_WORKSPACE_SYMBOL_FILES {
                    break;
                }
                let Ok(uri) = Url::from_file_path(&file) else {
                    continue;
                };
                if by_uri.contains_key(&uri) {
                    continue;
                }
                if let Some(doc) = self.load_symbol_document(&uri) {
                    by_uri.insert(uri, doc);
                }
            }
            if by_uri.len() >= MAX_WORKSPACE_SYMBOL_FILES {
                break;
            }
        }

        // Third: follow import chains for all discovered files
        let initial_uris: Vec<Url> = by_uri.keys().cloned().collect();
        for uri in initial_uris {
            let program = by_uri[&uri].program.clone();
            for import_doc in self.collect_import_documents(&uri, &program) {
                if !by_uri.contains_key(&import_doc.uri) {
                    let import_uri = import_doc.uri.clone();
                    by_uri.insert(import_uri, import_doc);
                }
            }
        }

        if let Ok(mut index) = self.workspace_index.write() {
            *index = by_uri;
        }
        if let Ok(mut ready) = self.workspace_index_ready.write() {
            *ready = true;
        }
    }

    /// Update (or insert) a single document in the workspace index.
    fn workspace_index_upsert(&self, uri: &Url) {
        if let Ok(ready) = self.workspace_index_ready.read() {
            if !*ready {
                return; // Index not yet built; will be populated on first use
            }
        }
        if let Some(doc) = self.load_symbol_document(uri) {
            if let Ok(mut index) = self.workspace_index.write() {
                index.insert(uri.clone(), doc);
            }
        }
    }

    /// Remove a document from the workspace index (on close, unless it's on disk).
    fn workspace_index_remove(&self, uri: &Url) {
        if let Ok(ready) = self.workspace_index_ready.read() {
            if !*ready {
                return;
            }
        }
        // Re-load from disk if the file still exists; otherwise remove
        let disk_doc = {
            let path = uri.to_file_path().ok();
            path.and_then(|p| {
                if p.exists() {
                    let source = std::fs::read_to_string(&p).ok()?;
                    let filename = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("untitled.trs");
                    let (program, _) =
                        tarsier_dsl::parse_with_diagnostics(&source, filename).ok()?;
                    Some(SymbolDocument {
                        uri: uri.clone(),
                        source,
                        program,
                    })
                } else {
                    None
                }
            })
        };
        if let Ok(mut index) = self.workspace_index.write() {
            match disk_doc {
                Some(doc) => {
                    index.insert(uri.clone(), doc);
                }
                None => {
                    index.remove(uri);
                }
            }
        }
    }

    /// Collect workspace-global navigation documents. The current file's open
    /// buffer always takes precedence (via the document cache). Includes all
    /// workspace-indexed documents plus the import graph.
    fn collect_navigation_documents(
        &self,
        current_uri: &Url,
        current_source: &str,
        current_program: &Program,
    ) -> Vec<SymbolDocument> {
        self.ensure_workspace_index();

        let mut by_uri: HashMap<Url, SymbolDocument> = HashMap::new();

        // Start with the current document (open buffer takes precedence)
        by_uri.insert(
            current_uri.clone(),
            SymbolDocument {
                uri: current_uri.clone(),
                source: current_source.to_string(),
                program: current_program.clone(),
            },
        );

        // Add all workspace-indexed documents
        if let Ok(index) = self.workspace_index.read() {
            for (uri, doc) in index.iter() {
                if !by_uri.contains_key(uri) {
                    by_uri.insert(uri.clone(), doc.clone());
                }
            }
        }

        // Also include the import graph (in case imports reference non-workspace files)
        for import_doc in self.collect_import_documents(current_uri, current_program) {
            if !by_uri.contains_key(&import_doc.uri) {
                let uri = import_doc.uri.clone();
                by_uri.insert(uri, import_doc);
            }
        }

        // Open buffers take precedence: overwrite disk-based entries
        if let Ok(docs) = self.documents.read() {
            for (uri, state) in docs.iter() {
                if uri == current_uri {
                    continue; // Already inserted above
                }
                if let Some(ref parsed) = state.parsed {
                    by_uri.insert(
                        uri.clone(),
                        SymbolDocument {
                            uri: uri.clone(),
                            source: state.source.clone(),
                            program: parsed.0.clone(),
                        },
                    );
                }
            }
        }

        let mut docs: Vec<SymbolDocument> = by_uri.into_values().collect();
        docs.sort_by_key(|d| d.uri.to_string());
        docs
    }
}

fn is_valid_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn resolve_import_path(base_path: &Path, import_path: &str) -> Option<PathBuf> {
    let import = Path::new(import_path);
    let mut candidates = Vec::new();

    if import.is_absolute() {
        candidates.push(import.to_path_buf());
    } else {
        let parent = base_path.parent()?;
        candidates.push(parent.join(import));
    }

    if import.extension().is_none() {
        let mut with_ext = candidates[0].clone();
        with_ext.set_extension("trs");
        candidates.push(with_ext);
    }

    for candidate in candidates {
        if candidate.exists() {
            if let Ok(canon) = std::fs::canonicalize(candidate) {
                return Some(canon);
            }
        }
    }
    None
}

fn resolve_import_uri(base_uri: &Url, import_path: &str) -> Option<Url> {
    let base_path = base_uri.to_file_path().ok()?;
    let import_fs_path = resolve_import_path(&base_path, import_path)?;
    Url::from_file_path(import_fs_path).ok()
}

fn is_skippable_workspace_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".idea" | ".vscode"
    )
}

fn workspace_roots_from_uris(uris: &[Url]) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for uri in uris {
        let Ok(file_path) = uri.to_file_path() else {
            continue;
        };
        let Some(parent) = file_path.parent() else {
            continue;
        };
        if let Ok(canon) = std::fs::canonicalize(parent) {
            if !roots.contains(&canon) {
                roots.push(canon);
            }
        }
    }
    roots
}

fn discover_workspace_trs_files(root: &Path, max_files: usize, max_depth: usize) -> Vec<PathBuf> {
    if max_files == 0 || !root.exists() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((root.to_path_buf(), 0));

    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };

            if ft.is_dir() {
                if depth >= max_depth {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if is_skippable_workspace_dir(name) {
                        continue;
                    }
                }
                queue.push_back((path, depth + 1));
                continue;
            }

            if ft.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("trs"))
                    .unwrap_or(false)
            {
                if let Ok(canon) = std::fs::canonicalize(path) {
                    out.push(canon);
                }
                if out.len() >= max_files {
                    return out;
                }
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Collect definitions from AST
// ---------------------------------------------------------------------------

fn collect_definitions(program: &Program) -> Vec<DefinitionInfo> {
    let mut defs = Vec::new();
    let proto = &program.protocol.node;

    // Messages
    for msg in &proto.messages {
        defs.push(DefinitionInfo {
            name: msg.name.clone(),
            kind: DefinitionKind::Message,
            start: msg.span.start,
            end: msg.span.end,
            parent: None,
        });
    }

    // Parameters
    for param in &proto.parameters {
        defs.push(DefinitionInfo {
            name: param.name.clone(),
            kind: DefinitionKind::Param,
            start: param.span.start,
            end: param.span.end,
            parent: None,
        });
    }

    // Enums
    for e in &proto.enums {
        defs.push(DefinitionInfo {
            name: e.name.clone(),
            kind: DefinitionKind::Enum,
            start: e.span.start,
            end: e.span.end,
            parent: None,
        });
    }

    // Roles
    for role in &proto.roles {
        defs.push(DefinitionInfo {
            name: role.node.name.clone(),
            kind: DefinitionKind::Role,
            start: role.span.start,
            end: role.span.end,
            parent: None,
        });

        // Phases
        for phase in &role.node.phases {
            defs.push(DefinitionInfo {
                name: phase.node.name.clone(),
                kind: DefinitionKind::Phase,
                start: phase.span.start,
                end: phase.span.end,
                parent: Some(role.node.name.clone()),
            });
        }

        // Variables
        for var in &role.node.vars {
            defs.push(DefinitionInfo {
                name: var.name.clone(),
                kind: DefinitionKind::Var,
                start: var.span.start,
                end: var.span.end,
                parent: Some(role.node.name.clone()),
            });
        }
    }

    // Properties
    for prop in &proto.properties {
        defs.push(DefinitionInfo {
            name: prop.node.name.clone(),
            kind: DefinitionKind::Property,
            start: prop.span.start,
            end: prop.span.end,
            parent: None,
        });
    }

    defs
}

// ---------------------------------------------------------------------------
// LanguageServer implementation
// ---------------------------------------------------------------------------

#[tower_lsp::async_trait]
impl LanguageServer for TarsierLspBackend {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        // Capture workspace roots from the client
        let mut roots = Vec::new();
        if let Some(folders) = &params.workspace_folders {
            for folder in folders {
                if let Ok(path) = folder.uri.to_file_path() {
                    if let Ok(canon) = std::fs::canonicalize(&path) {
                        if !roots.contains(&canon) {
                            roots.push(canon);
                        }
                    }
                }
            }
        }
        if roots.is_empty() {
            #[allow(deprecated)]
            if let Some(ref root_uri) = params.root_uri {
                if let Ok(path) = root_uri.to_file_path() {
                    if let Ok(canon) = std::fs::canonicalize(&path) {
                        roots.push(canon);
                    }
                }
            }
        }
        if let Ok(mut wr) = self.workspace_roots.write() {
            *wr = roots;
        }
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::INCREMENTAL,
                )),
                completion_provider: Some(CompletionOptions {
                    trigger_characters: Some(vec![" ".into(), ":".into(), "{".into()]),
                    ..Default::default()
                }),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                workspace_symbol_provider: Some(OneOf::Left(true)),
                document_formatting_provider: Some(OneOf::Left(true)),
                document_range_formatting_provider: Some(OneOf::Left(true)),
                rename_provider: Some(OneOf::Right(RenameOptions {
                    prepare_provider: Some(true),
                    work_done_progress_options: WorkDoneProgressOptions::default(),
                })),
                semantic_tokens_provider: Some(
                    SemanticTokensOptions {
                        work_done_progress_options: WorkDoneProgressOptions::default(),
                        legend: semantic_tokens_legend(),
                        range: Some(true),
                        full: Some(SemanticTokensFullOptions::Bool(true)),
                    }
                    .into(),
                ),
                code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
                inlay_hint_provider: Some(OneOf::Left(true)),
                folding_range_provider: Some(FoldingRangeProviderCapability::Simple(true)),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        tracing::info!("tarsier-lsp initialized");
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let text = params.text_document.text.clone();
        let version = params.text_document.version;
        {
            let Ok(mut docs) = self.documents.write() else {
                return;
            };
            docs.insert(
                uri.clone(),
                DocumentState {
                    source: text.clone(),
                    version,
                    parsed: None,
                },
            );
        }
        let diags = self.diagnose_and_cache(&uri, &text);
        self.workspace_index_upsert(&uri);
        self.client.publish_diagnostics(uri, diags, None).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let version = params.text_document.version;

        let text = {
            let Ok(mut docs) = self.documents.write() else {
                return;
            };
            let state = docs.entry(uri.clone()).or_insert_with(|| DocumentState {
                source: String::new(),
                version,
                parsed: None,
            });

            for change in &params.content_changes {
                if let Some(range) = change.range {
                    apply_incremental_change(&mut state.source, &range, &change.text);
                } else {
                    // Full replacement
                    state.source = change.text.clone();
                }
            }
            state.version = version;
            state.source.clone()
        };

        let diags = self.diagnose_and_cache(&uri, &text);
        self.workspace_index_upsert(&uri);
        self.client.publish_diagnostics(uri, diags, None).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        {
            if let Ok(mut docs) = self.documents.write() {
                docs.remove(&uri);
            }
        }
        self.workspace_index_remove(&uri);
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn completion(&self, params: CompletionParams) -> Result<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let offset = position_to_offset(&state.source, pos);
        let context = infer_cursor_context(&state.source, offset);
        let program = state.parsed.as_ref().map(|(p, _)| p);
        let items = build_completions(&context, program);

        Ok(Some(CompletionResponse::Array(items)))
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let offset = position_to_offset(&state.source, pos);
        let word_info = word_at_position(&state.source, offset);
        let (word, w_start, w_end) = match word_info {
            Some(w) => w,
            None => return Ok(None),
        };

        // Try keyword docs first
        if let Some(doc) = keyword_docs(&word) {
            let range = offset_to_range(&state.source, w_start, w_end);
            return Ok(Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: doc.to_string(),
                }),
                range,
            }));
        }

        // Try AST-aware docs
        if let Some((program, _)) = &state.parsed {
            if let Some(doc) = hover_for_user_defined(&word, program) {
                let range = offset_to_range(&state.source, w_start, w_end);
                return Ok(Some(Hover {
                    contents: HoverContents::Markup(MarkupContent {
                        kind: MarkupKind::Markdown,
                        value: doc,
                    }),
                    range,
                }));
            }
        }

        Ok(None)
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = params.text_document_position_params.text_document.uri;
        let pos = params.text_document_position_params.position;

        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };
        let Some(program) = parsed_program else {
            return Ok(None);
        };

        let offset = position_to_offset(&source, pos);
        let word_info = word_at_position(&source, offset);
        let (word, _, _) = match word_info {
            Some(w) => w,
            None => return Ok(None),
        };
        if keyword_docs(&word).is_some() {
            return Ok(None);
        }

        // Search current file first for fast local results
        let local_defs = definition_locations(&source, &program, &uri, &word);
        if !local_defs.is_empty() {
            return Ok(as_goto_definition_response(local_defs));
        }

        // Fall back to workspace-global search
        let mut workspace_defs = Vec::new();
        for doc in self.collect_navigation_documents(&uri, &source, &program) {
            if doc.uri == uri {
                continue; // Already checked above
            }
            workspace_defs.extend(definition_locations(
                &doc.source,
                &doc.program,
                &doc.uri,
                &word,
            ));
        }
        Ok(as_goto_definition_response(workspace_defs))
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let uri = params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let include_declaration = params.context.include_declaration;

        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };
        let Some(program) = parsed_program else {
            return Ok(None);
        };

        let offset = position_to_offset(&source, pos);
        let word_info = word_at_position(&source, offset);
        let (word, _, _) = match word_info {
            Some(w) => w,
            None => return Ok(None),
        };
        if keyword_docs(&word).is_some() {
            return Ok(None);
        }
        let local_occurrences = collect_symbol_occurrences(&source, &program);
        let target = resolve_symbol_target(&source, &program, offset, &local_occurrences);

        let docs = self.collect_navigation_documents(&uri, &source, &program);

        let has_definition = if let Some(target) = target.as_ref() {
            docs.iter()
                .any(|doc| has_target_definition(&doc.program, target))
        } else {
            docs.iter()
                .any(|doc| !definition_spans_for_name(&doc.program, &word).is_empty())
        };
        if !has_definition {
            return Ok(None);
        }

        let mut locations = Vec::new();
        for doc in &docs {
            if let Some(target) = target.as_ref() {
                let occurrences = collect_symbol_occurrences(&doc.source, &doc.program);
                locations.extend(target_reference_locations(
                    &doc.source,
                    &doc.program,
                    &doc.uri,
                    target,
                    include_declaration,
                    &occurrences,
                ));
            } else {
                locations.extend(reference_locations(
                    &doc.source,
                    &doc.program,
                    &doc.uri,
                    &word,
                    include_declaration,
                ));
            }
        }
        dedup_and_sort_locations(&mut locations);

        if locations.is_empty() {
            Ok(None)
        } else {
            Ok(Some(locations))
        }
    }

    async fn rename(&self, params: RenameParams) -> Result<Option<WorkspaceEdit>> {
        let uri = params.text_document_position.text_document.uri;
        let pos = params.text_document_position.position;
        let new_name = params.new_name;
        if !is_valid_identifier(&new_name) {
            return Err(Error::invalid_params(format!(
                "Invalid rename target '{new_name}': expected identifier [A-Za-z_][A-Za-z0-9_]*"
            )));
        }

        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };
        let Some(program) = parsed_program else {
            return Ok(None);
        };

        let offset = position_to_offset(&source, pos);
        let Some((old_name, _, _)) = word_at_position(&source, offset) else {
            return Ok(None);
        };
        if keyword_docs(&old_name).is_some() || !is_valid_identifier(&old_name) {
            return Ok(None);
        }
        let local_occurrences = collect_symbol_occurrences(&source, &program);
        let Some(target) = resolve_symbol_target(&source, &program, offset, &local_occurrences)
        else {
            return Err(Error::invalid_params(
                "Rename target is ambiguous or unresolved at cursor position".to_string(),
            ));
        };
        if target.name == new_name {
            return Ok(None);
        }

        let docs = self.collect_navigation_documents(&uri, &source, &program);

        let has_definition = docs
            .iter()
            .any(|doc| has_target_definition(&doc.program, &target));
        if !has_definition {
            return Ok(None);
        }

        // Safety check: reject rename if the target has multiple definitions
        // across different workspace files (ambiguous cross-file rename).
        let defining_uris: Vec<&Url> = docs
            .iter()
            .filter(|doc| has_target_definition(&doc.program, &target))
            .map(|doc| &doc.uri)
            .collect();
        if defining_uris.len() > 1 {
            let file_list: Vec<String> = defining_uris
                .iter()
                .filter_map(|u| {
                    u.path_segments()
                        .and_then(|mut s| s.next_back())
                        .map(|s| s.to_string())
                })
                .collect();
            return Err(Error::invalid_params(format!(
                "Rename rejected: '{}' has definitions in multiple workspace files ({}). \
                 Resolve the ambiguity before renaming.",
                target.name,
                file_list.join(", ")
            )));
        }

        let mut changes: HashMap<Url, Vec<TextEdit>> = HashMap::new();
        for doc in docs {
            let occurrences = collect_symbol_occurrences(&doc.source, &doc.program);
            let refs = collect_reference_spans_for_target(
                &doc.source,
                &doc.program,
                &target,
                true,
                &occurrences,
            );
            if refs.is_empty() {
                continue;
            }

            let mut edits: Vec<TextEdit> = refs
                .into_iter()
                .filter_map(|(start, end)| {
                    offset_to_range(&doc.source, start, end).map(|range| TextEdit {
                        range,
                        new_text: new_name.clone(),
                    })
                })
                .collect();
            edits.sort_by_key(|edit| {
                (
                    edit.range.start.line,
                    edit.range.start.character,
                    edit.range.end.line,
                    edit.range.end.character,
                )
            });
            edits.dedup_by(|a, b| a.range == b.range);
            if !edits.is_empty() {
                changes.insert(doc.uri, edits);
            }
        }

        if changes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(WorkspaceEdit {
                changes: Some(changes),
                ..Default::default()
            }))
        }
    }

    async fn prepare_rename(
        &self,
        params: TextDocumentPositionParams,
    ) -> Result<Option<PrepareRenameResponse>> {
        let uri = params.text_document.uri;
        let pos = params.position;

        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };
        let Some(program) = parsed_program else {
            return Ok(None);
        };

        let offset = position_to_offset(&source, pos);
        let Some((word, start, end)) = word_at_position(&source, offset) else {
            return Ok(None);
        };
        if keyword_docs(&word).is_some() || !is_valid_identifier(&word) {
            return Ok(None);
        }
        let local_occurrences = collect_symbol_occurrences(&source, &program);
        let Some(target) = resolve_symbol_target(&source, &program, offset, &local_occurrences)
        else {
            return Ok(None);
        };

        let docs = self.collect_navigation_documents(&uri, &source, &program);

        let has_definition = docs
            .iter()
            .any(|doc| has_target_definition(&doc.program, &target));
        if !has_definition {
            return Ok(None);
        }

        let range = offset_to_range(&source, start, end)
            .unwrap_or(Range::new(Position::new(0, 0), Position::new(0, 1)));
        Ok(Some(PrepareRenameResponse::RangeWithPlaceholder {
            range,
            placeholder: target.name,
        }))
    }

    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document.uri;
        let Some((source, _)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };

        let formatted = format_document_text(&source);
        if formatted == source {
            return Ok(None);
        }

        let edits = compute_minimal_edits(&source, &formatted);
        if edits.is_empty() {
            return Ok(None);
        }
        Ok(Some(edits))
    }

    async fn range_formatting(
        &self,
        params: DocumentRangeFormattingParams,
    ) -> Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document.uri;
        let Some((source, _)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };

        // Extend to full lines (LSP ranges may start/end mid-line).
        let start_line = params.range.start.line;
        let end_line = params.range.end.line;

        let edits = format_range_text(&source, start_line, end_line);
        if edits.is_empty() {
            return Ok(None);
        }
        Ok(Some(edits))
    }

    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>> {
        let uri = params.text_document.uri;
        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };

        let tokens = build_semantic_tokens(&source, parsed_program.as_ref(), None);
        Ok(Some(SemanticTokensResult::Tokens(tokens)))
    }

    async fn semantic_tokens_range(
        &self,
        params: SemanticTokensRangeParams,
    ) -> Result<Option<SemanticTokensRangeResult>> {
        let uri = params.text_document.uri;
        let Some((source, parsed_program)) = self.snapshot_document(&uri) else {
            return Ok(None);
        };

        let tokens = build_semantic_tokens(&source, parsed_program.as_ref(), Some(&params.range));
        Ok(Some(SemanticTokensRangeResult::Tokens(tokens)))
    }

    async fn symbol(
        &self,
        params: WorkspaceSymbolParams,
    ) -> Result<Option<Vec<SymbolInformation>>> {
        let docs = self.collect_workspace_symbol_documents();
        if docs.is_empty() {
            return Ok(None);
        }

        let mut symbols = Vec::new();
        for doc in &docs {
            symbols.extend(collect_workspace_symbol_information(
                &doc.source,
                &doc.program,
                &doc.uri,
                &params.query,
            ));
        }
        dedup_and_sort_workspace_symbols(&mut symbols);
        if symbols.len() > MAX_WORKSPACE_SYMBOL_RESULTS {
            symbols.truncate(MAX_WORKSPACE_SYMBOL_RESULTS);
        }

        if symbols.is_empty() {
            Ok(None)
        } else {
            Ok(Some(symbols))
        }
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = &params.text_document.uri;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let program = match &state.parsed {
            Some((program, _)) => program,
            None => return Ok(None),
        };

        let symbols = build_document_symbols(&state.source, program);
        if symbols.is_empty() {
            Ok(None)
        } else {
            Ok(Some(DocumentSymbolResponse::Nested(symbols)))
        }
    }

    async fn code_action(&self, params: CodeActionParams) -> Result<Option<CodeActionResponse>> {
        let uri = &params.text_document.uri;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let program = state.parsed.as_ref().map(|(p, _)| p);
        let actions = build_code_actions(uri, &state.source, program, &params.context.diagnostics);

        if actions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(actions))
        }
    }

    async fn inlay_hint(&self, params: InlayHintParams) -> Result<Option<Vec<InlayHint>>> {
        let uri = &params.text_document.uri;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let program = match &state.parsed {
            Some((program, _)) => program,
            None => return Ok(None),
        };

        let hints = build_inlay_hints(&state.source, program);
        if hints.is_empty() {
            Ok(None)
        } else {
            Ok(Some(hints))
        }
    }

    async fn folding_range(&self, params: FoldingRangeParams) -> Result<Option<Vec<FoldingRange>>> {
        let uri = &params.text_document.uri;

        let Ok(docs) = self.documents.read() else {
            return Ok(None);
        };
        let state = match docs.get(uri) {
            Some(s) => s,
            None => return Ok(None),
        };

        let program = match &state.parsed {
            Some((program, _)) => program,
            None => return Ok(None),
        };

        let ranges = build_folding_ranges(&state.source, program);
        if ranges.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ranges))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
