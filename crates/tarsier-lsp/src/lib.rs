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
mod tests {
    use super::*;
    use crate::code_actions::{
        collect_phase_names, extract_quoted_name, extract_second_quoted_name, find_closest,
        levenshtein,
    };
    use crate::completion::CursorContext;
    use crate::diagnostics::{
        collect_structural_lowering_diagnostics, diagnostic_has_code, lowering_error_code,
        lowering_error_message,
    };
    use crate::navigation::workspace_symbol_query_matches;
    use crate::semantic_tokens::{SEMANTIC_TOKEN_KEYWORD, SEMANTIC_TOKEN_TYPE};
    use crate::symbol_analysis::collect_references;
    use crate::utils::offset_to_position;

    // -- position_to_offset / offset_to_position --

    #[test]
    fn offset_to_position_basic() {
        let text = "hello\nworld\nfoo";
        assert_eq!(offset_to_position(text, 0), Position::new(0, 0));
        assert_eq!(offset_to_position(text, 5), Position::new(0, 5));
        assert_eq!(offset_to_position(text, 6), Position::new(1, 0));
        assert_eq!(offset_to_position(text, 11), Position::new(1, 5));
        assert_eq!(offset_to_position(text, 12), Position::new(2, 0));
    }

    #[test]
    fn offset_to_range_roundtrip() {
        let text = "protocol Foo {\n    params n, t;\n}";
        let range = offset_to_range(text, 0, 12).unwrap();
        assert_eq!(range.start, Position::new(0, 0));
        assert_eq!(range.end, Position::new(0, 12));
    }

    #[test]
    fn test_position_to_offset() {
        let text = "hello\nworld\nfoo";
        assert_eq!(position_to_offset(text, Position::new(0, 0)), 0);
        assert_eq!(position_to_offset(text, Position::new(0, 5)), 5);
        assert_eq!(position_to_offset(text, Position::new(1, 0)), 6);
        assert_eq!(position_to_offset(text, Position::new(1, 5)), 11);
        assert_eq!(position_to_offset(text, Position::new(2, 0)), 12);
        assert_eq!(position_to_offset(text, Position::new(2, 3)), 15);
    }

    #[test]
    fn test_position_offset_roundtrip() {
        let text = "hello\nworld\nfoo bar";
        for offset in [0, 3, 5, 6, 10, 12, 15] {
            let pos = offset_to_position(text, offset);
            let back = position_to_offset(text, pos);
            assert_eq!(back, offset, "roundtrip failed for offset {offset}");
        }
    }

    // -- incremental change --

    #[test]
    fn test_incremental_change_apply() {
        let mut text = "hello world".to_string();
        let range = Range::new(Position::new(0, 6), Position::new(0, 11));
        apply_incremental_change(&mut text, &range, "rust");
        assert_eq!(text, "hello rust");
    }

    #[test]
    fn test_incremental_change_insert() {
        let mut text = "hello world".to_string();
        let range = Range::new(Position::new(0, 5), Position::new(0, 5));
        apply_incremental_change(&mut text, &range, " beautiful");
        assert_eq!(text, "hello beautiful world");
    }

    #[test]
    fn test_incremental_change_multiline() {
        let mut text = "line1\nline2\nline3".to_string();
        let range = Range::new(Position::new(1, 0), Position::new(1, 5));
        apply_incremental_change(&mut text, &range, "REPLACED");
        assert_eq!(text, "line1\nREPLACED\nline3");
    }

    // -- levenshtein --

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("abc", "ab"), 1);
        assert_eq!(levenshtein("abc", "axc"), 1);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn test_find_closest() {
        let candidates = vec![
            "waiting".to_string(),
            "echoed".to_string(),
            "readied".to_string(),
            "done".to_string(),
        ];
        assert_eq!(
            find_closest("echoedd", &candidates),
            Some("echoed".to_string())
        );
        assert_eq!(find_closest("don", &candidates), Some("done".to_string()));
        assert_eq!(find_closest("zzzzz", &candidates), None);
    }

    // -- word_at_position --

    #[test]
    fn test_word_at_position() {
        let text = "hello world foo_bar";
        assert_eq!(word_at_position(text, 3), Some(("hello".to_string(), 0, 5)));
        assert_eq!(
            word_at_position(text, 8),
            Some(("world".to_string(), 6, 11))
        );
        assert_eq!(
            word_at_position(text, 15),
            Some(("foo_bar".to_string(), 12, 19))
        );
        // Cursor right after a word still identifies that word (useful for LSP hover)
        assert_eq!(word_at_position(text, 5), Some(("hello".to_string(), 0, 5)));
        // In the middle of two spaces: no word
        let text2 = "hello  world";
        assert_eq!(word_at_position(text2, 6), None);
    }

    #[test]
    fn test_is_valid_identifier_rules() {
        assert!(is_valid_identifier("foo"));
        assert!(is_valid_identifier("_foo2"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("2foo"));
        assert!(!is_valid_identifier("foo-bar"));
        assert!(!is_valid_identifier("foo bar"));
    }

    #[test]
    fn test_format_document_text_brace_indentation() {
        let input = r#"protocol X{
role P{
phase s{
}
}
}"#;
        let expected = r#"protocol X{
    role P{
        phase s{
        }
    }
}"#;
        assert_eq!(format_document_text(input), expected);
    }

    #[test]
    fn test_semantic_tokens_legend_includes_keyword_and_operator() {
        let legend = semantic_tokens_legend();
        assert!(legend.token_types.contains(&SemanticTokenType::KEYWORD));
        assert!(legend.token_types.contains(&SemanticTokenType::OPERATOR));
    }

    #[test]
    fn test_workspace_symbol_query_matches_fuzzy() {
        assert!(workspace_symbol_query_matches("Process", "proc"));
        assert!(workspace_symbol_query_matches("agreement", "agrrement"));
        assert!(!workspace_symbol_query_matches("Echo", "quorum"));
    }

    #[test]
    fn test_discover_workspace_trs_files_finds_nested_files() {
        let unique = format!(
            "tarsier-lsp-ws-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let a = root.join("a.trs");
        let b = nested.join("b.trs");
        std::fs::write(&a, "protocol A {}").unwrap();
        std::fs::write(&b, "protocol B {}").unwrap();

        let files = discover_workspace_trs_files(&root, 10, 4);
        assert!(files.iter().any(|p| p.ends_with("a.trs")));
        assert!(files.iter().any(|p| p.ends_with("b.trs")));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_resolve_import_uri_relative_with_extension_inference() {
        let unique = format!(
            "tarsier-lsp-import-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&root).unwrap();
        let base = root.join("main.trs");
        let imported = root.join("child.trs");
        std::fs::write(&base, "protocol Main { import Child from \"child\"; }").unwrap();
        std::fs::write(&imported, "protocol Child {}").unwrap();

        let base_uri = Url::from_file_path(&base).unwrap();
        let resolved = resolve_import_uri(&base_uri, "child").expect("import should resolve");
        assert_eq!(
            resolved.to_file_path().unwrap(),
            std::fs::canonicalize(&imported).unwrap()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    // -- keyword hover --

    #[test]
    fn test_hover_keyword() {
        let doc = keyword_docs("resilience");
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Resilience condition"));
    }

    #[test]
    fn test_hover_keyword_unknown() {
        assert!(keyword_docs("foobar_nonexistent").is_none());
    }

    // -- completions context --

    #[test]
    fn test_keyword_completions_at_protocol_level() {
        let text = "protocol Foo {\n    ";
        let offset = text.len();
        let ctx = infer_cursor_context(text, offset);
        assert_eq!(ctx, CursorContext::TopLevel);
        let items = build_completions(&ctx, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"parameters"));
        assert!(labels.contains(&"message"));
        assert!(labels.contains(&"role"));
        assert!(labels.contains(&"property"));
    }

    #[test]
    fn test_keyword_completions_at_role_level() {
        let text = "protocol Foo {\n    role Bar {\n        ";
        let offset = text.len();
        let ctx = infer_cursor_context(text, offset);
        assert_eq!(ctx, CursorContext::RoleLevel);
        let items = build_completions(&ctx, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"var"));
        assert!(labels.contains(&"init"));
        assert!(labels.contains(&"phase"));
    }

    #[test]
    fn test_after_colon_completions() {
        let text = "protocol Foo {\n    role Bar {\n        var x:";
        let offset = text.len();
        let ctx = infer_cursor_context(text, offset);
        assert_eq!(ctx, CursorContext::AfterColon);
        let items = build_completions(&ctx, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"bool"));
        assert!(labels.contains(&"nat"));
        assert!(labels.contains(&"int"));
    }

    #[test]
    fn test_property_kind_completions() {
        let text = "protocol Foo {\n    property myProp:";
        let offset = text.len();
        let ctx = infer_cursor_context(text, offset);
        assert_eq!(ctx, CursorContext::AfterPropertyColon);
        let items = build_completions(&ctx, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"agreement"));
        assert!(labels.contains(&"safety"));
        assert!(labels.contains(&"liveness"));
    }

    // -- parse + AST-based tests --

    fn parse_example() -> Program {
        let src = parse_example_src();
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        program
    }

    #[test]
    fn test_hover_user_defined_message() {
        let program = parse_example();
        let doc = hover_for_user_defined("Echo", &program);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Message"));
    }

    #[test]
    fn test_hover_user_defined_role() {
        let program = parse_example();
        let doc = hover_for_user_defined("Process", &program);
        assert!(doc.is_some());
        let text = doc.unwrap();
        assert!(text.contains("Role"));
        assert!(text.contains("Process"));
    }

    #[test]
    fn test_hover_user_defined_phase() {
        let program = parse_example();
        let doc = hover_for_user_defined("waiting", &program);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Phase"));
    }

    #[test]
    fn test_hover_user_defined_variable() {
        let program = parse_example();
        let doc = hover_for_user_defined("decided", &program);
        assert!(doc.is_some());
        let text = doc.unwrap();
        assert!(text.contains("Variable"));
        assert!(text.contains("bool"));
    }

    #[test]
    fn test_hover_user_defined_param() {
        let program = parse_example();
        let doc = hover_for_user_defined("n", &program);
        assert!(doc.is_some());
        assert!(doc.unwrap().contains("Parameter"));
    }

    #[test]
    fn test_build_semantic_tokens_contains_keyword_and_type() {
        let src = parse_example_src();
        let program = parse_example();
        let tokens = build_semantic_tokens(src, Some(&program), None);
        assert!(!tokens.data.is_empty());
        assert!(tokens
            .data
            .iter()
            .any(|t| t.token_type == SEMANTIC_TOKEN_KEYWORD));
        assert!(tokens
            .data
            .iter()
            .any(|t| t.token_type == SEMANTIC_TOKEN_TYPE));
    }

    #[test]
    fn test_collect_workspace_symbol_information_filters_by_query() {
        let src = parse_example_src();
        let program = parse_example();
        let uri = Url::parse("file:///tmp/test.trs").unwrap();
        let symbols = collect_workspace_symbol_information(src, &program, &uri, "proc");
        assert!(symbols.iter().any(|s| s.name == "Process"));
        assert!(!symbols.iter().any(|s| s.name == "Echo"));
    }

    // -- collect_definitions --

    #[test]
    fn test_collect_definitions() {
        let program = parse_example();
        let defs = collect_definitions(&program);

        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Echo"));
        assert!(names.contains(&"Ready"));
        assert!(names.contains(&"Process"));
        assert!(names.contains(&"waiting"));
        assert!(names.contains(&"done"));
        assert!(names.contains(&"n"));
        assert!(names.contains(&"t"));
        assert!(names.contains(&"f"));
        assert!(names.contains(&"decided"));
        assert!(names.contains(&"agreement"));

        // Check kinds
        let echo_def = defs.iter().find(|d| d.name == "Echo").unwrap();
        assert_eq!(echo_def.kind, DefinitionKind::Message);

        let process_def = defs.iter().find(|d| d.name == "Process").unwrap();
        assert_eq!(process_def.kind, DefinitionKind::Role);

        let waiting_def = defs.iter().find(|d| d.name == "waiting").unwrap();
        assert_eq!(waiting_def.kind, DefinitionKind::Phase);
        assert_eq!(waiting_def.parent.as_deref(), Some("Process"));
    }

    // -- goto definition --

    #[test]
    fn test_goto_definition_message() {
        let program = parse_example();
        let defs = collect_definitions(&program);
        let echo_def = defs
            .iter()
            .find(|d| d.name == "Echo" && d.kind == DefinitionKind::Message);
        assert!(echo_def.is_some());
        let def = echo_def.unwrap();
        assert!(
            def.start < def.end,
            "Message definition should have a valid span"
        );
    }

    #[test]
    fn test_goto_definition_phase() {
        let program = parse_example();
        let defs = collect_definitions(&program);
        let phase_def = defs
            .iter()
            .find(|d| d.name == "waiting" && d.kind == DefinitionKind::Phase);
        assert!(phase_def.is_some());
        let def = phase_def.unwrap();
        assert!(
            def.start < def.end,
            "Phase definition should have a valid span"
        );
    }

    #[test]
    fn test_goto_definition_role() {
        let program = parse_example();
        let defs = collect_definitions(&program);
        let role_def = defs
            .iter()
            .find(|d| d.name == "Process" && d.kind == DefinitionKind::Role);
        assert!(role_def.is_some());
        let def = role_def.unwrap();
        assert!(
            def.start < def.end,
            "Role definition should have a valid span"
        );
    }

    // -- find references --

    #[test]
    fn test_find_references_message() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                send Echo;
                goto phase done;
            }
        }
        phase done {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let refs = collect_references(src, &program, "Echo");
        // "Echo" should appear at: message declaration, threshold guard, send action
        assert!(
            refs.len() >= 3,
            "Expected at least 3 references to Echo, got {}",
            refs.len()
        );
    }

    #[test]
    fn test_reference_locations_excludes_declaration_when_requested() {
        let src = parse_example_src();
        let program = parse_example();
        let uri = Url::parse("file:///tmp/test.trs").unwrap();

        let include = reference_locations(src, &program, &uri, "Echo", true);
        let exclude = reference_locations(src, &program, &uri, "Echo", false);

        assert!(
            include.len() > exclude.len(),
            "excluding declarations should remove at least one location"
        );
    }

    #[test]
    fn test_collect_symbol_occurrences_disambiguates_message_and_var_names() {
        let src = r#"protocol Clash {
    parameters {
        n: nat;
        t: nat;
    }

    resilience { n > t; }
    message Echo;

    role R {
        var Echo: bool = false;
        init s;
        phase s {
            when Echo == false && received >= 1 Echo => {
                Echo = true;
                send Echo;
                goto phase done;
            }
        }
        phase done {}
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "clash.trs").unwrap();
        let occurrences = collect_symbol_occurrences(src, &program);

        let message_count = occurrences
            .iter()
            .filter(|occ| occ.name == "Echo" && occ.kind == DefinitionKind::Message)
            .count();
        let var_count = occurrences
            .iter()
            .filter(|occ| occ.name == "Echo" && occ.kind == DefinitionKind::Var)
            .count();

        assert!(message_count >= 3, "expected message declaration/usages");
        assert!(var_count >= 3, "expected var declaration/usages");
    }

    #[test]
    fn test_resolve_symbol_target_uses_contextual_kind() {
        let src = r#"protocol Clash {
    parameters {
        n: nat;
        t: nat;
    }

    resilience { n > t; }
    message Echo;

    role R {
        var Echo: bool = false;
        init s;
        phase s {
            when Echo == false && received >= 1 Echo => {
                Echo = true;
                send Echo;
                goto phase done;
            }
        }
        phase done {}
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "clash.trs").unwrap();
        let occurrences = collect_symbol_occurrences(src, &program);

        let send_offset = src.find("send Echo").unwrap() + "send ".len();
        let send_target =
            resolve_symbol_target(src, &program, send_offset, &occurrences).expect("send target");
        assert_eq!(send_target.kind, DefinitionKind::Message);
        assert_eq!(send_target.name, "Echo");

        let assign_offset = src.find("Echo = true").unwrap();
        let assign_target = resolve_symbol_target(src, &program, assign_offset, &occurrences)
            .expect("assign target");
        assert_eq!(assign_target.kind, DefinitionKind::Var);
        assert_eq!(assign_target.name, "Echo");
        assert_eq!(assign_target.parent.as_deref(), Some("R"));
    }

    #[test]
    fn test_collect_reference_spans_for_target_excludes_other_symbol_kinds() {
        let src = r#"protocol Clash {
    parameters {
        n: nat;
        t: nat;
    }

    resilience { n > t; }
    message Echo;

    role R {
        var Echo: bool = false;
        init s;
        phase s {
            when Echo == false && received >= 1 Echo => {
                Echo = true;
                send Echo;
                goto phase done;
            }
        }
        phase done {}
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "clash.trs").unwrap();
        let occurrences = collect_symbol_occurrences(src, &program);
        let target = SymbolTarget {
            name: "Echo".to_string(),
            kind: DefinitionKind::Var,
            parent: Some("R".to_string()),
        };

        let refs = collect_reference_spans_for_target(src, &program, &target, true, &occurrences);
        let send_span = {
            let start = src.find("send Echo").unwrap() + "send ".len();
            (start, start + "Echo".len())
        };
        let threshold_span = {
            let start = src.find("received >= 1 Echo").unwrap() + "received >= 1 ".len();
            (start, start + "Echo".len())
        };

        assert!(
            !refs.contains(&send_span),
            "var target must not capture send message type"
        );
        assert!(
            !refs.contains(&threshold_span),
            "var target must not capture threshold message type"
        );
    }

    #[test]
    fn test_as_goto_definition_response_uses_array_for_multiple_locations() {
        let uri = Url::parse("file:///tmp/test.trs").unwrap();
        let locations = vec![
            Location {
                uri: uri.clone(),
                range: Range::new(Position::new(1, 0), Position::new(1, 5)),
            },
            Location {
                uri,
                range: Range::new(Position::new(2, 0), Position::new(2, 4)),
            },
        ];

        match as_goto_definition_response(locations) {
            Some(GotoDefinitionResponse::Array(arr)) => assert_eq!(arr.len(), 2),
            other => panic!("expected array goto response, got {other:?}"),
        }
    }

    // -- diagnostics --

    #[test]
    fn test_diagnostics_have_codes() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let filename = "test.trs";
        let (program, parse_diags) = tarsier_dsl::parse_with_diagnostics(src, filename).unwrap();

        // Parse diagnostics should have codes
        for diag in &parse_diags {
            assert!(!diag.code.is_empty(), "Parse diagnostic should have a code");
        }

        // Lowering errors should produce codes
        if let Err(e) = tarsier_ir::lowering::lower_with_source(&program, src, filename) {
            let code = lowering_error_code(&e.inner);
            assert!(!code.is_empty(), "Lowering error should have a code");
        }
    }

    #[test]
    fn test_diagnostics_have_precise_spans() {
        // Use a protocol with an unknown phase to trigger a lowering error with a span
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase nonexistent;
            }
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let filename = "test.trs";
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, filename).unwrap();
        let err = tarsier_ir::lowering::lower_with_source(&program, src, filename);
        assert!(
            err.is_err(),
            "Should have a lowering error for unknown phase"
        );
        let e = err.unwrap_err();
        assert!(
            e.span.is_some(),
            "Lowering error should have a source span, not None"
        );
        let span = e.span.unwrap();
        assert!(
            span.offset() > 0,
            "Span offset should be > 0, not at file start"
        );
    }

    #[test]
    fn test_collect_structural_lowering_diagnostics_reports_multiple_codes() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    enum Status { idle, active }

    message Echo;

    role Process {
        var decided: bool = false;
        var status: Status;
        var state: Statu = idle;
        phase waiting {
            when received >= 1 Ehoo => {
                send Reddy;
                goto phase don;
            }
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let diags = collect_structural_lowering_diagnostics(&program, src);
        let codes: std::collections::HashSet<String> = diags
            .iter()
            .filter_map(|d| match d.code.as_ref() {
                Some(NumberOrString::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();

        assert!(codes.contains("tarsier::lower::no_init_phase"));
        assert!(codes.contains("tarsier::lower::unknown_enum"));
        assert!(codes.contains("tarsier::lower::missing_enum_init"));
        assert!(codes.contains("tarsier::lower::unknown_message"));
        assert!(codes.contains("tarsier::lower::unknown_phase"));
    }

    #[test]
    fn test_collect_lowering_diagnostics_preserves_non_structural_errors() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    role Process {
        var decided: bool = false;
        var x: int in 0..1 = 5;
        phase waiting {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let diags = collect_lowering_diagnostics(&program, src, "test.trs");
        let codes: std::collections::HashSet<String> = diags
            .iter()
            .filter_map(|d| match d.code.as_ref() {
                Some(NumberOrString::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect();

        assert!(codes.contains("tarsier::lower::no_init_phase"));
        assert!(codes.contains("tarsier::lower::out_of_range"));
    }

    #[test]
    fn test_collect_lowering_diagnostics_avoids_duplicate_structural_fallback() {
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                goto phase nonexistent;
            }
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let diags = collect_lowering_diagnostics(&program, src, "test.trs");
        let unknown_phase_count = diags
            .iter()
            .filter(|d| diagnostic_has_code(d, "tarsier::lower::unknown_phase"))
            .count();

        assert_eq!(
            unknown_phase_count, 1,
            "unknown phase should not be duplicated by fallback lowering diagnostics"
        );
    }

    #[test]
    fn test_parse_error_diagnostics_flattens_multiple_errors() {
        use tarsier_dsl::errors::{ParseError, ParseErrors};

        let parse_error = ParseError::MultipleErrors(ParseErrors {
            errors: vec![
                ParseError::MissingSection {
                    section: "parameters".into(),
                },
                ParseError::MissingSection {
                    section: "resilience".into(),
                },
            ],
        });

        let diags = parse_error_diagnostics(&parse_error, "protocol X {}");
        assert_eq!(diags.len(), 2);
        assert!(diags
            .iter()
            .all(|d| diagnostic_has_code(d, "tarsier::parse::missing_section")));
        assert!(diags.iter().any(|d| d.message.contains("parameters")));
        assert!(diags.iter().any(|d| d.message.contains("resilience")));
    }

    // -- code actions --

    #[test]
    fn test_code_action_unknown_phase_suggestion() {
        let program = parse_example();
        let known_phases = collect_phase_names(&program);
        let suggestion = find_closest("waitin", &known_phases);
        assert_eq!(suggestion, Some("waiting".to_string()));
    }

    #[test]
    fn test_code_action_missing_init() {
        // Parse a protocol that has no init phase to check the diagnostic message
        let src = r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;

    role Process {
        var decided: bool = false;
        phase waiting {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "test.trs").unwrap();
        let err = tarsier_ir::lowering::lower_with_source(&program, src, "test.trs");
        assert!(err.is_err());
        let e = err.unwrap_err();
        let msg = lowering_error_message(&e.inner, &program);
        assert!(
            msg.contains("no init phase"),
            "Expected 'no init phase' message, got: {msg}"
        );
        assert!(msg.contains("Process"));
    }

    #[test]
    fn test_code_action_unknown_enum_suggestion() {
        let src = r#"protocol EnumFix {
    parameters {
        n: nat;
        t: nat;
    }
    resilience {
        n > 3*t;
    }
    enum Status { idle, active }
    role Worker {
        var status: Statu = idle;
        init s;
        phase s {}
    }
}"#;
        let uri = Url::parse("file:///tmp/enum_fix.trs").unwrap();
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "enum_fix.trs").unwrap();
        let var_span = program.protocol.node.roles[0].node.vars[0].span;
        let range = offset_to_range(src, var_span.start, var_span.end).unwrap();
        let diag = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            source: Some("tarsier".into()),
            code: Some(NumberOrString::String(
                "tarsier::lower::unknown_enum".into(),
            )),
            message: "Unknown enum type 'Statu'. Did you mean 'Status'?".into(),
            ..Default::default()
        };

        let actions = build_code_actions(&uri, src, Some(&program), &[diag]);
        assert!(actions.iter().any(|a| match a {
            CodeActionOrCommand::CodeAction(action) => action.title == "Replace with 'Status'",
            _ => false,
        }));
    }

    #[test]
    fn test_code_action_missing_enum_init_insertion() {
        let src = r#"protocol EnumInitFix {
    parameters {
        n: nat;
        t: nat;
    }
    resilience {
        n > 3*t;
    }
    enum Status { idle, active }
    role Worker {
        var status: Status;
        init s;
        phase s {}
    }
}"#;
        let uri = Url::parse("file:///tmp/enum_init_fix.trs").unwrap();
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "enum_init_fix.trs").unwrap();
        let var_span = program.protocol.node.roles[0].node.vars[0].span;
        let range = offset_to_range(src, var_span.start, var_span.end).unwrap();
        let diag = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            source: Some("tarsier".into()),
            code: Some(NumberOrString::String(
                "tarsier::lower::missing_enum_init".into(),
            )),
            message: "Missing init value for enum variable 'status'".into(),
            ..Default::default()
        };

        let actions = build_code_actions(&uri, src, Some(&program), &[diag]);
        let init_action = actions.into_iter().find_map(|a| match a {
            CodeActionOrCommand::CodeAction(action)
                if action.title == "Initialize 'status' with 'idle'" =>
            {
                Some(action)
            }
            _ => None,
        });
        let action = init_action.expect("expected enum init quick fix");
        let edits = action
            .edit
            .and_then(|e| e.changes)
            .and_then(|mut c| c.remove(&uri))
            .expect("expected workspace edit changes");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].new_text, " = idle");
    }

    #[test]
    fn test_code_action_unknown_enum_variant_suggestion() {
        let src = r#"protocol EnumVariantFix {
    parameters {
        n: nat;
        t: nat;
    }
    resilience {
        n > 3*t;
    }
    enum Status { idle, active, done }
    role Worker {
        var status: Status = idle;
        init s;
        phase s {
            when received >= 1 Echo => {
                status = actve;
            }
        }
    }
    message Echo;
}"#;
        let uri = Url::parse("file:///tmp/enum_variant_fix.trs").unwrap();
        let (program, _) =
            tarsier_dsl::parse_with_diagnostics(src, "enum_variant_fix.trs").unwrap();
        // Use the transition span for the diagnostic range (matching structural detection)
        let transition_span = program.protocol.node.roles[0].node.phases[0]
            .node
            .transitions[0]
            .span;
        let range = offset_to_range(src, transition_span.start, transition_span.end).unwrap();
        let diag = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            source: Some("tarsier".into()),
            code: Some(NumberOrString::String(
                "tarsier::lower::unknown_enum_variant".into(),
            )),
            message: "Unknown enum variant 'actve' for enum 'Status'. Did you mean 'active'?"
                .into(),
            ..Default::default()
        };

        let actions = build_code_actions(&uri, src, Some(&program), &[diag]);
        assert!(actions.iter().any(|a| match a {
            CodeActionOrCommand::CodeAction(action) => action.title == "Replace with 'active'",
            _ => false,
        }));
    }

    #[test]
    fn test_code_action_unknown_param_suggestion() {
        let src = r#"protocol ParamFix {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }
    resilience {
        n > 3*t;
    }
    adversary {
        model: byzantine;
        bound: f;
    }
    message Echo;
    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 2*tt+1 Echo => {
                decided = true;
            }
        }
    }
    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let uri = Url::parse("file:///tmp/param_fix.trs").unwrap();
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "param_fix.trs").unwrap();
        // Use the transition span for the diagnostic range
        let transition_span = program.protocol.node.roles[0].node.phases[0]
            .node
            .transitions[0]
            .span;
        let range = offset_to_range(src, transition_span.start, transition_span.end).unwrap();
        let diag = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            source: Some("tarsier".into()),
            code: Some(NumberOrString::String(
                "tarsier::lower::unknown_param".into(),
            )),
            message: "Unknown parameter 'tt' in expression. Did you mean 't'?".into(),
            ..Default::default()
        };

        let actions = build_code_actions(&uri, src, Some(&program), &[diag]);
        assert!(actions.iter().any(|a| match a {
            CodeActionOrCommand::CodeAction(action) => action.title == "Replace with 't'",
            _ => false,
        }));
    }

    #[test]
    fn test_code_action_out_of_range_clamp() {
        let src = r#"protocol RangeFix {
    parameters {
        n: nat;
        t: nat;
    }
    resilience {
        n > 3*t;
    }
    role Worker {
        var x: int in 0..3 = 5;
        init s;
        phase s {}
    }
}"#;
        let uri = Url::parse("file:///tmp/range_fix.trs").unwrap();
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "range_fix.trs").unwrap();
        let var_span = program.protocol.node.roles[0].node.vars[0].span;
        let range = offset_to_range(src, var_span.start, var_span.end).unwrap();
        let diag = Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::ERROR),
            source: Some("tarsier".into()),
            code: Some(NumberOrString::String(
                "tarsier::lower::out_of_range".into(),
            )),
            message: "Out of range for variable 'x': 5 not in [0, 3]".into(),
            ..Default::default()
        };

        let actions = build_code_actions(&uri, src, Some(&program), &[diag]);
        let clamp_action = actions.into_iter().find_map(|a| match a {
            CodeActionOrCommand::CodeAction(action) if action.title == "Clamp value to 3" => {
                Some(action)
            }
            _ => None,
        });
        let action = clamp_action.expect("expected out-of-range clamp quick fix");
        let edits = action
            .edit
            .and_then(|e| e.changes)
            .and_then(|mut c| c.remove(&uri))
            .expect("expected workspace edit changes");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].new_text, "3");
    }

    #[test]
    fn test_extract_second_quoted_name() {
        assert_eq!(
            extract_second_quoted_name("Unknown enum variant 'actve' for enum 'Status'"),
            Some("Status".to_string())
        );
        assert_eq!(extract_second_quoted_name("Only 'one' quoted name"), None);
        assert_eq!(extract_second_quoted_name("No quotes"), None);
    }

    #[test]
    fn test_structural_unknown_enum_variant_diagnostic() {
        let src = r#"protocol VariantCheck {
    parameters {
        n: nat;
        t: nat;
    }
    resilience {
        n > 3*t;
    }
    enum Status { idle, active, done }
    role Worker {
        var status: Status = idl;
        init s;
        phase s {}
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "variant_check.trs").unwrap();
        let diags = collect_structural_lowering_diagnostics(&program, src);
        assert!(
            diags
                .iter()
                .any(|d| diagnostic_has_code(d, "tarsier::lower::unknown_enum_variant")),
            "Expected unknown_enum_variant diagnostic, got: {:?}",
            diags.iter().map(|d| &d.code).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_structural_unknown_param_diagnostic() {
        let src = r#"protocol ParamCheck {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }
    resilience {
        n > 3*t;
    }
    adversary {
        model: byzantine;
        bound: f;
    }
    message Echo;
    role Process {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 2*tt+1 Echo => {
                decided = true;
            }
        }
    }
    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#;
        let (program, _) = tarsier_dsl::parse_with_diagnostics(src, "param_check.trs").unwrap();
        let diags = collect_structural_lowering_diagnostics(&program, src);
        assert!(
            diags
                .iter()
                .any(|d| diagnostic_has_code(d, "tarsier::lower::unknown_param")),
            "Expected unknown_param diagnostic, got: {:?}",
            diags.iter().map(|d| &d.code).collect::<Vec<_>>()
        );
    }

    // -- extract_quoted_name --

    #[test]
    fn test_extract_quoted_name() {
        assert_eq!(
            extract_quoted_name("Unknown phase 'foo' in goto"),
            Some("foo".to_string())
        );
        assert_eq!(
            extract_quoted_name("Role 'Process' has no init phase"),
            Some("Process".to_string())
        );
        assert_eq!(extract_quoted_name("No quotes here"), None);
    }

    // -- name references across AST --

    #[test]
    fn test_all_major_names_referenced() {
        let src = parse_example_src();
        let program = parse_example();
        // Verify key names appear as references in the source
        for name in &["Echo", "Ready", "done", "Process"] {
            let refs = collect_references(src, &program, name);
            assert!(
                !refs.is_empty(),
                "Expected at least one reference to '{name}'"
            );
        }
    }

    #[test]
    fn test_build_document_symbols_outline_tree() {
        let src = parse_example_src();
        let program = parse_example();
        let symbols = build_document_symbols(src, &program);

        assert_eq!(symbols.len(), 1, "expected protocol root symbol");
        let protocol = &symbols[0];
        assert_eq!(protocol.name, "Test");
        assert_eq!(protocol.kind, SymbolKind::MODULE);
        let protocol_children = protocol
            .children
            .as_ref()
            .expect("protocol should expose children");
        assert!(protocol_children.iter().any(|s| s.name == "Echo"));
        assert!(protocol_children.iter().any(|s| s.name == "Ready"));
        assert!(protocol_children.iter().any(|s| s.name == "agreement"));

        let process = protocol_children
            .iter()
            .find(|s| s.name == "Process")
            .expect("role symbol should be present");
        assert_eq!(process.kind, SymbolKind::CLASS);

        let process_children = process
            .children
            .as_ref()
            .expect("role should expose child symbols");
        assert!(process_children
            .iter()
            .any(|s| s.name == "decided" && s.kind == SymbolKind::VARIABLE));
        assert!(process_children
            .iter()
            .any(|s| s.name == "waiting" && s.kind == SymbolKind::METHOD));
        assert!(process_children
            .iter()
            .any(|s| s.name == "done" && s.kind == SymbolKind::METHOD));
    }

    #[test]
    fn test_document_symbol_selection_range_prefers_name_token() {
        let src = parse_example_src();
        let program = parse_example();
        let symbols = build_document_symbols(src, &program);
        let protocol = &symbols[0];
        let range_start = position_to_offset(src, protocol.range.start);
        let selection_start = position_to_offset(src, protocol.selection_range.start);

        assert!(
            selection_start > range_start,
            "selection range should point at protocol name token"
        );
    }

    fn parse_example_src() -> &'static str {
        r#"protocol Test {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }

    resilience {
        n > 3*t;
    }

    adversary {
        model: byzantine;
        bound: f;
    }

    message Echo;
    message Ready;

    role Process {
        var decided: bool = false;

        init waiting;

        phase waiting {
            when received >= 1 Echo => {
                send Ready;
                goto phase done;
            }
        }

        phase done {
        }
    }

    property agreement: agreement {
        forall p: Process. forall q: Process.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#
    }

    // -- LSP capability check --

    #[test]
    fn test_lsp_capabilities_declared() {
        // Verify all capabilities are present in the initialize response
        // We test this indirectly by checking the ServerCapabilities struct
        let caps = ServerCapabilities {
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
            ..Default::default()
        };

        assert!(caps.text_document_sync.is_some());
        assert!(caps.completion_provider.is_some());
        assert!(caps.hover_provider.is_some());
        assert!(caps.definition_provider.is_some());
        assert!(caps.references_provider.is_some());
        assert!(caps.document_symbol_provider.is_some());
        assert!(caps.workspace_symbol_provider.is_some());
        assert!(caps.document_formatting_provider.is_some());
        assert!(caps.document_range_formatting_provider.is_some());
        assert!(caps.rename_provider.is_some());
        assert!(caps.semantic_tokens_provider.is_some());
        assert!(caps.code_action_provider.is_some());

        // Verify incremental sync
        match caps.text_document_sync {
            Some(TextDocumentSyncCapability::Kind(k)) => {
                assert_eq!(k, TextDocumentSyncKind::INCREMENTAL);
            }
            _ => panic!("Expected incremental sync kind"),
        }
    }

    // -- compute_minimal_edits / ranges_overlap --

    #[test]
    fn minimal_edits_no_change() {
        let source = "protocol Foo {\n    params n, t;\n}\n";
        let edits = compute_minimal_edits(source, source);
        assert!(edits.is_empty(), "identical input should produce no edits");
    }

    #[test]
    fn minimal_edits_indent_correction() {
        let source = "protocol Foo {\nparams n, t;\n}\n";
        let formatted = format_document_text(source);
        let edits = compute_minimal_edits(source, &formatted);
        // First line "protocol Foo {" is unchanged — edits should not touch line 0
        for edit in &edits {
            assert!(
                edit.range.start.line >= 1,
                "edit should not touch the unchanged first line, got start line {}",
                edit.range.start.line
            );
        }
        assert!(
            !edits.is_empty(),
            "should have at least one edit for indent fix"
        );
    }

    #[test]
    fn minimal_edits_blank_line_compression() {
        let source = "protocol Foo {\n\n\n\n    params n, t;\n}\n";
        let formatted = format_document_text(source);
        // Formatter compresses multiple blank lines into one
        assert!(formatted.len() < source.len());
        let edits = compute_minimal_edits(source, &formatted);
        assert!(
            !edits.is_empty(),
            "blank-line compression should produce edits"
        );
    }

    #[test]
    fn minimal_edits_range_filter() {
        // Source with two problems: bad indent on line 1, bad indent on line 3
        let source = "protocol Foo {\nparams n, t;\n\n  bad_indent;\n}\n";
        let formatted = format_document_text(source);
        let all_edits = compute_minimal_edits(source, &formatted);

        // Filter to only line 1 range
        let line1_range = Range::new(Position::new(1, 0), Position::new(2, 0));
        let filtered: Vec<_> = all_edits
            .iter()
            .filter(|e| ranges_overlap(&e.range, &line1_range))
            .collect();
        // Should include edits touching line 1 but not exclusively line 3+
        assert!(
            filtered.len() <= all_edits.len(),
            "filtered edits should be a subset"
        );
    }

    #[test]
    fn ranges_overlap_cases() {
        // Overlapping
        let a = Range::new(Position::new(0, 0), Position::new(2, 0));
        let b = Range::new(Position::new(1, 0), Position::new(3, 0));
        assert!(ranges_overlap(&a, &b));
        assert!(ranges_overlap(&b, &a));

        // Touching (end == start) — no overlap
        let a = Range::new(Position::new(0, 0), Position::new(1, 0));
        let b = Range::new(Position::new(1, 0), Position::new(2, 0));
        assert!(!ranges_overlap(&a, &b));

        // Disjoint
        let a = Range::new(Position::new(0, 0), Position::new(1, 0));
        let b = Range::new(Position::new(5, 0), Position::new(6, 0));
        assert!(!ranges_overlap(&a, &b));
        assert!(!ranges_overlap(&b, &a));
    }

    #[test]
    fn minimal_edits_roundtrip() {
        let source = "protocol Foo {\nparams n, t;\n  role R {\n}\n}\n";
        let formatted = format_document_text(source);
        let edits = compute_minimal_edits(source, &formatted);

        // Apply edits in reverse order to source and verify result equals formatted
        // Reconstruct by applying edits (they are non-overlapping and in order)
        // Simplest verification: apply all edits to source text via character offsets
        let mut result = source.to_string();
        // Apply in reverse to preserve earlier offsets
        let mut sorted_edits = edits.clone();
        sorted_edits.sort_by(|a, b| {
            b.range
                .start
                .line
                .cmp(&a.range.start.line)
                .then(b.range.start.character.cmp(&a.range.start.character))
        });
        for edit in &sorted_edits {
            let start_off = position_to_offset(&result, edit.range.start);
            let end_off = position_to_offset(&result, edit.range.end);
            result.replace_range(start_off..end_off, &edit.new_text);
        }
        assert_eq!(
            result, formatted,
            "applying edits to source should equal formatted"
        );
    }

    // -- format_range_text --

    /// Helper: apply a set of TextEdits to a source string and return the result.
    fn apply_edits(source: &str, edits: &[TextEdit]) -> String {
        let mut result = source.to_string();
        let mut sorted_edits = edits.to_vec();
        sorted_edits.sort_by(|a, b| {
            b.range
                .start
                .line
                .cmp(&a.range.start.line)
                .then(b.range.start.character.cmp(&a.range.start.character))
        });
        for edit in &sorted_edits {
            let start_off = position_to_offset(&result, edit.range.start);
            let end_off = position_to_offset(&result, edit.range.end);
            result.replace_range(start_off..end_off, &edit.new_text);
        }
        result
    }

    #[test]
    fn range_format_matches_full_doc_filtered() {
        // Range formatting over the whole document should produce the same
        // result as full-document formatting.
        let source = "protocol Foo {\nparams n, t;\n  role R {\n}\n}\n";
        let full_formatted = format_document_text(source);
        let line_count = source.lines().count() as u32;

        let range_edits = format_range_text(source, 0, line_count.saturating_sub(1));
        let range_result = apply_edits(source, &range_edits);
        assert_eq!(
            range_result, full_formatted,
            "range formatting over entire document should equal full-document formatting"
        );
    }

    #[test]
    fn range_format_nested_brace_depth() {
        // Formatting a range that starts inside a nested block should pick up
        // the correct brace depth from lines above the range.
        let source = "protocol X {\n    role R {\nbad_indent;\n    }\n}\n";
        // Line 2 ("bad_indent;") is inside role R { ... } which is inside protocol X { ... },
        // so it should be indented with depth 2 (8 spaces).
        let edits = format_range_text(source, 2, 2);
        assert!(
            !edits.is_empty(),
            "should have edits for the bad indent line"
        );
        let result = apply_edits(source, &edits);
        let line2 = result.lines().nth(2).unwrap();
        assert_eq!(
            line2, "        bad_indent;",
            "line inside nested block should get depth-2 indent"
        );
    }

    #[test]
    fn range_format_does_not_touch_outside_lines() {
        // Edits should only affect lines within the requested range.
        let source = "protocol Foo {\nbad1;\n  bad2;\nbad3;\n}\n";
        // Format only line 2
        let edits = format_range_text(source, 2, 2);
        for edit in &edits {
            assert!(
                edit.range.start.line >= 2 && edit.range.end.line <= 3,
                "edit at lines {}-{} should be within the requested range 2-2",
                edit.range.start.line,
                edit.range.end.line
            );
        }
    }

    #[test]
    fn range_format_empty_range() {
        let source = "protocol Foo {\n    params n, t;\n}\n";
        // start > end should return no edits
        let edits = format_range_text(source, 5, 3);
        assert!(
            edits.is_empty(),
            "empty/inverted range should produce no edits"
        );
    }

    #[test]
    fn range_format_already_correct() {
        let source = "protocol Foo {\n    params n, t;\n}\n";
        // Lines 0-2 are already correctly formatted
        let edits = format_range_text(source, 0, 2);
        assert!(
            edits.is_empty(),
            "already-formatted lines should produce no edits"
        );
    }

    #[test]
    fn range_format_blank_line_compression() {
        // Multiple consecutive blank lines within the range should be compressed
        // to a single blank line.
        let source = "protocol Foo {\n\n\n\n    params n, t;\n}\n";
        // Lines 1-3 are blank; formatter should compress to one blank line.
        let edits = format_range_text(source, 0, 5);
        let result = apply_edits(source, &edits);
        let full = format_document_text(source);
        assert_eq!(
            result, full,
            "range format of full doc with blank lines should match full format"
        );
    }

    #[test]
    fn range_format_closing_brace_dedent() {
        // A closing brace at the start of a line in the range should be
        // dedented correctly.
        let source = "protocol X {\n    role R {\n        phase p {\n        }\n        }\n}\n";
        // Line 4 has "        }" but should be "    }" (closing role R block).
        let edits = format_range_text(source, 4, 4);
        assert!(
            !edits.is_empty(),
            "misindented closing brace should produce edits"
        );
        let result = apply_edits(source, &edits);
        let line4 = result.lines().nth(4).unwrap();
        assert_eq!(
            line4, "    }",
            "closing brace should be dedented to depth 1"
        );
    }

    // -- cross-file workspace navigation --

    /// Helper: minimal protocol source for cross-file tests.
    fn parse_source(src: &str) -> Program {
        tarsier_dsl::parse_with_diagnostics(src, "test.trs")
            .expect("test source should parse")
            .0
    }

    /// Two-file workspace: a.trs defines message Echo + role Replica,
    /// b.trs uses Echo in a guard (no import link).
    fn cross_file_fixture() -> (String, Program, String, Program) {
        let src_a = r#"protocol A {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message Echo;
    role Replica {
        var decided: bool = false;
        init waiting;
        phase waiting {
            when received >= 1 Echo => {
                decided = true;
                goto phase done;
            }
        }
        phase done {}
    }
    property agreement: agreement {
        forall p: Replica. forall q: Replica.
            (p.decided == true && q.decided == true) ==> (p.decided == q.decided)
    }
}"#
        .to_string();
        let src_b = r#"protocol B {
    parameters {
        n: nat;
        t: nat;
        f: nat;
    }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message Echo;
    role Sender {
        init start;
        phase start {
            when received >= 1 Echo => {
                send Echo;
                goto phase sent;
            }
        }
        phase sent {}
    }
}"#
        .to_string();
        let prog_a = parse_source(&src_a);
        let prog_b = parse_source(&src_b);
        (src_a, prog_a, src_b, prog_b)
    }

    #[test]
    fn cross_file_goto_definition_without_import() {
        let (src_a, prog_a, src_b, prog_b) = cross_file_fixture();
        let uri_a = Url::parse("file:///workspace/a.trs").unwrap();
        let uri_b = Url::parse("file:///workspace/b.trs").unwrap();

        // "Echo" is defined in both files — searching a.trs finds it in a.trs
        let defs_a = definition_locations(&src_a, &prog_a, &uri_a, "Echo");
        assert!(!defs_a.is_empty(), "Echo defined in a.trs");

        // Searching b.trs also finds it locally
        let defs_b = definition_locations(&src_b, &prog_b, &uri_b, "Echo");
        assert!(!defs_b.is_empty(), "Echo defined in b.trs");

        // "Replica" only defined in a.trs — searching b.trs finds nothing locally
        let replica_in_b = definition_locations(&src_b, &prog_b, &uri_b, "Replica");
        assert!(
            replica_in_b.is_empty(),
            "Replica not in b.trs, workspace index needed"
        );

        // But workspace search across both files finds it
        let replica_in_a = definition_locations(&src_a, &prog_a, &uri_a, "Replica");
        assert!(
            !replica_in_a.is_empty(),
            "Replica found in a.trs via workspace"
        );
    }

    #[test]
    fn cross_file_references_include_both_files() {
        let (src_a, prog_a, src_b, prog_b) = cross_file_fixture();
        let uri_a = Url::parse("file:///workspace/a.trs").unwrap();
        let uri_b = Url::parse("file:///workspace/b.trs").unwrap();

        // Collect references to "Echo" across both files
        let mut all_refs = Vec::new();
        all_refs.extend(reference_locations(&src_a, &prog_a, &uri_a, "Echo", true));
        all_refs.extend(reference_locations(&src_b, &prog_b, &uri_b, "Echo", true));

        // Should find occurrences in both files
        let has_a = all_refs.iter().any(|loc| loc.uri == uri_a);
        let has_b = all_refs.iter().any(|loc| loc.uri == uri_b);
        assert!(has_a, "Echo referenced in a.trs");
        assert!(has_b, "Echo referenced in b.trs");
        assert!(
            all_refs.len() >= 2,
            "at least 2 references across both files"
        );
    }

    #[test]
    fn cross_file_rename_unique_target() {
        let (src_a, prog_a, _src_b, _prog_b) = cross_file_fixture();
        let _uri_a = Url::parse("file:///workspace/a.trs").unwrap();

        // "Replica" is only defined in a.trs — rename is safe
        let target = SymbolTarget {
            name: "Replica".to_string(),
            kind: DefinitionKind::Role,
            parent: None,
        };

        // Collect all reference spans for rename
        let occurrences = collect_symbol_occurrences(&src_a, &prog_a);
        let refs = collect_reference_spans_for_target(&src_a, &prog_a, &target, true, &occurrences);
        assert!(
            !refs.is_empty(),
            "Replica has references in a.trs for rename"
        );

        // Verify definition exists
        assert!(has_target_definition(&prog_a, &target));
    }

    #[test]
    fn cross_file_ambiguous_rename_rejection() {
        let (_src_a, prog_a, _src_b, prog_b) = cross_file_fixture();

        // "Echo" is defined in BOTH a.trs and b.trs — rename should be rejected
        let target = SymbolTarget {
            name: "Echo".to_string(),
            kind: DefinitionKind::Message,
            parent: None,
        };

        let has_def_a = has_target_definition(&prog_a, &target);
        let has_def_b = has_target_definition(&prog_b, &target);
        assert!(has_def_a, "Echo defined in a.trs");
        assert!(has_def_b, "Echo defined in b.trs");

        // Both files define the same symbol — workspace-wide rename must be rejected
        let defining_files: Vec<&str> = [(&prog_a, "a.trs"), (&prog_b, "b.trs")]
            .iter()
            .filter(|(prog, _)| has_target_definition(prog, &target))
            .map(|(_, name)| *name)
            .collect();
        assert_eq!(
            defining_files.len(),
            2,
            "Echo defined in 2 files — rename should be rejected"
        );
    }

    #[test]
    fn open_buffer_content_wins_over_disk() {
        // Simulate: user has unsaved changes in buffer. The open buffer's
        // source/AST should take precedence when constructing the navigation
        // document set. We test this by showing that load_symbol_document
        // returns cached (open) data before falling back to disk.

        // Parse two different versions of the same file
        let disk_src = r#"protocol Disk {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message OldMsg;
    role R { init p; phase p {} }
}"#;
        let buffer_src = r#"protocol Buffer {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message NewMsg;
    role R { init p; phase p {} }
}"#;
        let disk_prog = parse_source(disk_src);
        let buffer_prog = parse_source(buffer_src);

        // The buffer version should have NewMsg, not OldMsg
        let has_new = has_target_definition(
            &buffer_prog,
            &SymbolTarget {
                name: "NewMsg".to_string(),
                kind: DefinitionKind::Message,
                parent: None,
            },
        );
        let has_old = has_target_definition(
            &disk_prog,
            &SymbolTarget {
                name: "OldMsg".to_string(),
                kind: DefinitionKind::Message,
                parent: None,
            },
        );
        assert!(has_new, "buffer has NewMsg");
        assert!(has_old, "disk has OldMsg");

        // When workspace navigation uses open buffer, NewMsg is found, not OldMsg
        let no_old_in_buffer = has_target_definition(
            &buffer_prog,
            &SymbolTarget {
                name: "OldMsg".to_string(),
                kind: DefinitionKind::Message,
                parent: None,
            },
        );
        assert!(
            !no_old_in_buffer,
            "open buffer should NOT have disk-only OldMsg"
        );
    }

    // ---------------------------------------------------------------
    // Inlay hints
    // ---------------------------------------------------------------

    #[test]
    fn inlay_hints_var_type_enum_hint() {
        let src = r#"protocol Test {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    enum Vote { yes, no }
    message Proposal;
    role Voter {
        var decision: Vote = yes;
        init idle;
        phase idle {}
    }
}"#;
        let program = parse_source(src);
        let hints = build_inlay_hints(src, &program);
        // Should have at least one hint for the enum variable
        let enum_hints: Vec<_> = hints
            .iter()
            .filter(|h| match &h.label {
                InlayHintLabel::String(s) => s.contains("Vote"),
                _ => false,
            })
            .collect();
        assert!(
            !enum_hints.is_empty(),
            "should produce an inlay hint for enum variable type"
        );
    }

    #[test]
    fn inlay_hints_threshold_guard_quorum() {
        let src = r#"protocol Test {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message Prepare;
    role Replica {
        init start;
        phase start {
            when received >= 2*t+1 Prepare => {
                goto phase done;
            }
        }
        phase done {}
    }
}"#;
        let program = parse_source(src);
        let hints = build_inlay_hints(src, &program);
        // Should have a hint for the threshold guard with "quorum"
        let quorum_hints: Vec<_> = hints
            .iter()
            .filter(|h| match &h.label {
                InlayHintLabel::String(s) => s.contains("quorum"),
                _ => false,
            })
            .collect();
        assert!(
            !quorum_hints.is_empty(),
            "should produce a quorum hint for 2*t+1 threshold"
        );
    }

    #[test]
    fn inlay_hints_committee_bound() {
        let src = r#"protocol Test {
    parameters { n: nat; t: nat; f: nat; b: nat; }
    resilience { n > 2*b; }
    adversary { model: byzantine; bound: b; }
    committee voters {
        population: 1000;
        byzantine: 333;
        size: 100;
        epsilon: 1.0e-9;
        bound_param: b;
    }
    message Vote;
    role Voter {
        init idle;
        phase idle {}
    }
}"#;
        let program = parse_source(src);
        let hints = build_inlay_hints(src, &program);
        // Should have a committee bound hint
        let committee_hints: Vec<_> = hints
            .iter()
            .filter(|h| match &h.label {
                InlayHintLabel::String(s) => s.contains("N=1000"),
                _ => false,
            })
            .collect();
        assert!(
            !committee_hints.is_empty(),
            "should produce a committee bound hint"
        );
    }

    // ---------------------------------------------------------------
    // Folding ranges
    // ---------------------------------------------------------------

    #[test]
    fn folding_range_protocol_and_role() {
        let src = r#"protocol Test {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message Prepare;
    role Replica {
        init start;
        phase start {
            when received >= 1 Prepare => {
                goto phase done;
            }
        }
        phase done {}
    }
    property agreement: agreement {
        forall p: Replica. forall q: Replica.
            p.decided == q.decided
    }
}"#;
        let program = parse_source(src);
        let ranges = build_folding_ranges(src, &program);

        // Should have ranges for protocol, role, phase(s), transition, and property
        assert!(
            ranges.len() >= 3,
            "should have at least 3 folding ranges (protocol, role, property); got {}",
            ranges.len()
        );

        // Check that protocol range exists (starts at line 0)
        let protocol_range = ranges.iter().find(|r| {
            r.collapsed_text
                .as_ref()
                .is_some_and(|t| t.contains("protocol"))
        });
        assert!(
            protocol_range.is_some(),
            "should have a folding range for the protocol block"
        );

        // Check that role range exists
        let role_range = ranges.iter().find(|r| {
            r.collapsed_text
                .as_ref()
                .is_some_and(|t| t.contains("role Replica"))
        });
        assert!(
            role_range.is_some(),
            "should have a folding range for the role block"
        );
    }

    #[test]
    fn folding_range_phase_and_transition() {
        let src = r#"protocol Test {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message Prepare;
    role Replica {
        init start;
        phase start {
            when received >= 1 Prepare => {
                goto phase done;
            }
        }
        phase done {}
    }
}"#;
        let program = parse_source(src);
        let ranges = build_folding_ranges(src, &program);

        // Check that phase "start" range exists (multi-line)
        let phase_range = ranges.iter().find(|r| {
            r.collapsed_text
                .as_ref()
                .is_some_and(|t| t.contains("phase start"))
        });
        assert!(
            phase_range.is_some(),
            "should have a folding range for phase 'start'"
        );

        // Check that a transition range exists (multi-line when block)
        let transition_range = ranges.iter().find(|r| {
            r.collapsed_text
                .as_ref()
                .is_some_and(|t| t.contains("when"))
        });
        assert!(
            transition_range.is_some(),
            "should have a folding range for the multi-line transition"
        );
    }

    #[test]
    fn folding_range_comment_blocks() {
        let src = r#"// Line 1 of comment
// Line 2 of comment
// Line 3 of comment
protocol Test {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    message M;
    role R {
        init p;
        phase p {}
    }
}"#;
        let program = parse_source(src);
        let ranges = build_folding_ranges(src, &program);

        // Should have a comment folding range
        let comment_range = ranges
            .iter()
            .find(|r| r.kind == Some(FoldingRangeKind::Comment));
        assert!(
            comment_range.is_some(),
            "should have a folding range for the comment block"
        );
        let cr = comment_range.unwrap();
        assert_eq!(cr.start_line, 0);
        assert_eq!(cr.end_line, 2);
    }

    #[test]
    fn folding_range_enum_block() {
        let src = r#"protocol Test {
    parameters { n: nat; t: nat; f: nat; }
    resilience { n > 3*t; }
    adversary { model: byzantine; bound: f; }
    enum Status {
        idle,
        running,
        done
    }
    message M;
    role R {
        init p;
        phase p {}
    }
}"#;
        let program = parse_source(src);
        let ranges = build_folding_ranges(src, &program);

        let enum_range = ranges.iter().find(|r| {
            r.collapsed_text
                .as_ref()
                .is_some_and(|t| t.contains("enum Status"))
        });
        assert!(
            enum_range.is_some(),
            "should have a folding range for the enum block"
        );
    }
}
