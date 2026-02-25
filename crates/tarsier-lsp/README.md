# tarsier-lsp

Language Server Protocol (LSP) implementation for the Tarsier DSL, providing IDE
features for `.trs` threshold automata protocol specification files.

## Features

The language server implements the following LSP capabilities:

### Diagnostics

Real-time error and warning reporting as you type. The server runs two stages
of analysis on every edit:

- **Parse diagnostics** -- syntax errors, duplicate declarations, missing
  sections, and invalid fields are reported with precise source spans and
  structured error codes (e.g. `tarsier::parse::syntax`,
  `tarsier::parse::duplicate`).
- **Lowering diagnostics** -- semantic errors detected during IR lowering, such
  as unknown phases, unknown message types, missing `init` declarations, unknown
  enum types, missing enum initializers, and out-of-range values. Structural
  checks (unknown names, missing `init`, enum typing/init) are aggregated so
  multiple issues can be reported in one pass. Error messages include "did you
  mean?" suggestions when a close match exists (Levenshtein distance <= 2).

### Hover

Hover over any identifier to see documentation:

- **Keywords** -- built-in documentation for all Tarsier keywords (`protocol`,
  `parameters`, `resilience`, `adversary`, `message`, `role`, `phase`, `when`,
  `send`, `goto`, `decide`, `received`, `property`, `agreement`, `validity`,
  `safety`, `invariant`, `liveness`, `committee`, `identity`, `channel`,
  `equivocation`, `forall`, `exists`, `enum`, `certificate`,
  `threshold_signature`, `pacemaker`, `module`, `import`, and type keywords
  `bool`, `nat`, `int`, `distinct`).
- **User-defined symbols** -- messages (with field signatures), roles (variable
  and phase counts), phases (transition counts and parent role), parameters
  (with types), variables (type, initial value, and parent role), properties
  (kind), and enums (variant list).

### Go to Definition

Jump to the declaration of any user-defined symbol: messages, roles, phases,
parameters, variables, properties, and enums. The server resolves definitions
using AST span information from the parser and follows `import` declarations
across files (recursive import traversal).

### Find References

Find occurrences of a symbol in the current file and imported `.trs` files.
The server performs whole-word matching within each protocol span, returning
reference locations from the import graph.

### Workspace Symbol Search

Implements `workspace/symbol` for global symbol lookup across:

- currently open `.trs` documents
- recursively resolved imports
- discovered `.trs` files under workspace roots (bounded scan)

Results include symbol kind, location, and container name metadata.

### Document Symbols (Outline)

Provides hierarchical outline symbols (`textDocument/documentSymbol`) for:

- protocol root
- imports/modules
- parameters and enums
- messages and cryptographic objects
- committees
- roles with child symbols for variables and phases
- properties

Selection ranges target identifier tokens where possible, so editor outline
navigation and breadcrumbs land on symbol names rather than full declaration
blocks.

### Completions

Context-aware autocompletion triggered by `Space`, `:`, and `{` characters.
The server infers cursor context by analyzing brace nesting depth and nearby
keywords, then offers relevant suggestions:

| Context              | Completions offered                                                                              |
|----------------------|--------------------------------------------------------------------------------------------------|
| Protocol top level   | `parameters`, `resilience`, `adversary`, `message`, `role`, `property`, `committee`, `identity`, `channel`, `equivocation`, `enum`, `pacemaker`, `module`, `import`, `certificate`, `threshold_signature` |
| Inside a role        | `var`, `init`, `phase`                                                                           |
| Inside a phase       | `when`, `received`, `received distinct`, `has`, `true`, `false`                                  |
| Inside an action     | `send`, `goto phase`, `decide`, `assign`, `form`, `lock`, `justify`, plus message names and phase names from the AST |
| After `:`            | `bool`, `nat`, `int`, plus declared enum type names                                              |
| After `property X:`  | `agreement`, `validity`, `safety`, `invariant`, `liveness`                                       |
| Property formula     | `forall`, `exists`, `true`, `false`, temporal operators (`[]`, `<>`, `X`, `U`, `W`, `R`, `~>`), plus role names |

### Code Actions (Quick Fixes)

The server generates quick-fix code actions for specific diagnostic codes:

- **Unknown phase** (`tarsier::lower::unknown_phase`) -- offers to replace with
  the closest known phase name.
- **Unknown message** (`tarsier::lower::unknown_message`) -- offers to replace
  with the closest known message/object name, or to insert a new `message`
  declaration (for message-type diagnostics).
- **Missing init phase** (`tarsier::lower::no_init_phase`) -- offers to insert
  an `init <first_phase>;` statement before the first phase in the role.
- **Unknown enum type** (`tarsier::lower::unknown_enum`) -- offers to replace
  with the closest declared enum name.
- **Missing enum init** (`tarsier::lower::missing_enum_init`) -- offers to
  insert `= <first_enum_variant>` for enum variables without initializers.

### Rename Refactoring

Implements `textDocument/prepareRename` and `textDocument/rename`:

- validates identifier syntax (`[A-Za-z_][A-Za-z0-9_]*`)
- rejects keyword renames
- resolves symbol kind/scope at cursor (e.g., message vs role-local variable with
  the same identifier) before computing edits
- computes edits for declarations and references in the current file and
  imported `.trs` files
- returns a multi-file `WorkspaceEdit`

### Formatting

Implements `textDocument/formatting` and `textDocument/rangeFormatting` with a
deterministic canonicalization pass:

- normalizes indentation based on brace structure
- trims redundant whitespace-only lines
- produces stable output for repeated runs

### Semantic Tokens

Implements `textDocument/semanticTokens/full` and
`textDocument/semanticTokens/range` using an LSP semantic token legend for:

- keywords
- types
- variables
- properties
- functions
- strings
- numbers
- operators

### Incremental Document Sync

The server uses incremental text synchronization (`TextDocumentSyncKind::INCREMENTAL`),
so only changed regions are transmitted on each keystroke rather than the full
document. This keeps the server responsive even on larger protocol files.

## Building

```sh
cargo build -p tarsier-lsp --release
```

The binary is produced at `target/release/tarsier-lsp`. The server communicates
over stdin/stdout using the standard LSP JSON-RPC protocol.

### Build requirements

- Rust 1.70+ (see `rust-toolchain.toml` at the workspace root)
- Z3 with static linking (pulled in transitively through `tarsier-ir`). Set
  `CMAKE_POLICY_VERSION_MINIMUM=3.5` if your cmake version requires it.

## Editor Setup

### VS Code

A dedicated VS Code extension is provided in `editors/vscode/`. See the
[VS Code extension README](../../editors/vscode/README.md) for installation
and configuration instructions.

### Neovim (nvim-lspconfig)

Add a custom server configuration:

```lua
local lspconfig = require("lspconfig")
local configs = require("lspconfig.configs")

if not configs.tarsier then
  configs.tarsier = {
    default_config = {
      cmd = { "tarsier-lsp" },
      filetypes = { "tarsier" },
      root_dir = lspconfig.util.find_git_ancestor,
      settings = {},
    },
  }
end

lspconfig.tarsier.setup({})
```

You will also need to register the `.trs` filetype:

```lua
vim.filetype.add({
  extension = {
    trs = "tarsier",
  },
})
```

### Helix

Add to `~/.config/helix/languages.toml`:

```toml
[[language]]
name = "tarsier"
scope = "source.tarsier"
file-types = ["trs"]
roots = ["Cargo.toml"]
language-servers = ["tarsier-lsp"]

[language-server.tarsier-lsp]
command = "tarsier-lsp"
```

### Emacs (lsp-mode)

```elisp
(with-eval-after-load 'lsp-mode
  (add-to-list 'lsp-language-id-configuration '(tarsier-mode . "tarsier"))
  (lsp-register-client
   (make-lsp-client
    :new-connection (lsp-stdio-connection '("tarsier-lsp"))
    :activation-fn (lsp-activate-on "tarsier")
    :server-id 'tarsier-lsp)))
```

### Sublime Text (LSP package)

Add to `LSP.sublime-settings`:

```json
{
  "clients": {
    "tarsier": {
      "enabled": true,
      "command": ["tarsier-lsp"],
      "selector": "source.tarsier"
    }
  }
}
```

### Generic LSP Client

Any editor with LSP client support can use `tarsier-lsp`. Configure the client
to:

1. Launch `tarsier-lsp` as a stdio-based language server (no arguments needed).
2. Associate it with files that have the `.trs` extension.
3. Set the language identifier to `tarsier`.

## Supported `.trs` File Features

The LSP understands the full Tarsier DSL grammar, including:

- Protocol declarations with `parameters`, `resilience`, and `adversary` blocks
- Message declarations (with optional typed fields)
- Role definitions with `var`, `init`, and `phase` blocks
- Transition rules (`when ... => { ... }`) with threshold guards
- Actions: `send`, `goto phase`, `decide`, `assign`
- Property declarations: `agreement`, `validity`, `safety`, `invariant`, `liveness`
- Quantified formulas (`forall`, `exists`) and temporal operators
- Enum types and enum variable initialization
- Committee selection blocks for probabilistic verification
- Identity, channel, and equivocation declarations
- Cryptographic objects (`certificate`, `threshold_signature`)
- Pacemaker configuration
- Module and import declarations

## Known Limitations

- **Import-graph scope, not full workspace index.** Cross-file navigation and
  rename currently follow resolved `import` chains. Symbols in unrelated
  workspace files that are not imported are not indexed.
- **Range formatting uses document canonicalization.** `textDocument/rangeFormatting`
  currently applies the same formatter as full-document formatting, returning a
  whole-document edit for consistency.
- **Deep lowering remains first-error.** Structural lowering checks are
  multi-error, but non-structural lowering failures still come from a first
  failing `lower_with_source` pass.
- **Code actions are still selective.** Quick fixes currently target unknown
  phase/message/enum names and missing init/enum-init diagnostics; they do not
  yet cover all diagnostic codes.

## Workspace Links

- Workspace overview: [../../README.md](../../README.md)
- Getting started: [../../docs/GETTING_STARTED.md](../../docs/GETTING_STARTED.md)
- Language reference: [../../docs/LANGUAGE_REFERENCE.md](../../docs/LANGUAGE_REFERENCE.md)
- VS Code extension: [../../editors/vscode/](../../editors/vscode/)
