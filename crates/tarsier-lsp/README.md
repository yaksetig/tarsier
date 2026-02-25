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
  enum types, and out-of-range values. Error messages include "did you mean?"
  suggestions when a close match exists (Levenshtein distance <= 2).

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
using AST span information from the parser.

### Find References

Find all occurrences of a symbol across the current file. The server performs
whole-word matching within the protocol span, returning every reference site
for the selected identifier.

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
  with the closest known message name, or to insert a new `message` declaration.
- **Missing init phase** (`tarsier::lower::no_init_phase`) -- offers to insert
  an `init <first_phase>;` statement before the first phase in the role.

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

- **Single-file scope.** The server analyzes each file independently. Cross-file
  go-to-definition and references (e.g. following `import` declarations into
  other `.trs` files) are not yet supported.
- **No rename refactoring.** The `textDocument/rename` capability is not
  implemented. Use find-references and manual edits instead.
- **No document symbols / outline.** The `textDocument/documentSymbol` capability
  is not yet implemented, so the VS Code outline view and breadcrumbs do not
  populate.
- **No formatting.** The server does not provide `textDocument/formatting` or
  `textDocument/rangeFormatting`.
- **No semantic tokens.** Syntax highlighting relies on the TextMate grammar
  shipped with the VS Code extension rather than LSP semantic tokens.
- **First-error-only for lowering.** Lowering diagnostics stop at the first
  error; subsequent lowering issues in the same file are not reported until
  the first is fixed.
- **Code actions are limited.** Quick fixes are only available for a small set
  of diagnostic codes (unknown phase, unknown message, missing init).

## Workspace Links

- Workspace overview: [../../README.md](../../README.md)
- Getting started: [../../docs/GETTING_STARTED.md](../../docs/GETTING_STARTED.md)
- Language reference: [../../docs/LANGUAGE_REFERENCE.md](../../docs/LANGUAGE_REFERENCE.md)
- VS Code extension: [../../editors/vscode/](../../editors/vscode/)
