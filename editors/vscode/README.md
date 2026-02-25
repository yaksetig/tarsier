# Tarsier VS Code Extension

Language support for [Tarsier](../../README.md) threshold automata protocol
specification files (`.trs`).

## Features

### Syntax Highlighting

Full TextMate grammar for `.trs` files, with highlighting for:

- Keywords (`protocol`, `parameters`, `resilience`, `adversary`, `message`,
  `role`, `phase`, `when`, `send`, `goto`, `decide`, `init`, `var`, `enum`,
  `committee`, `identity`, `channel`, `equivocation`, `certificate`,
  `threshold_signature`, `form`, `lock`, `justify`, `has`, `import`, `module`,
  and more)
- Property keywords (`property`, `agreement`, `validity`, `safety`,
  `invariant`, `liveness`, `forall`, `exists`)
- Temporal operators (`[]`, `<>`, `X`, `U`, `W`, `R`, `~>`)
- Logical operators (`&&`, `||`, `==>`, `<=>`, `!`)
- Comparison operators (`>=`, `<=`, `==`, `!=`, `>`, `<`, `=>`)
- Types and constants (`nat`, `int`, `bool`, `true`, `false`, `byzantine`,
  `crash`, `authenticated`, `unauthenticated`, `signed`, `unsigned`, and more)
- Numeric literals (integers and scientific-notation floats)
- Comments (line `//` and block `/* */`)
- Strings

### Language Configuration

- Bracket matching and auto-closing for `{}`, `()`, `""`, and `/* */`
- Automatic indentation on `{` and dedentation on `}`
- Code folding based on brace markers

### Snippets

The extension ships 14 snippets for common Tarsier constructs:

| Prefix               | Description                                                        |
|----------------------|--------------------------------------------------------------------|
| `protocol`           | Full protocol skeleton with parameters, resilience, adversary, message, role, and property |
| `faithful-protocol`  | Protocol skeleton with faithful network semantics (identity-selective, per-recipient delivery) |
| `phase`              | Phase block with a transition rule                                 |
| `when`               | Transition rule with threshold guard, send, and goto               |
| `property-safety`    | Safety property with universal quantifiers                         |
| `property-liveness`  | Liveness property with eventual operator                           |
| `adversary`          | Adversary block with model, bound, and auth                        |
| `message`            | Message type declaration with optional fields                      |
| `role`               | Role with variable, init, and phase                                |
| `committee`          | Committee selection block for probabilistic verification           |
| `identity`           | Identity declaration for authenticated channels                    |
| `channel`            | Channel authentication declaration                                 |
| `var`                | Role-local variable declaration                                    |
| `resilience`         | Resilience constraint                                              |

### LSP Integration

The extension launches the `tarsier-lsp` language server and provides:

- **Real-time diagnostics** -- parse errors and lowering errors appear as you
  type, with precise source locations and structured error codes.
- **Hover information** -- hover over any keyword or user-defined symbol
  (messages, roles, phases, parameters, variables, properties, enums) to see
  documentation.
- **Go to definition** -- Ctrl/Cmd+click on a symbol to jump to its
  declaration.
- **Find references** -- right-click a symbol and select "Find All References"
  to see every occurrence in the file.
- **Autocompletion** -- context-aware completions for keywords, types, message
  names, phase names, property kinds, and more.
- **Code actions** -- quick fixes for common errors such as misspelled phase or
  message names, and missing `init` declarations.

### Commands

| Command                         | Default Keybinding             | Description                                |
|---------------------------------|--------------------------------|--------------------------------------------|
| `Tarsier: Verify Current File`  | Ctrl+Shift+V (Cmd+Shift+V)    | Run `tarsier verify` on the active `.trs` file |
| `Tarsier: Check Liveness`       | Ctrl+Shift+L (Cmd+Shift+L)    | Run `tarsier check-liveness` on the active `.trs` file |

Both commands are also available from the editor title bar (navigation group)
when a `.trs` file is open. Output appears in the "Tarsier" output channel.

### Status Bar

A status bar item shows the current state of the Tarsier LSP server and the
most recent verification result:

- `$(loading~spin) Tarsier` -- server starting
- `$(check) Tarsier` -- server connected / last command succeeded
- `$(warning) Tarsier` -- last command failed
- `$(error) Tarsier` -- server stopped or command error

## Installation

The extension is not published to the VS Code Marketplace. Install it from
source:

### Prerequisites

- [Node.js](https://nodejs.org/) 20+
- The `tarsier-lsp` binary (see below)
- Optionally, the `tarsier` CLI binary for verification commands

### Build the LSP server

From the repository root:

```sh
cargo build -p tarsier-lsp --release
```

Then either add `target/release/` to your `PATH`, or configure the
`tarsier.lsp.path` setting (see below).

### Build and install the extension

```sh
cd editors/vscode
npm install
npm run compile
```

Then install using one of these methods:

**Method 1: Symlink (recommended for development)**

```sh
# Create a symlink in the VS Code extensions directory
ln -s "$(pwd)" ~/.vscode/extensions/tarsier-vscode
```

**Method 2: Package as VSIX**

```sh
# Install vsce if you don't have it
npm install -g @vscode/vsce

# Package the extension
vsce package

# Install the .vsix file
code --install-extension tarsier-vscode-0.1.0.vsix
```

After installation, reload VS Code. The extension activates automatically when
you open a `.trs` file.

## Configuration

All settings are under the `tarsier` namespace in VS Code settings.

| Setting             | Type     | Default        | Description                                   |
|---------------------|----------|----------------|-----------------------------------------------|
| `tarsier.lsp.path`  | `string` | `"tarsier-lsp"` | Path to the `tarsier-lsp` binary. Set this if the binary is not on your `PATH`. Can be an absolute path (e.g. `/path/to/target/release/tarsier-lsp`). |
| `tarsier.cli.path`  | `string` | `"tarsier"`     | Path to the `tarsier` CLI binary used by the verify and check-liveness commands. Set this if the CLI is not on your `PATH`. |

Example `settings.json`:

```json
{
  "tarsier.lsp.path": "/home/user/tarsier/target/release/tarsier-lsp",
  "tarsier.cli.path": "/home/user/tarsier/target/release/tarsier"
}
```

## Requirements

- **VS Code 1.85.0 or later.**
- **`tarsier-lsp` binary** must be available at the configured path for LSP
  features (diagnostics, hover, completions, go-to-definition, references, code
  actions) to work. Syntax highlighting and snippets work without the LSP server.
- **`tarsier` CLI binary** must be available at the configured path for the
  verify and check-liveness commands to work.

## File Structure

```
editors/vscode/
  package.json                    -- Extension manifest
  language-configuration.json     -- Bracket matching, indentation, folding
  syntaxes/
    tarsier.tmLanguage.json       -- TextMate grammar for syntax highlighting
  snippets/
    tarsier.code-snippets         -- Code snippets
  src/
    extension.ts                  -- Extension entry point and LSP client
  tsconfig.json                   -- TypeScript configuration
```

## Troubleshooting

**LSP server not starting:**
- Check the "Tarsier" output channel (View > Output > select "Tarsier") for
  error messages.
- Verify that `tarsier-lsp` is on your PATH or that `tarsier.lsp.path` points
  to the correct binary.
- Ensure the binary was built successfully: run `tarsier-lsp` from a terminal
  to confirm it starts without errors.

**Verify command fails:**
- Check that the `tarsier` CLI binary is on your PATH or configured via
  `tarsier.cli.path`.
- Check the "Tarsier" output channel for the full command output and error
  messages.

**No syntax highlighting:**
- Ensure the file has a `.trs` extension. The extension activates only for
  files with this extension.
- Reload the VS Code window (Ctrl+Shift+P > "Developer: Reload Window").

## Related

- [tarsier-lsp crate README](../../crates/tarsier-lsp/README.md) -- LSP server
  documentation, capabilities, and configuration for other editors.
- [Language Reference](../../docs/LANGUAGE_REFERENCE.md) -- full specification
  of the `.trs` DSL.
- [Getting Started](../../docs/GETTING_STARTED.md) -- introduction to writing
  Tarsier protocol specifications.
