# Tarsier - Threshold Automata Language (VS Code Extension)

Language support for [Tarsier](../../README.md) threshold automata protocol
specification files (`.trs`).

## Features

- **Syntax highlighting** -- TextMate grammar for all Tarsier DSL constructs
  including keywords, types, operators, properties, temporal operators, comments,
  numbers, and strings.
- **Language configuration** -- bracket matching, auto-closing pairs, code
  folding, and indentation rules for `.trs` files.
- **LSP integration** -- launches the Tarsier language server for real-time
  diagnostics, hover documentation, go-to-definition, find references,
  autocompletion, code actions, formatting, and more.

## Installation

### Prerequisites

- [Node.js](https://nodejs.org/) 20+
- The `tarsier` binary (built from the workspace root with
  `cargo build --release`)

### Build and install

```sh
cd editors/vscode
npm install
npm run compile
```

Install via symlink (recommended for development):

```sh
ln -s "$(pwd)" ~/.vscode/extensions/tarsier-lang
```

Or package as a VSIX:

```sh
npm install -g @vscode/vsce
vsce package
code --install-extension tarsier-lang-0.1.0.vsix
```

Reload VS Code after installation. The extension activates automatically when
you open a `.trs` file.

## Configuration

| Setting              | Type     | Default     | Description                                      |
|----------------------|----------|-------------|--------------------------------------------------|
| `tarsier.serverPath` | `string` | `"tarsier"` | Path to the `tarsier` binary. The LSP is started via `tarsier lsp`. Set this if the binary is not on your `PATH`. |

Example `settings.json`:

```json
{
  "tarsier.serverPath": "/path/to/target/release/tarsier"
}
```

## Troubleshooting

**LSP server not starting:**
- Check the "Tarsier" output channel (View > Output > select "Tarsier") for
  error messages.
- Verify that `tarsier` is on your PATH or that `tarsier.serverPath` points to
  the correct binary.
- Ensure the binary was built successfully: run `tarsier lsp` from a terminal to
  confirm it starts without errors.

**No syntax highlighting:**
- Ensure the file has a `.trs` extension.
- Reload the VS Code window (Ctrl+Shift+P > "Developer: Reload Window").

## Related

- [tarsier-lsp README](../../crates/tarsier-lsp/README.md) -- LSP server
  documentation and capabilities.
- [Language Reference](../../docs/LANGUAGE_REFERENCE.md) -- full specification
  of the `.trs` DSL.
