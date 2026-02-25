#![doc = include_str!("../README.md")]

use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(tarsier_lsp::TarsierLspBackend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
