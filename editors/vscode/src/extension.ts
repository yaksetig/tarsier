import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  State,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel("Tarsier");
  context.subscriptions.push(outputChannel);

  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    50
  );
  statusBarItem.text = "$(loading~spin) Tarsier";
  statusBarItem.tooltip = "Tarsier LSP: starting...";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  const config = vscode.workspace.getConfiguration("tarsier");
  const serverPath = config.get<string>("serverPath", "tarsier");

  const serverOptions: ServerOptions = {
    run: { command: serverPath, args: ["lsp"] },
    debug: { command: serverPath, args: ["lsp"] },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "tarsier" }],
    outputChannel,
  };

  client = new LanguageClient(
    "tarsier-lsp",
    "Tarsier Language Server",
    serverOptions,
    clientOptions
  );

  client.onDidChangeState((e) => {
    if (e.newState === State.Running) {
      statusBarItem.text = "$(check) Tarsier";
      statusBarItem.tooltip = "Tarsier LSP: connected";
    } else if (e.newState === State.Stopped) {
      statusBarItem.text = "$(error) Tarsier";
      statusBarItem.tooltip = "Tarsier LSP: stopped";
    }
  });

  client.start();
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
