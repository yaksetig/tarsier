import * as vscode from "vscode";
import * as cp from "child_process";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  State,
} from "vscode-languageclient/node";

let client: LanguageClient;
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
  const lspPath = config.get<string>("lsp.path", "tarsier-lsp");

  const serverOptions: ServerOptions = {
    run: { command: lspPath, args: [] },
    debug: { command: lspPath, args: [] },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "tarsier" }],
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

  context.subscriptions.push(
    vscode.commands.registerCommand("tarsier.verify", () =>
      runTarsierCommand("verify")
    )
  );
  context.subscriptions.push(
    vscode.commands.registerCommand("tarsier.checkLiveness", () =>
      runTarsierCommand("check-liveness")
    )
  );
}

function runTarsierCommand(subcommand: string) {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== "tarsier") {
    vscode.window.showWarningMessage("Open a .trs file first.");
    return;
  }

  const filePath = editor.document.fileName;
  const config = vscode.workspace.getConfiguration("tarsier");
  const cliPath = config.get<string>("cli.path", "tarsier");

  outputChannel.clear();
  outputChannel.show(true);
  outputChannel.appendLine(`> ${cliPath} ${subcommand} ${filePath}\n`);

  statusBarItem.text = "$(sync~spin) Tarsier";
  statusBarItem.tooltip = `Running: tarsier ${subcommand}`;

  const proc = cp.spawn(cliPath, [subcommand, filePath]);

  proc.stdout.on("data", (data: string) => {
    outputChannel.append(data.toString());
  });

  proc.stderr.on("data", (data: string) => {
    outputChannel.append(data.toString());
  });

  proc.on("close", (code: number | null) => {
    if (code === 0) {
      statusBarItem.text = "$(check) Tarsier";
      statusBarItem.tooltip = `Last ${subcommand}: passed`;
      vscode.window.showInformationMessage(`Tarsier ${subcommand}: success`);
    } else {
      statusBarItem.text = "$(warning) Tarsier";
      statusBarItem.tooltip = `Last ${subcommand}: failed (exit ${code})`;
      vscode.window.showErrorMessage(
        `Tarsier ${subcommand} failed (exit code ${code})`
      );
    }
  });

  proc.on("error", (err: Error) => {
    outputChannel.appendLine(`\nError: ${err.message}`);
    statusBarItem.text = "$(error) Tarsier";
    statusBarItem.tooltip = `Error running tarsier ${subcommand}`;
    vscode.window.showErrorMessage(
      `Failed to run tarsier: ${err.message}`
    );
  });
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
