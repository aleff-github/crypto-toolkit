import * as vscode from 'vscode';
import { registerCommands } from './commands/registerCommands';

/**
 * Entry point for the extension host.
 * Keep activation lightweight: commands are registered immediately, but operation
 * modules are lazy-loaded only when the user invokes a specific command.
 */
export function activate(context: vscode.ExtensionContext): void {
  registerCommands(context);
}

export function deactivate(): void {
  // No telemetry, sockets, timers, or background workers to clean up.
}
