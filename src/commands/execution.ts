import * as vscode from 'vscode';
import { getSettings } from '../config/settings';
import { showResultPanel } from '../panels/resultPanel';
import { toUserMessage, UserFacingError } from '../utils/errors';
import { Operation, OperationResult } from './types';

function normalizeResult(result: OperationResult | string, fallbackTitle: string): OperationResult {
  if (typeof result === 'string') {
    return { text: result, title: fallbackTitle, language: 'plaintext' };
  }
  return {
    ...result,
    title: result.title ?? fallbackTitle
  };
}

function getPrimarySelection(editor: vscode.TextEditor): vscode.Selection {
  return editor.selection;
}

async function writeResultToEditor(
  editor: vscode.TextEditor,
  selection: vscode.Selection,
  text: string,
  outputMode: 'replace' | 'insert'
): Promise<boolean> {
  if (outputMode === 'replace') {
    return editor.edit((builder) => {
      if (selection.isEmpty) {
        builder.insert(selection.active, text);
      } else {
        builder.replace(selection, text);
      }
    });
  }

  return editor.edit((builder) => {
    if (selection.isEmpty) {
      builder.insert(selection.active, text);
      return;
    }

    const lineEnd = editor.document.lineAt(selection.end.line).range.end;
    builder.insert(lineEnd, `${editor.document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n'}${text}`);
  });
}

async function emitrWarnings(result: OperationResult, showNotifications: boolean): Promise<void> {
  if (!showNotifications || !result.warnings?.length) {
    return;
  }

  for (const warning of result.warnings.slice(0, 3)) {
    await vscode.window.showWarningMessage(`Crypto Toolkit: ${warning}`);
  }
}

export async function executeOperation(operation: Operation, commandId: string): Promise<void> {
  const settings = getSettings();
  const editor = vscode.window.activeTextEditor;

  try {
    const selection = editor ? getPrimarySelection(editor) : undefined;
    const input = editor && selection ? editor.document.getText(selection) : '';

    if (!operation.allowEmptyInput && input.length === 0) {
      throw new UserFacingError('No text selected.', {
        reason: 'This operation needs input from the active editor selection.',
        expected: 'Select the text you want to encode, decode, hash, inspect, or transform.',
        hint: 'For generators such as UUID or random tokens, use the Utility commands that support empty input.'
      });
    }

    const result = normalizeResult(await operation.run(input, { settings, commandId }), operation.title);
    let outputMode = result.outputMode ?? settings.outputMode;


    if (outputMode === 'sidePanel' || !editor) {
      showResultPanel(result);
    } else if (outputMode === 'clipboard') {
      await vscode.env.clipboard.writeText(result.text);
    } else if (outputMode === 'replace' || outputMode === 'insert') {
      if (!editor || !selection) {
        await vscode.env.clipboard.writeText(result.text);
        outputMode = 'clipboard';
      } else {
        const ok = await writeResultToEditor(editor, selection, result.text, outputMode);
        if (!ok) {
          throw new UserFacingError('Editor edit failed.', {
            reason: 'VS Code rejected the edit operation.',
            hint: 'The document may be readonly, closed, or controlled by another extension.'
          });
        }
      }
    }

    if (settings.autoCopyResults && outputMode !== 'clipboard') {
      await vscode.env.clipboard.writeText(result.text);
    }

    await emitrWarnings(result, settings.showNotifications);

    if (settings.showNotifications && !result.warnings?.length) {
      const suffix = outputMode === 'clipboard' ? ' copied to clipboard.' : outputMode === 'sidePanel' ? ' opened in side panel.' : ' completed.';
      void vscode.window.showInformationMessage(`Crypto Toolkit: ${operation.title}${suffix}`);
    }
  } catch (error) {
    void vscode.window.showErrorMessage(`Crypto Toolkit: ${toUserMessage(error)}`);
  }
}
