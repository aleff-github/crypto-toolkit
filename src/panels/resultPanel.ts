import * as vscode from 'vscode';
import { OperationResult } from '../commands/types';

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function languageLabel(language: OperationResult['language']): string {
  switch (language) {
    case 'json': return 'JSON';
    case 'jwt': return 'JWT';
    case 'markdown': return 'Markdown';
    default: return 'Plain text';
  }
}

export function showResultPanel(result: OperationResult): void {
  const panel = vscode.window.createWebviewPanel(
    'cryptoToolkit.result',
    result.title ?? 'Crypto Toolkit Result',
    vscode.ViewColumn.Beside,
    {
      enableScripts: false,
      retainContextWhenHidden: false
    }
  );

  const title = escapeHtml(result.title ?? 'Result');
  const warnings = result.warnings ?? [];
  const warningHtml = warnings.length
    ? `<section class="warnings"><strong>Warnings</strong><ul>${warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join('')}</ul></section>`
    : '';
  const bodyHtml = result.html ?? `<pre>${escapeHtml(result.text)}</pre>`;

  panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0;
      color: var(--vscode-editor-foreground);
      background: var(--vscode-editor-background);
      font-family: var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
    }
    .shell { padding: 18px; max-width: 1200px; }
    header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: start;
      margin-bottom: 14px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--vscode-editorWidget-border, rgba(127,127,127,0.25));
    }
    h1 { font-size: 18px; margin: 0 0 6px; font-weight: 650; }
    h2 { font-size: 15px; margin: 18px 0 8px; font-weight: 650; }
    h3 { font-size: 13px; margin: 14px 0 8px; font-weight: 650; }
    .meta { font-size: 12px; opacity: 0.8; }
    .badge {
      border: 1px solid var(--vscode-editorWidget-border, rgba(127,127,127,0.35));
      background: var(--vscode-badge-background, rgba(127,127,127,0.16));
      color: var(--vscode-badge-foreground, inherit);
      border-radius: 999px;
      padding: 3px 9px;
      font-size: 11px;
      white-space: nowrap;
    }
    .warnings {
      margin: 0 0 14px;
      padding: 12px;
      border-left: 3px solid var(--vscode-editorWarning-foreground, #cca700);
      background: var(--vscode-inputValidation-warningBackground, rgba(204,167,0,0.12));
      font-size: 13px;
    }
    .warnings ul { margin: 8px 0 0 18px; padding: 0; }
    .card {
      border: 1px solid var(--vscode-editorWidget-border, rgba(127,127,127,0.28));
      border-radius: 10px;
      padding: 14px;
      margin: 12px 0;
      background: var(--vscode-editorWidget-background, rgba(127,127,127,0.04));
    }
    .summary-card {
      border-left: 4px solid var(--vscode-focusBorder, #007acc);
    }
    .muted { opacity: 0.75; }
    .small { font-size: 12px; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      border: 1px solid var(--vscode-editorWidget-border, rgba(127,127,127,0.32));
      border-radius: 999px;
      padding: 3px 9px;
      font-size: 12px;
      background: var(--vscode-badge-background, rgba(127,127,127,0.12));
    }
    .ok { border-left-color: var(--vscode-testing-iconPassed, #73c991); }
    .warn { border-left-color: var(--vscode-editorWarning-foreground, #cca700); }
    .danger { border-left-color: var(--vscode-editorError-foreground, #f14c4c); }
    ul { margin: 8px 0 0 18px; padding: 0; }
    li { margin: 4px 0; }
    pre {
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.5;
      margin: 0;
      padding: 14px;
      border: 1px solid var(--vscode-editorWidget-border, transparent);
      border-radius: 8px;
      background: var(--vscode-textCodeBlock-background, rgba(127,127,127,0.1));
      font-family: var(--vscode-editor-font-family, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
      font-size: var(--vscode-editor-font-size, 13px);
    }
    code {
      font-family: var(--vscode-editor-font-family, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
      background: var(--vscode-textCodeBlock-background, rgba(127,127,127,0.1));
      padding: 1px 4px;
      border-radius: 4px;
    }
    details {
      margin-top: 14px;
      border: 1px solid var(--vscode-editorWidget-border, rgba(127,127,127,0.28));
      border-radius: 10px;
      background: var(--vscode-sideBar-background, transparent);
    }
    summary {
      cursor: pointer;
      user-select: none;
      padding: 10px 12px;
      font-weight: 650;
      color: var(--vscode-textLink-foreground, inherit);
    }
    details > div { padding: 0 12px 12px; }
    table { border-collapse: collapse; width: 100%; margin: 8px 0; }
    th, td { text-align: left; vertical-align: top; border-bottom: 1px solid var(--vscode-editorWidget-border, rgba(127,127,127,0.18)); padding: 6px; }
    th { font-size: 12px; opacity: 0.75; }
  </style>
</head>
<body>
  <div class="shell">
    <header>
      <div>
        <h1>${title}</h1>
        <div class="meta">Crypto Toolkit · local/offline result · scripts disabled</div>
      </div>
      <div class="badge">${languageLabel(result.language)}</div>
    </header>
    ${warningHtml}
    ${bodyHtml}
  </div>
</body>
</html>`;
}
