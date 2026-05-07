export type OutputMode = 'replace' | 'insert' | 'sidePanel' | 'clipboard';
export type PreferredEncoding = 'utf8' | 'hex' | 'base64';

export interface CryptoToolkitSettings {
  outputMode: OutputMode;
  preferredEncoding: PreferredEncoding;
  showNotifications: boolean;
  autoCopyResults: boolean;
  randomTokenBytes: number;
  smartDecodeMinimumConfidence: number;
  smartDecodeMaxCandidates: number;
  smartDecodeShowLowConfidence: boolean;
  smartDecodeIncludeReasons: boolean;
}



export interface OperationContext {
  settings: CryptoToolkitSettings;
  commandId: string;
}

export interface OperationResult {
  text: string;
  /** Optional title used by side panel and notifications. */
  title?: string;
  /** Warnings are shown as VS Code warning messages when enabled. */
  warnings?: string[];
  /** Optional language hint for the result webview. */
  language?: 'plaintext' | 'json' | 'jwt' | 'markdown';
  /** Optional per-result output mode. Useful for reports that should not replace selected text. */
  outputMode?: OutputMode;
  /** Trusted extension-generated HTML for rich readonly side panels. Never pass raw user input here without escaping. */
  html?: string;
}



export interface Operation {
  id: string;
  title: string;
  /** Set true for generators/utilities that can run without a text selection. */
  allowEmptyInput?: boolean;
  run(input: string, context: OperationContext): Promise<OperationResult> | OperationResult;
}

export type OperationLoader = () => Promise<Operation>;
