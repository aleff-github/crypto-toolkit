import * as vscode from 'vscode';
import { CryptoToolkitSettings, OutputMode, PreferredEncoding } from '../commands/types';

const outputModes: OutputMode[] = ['replace', 'insert', 'sidePanel', 'clipboard'];
const encodings: PreferredEncoding[] = ['utf8', 'hex', 'base64'];

function pickEnum<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === 'string' && allowed.includes(value as T) ? (value as T) : fallback;
}

export function getSettings(): CryptoToolkitSettings {
  const config = vscode.workspace.getConfiguration('cryptoToolkit');

  return {
    outputMode: pickEnum(config.get('outputMode'), outputModes, 'replace'),
    preferredEncoding: pickEnum(config.get('preferredEncoding'), encodings, 'utf8'),
    showNotifications: config.get<boolean>('showNotifications', true),
    autoCopyResults: config.get<boolean>('autoCopyResults', false),
    randomTokenBytes: Math.min(Math.max(config.get<number>('randomTokenBytes', 32), 8), 4096),
    smartDecodeMinimumConfidence: Math.min(Math.max(config.get<number>('smartDecode.minimumConfidence', 45), 0), 100),
    smartDecodeMaxCandidates: Math.min(Math.max(config.get<number>('smartDecode.maxCandidates', 8), 1), 20),
    smartDecodeShowLowConfidence: config.get<boolean>('smartDecode.showLowConfidence', false),
    smartDecodeIncludeReasons: config.get<boolean>('smartDecode.includeReasons', true)
  };
}
