import * as vscode from 'vscode';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { Operation, PreferredEncoding } from '../commands/types';
import { decodeByEncoding } from '../crypto/buffer';
import { UserFacingError } from '../utils/errors';

type AesMode = 'cbc' | 'gcm';
type Direction = 'encrypt' | 'decrypt';

interface ParsedCipherPayload {
  iv?: string;
  nonce?: string;
  ciphertext: string;
  tag?: string;
  encoding?: PreferredEncoding;
}

function aesAlgorithm(mode: AesMode, key: Buffer): string {
  if (![16, 24, 32].includes(key.length)) {
    throw new UserFacingError('Invalid AES key length. AES key validation failed.', {
      reason: `The decoded key is ${key.length} byte(s).`,
      expected: 'AES keys must be exactly 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.',
      hint: 'Check the selected key encoding. Hex keys need 32/48/64 hex characters; Base64 keys must decode to 16/24/32 bytes.'
    });
  }

  return `aes-${key.length * 8}-${mode}`;
}

async function pickEncoding(title: string, fallback: PreferredEncoding): Promise<PreferredEncoding> {
  const items: PreferredEncoding[] = ['utf8', 'hex', 'base64'];
  const selected = await vscode.window.showQuickPick(items, {
    title,
    placeHolder: `Default: ${fallback}`,
    ignoreFocusOut: true
  });

  return (selected as PreferredEncoding | undefined) ?? fallback;
}

async function promptSecretValue(title: string, prompt: string, password: boolean): Promise<string> {
  const value = await vscode.window.showInputBox({
    title,
    prompt,
    password,
    ignoreFocusOut: true
  });

  if (value === undefined) {
    throw new UserFacingError('Operation cancelled.');
  }

  return value;
}

async function promptKey(fallbackEncoding: PreferredEncoding): Promise<Buffer> {
  const encoding = await pickEncoding('Crypto Toolkit: AES key encoding', fallbackEncoding);
  const keyText = await promptSecretValue(
    'Crypto Toolkit: AES key',
    `Enter AES key encoded as ${encoding}. Valid decoded lengths: 16, 24, 32 bytes.`,
    true
  );
  return decodeByEncoding(keyText, encoding);
}

async function promptIv(mode: AesMode, fallbackEncoding: PreferredEncoding): Promise<Buffer> {
  const generate = await vscode.window.showQuickPick(['Generate secure random IV/nonce', 'Enter manually'], {
    title: mode === 'gcm' ? 'Crypto Toolkit: AES-GCM nonce' : 'Crypto Toolkit: AES IV',
    ignoreFocusOut: true
  });

  if (!generate) {
    throw new UserFacingError('Operation cancelled.');
  }

  if (generate === 'Generate secure random IV/nonce') {
    return randomBytes(mode === 'gcm' ? 12 : 16);
  }

  const encoding = await pickEncoding('Crypto Toolkit: IV/nonce encoding', fallbackEncoding);
  const ivText = await promptSecretValue(
    'Crypto Toolkit: IV/nonce',
    mode === 'gcm'
      ? `Enter nonce encoded as ${encoding}. 12 bytes is recommended for GCM.`
      : `Enter IV encoded as ${encoding}. CBC requires exactly 16 bytes.`,
    false
  );
  return decodeByEncoding(ivText, encoding);
}

async function promptIvForDecrypt(mode: AesMode, fallbackEncoding: PreferredEncoding): Promise<Buffer> {
  const encoding = await pickEncoding('Crypto Toolkit: IV/nonce encoding', fallbackEncoding);
  const ivText = await promptSecretValue(
    'Crypto Toolkit: IV/nonce',
    mode === 'gcm'
      ? `Enter nonce encoded as ${encoding}. If the selected ciphertext is JSON with iv/nonce, this prompt is skipped.`
      : `Enter IV encoded as ${encoding}. If the selected ciphertext is JSON with iv, this prompt is skipped.`,
    false
  );
  return decodeByEncoding(ivText, encoding);
}

function validateIv(mode: AesMode, iv: Buffer): string[] {
  const warnings: string[] = [];

  if (mode === 'cbc' && iv.length !== 16) {
    throw new UserFacingError(`Invalid AES-${mode.toUpperCase()} IV length. AES-${mode.toUpperCase()} IV validation failed.`, {
      reason: `The decoded IV is ${iv.length} byte(s).`,
      expected: 'AES-CBC requires exactly 16 IV bytes.',
      hint: 'Use Generate secure random IV/nonce, or provide 32 hex characters / a Base64 value that decodes to 16 bytes.'
    });
  }

  if (mode === 'gcm' && iv.length !== 12) {
    warnings.push(`AES-GCM nonce is ${iv.length} bytes. 12 bytes is the recommended default.`);
  }

  return warnings;
}

function tryParseCipherPayload(input: string): ParsedCipherPayload | undefined {
  try {
    const parsed = JSON.parse(input) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return undefined;
    }

    const record = parsed as Record<string, unknown>;
    if (typeof record.ciphertext !== 'string') {
      return undefined;
    }

    return {
      iv: typeof record.iv === 'string' ? record.iv : undefined,
      nonce: typeof record.nonce === 'string' ? record.nonce : undefined,
      ciphertext: record.ciphertext,
      tag: typeof record.tag === 'string' ? record.tag : undefined,
      encoding: record.encoding === 'hex' || record.encoding === 'base64' || record.encoding === 'utf8'
        ? record.encoding
        : undefined
    };
  } catch {
    return undefined;
  }
}

async function encrypt(mode: AesMode, input: string, preferredEncoding: PreferredEncoding) {
  const key = await promptKey(preferredEncoding);
  const algorithm = aesAlgorithm(mode, key);
  const iv = await promptIv(mode, preferredEncoding);
  const warnings = validateIv(mode, iv);

  const cipher = createCipheriv(algorithm, key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(input, 'utf8')), cipher.final()]);
  const tag = mode === 'gcm' ? (cipher as unknown as { getAuthTag(): Buffer }).getAuthTag() : undefined;

  const payload = {
    alg: algorithm.toUpperCase(),
    encoding: 'base64',
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    ...(tag ? { tag: tag.toString('base64') } : {})
  };

  return {
    text: JSON.stringify(payload, null, 2),
    warnings,
    language: 'json' as const
  };
}

async function decrypt(mode: AesMode, input: string, preferredEncoding: PreferredEncoding) {
  const key = await promptKey(preferredEncoding);
  const algorithm = aesAlgorithm(mode, key);
  const parsed = tryParseCipherPayload(input.trim());
  const encoding = parsed?.encoding ?? await pickEncoding('Crypto Toolkit: ciphertext encoding', preferredEncoding === 'utf8' ? 'base64' : preferredEncoding);

  let iv: Buffer;
  let ciphertext: Buffer;
  let tag: Buffer | undefined;

  if (parsed) {
    const ivText = parsed.iv ?? parsed.nonce;
    if (!ivText) {
      throw new UserFacingError('AES decrypt input is incomplete.', {
        reason: 'The selected JSON contains ciphertext but no iv or nonce field.',
        expected: 'JSON with ciphertext and iv/nonce fields, plus tag for GCM.',
        hint: 'Select the complete JSON output produced by the matching AES encrypt command.'
      });
    }
    iv = decodeByEncoding(ivText, 'base64');
    ciphertext = decodeByEncoding(parsed.ciphertext, encoding);
    tag = parsed.tag ? decodeByEncoding(parsed.tag, 'base64') : undefined;
  } else {
    iv = await promptIvForDecrypt(mode, preferredEncoding);
    ciphertext = decodeByEncoding(input, encoding);
  }

  const warnings = validateIv(mode, iv);

  if (mode === 'gcm' && !tag) {
    const tagText = await promptSecretValue('Crypto Toolkit: AES-GCM authentication tag', 'Enter auth tag encoded as base64.', false);
    tag = decodeByEncoding(tagText, 'base64');
  }

  try {
    const decipher = createDecipheriv(algorithm, key, iv);
    if (mode === 'gcm') {
      if (!tag) {
        throw new UserFacingError('AES-GCM decrypt input is incomplete.', {
          reason: 'AES-GCM requires an authentication tag to verify integrity before plaintext is released.',
          expected: 'A tag field in the selected JSON or a Base64 tag entered in the prompt.',
          hint: 'Use the full AES-GCM encrypt output JSON, including tag.'
        });
      }
      (decipher as unknown as { setAuthTag(tag: Buffer): void }).setAuthTag(tag);
    }

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    return { text: plaintext, warnings, language: 'plaintext' as const };
  } catch (error) {
    if (error instanceof UserFacingError) {
      throw error;
    }
    throw new UserFacingError('AES decryption failed.', {
      reason: 'The crypto backend rejected the ciphertext or final padding/authentication check.',
      expected: 'Matching algorithm, key, IV/nonce, ciphertext encoding, and GCM tag when applicable.',
      hint: 'For CBC, verify padding/key/IV. For GCM, any wrong key, nonce, ciphertext, or tag will fail authentication.'
    });
  }
}

function aesOperation(id: string, title: string, mode: AesMode, direction: Direction): Operation {
  return {
    id,
    title,
    async run(input, context) {
      return direction === 'encrypt'
        ? encrypt(mode, input, context.settings.preferredEncoding)
        : decrypt(mode, input, context.settings.preferredEncoding);
    }
  };
}

export const aesCbcEncrypt = aesOperation('cryptoToolkit.aes.cbcEncrypt', 'AES-CBC Encrypt', 'cbc', 'encrypt');
export const aesCbcDecrypt = aesOperation('cryptoToolkit.aes.cbcDecrypt', 'AES-CBC Decrypt', 'cbc', 'decrypt');
export const aesGcmEncrypt = aesOperation('cryptoToolkit.aes.gcmEncrypt', 'AES-GCM Encrypt', 'gcm', 'encrypt');
export const aesGcmDecrypt = aesOperation('cryptoToolkit.aes.gcmDecrypt', 'AES-GCM Decrypt', 'gcm', 'decrypt');
