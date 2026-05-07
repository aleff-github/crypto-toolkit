import * as vscode from 'vscode';
import { createHash, createHmac } from 'crypto';
import { Operation } from '../commands/types';
import { decodeByEncoding } from '../crypto/buffer';
import { UserFacingError } from '../utils/errors';

type HashAlgorithm = 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512';

function hashOperation(id: string, title: string, algorithm: HashAlgorithm): Operation {
  return {
    id,
    title,
    run(input) {
      const text = createHash(algorithm).update(input, 'utf8').digest('hex');
      const warnings = algorithm === 'md5' || algorithm === 'sha1'
        ? [`${algorithm.toUpperCase()} is cryptographically broken. Use SHA-256 or stronger for security-sensitive work.`]
        : undefined;
      return { text, warnings, language: 'plaintext' };
    }
  };
}

async function promptSecret(defaultEncoding: string): Promise<string> {
  const secret = await vscode.window.showInputBox({
    title: 'Crypto Toolkit: HMAC secret',
    prompt: `Enter HMAC secret. It will be interpreted as ${defaultEncoding}.`,
    password: true,
    ignoreFocusOut: true
  });

  if (secret === undefined) {
    throw new UserFacingError('Operation cancelled.');
  }

  return secret;
}

function hmacOperation(id: string, title: string, algorithm: HashAlgorithm): Operation {
  return {
    id,
    title,
    async run(input, context) {
      const secret = await promptSecret(context.settings.preferredEncoding);
      const key = decodeByEncoding(secret, context.settings.preferredEncoding);
      return {
        text: createHmac(algorithm, key).update(input, 'utf8').digest('hex'),
        language: 'plaintext'
      };
    }
  };
}

export const md5Hash = hashOperation('cryptoToolkit.hash.md5', 'MD5', 'md5');
export const sha1Hash = hashOperation('cryptoToolkit.hash.sha1', 'SHA1', 'sha1');
export const sha256Hash = hashOperation('cryptoToolkit.hash.sha256', 'SHA256', 'sha256');
export const sha512Hash = hashOperation('cryptoToolkit.hash.sha512', 'SHA512', 'sha512');

export const hmacSha256 = hmacOperation('cryptoToolkit.hmac.sha256', 'HMAC-SHA256', 'sha256');
export const hmacSha384 = hmacOperation('cryptoToolkit.hmac.sha384', 'HMAC-SHA384', 'sha384');
export const hmacSha512 = hmacOperation('cryptoToolkit.hmac.sha512', 'HMAC-SHA512', 'sha512');
