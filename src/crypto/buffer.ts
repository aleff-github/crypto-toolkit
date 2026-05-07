import { UserFacingError } from '../utils/errors';
import { PreferredEncoding } from '../commands/types';

export function bufferFromUtf8(value: string): Buffer {
  return Buffer.from(value, 'utf8');
}

export function bufferToUtf8(value: Buffer): string {
  return value.toString('utf8');
}

export function toBase64Url(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

export function fromBase64Url(value: string): Buffer {
  const normalized = value.trim().replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(normalized);
}

export function fromBase64(value: string): Buffer {
  const compact = value.trim().replace(/\s+/g, '');

  if (compact.length === 0) {
    return Buffer.alloc(0);
  }

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 === 1) {
    throw new UserFacingError('Malformed Base64 input. Base64 Decode failed.', {
      reason: 'The selected text contains characters or padding that are not valid for strict Base64.',
      expected: 'Characters A-Z, a-z, 0-9, +, / with optional = padding.',
      hint: 'If the value contains - or _, try Base64URL Decode instead. If it contains %, run URL Decode first.'
    });
  }

  const padded = compact.padEnd(Math.ceil(compact.length / 4) * 4, '=');
  const decoded = Buffer.from(padded, 'base64');

  // Node is permissive when decoding Base64. Round-trip to catch malformed data.
  const roundTrip = decoded.toString('base64').replace(/=+$/g, '');
  const original = compact.replace(/=+$/g, '');
  if (roundTrip !== original) {
    throw new UserFacingError('Malformed Base64 input. Base64 Decode failed.', {
      reason: 'The selected text contains characters or padding that are not valid for strict Base64.',
      expected: 'Characters A-Z, a-z, 0-9, +, / with optional = padding.',
      hint: 'If the value contains - or _, try Base64URL Decode instead. If it contains %, run URL Decode first.'
    });
  }

  return decoded;
}

export function fromHex(value: string): Buffer {
  const compact = value.trim().replace(/\s+/g, '');

  if (compact.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(compact)) {
    throw new UserFacingError('Malformed hex input. Hex Decode failed.', {
      reason: `The selection has ${compact.length} compact character(s) and ${/^[0-9a-fA-F]*$/.test(compact) ? 'uses valid hex characters' : 'contains non-hex characters'}.`,
      expected: 'An even number of characters using only 0-9, a-f, or A-F.',
      hint: 'Remove prefixes like 0x, separators, quotes, or whitespace that is not part of the hex payload.'
    });
  }

  return Buffer.from(compact, 'hex');
}

export function decodeByEncoding(value: string, encoding: PreferredEncoding): Buffer {
  switch (encoding) {
    case 'utf8':
      return Buffer.from(value, 'utf8');
    case 'hex':
      return fromHex(value);
    case 'base64':
      return fromBase64(value);
    default:
      return Buffer.from(value, 'utf8');
  }
}

export function encodeByEncoding(value: Buffer, encoding: PreferredEncoding): string {
  switch (encoding) {
    case 'utf8':
      return value.toString('utf8');
    case 'hex':
      return value.toString('hex');
    case 'base64':
      return value.toString('base64');
    default:
      return value.toString('utf8');
  }
}
