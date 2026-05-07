import { Buffer } from 'buffer';
import { containsHtmlEntity, containsPercentEncoding, looksLikeJsonText, printableScore } from './scoring';
import { SmartDecodeCandidate } from './types';

type CheckStatus = 'accepted' | 'rejected' | 'skipped';

export interface DetectorCheck {
  detector: string;
  status: CheckStatus;
  reasons: string[];
}

function clamp(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function isBase64Charset(value: string): boolean {
  return /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function isBase64UrlCharset(value: string): boolean {
  return /^[A-Za-z0-9_-]+={0,2}$/.test(value);
}

function tryBase64Text(value: string): { ok: boolean; printable?: number; decodedPreview?: string; reason?: string } {
  const compact = value.replace(/\s+/g, '');
  if (compact.length === 0) return { ok: false, reason: 'empty input' };
  if (compact.length % 4 === 1) return { ok: false, reason: 'length modulo 4 equals 1' };
  if (!isBase64Charset(compact)) return { ok: false, reason: 'contains characters outside the Base64 alphabet' };
  try {
    const padded = compact.padEnd(Math.ceil(compact.length / 4) * 4, '=');
    const decoded = Buffer.from(padded, 'base64');
    const roundTrip = decoded.toString('base64').replace(/=+$/g, '');
    if (roundTrip !== compact.replace(/=+$/g, '')) return { ok: false, reason: 'Base64 round-trip check failed' };
    const text = decoded.toString('utf8');
    return { ok: true, printable: printableScore(text), decodedPreview: text.replace(/\s+/g, ' ').slice(0, 90) };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : 'Base64 decode failed' };
  }
}

function tryBase64UrlJson(value: string): { ok: boolean; reason?: string } {
  const compact = value.replace(/\s+/g, '').replace(/=+$/g, '');
  if (!compact) return { ok: false, reason: 'empty input' };
  if (compact.length % 4 === 1) return { ok: false, reason: 'length modulo 4 equals 1' };
  if (!isBase64UrlCharset(compact)) return { ok: false, reason: 'contains characters outside the Base64URL alphabet' };
  try {
    const normalized = compact.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(compact.length / 4) * 4, '=');
    const text = Buffer.from(normalized, 'base64').toString('utf8');
    JSON.parse(text);
    return { ok: true };
  } catch {
    return { ok: false, reason: 'decoded value is not valid JSON' };
  }
}

export function candidateReasons(candidate: SmartDecodeCandidate): string[] {
  if (candidate.reasons?.length) {
    return candidate.reasons;
  }

  const reasons: string[] = [];
  reasons.push(`confidence score: ${clamp(candidate.confidence)}%`);

  switch (candidate.kind) {
    case 'jwt':
      reasons.push('three dot-separated compact token segments were found');
      reasons.push('header and payload decoded as Base64URL JSON');
      if (candidate.metadata?.alg) reasons.push(`JOSE alg present: ${String(candidate.metadata.alg)}`);
      if (candidate.metadata?.kid) reasons.push('JOSE kid header is present');
      if (candidate.metadata?.exp || candidate.metadata?.iat || candidate.metadata?.nbf) reasons.push('time-based JWT claims were found');
      break;
    case 'jwe':
      reasons.push('five compact JOSE segments were found');
      if (candidate.metadata?.alg) reasons.push(`JWE alg present: ${String(candidate.metadata.alg)}`);
      if (candidate.metadata?.enc) reasons.push(`JWE enc present: ${String(candidate.metadata.enc)}`);
      break;
    case 'base64':
      reasons.push('input matches the Base64 alphabet and survived strict round-trip validation');
      if (candidate.metadata?.printableScore) reasons.push(`decoded printable score: ${String(candidate.metadata.printableScore)}%`);
      if (candidate.language === 'json') reasons.push('decoded output is valid JSON');
      break;
    case 'base64url':
      reasons.push('input matches Base64URL alphabet and survived strict validation');
      if (candidate.metadata?.printableScore) reasons.push(`decoded printable score: ${String(candidate.metadata.printableScore)}%`);
      if (candidate.language === 'json') reasons.push('decoded output is valid JSON');
      break;
    case 'hex':
      reasons.push('input is even-length hexadecimal');
      if (candidate.metadata?.printableScore) reasons.push(`decoded printable score: ${String(candidate.metadata.printableScore)}%`);
      break;
    case 'json':
      reasons.push('input starts and ends like JSON and JSON.parse succeeded');
      break;
    case 'queryString':
    case 'url':
      reasons.push('URLSearchParams parsed multiple key/value pairs');
      if (candidate.metadata?.paramCount) reasons.push(`parameter count: ${String(candidate.metadata.paramCount)}`);
      break;
    case 'cookie':
    case 'setCookie':
      reasons.push('semicolon-separated key/value pairs were parsed');
      if (candidate.kind === 'setCookie') reasons.push('Set-Cookie prefix or cookie attributes were present');
      break;
    case 'basicAuth':
      reasons.push('Basic Auth prefix was present');
      reasons.push('Base64 credentials decoded into username:password form');
      break;
    case 'passwordHash':
      reasons.push('input matches a known password-hash grammar');
      break;
    case 'hashLike':
    case 'checksum':
      reasons.push('hexadecimal length matches one or more common digest sizes');
      break;
    case 'secret':
      reasons.push('input matches a known provider token prefix/shape');
      break;
    case 'certificate':
    case 'publicKey':
    case 'privateKey':
    case 'pem':
      reasons.push('PEM BEGIN/END markers were found');
      break;
    case 'sshPublicKey':
      reasons.push('OpenSSH public key prefix and binary key blob parsed successfully');
      break;
    case 'otpauth':
      reasons.push('otpauth:// URI scheme was found and parsed');
      break;
    case 'saml':
      reasons.push('SAML XML Response/Assertion markers were found');
      break;
    case 'powershellEncodedCommand':
      reasons.push('Base64 decoded into mostly printable UTF-16LE text');
      break;
    default:
      reasons.push('format-specific detector matched the selected text');
      break;
  }

  for (const warning of candidate.warnings ?? []) {
    reasons.push(`warning: ${warning}`);
  }

  return reasons;
}

export function explainDetectorChecks(input: string): DetectorCheck[] {
  const trimmed = input.trim();
  const compact = trimmed.replace(/\s+/g, '');
  const checks: DetectorCheck[] = [];

  const push = (detector: string, status: CheckStatus, reasons: string[]) => checks.push({ detector, status, reasons });

  if (!trimmed) {
    push('Input', 'rejected', ['selection is empty after trimming whitespace']);
    return checks;
  }

  const jwtParts = trimmed.replace(/^Authorization\s*:\s*/i, '').replace(/^Bearer\s+/i, '').split('.');
  if (jwtParts.length === 3) {
    const header = tryBase64UrlJson(jwtParts[0]);
    const payload = tryBase64UrlJson(jwtParts[1]);
    push('JWT', header.ok && payload.ok ? 'accepted' : 'rejected', [
      'three dot-separated segments found',
      header.ok ? 'header is Base64URL JSON' : `header rejected: ${header.reason}`,
      payload.ok ? 'payload is Base64URL JSON' : `payload rejected: ${payload.reason}`
    ]);
  } else {
    push('JWT', 'rejected', [`expected 3 dot-separated segments, found ${jwtParts.length}`]);
  }

  if (jwtParts.length === 5) {
    const header = tryBase64UrlJson(jwtParts[0]);
    push('JWE', header.ok ? 'accepted' : 'rejected', [
      'five dot-separated segments found',
      header.ok ? 'protected header is Base64URL JSON' : `protected header rejected: ${header.reason}`
    ]);
  } else {
    push('JWE', 'rejected', [`expected 5 dot-separated segments, found ${jwtParts.length}`]);
  }

  if (looksLikeJsonText(trimmed)) push('JSON', 'accepted', ['JSON.parse succeeded']);
  else push('JSON', 'rejected', ['input is not a valid JSON object/array']);

  const b64 = tryBase64Text(compact);
  if (b64.ok) {
    push('Base64', b64.printable && b64.printable >= 70 ? 'accepted' : 'rejected', [
      'charset and round-trip checks passed',
      `decoded printable score: ${b64.printable ?? 0}%`,
      b64.decodedPreview ? `decoded preview: ${b64.decodedPreview}` : 'no decoded preview'
    ]);
  } else {
    push('Base64', 'rejected', [b64.reason ?? 'Base64 decode failed']);
  }

  if (/^[A-Za-z0-9_-]+={0,2}$/.test(compact) && compact.length >= 8) {
    push('Base64URL', compact.includes('-') || compact.includes('_') || compact.length % 4 !== 0 ? 'accepted' : 'skipped', [
      compact.includes('-') || compact.includes('_') ? 'URL-specific characters found' : 'no URL-specific characters found',
      compact.length % 4 !== 0 ? 'unpadded Base64URL-like length found' : 'length is also compatible with regular Base64'
    ]);
  } else {
    push('Base64URL', 'rejected', ['input does not match the Base64URL alphabet or is too short']);
  }

  if (/^[0-9a-fA-F]+$/.test(compact)) {
    push('Hex', compact.length % 2 === 0 && compact.length >= 8 ? 'accepted' : 'rejected', [
      compact.length % 2 === 0 ? 'even number of hex characters' : 'odd number of hex characters',
      compact.length >= 8 ? 'length is large enough for decoding' : 'too short; likely ambiguous'
    ]);
  } else {
    push('Hex', 'rejected', ['contains non-hex characters']);
  }

  push('URL encoded', containsPercentEncoding(trimmed) ? 'accepted' : 'rejected', [
    containsPercentEncoding(trimmed) ? 'contains %XX escape sequences' : 'does not contain %XX escape sequences'
  ]);

  push('HTML entities', containsHtmlEntity(trimmed) ? 'accepted' : 'rejected', [
    containsHtmlEntity(trimmed) ? 'contains HTML entity syntax' : 'no HTML entity syntax found'
  ]);

  if (trimmed.includes('=') && (trimmed.includes('&') || trimmed.startsWith('?') || /^https?:\/\//i.test(trimmed))) {
    push('Query string', 'accepted', ['key=value pairs and query separators were found']);
  } else {
    push('Query string', 'rejected', ['requires key=value pairs plus &, ?, or full URL context']);
  }

  if (/^(Set-Cookie|Cookie)\s*:/i.test(trimmed) || (trimmed.includes('=') && trimmed.includes(';'))) {
    push('Cookie', 'accepted', ['cookie-like key=value pairs separated by semicolons were found']);
  } else {
    push('Cookie', 'rejected', ['requires Cookie/Set-Cookie prefix or semicolon-separated key=value pairs']);
  }

  push('Basic Auth', /^(Authorization\s*:\s*)?Basic\s+/i.test(trimmed) ? 'accepted' : 'rejected', [
    /^(Authorization\s*:\s*)?Basic\s+/i.test(trimmed) ? 'Basic prefix found' : 'missing Basic prefix'
  ]);

  push('PEM / OpenPGP', /^-----BEGIN [A-Z0-9 ]+-----/m.test(trimmed) ? 'accepted' : 'rejected', [
    /^-----BEGIN [A-Z0-9 ]+-----/m.test(trimmed) ? 'BEGIN armor marker found' : 'no BEGIN armor marker found'
  ]);

  push('Secret/API key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[pousr]_|github_pat_|xox[baprs]-|AIza|sk-|sk_(?:live|test)_|npm_)/.test(trimmed) ? 'accepted' : 'rejected', [
    'checked common AWS/GitHub/Slack/Google/OpenAI-like/Stripe/npm token prefixes'
  ]);

  return checks;
}

export function explainWhyNotDetected(input: string): string {
  const checks = explainDetectorChecks(input);
  const accepted = checks.filter((check) => check.status === 'accepted');
  const rejected = checks.filter((check) => check.status !== 'accepted');

  return JSON.stringify({
    inputLength: input.length,
    acceptedChecks: accepted,
    rejectedChecks: rejected,
    guidance: accepted.length > 0
      ? 'One or more lightweight checks looked promising. Use Crypto Toolkit: Detect and open View more to see candidates and confidence thresholds.'
      : 'No lightweight checks matched strongly. The selection is likely plain text, too short/ambiguous, or an unsupported format.'
  }, null, 2);
}
