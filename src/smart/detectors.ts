import { Buffer } from 'buffer';
import { createHash, createPrivateKey, createPublicKey, X509Certificate, KeyObject } from 'crypto';
import { fromBase64, fromHex, toBase64Url } from '../crypto/buffer';
import { SmartDecodeCandidate, DetectorContext, SmartDetector } from './types';
import {
  clampConfidence,
  containsHtmlEntity,
  containsPercentEncoding,
  countObjectKeys,
  hasCommonTokenClaim,
  hasCommonWebParam,
  isLikelyIsoDate,
  isMostlyPrintable,
  looksLikeJsonText,
  makePreview,
  printableScore,
  safeJsonParse,
  stringifyJson
} from './scoring';

function candidate(base: Omit<SmartDecodeCandidate, 'confidence'> & { confidence: number }): SmartDecodeCandidate {
  return { ...base, confidence: clampConfidence(base.confidence) };
}

function stripBearer(value: string): string {
  return value.replace(/^Authorization\s*:\s*/i, '').replace(/^Bearer\s+/i, '').trim();
}

function stripBasic(value: string): string {
  return value.replace(/^Authorization\s*:\s*/i, '').replace(/^Basic\s+/i, '').trim();
}

function base64UrlToBufferStrict(value: string): Buffer | undefined {
  const compact = value.trim().replace(/\s+/g, '');
  if (!compact || compact.length % 4 === 1 || !/^[A-Za-z0-9_-]+={0,2}$/.test(compact)) {
    return undefined;
  }

  try {
    const normalized = compact.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(compact.length / 4) * 4, '=');
    const decoded = Buffer.from(normalized, 'base64');
    const roundTrip = toBase64Url(decoded);
    const original = compact.replace(/=+$/g, '');
    if (roundTrip !== original) {
      return undefined;
    }
    return decoded;
  } catch {
    return undefined;
  }
}

function decodeUriComponentSafe(value: string): string | undefined {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return undefined;
  }
}

function decodeHtmlEntities(input: string): string {
  const named: Record<string, string> = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    '#39': "'",
    nbsp: '\u00a0',
    colon: ':',
    sol: '/',
    equals: '=',
    lpar: '(',
    rpar: ')',
    comma: ',',
    semi: ';'
  };

  return input.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]+);/g, (match, entity: string) => {
    if (Object.prototype.hasOwnProperty.call(named, entity)) {
      return named[entity];
    }

    if (entity.startsWith('#x')) {
      const code = Number.parseInt(entity.slice(2), 16);
      return Number.isFinite(code) ? String.fromCodePoint(code) : match;
    }

    if (entity.startsWith('#')) {
      const code = Number.parseInt(entity.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : match;
    }

    return match;
  });
}

function parseJwtPart(value: string): Record<string, unknown> | undefined {
  const decoded = base64UrlToBufferStrict(value)?.toString('utf8');
  if (!decoded) {
    return undefined;
  }
  const parsed = safeJsonParse(decoded);
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
}

function toIsoSeconds(value: unknown): string | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return undefined;
  }
  const date = new Date(value * 1000);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export const detectJwt: SmartDetector = ({ originalInput, trimmedInput }) => {
  const token = stripBearer(trimmedInput);
  const parts = token.split('.');

  if (parts.length !== 3) {
    return [];
  }

  const warnings: string[] = [];
  const header = parseJwtPart(parts[0]);
  const payload = parseJwtPart(parts[1]);

  if (!header || !payload) {
    return [candidate({
      kind: 'jwt',
      label: 'Malformed JWT-like token',
      confidence: 48,
      input: originalInput,
      output: JSON.stringify({ token, error: 'Three dot-separated segments found, but header or payload is not valid Base64URL JSON.' }, null, 2),
      preview: 'Three JWT-like segments found, but decode failed.',
      warnings: ['Malformed JWT structure or invalid Base64URL JSON segment.'],
      language: 'json',
      severity: 'warning'
    })];
  }

  let confidence = 74;
  if (typeof header.alg === 'string') confidence += 12;
  if (typeof header.typ === 'string' && /jwt/i.test(header.typ)) confidence += 5;
  if (typeof header.kid === 'string') confidence += 4;
  if (hasCommonTokenClaim(payload)) confidence += 8;
  if (typeof payload.exp === 'number') confidence += 3;
  if (parts[2].length > 0) confidence += 3;
  if (/^Authorization\s*:/i.test(trimmedInput) || /^Bearer\s+/i.test(trimmedInput)) confidence += 5;

  if (header.alg === 'none') {
    warnings.push('JWT uses alg=none. Treat unsigned tokens with extreme caution.');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === 'number' && payload.exp < nowSeconds) {
    warnings.push('JWT token is expired.');
  }
  if (typeof payload.nbf === 'number' && payload.nbf > nowSeconds) {
    warnings.push('JWT token is not valid yet according to nbf.');
  }

  const highlighted = {
    alg: header.alg ?? null,
    kid: header.kid ?? null,
    exp: payload.exp ?? null,
    exp_iso: toIsoSeconds(payload.exp) ?? null,
    iat: payload.iat ?? null,
    iat_iso: toIsoSeconds(payload.iat) ?? null,
    nbf: payload.nbf ?? null,
    nbf_iso: toIsoSeconds(payload.nbf) ?? null
  };

  return [candidate({
    kind: 'jwt',
    label: 'JWT Decode',
    confidence,
    input: originalInput,
    output: JSON.stringify({ header, highlighted, payload, signature: parts[2], warnings }, null, 2),
    preview: `alg=${String(header.alg ?? 'unknown')}${payload.sub ? ` sub=${String(payload.sub)}` : ''}${payload.iss ? ` iss=${String(payload.iss)}` : ''}`,
    warnings,
    language: 'json',
    metadata: highlighted,
    severity: warnings.some((warning) => /expired|none|not valid/i.test(warning)) ? 'warning' : 'info'
  })];
};

export const detectJson: SmartDetector = ({ originalInput, trimmedInput }) => {
  if (!trimmedInput || !looksLikeJsonText(trimmedInput)) {
    return [];
  }

  const parsed = safeJsonParse(trimmedInput);
  if (parsed === undefined) {
    return [];
  }

  let confidence = 78;
  if (countObjectKeys(parsed) >= 2) confidence += 8;
  if (Array.isArray(parsed)) confidence += 4;

  return [candidate({
    kind: 'json',
    label: 'JSON Pretty',
    confidence,
    input: originalInput,
    output: stringifyJson(parsed),
    preview: `${Array.isArray(parsed) ? 'array' : typeof parsed}${countObjectKeys(parsed) ? `, ${countObjectKeys(parsed)} keys` : ''}`,
    warnings: [],
    language: 'json'
  })];
};

export const detectBase64: SmartDetector = ({ originalInput, compactInput }) => {
  const compact = compactInput;
  if (compact.length < 8 || compact.includes('.') || /[-_]/.test(compact)) {
    return [];
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact) || compact.length % 4 === 1) {
    return [];
  }

  try {
    const decoded = fromBase64(compact);
    if (decoded.length === 0) {
      return [];
    }
    const output = decoded.toString('utf8');
    const pScore = printableScore(output);
    if (pScore < 70) {
      return [];
    }

    let confidence = 38;
    if (compact.length % 4 === 0) confidence += 10;
    if (/={1,2}$/.test(compact)) confidence += 5;
    if (pScore >= 90) confidence += 25;
    if (looksLikeJsonText(output)) confidence += 18;
    if (/^[\w .,:;!?@/+\-=\n\r\t{}\[\]"']+$/.test(output)) confidence += 5;
    if (compact.length < 12 && !looksLikeJsonText(output)) confidence -= 10;

    return [candidate({
      kind: 'base64',
      label: 'Base64 Decode',
      confidence,
      input: originalInput,
      output: looksLikeJsonText(output) ? stringifyJson(safeJsonParse(output)) : output,
      preview: makePreview(output),
      warnings: [],
      language: looksLikeJsonText(output) ? 'json' : 'plaintext',
      metadata: { decodedBytes: decoded.length, printableScore: pScore }
    })];
  } catch {
    return [];
  }
};

export const detectBase64Url: SmartDetector = ({ originalInput, compactInput }) => {
  const compact = compactInput.replace(/^Bearer\s+/i, '');
  const hasUrlSpecificChars = /[-_]/.test(compact);
  const isPotentialUnpadded = /^[A-Za-z0-9_-]+$/.test(compact) && compact.length % 4 !== 0;

  if (compact.length < 8 || compact.includes('.') || !(hasUrlSpecificChars || isPotentialUnpadded)) {
    return [];
  }
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(compact)) {
    return [];
  }

  const decoded = base64UrlToBufferStrict(compact);
  if (!decoded || decoded.length === 0) {
    return [];
  }

  const output = decoded.toString('utf8');
  const pScore = printableScore(output);
  if (pScore < 70) {
    return [];
  }

  let confidence = 42;
  if (hasUrlSpecificChars) confidence += 20;
  if (compact.length % 4 !== 0) confidence += 7;
  if (pScore >= 90) confidence += 18;
  if (looksLikeJsonText(output)) confidence += 18;

  return [candidate({
    kind: 'base64url',
    label: 'Base64URL Decode',
    confidence,
    input: originalInput,
    output: looksLikeJsonText(output) ? stringifyJson(safeJsonParse(output)) : output,
    preview: makePreview(output),
    warnings: [],
    language: looksLikeJsonText(output) ? 'json' : 'plaintext',
    metadata: { decodedBytes: decoded.length, printableScore: pScore }
  })];
};

export const detectHex: SmartDetector = ({ originalInput, compactInput }) => {
  const compact = compactInput;
  if (compact.length < 8 || compact.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(compact)) {
    return [];
  }

  try {
    const decoded = fromHex(compact);
    const output = decoded.toString('utf8');
    const pScore = printableScore(output);
    if (pScore < 80) {
      return [];
    }

    let confidence = 44;
    if (compact.length >= 16) confidence += 10;
    if (pScore >= 90) confidence += 24;
    if (looksLikeJsonText(output)) confidence += 18;
    if (/^(0x)?[0-9a-fA-F]+$/.test(originalInput.trim())) confidence += 5;

    return [candidate({
      kind: 'hex',
      label: 'Hex Decode',
      confidence,
      input: originalInput,
      output: looksLikeJsonText(output) ? stringifyJson(safeJsonParse(output)) : output,
      preview: makePreview(output),
      warnings: [],
      language: looksLikeJsonText(output) ? 'json' : 'plaintext',
      metadata: { decodedBytes: decoded.length, printableScore: pScore }
    })];
  } catch {
    return [];
  }
};

export const detectUrlEncoded: SmartDetector = ({ originalInput, trimmedInput }) => {
  if (!containsPercentEncoding(trimmedInput) && !/[?&][^=\s]+=[^\s]*/.test(trimmedInput)) {
    return [];
  }

  const decoded = decodeUriComponentSafe(trimmedInput);
  if (decoded === undefined || decoded === trimmedInput) {
    return [];
  }

  let confidence = 42;
  const matches = trimmedInput.match(/%[0-9a-fA-F]{2}/g)?.length ?? 0;
  confidence += Math.min(25, matches * 4);
  if (isMostlyPrintable(decoded)) confidence += 18;
  if (decoded.includes('=') && decoded.includes('&')) confidence += 6;
  if (/https?:\/\//i.test(decoded)) confidence += 5;

  return [candidate({
    kind: 'urlEncoded',
    label: 'URL Decode',
    confidence,
    input: originalInput,
    output: decoded,
    preview: makePreview(decoded),
    warnings: [],
    language: 'plaintext'
  })];
};

export const detectHtmlEntities: SmartDetector = ({ originalInput, trimmedInput }) => {
  if (!containsHtmlEntity(trimmedInput)) {
    return [];
  }

  const decoded = decodeHtmlEntities(trimmedInput);
  if (decoded === trimmedInput) {
    return [];
  }

  const entityCount = trimmedInput.match(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]+);/g)?.length ?? 0;
  return [candidate({
    kind: 'htmlEntities',
    label: 'HTML Entity Decode',
    confidence: 58 + Math.min(25, entityCount * 5),
    input: originalInput,
    output: decoded,
    preview: makePreview(decoded),
    warnings: [],
    language: 'plaintext'
  })];
};

export const detectUnixTimestamp: SmartDetector = ({ originalInput, trimmedInput }) => {
  if (!/^\d{10,13}$/.test(trimmedInput)) {
    return [];
  }

  const numeric = Number(trimmedInput);
  const milliseconds = trimmedInput.length === 13 ? numeric : numeric * 1000;
  const date = new Date(milliseconds);
  if (!isLikelyIsoDate(date)) {
    return [];
  }

  const now = Date.now();
  let confidence = 58;
  if (Math.abs(now - milliseconds) < 1000 * 60 * 60 * 24 * 365 * 15) confidence += 18;
  if (trimmedInput.length === 10 || trimmedInput.length === 13) confidence += 12;

  return [candidate({
    kind: 'unixTimestamp',
    label: 'Unix Timestamp Decode',
    confidence,
    input: originalInput,
    output: JSON.stringify({ input: trimmedInput, seconds: Math.floor(milliseconds / 1000), milliseconds, iso: date.toISOString(), utc: date.toUTCString(), local: date.toString() }, null, 2),
    preview: date.toISOString(),
    warnings: [],
    language: 'json'
  })];
};

function paramsToObject(params: URLSearchParams): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [key, value] of params.entries()) {
    const existing = out[key];
    if (Array.isArray(existing)) {
      existing.push(value);
    } else if (existing !== undefined) {
      out[key] = [existing, value];
    } else {
      out[key] = value;
    }
  }
  return out;
}

export const detectQueryString: SmartDetector = ({ originalInput, trimmedInput }) => {
  let source = trimmedInput;
  let urlMetadata: Record<string, unknown> | undefined;

  try {
    if (/^https?:\/\//i.test(trimmedInput)) {
      const url = new URL(trimmedInput);
      source = url.search.startsWith('?') ? url.search.slice(1) : url.search;
      urlMetadata = { protocol: url.protocol, host: url.host, path: url.pathname, hash: url.hash };
    } else if (trimmedInput.startsWith('?')) {
      source = trimmedInput.slice(1);
    }
  } catch {
    return [];
  }

  if (!source || !source.includes('=') || !(source.includes('&') || /^https?:\/\//i.test(trimmedInput) || trimmedInput.startsWith('?'))) {
    return [];
  }

  try {
    const params = new URLSearchParams(source);
    const entries = Array.from(params.entries());
    if (entries.length < 2) {
      return [];
    }

    let confidence = 55 + Math.min(20, entries.length * 3);
    if (entries.some(([key]) => hasCommonWebParam(key))) confidence += 15;
    if (containsPercentEncoding(source)) confidence += 8;
    if (/^https?:\/\//i.test(trimmedInput)) confidence += 5;

    const paramsObject = paramsToObject(params);
    const output = JSON.stringify({ type: /^https?:\/\//i.test(trimmedInput) ? 'url-query-string' : 'query-string', ...urlMetadata, params: paramsObject }, null, 2);

    return [candidate({
      kind: /^https?:\/\//i.test(trimmedInput) ? 'url' : 'queryString',
      label: /^https?:\/\//i.test(trimmedInput) ? 'URL Query String Pretty' : 'Query String Pretty',
      confidence,
      input: originalInput,
      output,
      preview: entries.slice(0, 4).map(([key, value]) => `${key}=${makePreview(value, 40)}`).join(' | '),
      warnings: [],
      language: 'json',
      metadata: { paramCount: entries.length, ...urlMetadata }
    })];
  } catch {
    return [];
  }
};

function parseCookiePairs(source: string): Record<string, string | boolean> {
  const pairs: Record<string, string | boolean> = {};
  for (const part of source.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf('=');
    if (index === -1) {
      pairs[trimmed] = true;
    } else {
      const key = trimmed.slice(0, index).trim();
      const value = trimmed.slice(index + 1).trim();
      if (key) pairs[key] = value;
    }
  }
  return pairs;
}

export const detectCookie: SmartDetector = ({ originalInput, trimmedInput }) => {
  const isSetCookie = /^Set-Cookie\s*:/i.test(trimmedInput);
  const isCookie = /^Cookie\s*:/i.test(trimmedInput);
  const source = trimmedInput.replace(/^(Set-Cookie|Cookie)\s*:\s*/i, '');

  if (!source.includes('=') || !source.includes(';')) {
    return [];
  }

  const pairs = parseCookiePairs(source);
  const keys = Object.keys(pairs);
  if (keys.length < 2) {
    return [];
  }

  let confidence = isCookie || isSetCookie ? 70 : 52;
  if (keys.some((key) => /session|csrf|xsrf|jwt|token|auth|sid|refresh/i.test(key))) confidence += 14;
  if (isSetCookie && keys.some((key) => /httponly|secure|samesite|max-age|expires|path|domain/i.test(key))) confidence += 10;

  const warnings: string[] = [];
  if (isSetCookie) {
    const flags = new Set(keys.map((key) => key.toLowerCase()));
    if (!flags.has('httponly')) warnings.push('Set-Cookie does not include HttpOnly.');
    if (!flags.has('secure')) warnings.push('Set-Cookie does not include Secure.');
    if (!flags.has('samesite')) warnings.push('Set-Cookie does not include SameSite.');
  }

  return [candidate({
    kind: isSetCookie ? 'setCookie' : 'cookie',
    label: isSetCookie ? 'Set-Cookie Pretty' : 'Cookie Pretty',
    confidence,
    input: originalInput,
    output: JSON.stringify({ type: isSetCookie ? 'set-cookie' : 'cookie', values: pairs, warnings }, null, 2),
    preview: keys.slice(0, 5).join(', '),
    warnings,
    language: 'json',
    metadata: { keyCount: keys.length },
    severity: warnings.length ? 'warning' : 'info'
  })];
};

export const detectBasicAuth: SmartDetector = ({ originalInput, trimmedInput }) => {
  const hasPrefix = /^(Authorization\s*:\s*)?Basic\s+/i.test(trimmedInput);
  if (!hasPrefix) {
    return [];
  }

  const encoded = stripBasic(trimmedInput);
  let decoded: string;
  try {
    decoded = fromBase64(encoded).toString('utf8');
  } catch {
    return [candidate({
      kind: 'basicAuth',
      label: 'Malformed Basic Auth',
      confidence: 55,
      input: originalInput,
      output: JSON.stringify({ error: 'Basic Auth prefix found, but credentials are not valid Base64.' }, null, 2),
      preview: 'Basic prefix found, Base64 decode failed.',
      warnings: ['Malformed Basic Auth credentials.'],
      language: 'json',
      severity: 'warning'
    })];
  }

  const colonIndex = decoded.indexOf(':');
  if (colonIndex <= 0) {
    return [];
  }

  const username = decoded.slice(0, colonIndex);
  const password = decoded.slice(colonIndex + 1);
  const warnings = ['Basic Auth credentials are only encoded, not encrypted.'];
  return [candidate({
    kind: 'basicAuth',
    label: 'Basic Auth Decode',
    confidence: 100,
    input: originalInput,
    output: JSON.stringify({ username, password, raw: decoded, warnings }, null, 2),
    preview: `${username}:********`,
    warnings,
    language: 'json',
    severity: 'warning'
  })];
};

export const detectPowerShellEncodedCommand: SmartDetector = ({ originalInput, compactInput }) => {
  if (compactInput.length < 16 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compactInput) || compactInput.length % 4 === 1) {
    return [];
  }

  let decodedBuffer: Buffer;
  try {
    decodedBuffer = fromBase64(compactInput);
  } catch {
    return [];
  }

  if (decodedBuffer.length < 4 || decodedBuffer.length % 2 !== 0) {
    return [];
  }

  const output = decodedBuffer.toString('utf16le');
  const pScore = printableScore(output);
  if (pScore < 80 || output.length < 4) {
    return [];
  }

  const psIndicators = [/\bInvoke-?/i, /\bIEX\b/i, /\bGet-/i, /\bSet-/i, /\bNew-/i, /\bWrite-/i, /\$[A-Za-z_][\w]*/, /\|/];
  const indicatorCount = psIndicators.filter((regex) => regex.test(output)).length;

  let confidence = 40 + Math.min(25, indicatorCount * 8);
  if (pScore >= 95) confidence += 14;
  if (/[\u0000-\u001f]/.test(output.replace(/[\r\n\t]/g, ''))) confidence -= 15;
  if (indicatorCount === 0 && !/^[\w\s'"(){}\[\].,;:\-/\\]+$/.test(output)) confidence -= 12;

  if (confidence < 45) {
    return [];
  }

  const warnings = ['PowerShell EncodedCommand uses Base64 over UTF-16LE; review content before execution.'];
  return [candidate({
    kind: 'powershellEncodedCommand',
    label: 'PowerShell EncodedCommand Decode',
    confidence,
    input: originalInput,
    output,
    preview: makePreview(output),
    warnings,
    language: 'plaintext',
    severity: 'warning',
    metadata: { decodedBytes: decodedBuffer.length, sha256: createHash('sha256').update(decodedBuffer).digest('hex') }
  })];
};

export const detectUuid: SmartDetector = ({ originalInput, trimmedInput }) => {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(trimmedInput)) {
    return [];
  }

  const version = trimmedInput[14];
  return [candidate({
    kind: 'uuid',
    label: 'UUID Inspect',
    confidence: 92,
    input: originalInput,
    output: JSON.stringify({ uuid: trimmedInput, version }, null, 2),
    preview: `UUID v${version}`,
    warnings: [],
    language: 'json',
    metadata: { version }
  })];
};



type SshString = { value: Buffer; next: number };

function decodeBase64Loose(value: string): Buffer | undefined {
  const compact = value.trim().replace(/\s+/g, '');
  if (!compact || compact.length % 4 === 1 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) {
    return undefined;
  }

  try {
    return fromBase64(compact);
  } catch {
    return undefined;
  }
}

function readSshString(buffer: Buffer, offset: number): SshString | undefined {
  if (offset + 4 > buffer.length) {
    return undefined;
  }
  const length = buffer.readUInt32BE(offset);
  const start = offset + 4;
  const end = start + length;
  if (length < 0 || end > buffer.length) {
    return undefined;
  }
  return { value: buffer.subarray(start, end), next: end };
}

function sha256Fingerprint(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('base64').replace(/=+$/g, '');
}

function keyMetadata(key: KeyObject): Record<string, unknown> {
  const details = key.asymmetricKeyDetails ?? {};
  return {
    type: key.type,
    asymmetricKeyType: key.asymmetricKeyType ?? 'unknown',
    modulusLength: 'modulusLength' in details ? details.modulusLength : undefined,
    publicExponent: 'publicExponent' in details ? String(details.publicExponent) : undefined,
    namedCurve: 'namedCurve' in details ? details.namedCurve : undefined
  };
}

function certificateDate(value: string): Date | undefined {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

export const detectPem: SmartDetector = ({ originalInput, trimmedInput }) => {
  const pemMatch = trimmedInput.match(/^-----BEGIN ([A-Z0-9][A-Z0-9 ]+)-----[\s\S]+-----END \1-----$/m);
  if (!pemMatch) {
    return [];
  }

  const pemType = pemMatch[1];
  const warnings: string[] = [];

  if (pemType === 'CERTIFICATE') {
    try {
      const cert = new X509Certificate(trimmedInput);
      const validFrom = certificateDate(cert.validFrom);
      const validTo = certificateDate(cert.validTo);
      const now = new Date();
      if (validTo && validTo.getTime() < now.getTime()) {
        warnings.push('Certificate is expired.');
      }
      if (validFrom && validFrom.getTime() > now.getTime()) {
        warnings.push('Certificate is not valid yet.');
      }
      if (cert.subject === cert.issuer) {
        warnings.push('Certificate appears to be self-signed based on subject/issuer equality.');
      }

      const pub = cert.publicKey;
      const metadata = {
        pemType,
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        serialNumber: cert.serialNumber,
        fingerprint256: cert.fingerprint256,
        publicKey: keyMetadata(pub),
        subjectAltName: cert.subjectAltName ?? null
      };

      return [candidate({
        kind: 'certificate',
        label: 'X.509 Certificate Inspect',
        confidence: 98,
        input: originalInput,
        output: JSON.stringify({ type: 'x509-certificate', ...metadata, warnings }, null, 2),
        preview: `${cert.subject || 'certificate'} issued by ${cert.issuer || 'unknown issuer'}`,
        warnings,
        language: 'json',
        metadata,
        severity: warnings.length ? 'warning' : 'info'
      })];
    } catch {
      return [candidate({
        kind: 'certificate',
        label: 'Malformed X.509 Certificate PEM',
        confidence: 75,
        input: originalInput,
        output: JSON.stringify({ type: 'x509-certificate', pemType, error: 'PEM marker found, but Node.js could not parse it as an X.509 certificate.' }, null, 2),
        preview: 'Certificate PEM markers found, parse failed.',
        warnings: ['Malformed or unsupported certificate PEM.'],
        language: 'json',
        severity: 'warning'
      })];
    }
  }

  if (/PRIVATE KEY/.test(pemType)) {
    try {
      const key = createPrivateKey(trimmedInput);
      const metadata: Record<string, unknown> = { pemType, ...keyMetadata(key) };
      warnings.push('Private key material is selected. Do not commitr or share this value.');
      return [candidate({
        kind: 'privateKey',
        label: 'Private Key Inspect',
        confidence: 97,
        input: originalInput,
        output: JSON.stringify({ type: 'private-key', ...metadata, warnings }, null, 2),
        preview: `${String(metadata.asymmetricKeyType)} private key`,
        warnings,
        language: 'json',
        metadata,
        severity: 'danger'
      })];
    } catch {
      return [candidate({
        kind: 'privateKey',
        label: 'Private Key PEM',
        confidence: 82,
        input: originalInput,
        output: JSON.stringify({ type: 'private-key', pemType, parseable: false, warnings: ['Private key marker found, but parsing failed.'] }, null, 2),
        preview: `${pemType} marker found`,
        warnings: ['Private key marker found. Treat as sensitive even if parsing failed.'],
        language: 'json',
        severity: 'danger'
      })];
    }
  }

  if (/PUBLIC KEY/.test(pemType)) {
    try {
      const key = createPublicKey(trimmedInput);
      const metadata: Record<string, unknown> = { pemType, ...keyMetadata(key) };
      return [candidate({
        kind: 'publicKey',
        label: 'Public Key Inspect',
        confidence: 95,
        input: originalInput,
        output: JSON.stringify({ type: 'public-key', ...metadata }, null, 2),
        preview: `${String(metadata.asymmetricKeyType)} public key`,
        warnings: [],
        language: 'json',
        metadata
      })];
    } catch {
      return [candidate({
        kind: 'publicKey',
        label: 'Public Key PEM',
        confidence: 76,
        input: originalInput,
        output: JSON.stringify({ type: 'public-key', pemType, parseable: false }, null, 2),
        preview: `${pemType} marker found`,
        warnings: ['Public key marker found, but parsing failed.'],
        language: 'json',
        severity: 'warning'
      })];
    }
  }

  return [candidate({
    kind: 'pem',
    label: 'PEM Block Inspect',
    confidence: 88,
    input: originalInput,
    output: JSON.stringify({ type: 'pem-block', pemType }, null, 2),
    preview: pemType,
    warnings: [],
    language: 'json',
    metadata: { pemType }
  })];
};

export const detectOpenPgp: SmartDetector = ({ originalInput, trimmedInput }) => {
  const match = trimmedInput.match(/^-----BEGIN PGP ([A-Z ]+)-----[\s\S]+-----END PGP \1-----$/m);
  if (!match) {
    return [];
  }

  const pgpType = match[1].trim();
  const warnings: string[] = [];
  if (/PRIVATE KEY/i.test(pgpType)) {
    warnings.push('OpenPGP private key material is selected. Do not commitr or share this value.');
  }
  const armorHeaders: Record<string, string> = {};
  for (const line of trimmedInput.split(/\r?\n/g)) {
    const header = line.match(/^([A-Za-z][A-Za-z-]+):\s*(.+)$/);
    if (header) {
      armorHeaders[header[1]] = header[2];
    }
  }

  return [candidate({
    kind: 'openpgp',
    label: 'OpenPGP Armor Inspect',
    confidence: 96,
    input: originalInput,
    output: JSON.stringify({ type: 'openpgp-armor', pgpType, armorHeaders, warnings }, null, 2),
    preview: `PGP ${pgpType}`,
    warnings,
    language: 'json',
    metadata: { pgpType, armorHeaders },
    severity: warnings.length ? 'danger' : 'info'
  })];
};

export const detectSshPublicKey: SmartDetector = ({ originalInput, trimmedInput }) => {
  const match = trimmedInput.match(/^(sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))\s+([A-Za-z0-9+/]+={0,3})(?:\s+(.+))?$/);
  if (!match) {
    return [];
  }

  const declaredType = match[1];
  const blob = decodeBase64Loose(match[3]);
  if (!blob || blob.length < 16) {
    return [];
  }

  const first = readSshString(blob, 0);
  if (!first) {
    return [];
  }
  const blobType = first.value.toString('utf8');
  if (blobType !== declaredType) {
    return [];
  }

  const warnings: string[] = [];
  let bits: number | undefined;
  let curve: string | undefined;

  if (declaredType === 'ssh-rsa') {
    const exponent = readSshString(blob, first.next);
    const modulus = exponent ? readSshString(blob, exponent.next) : undefined;
    if (modulus) {
      bits = Math.max(0, modulus.value.length * 8 - Math.clz32(modulus.value[0]) + 24);
      if (bits < 2048) {
        warnings.push('RSA key appears smaller than 2048 bits.');
      }
    }
  } else if (declaredType.startsWith('ecdsa-sha2-')) {
    const curvePart = readSshString(blob, first.next);
    curve = curvePart?.value.toString('utf8');
  }

  const metadata = {
    keyType: declaredType,
    comment: match[4] ?? '',
    fingerprintSHA256: `SHA256:${sha256Fingerprint(blob)}`,
    decodedBytes: blob.length,
    bits,
    curve
  };

  return [candidate({
    kind: 'sshPublicKey',
    label: 'SSH Public Key Inspect',
    confidence: 98,
    input: originalInput,
    output: JSON.stringify({ type: 'ssh-public-key', ...metadata, warnings }, null, 2),
    preview: `${declaredType} ${metadata.fingerprintSHA256}`,
    warnings,
    language: 'json',
    metadata,
    severity: warnings.length ? 'warning' : 'info'
  })];
};

export const detectJwe: SmartDetector = ({ originalInput, trimmedInput }) => {
  const token = stripBearer(trimmedInput);
  const parts = token.split('.');
  if (parts.length !== 5) {
    return [];
  }

  const header = parseJwtPart(parts[0]);
  if (!header) {
    return [candidate({
      kind: 'jwe',
      label: 'Malformed JWE-like token',
      confidence: 48,
      input: originalInput,
      output: JSON.stringify({ token, error: 'Five compact JOSE segments found, but protected header is not valid Base64URL JSON.' }, null, 2),
      preview: 'Five JOSE-like segments found, header decode failed.',
      warnings: ['Malformed JWE-like structure.'],
      language: 'json',
      severity: 'warning'
    })];
  }

  let confidence = 72;
  if (typeof header.alg === 'string') confidence += 10;
  if (typeof header.enc === 'string') confidence += 15;
  if (typeof header.zip === 'string') confidence += 3;

  const warnings = ['JWE compact token is encrypted; payload cannot be decoded without the appropriate key.'];
  const output = {
    type: 'jwe-compact',
    header,
    segments: {
      protectedHeader: parts[0],
      encryptedKeyLength: parts[1].length,
      ivLength: parts[2].length,
      ciphertextLength: parts[3].length,
      tagLength: parts[4].length
    },
    warnings
  };

  return [candidate({
    kind: 'jwe',
    label: 'JWE Compact Inspect',
    confidence,
    input: originalInput,
    output: JSON.stringify(output, null, 2),
    preview: `alg=${String(header.alg ?? 'unknown')} enc=${String(header.enc ?? 'unknown')}`,
    warnings,
    language: 'json',
    metadata: { alg: header.alg, enc: header.enc },
    severity: 'warning'
  })];
};

export const detectJoseHeader: SmartDetector = ({ originalInput, compactInput }) => {
  if (compactInput.includes('.') || compactInput.length < 12 || !/^[A-Za-z0-9_-]+={0,2}$/.test(compactInput)) {
    return [];
  }

  const header = parseJwtPart(compactInput);
  if (!header || typeof header.alg !== 'string') {
    return [];
  }

  let confidence = 62;
  if (typeof header.typ === 'string') confidence += 10;
  if (typeof header.kid === 'string') confidence += 8;
  if (/^(HS|RS|ES|PS|EdDSA|none)/.test(header.alg)) confidence += 10;
  const warnings: string[] = [];
  if (header.alg === 'none') warnings.push('JOSE header uses alg=none.');

  return [candidate({
    kind: 'joseHeader',
    label: 'JOSE Header Decode',
    confidence,
    input: originalInput,
    output: JSON.stringify({ type: 'jose-header', header, warnings }, null, 2),
    preview: `alg=${header.alg}${header.kid ? ` kid=${String(header.kid)}` : ''}`,
    warnings,
    language: 'json',
    metadata: { alg: header.alg, kid: header.kid, typ: header.typ },
    severity: warnings.length ? 'warning' : 'info'
  })];
};

export const detectPaseto: SmartDetector = ({ originalInput, trimmedInput }) => {
  const match = trimmedInput.match(/^v([1-4])\.(local|public)\.([A-Za-z0-9_-]+)(?:\.([A-Za-z0-9_-]+))?$/);
  if (!match) {
    return [];
  }

  const version = `v${match[1]}`;
  const purpose = match[2];
  const warnings = purpose === 'local'
    ? ['PASETO local tokens are encrypted and cannot be decoded without the symmetric key.']
    : ['PASETO public tokens are signed; verification requires the public key.'];

  return [candidate({
    kind: 'paseto',
    label: 'PASETO Token Inspect',
    confidence: 94,
    input: originalInput,
    output: JSON.stringify({ type: 'paseto', version, purpose, payloadLength: match[3].length, footerPresent: Boolean(match[4]), footerLength: match[4]?.length ?? 0, warnings }, null, 2),
    preview: `${version}.${purpose}`,
    warnings,
    language: 'json',
    metadata: { version, purpose, footerPresent: Boolean(match[4]) },
    severity: 'warning'
  })];
};

export const detectFernet: SmartDetector = ({ originalInput, compactInput }) => {
  if (!/^g[A-Za-z0-9_-]{20,}={0,2}$/.test(compactInput)) {
    return [];
  }

  const decoded = base64UrlToBufferStrict(compactInput);
  if (!decoded || decoded.length < 57 || decoded[0] !== 0x80) {
    return [];
  }

  const timestampSeconds = Number(decoded.readBigUInt64BE(1));
  const timestamp = new Date(timestampSeconds * 1000);
  if (Number.isNaN(timestamp.getTime()) || timestamp.getUTCFullYear() < 2000 || timestamp.getUTCFullYear() > 2100) {
    return [];
  }

  const warnings = ['Fernet token payload is encrypted and authenticated; decryption requires the Fernet key.'];
  return [candidate({
    kind: 'fernet',
    label: 'Fernet Token Inspect',
    confidence: compactInput.startsWith('gAAAAA') ? 96 : 88,
    input: originalInput,
    output: JSON.stringify({ type: 'fernet-token', version: `0x${decoded[0].toString(16)}`, timestampSeconds, timestampIso: timestamp.toISOString(), tokenBytes: decoded.length, hmacBytes: 32, warnings }, null, 2),
    preview: `Fernet timestamp ${timestamp.toISOString()}`,
    warnings,
    language: 'json',
    metadata: { timestampSeconds, timestampIso: timestamp.toISOString(), tokenBytes: decoded.length },
    severity: 'warning'
  })];
};

export const detectOtpAuth: SmartDetector = ({ originalInput, trimmedInput }) => {
  if (!/^otpauth:\/\//i.test(trimmedInput)) {
    return [];
  }

  try {
    const url = new URL(trimmedInput);
    const otpType = url.hostname.toLowerCase();
    if (otpType !== 'totp' && otpType !== 'hotp') {
      return [];
    }
    const params = Object.fromEntries(url.searchParams.entries());
    const warnings: string[] = [];
    if (params.secret) warnings.push('OTP shared secret is present in selected text. Treat it as sensitive.');
    if (params.algorithm && !/^(SHA1|SHA256|SHA512)$/i.test(params.algorithm)) warnings.push('Unusual OTP hash algorithm.');
    const label = decodeURIComponent(url.pathname.replace(/^\//, ''));

    return [candidate({
      kind: 'otpauth',
      label: 'OTPAuth URI Inspect',
      confidence: params.secret ? 98 : 88,
      input: originalInput,
      output: JSON.stringify({ type: otpType, label, issuer: params.issuer ?? null, account: label.includes(':') ? label.split(':').slice(1).join(':') : label, algorithm: params.algorithm ?? 'SHA1', digits: params.digits ?? '6', period: params.period ?? (otpType === 'totp' ? '30' : undefined), counter: params.counter, secretPresent: Boolean(params.secret), warnings }, null, 2),
      preview: `${otpType.toUpperCase()} ${params.issuer ? `${params.issuer}: ` : ''}${label}`,
      warnings,
      language: 'json',
      metadata: { otpType, issuer: params.issuer, secretPresent: Boolean(params.secret) },
      severity: warnings.length ? 'danger' : 'info'
    })];
  } catch {
    return [];
  }
};

export const detectPasswordHash: SmartDetector = ({ originalInput, trimmedInput }) => {
  const bcrypt = trimmedInput.match(/^\$(2[aby])\$(\d{2})\$([./A-Za-z0-9]{53})$/);
  if (bcrypt) {
    const cost = Number(bcrypt[2]);
    const warnings: string[] = [];
    if (cost < 10) warnings.push('bcrypt cost appears low.');
    return [candidate({
      kind: 'passwordHash',
      label: 'bcrypt Password Hash Inspect',
      confidence: 98,
      input: originalInput,
      output: JSON.stringify({ type: 'bcrypt', variant: bcrypt[1], cost, saltAndHashLength: bcrypt[3].length, warnings }, null, 2),
      preview: `bcrypt ${bcrypt[1]} cost=${cost}`,
      warnings,
      language: 'json',
      metadata: { type: 'bcrypt', variant: bcrypt[1], cost },
      severity: warnings.length ? 'warning' : 'info'
    })];
  }

  const argon2 = trimmedInput.match(/^\$(argon2(?:id|i|d))\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/);
  if (argon2) {
    return [candidate({
      kind: 'passwordHash',
      label: 'Argon2 Password Hash Inspect',
      confidence: 99,
      input: originalInput,
      output: JSON.stringify({ type: argon2[1], version: Number(argon2[2]), memoryKiB: Number(argon2[3]), iterations: Number(argon2[4]), parallelism: Number(argon2[5]), saltLength: argon2[6].length, hashLength: argon2[7].length }, null, 2),
      preview: `${argon2[1]} m=${argon2[3]} t=${argon2[4]} p=${argon2[5]}`,
      warnings: [],
      language: 'json',
      metadata: { type: argon2[1], memoryKiB: Number(argon2[3]), iterations: Number(argon2[4]), parallelism: Number(argon2[5]) }
    })];
  }

  const djangoPbkdf2 = trimmedInput.match(/^pbkdf2_sha(1|256|512)\$(\d+)\$([^$]+)\$([^$]+)$/i);
  if (djangoPbkdf2) {
    return [candidate({
      kind: 'passwordHash',
      label: 'PBKDF2 Password Hash Inspect',
      confidence: 95,
      input: originalInput,
      output: JSON.stringify({ type: `pbkdf2-sha${djangoPbkdf2[1]}`, iterations: Number(djangoPbkdf2[2]), saltLength: djangoPbkdf2[3].length, hashLength: djangoPbkdf2[4].length }, null, 2),
      preview: `PBKDF2-SHA${djangoPbkdf2[1]} iterations=${djangoPbkdf2[2]}`,
      warnings: [],
      language: 'json',
      metadata: { type: `pbkdf2-sha${djangoPbkdf2[1]}`, iterations: Number(djangoPbkdf2[2]) }
    })];
  }

  const scrypt = trimmedInput.match(/^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/i) ?? trimmedInput.match(/^scrypt[:$]/i);
  if (scrypt) {
    return [candidate({
      kind: 'passwordHash',
      label: 'scrypt Password Hash Inspect',
      confidence: 88,
      input: originalInput,
      output: JSON.stringify({ type: 'scrypt', raw: trimmedInput }, null, 2),
      preview: 'scrypt password hash',
      warnings: [],
      language: 'json',
      metadata: { type: 'scrypt' }
    })];
  }

  return [];
};

export const detectChecksumOrHash: SmartDetector = ({ originalInput, trimmedInput }) => {
  const checksum = trimmedInput.match(/^(?:([A-Z0-9-]+)\(([^)]+)\)\s*=\s*)?([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})(?:\s+\*?(.+))?$/);
  if (!checksum) {
    return [];
  }

  const hash = checksum[3].toLowerCase();
  const lengths: Record<number, string[]> = {
    32: ['MD5', 'NTLM', '128-bit hex token'],
    40: ['SHA1'],
    56: ['SHA224'],
    64: ['SHA256', 'BLAKE2s-256', '256-bit hex token'],
    96: ['SHA384'],
    128: ['SHA512', 'BLAKE2b-512']
  };
  const possibleTypes = lengths[hash.length] ?? ['hex-hash'];
  const isChecksumLine = Boolean(checksum[1] || checksum[2] || checksum[4]);
  const warnings: string[] = [];
  if (possibleTypes.includes('MD5') || possibleTypes.includes('SHA1') || possibleTypes.includes('NTLM')) {
    warnings.push('Hash type is ambiguous and may represent a weak or legacy digest.');
  }

  return [candidate({
    kind: isChecksumLine ? 'checksum' : 'hashLike',
    label: isChecksumLine ? 'Checksum Line Inspect' : 'Hash-like Value Inspect',
    confidence: isChecksumLine ? 88 : (hash.length === 32 ? 64 : 76),
    input: originalInput,
    output: JSON.stringify({ type: isChecksumLine ? 'checksum-line' : 'hash-like', algorithmLabel: checksum[1] ?? null, filename: checksum[2] ?? checksum[4] ?? null, hash, length: hash.length, possibleTypes, warnings }, null, 2),
    preview: `${possibleTypes.join(' / ')}${checksum[2] || checksum[4] ? ` for ${checksum[2] ?? checksum[4]}` : ''}`,
    warnings,
    language: 'json',
    metadata: { possibleTypes, length: hash.length, filename: checksum[2] ?? checksum[4] ?? undefined },
    severity: warnings.length ? 'warning' : 'info'
  })];
};

export const detectEncryptedContainer: SmartDetector = ({ originalInput, trimmedInput, compactInput }) => {
  if (/^\$ANSIBLE_VAULT;\d+\.\d+;[A-Z0-9_]+/i.test(trimmedInput)) {
    const [header] = trimmedInput.split(/\r?\n/g);
    const parts = header.split(';');
    return [candidate({
      kind: 'ansibleVault',
      label: 'Ansible Vault Inspect',
      confidence: 99,
      input: originalInput,
      output: JSON.stringify({ type: 'ansible-vault', version: parts[1] ?? null, cipher: parts[2] ?? null, encrypted: true }, null, 2),
      preview: header,
      warnings: ['Ansible Vault content is encrypted; decryption requires the vault password.'],
      language: 'json',
      metadata: { version: parts[1], cipher: parts[2] },
      severity: 'warning'
    })];
  }

  if (/^age-encryption\.org\/v1\b/i.test(trimmedInput)) {
    const recipients = (trimmedInput.match(/^->\s+/gm) ?? []).length;
    return [candidate({
      kind: 'ageEncrypted',
      label: 'age Encrypted File Inspect',
      confidence: 99,
      input: originalInput,
      output: JSON.stringify({ type: 'age-encrypted-file', recipients, encrypted: true }, null, 2),
      preview: `age encrypted file, recipients=${recipients}`,
      warnings: ['age encrypted content requires the private key/passphrase to decrypt.'],
      language: 'json',
      metadata: { recipients },
      severity: 'warning'
    })];
  }

  let raw: Buffer | undefined;
  let inputEncoding = 'raw';
  if (trimmedInput.startsWith('Salted__')) {
    raw = Buffer.from(trimmedInput, 'binary');
  } else if (/^[A-Za-z0-9+/]+={0,2}$/.test(compactInput)) {
    raw = decodeBase64Loose(compactInput);
    inputEncoding = 'base64';
  }

  if (raw && raw.length >= 16 && raw.subarray(0, 8).toString('ascii') === 'Salted__') {
    const salt = raw.subarray(8, 16).toString('hex');
    return [candidate({
      kind: 'opensslSalted',
      label: 'OpenSSL Salted Encrypted Data Inspect',
      confidence: 96,
      input: originalInput,
      output: JSON.stringify({ type: 'openssl-salted', inputEncoding, salt, encryptedBytes: raw.length - 16, encrypted: true }, null, 2),
      preview: `OpenSSL Salted__ salt=${salt}`,
      warnings: ['OpenSSL salted content is encrypted; decryption requires password/key and cipher parameters.'],
      language: 'json',
      metadata: { inputEncoding, salt, encryptedBytes: raw.length - 16 },
      severity: 'warning'
    })];
  }

  return [];
};

export const detectSecret: SmartDetector = ({ originalInput, trimmedInput }) => {
  const secretPatterns: Array<{ provider: string; type: string; regex: RegExp; danger?: boolean }> = [
    { provider: 'GitHub', type: 'classic token', regex: /^gh[pousr]_[A-Za-z0-9_]{30,}$/ },
    { provider: 'GitHub', type: 'fine-grained token', regex: /^github_pat_[A-Za-z0-9_]{40,}$/ },
    { provider: 'AWS', type: 'access key id', regex: /^(AKIA|ASIA)[A-Z0-9]{16}$/ },
    { provider: 'Google', type: 'API key', regex: /^AIza[0-9A-Za-z_-]{35}$/ },
    { provider: 'Slack', type: 'token', regex: /^xox[baprs]-[A-Za-z0-9-]{20,}$/ },
    { provider: 'OpenAI-like', type: 'secret key', regex: /^sk-[A-Za-z0-9_-]{20,}$/ },
    { provider: 'Stripe', type: 'secret key', regex: /^sk_(live|test)_[A-Za-z0-9]{20,}$/ },
    { provider: 'npm', type: 'access token', regex: /^npm_[A-Za-z0-9]{30,}$/ }
  ];

  for (const pattern of secretPatterns) {
    const match = trimmedInput.match(pattern.regex);
    if (!match) continue;
    const warnings = ['Possible secret/API key selected. Do not commitr, paste, or share this value.'];
    const metadata = { provider: pattern.provider, secretType: pattern.type, prefix: trimmedInput.slice(0, Math.min(12, trimmedInput.length)), length: trimmedInput.length };
    return [candidate({
      kind: 'secret',
      label: 'Secret/API Key Pattern Inspect',
      confidence: 90,
      input: originalInput,
      output: JSON.stringify({ type: 'secret-pattern', ...metadata, warnings }, null, 2),
      preview: `${pattern.provider} ${pattern.type}`,
      warnings,
      language: 'json',
      metadata,
      severity: 'danger'
    })];
  }

  return [];
};

export const detectAsn1Der: SmartDetector = ({ originalInput, compactInput }) => {
  let decoded: Buffer | undefined;
  let inputEncoding: 'base64' | 'hex' | undefined;

  if (/^[A-Za-z0-9+/]+={0,2}$/.test(compactInput) && compactInput.length >= 24) {
    decoded = decodeBase64Loose(compactInput);
    inputEncoding = 'base64';
  } else if (/^[0-9a-fA-F]+$/.test(compactInput) && compactInput.length >= 24 && compactInput.length % 2 === 0) {
    decoded = Buffer.from(compactInput, 'hex');
    inputEncoding = 'hex';
  }

  if (!decoded || decoded.length < 8 || decoded[0] !== 0x30) {
    return [];
  }

  const lengthByte = decoded[1];
  const derLike = lengthByte < 0x80 || lengthByte === 0x81 || lengthByte === 0x82 || lengthByte === 0x83 || lengthByte === 0x84;
  if (!derLike) {
    return [];
  }

  const warnings = ['ASN.1/DER structure detected. It may be a certificate, key, CSR, PKCS object, or other binary container.'];
  return [candidate({
    kind: 'asn1Der',
    label: 'ASN.1 / DER-like Structure Inspect',
    confidence: inputEncoding === 'base64' && compactInput.startsWith('MI') ? 72 : 58,
    input: originalInput,
    output: JSON.stringify({ type: 'asn1-der-like', inputEncoding, bytes: decoded.length, sha256: createHash('sha256').update(decoded).digest('hex'), firstBytesHex: decoded.subarray(0, 16).toString('hex'), warnings }, null, 2),
    preview: `DER-like ${decoded.length} bytes`,
    warnings,
    language: 'json',
    metadata: { inputEncoding, bytes: decoded.length },
    severity: 'info'
  })];
};

export const detectSaml: SmartDetector = ({ originalInput, trimmedInput }) => {
  if (!/<(?:\w+:)?(?:Response|Assertion)\b/i.test(trimmedInput) || !/saml/i.test(trimmedInput)) {
    return [];
  }

  const issuer = trimmedInput.match(/<[^>]*Issuer[^>]*>([^<]+)<\/[^>]*Issuer>/i)?.[1]?.trim();
  const audience = trimmedInput.match(/<[^>]*Audience[^>]*>([^<]+)<\/[^>]*Audience>/i)?.[1]?.trim();
  const nameId = trimmedInput.match(/<[^>]*NameID[^>]*>([^<]+)<\/[^>]*NameID>/i)?.[1]?.trim();
  const notBefore = trimmedInput.match(/\bNotBefore=["']([^"']+)["']/i)?.[1];
  const notOnOrAfter = trimmedInput.match(/\bNotOnOrAfter=["']([^"']+)["']/i)?.[1];
  const signaturePresent = /<[^>]*Signature\b/i.test(trimmedInput);
  const x509Present = /<[^>]*X509Certificate\b/i.test(trimmedInput);
  const warnings: string[] = [];
  if (!signaturePresent) warnings.push('SAML content does not appear to contain an XML Signature element.');
  const now = Date.now();
  if (notBefore && Date.parse(notBefore) > now) warnings.push('SAML assertion/condition is not valid yet.');
  if (notOnOrAfter && Date.parse(notOnOrAfter) <= now) warnings.push('SAML assertion/condition appears expired.');

  const metadata = { issuer, audience, nameId, notBefore, notOnOrAfter, signaturePresent, x509Present };
  return [candidate({
    kind: 'saml',
    label: 'SAML XML Inspect',
    confidence: signaturePresent ? 92 : 82,
    input: originalInput,
    output: JSON.stringify({ type: 'saml', ...metadata, warnings }, null, 2),
    preview: `issuer=${issuer ?? 'unknown'} audience=${audience ?? 'unknown'}`,
    warnings,
    language: 'json',
    metadata,
    severity: warnings.length ? 'warning' : 'info'
  })];
};

export const detectWebFrameworkToken: SmartDetector = ({ originalInput, trimmedInput }) => {
  const parsed = safeJsonParse(trimmedInput);
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const object = parsed as Record<string, unknown>;
    const hasLaravelShape = typeof object.iv === 'string' && typeof object.value === 'string' && typeof object.mac === 'string';
    if (hasLaravelShape) {
      const warnings = ['Possible Laravel encrypted cookie/payload. Decryption requires APP_KEY.'];
      return [candidate({
        kind: 'webFrameworkToken',
        label: 'Laravel Encrypted Payload Inspect',
        confidence: 94,
        input: originalInput,
        output: JSON.stringify({ type: 'laravel-encrypted-payload', fields: Object.keys(object), ivLength: String(object.iv).length, valueLength: String(object.value).length, macLength: String(object.mac).length, tagPresent: typeof object.tag === 'string', warnings }, null, 2),
        preview: 'Laravel encrypted payload shape: iv, value, mac',
        warnings,
        language: 'json',
        metadata: { framework: 'Laravel', tagPresent: typeof object.tag === 'string' },
        severity: 'warning'
      })];
    }
  }

  const rails = trimmedInput.match(/^([A-Za-z0-9+/=_-]{20,})--([A-Za-z0-9+/=_-]{20,})(?:--([A-Za-z0-9+/=_-]{16,}))?$/);
  if (rails) {
    const warnings = ['Possible Rails signed/encrypted cookie. Verification/decryption requires application secrets.'];
    return [candidate({
      kind: 'webFrameworkToken',
      label: 'Rails Signed/Encrypted Cookie Inspect',
      confidence: rails[3] ? 82 : 74,
      input: originalInput,
      output: JSON.stringify({ type: 'rails-cookie-like', parts: rails.slice(1).filter(Boolean).map((part) => ({ length: part.length })), encryptedOrSigned: true, warnings }, null, 2),
      preview: `Rails-like token with ${rails[3] ? 3 : 2} parts`,
      warnings,
      language: 'json',
      metadata: { framework: 'Rails', partCount: rails[3] ? 3 : 2 },
      severity: 'warning'
    })];
  }

  return [];
};

export const detectors: SmartDetector[] = [
  detectPem,
  detectOpenPgp,
  detectSshPublicKey,
  detectJwe,
  detectJwt,
  detectJoseHeader,
  detectPaseto,
  detectFernet,
  detectOtpAuth,
  detectPasswordHash,
  detectBasicAuth,
  detectChecksumOrHash,
  detectEncryptedContainer,
  detectSecret,
  detectSaml,
  detectWebFrameworkToken,
  detectJson,
  detectQueryString,
  detectCookie,
  detectUrlEncoded,
  detectHtmlEntities,
  detectUnixTimestamp,
  detectPowerShellEncodedCommand,
  detectAsn1Der,
  detectBase64Url,
  detectBase64,
  detectHex,
  detectUuid
];
