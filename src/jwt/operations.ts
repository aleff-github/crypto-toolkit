import { Operation } from '../commands/types';
import { fromBase64Url } from '../crypto/buffer';
import { UserFacingError } from '../utils/errors';

type JwtJson = Record<string, unknown>;

interface DecodedJwt {
  header: JwtJson;
  payload: JwtJson;
  signature: string;
  warnings: string[];
}

function parseJsonPart(part: string, label: string): JwtJson {
  try {
    const text = fromBase64Url(part).toString('utf8');
    const parsed = JSON.parse(text) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`${label} is not a JSON object.`);
    }
    return parsed as JwtJson;
  } catch (error) {
    if (error instanceof UserFacingError) {
      throw new UserFacingError(`JWT ${label} decode failed.`, {
        reason: error.message,
        expected: 'A Base64URL encoded JSON object.',
        hint: 'Select only a compact JWT or an Authorization: Bearer header.'
      });
    }
    throw new UserFacingError(`JWT ${label} decode failed.`, {
      reason: 'The decoded value is not a JSON object.',
      expected: 'A Base64URL encoded JSON object.',
      hint: 'If the value has 5 segments, it is probably a JWE encrypted token rather than a decodable JWT/JWS.'
    });
  }
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function analyzeJwt(header: JwtJson, payload: JwtJson): string[] {
  const warnings: string[] = [];
  const now = Math.floor(Date.now() / 1000);
  const alg = typeof header.alg === 'string' ? header.alg : undefined;

  if (!alg) {
    warnings.push('JWT header does not contain alg.');
  } else if (alg.toLowerCase() === 'none') {
    warnings.push('JWT uses alg=none. Do not trust this token unless unsigned tokens are explicitly expected.');
  }

  const exp = asNumber(payload.exp);
  const nbf = asNumber(payload.nbf);

  if (exp !== undefined && exp < now) {
    warnings.push(`Token expired at ${new Date(exp * 1000).toISOString()}.`);
  }

  if (nbf !== undefined && nbf > now) {
    warnings.push(`Token is not valid before ${new Date(nbf * 1000).toISOString()}.`);
  }

  if (exp === undefined) {
    warnings.push('JWT payload does not contain exp. Expiration is recommended for most tokens.');
  }

  return warnings;
}

function decodeJwt(input: string): DecodedJwt {
  const token = input.trim().replace(/^Authorization:\s*Bearer\s+/i, '').replace(/^Bearer\s+/i, '');
  const parts = token.split('.');

  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new UserFacingError('Malformed JWT. JWT Decode failed.', {
      reason: `Expected 3 non-empty dot-separated segments, found ${parts.length}.`,
      expected: 'header.payload.signature',
      hint: 'Select only the compact JWT token or a full Authorization: Bearer header. Five-segment tokens are usually JWE and cannot be decoded without a key.'
    });
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const header = parseJsonPart(encodedHeader, 'header');
  const payload = parseJsonPart(encodedPayload, 'payload');

  return {
    header,
    payload,
    signature,
    warnings: analyzeJwt(header, payload)
  };
}

function enrichClaims(payload: JwtJson): JwtJson {
  const out: JwtJson = { ...payload };

  for (const key of ['exp', 'iat', 'nbf']) {
    const value = asNumber(payload[key]);
    if (value !== undefined) {
      out[`${key}_iso`] = new Date(value * 1000).toISOString();
    }
  }

  return out;
}

export const jwtDecode: Operation = {
  id: 'cryptoToolkit.jwt.decode',
  title: 'Decode JWT',
  run(input) {
    const decoded = decodeJwt(input);
    return {
      title: 'Decode JWT',
      text: JSON.stringify({
        header: decoded.header,
        payload: enrichClaims(decoded.payload),
        signature: {
          present: decoded.signature.length > 0,
          length: decoded.signature.length
        },
        warnings: decoded.warnings
      }, null, 2),
      warnings: decoded.warnings,
      language: 'json'
    };
  }
};

// Backward-compatible aliases for older internal tests/imports.
export const jwtInspect = jwtDecode;
export const jwtPrettyPrint = jwtDecode;
