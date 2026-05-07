export function clampConfidence(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function makePreview(value: string, maxLength = 160): string {
  const compact = value.replace(/\s+/g, ' ').trim();
  if (compact.length <= maxLength) {
    return compact;
  }
  return `${compact.slice(0, Math.max(0, maxLength - 1))}…`;
}

export function safeJsonParse(value: string): unknown | undefined {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return undefined;
  }
}

export function looksLikeJsonText(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) {
    return false;
  }
  if (!((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']')))) {
    return false;
  }
  return safeJsonParse(trimmed) !== undefined;
}

export function stringifyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function isMostlyPrintable(value: string): boolean {
  if (value.length === 0) {
    return false;
  }

  let printable = 0;
  let suspicious = 0;

  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (char === '\uFFFD') {
      suspicious += 2;
      continue;
    }

    if (char === '\n' || char === '\r' || char === '\t') {
      printable += 1;
      continue;
    }

    if ((code >= 0x20 && code <= 0x7e) || code >= 0xa0) {
      printable += 1;
    } else {
      suspicious += 1;
    }
  }

  return printable / Math.max(1, printable + suspicious) >= 0.85;
}

export function printableScore(value: string): number {
  if (!value) {
    return 0;
  }

  let printable = 0;
  let suspicious = 0;

  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (char === '\uFFFD') {
      suspicious += 2;
    } else if (char === '\n' || char === '\r' || char === '\t') {
      printable += 1;
    } else if ((code >= 0x20 && code <= 0x7e) || code >= 0xa0) {
      printable += 1;
    } else {
      suspicious += 1;
    }
  }

  return Math.round((printable / Math.max(1, printable + suspicious)) * 100);
}

export function containsPercentEncoding(value: string): boolean {
  return /%[0-9a-fA-F]{2}/.test(value);
}

export function containsHtmlEntity(value: string): boolean {
  return /&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]+);/.test(value);
}

export function countObjectKeys(value: unknown): number {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.keys(value as Record<string, unknown>).length;
  }
  return 0;
}

export function isLikelyIsoDate(value: Date): boolean {
  return !Number.isNaN(value.getTime()) && value.getUTCFullYear() >= 1990 && value.getUTCFullYear() <= 2100;
}

export function hasCommonTokenClaim(value: Record<string, unknown>): boolean {
  return ['sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti', 'scope', 'scp'].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

export function hasCommonWebParam(key: string): boolean {
  return /^(redirect_uri|redirect|return_url|callback|client_id|client_secret|state|code|token|access_token|id_token|refresh_token|scope|response_type|grant_type|next|url|uri|continue|csrf|xsrf)$/i.test(key);
}

export function dedupeBy<T>(items: T[], getKey: (item: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    const key = getKey(item);
    if (!seen.has(key)) {
      seen.add(key);
      out.push(item);
    }
  }
  return out;
}
