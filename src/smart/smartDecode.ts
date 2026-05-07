import { detectors } from './detectors';
import { dedupeBy } from './scoring';
import { candidateReasons, explainWhyNotDetected } from './explain';
import { SmartDecodeCandidate, DetectorContext, SmartDecodeOptions } from './types';

function uniq(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

function extractFencedBlocks(input: string): string[] {
  const values: string[] = [];
  const regex = /```[\w-]*\s*([\s\S]*?)```/g;
  for (const match of input.matchAll(regex)) {
    if (match[1]) {
      values.push(match[1]);
    }
  }
  return values;
}

function extractPlaygroundMarkers(input: string): string[] {
  const trimmed = input.trim();
  const values: string[] = [];

  // The manual playground uses <<<value>>> markers. If the user selects the
  // markers together with the value, unwrap them before detection.
  if (trimmed.startsWith('<<<') && trimmed.endsWith('>>>') && trimmed.length > 6) {
    values.push(trimmed.slice(3, -3));
  }

  const markerRegex = /<<<([\s\S]*?)>>>/g;
  for (const match of trimmed.matchAll(markerRegex)) {
    if (match[1]) {
      values.push(match[1]);
    }
  }

  return values;
}

function extractInterestingLines(input: string): string[] {
  return input
    .split(/\r?\n/g)
    .map((line) => line.trim())
    .filter((line) => {
      if (line.length < 8) {
        return false;
      }
      return (
        /^(Authorization\s*:\s*)?(Bearer|Basic)\s+/i.test(line) ||
        /^Set-Cookie\s*:/i.test(line) ||
        /^Cookie\s*:/i.test(line) ||
        /^https?:\/\//i.test(line) ||
        /^otpauth:\/\//i.test(line) ||
        /^v[1-4]\.(local|public)\./i.test(line) ||
        /^(AKIA|ASIA)[A-Z0-9]{16}$/.test(line) ||
        /^(gh[pousr]_|github_pat_|xox[baprs]-|AIza|sk-|sk_(live|test)_|npm_)/.test(line) ||
        line.includes('%') ||
        line.includes('&') ||
        line.split('.').length === 5 ||
        /^[A-Za-z0-9+/=_-]{8,}$/.test(line) ||
        /^[0-9a-fA-F]{8,}$/.test(line)
      );
    });
}

function extractInterestingTokens(input: string): string[] {
  const values: string[] = [];

  // JWT/JWE/Bearer-like tokens.
  const jweRegex = /(?:Authorization\s*:\s*)?Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi;
  for (const match of input.matchAll(jweRegex)) {
    values.push(match[0]);
  }

  const bareJweRegex = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
  for (const match of input.matchAll(bareJweRegex)) {
    values.push(match[0]);
  }

  const jwtRegex = /(?:Authorization\s*:\s*)?Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/gi;
  for (const match of input.matchAll(jwtRegex)) {
    values.push(match[0]);
  }

  const bareJwtRegex = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b/g;
  for (const match of input.matchAll(bareJwtRegex)) {
    values.push(match[0]);
  }

  // PASETO, OTPAuth, and common secret-token lines.
  const pasetoRegex = /\bv[1-4]\.(?:local|public)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?\b/gi;
  for (const match of input.matchAll(pasetoRegex)) {
    values.push(match[0]);
  }

  const otpAuthRegex = /otpauth:\/\/[^\s<>'"]+/gi;
  for (const match of input.matchAll(otpAuthRegex)) {
    values.push(match[0]);
  }

  const secretRegex = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{40,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{30,})\b/g;
  for (const match of input.matchAll(secretRegex)) {
    values.push(match[0]);
  }

  // Basic Auth values.
  const basicRegex = /(?:Authorization\s*:\s*)?Basic\s+[A-Za-z0-9+/]+={0,2}/gi;
  for (const match of input.matchAll(basicRegex)) {
    values.push(match[0]);
  }

  // Long encoded tokens. Keep this conservative to avoid random words.
  const tokenRegex = /\b[A-Za-z0-9+/=_-]{12,}\b/g;
  for (const match of input.matchAll(tokenRegex)) {
    values.push(match[0]);
  }

  return values;
}

export function collectSmartInputVariants(input: string): string[] {
  const trimmed = input.trim();
  if (!trimmed) {
    return [];
  }

  const markerValues = extractPlaygroundMarkers(trimmed);
  const fencedValues = extractFencedBlocks(trimmed);
  const lineValues = extractInterestingLines(trimmed);
  const tokenValues = extractInterestingTokens(trimmed);

  // If explicit playground/code-block markers are present, prefer the extracted
  // payloads over the surrounding instructional text. This prevents outputs such
  // as <<<decoded value>>> when the user accidentally selects the markers too.
  if (markerValues.length > 0 || fencedValues.length > 0) {
    return uniq([
      ...markerValues,
      ...fencedValues,
      ...tokenValues
    ]);
  }

  return uniq([
    trimmed,
    ...lineValues,
    ...tokenValues
  ]);
}

function buildContext(input: string): DetectorContext {
  return {
    originalInput: input,
    trimmedInput: input.trim(),
    compactInput: input.trim().replace(/\s+/g, '')
  };
}

function stableCandidateKey(candidate: SmartDecodeCandidate): string {
  return `${candidate.kind}:${candidate.output}`;
}

function sortCandidates(a: SmartDecodeCandidate, b: SmartDecodeCandidate): number {
  if (b.confidence !== a.confidence) {
    return b.confidence - a.confidence;
  }
  return a.label.localeCompare(b.label);
}

function runDetectors(input: string): SmartDecodeCandidate[] {
  const context = buildContext(input);

  return detectors.flatMap((detector) => {
    try {
      return detector(context);
    } catch {
      // A detector should never break the whole Smart Decode run.
      return [];
    }
  });
}

export function smartDecode(input: string, options: SmartDecodeOptions): SmartDecodeCandidate[] {
  const variants = collectSmartInputVariants(input);

  if (variants.length === 0) {
    return [];
  }

  const candidates = variants.flatMap(runDetectors);
  const filtered = candidates.filter((candidate) =>
    options.showLowConfidence || candidate.confidence >= options.minimumConfidence
  );

  return dedupeBy(filtered, stableCandidateKey)
    .sort(sortCandidates)
    .slice(0, Math.max(1, options.maxCandidates));
}

export function smartDecodeReport(input: string, options: SmartDecodeOptions): string {
  const variants = collectSmartInputVariants(input);
  const candidates = smartDecode(input, { ...options, showLowConfidence: true });

  return JSON.stringify({
    inputLength: input.length,
    analyzedVariants: variants.map((variant) => ({
      length: variant.length,
      preview: variant.replace(/\s+/g, ' ').trim().slice(0, 180)
    })),
    options,
    candidateCount: candidates.length,
    candidates: candidates.map((candidate) => ({
      kind: candidate.kind,
      label: candidate.label,
      confidence: candidate.confidence,
      preview: candidate.preview,
      warnings: candidate.warnings,
      metadata: candidate.metadata ?? {},
      reasons: candidateReasons(candidate)
    })),
    whyNotDetected: candidates.length === 0 ? JSON.parse(explainWhyNotDetected(input)) : undefined
  }, null, 2);
}

export { explainWhyNotDetected };

