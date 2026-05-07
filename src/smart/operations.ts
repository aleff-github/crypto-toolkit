import { Operation, OperationResult } from '../commands/types';
import { collectSmartInputVariants, smartDecode, smartDecodeReport } from './smartDecode';
import { candidateReasons, explainDetectorChecks, DetectorCheck } from './explain';
import { SmartDecodeCandidate } from './types';

function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(value: unknown): string {
  return escapeHtml(value).replace(/`/g, '&#96;');
}

function confidenceLabel(confidence: number): string {
  if (confidence >= 85) return 'High confidence';
  if (confidence >= 65) return 'Medium confidence';
  return 'Low confidence';
}

function severityClass(candidate?: SmartDecodeCandidate): string {
  if (!candidate) return 'warn';
  if (candidate.severity === 'danger') return 'danger';
  if (candidate.severity === 'warning' || candidate.warnings.length > 0) return 'warn';
  return 'ok';
}

function candidatePlainSummary(candidate: SmartDecodeCandidate): string {
  const bits = [
    `Detected: ${candidate.label}`,
    `Confidence: ${candidate.confidence}%`,
    candidate.preview ? `Preview: ${candidate.preview}` : undefined,
    candidate.warnings.length ? `Warnings: ${candidate.warnings.join('; ')}` : undefined
  ].filter(Boolean);
  return bits.join('\n');
}

function outputPreview(candidate: SmartDecodeCandidate, max = 1200): string {
  const text = candidate.output.trim();
  const source = text || candidate.preview || '';
  return source.length > max ? `${source.slice(0, max)}\n\n[preview truncated]` : source;
}

function recommendedAction(candidate: SmartDecodeCandidate): string {
  if (/^possible /i.test(candidate.label)) return 'Review this signal before acting';
  if (/hash|bcrypt|argon2|secret|key|certificate|ssh|pgp|ansible|age/i.test(candidate.label)) {
    return 'Inspect only';
  }
  return candidate.label;
}

function renderWarnings(warnings: string[]): string {
  if (!warnings.length) return '';
  return `<div class="card warn"><strong>Warnings</strong><ul>${warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join('')}</ul></div>`;
}

function renderMetadata(metadata: Record<string, unknown> | undefined): string {
  if (!metadata || Object.keys(metadata).length === 0) {
    return '<p class="muted">No metadata available.</p>';
  }

  const rows = Object.entries(metadata)
    .map(([key, value]) => `<tr><th>${escapeHtml(key)}</th><td><code>${escapeHtml(typeof value === 'object' ? JSON.stringify(value) : String(value))}</code></td></tr>`)
    .join('');
  return `<table>${rows}</table>`;
}

function renderReasons(candidate: SmartDecodeCandidate): string {
  const reasons = candidateReasons(candidate);
  if (!reasons.length) {
    return '<p class="muted">No scoring reasons available.</p>';
  }
  return `<ul>${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul>`;
}

function renderCandidateCard(candidate: SmartDecodeCandidate, index: number): string {
  const title = index === 0 ? 'Best match' : `Alternative ${index + 1}`;
  return `<div class="card ${severityClass(candidate)}">
    <div class="row">
      <span class="pill">${escapeHtml(title)}</span>
      <span class="pill">${escapeHtml(candidate.label)}</span>
      <span class="pill">${candidate.confidence}%</span>
      <span class="pill">${escapeHtml(confidenceLabel(candidate.confidence))}</span>
    </div>
    <p>${escapeHtml(candidate.preview || 'No preview available.')}</p>
  </div>`;
}

function renderDetectedHtml(input: string, candidates: SmartDecodeCandidate[], threshold: number): string {
  const best = candidates[0];
  const alternatives = candidates.slice(1);
  const variants = collectSmartInputVariants(input);
  const compactResult = outputPreview(best, 1000);

  return `<section class="card summary-card ${severityClass(best)}">
    <div class="row">
      <span class="pill">Smart Detect</span>
      <span class="pill">Detected</span>
      <span class="pill">${escapeHtml(confidenceLabel(best.confidence))}</span>
      <span class="pill">${best.confidence}%</span>
    </div>
    <h2>Looks like: ${escapeHtml(best.label)}</h2>
    <p><strong>Recommended action:</strong> ${escapeHtml(recommendedAction(best))}</p>
    ${best.preview ? `<p class="muted">${escapeHtml(best.preview)}</p>` : ''}
  </section>

  ${renderWarnings(best.warnings)}

  ${compactResult ? `<section class="card"><h2>Result preview</h2><pre>${escapeHtml(compactResult)}</pre><p class="muted small">Detect does not modify the editor. Use the specific operation from the Crypto menu when you want to replace, insert, or copy the result.</p></section>` : `<p class="muted">No direct decoded output is available for this detection.</p>`}

  <details>
    <summary>View more</summary>
    <div>
      <h3>Full result</h3>
      <pre>${escapeHtml(outputPreview(best, 6000) || '[no output]')}</pre>

      <h3>Why this was detected</h3>
      ${renderReasons(best)}

      <h3>Metadata</h3>
      ${renderMetadata(best.metadata)}

      <h3>Other possible matches</h3>
      ${alternatives.length ? alternatives.map((candidate, index) => renderCandidateCard(candidate, index + 1)).join('') : '<p class="muted">No other candidates passed the current threshold.</p>'}

      <h3>Analyzed input variants</h3>
      <ul>${variants.map((variant) => `<li><code>${escapeHtml(variant.replace(/\s+/g, ' ').slice(0, 240))}</code></li>`).join('')}</ul>

      <h3>Threshold</h3>
      <p class="muted small">Current minimum confidence: ${threshold}%. Lowering it may show more weak candidates, but can increase false positives.</p>
    </div>
  </details>`;
}

function checkCloseness(check: DetectorCheck): number {
  const joined = check.reasons.join(' ').toLowerCase();
  if (check.status === 'accepted') return 90;
  if (check.status === 'skipped') return 55;
  let score = 0;
  if (joined.includes('three dot-separated') || joined.includes('five dot-separated')) score += 35;
  if (joined.includes('charset and round-trip checks passed')) score += 35;
  if (joined.includes('decoded printable score')) score += 20;
  if (joined.includes('even number of hex')) score += 20;
  if (joined.includes('too short') || joined.includes('ambiguous')) score += 10;
  if (joined.includes('basic prefix found')) score += 25;
  if (joined.includes('begin armor marker found')) score += 30;
  if (joined.includes('key=value')) score += 20;
  if (joined.includes('prefix')) score += 15;
  return score;
}

function renderChecks(checks: DetectorCheck[], limitr?: number): string {
  const items = (limitr ? checks.slice(0, limitr) : checks)
    .map((check) => `<div class="card">
      <div class="row"><span class="pill">${escapeHtml(check.detector)}</span><span class="pill">${escapeHtml(check.status)}</span></div>
      <ul>${check.reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join('')}</ul>
    </div>`)
    .join('');
  return items || '<p class="muted">No detector checks available.</p>';
}

function renderNotDetectedHtml(input: string, lowConfidence: SmartDecodeCandidate[], threshold: number): string {
  const checks = explainDetectorChecks(input);
  const rankedChecks = [...checks].sort((a, b) => checkCloseness(b) - checkCloseness(a));
  const closeChecks = rankedChecks.filter((check) => checkCloseness(check) > 0).slice(0, 4);
  const bestLow = lowConfidence[0];
  const closestName = bestLow?.label ?? closeChecks[0]?.detector ?? 'No close match';
  const closestReason = bestLow
    ? `A weak ${bestLow.label} candidate was found at ${bestLow.confidence}%, below the configured ${threshold}% threshold.`
    : closeChecks[0]
      ? closeChecks[0].reasons[0]
      : 'The selection looks like plain text, unsupported data, or too little data to classify safely.';

  const lowCandidateHtml = lowConfidence.length
    ? lowConfidence.map((candidate, index) => renderCandidateCard(candidate, index)).join('')
    : '<p class="muted">No decoder produced even a weak candidate.</p>';

  return `<section class="card summary-card warn">
    <div class="row">
      <span class="pill">Not detected</span>
      <span class="pill">Closest: ${escapeHtml(closestName)}</span>
    </div>
    <h2>No strong match found</h2>
    <p><strong>Closest signal:</strong> ${escapeHtml(closestName)}</p>
    <p>${escapeHtml(closestReason)}</p>
    <p class="muted small">Detect stayed conservative and did not apply any transformation.</p>
  </section>

  <h2>Closest signal</h2>
  ${bestLow ? renderCandidateCard(bestLow, 0) : renderChecks(closeChecks, 1)}

  <details>
    <summary>View more</summary>
    <div>
      <h3>Weak candidates below threshold</h3>
      ${lowCandidateHtml}

      <h3>Detector checks</h3>
      ${renderChecks(rankedChecks)}

      <h3>Raw selection preview</h3>
      <pre>${escapeHtml(input.trim().slice(0, 4000) || '[empty selection]')}</pre>
    </div>
  </details>`;
}

export const smartDetectAndDecode: Operation = {
  id: 'cryptoToolkit.smart.detectAndDecode',
  title: 'Detect',
  run(input, context): OperationResult {
    const threshold = context.settings.smartDecodeMinimumConfidence;
    const maxCandidates = context.settings.smartDecodeMaxCandidates;
    const candidates = smartDecode(input, {
      minimumConfidence: threshold,
      maxCandidates,
      showLowConfidence: false
    });

    if (candidates.length > 0) {
      const best = candidates[0];
      return {
        title: `Crypto Toolkit: Detect · ${best.label}`,
        text: candidatePlainSummary(best),
        html: renderDetectedHtml(input, candidates, threshold),
        warnings: best.warnings,
        language: best.language ?? 'plaintext',
        outputMode: 'sidePanel'
      };
    }

    const lowConfidenceCandidates = smartDecode(input, {
      minimumConfidence: 0,
      maxCandidates,
      showLowConfidence: true
    });

    return {
      title: 'Crypto Toolkit: Detect',
      text: lowConfidenceCandidates.length
        ? `No reliable candidate found. Closest: ${lowConfidenceCandidates[0].label} (${lowConfidenceCandidates[0].confidence}%).`
        : 'No reliable candidate found.',
      html: renderNotDetectedHtml(input, lowConfidenceCandidates, threshold),
      language: 'plaintext',
      outputMode: 'sidePanel'
    };
  }
};

// Kept as hidden command implementations for backwards compatibility with older
// keybindings or command IDs. They are no longer contributed to the menu/Command Palette.
export const smartWhyNotDetected: Operation = {
  id: 'cryptoToolkit.smart.whyNotDetected',
  title: 'Detect Details (Legacy)',
  run(input) {
    return {
      title: 'Crypto Toolkit: Detect',
      text: 'This command has been merged into Crypto Toolkit: Detect.',
      html: renderNotDetectedHtml(input, smartDecode(input, { minimumConfidence: 0, maxCandidates: 8, showLowConfidence: true }), 45),
      language: 'plaintext',
      outputMode: 'sidePanel'
    };
  }
};

export const smartDetectionReport: Operation = {
  id: 'cryptoToolkit.smart.detectionReport',
  title: 'Smart Decode Detection Report (Legacy)',
  run(input, context) {
    const text = smartDecodeReport(input, {
      minimumConfidence: context.settings.smartDecodeMinimumConfidence,
      maxCandidates: context.settings.smartDecodeMaxCandidates,
      showLowConfidence: true
    });

    return {
      title: 'Smart Decode Detection Report (Legacy)',
      text,
      language: 'json',
      outputMode: 'sidePanel'
    };
  }
};
