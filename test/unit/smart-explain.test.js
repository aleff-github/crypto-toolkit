'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { smartDecodeReport, explainWhyNotDetected } = require('../../dist/smart/smartDecode');

const options = { minimumConfidence: 45, maxCandidates: 8, showLowConfidence: true };

test('Smart Decode report includes explainable scoring reasons', () => {
  const report = JSON.parse(smartDecodeReport('aGVsbG8gd29ybGQ=', options));
  assert.ok(report.candidateCount >= 1);
  assert.equal(report.candidates[0].kind, 'base64');
  assert.ok(Array.isArray(report.candidates[0].reasons));
  assert.match(report.candidates[0].reasons.join('\n'), /Base64|printable|confidence/i);
});

test('Why Not Detected explains rejected detector checks', () => {
  const report = JSON.parse(explainWhyNotDetected('plain text that is not encoded'));
  assert.ok(Array.isArray(report.rejectedChecks));
  assert.ok(report.rejectedChecks.some((check) => check.detector === 'JWT'));
  assert.match(JSON.stringify(report), /Base64|JSON|Hex/);
});
