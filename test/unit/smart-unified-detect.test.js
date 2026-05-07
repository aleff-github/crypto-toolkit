'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { smartDetectAndDecode } = require('../../dist/smart/operations');

const context = {
  commandId: 'cryptoToolkit.smart.detectAndDecode',
  settings: {
    smartDecodeMinimumConfidence: 45,
    smartDecodeMaxCandidates: 8,
    smartDecodeShowLowConfidence: false,
    smartDecodeIncludeReasons: true
  }
};

test('Unified Detect opens a clean side-panel result for detected input', () => {
  const result = smartDetectAndDecode.run('aGVsbG8gd29ybGQ=', context);
  assert.equal(result.outputMode, 'sidePanel');
  assert.match(result.title, /Detect/i);
  assert.match(result.html, /Detected/);
  assert.match(result.html, /Base64 Decode/);
  assert.match(result.html, /View more/);
  assert.match(result.html, /hello world/);
  assert.doesNotMatch(result.html, /candidateCount/);
});

test('Unified Detect gives nearest-match guidance for non-detected input without JSON-first output', () => {
  const result = smartDetectAndDecode.run('plain text that is not encoded', context);
  assert.equal(result.outputMode, 'sidePanel');
  assert.match(result.html, /No strong match found/);
  assert.match(result.html, /Closest/);
  assert.match(result.html, /View more/);
  assert.doesNotMatch(result.text.trim(), /^\{/);
});
