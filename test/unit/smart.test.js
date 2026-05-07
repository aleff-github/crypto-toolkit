'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { smartDecode } = require('../../dist/smart/smartDecode');

const options = { minimumConfidence: 45, maxCandidates: 8, showLowConfidence: false };

function kinds(input) {
  return smartDecode(input, options).map((candidate) => candidate.kind);
}

function top(input) {
  const candidates = smartDecode(input, options);
  assert.ok(candidates.length > 0, 'expected at least one candidate');
  return candidates[0];
}

function jwt(payload, header = { alg: 'HS256', typ: 'JWT', kid: 'kid-1' }) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.createHmac('sha256', 'secret').update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
}

test('Smart Decode detects JWT with highlighted security metadata', () => {
  const token = jwt({ sub: 'abc', iss: 'issuer', exp: 4102444800, iat: 1700000000 });
  const candidate = top(`Authorization: Bearer ${token}`);
  assert.equal(candidate.kind, 'jwt');
  assert.ok(candidate.confidence >= 90);
  const output = JSON.parse(candidate.output);
  assert.equal(output.header.alg, 'HS256');
  assert.equal(output.highlighted.kid, 'kid-1');
  assert.equal(output.payload.sub, 'abc');
});

test('Smart Decode warns about alg none and expired JWT', () => {
  const token = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${Buffer.from(JSON.stringify({ exp: 1 })).toString('base64url')}.`;
  const candidate = top(token);
  assert.equal(candidate.kind, 'jwt');
  assert.match(candidate.warnings.join('\n'), /alg=none/);
  assert.match(candidate.warnings.join('\n'), /expired/i);
});

test('Smart Decode detects web formats precisely', () => {
  assert.equal(top('hello%20world%3Fq%3Dcrypto%26lang%3Dit').kind, 'urlEncoded');
  assert.equal(top('client_id=test&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&state=abc').kind, 'queryString');
  assert.equal(top('Cookie: session=abc; csrftoken=def; theme=dark').kind, 'cookie');
  assert.equal(top('Authorization: Basic YWRtaW46cGFzc3dvcmQ=').kind, 'basicAuth');
});

test('Smart Decode detects encoding formats while avoiding tiny ambiguous values', () => {
  assert.equal(top('aGVsbG8gd29ybGQ=').kind, 'base64');
  assert.equal(top('Pz8_aGVsbG8').kind, 'base64url');
  assert.equal(top('48656c6c6f2c205653436f646521').kind, 'hex');
  assert.deepEqual(kinds('abc123'), []);
});

test('Smart Decode detects JSON, timestamps, HTML entities, UUID, and PowerShell UTF-16LE commands', () => {
  assert.equal(top('{"hello":"world","n":1}').kind, 'json');
  assert.equal(top('1700000000').kind, 'unixTimestamp');
  assert.equal(top('Tom &amp; Jerry &lt;tag&gt;').kind, 'htmlEntities');
  assert.equal(top('550e8400-e29b-41d4-a716-446655440000').kind, 'uuid');

  const ps = Buffer.from('Write-Output "hello"', 'utf16le').toString('base64');
  assert.equal(top(ps).kind, 'powershellEncodedCommand');
});


test('Smart Decode unwraps manual playground markers and instructional blocks', () => {
  assert.equal(top('<<<aGVsbG8gd29ybGQ=>>>').kind, 'base64');
  assert.equal(top(`Select:
<<<aGVsbG8gd29ybGQ=>>>
Expected:
hello world`).kind, 'base64');
  const urlCandidate = top('<<<hello%20world%3Fq%3Dcrypto%26lang%3Dit>>>');
  assert.equal(urlCandidate.kind, 'urlEncoded');
  assert.equal(urlCandidate.output, 'hello world?q=crypto&lang=it');
});
