'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('../../dist/jwt/operations');

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function signHs(payload, secret = 'secret', header = { alg: 'HS256', typ: 'JWT', kid: 'kid-1' }) {
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.createHmac('sha256', secret).update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
}

test('JWT decode returns simple header, payload, signature metadata and ISO timestamps', () => {
  const token = signHs({ sub: '123', iat: 1700000000, exp: 4102444800 });
  const result = jwt.jwtDecode.run(token, { commandId: 'test', settings: {} });
  const parsed = JSON.parse(result.text);
  assert.equal(parsed.header.alg, 'HS256');
  assert.equal(parsed.header.kid, 'kid-1');
  assert.equal(parsed.payload.sub, '123');
  assert.equal(parsed.payload.iat_iso, '2023-11-14T22:13:20.000Z');
  assert.equal(parsed.signature.present, true);
  assert.deepEqual(parsed.warnings, []);
  assert.equal(result.outputMode, undefined, 'Decode JWT should respect the configured output mode');
});

test('JWT decode accepts Authorization Bearer input and warns on alg=none and expired token', () => {
  const token = `Bearer ${base64url(JSON.stringify({ alg: 'none' }))}.${base64url(JSON.stringify({ exp: 1 }))}.signature`;
  const result = jwt.jwtDecode.run(token, { commandId: 'test', settings: {} });
  assert.match(result.warnings.join('\n'), /alg=none/);
  assert.match(result.warnings.join('\n'), /expired/i);
});

test('JWT decode rejects malformed structure', () => {
  assert.throws(
    () => jwt.jwtDecode.run('not.a.jwt.with.too.many.parts', { commandId: 'test', settings: {} }),
    /Malformed JWT/
  );
});
