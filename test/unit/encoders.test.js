'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const encoders = require('../../dist/encoders/operations');
const buffer = require('../../dist/crypto/buffer');

test('Base64 encode/decode handles UTF-8 text', () => {
  const encoded = encoders.base64Encode.run('ciao 👋').text;
  assert.equal(encoded, Buffer.from('ciao 👋', 'utf8').toString('base64'));
  assert.equal(encoders.base64Decode.run(encoded).text, 'ciao 👋');
});

test('Base64URL encode/decode round trips text', () => {
  const encoded = encoders.base64UrlEncode.run('hello+/=').text;
  assert.equal(encoded.includes('+'), false);
  assert.equal(encoded.includes('/'), false);
  assert.equal(encoded.includes('='), false);
  assert.equal(encoders.base64UrlDecode.run(encoded).text, 'hello+/=');
});

test('Hex encode/decode round trips text', () => {
  const encoded = encoders.hexEncode.run('abc123').text;
  assert.equal(encoded, '616263313233');
  assert.equal(encoders.hexDecode.run(encoded).text, 'abc123');
});

test('URL and HTML encode/decode work on common payloads', () => {
  assert.equal(encoders.urlDecode.run(encoders.urlEncode.run('a b&x=1').text).text, 'a b&x=1');
  assert.equal(encoders.htmlEncode.run('<script>alert("x")</script>').text, '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
  assert.equal(encoders.htmlDecode.run('&lt;b&gt;ok&lt;/b&gt; &amp; &#x41;').text, '<b>ok</b> & A');
});

test('Malformed Base64 and hex are rejected', () => {
  assert.throws(() => buffer.fromBase64('not@@base64'), /Malformed Base64/);
  assert.throws(() => buffer.fromHex('abc'), /Malformed hex/);
  assert.throws(() => buffer.fromHex('zz'), /Malformed hex/);
});
