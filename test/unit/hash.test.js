'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const vscode = require('vscode');
const hash = require('../../dist/hash/operations');

test('SHA256 and SHA512 produce known digests', () => {
  assert.equal(
    hash.sha256Hash.run('abc').text,
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
  assert.equal(
    hash.sha512Hash.run('abc').text,
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
  );
});

test('MD5 and SHA1 work but return weak-crypto warnings', () => {
  const md5 = hash.md5Hash.run('abc');
  const sha1 = hash.sha1Hash.run('abc');
  assert.equal(md5.text, '900150983cd24fb0d6963f7d28e17f72');
  assert.equal(sha1.text, 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.match(md5.warnings[0], /MD5/i);
  assert.match(sha1.warnings[0], /SHA1/i);
});

test('HMAC-SHA256 prompts for a secret and returns expected digest', async () => {
  vscode.__reset();
  vscode.__setInputBoxResponses(['secret']);
  const result = await hash.hmacSha256.run('message', {
    commandId: 'test',
    settings: { preferredEncoding: 'utf8' }
  });
  assert.equal(result.text, '8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b');
});
