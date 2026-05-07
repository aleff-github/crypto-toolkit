'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const vscode = require('vscode');
const aes = require('../../dist/aes/operations');

const context = {
  commandId: 'test',
  settings: { preferredEncoding: 'utf8' }
};

test('AES-CBC encrypt/decrypt round trips with manual key and IV', async () => {
  vscode.__reset();
  vscode.__setQuickPickResponses(['utf8', 'Enter manually', 'utf8']);
  vscode.__setInputBoxResponses(['1234567890abcdef', 'abcdef1234567890']);

  const encrypted = await aes.aesCbcEncrypt.run('secret text', context);
  const payload = JSON.parse(encrypted.text);
  assert.equal(payload.alg, 'AES-128-CBC');
  assert.equal(payload.encoding, 'base64');
  assert.equal(typeof payload.iv, 'string');
  assert.equal(typeof payload.ciphertext, 'string');

  vscode.__reset();
  vscode.__setQuickPickResponses(['utf8']);
  vscode.__setInputBoxResponses(['1234567890abcdef']);

  const decrypted = await aes.aesCbcDecrypt.run(encrypted.text, context);
  assert.equal(decrypted.text, 'secret text');
});

test('AES-GCM encrypt/decrypt round trips with manual key and nonce', async () => {
  vscode.__reset();
  vscode.__setQuickPickResponses(['utf8', 'Enter manually', 'utf8']);
  vscode.__setInputBoxResponses(['1234567890abcdef', '123456789012']);

  const encrypted = await aes.aesGcmEncrypt.run('authenticated plaintext', context);
  const payload = JSON.parse(encrypted.text);
  assert.equal(payload.alg, 'AES-128-GCM');
  assert.equal(typeof payload.tag, 'string');

  vscode.__reset();
  vscode.__setQuickPickResponses(['utf8']);
  vscode.__setInputBoxResponses(['1234567890abcdef']);

  const decrypted = await aes.aesGcmDecrypt.run(encrypted.text, context);
  assert.equal(decrypted.text, 'authenticated plaintext');
});

test('AES rejects invalid key lengths with a user-facing error', async () => {
  vscode.__reset();
  vscode.__setQuickPickResponses(['utf8', 'Enter manually', 'utf8']);
  vscode.__setInputBoxResponses(['short', 'abcdef1234567890']);

  await assert.rejects(
    () => aes.aesCbcEncrypt.run('data', context),
    /Invalid AES key length/
  );
});
