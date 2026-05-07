'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { smartDecode } = require('../../dist/smart/smartDecode');

const options = { minimumConfidence: 45, maxCandidates: 12, showLowConfidence: false };

function top(input) {
  const candidates = smartDecode(input, options);
  assert.ok(candidates.length > 0, `expected candidates for ${input.slice(0, 80)}`);
  return candidates[0];
}

function kinds(input) {
  return smartDecode(input, options).map((candidate) => candidate.kind);
}

function b64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function sshString(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(buffer.length, 0);
  return Buffer.concat([length, buffer]);
}

test('Smart Decode detects private/public PEM keys without exposing parsing errors', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

  assert.equal(top(privatePem).kind, 'privateKey');
  assert.match(top(privatePem).warnings.join('\n'), /Private key material/);
  assert.equal(top(publicPem).kind, 'publicKey');
});

test('Smart Decode detects SSH public keys and fingerprints the key blob', () => {
  const keyBlob = Buffer.concat([sshString('ssh-ed25519'), sshString(Buffer.alloc(32, 7))]);
  const keyLine = `ssh-ed25519 ${keyBlob.toString('base64')} tester@example`;
  const candidate = top(keyLine);
  assert.equal(candidate.kind, 'sshPublicKey');
  assert.match(candidate.output, /SHA256:/);
});

test('Smart Decode detects password hash formats', () => {
  assert.equal(top(`$2b$12$${'a'.repeat(53)}`).kind, 'passwordHash');
  assert.equal(top('$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2g').kind, 'passwordHash');
  assert.equal(top('pbkdf2_sha256$260000$somesalt$abcdef123456').kind, 'passwordHash');
});

test('Smart Decode detects hash-like values and checksum lines conservatively', () => {
  const sha256 = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  assert.equal(top(sha256).kind, 'hashLike');
  assert.equal(top(`${sha256}  file.txt`).kind, 'checksum');
});

test('Smart Decode detects JOSE/JWE/PASETO/Fernet token containers', () => {
  const jwe = `${b64urlJson({ alg: 'dir', enc: 'A256GCM' })}..${'a'.repeat(16)}.${'b'.repeat(32)}.${'c'.repeat(22)}`;
  assert.equal(top(jwe).kind, 'jwe');

  assert.equal(top('v4.public.dGVzdHBheWxvYWQ.dGVzdGZvb3Rlcg').kind, 'paseto');

  const fernet = Buffer.alloc(73);
  fernet[0] = 0x80;
  fernet.writeBigUInt64BE(BigInt(1700000000), 1);
  assert.equal(top(fernet.toString('base64url')).kind, 'fernet');
});

test('Smart Decode detects OTPAuth, OpenPGP armor, encrypted containers, and API secrets', () => {
  assert.equal(top('otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub').kind, 'otpauth');

  const pgp = '-----BEGIN PGP MESSAGE-----\n\nabc123\n-----END PGP MESSAGE-----';
  assert.equal(top(pgp).kind, 'openpgp');

  assert.equal(top('$ANSIBLE_VAULT;1.1;AES256\n313233').kind, 'ansibleVault');

  const openssl = Buffer.concat([Buffer.from('Salted__'), Buffer.alloc(8, 1), Buffer.alloc(16, 2)]).toString('base64');
  assert.equal(top(openssl).kind, 'opensslSalted');

  assert.equal(top('AKIA1234567890ABCDEF').kind, 'secret');
});

test('Smart Decode detects ASN.1/DER-like data, SAML XML, and framework tokens', () => {
  const derLike = Buffer.from('3082010a020101300d06092a864886f70d0101010500', 'hex').toString('base64');
  assert.ok(kinds(derLike).includes('asn1Der'));

  const saml = '<samlp:Response><saml:Issuer>issuer</saml:Issuer><saml:Assertion><saml:Audience>aud</saml:Audience></saml:Assertion></samlp:Response>';
  assert.equal(top(saml).kind, 'saml');

  const laravel = JSON.stringify({ iv: 'abc', value: 'def', mac: '0123456789abcdef' });
  assert.equal(top(laravel).kind, 'webFrameworkToken');
});
