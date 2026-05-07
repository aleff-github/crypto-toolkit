'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const utils = require('../../dist/utils/operations');

test('JSON pretty/minify work and reject malformed JSON', () => {
  assert.equal(utils.jsonPretty.run('{"b":2,"a":1}').text, '{\n  "b": 2,\n  "a": 1\n}');
  assert.equal(utils.jsonMinify.run('{\n  "a": 1\n}').text, '{"a":1}');
  assert.throws(() => utils.jsonPretty.run('{bad'), /Malformed JSON/);
});

test('Unix timestamp decode handles seconds and milliseconds', () => {
  assert.equal(JSON.parse(utils.unixDecode.run('1700000000').text).iso, '2023-11-14T22:13:20.000Z');
  assert.equal(JSON.parse(utils.unixDecode.run('1700000000000').text).iso, '2023-11-14T22:13:20.000Z');
});

test('Generators work with empty input', async () => {
  assert.match(utils.uuidGenerate.run('').text, /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  const timestamp = JSON.parse(utils.unixEncode.run('').text);
  assert.equal(typeof timestamp.seconds, 'number');
});

test('Line sort and unique are deterministic', () => {
  assert.equal(utils.sortLines.run('b\na\nc').text, 'a\nb\nc');
  assert.equal(utils.uniqueLines.run('a\nb\na\nc\nb').text, 'a\nb\nc');
});
