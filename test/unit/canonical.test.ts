import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, digest, sha256Hex } from '../../src/canonical.js';

test('canonicalize sorts keys at every level and drops undefined', () => {
  assert.equal(canonicalize({ b: 1, a: { d: [1, { z: 1, y: 2 }], c: undefined } }), '{"a":{"d":[1,{"y":2,"z":1}]},"b":1}');
});

test('canonicalize gives equal output for equal objects built in different orders', () => {
  assert.equal(canonicalize({ x: 1, y: 'two' }), canonicalize({ y: 'two', x: 1 }));
  assert.equal(digest({ x: 1, y: 'two' }), digest({ y: 'two', x: 1 }));
});

test('canonicalize rejects non-finite numbers and functions', () => {
  assert.throws(() => canonicalize({ a: Number.NaN }));
  assert.throws(() => canonicalize({ a: Infinity }));
  assert.throws(() => canonicalize({ a: () => 1 }));
});

test('digest is prefixed sha256 and changes with any value', () => {
  assert.match(digest({ a: 1 }), /^sha256:[a-f0-9]{64}$/);
  assert.notEqual(digest({ a: 1 }), digest({ a: 2 }));
  assert.equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
