import { test } from 'node:test';
import assert from 'node:assert/strict';
import { actionHash, createEnvelope, envelopeShapeError, requestDigest, verifyEnvelopeSignature, type Envelope } from '../../src/envelope.js';
import { generateKeyPair, signBytes, verifyBytes } from '../../src/keys.js';
import { identity } from '../helpers.js';

const proof = { provider: 'affixio' as const, circuit: 'yesno', id: 'pf_test-1', digest: 'a'.repeat(64) };

function make(): Envelope {
  return createEnvelope({ from: identity('acme.example/buyer'), to: 'globex.example/sales', action: 'payment.send', params: { amount: 40, currency: 'GBP' }, proof });
}

test('Ed25519 sign and verify round trip, and wrong key fails', () => {
  const kp = generateKeyPair();
  const sig = signBytes(kp, 'hello');
  assert.equal(verifyBytes(kp.publicKey, 'hello', sig), true);
  assert.equal(verifyBytes(kp.publicKey, 'hellp', sig), false);
  assert.equal(verifyBytes(generateKeyPair().publicKey, 'hello', sig), false);
  assert.equal(verifyBytes('not-a-key', 'hello', sig), false);
  assert.equal(verifyBytes(kp.publicKey, 'hello', 'bad sig!'), false);
});

test('new envelope is well formed and its signature verifies', () => {
  const env = make();
  assert.equal(envelopeShapeError(env), null);
  assert.equal(env.v, 'agent-relay/1');
  assert.equal(env.action_hash, actionHash('payment.send', { currency: 'GBP', amount: 40 }));
  assert.equal(verifyEnvelopeSignature(env), true);
  assert.equal(Date.parse(env.exp) - Date.parse(env.iat), 300_000);
});

test('changing any signed field breaks the signature', () => {
  const fields: ((e: Envelope) => void)[] = [
    (e) => (e.to = 'evil.example/x'),
    (e) => (e.action = 'payment.refund'),
    (e) => (e.params = { amount: 4000, currency: 'GBP' }),
    (e) => (e.nonce = 'A'.repeat(24)),
    (e) => (e.exp = new Date(Date.now() + 86_400_000).toISOString()),
    (e) => (e.proof = { ...e.proof, id: 'pf_other' }),
    (e) => (e.from = { ...e.from, id: 'acme.example/other' }),
  ];
  for (const mutate of fields) {
    const env = make();
    mutate(env);
    assert.equal(verifyEnvelopeSignature(env), false);
  }
});

test('approvals are outside the signature and the request digest', () => {
  const env = make();
  const d = requestDigest(env);
  const withApprovals = { ...env, approvals: [] };
  assert.equal(verifyEnvelopeSignature(withApprovals), true);
  assert.equal(requestDigest(withApprovals), d);
});

test('two envelopes for the same action get different ids and nonces', () => {
  const a = make();
  const b = make();
  assert.notEqual(a.id, b.id);
  assert.notEqual(a.nonce, b.nonce);
  assert.equal(a.action_hash, b.action_hash);
});

test('shape check rejects malformed input', () => {
  assert.equal(envelopeShapeError(null), 'malformed');
  assert.equal(envelopeShapeError({ ...make(), v: 'agent-relay/0' }), 'unsupported_version');
  assert.equal(envelopeShapeError({ ...make(), proof: { ...proof, provider: 'other' } }), 'malformed');
  assert.equal(envelopeShapeError({ ...make(), proof: { ...proof, id: 'not-a-proof' } }), 'malformed');
  assert.equal(envelopeShapeError({ ...make(), action: 'Bad Action' }), 'malformed');
  assert.equal(envelopeShapeError({ ...make(), nonce: 'short' }), 'malformed');
  assert.equal(envelopeShapeError({ ...make(), exp: 'tomorrow' }), 'malformed');
  assert.equal(envelopeShapeError({ ...make(), params: [] }), 'malformed');
  assert.equal(envelopeShapeError({ ...make(), delegation: [] }), 'malformed');
});

test('createEnvelope refuses bad input', () => {
  const from = identity('acme.example/buyer');
  assert.throws(() => createEnvelope({ from, to: 'bad id with spaces', action: 'x', proof }));
  assert.throws(() => createEnvelope({ from, to: 'globex.example/sales', action: 'NOPE', proof }));
  assert.throws(() => createEnvelope({ from, to: 'globex.example/sales', action: 'x', proof, ttlSeconds: 0 }));
});
