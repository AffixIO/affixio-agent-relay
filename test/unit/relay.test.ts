import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createEnvelope, type Envelope } from '../../src/envelope.js';
import { MockAffixioClient, type AffixioClient } from '../../src/affixio.js';
import { Relay } from '../../src/relay.js';
import { identity, ref, twoOrgs } from '../helpers.js';

test('a signed request with a fresh proof is accepted and recorded', async () => {
  const { buyer, seller } = twoOrgs();
  const env = await buyer.createRequest({ to: seller.identity.id, action: 'quote.request', params: { sku: 'X-1', qty: 3 } });
  const r = await seller.receive(env);
  assert.equal(r.status, 'accepted');
  assert.equal(seller.inbox('accepted').length, 1);
  assert.deepEqual(seller.inbox()[0]?.envelope.params, { sku: 'X-1', qty: 3 });
  const types = seller.receipts.entries().map((e) => e.type);
  assert.deepEqual(types, ['request.verified', 'request.accepted']);
  assert.equal(buyer.receipts.entries()[0]?.type, 'request.sent');
});

test('replaying the same envelope is rejected locally without calling AffixIO again', async () => {
  const { buyer, seller, affixio } = twoOrgs();
  const env = await buyer.createRequest({ to: seller.identity.id, action: 'quote.request' });
  assert.equal((await seller.receive(env)).status, 'accepted');
  const before = (affixio as MockAffixioClient).calls.verify;
  const r = await seller.receive(env);
  assert.deepEqual([r.status, r.reason], ['rejected', 'replay']);
  assert.equal((affixio as MockAffixioClient).calls.verify, before);
});

test('concurrent duplicates: only one is accepted', async () => {
  const { buyer, seller } = twoOrgs();
  const env = await buyer.createRequest({ to: seller.identity.id, action: 'quote.request' });
  const results = await Promise.all([seller.receive(env), seller.receive(structuredClone(env)), seller.receive(structuredClone(env))]);
  assert.equal(results.filter((r) => r.status === 'accepted').length, 1);
});

test('a proof reused in a new envelope is caught by AffixIO single use', async () => {
  const { buyer, seller, buyerId } = twoOrgs();
  const first = await buyer.createRequest({ to: seller.identity.id, action: 'quote.request' });
  assert.equal((await seller.receive(first)).status, 'accepted');
  const second = createEnvelope({ from: buyerId, to: seller.identity.id, action: 'quote.request', proof: first.proof });
  const r = await seller.receive(second);
  assert.deepEqual([r.status, r.reason], ['rejected', 'proof_already_used']);
});

test('expired, future-dated and over-long envelopes are rejected before AffixIO', async () => {
  const affixio = new MockAffixioClient();
  const { buyerId, seller } = twoOrgs({ affixio });
  const proof = await affixio.prove();
  const old = createEnvelope({ from: buyerId, to: seller.identity.id, action: 'a', proof, ttlSeconds: 60, now: Date.now() - 120_000 });
  assert.equal((await seller.receive(old)).reason, 'expired');
  const future = createEnvelope({ from: buyerId, to: seller.identity.id, action: 'a', proof, now: Date.now() + 600_000 });
  assert.equal((await seller.receive(future)).reason, 'issued_in_future');
  const long = createEnvelope({ from: buyerId, to: seller.identity.id, action: 'a', proof, ttlSeconds: 86_400 });
  assert.equal((await seller.receive(long)).reason, 'lifetime_too_long');
  assert.equal(affixio.calls.verify, 0);
});

test('expiry is enforced against the receiver clock', async () => {
  let clock = Date.now();
  const affixio = new MockAffixioClient();
  const { buyer, seller } = twoOrgs({ affixio, seller: { now: () => clock } });
  const env = await buyer.createRequest({ to: seller.identity.id, action: 'a', ttlSeconds: 30 });
  clock += 31_000;
  assert.equal((await seller.receive(env)).reason, 'expired');
});

test('tampered params, wrong recipient, bad signature and unknown sender are rejected', async () => {
  const { buyer, seller, affixio } = twoOrgs();
  const base = await buyer.createRequest({ to: seller.identity.id, action: 'payment.send', params: { amount: 40 } });

  const tampered: Envelope = { ...structuredClone(base), params: { amount: 4000 } };
  assert.equal((await seller.receive(tampered)).reason, 'action_hash_mismatch');

  const rehashed: Envelope = { ...tampered, action_hash: (await import('../../src/envelope.js')).actionHash('payment.send', { amount: 4000 }) };
  assert.equal((await seller.receive(rehashed)).reason, 'bad_signature');

  const other = new Relay({ identity: identity('initech.example/ops'), affixio, peers: [buyer.ref] });
  assert.equal((await other.receive(structuredClone(base))).reason, 'wrong_recipient');

  const stranger = new Relay({ identity: identity('evil.example/bot'), affixio });
  const fromStranger = await stranger.createRequest({ to: seller.identity.id, action: 'payment.send' });
  assert.equal((await seller.receive(fromStranger)).reason, 'unknown_sender');

  // Same id as a pinned peer but a different key.
  const impostor = new Relay({ identity: { id: buyer.identity.id, keys: identity('x').keys }, affixio });
  assert.equal((await seller.receive(await impostor.createRequest({ to: seller.identity.id, action: 'a' }))).reason, 'unknown_sender');

  assert.equal((await seller.receive(base)).status, 'accepted');
});

test('malformed input is rejected and logged', async () => {
  const { seller } = twoOrgs();
  assert.equal((await seller.receive({ hello: 'world' })).reason, 'malformed');
  assert.equal((await seller.receive('nope')).reason, 'malformed');
  assert.equal(seller.receipts.entries().at(-1)?.type, 'request.rejected');
});

test('a "no" decision, a digest mismatch and an AffixIO outage all block the request', async () => {
  const affixio = new MockAffixioClient();
  const { buyerId, seller } = twoOrgs({ affixio });
  const no = await affixio.prove({ a: false });
  const env1 = createEnvelope({ from: buyerId, to: seller.identity.id, action: 'a', proof: no });
  assert.equal((await seller.receive(env1)).reason, 'proof_decision_no');

  const yes = await affixio.prove();
  const env2 = createEnvelope({ from: buyerId, to: seller.identity.id, action: 'a', proof: { ...yes, digest: '0'.repeat(64) } });
  assert.equal((await seller.receive(env2)).reason, 'proof_digest_mismatch');

  const down: AffixioClient = { ...affixio, prove: affixio.prove.bind(affixio), verify: async () => { throw new Error('network'); }, merkleRoot: affixio.merkleRoot.bind(affixio), merkleProof: affixio.merkleProof.bind(affixio) };
  const sellerDown = new Relay({ identity: seller.identity, affixio: down, peers: seller.peers });
  const env3 = createEnvelope({ from: buyerId, to: seller.identity.id, action: 'a', proof: await affixio.prove() });
  assert.equal((await sellerDown.receive(env3)).reason, 'proof_unverifiable');

  const invented = createEnvelope({ from: buyerId, to: seller.identity.id, action: 'a', proof: { provider: 'affixio', circuit: 'yesno', id: 'pf_invented', digest: 'a'.repeat(64) } });
  assert.equal((await seller.receive(invented)).reason, 'proof_invalid');
});

test('sender refuses to send when its own policy says no', async () => {
  const affixio = new MockAffixioClient();
  const buyer = new Relay({ identity: identity('acme.example/buyer'), affixio, authorise: (_kind, detail) => ({ condition_greater1: detail.action !== 'payment.send' }) });
  await assert.rejects(buyer.createRequest({ to: 'globex.example/sales', action: 'payment.send' }), /declined/);
  assert.ok(await buyer.createRequest({ to: 'globex.example/sales', action: 'quote.request' }));
});

test('policy can refuse unlisted actions', async () => {
  const { buyer, seller } = twoOrgs({ seller: { policy: { allowUnlistedActions: false, actions: { 'quote.*': {} } } } });
  assert.equal((await seller.receive(await buyer.createRequest({ to: seller.identity.id, action: 'quote.request' }))).status, 'accepted');
  assert.equal((await seller.receive(await buyer.createRequest({ to: seller.identity.id, action: 'payment.send' }))).reason, 'action_not_allowed');
});

test('inbox keeps a bounded number of items', async () => {
  const { buyer, seller } = twoOrgs({ seller: { maxInboxItems: 2 } });
  for (let i = 0; i < 3; i++) await seller.receive(await buyer.createRequest({ to: seller.identity.id, action: 'a' }));
  assert.equal(seller.inbox().length, 2);
});

test('nonces from the same pinned sender stay unique across envelopes', async () => {
  const { buyer, seller } = twoOrgs();
  for (let i = 0; i < 5; i++) {
    assert.equal((await seller.receive(await buyer.createRequest({ to: seller.identity.id, action: 'a' }))).status, 'accepted');
  }
  assert.equal(ref(buyer.identity).id, 'acme.example/buyer');
});
