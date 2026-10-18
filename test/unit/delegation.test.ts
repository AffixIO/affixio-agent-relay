import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MockAffixioClient } from '../../src/affixio.js';
import { actionMatches, checkChain, issueGrant, narrowingError, patternCovered, scopeError, type Grant } from '../../src/delegation.js';
import { Relay } from '../../src/relay.js';
import { identity, ref } from '../helpers.js';

const proof = { provider: 'affixio' as const, circuit: 'yesno', id: 'pf_g', digest: 'a'.repeat(64) };
const AUD = 'globex.example/sales';

test('action patterns and coverage', () => {
  assert.ok(actionMatches('*', 'payment.send'));
  assert.ok(actionMatches('payment.*', 'payment.send'));
  assert.ok(!actionMatches('payment.*', 'paymentx.send'));
  assert.ok(!actionMatches('payment.send', 'payment.refund'));
  assert.ok(patternCovered('payment.send', 'payment.*'));
  assert.ok(patternCovered('payment.eu.*', 'payment.*'));
  assert.ok(!patternCovered('payment.*', 'payment.send'));
  assert.ok(!patternCovered('*', 'payment.*'));
  assert.ok(patternCovered('anything', '*'));
});

test('narrowing rules: actions, amounts, currency', () => {
  const parent = { actions: ['payment.*'], max_amount: 100, max_total: 500, currency: 'GBP' };
  assert.equal(narrowingError({ actions: ['payment.send'], max_amount: 40, max_total: 100, currency: 'GBP' }, parent), null);
  assert.equal(narrowingError({ actions: ['deploy.prod'], max_amount: 40, max_total: 100, currency: 'GBP' }, parent), 'scope_actions_widened');
  assert.equal(narrowingError({ actions: ['payment.send'], max_amount: 400, max_total: 100, currency: 'GBP' }, parent), 'scope_max_amount_widened');
  assert.equal(narrowingError({ actions: ['payment.send'], max_total: 100, currency: 'GBP' }, parent), 'scope_max_amount_widened');
  assert.equal(narrowingError({ actions: ['payment.send'], max_amount: 40, max_total: 900, currency: 'GBP' }, parent), 'scope_max_total_widened');
  assert.equal(narrowingError({ actions: ['payment.send'], max_amount: 40, max_total: 100, currency: 'USD' }, parent), 'scope_currency_changed');
});

function chain3() {
  const kris = identity('acme.example/kris');
  const a = identity('acme.example/agent-a');
  const b = identity('acme.example/agent-b');
  const c1 = issueGrant({ issuer: kris, subject: ref(a), audience: AUD, scope: { actions: ['payment.*'], max_amount: 100, max_total: 100, currency: 'GBP' }, proof, ttlSeconds: 3600 });
  const c2 = issueGrant({ issuer: a, subject: ref(b), audience: AUD, scope: { actions: ['payment.send'], max_amount: 40, max_total: 60, currency: 'GBP' }, proof, parentChain: c1, ttlSeconds: 7200 });
  return { kris, a, b, c1, c2 };
}

test('a two-step chain checks out and the child expiry is capped by the parent', () => {
  const { kris, c2 } = chain3();
  const r = checkChain(c2, { trustedRoots: [ref(kris)], audience: AUD });
  assert.equal(r.ok, true);
  assert.ok(Date.parse(c2[1]!.exp) <= Date.parse(c2[0]!.exp));
});

test('issueGrant refuses to widen scope or skip a link', () => {
  const { a, b, c1 } = chain3();
  assert.throws(() => issueGrant({ issuer: a, subject: ref(b), audience: AUD, scope: { actions: ['payment.*'], max_amount: 500, max_total: 100, currency: 'GBP' }, proof, parentChain: c1 }), /widened/);
  assert.throws(() => issueGrant({ issuer: b, subject: ref(a), audience: AUD, scope: { actions: ['payment.send'], max_amount: 1, max_total: 1, currency: 'GBP' }, proof, parentChain: c1 }), /not the subject/);
  assert.throws(() => issueGrant({ issuer: a, subject: ref(b), audience: 'other.example/x', scope: { actions: ['payment.send'], max_amount: 1, max_total: 1, currency: 'GBP' }, proof, parentChain: c1 }), /audience/);
  assert.throws(() => issueGrant({ issuer: a, subject: ref(b), audience: AUD, scope: { actions: [] }, proof }), /invalid scope/);
});

test('chain check catches untrusted roots, broken links, forged scopes, wrong audience and expiry', () => {
  const { kris, c2 } = chain3();
  const roots = [ref(kris)];
  assert.equal(checkChain(c2, { trustedRoots: [ref(identity('acme.example/kris'))], audience: AUD }).ok, false);
  assert.deepEqual(checkChain(c2, { trustedRoots: [], audience: AUD }), { ok: false, reason: 'delegation_untrusted_root' });
  assert.deepEqual(checkChain(c2, { trustedRoots: roots, audience: 'other.example/x' }), { ok: false, reason: 'delegation_wrong_audience' });
  assert.deepEqual(checkChain([c2[1]], { trustedRoots: roots }), { ok: false, reason: 'delegation_broken_link' });

  const forged = structuredClone(c2) as Grant[];
  forged[1]!.scope.max_amount = 100000;
  assert.deepEqual(checkChain(forged, { trustedRoots: roots }), { ok: false, reason: 'delegation_bad_signature' });

  const swapped = structuredClone(c2) as Grant[];
  swapped[0]!.scope.max_amount = 1;
  assert.equal(checkChain(swapped, { trustedRoots: roots }).ok, false);

  assert.deepEqual(checkChain(c2, { trustedRoots: roots, now: Date.now() + 2 * 3600_000 }), { ok: false, reason: 'delegation_expired' });
  assert.deepEqual(checkChain([], {}), { ok: false, reason: 'delegation_malformed' });
  assert.deepEqual(checkChain([{ v: 'x' }], {}), { ok: false, reason: 'delegation_malformed' });
});

test('scope check against a concrete request', () => {
  const { c2 } = chain3();
  assert.equal(scopeError(c2, 'payment.send', { amount: 40, currency: 'GBP' }), null);
  assert.equal(scopeError(c2, 'payment.send', { amount: 41, currency: 'GBP' }), 'scope_amount_exceeded');
  assert.equal(scopeError(c2, 'payment.refund', { amount: 1, currency: 'GBP' }), 'scope_action_denied');
  assert.equal(scopeError(c2, 'payment.send', { amount: 10, currency: 'EUR' }), 'scope_currency_mismatch');
  assert.equal(scopeError(c2, 'payment.send', { currency: 'GBP' }), 'scope_amount_required');
  assert.equal(scopeError(c2, 'payment.send', { amount: -5, currency: 'GBP' }), 'scope_amount_required');
});

function relays() {
  const affixio = new MockAffixioClient();
  const kris = new Relay({ identity: identity('acme.example/kris'), affixio });
  const a = new Relay({ identity: identity('acme.example/agent-a'), affixio });
  const b = new Relay({ identity: identity('acme.example/agent-b'), affixio });
  const seller = new Relay({ identity: identity(AUD), affixio, trustedRoots: [kris.ref], policy: { actions: { 'payment.*': { requireDelegation: true } } } });
  return { affixio, kris, a, b, seller };
}

test('end to end: human to agent A to agent B, receiver enforces per-request and running totals', async () => {
  const { affixio, kris, a, b, seller } = relays();
  const c1 = await kris.delegate({ subject: a.ref, audience: AUD, scope: { actions: ['payment.*'], max_amount: 100, max_total: 100, currency: 'GBP' } });
  a.importGrant(c1);
  const c2 = await a.delegate({ subject: b.ref, audience: AUD, scope: { actions: ['payment.send'], max_amount: 40, max_total: 60, currency: 'GBP' }, parentChain: c1 });
  b.importGrant(c2);
  assert.equal(b.heldGrants().length, 1);

  const r1 = await seller.receive(await b.createRequest({ to: AUD, action: 'payment.send', params: { amount: 40, currency: 'GBP' }, delegation: c2 }));
  assert.equal(r1.status, 'accepted');
  const verifiesAfterFirst = affixio.calls.verify;
  assert.equal(verifiesAfterFirst, 3, 'two grant proofs plus the request proof');

  const r2 = await seller.receive(await b.createRequest({ to: AUD, action: 'payment.send', params: { amount: 20, currency: 'GBP' }, delegation: c2 }));
  assert.equal(r2.status, 'accepted');
  assert.equal(affixio.calls.verify, verifiesAfterFirst + 1, 'grant proofs are verified once and remembered');

  const r3 = await seller.receive(await b.createRequest({ to: AUD, action: 'payment.send', params: { amount: 1, currency: 'GBP' }, delegation: c2 }));
  assert.equal(r3.reason, 'scope_total_exceeded');

  await assert.rejects(b.createRequest({ to: AUD, action: 'payment.send', params: { amount: 50, currency: 'GBP' }, delegation: c2 }), /scope_amount_exceeded/);
});

test('receiver rejects a chain presented by someone other than its subject, and requires delegation when configured', async () => {
  const { kris, a, b, seller } = relays();
  const c1 = await kris.delegate({ subject: a.ref, audience: AUD, scope: { actions: ['payment.*'] } });
  const env = await b.createRequest({ to: AUD, action: 'payment.send', params: {} });
  const stolen = { ...env, delegation: c1 };
  // The signature covers delegation, so re-sign as b would: build a fresh envelope via the low-level API.
  const { createEnvelope } = await import('../../src/envelope.js');
  const forged = createEnvelope({ from: b.identity, to: AUD, action: 'payment.send', proof: env.proof, delegation: c1 });
  assert.equal((await seller.receive(stolen)).reason, 'bad_signature');
  assert.equal((await seller.receive(forged)).reason, 'delegation_subject_mismatch');
  const noChain = await a.createRequest({ to: AUD, action: 'payment.send' });
  assert.equal((await seller.receive(noChain)).reason, 'delegation_required');
});

test('a grant with an unverifiable proof is rejected', async () => {
  const { a, seller, kris } = relays();
  const c1 = issueGrant({ issuer: kris.identity, subject: a.ref, audience: AUD, scope: { actions: ['payment.*'] }, proof: { ...proof, id: 'pf_never_issued' } });
  const r = await seller.receive(await a.createRequest({ to: AUD, action: 'payment.send', delegation: c1 }));
  assert.equal(r.reason, 'delegation_proof_invalid');
});

test('importGrant only accepts chains addressed to this agent', async () => {
  const { kris, a, b } = relays();
  const c1 = await kris.delegate({ subject: a.ref, audience: AUD, scope: { actions: ['x'] } });
  assert.throws(() => b.importGrant(c1), /not addressed/);
  assert.throws(() => b.importGrant([{ bogus: true }]), /delegation_malformed/);
});
