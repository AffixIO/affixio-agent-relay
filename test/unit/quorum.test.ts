import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MockAffixioClient } from '../../src/affixio.js';
import { approvalError, createApproval, validQuorumPolicy } from '../../src/quorum.js';
import { Relay } from '../../src/relay.js';
import { identity } from '../helpers.js';

function setup(threshold = 2, clock?: () => number) {
  const affixio = new MockAffixioClient();
  const approvers = ['alice', 'bob', 'carol'].map((n) => new Relay({ identity: identity(`globex.example/${n}`), affixio }));
  const buyer = new Relay({ identity: identity('acme.example/deployer'), affixio });
  const seller = new Relay({
    identity: identity('globex.example/ci'),
    affixio,
    peers: [buyer.ref],
    policy: { actions: { 'deploy.production': { quorum: { threshold, approvers: approvers.map((a) => a.ref) } } } },
    now: clock,
  });
  return { affixio, approvers, buyer, seller };
}

test('policy validation', () => {
  const a = { id: 'x.example/a', key: identity('a').keys.publicKey };
  const b = { id: 'x.example/b', key: identity('b').keys.publicKey };
  assert.ok(validQuorumPolicy({ threshold: 2, approvers: [a, b] }));
  assert.ok(!validQuorumPolicy({ threshold: 3, approvers: [a, b] }));
  assert.ok(!validQuorumPolicy({ threshold: 0, approvers: [a] }));
  assert.ok(!validQuorumPolicy({ threshold: 1, approvers: [a, a] }));
  assert.throws(() => new Relay({ identity: identity('x'), affixio: new MockAffixioClient(), policy: { actions: { x: { quorum: { threshold: 5, approvers: [a] } } } } }));
});

test('2 of 3: request waits, one approval is not enough, the second accepts it', async () => {
  const { approvers, buyer, seller } = setup();
  const r = await seller.receive(await buyer.createRequest({ to: seller.identity.id, action: 'deploy.production', params: { sha: 'abc123' } }));
  assert.deepEqual([r.status, r.approvals], ['pending_approval', { have: 0, need: 2 }]);
  const s = seller.summary(r.id!);
  assert.equal(s?.status, 'pending_approval');
  assert.equal('params' in (s as object), false);

  const a1 = await approvers[0]!.approve({ requestId: s!.id, requestDigest: s!.digest });
  assert.equal((await seller.addApproval(s!.id, a1)).status, 'pending_approval');
  const dup = await approvers[0]!.approve({ requestId: s!.id, requestDigest: s!.digest });
  assert.equal((await seller.addApproval(s!.id, dup)).reason, 'approval_duplicate');

  const a2 = await approvers[2]!.approve({ requestId: s!.id, requestDigest: s!.digest });
  const done = await seller.addApproval(s!.id, a2);
  assert.deepEqual([done.status, done.approvals], ['accepted', { have: 2, need: 2 }]);
  assert.equal(seller.inbox('accepted').length, 1);
  assert.ok(seller.receipts.entries().some((e) => e.type === 'request.accepted' && Array.isArray(e.data.approvers)));
});

test('approvals attached to the envelope count at delivery', async () => {
  const { approvers, buyer, seller } = setup(2);
  const env = await buyer.createRequest({ to: seller.identity.id, action: 'deploy.production' });
  const { requestDigest } = await import('../../src/envelope.js');
  const d = requestDigest(env);
  env.approvals = [await approvers[0]!.approve({ requestId: env.id, requestDigest: d }), await approvers[1]!.approve({ requestId: env.id, requestDigest: d })];
  assert.equal((await seller.receive(env)).status, 'accepted');
});

test('outsiders, wrong digests, forged signatures and reused proofs do not count', async () => {
  const { approvers, buyer, seller, affixio } = setup();
  const r = await seller.receive(await buyer.createRequest({ to: seller.identity.id, action: 'deploy.production' }));
  const id = r.id!;
  const digest = r.digest!;
  const outsider = new Relay({ identity: identity('evil.example/mallory'), affixio });
  assert.equal((await seller.addApproval(id, await outsider.approve({ requestId: id, requestDigest: digest }))).reason, 'approval_unknown_approver');
  assert.equal((await seller.addApproval(id, await approvers[0]!.approve({ requestId: id, requestDigest: 'sha256:' + '0'.repeat(64) }))).reason, 'approval_wrong_request');
  const forged = await approvers[1]!.approve({ requestId: id, requestDigest: digest });
  forged.approver = approvers[2]!.ref;
  assert.equal((await seller.addApproval(id, forged)).reason, 'approval_bad_signature');
  assert.equal((await seller.addApproval(id, { nope: 1 })).reason, 'approval_malformed');

  const good = await approvers[0]!.approve({ requestId: id, requestDigest: digest });
  assert.equal((await seller.addApproval(id, good)).reason, undefined);
  // Bob signs a fresh approval but reuses Alice's spent proof.
  const reused = createApproval({ approver: approvers[1]!.identity, requestId: id, requestDigest: digest, proof: good.proof });
  assert.equal((await seller.addApproval(id, reused)).reason, 'approval_proof_already_used');
  assert.equal(seller.summary(id)?.approvals?.have, 1);
  assert.equal((await seller.addApproval('00000000-0000-0000-0000-000000000000', good)).reason, 'unknown_request');
});

test('a request that expires before quorum cannot be approved', async () => {
  let clock = Date.now();
  const { approvers, buyer, seller } = setup(2, () => clock);
  const r = await seller.receive(await buyer.createRequest({ to: seller.identity.id, action: 'deploy.production', ttlSeconds: 60 }));
  clock += 61_000;
  const a = await approvers[0]!.approve({ requestId: r.id!, requestDigest: r.digest! });
  assert.equal((await seller.addApproval(r.id!, a)).status, 'expired');
  assert.equal(seller.inbox('expired').length, 1);
});

test('approvalError is null for a valid approval', () => {
  const alice = identity('globex.example/alice');
  const policy = { threshold: 1, approvers: [{ id: alice.id, key: alice.keys.publicKey }] };
  const a = createApproval({ approver: alice, requestId: 'r1', requestDigest: 'sha256:' + 'a'.repeat(64), proof: { provider: 'affixio', circuit: 'yesno', id: 'pf_x', digest: 'b'.repeat(64) } });
  assert.equal(approvalError(a, policy, 'r1', 'sha256:' + 'a'.repeat(64)), null);
});
