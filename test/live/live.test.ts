/**
 * Live tests against the public AffixIO API. They run only when AFFIXIO_API_KEY is set and use about ten proofs.
 */
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AffixioError, HttpAffixioClient } from '../../src/affixio.js';
import { createEnvelope } from '../../src/envelope.js';
import { Relay } from '../../src/relay.js';
import { createInboxServer } from '../../src/server.js';
import { HttpTransport } from '../../src/transport.js';
import { createMcpServer } from '../../src/mcp.js';
import { close, identity, listen } from '../helpers.js';

const apiKey = process.env.AFFIXIO_API_KEY;
const skip = apiKey ? false : 'AFFIXIO_API_KEY is not set';
const opts = { skip, timeout: 120_000 };

function client(): HttpAffixioClient {
  return new HttpAffixioClient({ apiKey: apiKey ?? 'unset', baseUrl: process.env.AFFIXIO_BASE_URL });
}

describe('AffixIO REST client (live)', opts, () => {
  test('prove, verify once, then double spend is refused', async () => {
    const c = client();
    const p = await c.prove();
    assert.match(p.id, /^pf_/);
    assert.equal(p.decision, 'yes');
    const v = await c.verify(p);
    assert.equal(v.valid, true);
    assert.equal(v.decision, 'yes');
    assert.equal(v.digest, p.digest);
    const again = await c.verify(p);
    assert.deepEqual(again, { valid: false, code: 'double_spend_detected' });
  });

  test('wrong field names give invalid_fields', async () => {
    await assert.rejects(client().prove({ not_a_field: true }), (err: unknown) => err instanceof AffixioError && err.status === 400 && err.code === 'invalid_fields');
  });

  test('an unknown proof id is not valid', async () => {
    const v = await client().verify({ provider: 'affixio', circuit: 'yesno', id: 'pf_00000000-0000-0000-0000-000000000000', digest: '0'.repeat(64) });
    assert.equal(v.valid, false);
  });
});

describe('two organisations over HTTP inboxes (live)', opts, () => {
  const t = new HttpTransport();
  let servers: Server[] = [];
  let acme: { kris: Relay; buyer: Relay; agentA: Relay; agentB: Relay };
  let globex: { sales: Relay; ci: Relay; alice: Relay; bob: Relay; carol: Relay };
  let salesUrl = '';
  let ciUrl = '';

  before(async () => {
    // Each organisation has its own AffixIO client, as two separate companies would.
    const acmeApi = client();
    const globexApi = client();
    const kris = new Relay({ identity: identity('acme.example/kris'), affixio: acmeApi });
    const buyer = new Relay({ identity: identity('acme.example/buyer'), affixio: acmeApi });
    const agentA = new Relay({ identity: identity('acme.example/agent-a'), affixio: acmeApi });
    const agentB = new Relay({ identity: identity('acme.example/agent-b'), affixio: acmeApi });
    acme = { kris, buyer, agentA, agentB };
    const [alice, bob, carol] = ['alice', 'bob', 'carol'].map((n) => new Relay({ identity: identity(`globex.example/${n}`), affixio: globexApi })) as [Relay, Relay, Relay];
    const sales = new Relay({
      identity: identity('globex.example/sales'),
      affixio: globexApi,
      peers: [buyer.ref],
      trustedRoots: [kris.ref],
      policy: { allowUnlistedActions: false, actions: { 'quote.request': {}, 'payment.*': { requireDelegation: true } } },
    });
    const ci = new Relay({
      identity: identity('globex.example/ci'),
      affixio: globexApi,
      peers: [buyer.ref],
      policy: { allowUnlistedActions: false, actions: { 'deploy.production': { quorum: { threshold: 2, approvers: [alice.ref, bob.ref, carol.ref] } } } },
    });
    globex = { sales, ci, alice, bob, carol };
    servers = [createInboxServer(sales), createInboxServer(ci)];
    salesUrl = await listen(servers[0]!);
    ciUrl = await listen(servers[1]!);
  });

  after(async () => {
    await Promise.all(servers.map((s) => close(s)));
  });

  test('a pinned peer request is verified with AffixIO and accepted; replays and tampering are refused', async () => {
    const env = await acme.buyer.createRequest({ to: globex.sales.identity.id, action: 'quote.request', params: { sku: 'WIDGET-9', qty: 12 } });
    const r = await t.send(salesUrl, env);
    assert.equal(r.status, 'accepted');

    const replay = await t.send(salesUrl, env);
    assert.equal(replay.reason, 'replay');

    const tampered = { ...structuredClone(env), params: { sku: 'WIDGET-9', qty: 1200 } };
    assert.equal((await t.send(salesUrl, tampered)).reason, 'action_hash_mismatch');

    // A second receiver with no local memory of the nonce: AffixIO itself refuses the spent proof.
    const freshReceiver = new Relay({ identity: globex.sales.identity, affixio: client(), peers: [acme.buyer.ref], policy: globex.sales.policy });
    const rewrapped = createEnvelope({ from: acme.buyer.identity, to: globex.sales.identity.id, action: 'quote.request', params: { sku: 'WIDGET-9', qty: 12 }, proof: env.proof });
    assert.equal((await freshReceiver.receive(rewrapped)).reason, 'proof_already_used');

    const check = globex.sales.verifyReceipts();
    assert.equal(check.ok, true);
  });

  test('delegation: human to agent A to agent B, enforced by the receiving organisation', async () => {
    const aud = globex.sales.identity.id;
    const c1 = await acme.kris.delegate({ subject: acme.agentA.ref, audience: aud, scope: { actions: ['payment.*'], max_amount: 100, max_total: 100, currency: 'GBP' }, ttlSeconds: 600 });
    acme.agentA.importGrant(c1);
    const c2 = await acme.agentA.delegate({ subject: acme.agentB.ref, audience: aud, scope: { actions: ['payment.send'], max_amount: 40, max_total: 40, currency: 'GBP' }, parentChain: c1 });
    acme.agentB.importGrant(c2);

    const env = await acme.agentB.createRequest({ to: aud, action: 'payment.send', params: { amount: 40, currency: 'GBP', ref: 'INV-1' }, delegation: c2 });
    const r = await t.send(salesUrl, env);
    assert.equal(r.status, 'accepted', JSON.stringify(r));

    // Locally refused before any proof is spent: outside B's narrower scope.
    await assert.rejects(acme.agentB.createRequest({ to: aud, action: 'payment.refund', params: { amount: 1, currency: 'GBP' }, delegation: c2 }), /scope_action_denied/);
  });

  test('quorum: deploy waits for 2 of 3 approvers, one via MCP', async () => {
    const env = await acme.buyer.createRequest({ to: globex.ci.identity.id, action: 'deploy.production', params: { sha: '9f1c2e7' } });
    const r = await t.send(ciUrl, env);
    assert.deepEqual([r.status, r.approvals], ['pending_approval', { have: 0, need: 2 }]);

    const s = await t.summary(ciUrl, env.id);
    const a1 = await globex.alice.approve({ requestId: s.id, requestDigest: s.digest, action: s.action });
    const after1 = await t.approve(ciUrl, s.id, a1);
    assert.deepEqual([after1.status, after1.approvals], ['pending_approval', { have: 1, need: 2 }]);

    const [x, y] = InMemoryTransport.createLinkedPair();
    await createMcpServer(globex.carol).connect(x);
    const mcp = new Client({ name: 'live-test', version: '0.0.0' });
    await mcp.connect(y);
    const res = await mcp.callTool({ name: 'approve', arguments: { inbox_url: ciUrl, request_id: env.id, expect_action: 'deploy.production' } });
    await mcp.close();
    const body = JSON.parse((res.content as { text: string }[])[0]?.text ?? '{}') as { result: { status: string } };
    assert.equal(res.isError, undefined);
    assert.equal(body.result.status, 'accepted');
    assert.equal(globex.ci.inbox('accepted').length, 1);
  });

  test('receipts: chain verifies, anchors to the AffixIO Merkle root and a verified proof has an inclusion proof', async () => {
    const anchor = await globex.ci.anchor();
    assert.match(String(anchor.data.affixio_merkle_root), /^[a-f0-9]{64}$/);
    assert.equal(globex.ci.verifyReceipts().ok, true);
    const verified = globex.ci.receipts.entries().find((e) => e.type === 'request.verified');
    const inc = await globex.ci.inclusion(String(verified?.data.proof_digest));
    assert.equal(inc.digest, verified?.data.proof_digest);
    assert.ok(Array.isArray(inc.proof));
  });
});
