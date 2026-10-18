import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { MockAffixioClient } from '../../src/affixio.js';
import { createMcpServer } from '../../src/mcp.js';
import { createInboxServer } from '../../src/server.js';
import { Relay } from '../../src/relay.js';
import { close, identity, listen } from '../helpers.js';

const affixio = new MockAffixioClient();
const kris = new Relay({ identity: identity('acme.example/kris'), affixio });
const buyer = new Relay({ identity: identity('acme.example/buyer'), affixio });
const alice = new Relay({ identity: identity('globex.example/alice'), affixio });
const seller = new Relay({
  identity: identity('globex.example/sales'),
  affixio,
  peers: [buyer.ref],
  trustedRoots: [kris.ref],
  policy: {
    allowUnlistedActions: false,
    actions: {
      'quote.request': {},
      'payment.*': { requireDelegation: true },
      'deploy.production': { quorum: { threshold: 1, approvers: [alice.ref] } },
    },
  },
});
const inbox = createInboxServer(seller);
const inboxUrl = await listen(inbox);

async function connect(relay: Relay): Promise<Client> {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await createMcpServer(relay, { inboxUrl: 'http://example.test' }).connect(a);
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(b);
  return client;
}

const buyerMcp = await connect(buyer);
const sellerMcp = await connect(seller);
const aliceMcp = await connect(alice);
const krisMcp = await connect(kris);

after(async () => {
  await Promise.all([buyerMcp.close(), sellerMcp.close(), aliceMcp.close(), krisMcp.close()]);
  await close(inbox);
});

async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const res = await client.callTool({ name, arguments: args });
  const content = res.content as { type: string; text: string }[];
  const text = content[0]?.text ?? 'null';
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }
  return { isError: res.isError === true, data: data as Record<string, unknown> & unknown[] };
}

test('lists the relay tools and no trust-editing tools', async () => {
  const { tools } = await buyerMcp.listTools();
  const names = tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['approve', 'check_inbox', 'delegate', 'import_grant', 'receipts', 'send_request', 'verify_request', 'whoami']);
});

test('whoami', async () => {
  const r = await call(buyerMcp, 'whoami');
  assert.equal(r.data.agent, 'acme.example/buyer');
  assert.equal(r.data.key, buyer.identity.keys.publicKey);
  assert.equal(r.data.inbox_url, 'http://example.test');
});

test('send_request delivers over HTTP and check_inbox shows it as accepted', async () => {
  const r = await call(buyerMcp, 'send_request', { inbox_url: inboxUrl, action: 'quote.request', params: { sku: 'A1', qty: 2 } });
  assert.equal(r.isError, false);
  assert.equal(r.data.sent_to, 'globex.example/sales');
  assert.equal((r.data.result as { status: string }).status, 'accepted');
  const inboxList = await call(sellerMcp, 'check_inbox', { status: 'accepted' });
  assert.ok((inboxList.data as unknown as { id: string }[]).some((i) => i.id === r.data.request_id));
});

test('send_request reports a rejection for an action the receiver does not allow', async () => {
  const r = await call(buyerMcp, 'send_request', { inbox_url: inboxUrl, to: 'globex.example/sales', action: 'admin.wipe' });
  assert.equal((r.data.result as { reason: string }).reason, 'action_not_allowed');
});

test('approve tool completes a quorum request', async () => {
  const sent = await call(buyerMcp, 'send_request', { inbox_url: inboxUrl, action: 'deploy.production', params: { sha: 'abc' } });
  assert.equal((sent.data.result as { status: string }).status, 'pending_approval');
  const wrong = await call(aliceMcp, 'approve', { inbox_url: inboxUrl, request_id: sent.data.request_id, expect_action: 'deploy.staging' });
  assert.equal(wrong.isError, true);
  const outsider = await call(buyerMcp, 'approve', { inbox_url: inboxUrl, request_id: sent.data.request_id });
  assert.equal(outsider.isError, true);
  const r = await call(aliceMcp, 'approve', { inbox_url: inboxUrl, request_id: sent.data.request_id, expect_action: 'deploy.production' });
  assert.equal(r.isError, false);
  assert.equal((r.data.result as { status: string }).status, 'accepted');
  const again = await call(aliceMcp, 'approve', { inbox_url: inboxUrl, request_id: sent.data.request_id });
  assert.equal(again.isError, true);
});

test('delegate, import_grant and send_request with grant_id', async () => {
  const d = await call(krisMcp, 'delegate', {
    subject_id: buyer.identity.id,
    subject_key: buyer.identity.keys.publicKey,
    audience: seller.identity.id,
    actions: ['payment.send'],
    max_amount: 50,
    currency: 'GBP',
    ttl_seconds: 600,
  });
  assert.equal(d.isError, false);
  const imported = await call(buyerMcp, 'import_grant', { chain: d.data.chain });
  assert.equal(imported.data.grant_id, d.data.grant_id);
  const who = await call(buyerMcp, 'whoami');
  assert.equal((who.data.grants as unknown[]).length, 1);

  const ok = await call(buyerMcp, 'send_request', { inbox_url: inboxUrl, action: 'payment.send', params: { amount: 25, currency: 'GBP' }, grant_id: d.data.grant_id });
  assert.equal((ok.data.result as { status: string }).status, 'accepted');
  const over = await call(buyerMcp, 'send_request', { inbox_url: inboxUrl, action: 'payment.send', params: { amount: 75, currency: 'GBP' }, grant_id: d.data.grant_id });
  assert.equal(over.isError, true);
  const noGrant = await call(buyerMcp, 'send_request', { inbox_url: inboxUrl, action: 'payment.send', params: { amount: 5, currency: 'GBP' } });
  assert.equal((noGrant.data.result as { reason: string }).reason, 'delegation_required');
  const bogus = await call(buyerMcp, 'send_request', { inbox_url: inboxUrl, action: 'payment.send', grant_id: 'nope' });
  assert.equal(bogus.isError, true);
  const badImport = await call(aliceMcp, 'import_grant', { chain: d.data.chain });
  assert.equal(badImport.isError, true);
});

test('delegate validates its input', async () => {
  const r = await call(krisMcp, 'delegate', { subject_id: 'x.example/a', subject_key: 'short', audience: 'y.example/b', actions: ['a'] });
  assert.equal(r.isError, true);
});

test('verify_request checks an envelope received by another route', async () => {
  const env = await buyer.createRequest({ to: seller.identity.id, action: 'quote.request' });
  const r = await call(sellerMcp, 'verify_request', { envelope: env });
  assert.equal(r.data.status, 'accepted');
  const replay = await call(sellerMcp, 'verify_request', { envelope: env });
  assert.equal(replay.data.reason, 'replay');
});

test('receipts tool verifies the log and can anchor it', async () => {
  const r = await call(sellerMcp, 'receipts', { limit: 5, anchor: true });
  assert.equal((r.data.check as { ok: boolean }).ok, true);
  assert.equal((r.data.anchored as { type: string }).type, 'anchor');
  assert.ok((r.data.latest as unknown[]).length <= 5);
});

test('receipts tool checks the log against a saved head and will not anchor a mismatch', async () => {
  const first = await call(sellerMcp, 'receipts', {});
  const check = first.data.check as { ok: boolean; count: number; head: string };
  const saved = { expect_seq: check.count - 1, expect_hash: check.head };
  const r = await call(sellerMcp, 'receipts', saved);
  assert.equal((r.data.check as { ok: boolean }).ok, true);

  const count = seller.receipts.entries().length;
  const bad = await call(sellerMcp, 'receipts', { ...saved, expect_hash: 'f'.repeat(64), anchor: true });
  assert.deepEqual((bad.data.check as { reason: string }).reason, 'head_mismatch');
  assert.equal(bad.data.anchored, null);
  assert.equal(seller.receipts.entries().length, count);

  const ahead = await call(sellerMcp, 'receipts', { expect_seq: count + 5, expect_hash: check.head });
  assert.equal((ahead.data.check as { reason: string }).reason, 'truncated');

  const half = await call(sellerMcp, 'receipts', { expect_seq: 0 });
  assert.equal(half.isError, true);
});
