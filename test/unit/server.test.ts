import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createInboxServer } from '../../src/server.js';
import { HttpTransport } from '../../src/transport.js';
import { Relay } from '../../src/relay.js';
import { close, identity, listen, twoOrgs } from '../helpers.js';

const orgs = twoOrgs();
const approver = new Relay({ identity: identity('globex.example/alice'), affixio: orgs.affixio });
const seller = new Relay({ identity: orgs.sellerId, affixio: orgs.affixio, peers: [orgs.buyer.ref], policy: { actions: { 'deploy.production': { quorum: { threshold: 1, approvers: [approver.ref] } } } } });
const server = createInboxServer(seller, { inboxToken: 'local-test-token-123', maxBodyBytes: 4096 });
const base = await listen(server);
const t = new HttpTransport();
after(() => close(server));

test('identity endpoint', async () => {
  assert.deepEqual(await t.identity(base), { v: 'agent-relay/1', agent: seller.identity.id, key: seller.identity.keys.publicKey });
});

test('delivering a valid envelope returns 200 accepted; replay returns 403', async () => {
  const env = await orgs.buyer.createRequest({ to: seller.identity.id, action: 'quote.request', params: { qty: 1 } });
  const res = await fetch(`${base}/v1/requests`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(env) });
  assert.equal(res.status, 200);
  assert.equal(((await res.json()) as { status: string }).status, 'accepted');
  const again = await fetch(`${base}/v1/requests`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(env) });
  assert.equal(again.status, 403);
  assert.equal(((await again.json()) as { reason: string }).reason, 'replay');
});

test('quorum flow over HTTP: 202 pending, summary without params, approval accepts', async () => {
  const env = await orgs.buyer.createRequest({ to: seller.identity.id, action: 'deploy.production', params: { secret_detail: 'x' } });
  const r = await t.send(base, env);
  assert.equal(r.status, 'pending_approval');
  const s = await t.summary(base, env.id);
  assert.equal(JSON.stringify(s).includes('secret_detail'), false);
  const a = await approver.approve({ requestId: s.id, requestDigest: s.digest });
  const done = await t.approve(base, s.id, a);
  assert.equal(done.status, 'accepted');
});

test('inbox listing needs the bearer token', async () => {
  assert.equal((await fetch(`${base}/v1/inbox`)).status, 401);
  assert.equal((await fetch(`${base}/v1/inbox`, { headers: { authorization: 'Bearer wrong-token-xxxxxxx' } })).status, 401);
  const ok = await fetch(`${base}/v1/inbox?status=accepted`, { headers: { authorization: 'Bearer local-test-token-123' } });
  assert.equal(ok.status, 200);
  const body = (await ok.json()) as { items: { status: string }[] };
  assert.ok(body.items.length >= 1);
  assert.ok(body.items.every((i) => i.status === 'accepted'));
});

test('inbox listing is disabled when no token is configured', async () => {
  const s2 = createInboxServer(seller);
  const b2 = await listen(s2);
  assert.equal((await fetch(`${b2}/v1/inbox`)).status, 404);
  await close(s2);
});

test('bad input: wrong content type, invalid JSON, oversized body, malformed envelope, unknown routes', async () => {
  const post = (body: string, type = 'application/json') => fetch(`${base}/v1/requests`, { method: 'POST', headers: { 'content-type': type }, body });
  assert.equal((await post('{}', 'text/plain')).status, 415);
  assert.equal((await post('{nope')).status, 400);
  assert.equal((await post(JSON.stringify({ pad: 'x'.repeat(5000) }))).status, 413);
  assert.equal((await post('{"v":"agent-relay/1"}')).status, 400);
  assert.equal((await fetch(`${base}/nowhere`)).status, 404);
  assert.equal((await fetch(`${base}/v1/requests/00000000-0000-0000-0000-000000000000`)).status, 404);
  assert.equal(
    (await fetch(`${base}/v1/requests/00000000-0000-0000-0000-000000000000/approvals`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).status,
    404,
  );
});

test('transport refuses non-http URLs', async () => {
  await assert.rejects(t.identity('file:///etc/passwd'), /http or https/);
});
