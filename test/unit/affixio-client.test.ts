import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AffixioError, HttpAffixioClient, MockAffixioClient } from '../../src/affixio.js';

const KEY = 'test-key-not-real';

function fakeFetch(handler: (url: string, init: RequestInit) => { status: number; body: unknown }) {
  const calls: { url: string; init: RequestInit }[] = [];
  const f = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init: init ?? {} });
    const r = handler(url, init ?? {});
    return new Response(JSON.stringify(r.body), { status: r.status, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { f, calls };
}

test('prove posts yes/no fields with the API key header and maps the response', async () => {
  const { f, calls } = fakeFetch(() => ({ status: 200, body: { proof_id: 'pf_1', proof_digest: 'b'.repeat(64), decision: 'yes' } }));
  const c = new HttpAffixioClient({ apiKey: KEY, fetch: f });
  const p = await c.prove();
  assert.deepEqual(p, { provider: 'affixio', circuit: 'yesno', id: 'pf_1', digest: 'b'.repeat(64), decision: 'yes' });
  assert.equal(calls[0]?.url, 'https://api.affix-io.com/v1/circuits/yesno/prove');
  const headers = calls[0]?.init.headers as Record<string, string>;
  assert.equal(headers['X-API-Key'], KEY);
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), { fields: { condition_greater1: true, condition_greater2: true, condition_greater3: true } });
});

test('prove failure throws AffixioError with the code and without the key', async () => {
  const { f } = fakeFetch(() => ({ status: 400, body: { error: 'invalid_fields' } }));
  const c = new HttpAffixioClient({ apiKey: KEY, fetch: f });
  await assert.rejects(c.prove({ wrong: true }), (err: unknown) => {
    assert.ok(err instanceof AffixioError);
    assert.equal(err.code, 'invalid_fields');
    assert.equal(err.status, 400);
    assert.ok(!err.message.includes(KEY));
    return true;
  });
});

test('verify maps 200, 409 double spend and 400 invalid proof', async () => {
  let n = 0;
  const { f, calls } = fakeFetch(() => {
    n++;
    if (n === 1) return { status: 200, body: { valid: true, decision: 'yes', proof_digest: 'c'.repeat(64) } };
    if (n === 2) return { status: 409, body: { error: 'double_spend_detected' } };
    return { status: 400, body: { error: 'invalid_proof' } };
  });
  const c = new HttpAffixioClient({ apiKey: KEY, fetch: f, baseUrl: 'https://example.test/' });
  const ref = { provider: 'affixio' as const, circuit: 'yesno', id: 'pf_1', digest: 'c'.repeat(64) };
  assert.deepEqual(await c.verify(ref), { valid: true, decision: 'yes', digest: 'c'.repeat(64), code: undefined });
  assert.deepEqual(await c.verify(ref), { valid: false, code: 'double_spend_detected' });
  assert.deepEqual(await c.verify(ref), { valid: false, code: 'invalid_proof' });
  assert.equal(calls[0]?.url, 'https://example.test/v1/circuits/yesno/verify');
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), { proof: 'pf_1' });
});

test('verify throws on server errors and refuses unsafe ids without calling out', async () => {
  const { f, calls } = fakeFetch(() => ({ status: 503, body: {} }));
  const c = new HttpAffixioClient({ apiKey: KEY, fetch: f });
  await assert.rejects(c.verify({ provider: 'affixio', circuit: 'yesno', id: 'pf_1', digest: 'd'.repeat(64) }), AffixioError);
  const r = await c.verify({ provider: 'affixio', circuit: '../admin', id: 'pf_1', digest: 'd'.repeat(64) });
  assert.equal(r.code, 'malformed_proof_ref');
  assert.equal(calls.length, 1);
});

test('merkle root and proof calls', async () => {
  const { f, calls } = fakeFetch((url) =>
    url.endsWith('/root') ? { status: 200, body: { root: 'e'.repeat(64), leaf_count: 7, updated_at: '2026-01-01T00:00:00Z' } } : { status: 200, body: { digest: 'e'.repeat(64), proof: [] } },
  );
  const c = new HttpAffixioClient({ apiKey: KEY, fetch: f });
  assert.deepEqual(await c.merkleRoot(), { root: 'e'.repeat(64), leafCount: 7, updatedAt: '2026-01-01T00:00:00Z' });
  assert.equal((await c.merkleProof('e'.repeat(64))).digest, 'e'.repeat(64));
  await assert.rejects(c.merkleProof('../x'));
  assert.equal(calls.length, 2);
});

test('constructor requires a key', () => {
  assert.throws(() => new HttpAffixioClient({ apiKey: '' }));
});

test('mock keeps single-use semantics', async () => {
  const m = new MockAffixioClient();
  const p = await m.prove();
  assert.equal((await m.verify(p)).valid, true);
  assert.equal((await m.verify(p)).code, 'double_spend_detected');
  assert.equal((await m.verify({ ...p, id: 'pf_unknown' })).code, 'invalid_proof');
  assert.equal((await m.prove({ a: true, b: false })).decision, 'no');
  await assert.rejects(m.prove({}));
});
