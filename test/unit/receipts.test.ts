import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GENESIS, ReceiptLog, verifyReceipts } from '../../src/receipts.js';
import { MockAffixioClient } from '../../src/affixio.js';
import { twoOrgs } from '../helpers.js';

function filled(path?: string) {
  const log = new ReceiptLog(path);
  log.append('a', { n: 1 });
  log.append('b', { n: 2, nested: { x: [1, 2] } });
  log.append('c', { n: 3 });
  return log;
}

test('a fresh log is valid and chained from genesis', () => {
  const log = filled();
  const e = log.entries();
  assert.equal(e[0]?.prev, GENESIS);
  assert.equal(e[1]?.prev, e[0]?.hash);
  assert.deepEqual(log.verify(), { ok: true, count: 3, head: e[2]?.hash });
  assert.deepEqual(new ReceiptLog().verify(), { ok: true, count: 0, head: GENESIS });
});

test('editing, deleting, inserting or reordering entries is detected', () => {
  const e = filled().entries();
  const edited = structuredClone(e);
  edited[1]!.data.n = 99;
  assert.deepEqual([verifyReceipts(edited).ok, verifyReceipts(edited).brokenAt, verifyReceipts(edited).reason], [false, 1, 'hash']);
  const deleted = [e[0]!, e[2]!];
  assert.equal(verifyReceipts(deleted).ok, false);
  const reordered = [e[0]!, e[2]!, e[1]!];
  assert.equal(verifyReceipts(reordered).ok, false);
  const rehashed = structuredClone(e);
  rehashed[1]!.data.n = 99;
  // Even a correctly recomputed hash breaks the link to the next entry.
  rehashed[1]!.hash = 'f'.repeat(64);
  assert.equal(verifyReceipts(rehashed).brokenAt, 1);
});

test('file-backed log detects edits made on disk and survives reload', () => {
  const dir = mkdtempSync(join(tmpdir(), 'relay-receipts-'));
  const path = join(dir, 'receipts.jsonl');
  filled(path);
  const reloaded = new ReceiptLog(path);
  assert.equal(reloaded.verify().ok, true);
  reloaded.append('d', { n: 4 });
  assert.deepEqual([reloaded.verify().ok, reloaded.verify().count], [true, 4]);

  const lines = readFileSync(path, 'utf8').trim().split('\n');
  writeFileSync(path, lines.map((l, i) => (i === 2 ? l.replace('"n":3', '"n":30') : l)).join('\n') + '\n');
  assert.deepEqual([reloaded.verify().ok, reloaded.verify().brokenAt], [false, 2]);

  writeFileSync(path, lines.slice(1).join('\n') + '\n');
  assert.equal(new ReceiptLog(path).verify().ok, false);
  writeFileSync(path, 'not json\n');
  assert.equal(new ReceiptLog(path).verify().ok, false);
});

test('anchor records the log head against the AffixIO Merkle root, and refuses a tampered log', async () => {
  const affixio = new MockAffixioClient();
  const { buyer, seller } = twoOrgs({ affixio });
  await seller.receive(await buyer.createRequest({ to: seller.identity.id, action: 'a' }));
  const head = seller.receipts.head();
  const a = await seller.anchor();
  assert.equal(a.type, 'anchor');
  assert.equal(a.data.log_head, head);
  assert.equal(a.data.affixio_merkle_root, 'f'.repeat(64));
  assert.equal(seller.verifyReceipts().ok, true);
  const verified = seller.receipts.entries().find((e) => e.type === 'request.verified');
  const inc = await seller.inclusion(String(verified?.data.proof_digest));
  assert.equal(inc.digest, verified?.data.proof_digest);

  const dir = mkdtempSync(join(tmpdir(), 'relay-anchor-'));
  const path = join(dir, 'r.jsonl');
  filled(path);
  writeFileSync(path, readFileSync(path, 'utf8').replace('"n":2', '"n":20'));
  const { Relay } = await import('../../src/relay.js');
  const r = new Relay({ identity: seller.identity, affixio, receipts: new ReceiptLog(path) });
  await assert.rejects(r.anchor(), /failed verification/);
});
