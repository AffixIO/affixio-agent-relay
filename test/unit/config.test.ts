import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, statSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { initStateDir, loadIdentity, loadRelay, rotateIdentity } from '../../src/config.js';
import { MockAffixioClient } from '../../src/affixio.js';

test('init writes a private identity and load builds a working relay with persistent replay state', async () => {
  const affixio = new MockAffixioClient();
  const base = mkdtempSync(join(tmpdir(), 'relay-config-'));
  const a = initStateDir(join(base, 'a'), 'acme.example/buyer');
  const b = initStateDir(join(base, 'b'), 'globex.example/sales');
  assert.equal(statSync(join(base, 'a', 'identity.json')).mode & 0o777, 0o600);
  assert.throws(() => initStateDir(join(base, 'a'), 'acme.example/buyer'), /already exists/);
  writeFileSync(join(base, 'b', 'trust.json'), JSON.stringify({ peers: [{ id: a.id, key: a.keys.publicKey }], roots: [] }));
  writeFileSync(join(base, 'b', 'policy.json'), JSON.stringify({ allowUnlistedActions: false, actions: { 'quote.request': {} } }));

  const sender = loadRelay(join(base, 'a'), affixio);
  const env = await sender.createRequest({ to: b.id, action: 'quote.request' });
  const receiver = loadRelay(join(base, 'b'), affixio);
  assert.equal((await receiver.receive(env)).status, 'accepted');
  // A restarted receiver still remembers the nonce.
  const restarted = loadRelay(join(base, 'b'), affixio);
  assert.equal((await restarted.receive(env)).reason, 'replay');
  assert.equal(restarted.verifyReceipts().ok, true);
  assert.equal(restarted.verifyReceipts().count, 3);
  assert.equal(readFileSync(join(base, 'a', '.gitignore'), 'utf8'), '*\n');
});

test('bad trust file is reported', () => {
  const base = mkdtempSync(join(tmpdir(), 'relay-config-'));
  initStateDir(base, 'acme.example/x');
  writeFileSync(join(base, 'trust.json'), JSON.stringify({ peers: [{ id: 'x' }] }));
  assert.throws(() => loadRelay(base, new MockAffixioClient()), /trust.json/);
});

test('CLI init and id', () => {
  const cli = fileURLToPath(new URL('../../src/cli.js', import.meta.url));
  const dir = join(mkdtempSync(join(tmpdir(), 'relay-cli-')), 'state');
  const out = JSON.parse(execFileSync(process.execPath, [cli, 'init', '--dir', dir, '--id', 'acme.example/cli'], { encoding: 'utf8' })) as { id: string; key: string };
  assert.equal(out.id, 'acme.example/cli');
  const id = JSON.parse(execFileSync(process.execPath, [cli, 'id', '--dir', dir], { encoding: 'utf8' })) as { key: string };
  assert.equal(id.key, out.key);
  assert.equal(JSON.stringify(id).includes('privateKey'), false);
  assert.throws(() => execFileSync(process.execPath, [cli, 'serve', '--dir', dir], { encoding: 'utf8', stdio: 'pipe', env: { PATH: process.env.PATH ?? '' } }), /AFFIXIO_API_KEY/);
});

test('rotate keeps the agent id, backs up the old identity and records a receipt', async () => {
  const affixio = new MockAffixioClient();
  const base = mkdtempSync(join(tmpdir(), 'relay-rotate-'));
  const a = initStateDir(join(base, 'a'), 'acme.example/buyer');
  const b = initStateDir(join(base, 'b'), 'globex.example/sales');
  writeFileSync(join(base, 'b', 'trust.json'), JSON.stringify({ peers: [{ id: a.id, key: a.keys.publicKey }], roots: [] }));
  writeFileSync(join(base, 'b', 'policy.json'), JSON.stringify({ allowUnlistedActions: false, actions: { 'quote.request': {} } }));

  const now = new Date('2026-01-02T03:04:05.678Z');
  const r = rotateIdentity(join(base, 'a'), now);
  assert.deepEqual([r.id, r.oldKey, r.backup], [a.id, a.keys.publicKey, 'identity.2026-01-02T03-04-05-678Z.json']);
  assert.notEqual(r.newKey, r.oldKey);
  const backup = join(base, 'a', r.backup);
  assert.equal(statSync(backup).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(readFileSync(backup, 'utf8')), a);
  assert.equal(statSync(join(base, 'a', 'identity.json')).mode & 0o777, 0o600);
  assert.equal(existsSync(join(base, 'a', 'identity.json.tmp')), false);
  const current = loadIdentity(join(base, 'a'));
  assert.deepEqual([current.id, current.keys.publicKey], [a.id, r.newKey]);
  assert.throws(() => rotateIdentity(join(base, 'a'), now), /EEXIST/);
  assert.equal(loadIdentity(join(base, 'a')).keys.publicKey, r.newKey);

  const sender = loadRelay(join(base, 'a'), affixio);
  assert.equal(sender.verifyReceipts().ok, true);
  const receipt = sender.receipts.entries().find((e) => e.type === 'key.rotated');
  assert.deepEqual(receipt?.data, { id: a.id, old_key: r.oldKey, new_key: r.newKey, backup: r.backup });
  assert.equal(JSON.stringify(sender.receipts.entries()).includes(a.keys.privateKey), false);
  assert.equal(JSON.stringify(sender.receipts.entries()).includes(current.keys.privateKey), false);

  // The peer still pins the old key, so it rejects the new one until trust.json is updated.
  const receiver = loadRelay(join(base, 'b'), affixio);
  assert.equal((await receiver.receive(await sender.createRequest({ to: b.id, action: 'quote.request' }))).status, 'rejected');
  writeFileSync(join(base, 'b', 'trust.json'), JSON.stringify({ peers: [{ id: a.id, key: r.newKey }], roots: [] }));
  const updated = loadRelay(join(base, 'b'), affixio);
  assert.equal((await updated.receive(await sender.createRequest({ to: b.id, action: 'quote.request' }))).status, 'accepted');
});

test('CLI rotate', () => {
  const cli = fileURLToPath(new URL('../../src/cli.js', import.meta.url));
  const dir = join(mkdtempSync(join(tmpdir(), 'relay-cli-')), 'state');
  assert.throws(() => execFileSync(process.execPath, [cli, 'rotate', '--dir', dir], { encoding: 'utf8', stdio: 'pipe' }), /run "agent-relay init" first/);
  const init = JSON.parse(execFileSync(process.execPath, [cli, 'init', '--dir', dir, '--id', 'acme.example/cli'], { encoding: 'utf8' })) as { key: string };
  const out = JSON.parse(execFileSync(process.execPath, [cli, 'rotate', '--dir', dir], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })) as Record<string, string>;
  assert.deepEqual([out.id, out.old_key], ['acme.example/cli', init.key]);
  assert.match(out.backup ?? '', /^identity\..+\.json$/);
  assert.equal(JSON.stringify(out).includes('privateKey'), false);
  const id = JSON.parse(execFileSync(process.execPath, [cli, 'id', '--dir', dir], { encoding: 'utf8' })) as { key: string };
  assert.equal(id.key, out.new_key);
});
