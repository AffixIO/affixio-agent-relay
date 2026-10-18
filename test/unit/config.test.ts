import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { initStateDir, loadRelay } from '../../src/config.js';
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
