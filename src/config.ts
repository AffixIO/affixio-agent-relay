import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { generateKeyPair } from './keys.js';
import { AGENT_ID, isAgentRef, type AgentRef, type Identity } from './envelope.js';
import { Relay, type RelayPolicy } from './relay.js';
import { JsonFileStore } from './store.js';
import { ReceiptLog } from './receipts.js';
import type { AffixioClient } from './affixio.js';

/**
 * State directory layout:
 *   identity.json   this agent's id and Ed25519 key pair (mode 600, never commit)
 *   identity.<timestamp>.json  previous key pairs kept by rotateIdentity (mode 600, never commit)
 *   trust.json      { "peers": [AgentRef], "roots": [AgentRef] }, edited by a human
 *   policy.json     RelayPolicy, edited by a human
 *   state.json      nonces, verified grants, spend totals
 *   grants.json     delegation chains held by this agent
 *   receipts.jsonl  hash-chained receipt log
 */
export function initStateDir(dir: string, id: string): Identity {
  if (!AGENT_ID.test(id)) throw new Error('invalid agent id');
  const idPath = join(dir, 'identity.json');
  if (existsSync(idPath)) throw new Error(`${idPath} already exists`);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const identity: Identity = { id, keys: generateKeyPair() };
  writeFileSync(idPath, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o600 });
  chmodSync(idPath, 0o600);
  const trust = join(dir, 'trust.json');
  if (!existsSync(trust)) writeFileSync(trust, `${JSON.stringify({ peers: [], roots: [] }, null, 2)}\n`);
  const policy = join(dir, 'policy.json');
  if (!existsSync(policy)) writeFileSync(policy, `${JSON.stringify({ allowUnlistedActions: false, actions: {} }, null, 2)}\n`);
  writeFileSync(join(dir, '.gitignore'), '*\n');
  return identity;
}

function readJson(path: string, fallback: unknown): unknown {
  if (!existsSync(path)) return fallback;
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

export function loadIdentity(dir: string): Identity {
  const raw = readJson(join(dir, 'identity.json'), null) as Identity | null;
  if (!raw || typeof raw.id !== 'string' || !raw.keys?.publicKey || !raw.keys.privateKey) {
    throw new Error(`no identity in ${dir}; run "agent-relay init" first`);
  }
  return raw;
}

export interface KeyRotation {
  id: string;
  oldKey: string;
  newKey: string;
  /** File name of the previous identity, kept in the state directory. */
  backup: string;
}

/**
 * Give this agent a new Ed25519 key pair under the same agent id. The previous identity is kept as
 * identity.<timestamp>.json (mode 600) and a key.rotated receipt records both public keys. Peers keep trusting
 * the old key until their trust.json is updated.
 */
export function rotateIdentity(dir: string, now: Date = new Date()): KeyRotation {
  const old = loadIdentity(dir);
  const idPath = join(dir, 'identity.json');
  const backupPath = join(dir, `identity.${now.toISOString().replace(/[:.]/g, '-')}.json`);
  writeFileSync(backupPath, readFileSync(idPath), { mode: 0o600, flag: 'wx' });
  chmodSync(backupPath, 0o600);
  const identity: Identity = { id: old.id, keys: generateKeyPair() };
  const tmpPath = `${idPath}.tmp`;
  // Remove a stale temporary file before creating a new one exclusively. This
  // prevents a pre-existing symlink from redirecting the private key write.
  if (existsSync(tmpPath)) unlinkSync(tmpPath);
  writeFileSync(tmpPath, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  chmodSync(tmpPath, 0o600);
  renameSync(tmpPath, idPath);
  const rotation: KeyRotation = { id: old.id, oldKey: old.keys.publicKey, newKey: identity.keys.publicKey, backup: basename(backupPath) };
  new ReceiptLog(join(dir, 'receipts.jsonl')).append('key.rotated', { id: rotation.id, old_key: rotation.oldKey, new_key: rotation.newKey, backup: rotation.backup });
  return rotation;
}

function refs(x: unknown, name: string): AgentRef[] {
  if (x === undefined) return [];
  if (!Array.isArray(x) || !x.every(isAgentRef)) throw new Error(`trust.json: "${name}" must be a list of { id, key }`);
  return x;
}

export function loadRelay(dir: string, affixio: AffixioClient): Relay {
  const identity = loadIdentity(dir);
  const trust = readJson(join(dir, 'trust.json'), {}) as { peers?: unknown; roots?: unknown };
  const policy = readJson(join(dir, 'policy.json'), {}) as RelayPolicy;
  const state = new JsonFileStore(join(dir, 'state.json'));
  const prefixed = (prefix: string) => ({
    get: (k: string) => state.get(prefix + k),
    set: (k: string, v: unknown) => state.set(prefix + k, v),
    delete: (k: string) => state.delete(prefix + k),
    keys: () => state.keys().filter((k) => k.startsWith(prefix)).map((k) => k.slice(prefix.length)),
  });
  return new Relay({
    identity,
    affixio,
    peers: refs(trust.peers, 'peers'),
    trustedRoots: refs(trust.roots, 'roots'),
    policy,
    stores: { nonces: prefixed('nonce/'), grants: prefixed('grant/'), spend: prefixed('spend/'), held: new JsonFileStore(join(dir, 'grants.json')) },
    receipts: new ReceiptLog(join(dir, 'receipts.jsonl')),
  });
}
