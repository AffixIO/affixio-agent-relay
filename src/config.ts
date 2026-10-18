import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPair } from './keys.js';
import { AGENT_ID, isAgentRef, type AgentRef, type Identity } from './envelope.js';
import { Relay, type RelayPolicy } from './relay.js';
import { JsonFileStore } from './store.js';
import { ReceiptLog } from './receipts.js';
import type { AffixioClient } from './affixio.js';

/**
 * State directory layout:
 *   identity.json   this agent's id and Ed25519 key pair (mode 600, never commit)
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
