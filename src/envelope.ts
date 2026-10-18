import { randomBytes, randomUUID } from 'node:crypto';
import { canonicalize, digest } from './canonical.js';
import { isPublicKey, signBytes, verifyBytes, type KeyPair } from './keys.js';
import type { ProofRef } from './affixio.js';
import type { Grant } from './delegation.js';
import type { Approval } from './quorum.js';

export const ENVELOPE_VERSION = 'agent-relay/1';

/** An agent or human identity: a stable id plus its Ed25519 public key (base64url). */
export interface AgentRef {
  id: string;
  key: string;
}

export interface Identity {
  id: string;
  keys: KeyPair;
}

export type Params = Record<string, unknown>;

export interface Envelope {
  v: typeof ENVELOPE_VERSION;
  id: string;
  from: AgentRef;
  to: string;
  action: string;
  params: Params;
  /** sha256 over the canonical form of { action, params }. */
  action_hash: string;
  nonce: string;
  iat: string;
  exp: string;
  proof: ProofRef;
  delegation?: Grant[];
  /** Ed25519 signature by `from.key` over everything except `sig` and `approvals`. */
  sig: string;
  /** Quorum approvals. Not covered by `sig`; each approval signs the request digest itself. */
  approvals?: Approval[];
}

export const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,199}$/;
export const ACTION = /^[a-z0-9][a-z0-9._-]{0,99}$/;
const NONCE = /^[A-Za-z0-9_-]{16,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function actionHash(action: string, params: Params): string {
  return digest({ action, params });
}

function unsigned(env: Envelope): Omit<Envelope, 'sig' | 'approvals'> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sig, approvals, ...rest } = env;
  return rest;
}

/** Digest that identifies a request. Approvals sign this value. */
export function requestDigest(env: Envelope): string {
  return digest(unsigned(env));
}

function signingInput(env: Envelope): string {
  return `${ENVELOPE_VERSION}\n${canonicalize(unsigned(env))}`;
}

export interface CreateEnvelopeInput {
  from: Identity;
  to: string;
  action: string;
  params?: Params;
  proof: ProofRef;
  delegation?: Grant[];
  ttlSeconds?: number;
  now?: number;
}

export function createEnvelope(input: CreateEnvelopeInput): Envelope {
  const now = input.now ?? Date.now();
  const params = input.params ?? {};
  const ttl = input.ttlSeconds ?? 300;
  if (!AGENT_ID.test(input.to)) throw new Error('invalid recipient id');
  if (!ACTION.test(input.action)) throw new Error('invalid action name');
  if (!(ttl > 0)) throw new Error('ttlSeconds must be positive');
  const env: Envelope = {
    v: ENVELOPE_VERSION,
    id: randomUUID(),
    from: { id: input.from.id, key: input.from.keys.publicKey },
    to: input.to,
    action: input.action,
    params,
    action_hash: actionHash(input.action, params),
    nonce: randomBytes(18).toString('base64url'),
    iat: new Date(now).toISOString(),
    exp: new Date(now + ttl * 1000).toISOString(),
    proof: input.proof,
    ...(input.delegation && input.delegation.length > 0 ? { delegation: input.delegation } : {}),
    sig: '',
  };
  env.sig = signBytes(input.from.keys, signingInput(env));
  return env;
}

export function verifyEnvelopeSignature(env: Envelope): boolean {
  return verifyBytes(env.from.key, signingInput(env), env.sig);
}

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

export function isAgentRef(x: unknown): x is AgentRef {
  return isObject(x) && typeof x.id === 'string' && AGENT_ID.test(x.id) && isPublicKey(x.key);
}

export function isProofRef(x: unknown): x is ProofRef {
  return (
    isObject(x) &&
    x.provider === 'affixio' &&
    typeof x.circuit === 'string' &&
    /^[A-Za-z0-9_-]{1,64}$/.test(x.circuit) &&
    typeof x.id === 'string' &&
    /^pf_[A-Za-z0-9_.:-]{1,200}$/.test(x.id) &&
    typeof x.digest === 'string' &&
    /^[a-f0-9]{64}$/.test(x.digest)
  );
}

export function isIsoDate(x: unknown): x is string {
  return typeof x === 'string' && x.length <= 40 && !Number.isNaN(Date.parse(x));
}

/** Structural check. Returns a reason code, or null when the value has the shape of an envelope. */
export function envelopeShapeError(x: unknown): string | null {
  if (!isObject(x)) return 'malformed';
  if (typeof x.v !== 'string') return 'malformed';
  if (x.v !== ENVELOPE_VERSION) return 'unsupported_version';
  if (typeof x.id !== 'string' || !UUID.test(x.id)) return 'malformed';
  if (!isAgentRef(x.from)) return 'malformed';
  if (typeof x.to !== 'string' || !AGENT_ID.test(x.to)) return 'malformed';
  if (typeof x.action !== 'string' || !ACTION.test(x.action)) return 'malformed';
  if (!isObject(x.params)) return 'malformed';
  if (typeof x.action_hash !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(x.action_hash)) return 'malformed';
  if (typeof x.nonce !== 'string' || !NONCE.test(x.nonce)) return 'malformed';
  if (!isIsoDate(x.iat) || !isIsoDate(x.exp)) return 'malformed';
  if (!isProofRef(x.proof)) return 'malformed';
  if (typeof x.sig !== 'string' || x.sig.length === 0) return 'malformed';
  if (x.delegation !== undefined && (!Array.isArray(x.delegation) || x.delegation.length === 0)) return 'malformed';
  if (x.approvals !== undefined && !Array.isArray(x.approvals)) return 'malformed';
  try {
    canonicalize(x.params);
  } catch {
    return 'malformed';
  }
  return null;
}
