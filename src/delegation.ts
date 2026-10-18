import { randomUUID } from 'node:crypto';
import { canonicalize, digest } from './canonical.js';
import { signBytes, verifyBytes } from './keys.js';
import type { ProofRef } from './affixio.js';
import { ACTION, AGENT_ID, isAgentRef, isIsoDate, isProofRef, type AgentRef, type Identity, type Params } from './envelope.js';

export const GRANT_VERSION = 'agent-relay-grant/1';
export const MAX_CHAIN_DEPTH = 5;

export interface Scope {
  /** Exact action names, `prefix.*` patterns, or `*`. */
  actions: string[];
  /** Largest `params.amount` allowed in one request. */
  max_amount?: number;
  /** Largest running total of `params.amount` across all requests under this grant (tracked by the receiver). */
  max_total?: number;
  /** When set, `params.currency` must equal this value. */
  currency?: string;
}

export interface Grant {
  v: typeof GRANT_VERSION;
  id: string;
  issuer: AgentRef;
  subject: AgentRef;
  /** The receiving agent this grant may be presented to. */
  audience: string;
  scope: Scope;
  nbf: string;
  exp: string;
  /** Digest of the parent grant, or null for a root grant issued by a trusted human or organisation key. */
  parent: string | null;
  /** AffixIO proof that the issuer's own policy approved this delegation. */
  proof: ProofRef;
  sig: string;
}

const PATTERN = /^(\*|[a-z0-9][a-z0-9._-]{0,99}(\.\*)?)$/;

export function grantDigest(g: Grant): string {
  return digest(g);
}

function signingInput(g: Grant): string {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sig, ...rest } = g;
  return `${GRANT_VERSION}\n${canonicalize(rest)}`;
}

export function actionMatches(pattern: string, action: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('.*')) return action.startsWith(pattern.slice(0, -1));
  return pattern === action;
}

/** True when every action allowed by `child` is also allowed by `parent`. */
export function patternCovered(child: string, parent: string): boolean {
  if (parent === '*') return true;
  if (child === '*') return false;
  if (parent.endsWith('.*')) return child.startsWith(parent.slice(0, -1));
  return !child.endsWith('.*') && child === parent;
}

export function validScope(s: unknown): s is Scope {
  if (typeof s !== 'object' || s === null || Array.isArray(s)) return false;
  const o = s as Record<string, unknown>;
  if (!Array.isArray(o.actions) || o.actions.length === 0 || o.actions.length > 50) return false;
  if (!o.actions.every((a) => typeof a === 'string' && PATTERN.test(a))) return false;
  for (const k of ['max_amount', 'max_total'] as const) {
    if (o[k] !== undefined && (typeof o[k] !== 'number' || !Number.isFinite(o[k]) || (o[k] as number) < 0)) return false;
  }
  if (o.currency !== undefined && (typeof o.currency !== 'string' || !/^[A-Z]{3}$/.test(o.currency))) return false;
  return true;
}

/** Returns a reason why `child` is not a narrowing of `parent`, or null when it is. */
export function narrowingError(child: Scope, parent: Scope): string | null {
  if (!child.actions.every((c) => parent.actions.some((p) => patternCovered(c, p)))) return 'scope_actions_widened';
  for (const k of ['max_amount', 'max_total'] as const) {
    const p = parent[k];
    const c = child[k];
    if (p !== undefined && (c === undefined || c > p)) return `scope_${k}_widened`;
  }
  if (parent.currency !== undefined && child.currency !== parent.currency) return 'scope_currency_changed';
  return null;
}

export interface IssueGrantInput {
  issuer: Identity;
  subject: AgentRef;
  audience: string;
  scope: Scope;
  proof: ProofRef;
  ttlSeconds?: number;
  /** The chain the issuer itself holds. Omit for a root grant. */
  parentChain?: Grant[];
  now?: number;
}

/** Issue a grant and return the full chain (parent chain plus the new grant). */
export function issueGrant(input: IssueGrantInput): Grant[] {
  const now = input.now ?? Date.now();
  const parentChain = input.parentChain ?? [];
  const parent = parentChain[parentChain.length - 1];
  if (!validScope(input.scope)) throw new Error('invalid scope');
  if (!isAgentRef(input.subject)) throw new Error('invalid subject');
  if (!AGENT_ID.test(input.audience)) throw new Error('invalid audience');
  if (parentChain.length >= MAX_CHAIN_DEPTH) throw new Error('delegation chain too deep');
  let exp = now + (input.ttlSeconds ?? 3600) * 1000;
  if (parent) {
    if (parent.subject.id !== input.issuer.id || parent.subject.key !== input.issuer.keys.publicKey) {
      throw new Error('issuer is not the subject of the parent grant');
    }
    if (parent.audience !== input.audience) throw new Error('audience must match the parent grant');
    const err = narrowingError(input.scope, parent.scope);
    if (err) throw new Error(err);
    exp = Math.min(exp, Date.parse(parent.exp));
  }
  const grant: Grant = {
    v: GRANT_VERSION,
    id: randomUUID(),
    issuer: { id: input.issuer.id, key: input.issuer.keys.publicKey },
    subject: input.subject,
    audience: input.audience,
    scope: input.scope,
    nbf: new Date(now).toISOString(),
    exp: new Date(exp).toISOString(),
    parent: parent ? grantDigest(parent) : null,
    proof: input.proof,
    sig: '',
  };
  grant.sig = signBytes(input.issuer.keys, signingInput(grant));
  return [...parentChain, grant];
}

function isGrantShape(x: unknown): x is Grant {
  if (typeof x !== 'object' || x === null) return false;
  const g = x as Record<string, unknown>;
  return (
    g.v === GRANT_VERSION &&
    typeof g.id === 'string' &&
    g.id.length <= 64 &&
    isAgentRef(g.issuer) &&
    isAgentRef(g.subject) &&
    typeof g.audience === 'string' &&
    AGENT_ID.test(g.audience) &&
    validScope(g.scope) &&
    isIsoDate(g.nbf) &&
    isIsoDate(g.exp) &&
    (g.parent === null || (typeof g.parent === 'string' && /^sha256:[a-f0-9]{64}$/.test(g.parent))) &&
    isProofRef(g.proof) &&
    typeof g.sig === 'string'
  );
}

export interface ChainCheckOptions {
  /** Trusted root keys (humans or organisations). When omitted the root is not checked (holder-side import). */
  trustedRoots?: AgentRef[];
  audience?: string;
  now?: number;
  clockSkewMs?: number;
}

export type ChainResult = { ok: true; leaf: Grant } | { ok: false; reason: string };

/** Offline checks: shape, signatures, links, audience, time and scope narrowing. Proofs are checked separately. */
export function checkChain(chain: unknown, opts: ChainCheckOptions = {}): ChainResult {
  const now = opts.now ?? Date.now();
  const skew = opts.clockSkewMs ?? 60_000;
  if (!Array.isArray(chain) || chain.length === 0) return { ok: false, reason: 'delegation_malformed' };
  if (chain.length > MAX_CHAIN_DEPTH) return { ok: false, reason: 'delegation_too_deep' };
  for (let i = 0; i < chain.length; i++) {
    const g: unknown = chain[i];
    if (!isGrantShape(g)) return { ok: false, reason: 'delegation_malformed' };
    if (!verifyBytes(g.issuer.key, signingInput(g), g.sig)) return { ok: false, reason: 'delegation_bad_signature' };
    if (opts.audience !== undefined && g.audience !== opts.audience) return { ok: false, reason: 'delegation_wrong_audience' };
    if (Date.parse(g.nbf) > now + skew) return { ok: false, reason: 'delegation_not_yet_valid' };
    if (Date.parse(g.exp) <= now) return { ok: false, reason: 'delegation_expired' };
    if (i === 0) {
      if (g.parent !== null) return { ok: false, reason: 'delegation_broken_link' };
      if (opts.trustedRoots) {
        const root = opts.trustedRoots.find((r) => r.id === g.issuer.id);
        if (!root || root.key !== g.issuer.key) return { ok: false, reason: 'delegation_untrusted_root' };
      }
    } else {
      const parent = chain[i - 1] as Grant;
      if (g.parent !== grantDigest(parent)) return { ok: false, reason: 'delegation_broken_link' };
      if (g.issuer.id !== parent.subject.id || g.issuer.key !== parent.subject.key) {
        return { ok: false, reason: 'delegation_broken_link' };
      }
      if (g.audience !== parent.audience) return { ok: false, reason: 'delegation_wrong_audience' };
      if (Date.parse(g.exp) > Date.parse(parent.exp)) return { ok: false, reason: 'delegation_expiry_widened' };
      const err = narrowingError(g.scope, parent.scope);
      if (err) return { ok: false, reason: `delegation_${err}` };
    }
  }
  return { ok: true, leaf: chain[chain.length - 1] as Grant };
}

/** Returns a reason when the action and params fall outside any grant in the chain, or null when allowed. */
export function scopeError(chain: Grant[], action: string, params: Params): string | null {
  if (!ACTION.test(action)) return 'scope_action_denied';
  for (const g of chain) {
    if (!g.scope.actions.some((p) => actionMatches(p, action))) return 'scope_action_denied';
    if (g.scope.max_amount !== undefined || g.scope.max_total !== undefined) {
      const amount = params.amount;
      if (typeof amount !== 'number' || !Number.isFinite(amount) || amount < 0) return 'scope_amount_required';
      if (g.scope.max_amount !== undefined && amount > g.scope.max_amount) return 'scope_amount_exceeded';
    }
    if (g.scope.currency !== undefined && params.currency !== g.scope.currency) return 'scope_currency_mismatch';
  }
  return null;
}
