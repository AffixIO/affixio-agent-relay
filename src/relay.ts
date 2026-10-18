import { DEFAULT_YESNO_FIELDS, type AffixioClient, type ProofRef } from './affixio.js';
import {
  actionHash,
  createEnvelope,
  envelopeShapeError,
  requestDigest,
  verifyEnvelopeSignature,
  type AgentRef,
  type Envelope,
  type Identity,
  type Params,
} from './envelope.js';
import { actionMatches, checkChain, grantDigest, issueGrant, scopeError, type Grant, type Scope } from './delegation.js';
import { approvalError, createApproval, validQuorumPolicy, type Approval, type QuorumPolicy } from './quorum.js';
import { ReceiptLog, type LogCheck, type Receipt, type VerifyOptions } from './receipts.js';
import { MemoryStore, type KeyValueStore } from './store.js';

export interface ActionPolicy {
  /** Require a delegation chain to a trusted root, even from a pinned peer. */
  requireDelegation?: boolean;
  /** Hold the request until this many listed approvers have approved it. */
  quorum?: QuorumPolicy;
}

export interface RelayPolicy {
  /** Accept actions with no matching entry in `actions`. Default true. */
  allowUnlistedActions?: boolean;
  /** Keys are exact action names, `prefix.*` patterns, or `*`. The most specific match wins. */
  actions?: Record<string, ActionPolicy>;
}

export type RequestStatus = 'accepted' | 'pending_approval' | 'rejected' | 'expired';

export interface InboxItem {
  id: string;
  digest: string;
  status: RequestStatus;
  reason?: string;
  receivedAt: string;
  envelope: Envelope;
  approvals: Approval[];
  quorum?: { threshold: number; approvers: string[] };
}

export interface ReceiveResult {
  status: RequestStatus;
  id?: string;
  digest?: string;
  reason?: string;
  approvals?: { have: number; need: number };
}

export interface RequestSummary {
  id: string;
  digest: string;
  from: string;
  to: string;
  action: string;
  action_hash: string;
  exp: string;
  status: RequestStatus;
  approvals: { have: number; need: number; approvers: string[] } | null;
}

export interface RelayStores {
  nonces?: KeyValueStore;
  grants?: KeyValueStore;
  spend?: KeyValueStore;
  held?: KeyValueStore;
}

export interface RelayOptions {
  identity: Identity;
  affixio: AffixioClient;
  /** Agents in other organisations that may send requests directly (key pinned). */
  peers?: AgentRef[];
  /** Human or organisation root keys that may start delegation chains. */
  trustedRoots?: AgentRef[];
  policy?: RelayPolicy;
  stores?: RelayStores;
  receipts?: ReceiptLog;
  /** Longest lifetime accepted for an incoming envelope. Default 900 seconds. */
  maxTtlSeconds?: number;
  clockSkewSeconds?: number;
  maxInboxItems?: number;
  now?: () => number;
  /**
   * The sender's own policy. Returns the yes/no fields sent to AffixIO when this agent asks for a proof.
   * Replace the default with real checks: a "no" decision stops the request from being sent.
   */
  authorise?: (kind: 'request' | 'delegate' | 'approve', detail: Record<string, unknown>) => Record<string, boolean> | Promise<Record<string, boolean>>;
}

export class RelayError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
    this.name = 'RelayError';
  }
}

function policyFor(policy: RelayPolicy, action: string): ActionPolicy | undefined {
  const entries = Object.entries(policy.actions ?? {});
  const exact = entries.find(([k]) => k === action);
  if (exact) return exact[1];
  const prefixes = entries
    .filter(([k]) => k !== '*' && k.endsWith('.*') && actionMatches(k, action))
    .sort((a, b) => b[0].length - a[0].length);
  if (prefixes[0]) return prefixes[0][1];
  return entries.find(([k]) => k === '*')?.[1];
}

/**
 * One agent's end of the relay: it sends proof-carrying requests and decides whether incoming ones may be acted on.
 * Nothing is trusted by default: a request is accepted only if every check passes, including a single-use
 * AffixIO verification.
 */
export class Relay {
  readonly identity: Identity;
  readonly affixio: AffixioClient;
  readonly receipts: ReceiptLog;
  readonly policy: RelayPolicy;
  readonly peers: AgentRef[];
  readonly trustedRoots: AgentRef[];
  readonly #nonces: KeyValueStore;
  readonly #grants: KeyValueStore;
  readonly #spend: KeyValueStore;
  readonly #held: KeyValueStore;
  readonly #inbox = new Map<string, InboxItem>();
  readonly #maxTtlMs: number;
  readonly #skewMs: number;
  readonly #maxInbox: number;
  readonly #now: () => number;
  readonly #authorise: NonNullable<RelayOptions['authorise']>;
  readonly #approvalsInFlight = new Set<string>();

  constructor(opts: RelayOptions) {
    this.identity = opts.identity;
    this.affixio = opts.affixio;
    this.receipts = opts.receipts ?? new ReceiptLog();
    this.policy = opts.policy ?? {};
    this.peers = opts.peers ?? [];
    this.trustedRoots = opts.trustedRoots ?? [];
    this.#nonces = opts.stores?.nonces ?? new MemoryStore();
    this.#grants = opts.stores?.grants ?? new MemoryStore();
    this.#spend = opts.stores?.spend ?? new MemoryStore();
    this.#held = opts.stores?.held ?? new MemoryStore();
    this.#maxTtlMs = (opts.maxTtlSeconds ?? 900) * 1000;
    this.#skewMs = (opts.clockSkewSeconds ?? 60) * 1000;
    this.#maxInbox = opts.maxInboxItems ?? 1000;
    this.#now = opts.now ?? Date.now;
    this.#authorise = opts.authorise ?? (() => ({ ...DEFAULT_YESNO_FIELDS }));
    for (const [action, p] of Object.entries(this.policy.actions ?? {})) {
      if (p.quorum && !validQuorumPolicy(p.quorum)) throw new Error(`invalid quorum policy for ${action}`);
    }
  }

  get ref(): AgentRef {
    return { id: this.identity.id, key: this.identity.keys.publicKey };
  }

  async #proof(kind: 'request' | 'delegate' | 'approve', detail: Record<string, unknown>): Promise<ProofRef> {
    const fields = await this.#authorise(kind, detail);
    const p = await this.affixio.prove(fields);
    if (p.decision !== 'yes') throw new RelayError(`own policy declined this ${kind}`, 'policy_declined');
    return { provider: p.provider, circuit: p.circuit, id: p.id, digest: p.digest };
  }

  // ---------------------------------------------------------------- sending side

  /** Build and sign a request carrying a fresh AffixIO proof. */
  async createRequest(input: { to: string; action: string; params?: Params; ttlSeconds?: number; delegation?: Grant[] }): Promise<Envelope> {
    const params = input.params ?? {};
    if (input.delegation) {
      const leaf = input.delegation[input.delegation.length - 1];
      if (!leaf || leaf.subject.key !== this.identity.keys.publicKey) throw new RelayError('this agent is not the subject of the grant', 'not_grant_subject');
      const err = scopeError(input.delegation, input.action, params);
      if (err) throw new RelayError(`request falls outside the delegated scope (${err})`, err);
    }
    const proof = await this.#proof('request', { to: input.to, action: input.action, action_hash: actionHash(input.action, params) });
    const env = createEnvelope({
      from: this.identity,
      to: input.to,
      action: input.action,
      params,
      proof,
      delegation: input.delegation,
      ttlSeconds: input.ttlSeconds,
      now: this.#now(),
    });
    this.receipts.append('request.sent', { id: env.id, digest: requestDigest(env), to: env.to, action: env.action, action_hash: env.action_hash, proof_digest: proof.digest });
    return env;
  }

  /** Issue a delegation grant to another agent. Without `parentChain` this identity acts as the root. */
  async delegate(input: { subject: AgentRef; audience: string; scope: Scope; ttlSeconds?: number; parentChain?: Grant[] }): Promise<Grant[]> {
    const proof = await this.#proof('delegate', { subject: input.subject.id, audience: input.audience, scope: input.scope });
    const chain = issueGrant({ issuer: this.identity, ...input, proof, now: this.#now() });
    const leaf = chain[chain.length - 1] as Grant;
    this.receipts.append('grant.issued', { id: leaf.id, digest: grantDigest(leaf), subject: leaf.subject.id, audience: leaf.audience, scope: leaf.scope as unknown as Record<string, unknown>, exp: leaf.exp });
    return chain;
  }

  /** Store a chain delegated to this agent so it can be attached to later requests. */
  importGrant(chain: unknown): Grant[] {
    const res = checkChain(chain, { now: this.#now(), clockSkewMs: this.#skewMs });
    if (!res.ok) throw new RelayError(`grant rejected (${res.reason})`, res.reason);
    if (res.leaf.subject.id !== this.identity.id || res.leaf.subject.key !== this.identity.keys.publicKey) {
      throw new RelayError('grant is not addressed to this agent', 'not_grant_subject');
    }
    this.#held.set(res.leaf.id, chain);
    return chain as Grant[];
  }

  heldGrant(id: string): Grant[] | undefined {
    return this.#held.get(id) as Grant[] | undefined;
  }

  heldGrants(): { id: string; audience: string; scope: Scope; exp: string }[] {
    return this.#held.keys().map((k) => {
      const chain = this.#held.get(k) as Grant[];
      const leaf = chain[chain.length - 1] as Grant;
      return { id: leaf.id, audience: leaf.audience, scope: leaf.scope, exp: leaf.exp };
    });
  }

  /** Approve a request held by another agent's inbox, identified by its id and digest. */
  async approve(input: { requestId: string; requestDigest: string; action?: string }): Promise<Approval> {
    const proof = await this.#proof('approve', { request_id: input.requestId, request: input.requestDigest, action: input.action });
    const a = createApproval({ approver: this.identity, requestId: input.requestId, requestDigest: input.requestDigest, proof, now: this.#now() });
    this.receipts.append('approval.issued', { request_id: a.request_id, request: a.request, proof_digest: proof.digest });
    return a;
  }

  // ---------------------------------------------------------------- receiving side

  #reject(id: string | undefined, digestValue: string | undefined, reason: string, env?: Envelope): ReceiveResult {
    this.receipts.append('request.rejected', { id: id ?? null, digest: digestValue ?? null, from: env?.from.id ?? null, action: env?.action ?? null, reason });
    return { status: 'rejected', id, digest: digestValue, reason };
  }

  #store(item: InboxItem): void {
    this.#inbox.set(item.id, item);
    while (this.#inbox.size > this.#maxInbox) {
      const oldest = this.#inbox.keys().next().value;
      if (oldest === undefined) break;
      this.#inbox.delete(oldest);
    }
  }

  #pruneNonces(now: number): void {
    for (const k of this.#nonces.keys()) {
      const exp = this.#nonces.get(k);
      if (typeof exp === 'number' && exp + this.#skewMs < now) this.#nonces.delete(k);
    }
  }

  /**
   * Verify an incoming request and record the outcome. Checks run cheapest first; the AffixIO proof is consumed
   * only once every local check has passed.
   */
  async receive(input: unknown): Promise<ReceiveResult> {
    const now = this.#now();
    const shape = envelopeShapeError(input);
    if (shape) return this.#reject(undefined, undefined, shape);
    const env = input as Envelope;
    const dg = requestDigest(env);
    if (env.to !== this.identity.id) return this.#reject(env.id, dg, 'wrong_recipient', env);
    const iat = Date.parse(env.iat);
    const exp = Date.parse(env.exp);
    if (iat > now + this.#skewMs) return this.#reject(env.id, dg, 'issued_in_future', env);
    if (exp <= now) return this.#reject(env.id, dg, 'expired', env);
    if (exp <= iat || exp - iat > this.#maxTtlMs) return this.#reject(env.id, dg, 'lifetime_too_long', env);
    if (actionHash(env.action, env.params) !== env.action_hash) return this.#reject(env.id, dg, 'action_hash_mismatch', env);
    if (!verifyEnvelopeSignature(env)) return this.#reject(env.id, dg, 'bad_signature', env);

    const actionPolicy = policyFor(this.policy, env.action);
    if (!actionPolicy && this.policy.allowUnlistedActions === false) return this.#reject(env.id, dg, 'action_not_allowed', env);

    let chain: Grant[] | undefined;
    if (env.delegation) {
      const res = checkChain(env.delegation, { trustedRoots: this.trustedRoots, audience: this.identity.id, now, clockSkewMs: this.#skewMs });
      if (!res.ok) return this.#reject(env.id, dg, res.reason, env);
      if (res.leaf.subject.id !== env.from.id || res.leaf.subject.key !== env.from.key) return this.#reject(env.id, dg, 'delegation_subject_mismatch', env);
      chain = env.delegation;
      const scopeErr = scopeError(chain, env.action, env.params);
      if (scopeErr) return this.#reject(env.id, dg, scopeErr, env);
      for (const g of chain) {
        if (g.scope.max_total === undefined) continue;
        const spent = Number(this.#spend.get(grantDigest(g)) ?? 0);
        if (spent + (env.params.amount as number) > g.scope.max_total) return this.#reject(env.id, dg, 'scope_total_exceeded', env);
      }
    } else {
      if (actionPolicy?.requireDelegation) return this.#reject(env.id, dg, 'delegation_required', env);
      const peer = this.peers.find((p) => p.id === env.from.id);
      if (!peer || peer.key !== env.from.key) return this.#reject(env.id, dg, 'unknown_sender', env);
    }

    // Replay protection, recorded before any await so concurrent duplicates are caught.
    this.#pruneNonces(now);
    const nonceKey = `n:${env.from.id}:${env.nonce}`;
    const idKey = `id:${env.id}`;
    if (this.#nonces.get(nonceKey) !== undefined || this.#nonces.get(idKey) !== undefined || this.#inbox.has(env.id)) {
      return this.#reject(env.id, dg, 'replay', env);
    }
    this.#nonces.set(nonceKey, exp);
    this.#nonces.set(idKey, exp);

    // Grant proofs are verified once per audience and remembered, because AffixIO proofs are single use.
    if (chain) {
      for (const g of chain) {
        const gd = grantDigest(g);
        if (this.#grants.get(gd) !== undefined) continue;
        const v = await this.#verifyProof(g.proof);
        if (v) return this.#reject(env.id, dg, `delegation_${v}`, env);
        this.#grants.set(gd, { verified_at: new Date(now).toISOString(), proof_digest: g.proof.digest });
      }
    }

    const pv = await this.#verifyProof(env.proof);
    if (pv) return this.#reject(env.id, dg, pv, env);

    if (chain) {
      for (const g of chain) {
        if (g.scope.max_total === undefined) continue;
        const key = grantDigest(g);
        const spent = Number(this.#spend.get(key) ?? 0);
        const next = spent + (env.params.amount as number);
        if (next > g.scope.max_total) return this.#reject(env.id, dg, 'scope_total_exceeded', env);
        this.#spend.set(key, next);
      }
    }

    const item: InboxItem = {
      id: env.id,
      digest: dg,
      status: 'accepted',
      receivedAt: new Date(now).toISOString(),
      envelope: { ...env, approvals: undefined },
      approvals: [],
    };
    if (actionPolicy?.quorum) {
      item.status = 'pending_approval';
      item.quorum = { threshold: actionPolicy.quorum.threshold, approvers: actionPolicy.quorum.approvers.map((a) => a.id) };
    }
    this.#store(item);
    this.receipts.append('request.verified', {
      id: env.id,
      digest: dg,
      from: env.from.id,
      action: env.action,
      action_hash: env.action_hash,
      proof_digest: env.proof.digest,
      delegation: chain ? chain.map((g) => grantDigest(g)) : null,
    });

    if (actionPolicy?.quorum) {
      for (const a of env.approvals ?? []) {
        await this.addApproval(env.id, a);
      }
      if (item.status === 'pending_approval') {
        return { status: item.status, id: env.id, digest: dg, approvals: { have: item.approvals.length, need: actionPolicy.quorum.threshold } };
      }
    } else {
      this.receipts.append('request.accepted', { id: env.id, digest: dg });
    }
    return {
      status: item.status,
      id: env.id,
      digest: dg,
      ...(item.quorum ? { approvals: { have: item.approvals.length, need: item.quorum.threshold } } : {}),
    };
  }

  /** Returns a reason code when the proof is not accepted, or null when AffixIO confirms a valid "yes". */
  async #verifyProof(ref: ProofRef): Promise<string | null> {
    let res;
    try {
      res = await this.affixio.verify(ref);
    } catch {
      return 'proof_unverifiable';
    }
    if (res.code === 'double_spend_detected') return 'proof_already_used';
    if (!res.valid) return 'proof_invalid';
    if (res.decision !== 'yes') return 'proof_decision_no';
    if (res.digest !== undefined && res.digest !== ref.digest) return 'proof_digest_mismatch';
    return null;
  }

  /** Add one approval to a request waiting for quorum. */
  async addApproval(requestId: string, approval: unknown): Promise<ReceiveResult> {
    const item = this.#inbox.get(requestId);
    if (!item) return { status: 'rejected', id: requestId, reason: 'unknown_request' };
    const policy = policyFor(this.policy, item.envelope.action)?.quorum;
    if (!policy || !item.quorum) return { status: item.status, id: item.id, reason: 'no_quorum_required' };
    const counts = () => ({ have: item.approvals.length, need: policy.threshold });
    if (item.status !== 'pending_approval') return { status: item.status, id: item.id, digest: item.digest, approvals: counts() };
    if (Date.parse(item.envelope.exp) <= this.#now()) {
      item.status = 'expired';
      this.receipts.append('request.expired', { id: item.id, digest: item.digest });
      return { status: 'expired', id: item.id, digest: item.digest, approvals: counts() };
    }
    const err = approvalError(approval, policy, item.id, item.digest);
    if (err) {
      this.receipts.append('approval.rejected', { request_id: item.id, reason: err });
      return { status: item.status, id: item.id, digest: item.digest, reason: err, approvals: counts() };
    }
    const a = approval as Approval;
    const slot = `${item.id}:${a.approver.id}`;
    if (item.approvals.some((x) => x.approver.id === a.approver.id) || this.#approvalsInFlight.has(slot)) {
      return { status: item.status, id: item.id, digest: item.digest, reason: 'approval_duplicate', approvals: counts() };
    }
    this.#approvalsInFlight.add(slot);
    try {
      const pv = await this.#verifyProof(a.proof);
      if (pv) {
        this.receipts.append('approval.rejected', { request_id: item.id, approver: a.approver.id, reason: `approval_${pv}` });
        return { status: item.status, id: item.id, digest: item.digest, reason: `approval_${pv}`, approvals: counts() };
      }
      if (item.status !== 'pending_approval') return { status: item.status, id: item.id, digest: item.digest, approvals: counts() };
      item.approvals.push(a);
      this.receipts.append('approval.verified', { request_id: item.id, approver: a.approver.id, proof_digest: a.proof.digest });
      if (item.approvals.length >= policy.threshold) {
        item.status = 'accepted';
        this.receipts.append('request.accepted', { id: item.id, digest: item.digest, approvers: item.approvals.map((x) => x.approver.id) });
      }
      return { status: item.status, id: item.id, digest: item.digest, approvals: counts() };
    } finally {
      this.#approvalsInFlight.delete(slot);
    }
  }

  inbox(status?: RequestStatus): InboxItem[] {
    const now = this.#now();
    const items = [...this.#inbox.values()];
    for (const item of items) {
      if (item.status === 'pending_approval' && Date.parse(item.envelope.exp) <= now) {
        item.status = 'expired';
        this.receipts.append('request.expired', { id: item.id, digest: item.digest });
      }
    }
    return status ? items.filter((i) => i.status === status) : items;
  }

  /** Public view of a request for approvers: no params, only their hash. */
  summary(id: string): RequestSummary | undefined {
    this.inbox();
    const item = this.#inbox.get(id);
    if (!item) return undefined;
    const env = item.envelope;
    return {
      id: item.id,
      digest: item.digest,
      from: env.from.id,
      to: env.to,
      action: env.action,
      action_hash: env.action_hash,
      exp: env.exp,
      status: item.status,
      approvals: item.quorum
        ? { have: item.approvals.length, need: item.quorum.threshold, approvers: item.quorum.approvers }
        : null,
    };
  }

  verifyReceipts(opts: VerifyOptions = {}): LogCheck {
    return this.receipts.verify(opts);
  }

  /**
   * Record a checkpoint that pairs the local log head with the current AffixIO Merkle root. Every verified
   * proof digest in the log can later be looked up in that tree with `inclusion()`.
   */
  async anchor(): Promise<Receipt> {
    const check = this.receipts.verify();
    if (!check.ok) throw new RelayError('receipt log failed verification; not anchoring', 'receipts_tampered');
    const root = await this.affixio.merkleRoot();
    return this.receipts.append('anchor', { log_head: check.head, log_count: check.count, affixio_merkle_root: root.root, affixio_leaf_count: root.leafCount, affixio_updated_at: root.updatedAt ?? null });
  }

  /** Fetch the AffixIO Merkle inclusion proof for a proof digest recorded in the log. */
  async inclusion(proofDigest: string): Promise<Record<string, unknown>> {
    return this.affixio.merkleProof(proofDigest);
  }
}
