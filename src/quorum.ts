import { canonicalize } from './canonical.js';
import { signBytes, verifyBytes } from './keys.js';
import type { ProofRef } from './affixio.js';
import { isAgentRef, isIsoDate, isProofRef, type AgentRef, type Identity } from './envelope.js';

export const APPROVAL_VERSION = 'agent-relay-approval/1';

export interface QuorumPolicy {
  threshold: number;
  approvers: AgentRef[];
}

export interface Approval {
  v: typeof APPROVAL_VERSION;
  request_id: string;
  /** requestDigest() of the envelope being approved. */
  request: string;
  approver: AgentRef;
  decision: 'approve';
  iat: string;
  proof: ProofRef;
  sig: string;
}

function signingInput(a: Approval): string {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sig, ...rest } = a;
  return `${APPROVAL_VERSION}\n${canonicalize(rest)}`;
}

export function createApproval(input: {
  approver: Identity;
  requestId: string;
  requestDigest: string;
  proof: ProofRef;
  now?: number;
}): Approval {
  const a: Approval = {
    v: APPROVAL_VERSION,
    request_id: input.requestId,
    request: input.requestDigest,
    approver: { id: input.approver.id, key: input.approver.keys.publicKey },
    decision: 'approve',
    iat: new Date(input.now ?? Date.now()).toISOString(),
    proof: input.proof,
    sig: '',
  };
  a.sig = signBytes(input.approver.keys, signingInput(a));
  return a;
}

export function validQuorumPolicy(p: unknown): p is QuorumPolicy {
  if (typeof p !== 'object' || p === null) return false;
  const q = p as Record<string, unknown>;
  if (!Array.isArray(q.approvers) || !q.approvers.every(isAgentRef)) return false;
  const ids = new Set((q.approvers as AgentRef[]).map((a) => a.id));
  if (ids.size !== q.approvers.length) return false;
  return typeof q.threshold === 'number' && Number.isInteger(q.threshold) && q.threshold >= 1 && q.threshold <= q.approvers.length;
}

/** Offline checks for one approval against a policy and request digest. Returns a reason code or null. */
export function approvalError(a: unknown, policy: QuorumPolicy, requestId: string, digestValue: string): string | null {
  if (typeof a !== 'object' || a === null) return 'approval_malformed';
  const x = a as Record<string, unknown>;
  if (
    x.v !== APPROVAL_VERSION ||
    typeof x.request_id !== 'string' ||
    typeof x.request !== 'string' ||
    !isAgentRef(x.approver) ||
    x.decision !== 'approve' ||
    !isIsoDate(x.iat) ||
    !isProofRef(x.proof) ||
    typeof x.sig !== 'string'
  ) {
    return 'approval_malformed';
  }
  const approval = x as unknown as Approval;
  if (approval.request_id !== requestId || approval.request !== digestValue) return 'approval_wrong_request';
  const listed = policy.approvers.find((p) => p.id === approval.approver.id);
  if (!listed || listed.key !== approval.approver.key) return 'approval_unknown_approver';
  if (!verifyBytes(approval.approver.key, signingInput(approval), approval.sig)) return 'approval_bad_signature';
  return null;
}
