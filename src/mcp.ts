import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { isPublicKey } from './keys.js';
import { AGENT_ID } from './envelope.js';
import type { Relay, RequestStatus } from './relay.js';
import { HttpTransport } from './transport.js';
import type { Scope } from './delegation.js';

export interface McpOptions {
  transport?: HttpTransport;
  /** Public URL of this agent's own inbox, reported by whoami. */
  inboxUrl?: string;
  version?: string;
}

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

function ok(value: unknown): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function fail(err: unknown): ToolResult {
  const message = err instanceof Error ? err.message : String(err);
  return { content: [{ type: 'text', text: JSON.stringify({ error: message }) }], isError: true };
}

async function guard(fn: () => Promise<unknown> | unknown): Promise<ToolResult> {
  try {
    return ok(await fn());
  } catch (err) {
    return fail(err);
  }
}

const agentId = z.string().regex(AGENT_ID, 'invalid agent id');
const publicKey = z.string().refine(isPublicKey, 'expected a base64url Ed25519 public key');

/**
 * MCP server exposing the relay as tools. Trust settings (pinned peers, roots, policy) are deliberately not
 * editable through MCP, so a prompt cannot widen what this agent accepts.
 */
export function createMcpServer(relay: Relay, opts: McpOptions = {}): McpServer {
  const transport = opts.transport ?? new HttpTransport();
  const server = new McpServer({ name: 'affixio-agent-relay', version: opts.version ?? '0.1.0' });

  server.registerTool(
    'whoami',
    { description: 'Show this agent id, its public key and inbox URL, and the grants it holds.', inputSchema: {} },
    async () => guard(() => ({ agent: relay.identity.id, key: relay.identity.keys.publicKey, inbox_url: opts.inboxUrl ?? null, grants: relay.heldGrants() })),
  );

  server.registerTool(
    'send_request',
    {
      description:
        'Send a proof-carrying request to another agent inbox. A fresh single-use AffixIO proof is attached and the envelope is signed over the exact action and params.',
      inputSchema: {
        inbox_url: z.string().url(),
        to: agentId.optional().describe('Recipient agent id. Looked up from the inbox when omitted.'),
        action: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,99}$/),
        params: z.record(z.string(), z.unknown()).optional(),
        ttl_seconds: z.number().int().min(1).max(3600).optional(),
        grant_id: z.string().max(64).optional().describe('Attach a delegation chain this agent holds.'),
      },
    },
    async (args) =>
      guard(async () => {
        const to = args.to ?? (await transport.identity(args.inbox_url)).agent;
        let delegation;
        if (args.grant_id) {
          delegation = relay.heldGrant(args.grant_id);
          if (!delegation) throw new Error(`no held grant with id ${args.grant_id}`);
        }
        const env = await relay.createRequest({ to, action: args.action, params: args.params ?? {}, ttlSeconds: args.ttl_seconds, delegation });
        const result = await transport.send(args.inbox_url, env);
        return { request_id: env.id, sent_to: to, result };
      }),
  );

  server.registerTool(
    'check_inbox',
    {
      description: 'List requests received by this agent, with their verification status. Only act on status "accepted".',
      inputSchema: { status: z.enum(['accepted', 'pending_approval', 'rejected', 'expired']).optional() },
    },
    async (args) =>
      guard(() =>
        relay.inbox(args.status as RequestStatus | undefined).map((i) => ({
          id: i.id,
          status: i.status,
          from: i.envelope.from.id,
          action: i.envelope.action,
          params: i.envelope.params,
          received_at: i.receivedAt,
          approvals: i.quorum ? { have: i.approvals.length, need: i.quorum.threshold } : null,
        })),
      ),
  );

  server.registerTool(
    'verify_request',
    {
      description: 'Verify an envelope received by some other route (for example a queue or email). Consumes its AffixIO proof and records a receipt.',
      inputSchema: { envelope: z.record(z.string(), z.unknown()) },
    },
    async (args) => guard(() => relay.receive(args.envelope)),
  );

  server.registerTool(
    'approve',
    {
      description: 'Approve a request that is waiting for quorum in another agent inbox. Signs the request digest and attaches a fresh AffixIO proof.',
      inputSchema: {
        inbox_url: z.string().url(),
        request_id: z.string().uuid(),
        expect_action: z.string().optional().describe('Refuse to approve unless the request has this action.'),
      },
    },
    async (args) =>
      guard(async () => {
        const s = await transport.summary(args.inbox_url, args.request_id);
        if (s.id !== args.request_id) throw new Error('inbox returned a different request');
        if (s.status !== 'pending_approval') throw new Error(`request is ${s.status}, not pending approval`);
        if (args.expect_action && s.action !== args.expect_action) throw new Error(`request action is ${s.action}, expected ${args.expect_action}`);
        if (s.approvals && !s.approvals.approvers.includes(relay.identity.id)) throw new Error('this agent is not a listed approver');
        const approval = await relay.approve({ requestId: s.id, requestDigest: s.digest, action: s.action });
        return { request: s, result: await transport.approve(args.inbox_url, s.id, approval) };
      }),
  );

  server.registerTool(
    'delegate',
    {
      description:
        'Delegate a narrower slice of authority to another agent for one audience. Without parent_grant_id this agent acts as the root. Returns the chain to hand to the subject.',
      inputSchema: {
        subject_id: agentId,
        subject_key: publicKey,
        audience: agentId.describe('The agent the subject may present this grant to.'),
        actions: z.array(z.string()).min(1).max(50),
        max_amount: z.number().nonnegative().optional(),
        max_total: z.number().nonnegative().optional(),
        currency: z.string().regex(/^[A-Z]{3}$/).optional(),
        ttl_seconds: z.number().int().min(60).max(7 * 24 * 3600).optional(),
        parent_grant_id: z.string().max(64).optional(),
      },
    },
    async (args) =>
      guard(async () => {
        let parentChain;
        if (args.parent_grant_id) {
          parentChain = relay.heldGrant(args.parent_grant_id);
          if (!parentChain) throw new Error(`no held grant with id ${args.parent_grant_id}`);
        }
        const scope: Scope = { actions: args.actions };
        if (args.max_amount !== undefined) scope.max_amount = args.max_amount;
        if (args.max_total !== undefined) scope.max_total = args.max_total;
        if (args.currency !== undefined) scope.currency = args.currency;
        const chain = await relay.delegate({ subject: { id: args.subject_id, key: args.subject_key }, audience: args.audience, scope, ttlSeconds: args.ttl_seconds, parentChain });
        return { grant_id: chain[chain.length - 1]?.id, chain };
      }),
  );

  server.registerTool(
    'import_grant',
    {
      description: 'Store a delegation chain issued to this agent so send_request can attach it with grant_id.',
      inputSchema: { chain: z.array(z.record(z.string(), z.unknown())).min(1) },
    },
    async (args) =>
      guard(() => {
        const chain = relay.importGrant(args.chain);
        const leaf = chain[chain.length - 1];
        return { grant_id: leaf?.id, audience: leaf?.audience, scope: leaf?.scope, exp: leaf?.exp };
      }),
  );

  server.registerTool(
    'receipts',
    {
      description: 'Check the hash-chained receipt log and show the latest entries. With anchor=true, record a checkpoint against the AffixIO Merkle root.',
      inputSchema: { limit: z.number().int().min(1).max(200).optional(), anchor: z.boolean().optional() },
    },
    async (args) =>
      guard(async () => {
        const anchored = args.anchor ? await relay.anchor() : undefined;
        const check = relay.verifyReceipts();
        const entries = relay.receipts.entries();
        return { check, anchored: anchored ?? null, latest: entries.slice(-(args.limit ?? 20)) };
      }),
  );

  return server;
}
