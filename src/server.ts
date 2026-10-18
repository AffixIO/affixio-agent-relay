import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import type { Relay, ReceiveResult } from './relay.js';
import { ENVELOPE_VERSION } from './envelope.js';

export interface InboxServerOptions {
  /** Bearer token for GET /v1/inbox. When unset, the full inbox is not served over HTTP. */
  inboxToken?: string;
  maxBodyBytes?: number;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(text);
}

async function readJson(req: IncomingMessage, limit: number): Promise<unknown> {
  const type = req.headers['content-type'] ?? '';
  if (!type.toLowerCase().startsWith('application/json')) throw new HttpError(415, 'unsupported_media_type');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > limit) throw new HttpError(413, 'body_too_large');
    chunks.push(buf);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new HttpError(400, 'invalid_json');
  }
}

function statusCode(r: ReceiveResult): number {
  if (r.status === 'accepted') return 200;
  if (r.status === 'pending_approval') return r.reason ? 422 : 202;
  if (r.status === 'expired') return 410;
  if (r.reason === 'unknown_request') return 404;
  if (r.reason === 'malformed' || r.reason === 'unsupported_version') return 400;
  return 403;
}

function tokenMatches(header: string | undefined, token: string): boolean {
  if (!header?.startsWith('Bearer ')) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

const REQUEST_PATH = /^\/v1\/requests\/([0-9a-f-]{36})(\/approvals)?$/;

/**
 * HTTP inbox for one agent.
 *   GET  /.well-known/agent-relay        identity (id and public key)
 *   POST /v1/requests                    deliver an envelope
 *   GET  /v1/requests/:id                public summary for approvers (no params)
 *   POST /v1/requests/:id/approvals      deliver a quorum approval
 *   GET  /v1/inbox                       full inbox, bearer token required
 */
export function createInboxServer(relay: Relay, opts: InboxServerOptions = {}): Server {
  const limit = opts.maxBodyBytes ?? 64 * 1024;
  return createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://localhost');
        const path = url.pathname;
        if (req.method === 'GET' && path === '/.well-known/agent-relay') {
          return send(res, 200, { v: ENVELOPE_VERSION, agent: relay.identity.id, key: relay.identity.keys.publicKey });
        }
        if (req.method === 'POST' && path === '/v1/requests') {
          const body = await readJson(req, limit);
          const r = await relay.receive(body);
          return send(res, statusCode(r), r);
        }
        if (req.method === 'GET' && path === '/v1/inbox') {
          if (!opts.inboxToken) throw new HttpError(404, 'not_found');
          if (!tokenMatches(req.headers.authorization, opts.inboxToken)) throw new HttpError(401, 'unauthorised');
          const status = url.searchParams.get('status') ?? undefined;
          const items = relay.inbox(status as Parameters<Relay['inbox']>[0]);
          return send(res, 200, { items });
        }
        const m = REQUEST_PATH.exec(path);
        if (m?.[1]) {
          if (req.method === 'GET' && !m[2]) {
            const s = relay.summary(m[1]);
            if (!s) throw new HttpError(404, 'unknown_request');
            return send(res, 200, s);
          }
          if (req.method === 'POST' && m[2]) {
            const body = await readJson(req, limit);
            const r = await relay.addApproval(m[1], body);
            return send(res, statusCode(r), r);
          }
        }
        throw new HttpError(404, 'not_found');
      } catch (err) {
        if (err instanceof HttpError) return send(res, err.status, { error: err.code });
        return send(res, 500, { error: 'internal_error' });
      }
    })();
  });
}
