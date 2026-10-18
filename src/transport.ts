import type { Envelope } from './envelope.js';
import type { Approval } from './quorum.js';
import type { ReceiveResult, RequestSummary } from './relay.js';

export interface HttpTransportOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

/** Client for another agent's HTTP inbox. */
export class HttpTransport {
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(opts: HttpTransportOptions = {}) {
    this.#fetch = opts.fetch ?? fetch;
    this.#timeoutMs = opts.timeoutMs ?? 30_000;
  }

  async #json<T>(url: string, init: RequestInit): Promise<{ status: number; body: T }> {
    const res = await this.#fetch(url, { ...init, signal: AbortSignal.timeout(this.#timeoutMs) });
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      body = { error: 'invalid_response' };
    }
    return { status: res.status, body: body as T };
  }

  #base(inboxUrl: string): string {
    const u = new URL(inboxUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('inbox URL must be http or https');
    return u.origin + u.pathname.replace(/\/+$/, '');
  }

  async identity(inboxUrl: string): Promise<{ agent: string; key: string }> {
    const r = await this.#json<{ agent: string; key: string }>(`${this.#base(inboxUrl)}/.well-known/agent-relay`, { method: 'GET' });
    if (r.status !== 200) throw new Error(`identity lookup failed with HTTP ${r.status}`);
    return r.body;
  }

  async send(inboxUrl: string, envelope: Envelope): Promise<ReceiveResult> {
    const r = await this.#json<ReceiveResult>(`${this.#base(inboxUrl)}/v1/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    return r.body;
  }

  async summary(inboxUrl: string, requestId: string): Promise<RequestSummary> {
    const r = await this.#json<RequestSummary>(`${this.#base(inboxUrl)}/v1/requests/${encodeURIComponent(requestId)}`, { method: 'GET' });
    if (r.status !== 200) throw new Error(`request lookup failed with HTTP ${r.status}`);
    return r.body;
  }

  async approve(inboxUrl: string, requestId: string, approval: Approval): Promise<ReceiveResult> {
    const r = await this.#json<ReceiveResult>(`${this.#base(inboxUrl)}/v1/requests/${encodeURIComponent(requestId)}/approvals`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(approval),
    });
    return r.body;
  }
}
