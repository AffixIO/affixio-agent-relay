import { randomBytes, randomUUID } from 'node:crypto';

/** Reference to an AffixIO proof, carried inside envelopes, grants and approvals. */
export interface ProofRef {
  provider: 'affixio';
  circuit: string;
  id: string;
  digest: string;
}

export interface ProveResult extends ProofRef {
  decision: string;
}

export interface VerifyResult {
  valid: boolean;
  decision?: string;
  digest?: string;
  /** Error code when the proof was not accepted, e.g. `double_spend_detected` or `invalid_proof`. */
  code?: string;
}

export interface MerkleRoot {
  root: string;
  leafCount: number;
  updatedAt?: string;
}

/** The subset of the AffixIO REST API this package uses. Swap in a mock for tests or offline work. */
export interface AffixioClient {
  prove(fields?: Record<string, boolean>, circuit?: string): Promise<ProveResult>;
  verify(ref: ProofRef): Promise<VerifyResult>;
  merkleRoot(): Promise<MerkleRoot>;
  merkleProof(digest: string): Promise<Record<string, unknown>>;
}

export class AffixioError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = 'AffixioError';
  }
}

/** Default yes/no fields. Replace with the outcome of your own policy checks. */
export const DEFAULT_YESNO_FIELDS: Readonly<Record<string, boolean>> = Object.freeze({
  condition_greater1: true,
  condition_greater2: true,
  condition_greater3: true,
});

export interface HttpAffixioOptions {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

const SAFE_ID = /^[A-Za-z0-9_.:-]{1,200}$/;

/** Calls the public AffixIO REST API with `fetch`. The API key is sent only in the X-API-Key header. */
export class HttpAffixioClient implements AffixioClient {
  readonly #apiKey: string;
  readonly #baseUrl: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(options: HttpAffixioOptions) {
    if (!options.apiKey) throw new Error('an AffixIO API key is required');
    this.#apiKey = options.apiKey;
    this.#baseUrl = (options.baseUrl ?? 'https://api.affix-io.com').replace(/\/+$/, '');
    this.#timeoutMs = options.timeoutMs ?? 20_000;
    this.#fetch = options.fetch ?? fetch;
  }

  async #call(method: 'GET' | 'POST', path: string, body?: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
    const res = await this.#fetch(`${this.#baseUrl}${path}`, {
      method,
      headers: {
        'X-API-Key': this.#apiKey,
        accept: 'application/json',
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    let json: Record<string, unknown> = {};
    try {
      const parsed: unknown = await res.json();
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) json = parsed as Record<string, unknown>;
    } catch {
      json = {};
    }
    return { status: res.status, json };
  }

  async prove(fields: Record<string, boolean> = { ...DEFAULT_YESNO_FIELDS }, circuit = 'yesno'): Promise<ProveResult> {
    if (!SAFE_ID.test(circuit)) throw new Error('invalid circuit id');
    const { status, json } = await this.#call('POST', `/v1/circuits/${circuit}/prove`, { fields });
    if (status !== 200 || typeof json.proof_id !== 'string' || typeof json.proof_digest !== 'string') {
      const code = typeof json.error === 'string' ? json.error : undefined;
      throw new AffixioError(`AffixIO prove failed with HTTP ${status}${code ? ` (${code})` : ''}`, status, code);
    }
    return {
      provider: 'affixio',
      circuit,
      id: json.proof_id,
      digest: json.proof_digest,
      decision: typeof json.decision === 'string' ? json.decision : 'unknown',
    };
  }

  async verify(ref: ProofRef): Promise<VerifyResult> {
    if (!SAFE_ID.test(ref.circuit) || !SAFE_ID.test(ref.id)) return { valid: false, code: 'malformed_proof_ref' };
    const { status, json } = await this.#call('POST', `/v1/circuits/${ref.circuit}/verify`, { proof: ref.id });
    const code = typeof json.error === 'string' ? json.error : undefined;
    if (status === 409 || status === 400 || status === 404) return { valid: false, code: code ?? `http_${status}` };
    if (status !== 200) throw new AffixioError(`AffixIO verify failed with HTTP ${status}${code ? ` (${code})` : ''}`, status, code);
    return {
      valid: json.valid === true,
      decision: typeof json.decision === 'string' ? json.decision : undefined,
      digest: typeof json.proof_digest === 'string' ? json.proof_digest : undefined,
      code,
    };
  }

  async merkleRoot(): Promise<MerkleRoot> {
    const { status, json } = await this.#call('GET', '/v1/merkle/root');
    if (status !== 200 || typeof json.root !== 'string') throw new AffixioError(`AffixIO merkle root failed with HTTP ${status}`, status);
    return {
      root: json.root,
      leafCount: typeof json.leaf_count === 'number' ? json.leaf_count : 0,
      updatedAt: typeof json.updated_at === 'string' ? json.updated_at : undefined,
    };
  }

  async merkleProof(digest: string): Promise<Record<string, unknown>> {
    if (!/^[a-f0-9]{64}$/.test(digest)) throw new Error('digest must be 64 hex characters');
    const { status, json } = await this.#call('GET', `/v1/merkle/proof/${digest}`);
    if (status !== 200) throw new AffixioError(`AffixIO merkle proof failed with HTTP ${status}`, status);
    return json;
  }
}

/**
 * In-memory stand-in for AffixIO with the same single-use semantics. For tests and offline development only:
 * it proves nothing to anyone else.
 */
export class MockAffixioClient implements AffixioClient {
  readonly issued = new Map<string, { digest: string; decision: string; circuit: string }>();
  readonly spent = new Set<string>();
  readonly calls = { prove: 0, verify: 0, merkleRoot: 0, merkleProof: 0 };

  async prove(fields: Record<string, boolean> = { ...DEFAULT_YESNO_FIELDS }, circuit = 'yesno'): Promise<ProveResult> {
    this.calls.prove++;
    const values = Object.values(fields);
    if (values.length === 0) throw new AffixioError('AffixIO prove failed with HTTP 400 (invalid_fields)', 400, 'invalid_fields');
    const decision = values.every((v) => v === true) ? 'yes' : 'no';
    const id = `pf_mock-${randomUUID()}`;
    const digest = randomBytes(32).toString('hex');
    this.issued.set(id, { digest, decision, circuit });
    return { provider: 'affixio', circuit, id, digest, decision };
  }

  async verify(ref: ProofRef): Promise<VerifyResult> {
    this.calls.verify++;
    const rec = this.issued.get(ref.id);
    if (!rec || rec.circuit !== ref.circuit) return { valid: false, code: 'invalid_proof' };
    if (this.spent.has(ref.id)) return { valid: false, code: 'double_spend_detected' };
    this.spent.add(ref.id);
    return { valid: true, decision: rec.decision, digest: rec.digest };
  }

  async merkleRoot(): Promise<MerkleRoot> {
    this.calls.merkleRoot++;
    return { root: 'f'.repeat(64), leafCount: this.issued.size };
  }

  async merkleProof(digest: string): Promise<Record<string, unknown>> {
    this.calls.merkleProof++;
    const found = [...this.issued.values()].some((r) => r.digest === digest);
    if (!found) throw new AffixioError('AffixIO merkle proof failed with HTTP 404', 404);
    return { digest, root: 'f'.repeat(64), proof: [] };
  }
}
