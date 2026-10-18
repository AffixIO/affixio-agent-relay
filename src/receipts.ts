import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { canonicalize, sha256Hex } from './canonical.js';

export const GENESIS = '0'.repeat(64);

export interface Receipt {
  seq: number;
  ts: string;
  type: string;
  data: Record<string, unknown>;
  /** Hash of the previous receipt, or 64 zeros for the first. */
  prev: string;
  /** sha256 over the canonical form of { seq, ts, type, data, prev }. */
  hash: string;
}

export interface LogCheck {
  ok: boolean;
  count: number;
  head: string;
  /** Sequence number of the first receipt that failed, when ok is false. */
  brokenAt?: number;
  reason?: string;
}

export function receiptHash(r: Omit<Receipt, 'hash'>): string {
  return sha256Hex(canonicalize({ seq: r.seq, ts: r.ts, type: r.type, data: r.data, prev: r.prev }));
}

/** A log head saved earlier, for example from a previous check. */
export interface ExpectedHead {
  seq: number;
  hash: string;
}

export interface VerifyOptions {
  /** Require the log to contain this receipt, which catches entries cut off the end since the head was saved. */
  expect?: ExpectedHead;
}

/**
 * Check a list of receipts. Any edit, deletion, insertion or reordering breaks the chain. With `expect`, the log
 * must also contain a receipt at `expect.seq` whose hash is `expect.hash`.
 */
export function verifyReceipts(entries: readonly Receipt[], opts: VerifyOptions = {}): LogCheck {
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const r = entries[i];
    if (!r || r.seq !== i) return { ok: false, count: entries.length, head: prev, brokenAt: i, reason: 'sequence' };
    if (r.prev !== prev) return { ok: false, count: entries.length, head: prev, brokenAt: i, reason: 'link' };
    if (receiptHash(r) !== r.hash) return { ok: false, count: entries.length, head: prev, brokenAt: i, reason: 'hash' };
    prev = r.hash;
  }
  const expect = opts.expect;
  if (expect) {
    if (expect.seq >= entries.length) return { ok: false, count: entries.length, head: prev, brokenAt: entries.length, reason: 'truncated' };
    if (entries[expect.seq]?.hash !== expect.hash) return { ok: false, count: entries.length, head: prev, brokenAt: expect.seq, reason: 'head_mismatch' };
  }
  return { ok: true, count: entries.length, head: prev };
}

/**
 * Append-only, hash-chained receipt log. With a path, receipts are stored as JSON lines and re-read on every
 * check, so edits made to the file on disk are detected.
 */
export class ReceiptLog {
  readonly #path?: string;
  #entries: Receipt[] = [];

  constructor(path?: string) {
    this.#path = path;
    if (path) this.#entries = this.#load();
  }

  #load(): Receipt[] {
    if (!this.#path) return this.#entries;
    let text: string;
    try {
      text = readFileSync(this.#path, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw err;
    }
    const out: Receipt[] = [];
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      try {
        out.push(JSON.parse(line) as Receipt);
      } catch {
        out.push({ seq: -1, ts: '', type: 'unparseable', data: {}, prev: '', hash: '' });
      }
    }
    return out;
  }

  append(type: string, data: Record<string, unknown>): Receipt {
    const last = this.#entries[this.#entries.length - 1];
    const base = { seq: this.#entries.length, ts: new Date().toISOString(), type, data, prev: last ? last.hash : GENESIS };
    const receipt: Receipt = { ...base, hash: receiptHash(base) };
    // Round-trip through JSON so the stored form and the hashed form are identical.
    const stored = JSON.parse(JSON.stringify(receipt)) as Receipt;
    if (this.#path) {
      mkdirSync(dirname(this.#path), { recursive: true });
      appendFileSync(this.#path, `${JSON.stringify(stored)}\n`, { mode: 0o600 });
    }
    this.#entries.push(stored);
    return stored;
  }

  entries(): Receipt[] {
    return this.#path ? this.#load() : this.#entries.map((e) => ({ ...e }));
  }

  head(): string {
    const last = this.#entries[this.#entries.length - 1];
    return last ? last.hash : GENESIS;
  }

  verify(opts: VerifyOptions = {}): LogCheck {
    return verifyReceipts(this.entries(), opts);
  }
}
