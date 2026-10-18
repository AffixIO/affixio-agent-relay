import { createHash } from 'node:crypto';

/** A JSON value that can be canonicalised. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/**
 * Deterministic JSON: object keys sorted, no whitespace, `undefined` members dropped.
 * Non-finite numbers are rejected so that both sides always hash the same bytes.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('non-finite numbers cannot be canonicalised');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
  }
  throw new TypeError(`cannot canonicalise value of type ${typeof value}`);
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** sha256 of the canonical form, prefixed with the algorithm name. */
export function digest(value: unknown): string {
  return `sha256:${sha256Hex(canonicalize(value))}`;
}
