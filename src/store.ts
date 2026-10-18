import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/** Minimal key-value store used for nonces, verified grants and spend totals. */
export interface KeyValueStore {
  get(key: string): unknown;
  set(key: string, value: unknown): void;
  delete(key: string): void;
  keys(): string[];
}

export class MemoryStore implements KeyValueStore {
  readonly #map = new Map<string, unknown>();
  get(key: string): unknown {
    return this.#map.get(key);
  }
  set(key: string, value: unknown): void {
    this.#map.set(key, value);
  }
  delete(key: string): void {
    this.#map.delete(key);
  }
  keys(): string[] {
    return [...this.#map.keys()];
  }
}

/** A JSON file store. Each write replaces the file atomically (write then rename). Single process only. */
export class JsonFileStore implements KeyValueStore {
  readonly #path: string;
  readonly #data: Record<string, unknown>;

  constructor(path: string) {
    this.#path = path;
    let data: Record<string, unknown> = {};
    try {
      const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) data = parsed as Record<string, unknown>;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    this.#data = data;
  }

  #flush(): void {
    mkdirSync(dirname(this.#path), { recursive: true });
    const tmp = `${this.#path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.#data), { mode: 0o600 });
    renameSync(tmp, this.#path);
  }

  get(key: string): unknown {
    return Object.prototype.hasOwnProperty.call(this.#data, key) ? this.#data[key] : undefined;
  }
  set(key: string, value: unknown): void {
    this.#data[key] = value;
    this.#flush();
  }
  delete(key: string): void {
    if (key in this.#data) {
      delete this.#data[key];
      this.#flush();
    }
  }
  keys(): string[] {
    return Object.keys(this.#data);
  }
}
