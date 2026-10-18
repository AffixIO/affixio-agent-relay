import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { generateKeyPair } from '../src/keys.js';
import { MockAffixioClient, type AffixioClient } from '../src/affixio.js';
import { Relay, type RelayOptions } from '../src/relay.js';
import type { Identity } from '../src/envelope.js';

export function identity(id: string): Identity {
  return { id, keys: generateKeyPair() };
}

export function ref(i: Identity) {
  return { id: i.id, key: i.keys.publicKey };
}

/** Two organisations, each with its own AffixIO client, pinned to each other. */
export function twoOrgs(opts: { affixio?: AffixioClient; buyer?: Partial<RelayOptions>; seller?: Partial<RelayOptions> } = {}) {
  const affixio = opts.affixio ?? new MockAffixioClient();
  const buyerId = identity('acme.example/buyer');
  const sellerId = identity('globex.example/sales');
  const buyer = new Relay({ identity: buyerId, affixio, peers: [ref(sellerId)], ...opts.buyer });
  const seller = new Relay({ identity: sellerId, affixio, peers: [ref(buyerId)], ...opts.seller });
  return { affixio, buyer, seller, buyerId, sellerId };
}

export async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

export async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}
