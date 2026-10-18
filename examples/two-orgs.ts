/**
 * Two organisations, two agents, one HTTP inbox.
 *
 *   npm run example                       uses an in-memory mock (no key, proves nothing)
 *   AFFIXIO_API_KEY=... npm run example   uses the live AffixIO API (2 proofs)
 */
import { generateKeyPair } from '../src/keys.js';
import { HttpAffixioClient, MockAffixioClient, type AffixioClient } from '../src/affixio.js';
import { Relay } from '../src/relay.js';
import { createInboxServer } from '../src/server.js';
import { HttpTransport } from '../src/transport.js';
import type { AddressInfo } from 'node:net';

const key = process.env.AFFIXIO_API_KEY;
const affixio: AffixioClient = key ? new HttpAffixioClient({ apiKey: key }) : new MockAffixioClient();
console.log(key ? 'Using the live AffixIO API' : 'Using the in-memory mock (set AFFIXIO_API_KEY for live proofs)');

// Acme's human owner and its purchasing agent.
const owner = new Relay({ identity: { id: 'acme.example/owner', keys: generateKeyPair() }, affixio });
const buyer = new Relay({ identity: { id: 'acme.example/buyer', keys: generateKeyPair() }, affixio });

// Globex's sales agent trusts Acme's owner key as a root, and nothing else.
const sales = new Relay({
  identity: { id: 'globex.example/sales', keys: generateKeyPair() },
  affixio,
  trustedRoots: [owner.ref],
  policy: { allowUnlistedActions: false, actions: { 'order.place': { requireDelegation: true } } },
});

const server = createInboxServer(sales);
await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
const inbox = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
const transport = new HttpTransport();

// The owner lets the buyer place orders with Globex, up to 40 GBP each.
const chain = await owner.delegate({ subject: buyer.ref, audience: sales.identity.id, scope: { actions: ['order.place'], max_amount: 40, currency: 'GBP' }, ttlSeconds: 600 });
buyer.importGrant(chain);

const env = await buyer.createRequest({ to: sales.identity.id, action: 'order.place', params: { sku: 'WIDGET-9', amount: 36, currency: 'GBP' }, delegation: chain });
console.log('first delivery:', await transport.send(inbox, env));
console.log('replayed:      ', await transport.send(inbox, env));
console.log('receipt log:   ', sales.verifyReceipts());

server.close();
