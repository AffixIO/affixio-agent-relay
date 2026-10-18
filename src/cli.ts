#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { HttpAffixioClient, MockAffixioClient, type AffixioClient } from './affixio.js';
import { initStateDir, loadIdentity, loadRelay } from './config.js';
import { createInboxServer } from './server.js';
import { createMcpServer } from './mcp.js';

const USAGE = `agent-relay <command> [options]

Commands:
  init  --id <agent-id>           create an identity and empty trust and policy files
  id                              print this agent's id and public key
  serve [--port 8787] [--host 127.0.0.1]
                                  run the HTTP inbox
  mcp   [--listen <port>]         run the MCP server on stdio, optionally hosting the inbox too

Options:
  --dir <path>                    state directory (default .agent-relay)

Environment:
  AFFIXIO_API_KEY                 AffixIO API key (from https://www.affix-io.com/studio)
  AFFIXIO_BASE_URL                override the API base URL
  AGENT_RELAY_INBOX_TOKEN         bearer token for GET /v1/inbox
  AGENT_RELAY_PUBLIC_URL          inbox URL reported by the whoami tool
  AFFIXIO_MOCK=1                  use an in-memory mock instead of AffixIO (local testing only)
`;

function affixioFromEnv(): AffixioClient {
  if (process.env.AFFIXIO_MOCK === '1') {
    process.stderr.write('agent-relay: AFFIXIO_MOCK=1, proofs are simulated and prove nothing\n');
    return new MockAffixioClient();
  }
  const apiKey = process.env.AFFIXIO_API_KEY;
  if (!apiKey) throw new Error('AFFIXIO_API_KEY is not set (get a key at https://www.affix-io.com/studio)');
  return new HttpAffixioClient({ apiKey, baseUrl: process.env.AFFIXIO_BASE_URL });
}

async function main(argv: string[]): Promise<void> {
  const { positionals, values } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      dir: { type: 'string', default: '.agent-relay' },
      id: { type: 'string' },
      port: { type: 'string', default: '8787' },
      host: { type: 'string', default: '127.0.0.1' },
      listen: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const cmd = positionals[0];
  const dir = values.dir ?? '.agent-relay';
  if (!cmd || values.help) {
    process.stdout.write(USAGE);
    return;
  }
  if (cmd === 'init') {
    if (!values.id) throw new Error('init needs --id <agent-id>');
    const identity = initStateDir(dir, values.id);
    process.stdout.write(`${JSON.stringify({ id: identity.id, key: identity.keys.publicKey }, null, 2)}\n`);
    return;
  }
  if (cmd === 'id') {
    const identity = loadIdentity(dir);
    process.stdout.write(`${JSON.stringify({ id: identity.id, key: identity.keys.publicKey }, null, 2)}\n`);
    return;
  }
  if (cmd === 'serve') {
    const relay = loadRelay(dir, affixioFromEnv());
    const server = createInboxServer(relay, { inboxToken: process.env.AGENT_RELAY_INBOX_TOKEN });
    server.listen(Number(values.port), values.host, () => {
      process.stderr.write(`agent-relay: ${relay.identity.id} inbox on http://${values.host}:${values.port}\n`);
    });
    return;
  }
  if (cmd === 'mcp') {
    const relay = loadRelay(dir, affixioFromEnv());
    if (values.listen) {
      createInboxServer(relay, { inboxToken: process.env.AGENT_RELAY_INBOX_TOKEN }).listen(Number(values.listen), values.host);
    }
    const server = createMcpServer(relay, { inboxUrl: process.env.AGENT_RELAY_PUBLIC_URL });
    await server.connect(new StdioServerTransport());
    return;
  }
  throw new Error(`unknown command "${cmd}"\n\n${USAGE}`);
}

main(process.argv.slice(2)).catch((err: unknown) => {
  process.stderr.write(`agent-relay: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
