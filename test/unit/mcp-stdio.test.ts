import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { initStateDir } from '../../src/config.js';

test('the CLI serves MCP over stdio', async () => {
  const dir = join(mkdtempSync(join(tmpdir(), 'relay-stdio-')), 'state');
  const id = initStateDir(dir, 'acme.example/stdio');
  const cli = fileURLToPath(new URL('../../src/cli.js', import.meta.url));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [cli, 'mcp', '--dir', dir],
    env: { PATH: process.env.PATH ?? '', AFFIXIO_MOCK: '1' },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'stdio-test', version: '0.0.0' });
  await client.connect(transport);
  try {
    const { tools } = await client.listTools();
    assert.equal(tools.length, 8);
    const res = await client.callTool({ name: 'whoami', arguments: {} });
    const body = JSON.parse((res.content as { text: string }[])[0]?.text ?? '{}') as { agent: string; key: string };
    assert.deepEqual([body.agent, body.key], [id.id, id.keys.publicKey]);
    const receipts = await client.callTool({ name: 'receipts', arguments: {} });
    assert.equal(receipts.isError, undefined);
  } finally {
    await client.close();
  }
});
