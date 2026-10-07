// Harmless dummy MCP stdio server used only by tests/live/verify-live.mjs.
// Three dummy tools, no side effects, no network, no file access. NOT a production MCP server.
import readline from 'node:readline';

const TOOLS = ['dummy_read_a', 'dummy_read_b', 'dummy_write_c'].map((name) => ({
  name,
  description: `dummy tool ${name}`,
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
}));
const send = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);

readline.createInterface({ input: process.stdin }).on('line', (line) => {
  let m;
  try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'initialize') {
    send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: m.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'aihf-fixture', version: '0.0.0' } } });
  } else if (m.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: m.id, result: { tools: TOOLS } });
  } else if (m.method === 'tools/call') {
    send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: `called ${m.params?.name}` }] } });
  } else {
    send({ jsonrpc: '2.0', id: m.id, result: {} });
  }
});
