import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { Classic } from './stellar/classic.js';
import { Soroban } from './stellar/soroban.js';

const server = new Server({ name: 'stellar-mcp', version: '1.0.0' }, { capabilities: { tools: {} } });

async function handleToolCall(name: string, args: any) {
  const stellarClassic = new Classic(process.env.STELLAR_SERVER_URL);
  const soroban = new Soroban(process.env.STELLAR_SERVER_URL);
  switch (name) {
    case 'stellar_payment':
      return { content: [{ type: 'text', text: JSON.stringify(await stellarClassic.createPayment(args)) }] };
    case 'soroban_build_and_optimize':
      return { content: [{ type: 'text', text: JSON.stringify(await soroban.buildAndOptimize(args)) }] };
  }
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  return await handleToolCall(name, args ?? {});
});
