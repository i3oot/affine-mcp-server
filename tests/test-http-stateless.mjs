#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { startHttpMcpServer } from "../src/sse.ts";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function postMcp(baseUrl, body) {
  return await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

const previousHost = process.env.AFFINE_MCP_HTTP_HOST;
process.env.AFFINE_MCP_HTTP_HOST = "127.0.0.1";

let handle;
try {
  handle = await startHttpMcpServer(
    async () => new McpServer({ name: "stateless-test", version: "1.0.0" }),
    {
      baseUrl: "http://127.0.0.1:3010",
      graphqlEndpoint: "http://127.0.0.1:3010/graphql",
      graphqlPath: "/graphql",
      authMode: "bearer",
      oauthScopes: ["mcp"],
      oauthClockSkewSeconds: 60,
      transportMode: "http",
      loginAtStart: "async",
      http: {
        host: "127.0.0.1",
        port: 0,
        allowedOrigins: [],
        allowAllOrigins: false,
      },
      oauthAllowServiceWrites: false,
    },
  );
  const baseUrl = `http://127.0.0.1:${handle.port}`;
  const initialize = await postMcp(baseUrl, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "stateless-test", version: "1.0.0" },
    },
  });
  const initializeBody = await initialize.text();
  assert(initialize.status === 200, `initialize returned ${initialize.status}: ${initializeBody}`);
  assert(!initialize.headers.has("mcp-session-id"), "initialize returned Mcp-Session-Id");

  const tools = await postMcp(baseUrl, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: {},
  });
  const toolsBody = await tools.text();
  assert(tools.status === 200, `tools/list without session returned ${tools.status}: ${toolsBody}`);
  assert(!tools.headers.has("mcp-session-id"), "tools/list returned Mcp-Session-Id");
  assert(handle.sessionCount() === 0, "stateless requests left a tracked session");
  console.log("Stateless Streamable HTTP regression test passed.");
} finally {
  await handle?.close("Stateless regression test shutdown");
  if (previousHost === undefined) delete process.env.AFFINE_MCP_HTTP_HOST;
  else process.env.AFFINE_MCP_HTTP_HOST = previousHost;
}
