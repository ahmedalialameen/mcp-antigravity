# Antigravity Remote MCP Server Specification

## 1. System Overview
This specification details a remote Model Context Protocol (MCP) server running on Cloudflare Workers. It exposes Google's Antigravity Agent runtime (code sandbox, file manipulation, and autonomous reasoning) to Claude clients (Claude Desktop, Claude Code, and Claude Web).

The server enforces OAuth 2.1 authentication backed by Cloudflare KV and exposes MCP transport over Server-Sent Events (SSE) and HTTP POST.

```
┌────────────────┐     Streamable HTTP / SSE       ┌───────────────────────────┐
│                │ ──────────────────────────────> │   Cloudflare Worker       │
│  Claude Client │ <────────────────────────────── │ (OAuth Resource Server)   │
│ (Desktop/Code) │   OAuth 2.1 PKCE Authorization  │                           │
└────────────────┘ <.............................> │  - OAuth Provider (KV)    │
                                                   │  - MCP Server & Tools     │
                                                   └─────────────┬─────────────┘
                                                                 │ x-goog-api-key:
                                                                 │ $GEMINI_API_KEY
                                                                 ▼
                                                   ┌───────────────────────────┐
                                                   │ Google Antigravity Agent  │
                                                   │   (Cloud Linux Sandbox)   │
                                                   └───────────────────────────┘
```

---

## 2. Environment & Configuration

### Dependencies (`package.json`)
```json
{
  "name": "antigravity-mcp-server",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "test": "vitest run"
  },
  "dependencies": {
    "@cloudflare/workers-oauth-provider": "^0.1.0",
    "@modelcontextprotocol/sdk": "^1.6.0",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.7.0",
    "@cloudflare/workers-types": "^4.20250214.0",
    "typescript": "^5.7.0",
    "vitest": "^3.0.0",
    "wrangler": "^3.109.0"
  }
}
```

### Worker Configuration (`wrangler.jsonc`)
```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "antigravity-mcp-server",
  "main": "src/index.ts",
  "compatibility_date": "2026-01-01",
  "compatibility_flags": ["nodejs_compat"],
  "kv_namespaces": [
    {
      "binding": "OAUTH_KV",
      "id": "<YOUR_KV_NAMESPACE_ID>"
    }
  ],
  "vars": {
    "MCP_RESOURCE": "https://antigravity-mcp-server.<your-subdomain>.workers.dev/mcp"
  }
}
```

### Secrets Setup
Secrets must be stored using Wrangler secrets:
```bash
npx wrangler secret put GEMINI_API_KEY
```

---

## 3. Worker Implementation (`src/index.ts`)

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { z } from "zod";

export interface Env {
  OAUTH_KV: KVNamespace;
  GEMINI_API_KEY: string;
  MCP_RESOURCE: string;
}

/**
 * Dispatches autonomous tasks to Google's Antigravity Agent endpoint.
 * Authenticates via the official Google 'x-goog-api-key' header.
 */
async function callAntigravityAgent(
  apiKey: string,
  prompt: string,
  workspaceFiles?: Record<string, string>
) {
  const url = "https://generativelanguage.googleapis.com/v1beta/models/antigravity:generateContent";

  const payload = {
    contents: [
      {
        role: "user",
        parts: [{ text: prompt }]
      }
    ],
    agent_config: {
      tools: [{ type: "code_execution" }, { type: "file_system" }],
      workspace: workspaceFiles || {}
    }
  };

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-goog-api-key": apiKey
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Google Antigravity API error (${response.status}): ${errorBody}`);
  }

  return await response.json();
}

/**
 * Instantiates the MCP Server and registers Antigravity tools.
 */
export function createAntigravityMcpServer(env: Env) {
  const server = new McpServer({
    name: "Antigravity Agent Server",
    version: "1.0.0"
  });

  server.tool(
    "run_antigravity_agent",
    "Executes autonomous multi-step reasoning, test suites, or file transformations inside Google's Antigravity sandbox.",
    {
      task: z.string().describe("Instructions describing the software task, bug fix, or analysis required."),
      contextFiles: z
        .record(z.string())
        .optional()
        .describe("Key-value mapping of file paths to raw contents to initialize into the sandbox workspace.")
    },
    async ({ task, contextFiles }) => {
      try {
        const result = await callAntigravityAgent(env.GEMINI_API_KEY, task, contextFiles);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2)
            }
          ]
        };
      } catch (err: any) {
        return {
          content: [{ type: "text", text: `Error executing Antigravity task: ${err.message}` }],
          isError: true
        };
      }
    }
  );

  return server;
}

// In-memory mapping of active SSE transport streams
const transports = new Map<string, SSEServerTransport>();

// Initialize OAuth 2.1 Provider
const oauth = new OAuthProvider({
  apiRoute: "/mcp",
  authorizeRoute: "/oauth/authorize",
  tokenRoute: "/oauth/token",
  clientRegistrationRoute: "/oauth/register"
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // 1. Establish SSE Transport Connection for Claude
    if (url.pathname === "/sse") {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return new Response("Unauthorized", { status: 401 });
      }

      const transport = new SSEServerTransport("/message", new Response());
      const server = createAntigravityMcpServer(env);
      await server.connect(transport);

      const sessionId = crypto.randomUUID();
      transports.set(sessionId, transport);

      return transport.handleRequest(request);
    }

    // 2. Client-to-Server Message Dispatcher
    if (url.pathname === "/message" && request.method === "POST") {
      const sessionId = url.searchParams.get("sessionId");
      const transport = sessionId ? transports.get(sessionId) : null;
      if (!transport) {
        return new Response("Session not found or expired", { status: 404 });
      }
      return transport.handlePostMessage(request);
    }

    // 3. Delegate to OAuth Provider
    return oauth.fetch(request, env, ctx);
  }
};
```

---

## 4. Claude Client Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "antigravity": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://antigravity-mcp-server.<your-subdomain>.workers.dev/sse"
      ]
    }
  }
}
```
```
