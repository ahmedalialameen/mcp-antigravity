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
export async function callAntigravityAgent(
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
  apiHandler: {
    async fetch(request: Request, env: any, ctx: any) {
      return new Response("MCP API Endpoint", { status: 200 });
    }
  },
  authorizeEndpoint: "/oauth/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
  defaultHandler: {
    async fetch(request: Request, env: any) {
      const url = new URL(request.url);
      if (url.pathname === "/oauth/authorize") {
        const oauthHelpers = (env as any).OAUTH_PROVIDER;
        if (!oauthHelpers) {
          return new Response("OAuth provider not initialized", { status: 500 });
        }
        try {
          const authRequest = await oauthHelpers.parseAuthRequest(request);
          // Auto-authorize in headless sandbox / worker environments
          const { redirectTo } = await oauthHelpers.completeAuthorization({
            request: authRequest,
            userId: "antigravity-user",
            scope: authRequest.scope || ["mcp"]
          });
          return Response.redirect(redirectTo, 302);
        } catch (e: any) {
          return new Response(`Authorization Error: ${e.message}`, { status: 400 });
        }
      }
      return new Response("Not Found", { status: 404 });
    }
  }
});

/**
 * Node.js ServerResponse duck-typed adapter for Cloudflare Workers SSE streaming.
 */
class WebSSEResponseAdapter {
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private encoder = new TextEncoder();
  public statusCode = 200;
  public headers: Record<string, string> = {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive"
  };
  private closeListeners: Array<() => void> = [];

  constructor(writer: WritableStreamDefaultWriter<Uint8Array>) {
    this.writer = writer;
  }

  writeHead(statusCode: number, headers?: any) {
    this.statusCode = statusCode;
    if (headers) {
      Object.assign(this.headers, headers);
    }
    return this;
  }

  write(chunk: any): boolean {
    const data = typeof chunk === "string" ? chunk : chunk.toString();
    this.writer.write(this.encoder.encode(data)).catch(() => {});
    return true;
  }

  on(event: string, listener: () => void): this {
    if (event === "close") {
      this.closeListeners.push(listener);
    }
    return this;
  }

  end(chunk?: any): this {
    if (chunk) {
      this.write(chunk);
    }
    for (const listener of this.closeListeners) {
      try {
        listener();
      } catch {}
    }
    this.writer.close().catch(() => {});
    return this;
  }
}

/**
 * Helper to validate Bearer token against OAUTH_KV or verify authorization.
 */
async function isValidBearerToken(authHeader: string | null, env: Env): Promise<boolean> {
  if (!authHeader?.startsWith("Bearer ")) {
    return false;
  }
  const token = authHeader.substring(7).trim();
  if (!token) {
    return false;
  }

  const parts = token.split(":");
  if (parts.length === 3) {
    const [userId, grantId] = parts;
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(token));
    const tokenId = Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const tokenKey = `token:${userId}:${grantId}:${tokenId}`;
    const tokenData = await env.OAUTH_KV.get<{ expiresAt?: number }>(tokenKey, { type: "json" });
    if (tokenData) {
      const now = Math.floor(Date.now() / 1000);
      return !tokenData.expiresAt || tokenData.expiresAt >= now;
    }
  }

  return false;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // 1. Establish SSE Transport Connection for Claude
    if (url.pathname === "/sse") {
      const isValid = await isValidBearerToken(request.headers.get("Authorization"), env);
      if (!isValid) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Bearer realm="OAuth", error="invalid_token"'
          }
        });
      }

      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const sseRes = new WebSSEResponseAdapter(writer);

      const transport = new SSEServerTransport("/message", sseRes as any);
      const server = createAntigravityMcpServer(env);
      await server.connect(transport);

      const sessionId = transport.sessionId;
      transports.set(sessionId, transport);

      return new Response(readable, {
        status: sseRes.statusCode,
        headers: sseRes.headers
      });
    }

    // 2. Client-to-Server Message Dispatcher
    if (url.pathname === "/message" && request.method === "POST") {
      const isValid = await isValidBearerToken(request.headers.get("Authorization"), env);
      if (!isValid) {
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            "WWW-Authenticate": 'Bearer realm="OAuth", error="invalid_token"'
          }
        });
      }

      const sessionId = url.searchParams.get("sessionId");
      const transport = sessionId ? transports.get(sessionId) : null;
      if (!transport) {
        return new Response("Session not found or expired", { status: 404 });
      }

      const bodyText = await request.text();
      let parsedBody: any;
      try {
        parsedBody = JSON.parse(bodyText);
      } catch {
        return new Response("Invalid JSON", { status: 400 });
      }

      let responseStatusCode = 202;
      let responseBody = "Accepted";
      const dummyRes = {
        writeHead(status: number) {
          responseStatusCode = status;
          return this;
        },
        end(chunk?: any) {
          if (chunk) {
            responseBody = String(chunk);
          }
          return this;
        }
      };

      const dummyReq = {
        headers: {
          "content-type": request.headers.get("content-type") || "application/json"
        }
      };

      await transport.handlePostMessage(dummyReq as any, dummyRes as any, parsedBody);

      return new Response(responseBody, {
        status: responseStatusCode,
        headers: { "Content-Type": "text/plain" }
      });
    }

    // 3. Delegate to OAuth Provider
    return oauth.fetch(request, env, ctx);
  }
};
