import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { z } from "zod";

export interface Env {
  OAUTH_KV: KVNamespace;
  GEMINI_API_KEY: string;
  MCP_RESOURCE: string;
  MCP_SESSION: DurableObjectNamespace;
  ALLOWED_USERS?: string;
  AUTH_SECRET?: string;
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

/**
 * Node.js ServerResponse duck-typed adapter for Cloudflare Workers SSE streaming.
 */
export class WebSSEResponseAdapter {
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private encoder = new TextEncoder();
  public statusCode = 200;
  public headers: Record<string, string> = {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive"
  };
  private closeListeners: Array<() => void> = [];
  public isClosed = false;

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
    if (this.isClosed) return false;
    const data = typeof chunk === "string" ? chunk : chunk.toString();
    this.writer.write(this.encoder.encode(data)).catch(() => {
      this.close();
    });
    return true;
  }

  on(event: string, listener: () => void): this {
    if (event === "close") {
      this.closeListeners.push(listener);
    }
    return this;
  }

  close() {
    if (this.isClosed) return;
    this.isClosed = true;
    for (const listener of this.closeListeners) {
      try {
        listener();
      } catch {}
    }
    this.writer.close().catch(() => {});
  }

  end(chunk?: any): this {
    if (chunk) {
      this.write(chunk);
    }
    this.close();
    return this;
  }
}

/**
 * McpSessionDO: Shared Durable Object session owner.
 * Owns the lifecycle of the active SSE connection, transport, and MCP server.
 */
export class McpSessionDO {
  private state: DurableObjectState;
  private env: Env;
  private transport?: SSEServerTransport;
  private server?: McpServer;
  private activeSessionId?: string;
  private sseAdapter?: WebSSEResponseAdapter;
  private isCleanedUp = false;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async cleanupSession(sessionId: string) {
    // Only cleanup if the matching session is still active
    if (this.activeSessionId === sessionId && !this.isCleanedUp) {
      this.isCleanedUp = true;
      try {
        if (this.transport) {
          await this.transport.close();
        }
      } catch {}
      try {
        if (this.server) {
          await this.server.close();
        }
      } catch {}
      if (this.sseAdapter) {
        this.sseAdapter.close();
      }
      this.transport = undefined;
      this.server = undefined;
      this.activeSessionId = undefined;
      this.sseAdapter = undefined;

      // Clean up the shared lookup mapping safely
      try {
        await this.env.OAUTH_KV.delete(`session:${sessionId}`);
      } catch {}
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/sse") {
      // Clean up any pre-existing session on new connection
      if (this.activeSessionId) {
        await this.cleanupSession(this.activeSessionId);
      }
      this.isCleanedUp = false;

      const doIdString = this.state.id.toString();

      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const sseRes = new WebSSEResponseAdapter(writer);
      this.sseAdapter = sseRes;

      const transport = new SSEServerTransport("/message", sseRes as any);
      const server = createAntigravityMcpServer(this.env);
      await server.connect(transport);

      const sessionId = transport.sessionId;
      this.transport = transport;
      this.server = server;
      this.activeSessionId = sessionId;

      // Register shared session mapping to this DO instance ID in OAUTH_KV
      await this.env.OAUTH_KV.put(
        `session:${sessionId}`,
        JSON.stringify({ doId: doIdString, createdAt: Math.floor(Date.now() / 1000) }),
        { expirationTtl: 86400 }
      );

      // Register disconnect and close listener
      sseRes.on("close", () => {
        this.cleanupSession(sessionId).catch(() => {});
      });

      return new Response(readable, {
        status: sseRes.statusCode,
        headers: {
          ...sseRes.headers,
          "X-Session-Id": sessionId
        }
      });
    }

    if (url.pathname === "/message" && request.method === "POST") {
      const sessionId = url.searchParams.get("sessionId");
      if (!this.transport || this.activeSessionId !== sessionId || this.isCleanedUp) {
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

      try {
        await this.transport.handlePostMessage(dummyReq as any, dummyRes as any, parsedBody);
      } catch (err: any) {
        return new Response(err.message || "Transport error", { status: 500 });
      }

      return new Response(responseBody, {
        status: responseStatusCode,
        headers: { "Content-Type": "text/plain" }
      });
    }

    if (url.pathname === "/cleanup" && request.method === "POST") {
      const sessionId = url.searchParams.get("sessionId");
      if (sessionId) {
        await this.cleanupSession(sessionId);
      }
      return new Response("OK", { status: 200 });
    }

    return new Response("Not Found", { status: 404 });
  }
}

/**
 * Validates trusted user authentication and verifies against ALLOWED_USERS policy.
 * Supports:
 * - Direct authentication header verification (Bearer user-auth token, Cookie, or HMAC signature)
 * - Fails closed if no trusted identity mechanism is configured or caller is unauthorized.
 */
export async function authenticateAndAuthorizeUser(
  request: Request,
  env: Env
): Promise<{ authorized: boolean; userId?: string; error?: string }> {
  // If no allowed users policy is configured, fail closed
  const allowedUsersConfig = env.ALLOWED_USERS?.trim();
  if (!allowedUsersConfig) {
    return {
      authorized: false,
      error: "No allowed-user policy configured in server environment (ALLOWED_USERS)"
    };
  }

  const allowedUsers = allowedUsersConfig.split(",").map((u) => u.trim().toLowerCase());

  // 1. Check for authenticated user assertion header (e.g., from Cloudflare Access or Auth Gateway)
  // To prevent spoofing, if AUTH_SECRET is configured, we verify the signature header
  const authUser = request.headers.get("X-Auth-User") || request.headers.get("Cf-Access-Authenticated-User-Email");
  const authSig = request.headers.get("X-Auth-Signature");

  // If the deployment has no configured trusted identity/authentication mechanism, fail closed
  if (!env.AUTH_SECRET) {
    return {
      authorized: false,
      error: "No trusted authentication mechanism configured in server environment (AUTH_SECRET required)"
    };
  }

  // With AUTH_SECRET configured, require and verify the cryptographic signature
  if (!authUser || !authSig) {
    return {
      authorized: false,
      error: "Missing authenticated user credentials or cryptographic signature"
    };
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.AUTH_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const sigBytes = new Uint8Array(
    (authSig.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
  );
  const valid = await crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(authUser));
  if (!valid) {
    return { authorized: false, error: "Invalid authentication signature" };
  }

  const normalizedUser = authUser.trim().toLowerCase();
  if (!allowedUsers.includes(normalizedUser) && !allowedUsers.includes("*")) {
    return {
      authorized: false,
      error: `User '${normalizedUser}' is not authorized by the allowed-user policy`
    };
  }

  return {
    authorized: true,
    userId: normalizedUser
  };
}

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

        // Authenticate & check authorization policy
        const authResult = await authenticateAndAuthorizeUser(request, env);
        if (!authResult.authorized || !authResult.userId) {
          return new Response(
            JSON.stringify({
              error: "access_denied",
              error_description: authResult.error || "User authentication and authorization required"
            }),
            {
              status: 403,
              headers: { "Content-Type": "application/json" }
            }
          );
        }

        try {
          const authRequest = await oauthHelpers.parseAuthRequest(request);
          const { redirectTo } = await oauthHelpers.completeAuthorization({
            request: authRequest,
            userId: authResult.userId,
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
 * Helper to validate Bearer token against OAUTH_KV.
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

      // Create a unique Durable Object session owner instance
      const doId = env.MCP_SESSION.newUniqueId();
      const sessionStub = env.MCP_SESSION.get(doId);

      const doResponse = await sessionStub.fetch(new Request("http://internal/sse", request));
      return doResponse;
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
      if (!sessionId) {
        return new Response("Session not found or expired", { status: 404 });
      }

      // Resolve the shared DO owner from OAUTH_KV
      const sessionLookup = await env.OAUTH_KV.get<{ doId: string }>(`session:${sessionId}`, {
        type: "json"
      });
      if (!sessionLookup?.doId) {
        return new Response("Session not found or expired", { status: 404 });
      }

      const doId = env.MCP_SESSION.idFromString(sessionLookup.doId);
      const sessionStub = env.MCP_SESSION.get(doId);

      const doResponse = await sessionStub.fetch(
        new Request(`http://internal/message?sessionId=${encodeURIComponent(sessionId)}`, request)
      );
      return doResponse;
    }

    // 3. Delegate to OAuth Provider
    return oauth.fetch(request, env, ctx);
  }
};
