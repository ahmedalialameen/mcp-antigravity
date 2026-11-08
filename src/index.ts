import { McpServer, createMcpHandler, type AuthInfo } from "@modelcontextprotocol/server";
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
 * Uses Google's Interactions API endpoint and official 'x-goog-api-key' header.
 */
export async function callAntigravityAgent(
  apiKey: string,
  prompt: string,
  workspaceFiles?: Record<string, string>
) {
  const url = "https://generativelanguage.googleapis.com/v1beta/interactions";

  const filesArray = workspaceFiles
    ? Object.entries(workspaceFiles).map(([path, content]) => ({
        path,
        content
      }))
    : [];

  const payload: Record<string, any> = {
    agent: "antigravity-preview-09-2026",
    input: {
      query: prompt
    }
  };

  if (filesArray.length > 0) {
    payload.input.files = filesArray;
  }

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
    let parsedMessage = errorBody;
    try {
      const errJson = JSON.parse(errorBody);
      if (errJson.error?.message) {
        parsedMessage = errJson.error.message;
      }
    } catch {}
    throw new Error(`Google Antigravity API error (${response.status}): ${parsedMessage}`);
  }

  return await response.json();
}

/**
 * Instantiates the MCP Server and registers Antigravity tools using SDK v2.
 */
export function createAntigravityMcpServer(env: Env, authInfo?: AuthInfo) {
  const server = new McpServer({
    name: "Antigravity Agent Server",
    version: "1.0.0"
  });

  server.registerTool(
    "run_antigravity_agent",
    {
      description:
        "Executes autonomous multi-step reasoning, test suites, or file transformations inside Google's Antigravity sandbox.",
      inputSchema: z.object({
        task: z.string().describe("Instructions describing the software task, bug fix, or analysis required."),
        contextFiles: z
          .record(z.string(), z.string())
          .optional()
          .describe("Key-value mapping of file paths to raw contents to initialize into the sandbox workspace.")
      })
    },
    async ({ task, contextFiles }) => {
      try {
        const result = await callAntigravityAgent(env.GEMINI_API_KEY, task, contextFiles as Record<string, string> | undefined);
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
 * McpSessionDO: Shared Durable Object session owner for legacy SSE connections.
 */
export class McpSessionDO {
  private state: DurableObjectState;
  private env: Env;
  private activeSessionId?: string;
  private sessionUser?: string;
  private isCleanedUp = false;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async cleanupSession(sessionId: string) {
    if (this.activeSessionId === sessionId && !this.isCleanedUp) {
      this.isCleanedUp = true;
      this.activeSessionId = undefined;
      this.sessionUser = undefined;
      try {
        await this.env.OAUTH_KV.delete(`session:${sessionId}`);
      } catch {}
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const requestUser = request.headers.get("X-Session-User") || undefined;

    if (url.pathname === "/sse") {
      if (this.activeSessionId) {
        await this.cleanupSession(this.activeSessionId);
      }
      this.isCleanedUp = false;

      const sessionId = crypto.randomUUID();
      this.activeSessionId = sessionId;
      this.sessionUser = requestUser;

      await this.env.OAUTH_KV.put(
        `session:${sessionId}`,
        JSON.stringify({
          doId: this.state.id.toString(),
          userId: requestUser,
          createdAt: Math.floor(Date.now() / 1000)
        }),
        { expirationTtl: 86400 }
      );

      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const encoder = new TextEncoder();

      // Write endpoint event for legacy SSE clients
      writer.write(encoder.encode(`event: endpoint\ndata: /message?sessionId=${sessionId}\n\n`)).catch(() => {});

      return new Response(readable, {
        status: 200,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache, no-transform",
          "Connection": "keep-alive",
          "X-Session-Id": sessionId
        }
      });
    }

    if (url.pathname === "/message" && request.method === "POST") {
      const sessionId = url.searchParams.get("sessionId");
      if (this.activeSessionId !== sessionId || this.isCleanedUp) {
        return new Response("Session not found or expired", { status: 404 });
      }

      if (this.sessionUser && requestUser && this.sessionUser !== requestUser) {
        return new Response("Forbidden: Session owned by another user", { status: 403 });
      }

      return new Response("Accepted", {
        status: 202,
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
 */
export async function authenticateAndAuthorizeUser(
  request: Request,
  env: Env
): Promise<{ authorized: boolean; userId?: string; error?: string }> {
  const allowedUsersConfig = env.ALLOWED_USERS?.trim();
  if (!allowedUsersConfig) {
    return {
      authorized: false,
      error: "No allowed-user policy configured in server environment (ALLOWED_USERS)"
    };
  }

  const allowedUsers = allowedUsersConfig
    .split(",")
    .map((u) => u.trim().toLowerCase())
    .filter((u) => u.length > 0);

  if (allowedUsers.length === 0) {
    return {
      authorized: false,
      error: "No valid allowed users configured in ALLOWED_USERS"
    };
  }

  const authUser = request.headers.get("X-Auth-User") || request.headers.get("Cf-Access-Authenticated-User-Email");
  const authSig = request.headers.get("X-Auth-Signature");

  if (!env.AUTH_SECRET) {
    return {
      authorized: false,
      error: "No trusted authentication mechanism configured in server environment (AUTH_SECRET required)"
    };
  }

  if (!authUser || !authSig) {
    return {
      authorized: false,
      error: "Missing authenticated user credentials or cryptographic signature"
    };
  }

  const cleanSig = authSig.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(cleanSig)) {
    return { authorized: false, error: "Invalid authentication signature format" };
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
    (cleanSig.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
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
  apiRoute: "/api",
  apiHandler: {
    async fetch(request: Request, env: any, ctx: any) {
      return new Response("API Endpoint", { status: 200 });
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

export interface ValidatedToken {
  isValid: boolean;
  userId?: string;
  grantId?: string;
  scope?: string[];
  audience?: string | string[];
  error?: string;
}

/**
 * Validates a Bearer token against OAUTH_KV and checks expiration and audience/resource matching.
 */
export async function validateBearerToken(
  authHeader: string | null,
  env: Env,
  requestUrl?: URL
): Promise<ValidatedToken> {
  if (!authHeader?.startsWith("Bearer ")) {
    return { isValid: false, error: "invalid_token" };
  }
  const token = authHeader.substring(7).trim();
  if (!token) {
    return { isValid: false, error: "invalid_token" };
  }

  const parts = token.split(":");
  if (parts.length !== 3) {
    return { isValid: false, error: "invalid_token" };
  }

  const [userId, grantId] = parts;
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(token));
  const tokenId = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const tokenKey = `token:${userId}:${grantId}:${tokenId}`;
  const tokenData = await env.OAUTH_KV.get<{
    expiresAt?: number;
    audience?: string | string[];
    grant?: { clientId?: string; scope?: string[] };
  }>(tokenKey, { type: "json" });

  if (!tokenData) {
    return { isValid: false, error: "invalid_token" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (tokenData.expiresAt && tokenData.expiresAt < now) {
    return { isValid: false, error: "token_expired" };
  }

  // Audience / Resource validation (RFC 8707 / RFC 7519)
  if (tokenData.audience && requestUrl) {
    const resourceServer = `${requestUrl.protocol}//${requestUrl.host}`;
    const audiences = Array.isArray(tokenData.audience) ? tokenData.audience : [tokenData.audience];
    const matches = audiences.some((aud) => {
      if (aud === resourceServer || aud === requestUrl.origin || aud === requestUrl.href) {
        return true;
      }
      try {
        const audUrl = new URL(aud);
        return audUrl.origin === requestUrl.origin && requestUrl.pathname.startsWith(audUrl.pathname);
      } catch {
        return aud === requestUrl.host;
      }
    });

    if (!matches) {
      return { isValid: false, error: "invalid_audience" };
    }
  }

  return {
    isValid: true,
    userId,
    grantId,
    scope: tokenData.grant?.scope || [],
    audience: tokenData.audience
  };
}

/**
 * Helper to build 401 Unauthorized responses with RFC 9728 resource_metadata link in WWW-Authenticate.
 */
export function createUnauthorizedResponse(
  requestUrl: URL,
  env: Env,
  error = "invalid_token",
  errorDescription?: string
): Response {
  const resourceMetadataUrl = `${requestUrl.origin}/.well-known/oauth-protected-resource/mcp`;
  let challenge = `Bearer realm="OAuth", error="${error}", resource_metadata="${resourceMetadataUrl}"`;
  if (errorDescription) {
    challenge += `, error_description="${errorDescription}"`;
  }
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": challenge,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Expose-Headers": "WWW-Authenticate"
    }
  });
}

/**
 * Handles RFC 9728 Protected Resource Metadata discovery requests.
 */
export function handleProtectedResourceMetadata(requestUrl: URL, env: Env): Response {
  const resourceUri = env.MCP_RESOURCE || `${requestUrl.origin}/mcp`;
  const metadata = {
    resource: resourceUri,
    authorization_servers: [requestUrl.origin],
    scopes_supported: ["mcp"],
    bearer_methods_supported: ["header"],
    resource_documentation: `${requestUrl.origin}/README.md`
  };

  return new Response(JSON.stringify(metadata, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "public, max-age=3600"
    }
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // RFC 9728 Protected Resource Metadata Discovery endpoints
    if (
      url.pathname === "/.well-known/oauth-protected-resource/mcp" ||
      url.pathname === "/.well-known/oauth-protected-resource"
    ) {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type"
          }
        });
      }
      return handleProtectedResourceMetadata(url, env);
    }

    // 1. Primary Remote MCP Endpoint: Stateless Web-Standard Transport (/mcp)
    if (url.pathname === "/mcp") {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, MCP-Protocol-Version",
            "Access-Control-Expose-Headers": "WWW-Authenticate"
          }
        });
      }

      const tokenResult = await validateBearerToken(request.headers.get("Authorization"), env, url);
      if (!tokenResult.isValid) {
        return createUnauthorizedResponse(url, env, tokenResult.error || "invalid_token");
      }

      const mcpHandler = createMcpHandler((context) =>
        createAntigravityMcpServer(env, context?.authInfo)
      );

      const response = await mcpHandler.fetch(request, {
        authInfo: {
          token: request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "") || "",
          clientId: tokenResult.grantId || "claude-client",
          scopes: tokenResult.scope || ["mcp"],
          extra: { userId: tokenResult.userId }
        } as any
      });

      const resHeaders = new Headers(response.headers);
      resHeaders.set("Access-Control-Allow-Origin", "*");
      resHeaders.set("Access-Control-Expose-Headers", "WWW-Authenticate");

      return new Response(response.body, {
        status: response.status,
        headers: resHeaders
      });
    }

    // 2. Legacy SSE Transport Connection (/sse)
    if (url.pathname === "/sse") {
      const tokenResult = await validateBearerToken(request.headers.get("Authorization"), env, url);
      if (!tokenResult.isValid) {
        return createUnauthorizedResponse(url, env, tokenResult.error || "invalid_token");
      }

      const doId = env.MCP_SESSION.newUniqueId();
      const sessionStub = env.MCP_SESSION.get(doId);

      const doRequest = new Request("http://internal/sse", request);
      if (tokenResult.userId) {
        doRequest.headers.set("X-Session-User", tokenResult.userId);
      }
      return await sessionStub.fetch(doRequest);
    }

    // 3. Legacy Message Dispatcher (/message)
    if (url.pathname === "/message" && request.method === "POST") {
      const tokenResult = await validateBearerToken(request.headers.get("Authorization"), env, url);
      if (!tokenResult.isValid) {
        return createUnauthorizedResponse(url, env, tokenResult.error || "invalid_token");
      }

      const sessionId = url.searchParams.get("sessionId");
      if (!sessionId) {
        return new Response("Session not found or expired", { status: 404 });
      }

      const sessionLookup = await env.OAUTH_KV.get<{ doId: string; userId?: string }>(
        `session:${sessionId}`,
        { type: "json" }
      );
      if (!sessionLookup?.doId) {
        return new Response("Session not found or expired", { status: 404 });
      }

      if (sessionLookup.userId && sessionLookup.userId !== tokenResult.userId) {
        return new Response("Forbidden: Session owned by another user", { status: 403 });
      }

      const doId = env.MCP_SESSION.idFromString(sessionLookup.doId);
      const sessionStub = env.MCP_SESSION.get(doId);

      const doRequest = new Request(
        `http://internal/message?sessionId=${encodeURIComponent(sessionId)}`,
        request
      );
      if (tokenResult.userId) {
        doRequest.headers.set("X-Session-User", tokenResult.userId);
      }
      return await sessionStub.fetch(doRequest);
    }

    // 4. Delegate to OAuth Provider
    return oauth.fetch(request, env, ctx);
  }
};
