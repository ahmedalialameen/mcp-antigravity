import { describe, it, expect, vi, beforeEach } from "vitest";
import worker, {
  callAntigravityAgent,
  createAntigravityMcpServer,
  McpSessionDO,
  authenticateAndAuthorizeUser
} from "../src/index";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";

describe("Cloudflare Workers MCP Server for Google Antigravity Agent", () => {
  beforeEach(async () => {
    vi.restoreAllMocks();
  });

  describe("Authentication and Protection", () => {
    it("returns 401 Unauthorized for direct unauthenticated access to /sse", async () => {
      const request = new Request("http://example.com/sse");
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const text = await response.text();
      expect(text).toContain("Unauthorized");
    });

    it("returns 401 Unauthorized for direct unauthenticated access to /message", async () => {
      const request = new Request("http://example.com/message", {
        method: "POST",
        body: JSON.stringify({}),
        headers: { "Content-Type": "application/json" }
      });
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const text = await response.text();
      expect(text).toContain("Unauthorized");
    });

    it("returns 401 for /sse with invalid Bearer token prefix", async () => {
      const request = new Request("http://example.com/sse", {
        headers: { Authorization: "Basic abc" }
      });
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
    });

    it("returns 401 for /sse with unknown or invalid Bearer token", async () => {
      const request = new Request("http://example.com/sse", {
        headers: { Authorization: "Bearer invalid-or-unregistered-token" }
      });
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const authHeader = response.headers.get("WWW-Authenticate");
      expect(authHeader).toContain("invalid_token");
    });

    it("allows /sse access when Bearer token exists and is valid in OAUTH_KV", async () => {
      const userId = "antigravity-user";
      const grantId = "test-grant-id";
      const tokenSecret = "abcdef1234567890abcdef1234567890";
      const validToken = `${userId}:${grantId}:${tokenSecret}`;

      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(validToken));
      const tokenId = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      await env.OAUTH_KV.put(
        `token:${userId}:${grantId}:${tokenId}`,
        JSON.stringify({
          expiresAt: Math.floor(Date.now() / 1000) + 3600
        })
      );

      const request = new Request("http://example.com/sse", {
        headers: { Authorization: `Bearer ${validToken}` }
      });
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("text/event-stream");
    });
  });

  describe("Secure OAuth Authorization Flow", () => {
    it("fails closed when no allowed-user policy is configured", async () => {
      const testEnv = { ...env, ALLOWED_USERS: "" };
      const req = new Request("http://example.com/oauth/authorize");
      const res = await authenticateAndAuthorizeUser(req, testEnv as any);
      expect(res.authorized).toBe(false);
      expect(res.error).toContain("No allowed-user policy configured");
    });

    it("fails closed when AUTH_SECRET is not configured", async () => {
      const testEnv = { ...env, ALLOWED_USERS: "alice@example.com", AUTH_SECRET: undefined };
      const req = new Request("http://example.com/oauth/authorize", {
        headers: { "X-Auth-User": "alice@example.com" }
      });
      const res = await authenticateAndAuthorizeUser(req, testEnv as any);
      expect(res.authorized).toBe(false);
      expect(res.error).toContain("No trusted authentication mechanism configured");
    });

    it("rejects unauthenticated requests to /oauth/authorize even with client registration", async () => {
      const clientPayload = {
        client_name: "Test Client",
        redirect_uris: ["https://example.com/callback"],
        token_endpoint_auth_method: "client_secret_basic"
      };

      // Register client first
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(clientPayload)
      });
      const ctx = createExecutionContext();
      const regRes = await worker.fetch(regReq, env as any, ctx);
      const regData = await regRes.json<any>();

      // Attempt authorization without user identity or secret configured
      const authReq = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${regData.client_id}&redirect_uri=https://example.com/callback`
      );
      const authRes = await worker.fetch(authReq, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(authRes.status).toBe(403);
      const err = await authRes.json<any>();
      expect(err.error).toBe("access_denied");
    });

    it("rejects unauthorized users not in ALLOWED_USERS", async () => {
      const authSecret = "my-secret-key";
      const testEnv = { ...env, ALLOWED_USERS: "alice@example.com", AUTH_SECRET: authSecret };

      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, encoder.encode("eve@example.com"));
      const hexSig = Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const req = new Request("http://example.com/oauth/authorize", {
        headers: {
          "X-Auth-User": "eve@example.com",
          "X-Auth-Signature": hexSig
        }
      });
      const res = await authenticateAndAuthorizeUser(req, testEnv as any);
      expect(res.authorized).toBe(false);
      expect(res.error).toContain("User 'eve@example.com' is not authorized");
    });

    it("verifies HMAC signature if AUTH_SECRET is set", async () => {
      const authSecret = "super-secret-key-12345";
      const testEnv = {
        ...env,
        ALLOWED_USERS: "alice@example.com",
        AUTH_SECRET: authSecret
      };

      // 1. Missing signature fails
      const reqNoSig = new Request("http://example.com/oauth/authorize", {
        headers: { "X-Auth-User": "alice@example.com" }
      });
      const resNoSig = await authenticateAndAuthorizeUser(reqNoSig, testEnv as any);
      expect(resNoSig.authorized).toBe(false);
      expect(resNoSig.error).toContain("Missing authenticated user credentials or cryptographic signature");

      // 2. Valid signature succeeds
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, encoder.encode("alice@example.com"));
      const hexSig = Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const reqWithSig = new Request("http://example.com/oauth/authorize", {
        headers: {
          "X-Auth-User": "alice@example.com",
          "X-Auth-Signature": hexSig
        }
      });
      const resWithSig = await authenticateAndAuthorizeUser(reqWithSig, testEnv as any);
      expect(resWithSig.authorized).toBe(true);
      expect(resWithSig.userId).toBe("alice@example.com");
    });

    it("allows authenticated allowed user to complete authorization", async () => {
      const authSecret = "test-auth-secret-key";
      const testEnv = {
        ...env,
        ALLOWED_USERS: "user@example.com",
        AUTH_SECRET: authSecret
      };

      const clientPayload = {
        client_name: "Test Client Allowed",
        redirect_uris: ["https://example.com/oauth-callback"],
        token_endpoint_auth_method: "client_secret_basic"
      };

      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(clientPayload)
      });
      const ctx = createExecutionContext();
      const regRes = await worker.fetch(regReq, testEnv as any, ctx);
      const regData = await regRes.json<any>();

      // Generate signature
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, encoder.encode("user@example.com"));
      const hexSig = Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const authReq = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${regData.client_id}&redirect_uri=https://example.com/oauth-callback&state=mystate`,
        {
          headers: {
            "X-Auth-User": "user@example.com",
            "X-Auth-Signature": hexSig
          }
        }
      );
      const authRes = await worker.fetch(authReq, testEnv as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(authRes.status).toBe(302);
      const location = authRes.headers.get("Location");
      expect(location).toBeDefined();
      expect(location).toContain("https://example.com/oauth-callback?code=");
      expect(location).toContain("state=mystate");
    });
  });

  describe("Google Antigravity Agent API Integration", () => {
    it("calls Google Antigravity endpoint with official x-goog-api-key header and correct payload", async () => {
      const fakeApiKey = "AIzaSyTestApiKey123";
      const prompt = "Solve bug in sandbox";
      const workspaceFiles = {
        "index.js": "console.log('hello')",
        "package.json": "{}"
      };

      const mockResponseData = {
        candidates: [
          {
            content: {
              parts: [{ text: "Bug fixed successfully" }]
            }
          }
        ]
      };

      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify(mockResponseData), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
      );

      const result = await callAntigravityAgent(fakeApiKey, prompt, workspaceFiles);

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [calledUrl, calledInit] = fetchSpy.mock.calls[0];

      expect(calledUrl).toBe(
        "https://generativelanguage.googleapis.com/v1beta/models/antigravity:generateContent"
      );
      expect(calledInit?.method).toBe("POST");

      const headers = new Headers(calledInit?.headers);
      expect(headers.get("x-goog-api-key")).toBe(fakeApiKey);
      expect(headers.get("Content-Type")).toBe("application/json");

      const payload = JSON.parse(calledInit?.body as string);
      expect(payload).toEqual({
        contents: [
          {
            role: "user",
            parts: [{ text: prompt }]
          }
        ],
        agent_config: {
          tools: [{ type: "code_execution" }, { type: "file_system" }],
          workspace: workspaceFiles
        }
      });

      expect(result).toEqual(mockResponseData);
    });

    it("handles Google API errors properly and throws descriptive error", async () => {
      const fakeApiKey = "invalid_key";
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response("API Key not valid", { status: 403 })
      );

      await expect(
        callAntigravityAgent(fakeApiKey, "test prompt")
      ).rejects.toThrow("Google Antigravity API error (403): API Key not valid");
    });
  });

  describe("MCP Server and Tool Definition", () => {
    it("registers run_antigravity_agent tool and handles successful execution", async () => {
      const mockEnv: any = {
        GEMINI_API_KEY: "test_key",
        OAUTH_KV: env.OAUTH_KV,
        MCP_RESOURCE: "http://example.com/mcp"
      };

      const mockResponseData = { output: "done" };
      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify(mockResponseData), { status: 200 })
      );

      const server = createAntigravityMcpServer(mockEnv);
      expect(server).toBeDefined();

      const tool = (server as any)._registeredTools?.["run_antigravity_agent"];
      expect(tool).toBeDefined();

      const result = await tool.callback({ task: "run tests", contextFiles: { "test.js": "assert(true)" } });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].type).toBe("text");
      expect(result.content[0].text).toBe(JSON.stringify(mockResponseData, null, 2));
    });

    it("returns isError: true when run_antigravity_agent tool fails", async () => {
      const mockEnv: any = {
        GEMINI_API_KEY: "invalid_key",
        OAUTH_KV: env.OAUTH_KV,
        MCP_RESOURCE: "http://example.com/mcp"
      };

      vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response("Forbidden", { status: 403 })
      );

      const server = createAntigravityMcpServer(mockEnv);
      const tool = (server as any)._registeredTools?.["run_antigravity_agent"];
      expect(tool).toBeDefined();

      const result = await tool.callback({ task: "fail task" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error executing Antigravity task");
      expect(result.content[0].text).toContain("Google Antigravity API error (403)");
    });
  });

  describe("Durable Object Cross-Instance Session Management & Disconnect Cleanup", () => {
    it("routes SSE establishment followed by /message through worker.fetch to the shared session owner DO", async () => {
      const validToken = "user:grant:tokenCrossInstanceTest1234567890";
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(validToken));
      const tokenId = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      await env.OAUTH_KV.put(
        `token:user:grant:${tokenId}`,
        JSON.stringify({ expiresAt: Math.floor(Date.now() / 1000) + 3600 })
      );

      // 1. Establish SSE session via worker.fetch
      const sseReq = new Request("http://example.com/sse", {
        headers: { Authorization: `Bearer ${validToken}` }
      });
      const ctx1 = createExecutionContext();
      const sseRes = await worker.fetch(sseReq, env as any, ctx1);
      await waitOnExecutionContext(ctx1);

      expect(sseRes.status).toBe(200);

      // Read SSE stream header to get sessionId from the endpoint event
      const reader = sseRes.body?.getReader();
      const chunk = await reader?.read();
      const text = new TextDecoder().decode(chunk?.value);
      expect(text).toContain("event: endpoint");
      const sessionMatch = text.match(/sessionId=([a-zA-Z0-9-]+)/);
      expect(sessionMatch).not.toBeNull();
      const sessionId = sessionMatch![1];

      // 2. From a separate Worker invocation context, send POST /message to worker.fetch
      const postReq = new Request(`http://example.com/message?sessionId=${sessionId}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${validToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "ping",
          id: 1
        })
      });
      const ctx2 = createExecutionContext();
      const postRes = await worker.fetch(postReq, env as any, ctx2);
      await waitOnExecutionContext(ctx2);

      expect(postRes.status).toBe(202);
      expect(await postRes.text()).toBe("Accepted");

      // 3. Close the stream reader (simulating disconnect) and trigger cleanup
      await reader?.cancel();
      const sessionLookup = await env.OAUTH_KV.get<{ doId: string }>(`session:${sessionId}`, { type: "json" });
      if (sessionLookup?.doId) {
        const doId = env.MCP_SESSION.idFromString(sessionLookup.doId);
        const sessionStub = env.MCP_SESSION.get(doId);
        await sessionStub.fetch(
          new Request(`http://internal/cleanup?sessionId=${sessionId}`, { method: "POST" })
        );
      }

      // Subsequent message through worker.fetch for cleaned up session yields 404
      const afterCleanupReq = new Request(`http://example.com/message?sessionId=${sessionId}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${validToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 2 })
      });
      const ctx3 = createExecutionContext();
      const afterCleanupRes = await worker.fetch(afterCleanupReq, env as any, ctx3);
      await waitOnExecutionContext(ctx3);

      expect(afterCleanupRes.status).toBe(404);
      expect(await afterCleanupRes.text()).toContain("Session not found or expired");
    });

    it("returns 404 for unknown or expired session IDs on /message", async () => {
      const validToken = "user:grant:token123456789012345678901234567890";
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(validToken));
      const tokenId = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      await env.OAUTH_KV.put(
        `token:user:grant:${tokenId}`,
        JSON.stringify({ expiresAt: Math.floor(Date.now() / 1000) + 3600 })
      );

      const request = new Request("http://example.com/message?sessionId=non-existent-id", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${validToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 })
      });
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(404);
      expect(await response.text()).toContain("Session not found or expired");
    });
  });

  describe("OAuth 2.1 Provider & KV Storage", () => {
    it("handles OAuth metadata discovery (RFC 8414)", async () => {
      const request = new Request("http://example.com/.well-known/oauth-authorization-server");
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(200);
      const metadata = await response.json<any>();
      expect(metadata.token_endpoint).toBe("http://example.com/oauth/token");
      expect(metadata.authorization_endpoint).toBe("http://example.com/oauth/authorize");
      expect(metadata.registration_endpoint).toBe("http://example.com/oauth/register");
    });

    it("handles dynamic client registration via /oauth/register and stores in OAUTH_KV", async () => {
      const clientPayload = {
        client_name: "Test MCP Client",
        redirect_uris: ["https://example.com/oauth/callback"],
        token_endpoint_auth_method: "client_secret_basic"
      };

      const request = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(clientPayload)
      });

      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(201);
      const data = await response.json<any>();
      expect(data.client_id).toBeDefined();
      expect(data.client_secret).toBeDefined();
      expect(data.client_name).toBe("Test MCP Client");

      const stored = await env.OAUTH_KV.get(`client:${data.client_id}`, "json");
      expect(stored).toBeDefined();
      expect((stored as any).clientName).toBe("Test MCP Client");
    });
  });
});
