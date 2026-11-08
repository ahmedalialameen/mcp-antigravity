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

  describe("Protected Resource Metadata & OAuth Discovery", () => {
    it("returns RFC 9728 protected resource metadata on /.well-known/oauth-protected-resource/mcp", async () => {
      const request = new Request("http://example.com/.well-known/oauth-protected-resource/mcp");
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("application/json");
      const metadata = await response.json<any>();
      expect(metadata.resource).toBeDefined();
      expect(metadata.authorization_servers).toContain("http://example.com");
      expect(metadata.scopes_supported).toEqual(["mcp"]);
      expect(metadata.bearer_methods_supported).toEqual(["header"]);
    });

    it("returns 401 challenge with resource_metadata attribute for unauthenticated access to /mcp", async () => {
      const request = new Request("http://example.com/mcp");
      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const wwwAuth = response.headers.get("WWW-Authenticate");
      expect(wwwAuth).toBeDefined();
      expect(wwwAuth).toContain('Bearer realm="OAuth"');
      expect(wwwAuth).toContain('resource_metadata="http://example.com/.well-known/oauth-protected-resource/mcp"');
    });
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

      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(clientPayload)
      });
      const ctx = createExecutionContext();
      const regRes = await worker.fetch(regReq, env as any, ctx);
      const regData = await regRes.json<any>();

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

    it("safely handles ALLOWED_USERS with whitespace and empty items", async () => {
      const authSecret = "test-secret";
      const testEnv = { ...env, ALLOWED_USERS: "  alice@example.com , , bob@example.com,  ", AUTH_SECRET: authSecret };

      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, encoder.encode("bob@example.com"));
      const hexSig = Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      const req = new Request("http://example.com/oauth/authorize", {
        headers: {
          "X-Auth-User": "bob@example.com",
          "X-Auth-Signature": hexSig
        }
      });
      const res = await authenticateAndAuthorizeUser(req, testEnv as any);
      expect(res.authorized).toBe(true);
      expect(res.userId).toBe("bob@example.com");
    });

    it("rejects invalid HMAC signature hex formatting strictly", async () => {
      const testEnv = { ...env, ALLOWED_USERS: "alice@example.com", AUTH_SECRET: "secret" };
      const req = new Request("http://example.com/oauth/authorize", {
        headers: {
          "X-Auth-User": "alice@example.com",
          "X-Auth-Signature": "invalid-hex-not-64-chars"
        }
      });
      const res = await authenticateAndAuthorizeUser(req, testEnv as any);
      expect(res.authorized).toBe(false);
      expect(res.error).toContain("Invalid authentication signature format");
    });

    it("verifies HMAC signature if AUTH_SECRET is set", async () => {
      const authSecret = "super-secret-key-12345";
      const testEnv = {
        ...env,
        ALLOWED_USERS: "alice@example.com",
        AUTH_SECRET: authSecret
      };

      const reqNoSig = new Request("http://example.com/oauth/authorize", {
        headers: { "X-Auth-User": "alice@example.com" }
      });
      const resNoSig = await authenticateAndAuthorizeUser(reqNoSig, testEnv as any);
      expect(resNoSig.authorized).toBe(false);
      expect(resNoSig.error).toContain("Missing authenticated user credentials or cryptographic signature");

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
    it("calls Google Antigravity Interactions API endpoint with official x-goog-api-key header and correct payload", async () => {
      const fakeApiKey = "AIzaSyTestApiKey123";
      const prompt = "Solve bug in sandbox";
      const workspaceFiles = {
        "index.js": "console.log('hello')",
        "package.json": "{}"
      };

      const mockResponseData = {
        interaction_id: "int-12345",
        status: "completed",
        output: {
          result: "Bug fixed successfully"
        }
      };

      const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        return Response.json(mockResponseData, { status: 200 });
      });

      const result = await callAntigravityAgent(fakeApiKey, prompt, workspaceFiles);

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [calledUrl, calledInit] = fetchSpy.mock.calls[0];

      expect(calledUrl).toBe(
        "https://generativelanguage.googleapis.com/v1beta/interactions"
      );
      expect(calledInit?.method).toBe("POST");

      const headers = new Headers(calledInit?.headers);
      expect(headers.get("x-goog-api-key")).toBe(fakeApiKey);
      expect(headers.get("Content-Type")).toBe("application/json");

      const payload = JSON.parse(calledInit?.body as string);
      expect(payload).toEqual({
        agent: "antigravity-preview-09-2026",
        input: {
          query: prompt,
          files: [
            { path: "index.js", content: "console.log('hello')" },
            { path: "package.json", content: "{}" }
          ]
        }
      });

      expect(result).toEqual(mockResponseData);
    });

    it("handles Google API errors properly and throws descriptive error with parsed message", async () => {
      const fakeApiKey = "invalid_key";
      const errorJson = {
        error: {
          code: 403,
          message: "API Key not valid or project quota exceeded"
        }
      };

      vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        return Response.json(errorJson, { status: 403 });
      });

      await expect(
        callAntigravityAgent(fakeApiKey, "test prompt")
      ).rejects.toThrow(
        "Google Antigravity API error (403): API Key not valid or project quota exceeded"
      );
    });
  });

  describe("Stateless MCP Transport (/mcp) with SDK v2", () => {
    it("handles tools/list over /mcp using createMcpHandler with Bearer token", async () => {
      const validToken = "alice:grant1:tokenMcpStateless12345678";
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(validToken));
      const tokenId = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      await env.OAUTH_KV.put(
        `token:alice:grant1:${tokenId}`,
        JSON.stringify({ expiresAt: Math.floor(Date.now() / 1000) + 3600 })
      );

      const request = new Request("http://example.com/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${validToken}`,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream"
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: {}
        })
      });

      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(200);
      const text = await response.text();
      expect(text).toContain("run_antigravity_agent");
    });

    it("executes run_antigravity_agent tool call over /mcp", async () => {
      const validToken = "alice:grant1:tokenToolCall1234567890123";
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(validToken));
      const tokenId = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      await env.OAUTH_KV.put(
        `token:alice:grant1:${tokenId}`,
        JSON.stringify({ expiresAt: Math.floor(Date.now() / 1000) + 3600 })
      );

      const mockResponseData = {
        interaction_id: "int-6789",
        status: "completed",
        output: { result: "Task completed successfully" }
      };

      vi.spyOn(globalThis, "fetch").mockImplementation(async (info, init) => {
        const urlStr = typeof info === "string" ? info : (info instanceof URL ? info.href : (info as any).url);
        if (urlStr.includes("interactions")) {
          return Response.json(mockResponseData, { status: 200 });
        }
        return new Response("Not found", { status: 404 });
      });

      const request = new Request("http://example.com/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${validToken}`,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream"
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "run_antigravity_agent",
            arguments: {
              task: "Fix a bug",
              contextFiles: { "test.py": "print('hello')" }
            }
          }
        })
      });

      const ctx = createExecutionContext();
      const response = await worker.fetch(request, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(200);
      const text = await response.text();
      expect(text).toContain("Task completed successfully");
    });

    it("rejects token with mismatched audience/resource on /mcp", async () => {
      const validToken = "alice:grant1:audienceMismatchToken12345";
      const encoder = new TextEncoder();
      const hash = await crypto.subtle.digest("SHA-256", encoder.encode(validToken));
      const tokenId = Array.from(new Uint8Array(hash))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      await env.OAUTH_KV.put(
        `token:alice:grant1:${tokenId}`,
        JSON.stringify({
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          audience: "https://other-service.com/mcp"
        })
      );

      const req = new Request("http://example.com/mcp", {
        method: "POST",
        headers: { Authorization: `Bearer ${validToken}` }
      });
      const ctx = createExecutionContext();
      const res = await worker.fetch(req, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(res.status).toBe(401);
      expect(res.headers.get("WWW-Authenticate")).toContain("invalid_audience");
    });
  });

  describe("Legacy SSE Transport Compatibility & Session Management", () => {
    it("routes SSE connection to DO, receives endpoint event, and allows message post", async () => {
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

      const sseReq = new Request("http://example.com/sse", {
        headers: { Authorization: `Bearer ${validToken}` }
      });
      const ctx1 = createExecutionContext();
      const sseRes = await worker.fetch(sseReq, env as any, ctx1);
      await waitOnExecutionContext(ctx1);

      expect(sseRes.status).toBe(200);

      const reader = sseRes.body?.getReader();
      const chunk = await reader?.read();
      const text = new TextDecoder().decode(chunk?.value);
      expect(text).toContain("event: endpoint");
      const sessionMatch = text.match(/sessionId=([a-zA-Z0-9-]+)/);
      expect(sessionMatch).not.toBeNull();
      const sessionId = sessionMatch![1];

      const postReq = new Request(`http://example.com/message?sessionId=${sessionId}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${validToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 })
      });
      const ctx2 = createExecutionContext();
      const postRes = await worker.fetch(postReq, env as any, ctx2);
      await waitOnExecutionContext(ctx2);

      expect(postRes.status).toBe(202);
      expect(await postRes.text()).toBe("Accepted");

      await reader?.cancel();
    });

    it("enforces session ownership and rejects another user attempting to post to legacy session", async () => {
      const aliceToken = "alice:grant1:aliceLegacyToken123456";
      const eveToken = "eve:grant2:eveLegacyToken12345678";

      const encoder = new TextEncoder();
      const hashAlice = await crypto.subtle.digest("SHA-256", encoder.encode(aliceToken));
      const tokenIdAlice = Array.from(new Uint8Array(hashAlice))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const hashEve = await crypto.subtle.digest("SHA-256", encoder.encode(eveToken));
      const tokenIdEve = Array.from(new Uint8Array(hashEve))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      await env.OAUTH_KV.put(
        `token:alice:grant1:${tokenIdAlice}`,
        JSON.stringify({ expiresAt: Math.floor(Date.now() / 1000) + 3600 })
      );
      await env.OAUTH_KV.put(
        `token:eve:grant2:${tokenIdEve}`,
        JSON.stringify({ expiresAt: Math.floor(Date.now() / 1000) + 3600 })
      );

      const sseReq = new Request("http://example.com/sse", {
        headers: { Authorization: `Bearer ${aliceToken}` }
      });
      const ctx1 = createExecutionContext();
      const sseRes = await worker.fetch(sseReq, env as any, ctx1);
      await waitOnExecutionContext(ctx1);

      const reader = sseRes.body?.getReader();
      const chunk = await reader?.read();
      const text = new TextDecoder().decode(chunk?.value);
      const sessionMatch = text.match(/sessionId=([a-zA-Z0-9-]+)/);
      const sessionId = sessionMatch![1];

      const eveReq = new Request(`http://example.com/message?sessionId=${sessionId}`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${eveToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 })
      });
      const ctx2 = createExecutionContext();
      const eveRes = await worker.fetch(eveReq, env as any, ctx2);
      await waitOnExecutionContext(ctx2);

      expect(eveRes.status).toBe(403);
      expect(await eveRes.text()).toContain("Forbidden: Session owned by another user");
      await reader?.cancel();
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
