import { describe, it, expect, vi, beforeEach } from "vitest";
import worker, { callAntigravityAgent, createAntigravityMcpServer } from "../src/index";
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
