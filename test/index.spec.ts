import { describe, it, expect, vi, beforeEach } from "vitest";
import worker, {
  callAntigravityAgent,
  createAntigravityMcpServer,
  authenticateAndAuthorizeUser,
  verifyCloudflareAccessJwt,
  validateBearerToken,
  getCanonicalResourceUri,
  validateWorkspaceFiles,
  createConsentCsrfToken
} from "../src/index";
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";

// Helpers for Cloudflare Access JWT testing
async function generateTestRsaKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
}

function base64UrlEncode(str: string): string {
  return btoa(str).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function signTestJwt(
  payload: Record<string, any>,
  privateKey: CryptoKey,
  kid = "test-key-id",
  alg = "RS256"
) {
  const header = { alg, typ: "JWT", kid };
  const hB64 = base64UrlEncode(JSON.stringify(header));
  const pB64 = base64UrlEncode(JSON.stringify(payload));
  const data = new TextEncoder().encode(`${hB64}.${pB64}`);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, data);
  const sB64 = base64UrlEncodeBytes(new Uint8Array(sig));
  return `${hB64}.${pB64}.${sB64}`;
}

describe("Cloudflare Workers MCP Server for Google Antigravity Agent", () => {
  beforeEach(async () => {
    vi.restoreAllMocks();
  });

  describe("1. Google Antigravity Agent API Integration", () => {
    it("sends prompt-only requests adhering to official Google Interactions API contract", async () => {
      const fakeApiKey = "AIzaSyFakePromptOnly123";
      const prompt = "Summarize top Hacker News stories";

      const mockResponseData = {
        id: "int-111",
        status: "completed",
        output_text: "Summary of stories..."
      };

      const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        return Response.json(mockResponseData, { status: 200 });
      });

      const result = await callAntigravityAgent(fakeApiKey, prompt);

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [calledUrl, calledInit] = fetchSpy.mock.calls[0];

      expect(calledUrl).toBe("https://generativelanguage.googleapis.com/v1beta/interactions");
      expect(calledInit?.method).toBe("POST");

      const headers = new Headers(calledInit?.headers);
      expect(headers.get("x-goog-api-key")).toBe(fakeApiKey);
      expect(headers.get("Content-Type")).toBe("application/json");

      const payload = JSON.parse(calledInit?.body as string);
      expect(payload).toEqual({
        agent: "antigravity-preview-09-2026",
        input: prompt,
        environment: "remote"
      });

      expect(result).toEqual(mockResponseData);
    });

    it("sends multi-file inline sources under environment.sources adhering to official schema", async () => {
      const fakeApiKey = "AIzaSyFakeMultiFiles123";
      const prompt = "Refactor code";
      const workspaceFiles = {
        "/workspace/src/app.js": "console.log('app');",
        "package.json": '{"name": "test"}'
      };

      const mockResponseData = {
        id: "int-222",
        status: "completed",
        output_text: "Refactored app.js"
      };

      const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        return Response.json(mockResponseData, { status: 200 });
      });

      const result = await callAntigravityAgent(fakeApiKey, prompt, workspaceFiles);

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [, calledInit] = fetchSpy.mock.calls[0];
      const payload = JSON.parse(calledInit?.body as string);

      expect(payload.agent).toBe("antigravity-preview-09-2026");
      expect(payload.input).toBe(prompt);
      expect(payload.environment).toEqual({
        type: "remote",
        sources: [
          {
            type: "inline",
            target: "/workspace/src/app.js",
            content: "console.log('app');"
          },
          {
            type: "inline",
            target: "/workspace/package.json",
            content: '{"name": "test"}'
          }
        ]
      });

      expect(result).toEqual(mockResponseData);
    });

    it("enforces workspace validation: rejects path traversal and payload limits", () => {
      expect(() =>
        validateWorkspaceFiles({ "../secret.txt": "evil" })
      ).toThrow("path traversal not permitted");

      expect(() =>
        validateWorkspaceFiles({ "   ": "empty path" })
      ).toThrow("path cannot be empty");

      const tooManyFiles: Record<string, string> = {};
      for (let i = 0; i < 51; i++) {
        tooManyFiles[`file_${i}.txt`] = "content";
      }
      expect(() => validateWorkspaceFiles(tooManyFiles)).toThrow("maximum 50 files allowed");
    });

    it("polls Google Interactions API when status is in_progress until completed", async () => {
      const fakeApiKey = "AIzaSyPollingKey";
      const prompt = "Long running task";

      let callCount = 0;
      vi.spyOn(globalThis, "fetch").mockImplementation(async (urlInfo) => {
        const urlStr = typeof urlInfo === "string" ? urlInfo : (urlInfo as any).url;
        callCount++;
        if (callCount === 1) {
          // Initial creation returning in_progress
          return Response.json(
            { id: "int-poll-123", status: "in_progress" },
            { status: 200 }
          );
        } else if (callCount === 2) {
          // Polling GET request returning completed
          expect(urlStr).toContain("/interactions/int-poll-123");
          return Response.json(
            { id: "int-poll-123", status: "completed", output_text: "Task finished!" },
            { status: 200 }
          );
        }
        return new Response("Not found", { status: 404 });
      });

      const result = await callAntigravityAgent(fakeApiKey, prompt, undefined, {
        maxPollIntervalMs: 10,
        maxPollTimeMs: 1000
      });

      expect(callCount).toBe(2);
      expect(result.status).toBe("completed");
      expect(result.output_text).toBe("Task finished!");
    });

    it("rejects incomplete interaction status when budget or token limit was reached", async () => {
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        return Response.json(
          { id: "int-incomplete", status: "incomplete" },
          { status: 200 }
        );
      });

      await expect(callAntigravityAgent("fake_key", "prompt")).rejects.toThrow(
        "Agent budget or token limit reached"
      );
    });

    it("rejects failed interaction status with error details", async () => {
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        return Response.json(
          {
            id: "int-fail",
            status: "failed",
            error: { message: "Sandbox execution crashed" }
          },
          { status: 200 }
        );
      });

      await expect(callAntigravityAgent("fake_key", "prompt")).rejects.toThrow(
        "Sandbox execution crashed"
      );
    });

    it("handles non-2xx HTTP errors and parses error message without exposing API key", async () => {
      const secretApiKey = "SECRET_GEMINI_KEY_999";
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        return Response.json(
          {
            error: {
              code: 403,
              message: `Invalid key ${secretApiKey}`
            }
          },
          { status: 403 }
        );
      });

      await expect(callAntigravityAgent(secretApiKey, "prompt")).rejects.toThrow(
        /Google Antigravity API error \(403\): Invalid key \[REDACTED_API_KEY\]/
      );
    });

    it("handles malformed JSON responses cleanly", async () => {
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        return new Response("<html><body>502 Bad Gateway</body></html>", {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      });

      await expect(callAntigravityAgent("fake_key", "prompt")).rejects.toThrow(
        "Received malformed JSON response"
      );
    });

    it("handles timeout and abort signals cleanly without exposing key", async () => {
      const secretKey = "SECRET_KEY_TIMEOUT";
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        throw new Error(`The operation was aborted for key ${secretKey}`);
      });

      await expect(callAntigravityAgent(secretKey, "prompt")).rejects.toThrow(
        /Google Antigravity request failed: The operation was aborted for key \[REDACTED_API_KEY\]/
      );
    });
  });

  describe("2. Cloudflare Access JWT Assertion & Identity Verification", () => {
    it("authenticates valid Cloudflare Access RS256 JWT assertion against JWKS", async () => {
      const keyPair = await generateTestRsaKeyPair();
      const publicJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as any;
      publicJwk.kid = "test-kid-1";
      publicJwk.alg = "RS256";

      const jwksJson = JSON.stringify({ keys: [publicJwk] });
      const now = Math.floor(Date.now() / 1000);
      const jwt = await signTestJwt(
        {
          email: "alice@example.com",
          iss: "https://my-team.cloudflareaccess.com",
          aud: ["my-access-aud-123"],
          exp: now + 3600
        },
        keyPair.privateKey,
        "test-kid-1"
      );

      const testEnv = {
        ...env,
        ALLOWED_USERS: "alice@example.com",
        CF_ACCESS_TEAM_DOMAIN: "my-team",
        CF_ACCESS_AUD: "my-access-aud-123",
        CF_ACCESS_JWKS_JSON: jwksJson
      };

      const result = await verifyCloudflareAccessJwt(jwt, testEnv as any);
      expect(result.valid).toBe(true);
      expect(result.email).toBe("alice@example.com");

      const req = new Request("http://example.com/oauth/authorize", {
        headers: { "Cf-Access-Jwt-Assertion": jwt }
      });
      const authResult = await authenticateAndAuthorizeUser(req, testEnv as any);
      expect(authResult.authorized).toBe(true);
      expect(authResult.userId).toBe("alice@example.com");
    });

    it("rejects JWT with invalid cryptographic signature", async () => {
      const keyPair1 = await generateTestRsaKeyPair();
      const keyPair2 = await generateTestRsaKeyPair();
      const publicJwk = (await crypto.subtle.exportKey("jwk", keyPair1.publicKey)) as any;
      publicJwk.kid = "test-kid-1";

      const jwksJson = JSON.stringify({ keys: [publicJwk] });
      // Sign with keyPair2 instead of keyPair1
      const jwt = await signTestJwt(
        {
          email: "alice@example.com",
          iss: "https://my-team.cloudflareaccess.com",
          exp: Math.floor(Date.now() / 1000) + 3600
        },
        keyPair2.privateKey,
        "test-kid-1"
      );

      const testEnv = {
        ...env,
        ALLOWED_USERS: "alice@example.com",
        CF_ACCESS_TEAM_DOMAIN: "my-team",
        CF_ACCESS_JWKS_JSON: jwksJson
      };

      const result = await verifyCloudflareAccessJwt(jwt, testEnv as any);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("Invalid JWT cryptographic signature");
    });

    it("rejects expired Cloudflare Access JWT", async () => {
      const keyPair = await generateTestRsaKeyPair();
      const publicJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as any;
      publicJwk.kid = "test-kid-1";

      const jwksJson = JSON.stringify({ keys: [publicJwk] });
      const now = Math.floor(Date.now() / 1000);
      const jwt = await signTestJwt(
        {
          email: "alice@example.com",
          iss: "https://my-team.cloudflareaccess.com",
          exp: now - 60 // expired 60 seconds ago
        },
        keyPair.privateKey,
        "test-kid-1"
      );

      const testEnv = {
        ...env,
        CF_ACCESS_TEAM_DOMAIN: "my-team",
        CF_ACCESS_JWKS_JSON: jwksJson
      };

      const result = await verifyCloudflareAccessJwt(jwt, testEnv as any);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("JWT has expired");
    });

    it("rejects JWT with mismatched audience or issuer", async () => {
      const keyPair = await generateTestRsaKeyPair();
      const publicJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as any;
      publicJwk.kid = "test-kid-1";

      const jwksJson = JSON.stringify({ keys: [publicJwk] });
      const now = Math.floor(Date.now() / 1000);
      const jwt = await signTestJwt(
        {
          email: "alice@example.com",
          iss: "https://wrong-team.cloudflareaccess.com",
          aud: ["wrong-aud"],
          exp: now + 3600
        },
        keyPair.privateKey,
        "test-kid-1"
      );

      const testEnv = {
        ...env,
        CF_ACCESS_TEAM_DOMAIN: "my-team",
        CF_ACCESS_AUD: "correct-aud",
        CF_ACCESS_JWKS_JSON: jwksJson
      };

      const result = await verifyCloudflareAccessJwt(jwt, testEnv as any);
      expect(result.valid).toBe(false);
    });

    it("never trusts Cf-Access-Authenticated-User-Email alone without verified assertion or HMAC", async () => {
      const testEnv = {
        ...env,
        ALLOWED_USERS: "alice@example.com",
        AUTH_SECRET: "hmac-secret"
      };

      const req = new Request("http://example.com/oauth/authorize", {
        headers: { "Cf-Access-Authenticated-User-Email": "alice@example.com" }
      });
      const result = await authenticateAndAuthorizeUser(req, testEnv as any);
      expect(result.authorized).toBe(false);
      expect(result.error).toContain("Missing authenticated user credentials or cryptographic signature");
    });
  });

  describe("3. OAuth 2.1 Consent, PKCE & Authorization", () => {
    it("handles dynamic client registration via /oauth/register", async () => {
      const clientPayload = {
        client_name: "Claude Code Client",
        redirect_uris: ["https://example.com/oauth-callback"],
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
      expect(data.client_name).toBe("Claude Code Client");
    });

    it("renders consent UI for untrusted dynamically registered client", async () => {
      const authSecret = "test-auth-secret";
      const testEnv = {
        ...env,
        ALLOWED_USERS: "user@example.com",
        AUTH_SECRET: authSecret,
        MCP_RESOURCE: "http://example.com/mcp"
      };

      // Register client
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Untrusted Client App",
          redirect_uris: ["https://example.com/cb"],
          token_endpoint_auth_method: "client_secret_basic"
        })
      });
      const ctx1 = createExecutionContext();
      const regRes = await worker.fetch(regReq, testEnv as any, ctx1);
      const regData = await regRes.json<any>();

      // Generate HMAC signature for user
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        enc.encode(authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode("user@example.com"));
      const sigHex = Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      // Authorization request with PKCE S256
      const codeVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      const verifierHash = await crypto.subtle.digest("SHA-256", enc.encode(codeVerifier));
      let binary = "";
      const hashBytes = new Uint8Array(verifierHash);
      for (let i = 0; i < hashBytes.byteLength; i++) {
        binary += String.fromCharCode(hashBytes[i]);
      }
      const codeChallenge = btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

      const authReq = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${regData.client_id}&redirect_uri=https://example.com/cb&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=mcp&state=mystate`,
        {
          headers: {
            "X-Auth-User": "user@example.com",
            "X-Auth-Signature": sigHex
          }
        }
      );
      const ctx2 = createExecutionContext();
      const authRes = await worker.fetch(authReq, testEnv as any, ctx2);
      await waitOnExecutionContext(ctx2);

      expect(authRes.status).toBe(200);
      const html = await authRes.text();
      expect(html).toContain("Authorize Untrusted Client App");
      expect(html).toContain("name=\"csrf_token\"");
      expect(html).toContain("name=\"consent_action\"");
    });

    it("rejects unauthorized scopes or invalid target resources", async () => {
      const authSecret = "test-auth-secret";
      const testEnv = {
        ...env,
        ALLOWED_USERS: "user@example.com",
        AUTH_SECRET: authSecret,
        MCP_RESOURCE: "http://example.com/mcp"
      };

      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Scope Client",
          redirect_uris: ["https://example.com/cb"],
          token_endpoint_auth_method: "client_secret_basic"
        })
      });
      const ctx = createExecutionContext();
      const regRes = await worker.fetch(regReq, testEnv as any, ctx);
      const regData = await regRes.json<any>();

      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        enc.encode(authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode("user@example.com"));
      const sigHex = Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      // Request with invalid scope
      const authReqInvalidScope = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${regData.client_id}&redirect_uri=https://example.com/cb&code_challenge=xyz&code_challenge_method=S256&scope=admin&state=s1`,
        {
          headers: {
            "X-Auth-User": "user@example.com",
            "X-Auth-Signature": sigHex
          }
        }
      );
      const resInvalidScope = await worker.fetch(authReqInvalidScope, testEnv as any, ctx);
      expect(resInvalidScope.status).toBe(302);
      expect(resInvalidScope.headers.get("Location")).toContain("error=invalid_scope");

      // Request with invalid resource target
      const authReqInvalidTarget = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${regData.client_id}&redirect_uri=https://example.com/cb&code_challenge=xyz&code_challenge_method=S256&scope=mcp&resource=https://other-domain.com/api&state=s2`,
        {
          headers: {
            "X-Auth-User": "user@example.com",
            "X-Auth-Signature": sigHex
          }
        }
      );
      const resInvalidTarget = await worker.fetch(authReqInvalidTarget, testEnv as any, ctx);
      expect(resInvalidTarget.status).toBe(302);
      expect(resInvalidTarget.headers.get("Location")).toContain("error=invalid_target");
    });
  });

  describe("4. End-to-End OAuth 2.1 + PKCE + Real Token Validation", () => {
    it("completes full OAuth 2.1 authorization code exchange and invokes /mcp successfully", async () => {
      const authSecret = "e2e-secret-key-12345";

      // 1. Register Client
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Claude Desktop Trusted",
          redirect_uris: ["https://example.com/oauth-callback"],
          token_endpoint_auth_method: "client_secret_post"
        })
      });
      const ctx1 = createExecutionContext();
      const regRes = await worker.fetch(regReq, env as any, ctx1);
      const regData = await regRes.json<any>();
      const clientId = regData.client_id;
      const clientSecret = regData.client_secret;

      const testEnv = {
        ...env,
        ALLOWED_USERS: "developer@example.com",
        AUTH_SECRET: authSecret,
        GEMINI_API_KEY: "test-fake-gemini-key",
        MCP_RESOURCE: "http://example.com/mcp",
        TRUSTED_CLIENT_IDS: clientId
      };

      // 2. PKCE Setup (code_verifier and code_challenge S256)
      const codeVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const enc = new TextEncoder();
      const hash = await crypto.subtle.digest("SHA-256", enc.encode(codeVerifier));
      let bin = "";
      const hBytes = new Uint8Array(hash);
      for (let i = 0; i < hBytes.byteLength; i++) {
        bin += String.fromCharCode(hBytes[i]);
      }
      const codeChallenge = btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

      // 3. Authenticate User with HMAC
      const key = await crypto.subtle.importKey(
        "raw",
        enc.encode(authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode("developer@example.com"));
      const sigHex = Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      // 4. Request Authorization Code
      const authReq = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/oauth-callback&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=mcp&state=e2estate&resource=http://example.com/mcp`,
        {
          headers: {
            "X-Auth-User": "developer@example.com",
            "X-Auth-Signature": sigHex
          }
        }
      );
      const ctx2 = createExecutionContext();
      const authRes = await worker.fetch(authReq, testEnv as any, ctx2);
      await waitOnExecutionContext(ctx2);

      expect(authRes.status).toBe(302);
      const location = authRes.headers.get("Location")!;
      expect(location).toContain("code=");
      const redirectUrl = new URL(location);
      const authCode = redirectUrl.searchParams.get("code")!;
      expect(authCode).toBeDefined();

      // 5. Exchange Authorization Code for Access Token
      const tokenBody = new URLSearchParams();
      tokenBody.set("grant_type", "authorization_code");
      tokenBody.set("client_id", clientId);
      tokenBody.set("client_secret", clientSecret);
      tokenBody.set("code", authCode);
      tokenBody.set("redirect_uri", "https://example.com/oauth-callback");
      tokenBody.set("code_verifier", codeVerifier);

      const tokenReq = new Request("http://example.com/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenBody.toString()
      });
      const ctx3 = createExecutionContext();
      const tokenRes = await worker.fetch(tokenReq, testEnv as any, ctx3);
      await waitOnExecutionContext(ctx3);

      expect(tokenRes.status).toBe(200);
      const tokenData = await tokenRes.json<any>();
      expect(tokenData.access_token).toBeDefined();
      expect(tokenData.token_type.toLowerCase()).toBe("bearer");
      expect(tokenData.scope).toBe("mcp");

      const issuedAccessToken = tokenData.access_token;

      // 6. Invoke /mcp with Real Issued Token: tools/list
      const listReq = new Request("http://example.com/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${issuedAccessToken}`,
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
      const ctx4 = createExecutionContext();
      const listRes = await worker.fetch(listReq, testEnv as any, ctx4);
      await waitOnExecutionContext(ctx4);

      expect(listRes.status).toBe(200);
      const listText = await listRes.text();
      expect(listText).toContain("run_antigravity_agent");

      // 7. Invoke /mcp with Real Issued Token: tools/call
      const mockGoogleResponse = {
        id: "int-e2e-ok",
        status: "completed",
        output_text: "E2E Antigravity task executed successfully"
      };
      vi.spyOn(globalThis, "fetch").mockImplementation(async (info) => {
        const urlStr = typeof info === "string" ? info : (info as any).url;
        if (urlStr.includes("interactions")) {
          return Response.json(mockGoogleResponse, { status: 200 });
        }
        return new Response("Not found", { status: 404 });
      });

      const callReq = new Request("http://example.com/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${issuedAccessToken}`,
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
              task: "Run comprehensive analysis",
              contextFiles: { "README.md": "# Test" }
            }
          }
        })
      });
      const ctx5 = createExecutionContext();
      const callRes = await worker.fetch(callReq, testEnv as any, ctx5);
      await waitOnExecutionContext(ctx5);

      expect(callRes.status).toBe(200);
      const callText = await callRes.text();
      expect(callText).toContain("E2E Antigravity task executed successfully");
    });

    it("rejects token with wrong audience or expired timestamp", async () => {
      const now = Math.floor(Date.now() / 1000);
      const userId = "alice";
      const grantId = "grant1";
      const secret = "secret1234567890abcdef12345678";
      const token = `${userId}:${grantId}:${secret}`;

      const enc = new TextEncoder();
      const hash = await crypto.subtle.digest("SHA-256", enc.encode(token));
      const tokenId = Array.from(new Uint8Array(hash))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      // 1. Expired token
      await env.OAUTH_KV.put(
        `token:${userId}:${grantId}:${tokenId}`,
        JSON.stringify({
          id: tokenId,
          userId,
          grantId,
          expiresAt: now - 100, // Expired
          audience: "http://example.com/mcp",
          grant: { scope: ["mcp"] }
        })
      );

      const expReq = new Request("http://example.com/mcp", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      const ctx1 = createExecutionContext();
      const expRes = await worker.fetch(expReq, env as any, ctx1);
      expect(expRes.status).toBe(401);
      expect(expRes.headers.get("WWW-Authenticate")).toContain("token_expired");

      // 2. Wrong audience
      await env.OAUTH_KV.put(
        `token:${userId}:${grantId}:${tokenId}`,
        JSON.stringify({
          id: tokenId,
          userId,
          grantId,
          expiresAt: now + 3600,
          audience: "https://other-service.com/mcp",
          grant: { scope: ["mcp"] }
        })
      );

      const audReq = new Request("http://example.com/mcp", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      const ctx2 = createExecutionContext();
      const audRes = await worker.fetch(audReq, env as any, ctx2);
      expect(audRes.status).toBe(401);
      expect(audRes.headers.get("WWW-Authenticate")).toContain("invalid_audience");

      // 3. Missing required scope
      await env.OAUTH_KV.put(
        `token:${userId}:${grantId}:${tokenId}`,
        JSON.stringify({
          id: tokenId,
          userId,
          grantId,
          expiresAt: now + 3600,
          audience: "http://example.com/mcp",
          grant: { scope: ["read:profile"] } // missing "mcp"
        })
      );

      const scopeReq = new Request("http://example.com/mcp", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      const ctx3 = createExecutionContext();
      const scopeRes = await worker.fetch(scopeReq, env as any, ctx3);
      expect(scopeRes.status).toBe(403);
      expect(scopeRes.headers.get("WWW-Authenticate")).toContain("insufficient_scope");
    });
  });

  describe("5. Protected Resource Metadata, Canonical URL & RFC 8414", () => {
    it("serves RFC 9728 metadata matching canonical URL and authorization server", async () => {
      const customEnv = {
        ...env,
        MCP_RESOURCE: "https://mcp.customdomain.com/mcp"
      };

      const req = new Request("https://mcp.customdomain.com/.well-known/oauth-protected-resource/mcp");
      const ctx = createExecutionContext();
      const res = await worker.fetch(req, customEnv as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(res.status).toBe(200);
      const data = await res.json<any>();
      expect(data.resource).toBe("https://mcp.customdomain.com/mcp");
      expect(data.authorization_servers).toEqual(["https://mcp.customdomain.com"]);
      expect(data.scopes_supported).toEqual(["mcp"]);
      expect(data.bearer_methods_supported).toEqual(["header"]);
    });

    it("serves RFC 8414 OAuth authorization server discovery", async () => {
      const req = new Request("http://example.com/.well-known/oauth-authorization-server");
      const ctx = createExecutionContext();
      const res = await worker.fetch(req, env as any, ctx);
      await waitOnExecutionContext(ctx);

      expect(res.status).toBe(200);
      const meta = await res.json<any>();
      expect(meta.token_endpoint).toBe("http://example.com/oauth/token");
      expect(meta.authorization_endpoint).toBe("http://example.com/oauth/authorize");
      expect(meta.registration_endpoint).toBe("http://example.com/oauth/register");
    });
  });

  describe("6. Host & Origin Protections and CORS Behavior", () => {
    it("rejects unauthorized Host headers when ALLOWED_HOSTS is configured", async () => {
      const testEnv = {
        ...env,
        ALLOWED_HOSTS: "legitimate-host.workers.dev"
      };

      const req = new Request("http://legitimate-host.workers.dev/mcp", {
        headers: { Host: "evil-rebinding-host.attacker.com" }
      });
      const ctx = createExecutionContext();
      const res = await worker.fetch(req, testEnv as any, ctx);
      expect(res.status).toBe(403);
      expect(await res.text()).toContain("Invalid Host header");
    });

    it("returns dynamic CORS headers reflecting allowed origin", async () => {
      const req = new Request("http://example.com/mcp", {
        method: "OPTIONS",
        headers: { Origin: "https://claude.ai" }
      });
      const ctx = createExecutionContext();
      const res = await worker.fetch(req, env as any, ctx);

      expect(res.status).toBe(204);
      expect(res.headers.get("Access-Control-Allow-Origin")).toBe("https://claude.ai");
      expect(res.headers.get("Vary")).toBe("Origin");
      expect(res.headers.get("Access-Control-Allow-Methods")).toContain("POST");
    });
  });

  describe("7. Optional Gated Live Integration Test", () => {
    const runLive = process.env.RUN_LIVE_TESTS === "true" && Boolean(process.env.GEMINI_API_KEY);
    it.skipIf(!runLive)("invokes real live Google Antigravity Agent API if credentials are provided", async () => {
      const realKey = process.env.GEMINI_API_KEY!;
      const result = await callAntigravityAgent(realKey, "Ping: return Hello World", undefined, {
        timeoutMs: 30000
      });
      expect(result).toBeDefined();
    });
  });
});
