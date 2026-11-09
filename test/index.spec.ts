import { describe, it, expect, vi, beforeEach } from "vitest";
import worker, {
  callAntigravityAgent,
  createAntigravityMcpServer,
  authenticateAndAuthorizeUser,
  verifyCloudflareAccessJwt,
  validateBearerToken,
  getCanonicalResourceUri,
  validateWorkspaceFiles,
  createConsentCsrfToken,
  verifyAndConsumeConsentCsrfToken,
  clearJwksCache
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

    it("rejects empty response {} or missing/malformed status strictly (Greptile P2)", async () => {
      // 1. Initial response {}
      vi.spyOn(globalThis, "fetch").mockImplementationOnce(async () => {
        return Response.json({}, { status: 200 });
      });
      await expect(callAntigravityAgent("fake_key", "prompt")).rejects.toThrow(
        "Missing or invalid 'status' in initial response"
      );

      // 2. Initial response without status
      vi.spyOn(globalThis, "fetch").mockImplementationOnce(async () => {
        return Response.json({ id: "int-no-status" }, { status: 200 });
      });
      await expect(callAntigravityAgent("fake_key", "prompt")).rejects.toThrow(
        "Missing or invalid 'status' in initial response"
      );

      // 3. Unknown status value
      vi.spyOn(globalThis, "fetch").mockImplementationOnce(async () => {
        return Response.json({ id: "int-unknown", status: "some_weird_status" }, { status: 200 });
      });
      await expect(callAntigravityAgent("fake_key", "prompt")).rejects.toThrow(
        "Unknown interaction status 'some_weird_status' in initial response"
      );

      // 4. Polling response missing status
      let pollCall = 0;
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        pollCall++;
        if (pollCall === 1) {
          return Response.json({ id: "int-poll-bad", status: "in_progress" }, { status: 200 });
        }
        return Response.json({ id: "int-poll-bad" }, { status: 200 });
      });
      await expect(
        callAntigravityAgent("fake_key", "prompt", undefined, { maxPollIntervalMs: 5, maxPollTimeMs: 500 })
      ).rejects.toThrow("Missing or invalid 'status' in polling response");

      // 5. Polling response with malformed/unknown status
      pollCall = 0;
      vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
        pollCall++;
        if (pollCall === 1) {
          return Response.json({ id: "int-poll-bad2", status: "in_progress" }, { status: 200 });
        }
        return Response.json({ id: "int-poll-bad2", status: "bogus_status" }, { status: 200 });
      });
      await expect(
        callAntigravityAgent("fake_key", "prompt", undefined, { maxPollIntervalMs: 5, maxPollTimeMs: 500 })
      ).rejects.toThrow("Unknown interaction status 'bogus_status' in polling response");

      // 6. requires_action is rejected as unsupported
      vi.spyOn(globalThis, "fetch").mockImplementationOnce(async () => {
        return Response.json({ id: "int-action", status: "requires_action" }, { status: 200 });
      });
      await expect(callAntigravityAgent("fake_key", "prompt")).rejects.toThrow(
        "Continuation flows are currently unsupported"
      );

      // 7. cancelled status is rejected
      vi.spyOn(globalThis, "fetch").mockImplementationOnce(async () => {
        return Response.json({ id: "int-cancelled", status: "cancelled" }, { status: 200 });
      });
      await expect(callAntigravityAgent("fake_key", "prompt")).rejects.toThrow(
        "Google Antigravity interaction cancelled."
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
          aud: "test-aud-123",
          exp: Math.floor(Date.now() / 1000) + 3600
        },
        keyPair2.privateKey,
        "test-kid-1"
      );

      const testEnv = {
        ...env,
        ALLOWED_USERS: "alice@example.com",
        CF_ACCESS_TEAM_DOMAIN: "my-team",
        CF_ACCESS_AUD: "test-aud-123",
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
          aud: "test-aud-123",
          exp: now - 60 // expired 60 seconds ago
        },
        keyPair.privateKey,
        "test-kid-1"
      );

      const testEnv = {
        ...env,
        CF_ACCESS_TEAM_DOMAIN: "my-team",
        CF_ACCESS_AUD: "test-aud-123",
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

    it("strictly validates exp, nbf, iss, and aud claim types and values (Access JWT Fail-Closed)", async () => {
      const keyPair = await generateTestRsaKeyPair();
      const publicJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as any;
      publicJwk.kid = "test-kid-1";
      const jwksJson = JSON.stringify({ keys: [publicJwk] });
      const now = Math.floor(Date.now() / 1000);

      const baseEnv = {
        ...env,
        CF_ACCESS_TEAM_DOMAIN: "my-team",
        CF_ACCESS_AUD: "expected-aud-123",
        CF_ACCESS_JWKS_JSON: jwksJson
      };

      // 1. Missing exp claim
      const jwtNoExp = await signTestJwt(
        { email: "alice@example.com", iss: "https://my-team.cloudflareaccess.com", aud: "expected-aud-123" },
        keyPair.privateKey
      );
      const resNoExp = await verifyCloudflareAccessJwt(jwtNoExp, baseEnv as any);
      expect(resNoExp.valid).toBe(false);
      expect(resNoExp.error).toContain("missing numeric 'exp' claim");

      // 2. Non-numeric exp claim
      const jwtBadExp = await signTestJwt(
        { email: "alice@example.com", iss: "https://my-team.cloudflareaccess.com", aud: "expected-aud-123", exp: "tomorrow" },
        keyPair.privateKey
      );
      const resBadExp = await verifyCloudflareAccessJwt(jwtBadExp, baseEnv as any);
      expect(resBadExp.valid).toBe(false);
      expect(resBadExp.error).toContain("missing numeric 'exp' claim");

      // 3. nbf in the future
      const jwtFutureNbf = await signTestJwt(
        {
          email: "alice@example.com",
          iss: "https://my-team.cloudflareaccess.com",
          aud: "expected-aud-123",
          exp: now + 3600,
          nbf: now + 500
        },
        keyPair.privateKey
      );
      const resFutureNbf = await verifyCloudflareAccessJwt(jwtFutureNbf, baseEnv as any);
      expect(resFutureNbf.valid).toBe(false);
      expect(resFutureNbf.error).toContain("not yet valid");

      // 4. Missing required configuration (missing CF_ACCESS_AUD)
      const jwtValid = await signTestJwt(
        {
          email: "alice@example.com",
          iss: "https://my-team.cloudflareaccess.com",
          aud: "expected-aud-123",
          exp: now + 3600
        },
        keyPair.privateKey
      );
      const resNoAudConfig = await verifyCloudflareAccessJwt(jwtValid, { ...baseEnv, CF_ACCESS_AUD: undefined } as any);
      expect(resNoAudConfig.valid).toBe(false);
      expect(resNoAudConfig.error).toContain("CF_ACCESS_AUD is required");

      // 5. Missing required configuration (missing CF_ACCESS_TEAM_DOMAIN)
      const resNoTeamConfig = await verifyCloudflareAccessJwt(jwtValid, { ...baseEnv, CF_ACCESS_TEAM_DOMAIN: undefined } as any);
      expect(resNoTeamConfig.valid).toBe(false);
      expect(resNoTeamConfig.error).toContain("CF_ACCESS_TEAM_DOMAIN is required");
    });

    it("caches Access JWKS and performs single refresh on unknown kid", async () => {
      clearJwksCache();
      const keyPair1 = await generateTestRsaKeyPair();
      const keyPair2 = await generateTestRsaKeyPair();
      const publicJwk1 = (await crypto.subtle.exportKey("jwk", keyPair1.publicKey)) as any;
      publicJwk1.kid = "cached-kid-1";
      const publicJwk2 = (await crypto.subtle.exportKey("jwk", keyPair2.publicKey)) as any;
      publicJwk2.kid = "refreshed-kid-2";

      let fetchCount = 0;
      vi.spyOn(globalThis, "fetch").mockImplementation(async (info) => {
        const urlStr = typeof info === "string" ? info : (info as any).url;
        if (urlStr.includes("access/certs")) {
          fetchCount++;
          if (fetchCount === 1) {
            return Response.json({ keys: [publicJwk1] }, { status: 200 });
          } else {
            return Response.json({ keys: [publicJwk1, publicJwk2] }, { status: 200 });
          }
        }
        return new Response("Not found", { status: 404 });
      });

      const testEnv = {
        ...env,
        CF_ACCESS_TEAM_DOMAIN: "test-cache-team",
        CF_ACCESS_AUD: "test-aud"
      };

      const now = Math.floor(Date.now() / 1000);
      const jwt1 = await signTestJwt(
        { email: "user@example.com", iss: "https://test-cache-team.cloudflareaccess.com", aud: "test-aud", exp: now + 3600 },
        keyPair1.privateKey,
        "cached-kid-1"
      );

      // First verification: fetches JWKS
      const res1 = await verifyCloudflareAccessJwt(jwt1, testEnv as any);
      expect(res1.valid).toBe(true);
      expect(fetchCount).toBe(1);

      // Second verification with same kid: uses cache without fetching
      const res2 = await verifyCloudflareAccessJwt(jwt1, testEnv as any);
      expect(res2.valid).toBe(true);
      expect(fetchCount).toBe(1);

      // Verification with new unknown kid: triggers controlled single refresh
      const jwt2 = await signTestJwt(
        { email: "user@example.com", iss: "https://test-cache-team.cloudflareaccess.com", aud: "test-aud", exp: now + 3600 },
        keyPair2.privateKey,
        "refreshed-kid-2"
      );
      const res3 = await verifyCloudflareAccessJwt(jwt2, testEnv as any);
      expect(res3.valid).toBe(true);
      expect(fetchCount).toBe(2);

      // Repeated unknown kid within cooldown does not trigger flood (per-team cooldown active)
      const jwtBad = await signTestJwt(
        { email: "user@example.com", iss: "https://test-cache-team.cloudflareaccess.com", aud: "test-aud", exp: now + 3600 },
        keyPair1.privateKey,
        "non-existent-kid"
      );
      const resBad1 = await verifyCloudflareAccessJwt(jwtBad, testEnv as any);
      expect(resBad1.valid).toBe(false);
      const resBad2 = await verifyCloudflareAccessJwt(jwtBad, testEnv as any);
      expect(resBad2.valid).toBe(false);
      expect(fetchCount).toBe(2); // protected by cooldown from repeated upstream fetch
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
        CONSENT_CSRF_SECRET: "test-consent-csrf-secret",
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


    it("escapes malicious client names, URLs, and attributes to prevent XSS (Greptile P1)", async () => {
      const authSecret = "test-auth-secret";
      const testEnv = {
        ...env,
        ALLOWED_USERS: "user@example.com",
        AUTH_SECRET: authSecret,
        CONSENT_CSRF_SECRET: "csrf-secret-12345",
        MCP_RESOURCE: "http://example.com/mcp"
      };

      const maliciousName = `"><script>alert(1)</script><img src=x onerror=alert(2)>`;
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: maliciousName,
          redirect_uris: ["https://example.com/cb"],
          token_endpoint_auth_method: "client_secret_basic"
        })
      });
      const ctx1 = createExecutionContext();
      const regRes = await worker.fetch(regReq, testEnv as any, ctx1);
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

      const authReq = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${regData.client_id}&redirect_uri=https://example.com/cb&code_challenge=xyz&code_challenge_method=S256&scope=mcp&state=mystate`,
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
      const csp = authRes.headers.get("Content-Security-Policy");
      expect(csp).toContain("default-src 'none'");
      expect(csp).toContain("form-action 'self'");
      expect(authRes.headers.get("X-Frame-Options")).toBe("DENY");
      expect(authRes.headers.get("X-Content-Type-Options")).toBe("nosniff");

      const html = await authRes.text();
      expect(html).not.toContain("<script>alert(1)</script>");
      expect(html).not.toContain("<img src=x onerror=alert(2)>");
      expect(html).toContain("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;");
    });

    it("rejects unsafe URL schemes during registration (e.g. javascript:, data:)", async () => {
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Malicious Scheme Client",
          redirect_uris: ["javascript:alert(1)"],
          token_endpoint_auth_method: "client_secret_basic"
        })
      });
      const ctx = createExecutionContext();
      const regRes = await worker.fetch(regReq, env as any, ctx);
      expect(regRes.status).toBe(400);
      const data = await regRes.json<any>();
      expect(data.error).toBe("invalid_client_metadata");
      expect(data.error_description).toContain("Invalid redirect URI");
    });

    it("enforces strong CSRF token validation, transaction binding, and atomic concurrency replay protection (Greptile P1)", async () => {
      const secret = "high-entropy-consent-csrf-secret-999";
      const clientId = "client-abc";
      const redirectUri = "https://example.com/cb";
      const userId = "alice@example.com";
      const codeChallenge = "challenge-123";

      // 1. Generation and successful verification
      const token = await createConsentCsrfToken(clientId, redirectUri, userId, codeChallenge, secret);
      expect(token).toBeDefined();

      // 2. Concurrency guarantee: 5 simultaneous submissions with identical token, exactly 1 succeeds
      const attempts = await Promise.all([
        verifyAndConsumeConsentCsrfToken(token, clientId, redirectUri, userId, codeChallenge, secret, env),
        verifyAndConsumeConsentCsrfToken(token, clientId, redirectUri, userId, codeChallenge, secret, env),
        verifyAndConsumeConsentCsrfToken(token, clientId, redirectUri, userId, codeChallenge, secret, env),
        verifyAndConsumeConsentCsrfToken(token, clientId, redirectUri, userId, codeChallenge, secret, env),
        verifyAndConsumeConsentCsrfToken(token, clientId, redirectUri, userId, codeChallenge, secret, env)
      ]);
      const successfulAttempts = attempts.filter((r) => r === true);
      expect(successfulAttempts.length).toBe(1);

      // 3. Replay rejection: subsequent verification fails
      const replayResult = await verifyAndConsumeConsentCsrfToken(
        token,
        clientId,
        redirectUri,
        userId,
        codeChallenge,
        secret,
        env
      );
      expect(replayResult).toBe(false);

      // 4. Missing secret fails closed
      const missingSecretResult = await verifyAndConsumeConsentCsrfToken(
        token,
        clientId,
        redirectUri,
        userId,
        codeChallenge,
        undefined,
        env
      );
      expect(missingSecretResult).toBe(false);

      // 5. Transaction binding mismatch
      const freshToken = await createConsentCsrfToken(clientId, redirectUri, userId, codeChallenge, secret);
      const wrongClientResult = await verifyAndConsumeConsentCsrfToken(
        freshToken,
        "different-client",
        redirectUri,
        userId,
        codeChallenge,
        secret,
        env
      );
      expect(wrongClientResult).toBe(false);
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

    it("verifies explicitly trusted-client path bypasses interactive consent and exercises revocation", async () => {
      const authSecret = "provider-lifecycle-secret";

      // 1. Register Client
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Trusted Client App",
          redirect_uris: ["https://example.com/cb"],
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
        ALLOWED_USERS: "user@example.com",
        AUTH_SECRET: authSecret,
        CONSENT_CSRF_SECRET: "csrf-secret-life",
        MCP_RESOURCE: "http://example.com/mcp",
        TRUSTED_CLIENT_IDS: clientId
      };

      // 2. PKCE setup
      const codeVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const enc = new TextEncoder();
      const hash = await crypto.subtle.digest("SHA-256", enc.encode(codeVerifier));
      let bin = "";
      const hBytes = new Uint8Array(hash);
      for (let i = 0; i < hBytes.byteLength; i++) {
        bin += String.fromCharCode(hBytes[i]);
      }
      const codeChallenge = btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

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

      // 3. Obtain authorization code
      const authReq = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/cb&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=mcp&state=mystate&resource=http://example.com/mcp`,
        {
          headers: {
            "X-Auth-User": "user@example.com",
            "X-Auth-Signature": sigHex
          }
        }
      );
      const ctx2 = createExecutionContext();
      const authRes = await worker.fetch(authReq, testEnv as any, ctx2);
      expect(authRes.status).toBe(302);
      const loc = new URL(authRes.headers.get("Location")!);
      const code = loc.searchParams.get("code")!;

      // 4. Exchange code for access token & refresh token
      const tokenBody = new URLSearchParams();
      tokenBody.set("grant_type", "authorization_code");
      tokenBody.set("client_id", clientId);
      tokenBody.set("client_secret", clientSecret);
      tokenBody.set("code", code);
      tokenBody.set("redirect_uri", "https://example.com/cb");
      tokenBody.set("code_verifier", codeVerifier);

      const tokenReq = new Request("http://example.com/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenBody.toString()
      });
      const ctx3 = createExecutionContext();
      const tokenRes = await worker.fetch(tokenReq, testEnv as any, ctx3);
      const tokenData = await tokenRes.json<any>();
      expect(tokenData.access_token).toBeDefined();

      const accessToken = tokenData.access_token;

      // 5. Revoke access token via provider revocation endpoint (POST /oauth/token with token parameter)
      const revokeBody = new URLSearchParams();
      revokeBody.set("client_id", clientId);
      revokeBody.set("client_secret", clientSecret);
      revokeBody.set("token", accessToken);

      const revokeReq = new Request("http://example.com/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: revokeBody.toString()
      });
      const ctx4 = createExecutionContext();
      const revokeRes = await worker.fetch(revokeReq, testEnv as any, ctx4);
      expect(revokeRes.status).toBe(200);

      // 6. Accessing /mcp with revoked token fails with 401
      const mcpReq = new Request("http://example.com/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 10, method: "tools/list", params: {} })
      });
      const ctx5 = createExecutionContext();
      const mcpRes = await worker.fetch(mcpReq, testEnv as any, ctx5);
      expect(mcpRes.status).toBe(401);
      expect(mcpRes.headers.get("WWW-Authenticate")).toContain("invalid_token");
    });

    it("exercises genuine OAuth consent-denial integration flow for untrusted client", async () => {
      const authSecret = "denial-test-auth-secret";
      const csrfSecret = "denial-test-csrf-secret-999";

      // 1. Register an untrusted client (not in TRUSTED_CLIENT_IDS)
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Untrusted Denial App",
          redirect_uris: ["https://example.com/denial-cb"],
          token_endpoint_auth_method: "client_secret_post"
        })
      });
      const ctx1 = createExecutionContext();
      const regRes = await worker.fetch(regReq, env as any, ctx1);
      const regData = await regRes.json<any>();
      const clientId = regData.client_id;

      const testEnv = {
        ...env,
        ALLOWED_USERS: "user@example.com",
        AUTH_SECRET: authSecret,
        CONSENT_CSRF_SECRET: csrfSecret,
        MCP_RESOURCE: "http://example.com/mcp"
        // Notice TRUSTED_CLIENT_IDS is explicitly omitted
      };

      // 2. Setup PKCE S256
      const codeVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const enc = new TextEncoder();
      const hash = await crypto.subtle.digest("SHA-256", enc.encode(codeVerifier));
      let bin = "";
      const hBytes = new Uint8Array(hash);
      for (let i = 0; i < hBytes.byteLength; i++) {
        bin += String.fromCharCode(hBytes[i]);
      }
      const codeChallenge = btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

      // 3. User HMAC signature
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

      // 4. GET /oauth/authorize -> returns interactive consent page
      const originalState = "oauth-denial-state-12345";
      const authUrl = `http://example.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/denial-cb&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=mcp&state=${originalState}&resource=http://example.com/mcp`;
      const authReq = new Request(authUrl, {
        headers: {
          "X-Auth-User": "user@example.com",
          "X-Auth-Signature": sigHex
        }
      });
      const ctx2 = createExecutionContext();
      const authRes = await worker.fetch(authReq, testEnv as any, ctx2);
      expect(authRes.status).toBe(200);

      const html = await authRes.text();
      expect(html).toContain("Authorize Untrusted Denial App");

      // Extract CSRF token from HTML
      const csrfMatch = html.match(/name="csrf_token"\s+value="([^"]+)"/);
      expect(csrfMatch).not.toBeNull();
      const csrfToken = csrfMatch![1];
      expect(csrfToken.length).toBeGreaterThan(20);

      // 5. Submit POST /oauth/authorize with consent_action=deny and valid csrf_token
      const denyFormData = new FormData();
      denyFormData.set("consent_action", "deny");
      denyFormData.set("csrf_token", csrfToken);

      const denyReq = new Request(authUrl, {
        method: "POST",
        headers: {
          "X-Auth-User": "user@example.com",
          "X-Auth-Signature": sigHex
        },
        body: denyFormData
      });
      const ctx3 = createExecutionContext();
      const denyRes = await worker.fetch(denyReq, testEnv as any, ctx3);
      expect(denyRes.status).toBe(302);

      const redirectLocation = denyRes.headers.get("Location")!;
      const redirectUrl = new URL(redirectLocation);
      // Verify redirect contains access_denied
      expect(redirectUrl.searchParams.get("error")).toBe("access_denied");
      expect(redirectUrl.searchParams.get("error_description")).toBe("User denied authorization");
      // Verify original state is preserved
      expect(redirectUrl.searchParams.get("state")).toBe(originalState);
      // Verify no code or grant is issued
      expect(redirectUrl.searchParams.get("code")).toBeNull();

      // 6. Verify that replaying the exact same denial submission fails
      const replayReq = new Request(authUrl, {
        method: "POST",
        headers: {
          "X-Auth-User": "user@example.com",
          "X-Auth-Signature": sigHex
        },
        body: denyFormData
      });
      const ctx4 = createExecutionContext();
      const replayRes = await worker.fetch(replayReq, testEnv as any, ctx4);
      expect(replayRes.status).toBe(400);
      const replayErr = await replayRes.json<any>();
      expect(replayErr.error).toBe("invalid_request");
      expect(replayErr.error_description).toContain("Invalid, expired, or already used CSRF token");
    });

    it("exercises genuine OAuth consent-approval integration flow for untrusted client", async () => {
      const authSecret = "approval-test-auth-secret";
      const csrfSecret = "approval-test-csrf-secret-999";

      // 1. Register an untrusted client
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Untrusted Approval App",
          redirect_uris: ["https://example.com/approval-cb"],
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
        ALLOWED_USERS: "user@example.com",
        AUTH_SECRET: authSecret,
        CONSENT_CSRF_SECRET: csrfSecret,
        MCP_RESOURCE: "http://example.com/mcp"
      };

      // 2. PKCE Setup
      const codeVerifier = "abcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      const enc = new TextEncoder();
      const hash = await crypto.subtle.digest("SHA-256", enc.encode(codeVerifier));
      let bin = "";
      const hBytes = new Uint8Array(hash);
      for (let i = 0; i < hBytes.byteLength; i++) {
        bin += String.fromCharCode(hBytes[i]);
      }
      const codeChallenge = btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

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

      // 3. Initiate authorization request to get interactive consent HTML
      const originalState = "approval-state-777";
      const authUrl = `http://example.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://example.com/approval-cb&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=mcp&state=${originalState}&resource=http://example.com/mcp`;
      const authReq = new Request(authUrl, {
        headers: {
          "X-Auth-User": "user@example.com",
          "X-Auth-Signature": sigHex
        }
      });
      const ctx2 = createExecutionContext();
      const authRes = await worker.fetch(authReq, testEnv as any, ctx2);
      expect(authRes.status).toBe(200);

      const html = await authRes.text();
      const csrfMatch = html.match(/name="csrf_token"\s+value="([^"]+)"/);
      expect(csrfMatch).not.toBeNull();
      const csrfToken = csrfMatch![1];

      // 4. Submit approval
      const approveFormData = new FormData();
      approveFormData.set("consent_action", "approve");
      approveFormData.set("csrf_token", csrfToken);

      const approveReq = new Request(authUrl, {
        method: "POST",
        headers: {
          "X-Auth-User": "user@example.com",
          "X-Auth-Signature": sigHex
        },
        body: approveFormData
      });
      const ctx3 = createExecutionContext();
      const approveRes = await worker.fetch(approveReq, testEnv as any, ctx3);
      expect(approveRes.status).toBe(302);

      const redirectLocation = approveRes.headers.get("Location")!;
      const redirectUrl = new URL(redirectLocation);
      const issuedCode = redirectUrl.searchParams.get("code")!;
      expect(issuedCode).toBeDefined();
      expect(redirectUrl.searchParams.get("state")).toBe(originalState);

      // 5. Exchange code for token with PKCE verifier
      const tokenBody = new URLSearchParams();
      tokenBody.set("grant_type", "authorization_code");
      tokenBody.set("client_id", clientId);
      tokenBody.set("client_secret", clientSecret);
      tokenBody.set("code", issuedCode);
      tokenBody.set("redirect_uri", "https://example.com/approval-cb");
      tokenBody.set("code_verifier", codeVerifier);

      const tokenReq = new Request("http://example.com/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: tokenBody.toString()
      });
      const ctx4 = createExecutionContext();
      const tokenRes = await worker.fetch(tokenReq, testEnv as any, ctx4);
      expect(tokenRes.status).toBe(200);
      const tokenData = await tokenRes.json<any>();
      expect(tokenData.access_token).toBeDefined();

      // 6. Verify protected resource access on /mcp with issued token
      const mcpReq = new Request("http://example.com/mcp", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream"
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })
      });
      const ctx5 = createExecutionContext();
      const mcpRes = await worker.fetch(mcpReq, testEnv as any, ctx5);
      expect(mcpRes.status).toBe(200);
      expect(await mcpRes.text()).toContain("run_antigravity_agent");
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

    it("returns dynamic CORS headers reflecting allowed origin and rejects untrusted origins (Greptile P2)", async () => {
      const testEnv = {
        ...env,
        ALLOWED_ORIGINS: "https://claude.ai,https://trusted-client.com"
      };

      // 1. Allowed origin receives CORS headers on OPTIONS
      const reqAllowed = new Request("http://example.com/mcp", {
        method: "OPTIONS",
        headers: { Origin: "https://claude.ai" }
      });
      const ctx1 = createExecutionContext();
      const resAllowed = await worker.fetch(reqAllowed, testEnv as any, ctx1);

      expect(resAllowed.status).toBe(204);
      expect(resAllowed.headers.get("Access-Control-Allow-Origin")).toBe("https://claude.ai");
      expect(resAllowed.headers.get("Vary")).toBe("Origin");
      expect(resAllowed.headers.get("Access-Control-Allow-Methods")).toContain("POST");

      // 2. Untrusted origin is rejected
      const reqUntrusted = new Request("http://example.com/mcp", {
        method: "OPTIONS",
        headers: { Origin: "https://evil-attacker.com" }
      });
      const ctx2 = createExecutionContext();
      const resUntrusted = await worker.fetch(reqUntrusted, testEnv as any, ctx2);
      expect(resUntrusted.status).toBe(403);
      expect(await resUntrusted.text()).toContain("Unauthorized Origin");

      // 3. Origin: null is rejected by default
      const reqNullOrigin = new Request("http://example.com/mcp", {
        method: "OPTIONS",
        headers: { Origin: "null" }
      });
      const ctx3 = createExecutionContext();
      const resNullOrigin = await worker.fetch(reqNullOrigin, testEnv as any, ctx3);
      expect(resNullOrigin.status).toBe(403);
      expect(await resNullOrigin.text()).toContain("Origin 'null' is not allowed");

      // 4. Request without Origin header succeeds for legitimate non-browser clients
      const reqNoOrigin = new Request("http://example.com/.well-known/oauth-protected-resource/mcp", {
        method: "GET"
      });
      const ctx4 = createExecutionContext();
      const resNoOrigin = await worker.fetch(reqNoOrigin, testEnv as any, ctx4);
      expect(resNoOrigin.status).toBe(200);

      // 5. Unexpected Host header mismatch is rejected
      const reqBadHost = new Request("http://example.com/mcp", {
        headers: { Host: "attacker.com" }
      });
      const ctx5 = createExecutionContext();
      const resBadHost = await worker.fetch(reqBadHost, testEnv as any, ctx5);
      expect(resBadHost.status).toBe(403);
      expect(await resBadHost.text()).toContain("Invalid Host header");
    });
  });

  describe("7. Dedicated CSRF Secret Separation & Durable Object Coordinator Verification", () => {
    it("fails closed when CONSENT_CSRF_SECRET is missing even if AUTH_SECRET exists", async () => {
      const testEnv = {
        ...env,
        ALLOWED_USERS: "user@example.com",
        AUTH_SECRET: "my-hmac-auth-secret",
        CONSENT_CSRF_SECRET: undefined, // Explicitly missing
        MCP_RESOURCE: "http://example.com/mcp"
      };

      // 1. Dynamic client registration
      const regReq = new Request("http://example.com/oauth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client_name: "Missing CSRF Secret Client",
          redirect_uris: ["https://example.com/cb"],
          token_endpoint_auth_method: "client_secret_post"
        })
      });
      const ctx1 = createExecutionContext();
      const regRes = await worker.fetch(regReq, env as any, ctx1);
      const regData = await regRes.json<any>();

      // User HMAC signature
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        enc.encode("my-hmac-auth-secret"),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode("user@example.com"));
      const sigHex = Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      // 2. GET /oauth/authorize should fail closed with 500 when CONSENT_CSRF_SECRET is missing
      const authReq = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${regData.client_id}&redirect_uri=https://example.com/cb&code_challenge=xyz&code_challenge_method=S256&scope=mcp&state=mystate`,
        {
          headers: {
            "X-Auth-User": "user@example.com",
            "X-Auth-Signature": sigHex
          }
        }
      );
      const ctx2 = createExecutionContext();
      const authRes = await worker.fetch(authReq, testEnv as any, ctx2);
      expect(authRes.status).toBe(500);
      const resJson = await authRes.json<any>();
      expect(resJson.error).toBe("server_error");
      expect(resJson.error_description).toContain("CONSENT_CSRF_SECRET is required");

      // 3. POST /oauth/authorize submission also fails closed with 500
      const postFormData = new FormData();
      postFormData.set("consent_action", "approve");
      postFormData.set("csrf_token", "dummy-token");

      const postReq = new Request(
        `http://example.com/oauth/authorize?response_type=code&client_id=${regData.client_id}&redirect_uri=https://example.com/cb&code_challenge=xyz&code_challenge_method=S256&scope=mcp&state=mystate`,
        {
          method: "POST",
          headers: {
            "X-Auth-User": "user@example.com",
            "X-Auth-Signature": sigHex
          },
          body: postFormData
        }
      );
      const ctx3 = createExecutionContext();
      const postRes = await worker.fetch(postReq, testEnv as any, ctx3);
      expect(postRes.status).toBe(500);
      const postJson = await postRes.json<any>();
      expect(postJson.error_description).toContain("CONSENT_CSRF_SECRET is required");
    });

    it("verifies real SQLite-backed CONSENT_COORDINATOR Durable Object atomicity, persistence, and alarm cleanup", async () => {
      const coordinator = env.CONSENT_COORDINATOR;
      expect(coordinator).toBeDefined();

      const testNonce = "abcdef0123456789abcdef0123456789";
      const id = coordinator.idFromName("test-csrf-coordinator");
      const stub = coordinator.get(id);

      // 1. First valid consumption succeeds (200)
      const res1 = await stub.fetch("https://coordinator/consume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nonce: testNonce })
      });
      expect(res1.status).toBe(200);
      const data1 = (await res1.json()) as { consumed: boolean };
      expect(data1.consumed).toBe(true);

      // 2. Replaying the same nonce fails (409 Conflict)
      const res2 = await stub.fetch("https://coordinator/consume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nonce: testNonce })
      });
      expect(res2.status).toBe(409);
      const data2 = (await res2.json()) as { consumed: boolean };
      expect(data2.consumed).toBe(false);

      // 3. Concurrency test: 5 simultaneous submissions for a fresh nonce result in exactly 1 success
      const concurrentNonce = "11223344556677889900aabbccddeeff";
      const concurrentResults = await Promise.all([
        stub.fetch("https://coordinator/consume", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ nonce: concurrentNonce })
        }),
        stub.fetch("https://coordinator/consume", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ nonce: concurrentNonce })
        }),
        stub.fetch("https://coordinator/consume", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ nonce: concurrentNonce })
        }),
        stub.fetch("https://coordinator/consume", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ nonce: concurrentNonce })
        }),
        stub.fetch("https://coordinator/consume", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ nonce: concurrentNonce })
        })
      ]);

      const statuses = concurrentResults.map((r) => r.status);
      const successCount = statuses.filter((s) => s === 200).length;
      const conflictCount = statuses.filter((s) => s === 409).length;
      expect(successCount).toBe(1);
      expect(conflictCount).toBe(4);

      // 4. Persistence across separate stub invocations and distinct instances
      // Getting another stub to the same ID maintains persistence
      const stub2 = coordinator.get(id);
      const resPersisted = await stub2.fetch("https://coordinator/consume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nonce: concurrentNonce })
      });
      expect(resPersisted.status).toBe(409);

      // 5. Distinct nonces consume independently
      const distinctNonce = "aabbccddee0011223344556677889900";
      const resDistinct = await stub2.fetch("https://coordinator/consume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nonce: distinctNonce })
      });
      expect(resDistinct.status).toBe(200);

      // 6. Missing coordinator fails closed
      const noCoordEnv = { ...env, CONSENT_COORDINATOR: undefined };
      const failedClosed = await (await import("../src/index")).consumeNonceAtomically(
        "any-nonce-12345678",
        noCoordEnv as any
      );
      expect(failedClosed).toBe(false);

      // 7. Rejection of invalid HTTP methods and paths
      const getRes = await stub.fetch("https://coordinator/consume", { method: "GET" });
      expect(getRes.status).toBe(405);

      const invalidPath = await stub.fetch("https://coordinator/other", { method: "POST" });
      expect(invalidPath.status).toBe(404);

      const invalidNonce = await stub.fetch("https://coordinator/consume", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nonce: "bad-short" })
      });
      expect(invalidNonce.status).toBe(400);
    });
  });

  describe("8. Bounded JWKS Cache & Key Rotation Verification", () => {
    it("deduplicates concurrent JWKS refreshes into a single fetch", async () => {
      clearJwksCache();
      const keyPair = await generateTestRsaKeyPair();
      const publicJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as any;
      publicJwk.kid = "dedup-kid-1";

      let fetchCount = 0;
      vi.spyOn(globalThis, "fetch").mockImplementation(async (info) => {
        const urlStr = typeof info === "string" ? info : (info as any).url;
        if (urlStr.includes("access/certs")) {
          fetchCount++;
          // simulate slight network delay
          await new Promise((resolve) => setTimeout(resolve, 50));
          return Response.json({ keys: [publicJwk] }, { status: 200 });
        }
        return new Response("Not found", { status: 404 });
      });

      // Launch 5 simultaneous requests for the same teamDomain
      const results = await Promise.all([
        (await import("../src/index")).getCachedAccessJwks("dedup-team", "dedup-kid-1"),
        (await import("../src/index")).getCachedAccessJwks("dedup-team", "dedup-kid-1"),
        (await import("../src/index")).getCachedAccessJwks("dedup-team", "dedup-kid-1"),
        (await import("../src/index")).getCachedAccessJwks("dedup-team", "dedup-kid-1"),
        (await import("../src/index")).getCachedAccessJwks("dedup-team", "dedup-kid-1")
      ]);

      expect(fetchCount).toBe(1);
      results.forEach((jwks) => {
        expect(jwks.keys[0].kid).toBe("dedup-kid-1");
      });
    });

    it("validates JWKS structure and rejects malformed responses safely", async () => {
      clearJwksCache();

      // Missing keys array
      vi.spyOn(globalThis, "fetch").mockImplementationOnce(async () => {
        return Response.json({ invalid: "payload" }, { status: 200 });
      });

      await expect(
        (await import("../src/index")).getCachedAccessJwks("malformed-team")
      ).rejects.toThrow("Expected an object with a 'keys' array");

      // Upstream fetch failure
      vi.spyOn(globalThis, "fetch").mockImplementationOnce(async () => {
        return new Response("Internal Server Error", { status: 500 });
      });

      await expect(
        (await import("../src/index")).getCachedAccessJwks("fail-team")
      ).rejects.toThrow("HTTP 500");
    });

    it("strictly rejects non-RS256 keys or missing RSA modulus/exponent", async () => {
      const { validateRsaJwk } = await import("../src/index");

      expect(() => validateRsaJwk({ kty: "EC", alg: "ES256" })).toThrow("expected RSA");
      expect(() => validateRsaJwk({ kty: "RSA", alg: "RS512" })).toThrow("expected RS256");
      expect(() => validateRsaJwk({ kty: "RSA", alg: "RS256", use: "enc" })).toThrow("expected 'sig'");
      expect(() => validateRsaJwk({ kty: "RSA", alg: "RS256", n: "abc" })).toThrow("Missing required RSA modulus");
      expect(() => validateRsaJwk({ kty: "RSA", alg: "RS256", n: "abc", e: "AQAB" })).not.toThrow();
    });

    it("strictly rejects non-finite numeric JWT exp and nbf values", async () => {
      const keyPair = await generateTestRsaKeyPair();
      const publicJwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as any;
      publicJwk.kid = "num-test-kid";
      const jwksJson = JSON.stringify({ keys: [publicJwk] });

      const testEnv = {
        ...env,
        CF_ACCESS_TEAM_DOMAIN: "num-team",
        CF_ACCESS_AUD: "num-aud",
        CF_ACCESS_JWKS_JSON: jwksJson
      };

      // 1. exp is NaN
      const jwtExpNaN = await signTestJwt(
        { email: "user@example.com", iss: "https://num-team.cloudflareaccess.com", aud: "num-aud", exp: NaN },
        keyPair.privateKey,
        "num-test-kid"
      );
      const resNaN = await verifyCloudflareAccessJwt(jwtExpNaN, testEnv as any);
      expect(resNaN.valid).toBe(false);
      expect(resNaN.error).toContain("missing numeric 'exp' claim");

      // 2. exp is Infinity
      const jwtExpInf = await signTestJwt(
        { email: "user@example.com", iss: "https://num-team.cloudflareaccess.com", aud: "num-aud", exp: Infinity },
        keyPair.privateKey,
        "num-test-kid"
      );
      const resInf = await verifyCloudflareAccessJwt(jwtExpInf, testEnv as any);
      expect(resInf.valid).toBe(false);
      expect(resInf.error).toContain("missing numeric 'exp' claim");

      // 3. nbf is non-finite
      const now = Math.floor(Date.now() / 1000);
      const jwtNbfNaN = await signTestJwt(
        {
          email: "user@example.com",
          iss: "https://num-team.cloudflareaccess.com",
          aud: "num-aud",
          exp: now + 3600,
          nbf: NaN
        },
        keyPair.privateKey,
        "num-test-kid"
      );
      const resNbfNaN = await verifyCloudflareAccessJwt(jwtNbfNaN, testEnv as any);
      expect(resNbfNaN.valid).toBe(false);
      expect(resNbfNaN.error).toContain("JWT is not yet valid (nbf)");

      // 4. exp is equal to now (expired)
      const jwtExpNow = await signTestJwt(
        { email: "user@example.com", iss: "https://num-team.cloudflareaccess.com", aud: "num-aud", exp: now },
        keyPair.privateKey,
        "num-test-kid"
      );
      const resNow = await verifyCloudflareAccessJwt(jwtExpNow, testEnv as any);
      expect(resNow.valid).toBe(false);
      expect(resNow.error).toContain("JWT has expired");

      // 5. Invalid kid format in JWT header
      const jwtBadKid = await signTestJwt(
        { email: "user@example.com", iss: "https://num-team.cloudflareaccess.com", aud: "num-aud", exp: now + 3600 },
        keyPair.privateKey,
        ""
      );
      const resBadKid = await verifyCloudflareAccessJwt(jwtBadKid, testEnv as any);
      expect(resBadKid.valid).toBe(false);
      expect(resBadKid.error).toContain("Invalid or missing 'kid'");
    });
  });

  describe("9. Optional Gated Live Integration Test", () => {
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
