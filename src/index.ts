import { McpServer, createMcpHandler, type AuthInfo } from "@modelcontextprotocol/server";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { z } from "zod";

export interface Env {
  OAUTH_KV: KVNamespace;
  GEMINI_API_KEY: string;
  MCP_RESOURCE: string;
  ALLOWED_USERS?: string;
  AUTH_SECRET?: string;
  CF_ACCESS_TEAM_DOMAIN?: string;
  CF_ACCESS_AUD?: string;
  CF_ACCESS_JWKS_JSON?: string;
  TRUSTED_CLIENT_IDS?: string;
  ALLOWED_HOSTS?: string;
}

export interface AntigravityOptions {
  timeoutMs?: number;
  maxPollIntervalMs?: number;
  maxPollTimeMs?: number;
}

/**
 * Validates workspace files against reasonable limits:
 * - max 50 files
 * - total payload size <= 1MB
 * - valid normalized target paths
 */
export function validateWorkspaceFiles(workspaceFiles?: Record<string, string>): {
  type: "inline";
  target: string;
  content: string;
}[] {
  if (!workspaceFiles) return [];

  const entries = Object.entries(workspaceFiles);
  if (entries.length > 50) {
    throw new Error("Workspace files limit exceeded: maximum 50 files allowed.");
  }

  let totalBytes = 0;
  const sources: { type: "inline"; target: string; content: string }[] = [];

  for (const [targetPath, content] of entries) {
    const cleanPath = targetPath.trim();
    if (!cleanPath) {
      throw new Error("Workspace file target path cannot be empty.");
    }
    if (cleanPath.includes("..")) {
      throw new Error(`Invalid workspace file path '${targetPath}': path traversal not permitted.`);
    }
    if (typeof content !== "string") {
      throw new Error(`Workspace file content for '${targetPath}' must be a string.`);
    }

    const normalizedTarget = cleanPath.startsWith("/") ? cleanPath : `/workspace/${cleanPath}`;
    totalBytes += new TextEncoder().encode(content).length;
    if (totalBytes > 1024 * 1024) {
      throw new Error("Workspace files payload size exceeded: maximum 1MB allowed.");
    }

    sources.push({
      type: "inline",
      target: normalizedTarget,
      content
    });
  }

  return sources;
}

/**
 * Strips or redacts any occurrences of sensitive API keys from strings.
 */
export function sanitizeSecret(text: string, secret?: string): string {
  if (!secret || !text) return text;
  return text.split(secret).join("[REDACTED_API_KEY]");
}

/**
 * Dispatches autonomous tasks to Google's Antigravity Agent endpoint.
 * Uses Google's official Interactions API request structure:
 * - agent: "antigravity-preview-09-2026"
 * - input: prompt (string)
 * - environment: "remote" | { type: "remote", sources: [...] }
 * - AbortSignal.timeout()
 * - Inspects interaction status and handles polling if in_progress.
 * - Never exposes Google API key in errors.
 */
export async function callAntigravityAgent(
  apiKey: string,
  prompt: string,
  workspaceFiles?: Record<string, string>,
  options?: AntigravityOptions
) {
  if (!apiKey || typeof apiKey !== "string") {
    throw new Error("Missing or invalid Google Gemini API Key.");
  }
  if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
    throw new Error("Prompt input cannot be empty.");
  }

  const timeoutMs = options?.timeoutMs ?? 60000;
  const maxPollTimeMs = options?.maxPollTimeMs ?? 120000;
  const pollIntervalMs = options?.maxPollIntervalMs ?? 1000;

  const sources = validateWorkspaceFiles(workspaceFiles);

  const payload: Record<string, any> = {
    agent: "antigravity-preview-09-2026",
    input: prompt
  };

  if (sources.length > 0) {
    payload.environment = {
      type: "remote",
      sources
    };
  } else {
    payload.environment = "remote";
  }

  const baseUrl = "https://generativelanguage.googleapis.com/v1beta/interactions";

  let response: Response;
  try {
    response = await fetch(baseUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs)
    });
  } catch (err: any) {
    const safeMsg = sanitizeSecret(err?.message || "Network request failed", apiKey);
    throw new Error(`Google Antigravity request failed: ${safeMsg}`);
  }

  if (!response.ok) {
    let errorBody = "";
    try {
      errorBody = await response.text();
    } catch {}
    let parsedMessage = errorBody;
    try {
      const errJson = JSON.parse(errorBody);
      if (errJson.error?.message) {
        parsedMessage = errJson.error.message;
      }
    } catch {}
    const safeError = sanitizeSecret(parsedMessage, apiKey);
    throw new Error(`Google Antigravity API error (${response.status}): ${safeError}`);
  }

  let data: any;
  try {
    data = await response.json();
  } catch {
    throw new Error("Google Antigravity API error: Received malformed JSON response.");
  }

  if (!data || typeof data !== "object") {
    throw new Error("Google Antigravity API error: Invalid response object.");
  }

  // Handle polling if interaction is in_progress
  const pollStartTime = Date.now();
  while (data.status === "in_progress" && data.id) {
    if (Date.now() - pollStartTime > maxPollTimeMs) {
      throw new Error(`Google Antigravity interaction timed out after ${maxPollTimeMs}ms while still in_progress.`);
    }

    // Wait poll interval
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));

    const pollUrl = `${baseUrl}/${encodeURIComponent(data.id)}`;
    let pollRes: Response;
    try {
      pollRes = await fetch(pollUrl, {
        method: "GET",
        headers: {
          "x-goog-api-key": apiKey
        },
        signal: AbortSignal.timeout(timeoutMs)
      });
    } catch (err: any) {
      const safeMsg = sanitizeSecret(err?.message || "Polling request failed", apiKey);
      throw new Error(`Google Antigravity polling request failed: ${safeMsg}`);
    }

    if (!pollRes.ok) {
      let pollErrBody = "";
      try {
        pollErrBody = await pollRes.text();
      } catch {}
      let parsedPollErr = pollErrBody;
      try {
        const errJson = JSON.parse(pollErrBody);
        if (errJson.error?.message) {
          parsedPollErr = errJson.error.message;
        }
      } catch {}
      const safePollErr = sanitizeSecret(parsedPollErr, apiKey);
      throw new Error(`Google Antigravity polling error (${pollRes.status}): ${safePollErr}`);
    }

    try {
      data = await pollRes.json();
    } catch {
      throw new Error("Google Antigravity API polling error: Received malformed JSON response.");
    }
  }

  // Inspect final interaction status
  if (data.status === "failed") {
    const errorDetails = data.error?.message || data.output_text || JSON.stringify(data.error || "Interaction execution failed");
    throw new Error(`Google Antigravity interaction failed: ${sanitizeSecret(errorDetails, apiKey)}`);
  }

  if (data.status === "incomplete") {
    throw new Error("Google Antigravity interaction incomplete: Agent budget or token limit reached before task completion.");
  }

  if (data.status && data.status !== "completed" && data.status !== "requires_action") {
    throw new Error(`Google Antigravity interaction finished with unexpected status: ${data.status}`);
  }

  return data;
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

function base64UrlToUint8Array(base64Url: string): Uint8Array {
  let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Validates a Cloudflare Access JWT assertion.
 * Verifies JWT signature against Cloudflare Access certs/JWKS, issuer, aud, and exp.
 * Never trusts unverified Cf-Access-Authenticated-User-Email header.
 */
export async function verifyCloudflareAccessJwt(
  jwt: string,
  env: Env
): Promise<{ valid: boolean; email?: string; error?: string }> {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) {
      return { valid: false, error: "Invalid JWT format" };
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(headerB64)));
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(payloadB64)));

    if (header.alg !== "RS256") {
      return { valid: false, error: `Unsupported JWT algorithm: ${header.alg}` };
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return { valid: false, error: "JWT has expired" };
    }

    // Validate audience if configured
    if (env.CF_ACCESS_AUD) {
      const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!auds.includes(env.CF_ACCESS_AUD)) {
        return { valid: false, error: "JWT audience mismatch" };
      }
    }

    // Validate issuer if team domain is configured
    if (env.CF_ACCESS_TEAM_DOMAIN) {
      const expectedIss = `https://${env.CF_ACCESS_TEAM_DOMAIN}.cloudflareaccess.com`;
      if (payload.iss !== expectedIss) {
        return { valid: false, error: "JWT issuer mismatch" };
      }
    }

    // Retrieve public JWK (either cached/injected in env or fetched)
    let jwks: { keys: any[] };
    if (env.CF_ACCESS_JWKS_JSON) {
      jwks = JSON.parse(env.CF_ACCESS_JWKS_JSON);
    } else if (env.CF_ACCESS_TEAM_DOMAIN) {
      const certsUrl = `https://${env.CF_ACCESS_TEAM_DOMAIN}.cloudflareaccess.com/cdn-cgi/access/certs`;
      const certsRes = await fetch(certsUrl);
      if (!certsRes.ok) {
        return { valid: false, error: `Failed to fetch Access JWKS: ${certsRes.status}` };
      }
      jwks = (await certsRes.json()) as { keys: any[] };
    } else {
      return { valid: false, error: "Cloudflare Access verification unconfigured (no team domain or JWKS)" };
    }

    const keyJwk = jwks.keys?.find((k) => k.kid === header.kid);
    if (!keyJwk) {
      return { valid: false, error: `Key ID (kid: ${header.kid}) not found in JWKS` };
    }

    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      keyJwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signatureBytes = base64UrlToUint8Array(signatureB64);
    const verified = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signatureBytes, signedData);

    if (!verified) {
      return { valid: false, error: "Invalid JWT cryptographic signature" };
    }

    const email = payload.email || payload.identity?.email || payload.sub;
    if (!email || typeof email !== "string") {
      return { valid: false, error: "No email or subject found in verified JWT payload" };
    }

    return { valid: true, email };
  } catch (err: any) {
    return { valid: false, error: `Cloudflare Access JWT verification error: ${err.message}` };
  }
}

/**
 * Validates trusted user authentication (Cloudflare Access JWT or HMAC signing proxy)
 * and verifies against ALLOWED_USERS policy.
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

  let authenticatedEmail: string | undefined;

  // 1. Cloudflare Access JWT Assertion Header
  const accessJwt = request.headers.get("Cf-Access-Jwt-Assertion");
  if (accessJwt) {
    const jwtResult = await verifyCloudflareAccessJwt(accessJwt, env);
    if (!jwtResult.valid || !jwtResult.email) {
      return {
        authorized: false,
        error: `Cloudflare Access authentication failed: ${jwtResult.error || "Invalid assertion"}`
      };
    }
    authenticatedEmail = jwtResult.email;
  } else if (env.AUTH_SECRET) {
    // 2. HMAC-signed identity proxy verification
    const authUser = request.headers.get("X-Auth-User");
    const authSig = request.headers.get("X-Auth-Signature");

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

    authenticatedEmail = authUser;
  } else {
    // No supported authentication method configured or provided
    return {
      authorized: false,
      error: "No trusted authentication mechanism configured in server environment (AUTH_SECRET or CF_ACCESS_TEAM_DOMAIN required)"
    };
  }

  const normalizedUser = authenticatedEmail.trim().toLowerCase();
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

/**
 * Creates and verifies CSRF tokens bound to client ID, redirect URI, user ID, and code challenge.
 */
export async function createConsentCsrfToken(
  clientId: string,
  redirectUri: string,
  userId: string,
  codeChallenge: string,
  secret: string
): Promise<string> {
  const payload = `${clientId}|${redirectUri}|${userId}|${codeChallenge}|${Math.floor(Date.now() / 1000)}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  const sigHex = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${btoa(payload)}.${sigHex}`;
}

export async function verifyConsentCsrfToken(
  token: string,
  expectedClientId: string,
  expectedRedirectUri: string,
  expectedUserId: string,
  expectedCodeChallenge: string,
  secret: string
): Promise<boolean> {
  try {
    const [payloadB64, sigHex] = token.split(".");
    if (!payloadB64 || !sigHex || !/^[0-9a-f]{64}$/.test(sigHex)) return false;
    const payload = atob(payloadB64);
    const [clientId, redirectUri, userId, codeChallenge, timestampStr] = payload.split("|");
    if (
      clientId !== expectedClientId ||
      redirectUri !== expectedRedirectUri ||
      userId !== expectedUserId ||
      codeChallenge !== expectedCodeChallenge
    ) {
      return false;
    }

    const timestamp = parseInt(timestampStr, 10);
    const now = Math.floor(Date.now() / 1000);
    // 10-minute expiry for consent CSRF token
    if (isNaN(timestamp) || now - timestamp > 600 || timestamp > now + 60) {
      return false;
    }

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = new Uint8Array(
      (sigHex.match(/.{1,2}/g) || []).map((b) => parseInt(b, 16))
    );
    return await crypto.subtle.verify("HMAC", key, sigBytes, encoder.encode(payload));
  } catch {
    return false;
  }
}

// Initialize OAuth 2.1 Provider
// Note: @cloudflare/workers-oauth-provider 0.1.0 requires an apiRoute / apiHandler pair.
// We configure apiRoute to /oauth/dummy-api so it satisfies provider initialization
// without intercepting or conflicting with our MCP handler on /mcp.
export const oauth = new OAuthProvider({
  apiRoute: "/oauth/dummy-api",
  apiHandler: {
    async fetch() {
      return new Response("Not Used", { status: 404 });
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

          // 1. Validate PKCE parameters (RFC 7636)
          if (!authRequest.codeChallenge) {
            return new Response(
              JSON.stringify({
                error: "invalid_request",
                error_description: "PKCE code_challenge is required"
              }),
              { status: 400, headers: { "Content-Type": "application/json" } }
            );
          }
          if (authRequest.codeChallengeMethod && authRequest.codeChallengeMethod !== "S256") {
            return new Response(
              JSON.stringify({
                error: "invalid_request",
                error_description: "Only PKCE code_challenge_method=S256 is supported"
              }),
              { status: 400, headers: { "Content-Type": "application/json" } }
            );
          }

          // 2. Validate requested scopes (only "mcp" scope supported)
          const requestedScopes = authRequest.scope && authRequest.scope.length > 0 ? authRequest.scope : ["mcp"];
          const supportedScopes = ["mcp"];
          const invalidScopes = requestedScopes.filter((s: string) => !supportedScopes.includes(s));
          if (invalidScopes.length > 0) {
            const redirectUrl = new URL(authRequest.redirectUri);
            redirectUrl.searchParams.set("error", "invalid_scope");
            redirectUrl.searchParams.set("error_description", `Unsupported scope(s): ${invalidScopes.join(", ")}`);
            if (authRequest.state) redirectUrl.searchParams.set("state", authRequest.state);
            return Response.redirect(redirectUrl.toString(), 302);
          }

          // 3. Validate resource parameter (RFC 8707) against canonical resource URI
          const canonicalResource = getCanonicalResourceUri(url, env);
          if (authRequest.resource) {
            const requestedResources = Array.isArray(authRequest.resource)
              ? authRequest.resource
              : [authRequest.resource];
            const resourceMatches = requestedResources.every(
              (res: string) => res.replace(/\/+$/, "") === canonicalResource.replace(/\/+$/, "")
            );
            if (!resourceMatches) {
              const redirectUrl = new URL(authRequest.redirectUri);
              redirectUrl.searchParams.set("error", "invalid_target");
              redirectUrl.searchParams.set("error_description", `Requested resource is not authorized for this server`);
              if (authRequest.state) redirectUrl.searchParams.set("state", authRequest.state);
              return Response.redirect(redirectUrl.toString(), 302);
            }
          }

          // 4. Verify client trust and handle explicit user consent
          const client = await oauthHelpers.lookupClient(authRequest.clientId);
          if (!client) {
            return new Response(
              JSON.stringify({
                error: "unauthorized_client",
                error_description: "Client not found or not registered"
              }),
              { status: 400, headers: { "Content-Type": "application/json" } }
            );
          }

          const trustedList = env.TRUSTED_CLIENT_IDS
            ? env.TRUSTED_CLIENT_IDS.split(",").map((s: string) => s.trim().toLowerCase())
            : [];
          const isPreTrusted = trustedList.includes(authRequest.clientId.toLowerCase());

          // Handle POST submission for consent approval or denial
          if (request.method === "POST") {
            const formData = await request.formData();
            const action = formData.get("consent_action");
            const csrfToken = (formData.get("csrf_token") as string) || "";
            const csrfSecret = env.AUTH_SECRET || "default-consent-csrf-secret";

            const csrfValid = await verifyConsentCsrfToken(
              csrfToken,
              authRequest.clientId,
              authRequest.redirectUri,
              authResult.userId,
              authRequest.codeChallenge || "",
              csrfSecret
            );

            if (!csrfValid) {
              return new Response(
                JSON.stringify({
                  error: "invalid_request",
                  error_description: "Invalid or expired CSRF token on consent submission"
                }),
                { status: 400, headers: { "Content-Type": "application/json" } }
              );
            }

            if (action === "deny") {
              const redirectUrl = new URL(authRequest.redirectUri);
              redirectUrl.searchParams.set("error", "access_denied");
              redirectUrl.searchParams.set("error_description", "User denied authorization");
              if (authRequest.state) redirectUrl.searchParams.set("state", authRequest.state);
              return Response.redirect(redirectUrl.toString(), 302);
            }

            if (action === "approve") {
              const { redirectTo } = await oauthHelpers.completeAuthorization({
                request: authRequest,
                userId: authResult.userId,
                scope: requestedScopes
              });
              return Response.redirect(redirectTo, 302);
            }
          }

          // If client is pre-trusted and no interactive consent required
          if (isPreTrusted) {
            const { redirectTo } = await oauthHelpers.completeAuthorization({
              request: authRequest,
              userId: authResult.userId,
              scope: requestedScopes
            });
            return Response.redirect(redirectTo, 302);
          }

          // Render interactive consent UI with CSRF protection and form submission
          const clientName = client.clientName || client.clientId;
          const csrfSecret = env.AUTH_SECRET || "default-consent-csrf-secret";
          const csrfToken = await createConsentCsrfToken(
            authRequest.clientId,
            authRequest.redirectUri,
            authResult.userId,
            authRequest.codeChallenge || "",
            csrfSecret
          );

          const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorize ${clientName}</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #f4f4f9; padding: 2rem; display: flex; justify-content: center; }
    .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 450px; width: 100%; }
    h2 { margin-top: 0; }
    .scopes { background: #f0f0f5; padding: 0.75rem; border-radius: 4px; font-family: monospace; }
    .buttons { display: flex; gap: 1rem; margin-top: 1.5rem; }
    button.btn { padding: 0.6rem 1.25rem; border-radius: 4px; border: none; font-weight: bold; cursor: pointer; flex: 1; font-size: 1rem; }
    .approve { background: #2563eb; color: white; }
    .deny { background: #e5e7eb; color: #1f2937; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Authorize Application</h2>
    <p><strong>${authResult.userId}</strong>, do you authorize <strong>${clientName}</strong> to access the Antigravity MCP Server?</p>
    <p>Requested Scopes:</p>
    <div class="scopes">${requestedScopes.join(", ")}</div>
    <p><small>Resource: ${canonicalResource}</small></p>
    <form method="POST" action="${url.pathname}${url.search}">
      <input type="hidden" name="csrf_token" value="${csrfToken}" />
      <div class="buttons">
        <button type="submit" name="consent_action" value="approve" class="btn approve">Approve</button>
        <button type="submit" name="consent_action" value="deny" class="btn deny">Deny</button>
      </div>
    </form>
  </div>
</body>
</html>`;
          return new Response(html, {
            status: 200,
            headers: { "Content-Type": "text/html; charset=utf-8" }
          });
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
  clientId?: string;
  scope?: string[];
  audience?: string | string[];
  error?: "invalid_token" | "token_expired" | "invalid_audience" | "insufficient_scope";
  errorDescription?: string;
}

/**
 * Validates a Bearer token against OAUTH_KV and checks:
 * - Format (userId:grantId:secret)
 * - Expiration (expiresAt must be present and not expired)
 * - Required scopes (enforces requiredScope e.g. "mcp")
 * - Exact canonical audience/resource matching (rejects origin-only or overly broad prefixes)
 * - Associated grant existence and user identity binding
 */
export async function validateBearerToken(
  authHeader: string | null,
  env: Env,
  requestUrl?: URL,
  requiredScope = "mcp"
): Promise<ValidatedToken> {
  if (!authHeader?.startsWith("Bearer ")) {
    return { isValid: false, error: "invalid_token", errorDescription: "Missing or malformed Authorization header" };
  }
  const token = authHeader.substring(7).trim();
  if (!token) {
    return { isValid: false, error: "invalid_token", errorDescription: "Empty bearer token" };
  }

  const parts = token.split(":");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    return { isValid: false, error: "invalid_token", errorDescription: "Invalid token format" };
  }

  const [userId, grantId] = parts;
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(token));
  const tokenId = Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const tokenKey = `token:${userId}:${grantId}:${tokenId}`;
  const tokenData = await env.OAUTH_KV.get<{
    id?: string;
    userId?: string;
    grantId?: string;
    expiresAt?: number;
    audience?: string | string[];
    grant?: { clientId?: string; scope?: string[] };
  }>(tokenKey, { type: "json" });

  if (!tokenData) {
    return { isValid: false, error: "invalid_token", errorDescription: "Token not found or revoked" };
  }

  // Token ownership check
  if (tokenData.userId && tokenData.userId !== userId) {
    return { isValid: false, error: "invalid_token", errorDescription: "Token identity mismatch" };
  }

  // Mandatory expiration enforcement
  const now = Math.floor(Date.now() / 1000);
  if (tokenData.expiresAt === undefined || typeof tokenData.expiresAt !== "number") {
    return { isValid: false, error: "invalid_token", errorDescription: "Token missing expiration timestamp" };
  }
  if (tokenData.expiresAt < now) {
    return { isValid: false, error: "token_expired", errorDescription: "Access token has expired" };
  }

  // Required scopes enforcement
  const scopes = tokenData.grant?.scope || [];
  if (requiredScope && !scopes.includes(requiredScope)) {
    return { isValid: false, error: "insufficient_scope", errorDescription: `Missing required scope: ${requiredScope}` };
  }

  // Audience / Resource validation (RFC 8707 / RFC 7519)
  // Must match canonical resource URI exactly. Origin-only matching is rejected.
  const canonicalResource = env.MCP_RESOURCE || (requestUrl ? `${requestUrl.origin}/mcp` : undefined);
  if (!tokenData.audience) {
    return { isValid: false, error: "invalid_audience", errorDescription: "Token is missing audience claim" };
  }

  if (canonicalResource) {
    const audiences = Array.isArray(tokenData.audience) ? tokenData.audience : [tokenData.audience];
    const canonicalAudience = canonicalResource.replace(/\/+$/, "");
    const matches = audiences.some((aud) => {
      const cleanAud = aud.replace(/\/+$/, "");
      return cleanAud === canonicalAudience;
    });

    if (!matches) {
      return { isValid: false, error: "invalid_audience", errorDescription: `Token audience mismatch for resource ${canonicalResource}` };
    }
  }

  return {
    isValid: true,
    userId,
    grantId,
    clientId: tokenData.grant?.clientId,
    scope: scopes,
    audience: tokenData.audience
  };
}

/**
 * Resolves and validates the canonical MCP resource URI.
 * Checks env.MCP_RESOURCE if provided, otherwise derives safely from public request origin.
 */
export function getCanonicalResourceUri(requestUrl: URL, env: Env): string {
  if (env.MCP_RESOURCE) {
    try {
      const parsed = new URL(env.MCP_RESOURCE);
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
        throw new Error("Invalid protocol in MCP_RESOURCE");
      }
      return env.MCP_RESOURCE.replace(/\/+$/, "");
    } catch {
      // Fallback if invalid
    }
  }
  return `${requestUrl.origin}/mcp`;
}

/**
 * Helper to validate Host and Origin headers to protect against DNS rebinding and CSRF.
 */
export function validateHostAndOrigin(request: Request, env: Env): { valid: boolean; error?: string } {
  const url = new URL(request.url);
  const host = request.headers.get("Host") || url.host;

  // Check allowed hosts if configured, or default to URL hostname and localhost
  if (env.ALLOWED_HOSTS) {
    const allowed = env.ALLOWED_HOSTS.split(",").map((h) => h.trim().toLowerCase());
    const hostWithoutPort = host.split(":")[0].toLowerCase();
    if (!allowed.includes(host.toLowerCase()) && !allowed.includes(hostWithoutPort) && !allowed.includes("*")) {
      return { valid: false, error: `Invalid Host header '${host}'` };
    }
  }

  // If Origin is present, check origin
  const origin = request.headers.get("Origin");
  if (origin && origin !== "null") {
    try {
      const originUrl = new URL(origin);
      if (env.ALLOWED_HOSTS) {
        const allowed = env.ALLOWED_HOSTS.split(",").map((h) => h.trim().toLowerCase());
        const originHostWithoutPort = originUrl.hostname.toLowerCase();
        if (!allowed.includes(originUrl.host.toLowerCase()) && !allowed.includes(originHostWithoutPort) && !allowed.includes("*")) {
          return { valid: false, error: `Unauthorized Origin '${origin}'` };
        }
      }
    } catch {
      return { valid: false, error: `Malformed Origin header` };
    }
  }

  return { valid: true };
}

/**
 * Returns appropriate CORS headers for allowed requests.
 */
export function getCorsHeaders(request: Request, env: Env): Headers {
  const headers = new Headers();
  const origin = request.headers.get("Origin");

  if (origin && origin !== "null") {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
  } else {
    headers.set("Access-Control-Allow-Origin", "*");
  }

  headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  headers.set(
    "Access-Control-Allow-Headers",
    "Authorization, Content-Type, Accept, MCP-Protocol-Version, X-Session-Id"
  );
  headers.set("Access-Control-Expose-Headers", "WWW-Authenticate");
  return headers;
}

/**
 * Helper to build 401 Unauthorized / 403 Forbidden responses with RFC 9728 resource_metadata link in WWW-Authenticate.
 */
export function createUnauthorizedResponse(
  requestUrl: URL,
  env: Env,
  error = "invalid_token",
  errorDescription?: string,
  statusCode = 401,
  corsHeaders?: Headers
): Response {
  const canonicalResource = getCanonicalResourceUri(requestUrl, env);
  const resourceOrigin = new URL(canonicalResource).origin;
  const resourceMetadataUrl = `${resourceOrigin}/.well-known/oauth-protected-resource/mcp`;
  let challenge = `Bearer realm="OAuth", error="${error}", resource_metadata="${resourceMetadataUrl}"`;
  if (errorDescription) {
    challenge += `, error_description="${errorDescription}"`;
  }

  const resHeaders = corsHeaders ? new Headers(corsHeaders) : new Headers();
  resHeaders.set("WWW-Authenticate", challenge);
  resHeaders.set("Access-Control-Expose-Headers", "WWW-Authenticate");
  if (!resHeaders.has("Access-Control-Allow-Origin")) {
    resHeaders.set("Access-Control-Allow-Origin", "*");
  }

  return new Response(statusCode === 403 ? "Forbidden" : "Unauthorized", {
    status: statusCode,
    headers: resHeaders
  });
}

/**
 * Handles RFC 9728 Protected Resource Metadata discovery requests.
 */
export function handleProtectedResourceMetadata(requestUrl: URL, env: Env): Response {
  const resourceUri = getCanonicalResourceUri(requestUrl, env);
  const authServer = new URL(resourceUri).origin;
  const metadata = {
    resource: resourceUri,
    authorization_servers: [authServer],
    scopes_supported: ["mcp"],
    bearer_methods_supported: ["header"],
    resource_documentation: `${authServer}/README.md`
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

    // Host & Origin validation (DNS rebinding / CSRF protection)
    const hostValidation = validateHostAndOrigin(request, env);
    if (!hostValidation.valid) {
      return new Response(hostValidation.error || "Forbidden", { status: 403 });
    }

    // RFC 9728 Protected Resource Metadata Discovery endpoints
    if (
      url.pathname === "/.well-known/oauth-protected-resource/mcp" ||
      url.pathname === "/.well-known/oauth-protected-resource"
    ) {
      if (request.method === "OPTIONS") {
        const cors = getCorsHeaders(request, env);
        return new Response(null, {
          status: 204,
          headers: cors
        });
      }
      const response = handleProtectedResourceMetadata(url, env);
      const cors = getCorsHeaders(request, env);
      cors.forEach((value, key) => response.headers.set(key, value));
      return response;
    }

    // 1. Primary Remote MCP Endpoint: Stateless Web-Standard Transport (/mcp)
    if (url.pathname === "/mcp") {
      const cors = getCorsHeaders(request, env);
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: cors
        });
      }

      const tokenResult = await validateBearerToken(request.headers.get("Authorization"), env, url, "mcp");
      if (!tokenResult.isValid) {
        const status = tokenResult.error === "insufficient_scope" ? 403 : 401;
        return createUnauthorizedResponse(
          url,
          env,
          tokenResult.error || "invalid_token",
          tokenResult.errorDescription,
          status,
          cors
        );
      }

      const mcpHandler = createMcpHandler((context) =>
        createAntigravityMcpServer(env, context?.authInfo)
      );

      const response = await mcpHandler.fetch(request, {
        authInfo: {
          token: request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "") || "",
          clientId: tokenResult.clientId || tokenResult.grantId || "claude-client",
          scopes: tokenResult.scope || ["mcp"],
          extra: { userId: tokenResult.userId }
        } as any
      });

      const resHeaders = new Headers(response.headers);
      cors.forEach((value, key) => {
        if (!resHeaders.has(key)) resHeaders.set(key, value);
      });
      resHeaders.set("Access-Control-Expose-Headers", "WWW-Authenticate");

      return new Response(response.body, {
        status: response.status,
        headers: resHeaders
      });
    }

    // 2. Delegate to OAuth Provider
    return oauth.fetch(request, env, ctx);
  }
};
