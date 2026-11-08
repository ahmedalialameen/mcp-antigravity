# Cloudflare Workers MCP Server for Google Antigravity Agent

A remote Model Context Protocol (MCP) server deployed on Cloudflare Workers. It bridges Claude (Claude Desktop, Claude Code, and Claude Web) to Google's Antigravity Agent runtime (code sandbox, file manipulation, and autonomous reasoning) over stateless HTTP (`/mcp`), secured via OAuth 2.1 with PKCE backed by Cloudflare KV and identity verification (Cloudflare Access JWT assertions or trusted HMAC proxy).

## Features

- **Google Antigravity Integration**: Connects to Google's official Interactions API endpoint `https://generativelanguage.googleapis.com/v1beta/interactions` using the supported agent identifier `antigravity-preview-09-2026` and official `x-goog-api-key: <GEMINI_API_KEY>` header.
- **MCP Server & Tool**: Implements the `run_antigravity_agent` tool via official SDK v2 (`@modelcontextprotocol/server`) to execute multi-step tasks and file manipulation within the sandbox workspace.
- **Stateless Web-Standard MCP Transport**: Exposes the primary remote MCP endpoint at `/mcp` via `createMcpHandler()`, providing native support for MCP 2026-07-28 and 2025 stateless fallback over POST without requiring transport session state.
- **Protected Resource Metadata (RFC 9728)**: Exposes discovery at `/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-protected-resource`, and supplies `resource_metadata` in 401 `WWW-Authenticate` response headers.
- **Identity Verification & Security**: Supports Cloudflare Access JWT validation (`Cf-Access-Jwt-Assertion` validated against official Access JWKS) and HMAC-signed identity proxy verification (`AUTH_SECRET`). Never trusts unverified raw email headers.
- **OAuth 2.1 with Explicit User Consent & PKCE**: Implements OAuth 2.1 routes (`/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/.well-known/oauth-authorization-server`) backed by Cloudflare KV (`OAUTH_KV`). Enforces mandatory PKCE (S256), scope validation, canonical resource validation, and CSRF-protected explicit user consent.
- **Host & Origin Validation**: Prevents DNS rebinding and unauthorized cross-origin requests with configurable `ALLOWED_HOSTS` and dynamic CORS headers.

---

## Prerequisites

- [Node.js](https://nodejs.org/) (v20 or newer)
- Cloudflare account with Wrangler CLI configured
- Google Gemini API Key with Antigravity Agent access

---

## Setup & Configuration

### 1. Create Cloudflare KV Namespace

Create the KV namespace used to persist OAuth clients, grants, and tokens:

```bash
wrangler kv namespace create OAUTH_KV
```

Update your `wrangler.jsonc` file with the generated namespace ID:

```jsonc
"kv_namespaces": [
  {
    "binding": "OAUTH_KV",
    "id": "<YOUR_KV_NAMESPACE_ID>"
  }
]
```

### 2. Configure Allowed Users & Identity Policy

Authorization requests to `/oauth/authorize` fail closed unless an allowed-user policy is configured:

- Set `ALLOWED_USERS` in `wrangler.jsonc` or secrets (comma-separated email list, e.g. `"alice@example.com,bob@example.com"`).
- Set `MCP_RESOURCE` to your canonical public MCP URL (e.g. `"https://antigravity-mcp-server.<your-subdomain>.workers.dev/mcp"` or custom domain `"https://mcp.example.com/mcp"`).

#### Authentication Method A: Cloudflare Access (Preferred)
Protect your Worker behind Cloudflare Access. The server validates the cryptographic RS256 signature in the `Cf-Access-Jwt-Assertion` header:
- Set `CF_ACCESS_TEAM_DOMAIN` (e.g. `"my-team"` which fetches keys from `https://my-team.cloudflareaccess.com/cdn-cgi/access/certs`).
- Optionally set `CF_ACCESS_AUD` to match your Cloudflare Access Application Audience Tag.
- The server extracts and cryptographically verifies the authenticated email.

#### Authentication Method B: HMAC Signing Proxy (Alternative)
When using a trusted proxy that signs user requests:
- Set `AUTH_SECRET` via `wrangler secret put AUTH_SECRET`.
- The proxy must supply `X-Auth-User` and `X-Auth-Signature` (HMAC-SHA256 of the user email using `AUTH_SECRET`).

### 3. Set Secret: `GEMINI_API_KEY`

Store your Google Gemini API key securely using Wrangler secrets:

```bash
wrangler secret put GEMINI_API_KEY
```

---

## Local Development & Testing

### Install Dependencies

```bash
npm install
```

### Run Tests

Run the test suite using Vitest:

```bash
npm test
```

### TypeScript Validation

Ensure all TypeScript types compile without errors:

```bash
npx tsc --noEmit
```

### Run Local Development Server

Start the local development server with Wrangler:

```bash
wrangler dev
```

---

## Deployment

Deploy the worker to Cloudflare Workers:

```bash
npm run deploy
```

---

## Claude Desktop Configuration

Configure Claude Desktop to connect to your remote MCP server via `mcp-remote` using the primary stateless `/mcp` endpoint:

```json
{
  "mcpServers": {
    "antigravity": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://antigravity-mcp-server.<your-subdomain>.workers.dev/mcp"
      ]
    }
  }
}
```

When connecting for the first time, Claude will perform the OAuth 2.1 authorization flow with PKCE against the server and request explicit user consent.

---

## MCP Tool Definition

### `run_antigravity_agent`

Executes autonomous multi-step reasoning, test suites, or file transformations inside Google's Antigravity sandbox.

**Input Schema:**

```typescript
{
  task: string;                  // Instructions describing the software task, bug fix, or analysis
  contextFiles?: Record<string, string>; // Optional key-value mapping of file paths to raw contents (max 50 files, 1MB total)
}
```

**Output:**

Returns the structured JSON response or an MCP error block (`isError: true`) if the API request fails.
