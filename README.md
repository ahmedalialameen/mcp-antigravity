# Cloudflare Workers MCP Server for Google Antigravity Agent

A remote Model Context Protocol (MCP) server deployed on Cloudflare Workers. It bridges Claude (Claude Desktop, Claude Code, and Claude Web) to Google's Antigravity Agent runtime (code sandbox, file manipulation, and autonomous reasoning) over stateless HTTP (`/mcp`) and legacy SSE (`/sse` + `/message`), secured via OAuth 2.1 with PKCE backed by Cloudflare KV and Cloudflare Durable Objects.

## Features

- **Google Antigravity Integration**: Connects to Google's Interactions API endpoint `https://generativelanguage.googleapis.com/v1beta/interactions` using the supported agent identifier `antigravity-preview-09-2026` and official `x-goog-api-key: <GEMINI_API_KEY>` header.
- **MCP Server & Tool**: Implements the `run_antigravity_agent` tool via official SDK v2 (`@modelcontextprotocol/server`) to execute multi-step tasks and file manipulation within the sandbox workspace.
- **Stateless Web-Standard MCP Transport**: Exposes the primary remote MCP endpoint at `/mcp` via `createMcpHandler()`, providing native support for MCP 2026-07-28 and 2025 stateless fallback over POST without requiring transport session state.
- **Protected Resource Metadata (RFC 9728)**: Exposes discovery at `/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-protected-resource`, and supplies `resource_metadata` in 401 `WWW-Authenticate` response headers.
- **Legacy SSE Compatibility**: Preserves `/sse` and `/message` backed by `McpSessionDO` Durable Objects for legacy SSE clients with session ownership validation.
- **Secure OAuth 2.1 with Mandatory Identity Verification**: Implements OAuth 2.1 routes (`/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/.well-known/oauth-authorization-server`) backed by Cloudflare KV (`OAUTH_KV`). Enforces mandatory `AUTH_SECRET` HMAC signature verification and `ALLOWED_USERS` policy (fails closed if unconfigured or unauthorized).

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

### 2. Configure Durable Objects (Legacy SSE Compatibility)

The server retains a Durable Object named `McpSessionDO` for backwards compatibility with legacy SSE connections. In `wrangler.jsonc`:

```jsonc
"durable_objects": {
  "bindings": [
    {
      "name": "MCP_SESSION",
      "class_name": "McpSessionDO"
    }
  ]
},
"migrations": [
  {
    "tag": "v1",
    "new_classes": ["McpSessionDO"]
  }
]
```

### 3. Configure Allowed Users & Identity Policy

Authorization requests to `/oauth/authorize` fail closed unless both `AUTH_SECRET` and `ALLOWED_USERS` are configured:

- Set the `ALLOWED_USERS` variable in `wrangler.jsonc` or via secret/env (comma-separated email list, e.g. `"alice@example.com,bob@example.com"`).
- Configure `AUTH_SECRET` via `wrangler secret put AUTH_SECRET`. This secret is **mandatory** and enforces HMAC-SHA256 signature verification on `X-Auth-Signature` when receiving user assertions via `X-Auth-User` or `Cf-Access-Authenticated-User-Email`.

### 4. Set Secret: `GEMINI_API_KEY`

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

Run the test suite using Vitest with `@cloudflare/vitest-pool-workers`:

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

For legacy clients that require SSE:
```json
{
  "mcpServers": {
    "antigravity-legacy": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://antigravity-mcp-server.<your-subdomain>.workers.dev/sse"
      ]
    }
  }
}
```

When connecting for the first time, Claude will perform the OAuth 2.1 authorization flow with PKCE against the server.

---

## MCP Tool Definition

### `run_antigravity_agent`

Executes autonomous multi-step reasoning, test suites, or file transformations inside Google's Antigravity sandbox.

**Input Schema:**

```typescript
{
  task: string;                  // Instructions describing the software task, bug fix, or analysis
  contextFiles?: Record<string, string>; // Optional key-value mapping of file paths to raw contents
}
```

**Output:**

Returns the structured JSON response or an MCP error block (`isError: true`) if the API request fails.
