# Cloudflare Workers MCP Server for Google Antigravity Agent

A remote Model Context Protocol (MCP) server deployed on Cloudflare Workers. It bridges Claude (Claude Desktop, Claude Code, and Claude Web) to Google's Antigravity Agent runtime (code sandbox, file manipulation, and autonomous reasoning) over Streamable HTTP/SSE, secured via OAuth 2.1 with PKCE backed by Cloudflare KV.

## Features

- **Google Antigravity Integration**: Connects to `https://generativelanguage.googleapis.com/v1beta/models/antigravity:generateContent` using the official `x-goog-api-key: <GEMINI_API_KEY>` header.
- **MCP Server & Tool**: Implements the `run_antigravity_agent` tool via `@modelcontextprotocol/sdk` to execute multi-step tasks and file manipulation within the sandbox workspace.
- **OAuth 2.1 Provider**: Implements standard OAuth 2.1 routes (`/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/.well-known/oauth-authorization-server`) backed by Cloudflare KV (`OAUTH_KV`).
- **Endpoint Protection**: Protects `/sse` and `/message` endpoints, requiring a valid `Bearer` token for all client requests.

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

### 2. Set Secret: `GEMINI_API_KEY`

Store your Google Gemini API key securely in Cloudflare Workers using Wrangler secrets:

```bash
wrangler secret put GEMINI_API_KEY
```

When prompted, paste your Gemini API key.

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

Configure Claude Desktop to connect to your remote MCP server via `mcp-remote`. Add the server configuration to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "antigravity": {
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
