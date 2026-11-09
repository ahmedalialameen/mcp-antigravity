# Antigravity Remote MCP Server Specification

## 1. System Overview
This specification details a remote Model Context Protocol (MCP) server running on Cloudflare Workers. It exposes Google's Antigravity Agent runtime (code sandbox, file manipulation, and autonomous reasoning) to Claude clients (Claude Desktop, Claude Code, and Claude Web).

The server enforces OAuth 2.1 authentication backed by Cloudflare KV and exposes MCP transport over stateless HTTP (`/mcp`) using official SDK v2 (`@modelcontextprotocol/server`).

```
┌────────────────┐            HTTP POST (/mcp)             ┌───────────────────────────┐
│                │ ──────────────────────────────────────> │   Cloudflare Worker       │
│  Claude Client │ <────────────────────────────────────── │ (OAuth Resource Server)   │
│ (Desktop/Code) │   OAuth 2.1 PKCE Authorization          │                           │
└────────────────┘ <.....................................> │  - OAuth Provider (KV)    │
                                                           │  - MCP Server & Tools     │
                                                           └─────────────┬─────────────┘
                                                                         │ x-goog-api-key:
                                                                         │ $GEMINI_API_KEY
                                                                         ▼
                                                           ┌───────────────────────────┐
                                                           │ Google Antigravity Agent  │
                                                           │ (Interactions API Sandbox)│
                                                           └───────────────────────────┘
```

---

## 2. Environment & Configuration

### Dependencies (`package.json`)
```json
{
  "name": "antigravity-mcp-server",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "test": "vitest run"
  },
  "dependencies": {
    "@cloudflare/workers-oauth-provider": "^0.1.0",
    "@modelcontextprotocol/core": "^2.4.0",
    "@modelcontextprotocol/server": "^2.4.0",
    "zod": "^4.6.7"
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.7.0",
    "@cloudflare/workers-types": "^4.20250214.0",
    "typescript": "^5.7.0",
    "vitest": "^3.0.9",
    "wrangler": "^3.109.0"
  }
}
```

### Worker Configuration (`wrangler.jsonc`)
```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "antigravity-mcp-server",
  "main": "src/index.ts",
  "compatibility_date": "2026-01-01",
  "compatibility_flags": ["nodejs_compat"],
  "kv_namespaces": [
    {
      "binding": "OAUTH_KV",
      "id": "<YOUR_KV_NAMESPACE_ID>"
    }
  ],
  "vars": {
    "MCP_RESOURCE": "https://antigravity-mcp-server.<your-subdomain>.workers.dev/mcp",
    "ALLOWED_USERS": "user@example.com"
  }
}
```

### Secrets Setup
Secrets must be stored using Wrangler secrets:
```bash
npx wrangler secret put GEMINI_API_KEY
npx wrangler secret put AUTH_SECRET
```

---

## 3. Worker Implementation Summary

The server implements:
1. `callAntigravityAgent`: Uses Google's Interactions API endpoint `https://generativelanguage.googleapis.com/v1beta/interactions` with agent `antigravity-preview-09-2026`.
2. `createAntigravityMcpServer`: Registers `run_antigravity_agent` tool via `@modelcontextprotocol/server`.
3. `createMcpHandler`: Serves stateless MCP 2026-07-28 and 2025 fallback requests on `/mcp`.
4. RFC 9728 Discovery: Serves Protected Resource Metadata at `/.well-known/oauth-protected-resource/mcp` and challenges via `WWW-Authenticate`.
5. Security & Isolation: Enforces Host & Origin validation, dynamic CORS handling, Cloudflare Access JWT validation, and CSRF-protected OAuth consent.

---

## 4. Claude Client Configuration

Add to `claude_desktop_config.json`:

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
