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
                                                           └─────────────┬─────────────┘
                                                                         │ Managed Egress Proxy
                                                                         │ (Injects GitHub PAT)
                                                                         ▼
                                                           ┌───────────────────────────┐
                                                           │ GitHub Remote MCP Server  │
                                                           │ api.githubcopilot.com/mcp │
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
    "ALLOWED_USERS": "user@example.com",
    "GITHUB_MCP_READ_CREDENTIAL_ID": "github-mcp-read-cred",
    "GITHUB_MCP_WRITE_CREDENTIAL_ID": "github-mcp-write-cred"
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
1. `callAntigravityAgent`: Uses Google's Interactions API endpoint `https://generativelanguage.googleapis.com/v1beta/interactions` with agent `antigravity-preview-09-2026`. Registers the official GitHub remote MCP server (`https://api.githubcopilot.com/mcp/`) within the `tools` array using Google-managed credential references, narrow allowlists, and remote headers, while strictly preserving native agent tools (`code_execution`, `google_search`, `url_context`) and inline files under `environment.sources`. Sets `store: true` for stateful execution.
2. `createAntigravityMcpServer`: Registers `run_antigravity_agent` tool via `@modelcontextprotocol/server` supporting extended repository-scoped parameters and 4 operating modes.
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

---

## 5. Tool Specification: `run_antigravity_agent`

### Input Schema

```typescript
{
  task: string;                  // Instructions describing software task, bug fix, or analysis
  contextFiles?: Record<string, string>; // Optional mapping of file paths to raw contents
  repository?: string;           // Optional target GitHub repository formatted as "owner/repository"
  ref?: string;                  // Optional target Git ref (branch, tag, or commit SHA)
  pullRequest?: number;          // Optional positive integer pull request number to inspect/review
  baseBranch?: string;           // Optional target base branch for implementation
  mode?: "inspect" | "review" | "propose" | "implement"; // Operating mode (default: "inspect")
}
```

### Operational Modes & GitHub MCP Tool Allowlists

| Mode | Allowed GitHub Tools | Remote Headers | Google Managed Credential |
| :--- | :--- | :--- | :--- |
| `inspect` | `get_file_contents`<br>`search_code`<br>`pull_request_read`<br>`search_pull_requests` | `X-MCP-Tools: get_file_contents,search_code,pull_request_read,search_pull_requests`<br>`X-MCP-Readonly: true` | `GITHUB_MCP_READ_CREDENTIAL_ID` |
| `review` | `get_file_contents`<br>`search_code`<br>`pull_request_read`<br>`search_pull_requests` | `X-MCP-Tools: get_file_contents,search_code,pull_request_read,search_pull_requests`<br>`X-MCP-Readonly: true` | `GITHUB_MCP_READ_CREDENTIAL_ID` |
| `propose` | `get_file_contents`<br>`search_code`<br>`pull_request_read`<br>`search_pull_requests` | `X-MCP-Tools: get_file_contents,search_code,pull_request_read,search_pull_requests`<br>`X-MCP-Readonly: true` | `GITHUB_MCP_READ_CREDENTIAL_ID` |
| `implement` | `get_file_contents`<br>`search_code`<br>`pull_request_read`<br>`search_pull_requests`<br>`create_branch`<br>`push_files`<br>`create_pull_request` | `X-MCP-Tools: get_file_contents,search_code,pull_request_read,search_pull_requests,create_branch,push_files,create_pull_request`<br>`X-MCP-Exclude-Tools: merge_pull_request` | `GITHUB_MCP_WRITE_CREDENTIAL_ID` |

---

## 6. GitHub Remote MCP Integration & Google Managed Credentials

### Credentials API Setup
GitHub Personal Access Tokens (PATs) are never stored in Cloudflare Workers variables, secrets, or logs. They are stored directly in Google's managed credentials service:

1. **Read-Only PAT**:
   - Scope: Selected repositories only.
   - Permissions: `Contents: Read-only`, `Pull requests: Read-only`, `Metadata: Read-only`.
   - Stored in Google via `POST https://generativelanguage.googleapis.com/v1beta/credentials` with ID e.g. `github-mcp-read-cred`.

2. **Write PAT**:
   - Scope: Selected repositories only.
   - Permissions: `Contents: Read and write`, `Pull requests: Read and write`, `Metadata: Read-only`.
   - Stored in Google via `POST https://generativelanguage.googleapis.com/v1beta/credentials` with ID e.g. `github-mcp-write-cred`.

### Crucial Security Boundaries & Requirements
1. **GitHub Repository Scope is the Authorization Boundary**: The `repository` tool argument provides context to the agent prompt; it is **not** an authorization boundary. Actual repository access is enforced by GitHub according to the repository scope of the fine-grained PAT.
2. **Branch Protection & Ruleset Requirement**: The MCP allowlist permits `push_files`, but cannot restrict which branch string is passed to `push_files`. Because tool calls are dispatched directly by the agent to GitHub remote MCP, the Cloudflare Worker cannot intercept or alter tool call parameters. Explicit system instructions mandate creating `antigravity/<descriptive-task-name>` and targeting that branch in `push_files` and PR `head`, but branch protection rulesets must be configured on default and protected branches (e.g., `main`) to enforce PR review and prevent direct pushes or force pushes.
3. **Excluded Write Operations**: Merge operations (`merge_pull_request`), branch protection modification, repository deletion, and secret administration are permanently disabled and excluded.
4. **Untrusted GitHub Input**: All external repository files, issues, PR comments, and commit messages are treated as untrusted data that must not override agent system policies or compromise credentials.
