# Cloudflare Workers MCP Server for Google Antigravity Agent

A remote Model Context Protocol (MCP) server deployed on Cloudflare Workers. It bridges Claude (Claude Desktop, Claude Code, and Claude Web) to Google's Antigravity Agent runtime (code sandbox, file manipulation, and autonomous reasoning) over stateless HTTP (`/mcp`), secured via OAuth 2.1 with PKCE backed by Cloudflare KV and identity verification (Cloudflare Access JWT assertions or trusted HMAC proxy).

## Features

- **Google Antigravity Integration**: Connects to Google's official Interactions API endpoint `https://generativelanguage.googleapis.com/v1beta/interactions` using the supported agent identifier `antigravity-preview-09-2026` and official `x-goog-api-key: <GEMINI_API_KEY>` header.
- **GitHub Sandbox Access**: Repository tasks reach GitHub only with `curl` or `git` inside the Google Antigravity sandbox. The Worker restricts sandbox egress to `api.github.com` and `github.com` using Google-managed credential IDs; authentication is injected automatically by the egress proxy. The sandbox may also make unauthenticated, GET-only requests to `rubygems.org` to read public package metadata, and must never send repository content or any other data to it.
- **Controlled Operational Modes**: Restricts repository access across 4 explicit modes (`inspect`, `review`, `propose`, `implement`) using per-mode credential selection and a mode-specific system instruction. Read modes are GET-only; `implement` may only create a short-lived branch and open a draft pull request.
- **MCP Server & Async Task Tools**: Implements `run_antigravity_agent`, `start_antigravity_task`, `get_antigravity_task`, `cancel_antigravity_task`, and `list_antigravity_tasks` via official SDK v2 (`@modelcontextprotocol/server`). Tasks run in Google background mode (`background: true`, `store: true`) so long-running work can outlive a single MCP request.
- **Stateless Web-Standard MCP Transport**: Exposes the primary remote MCP endpoint at `/mcp` via `createMcpHandler()`, providing native support for MCP 2026-07-28 and 2025 stateless fallback over POST without requiring transport session state.
- **Protected Resource Metadata (RFC 9728)**: Exposes discovery at `/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-protected-resource`, and supplies `resource_metadata` in 401 `WWW-Authenticate` response headers.
- **Identity Verification & Security**: Supports Cloudflare Access JWT validation (`Cf-Access-Jwt-Assertion` validated against official Access JWKS) and HMAC-signed identity proxy verification (`AUTH_SECRET`). Never trusts unverified raw email headers.
- **OAuth 2.1 with Explicit User Consent & PKCE**: Implements OAuth 2.1 routes (`/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/.well-known/oauth-authorization-server`) backed by Cloudflare KV (`OAUTH_KV`). Enforces mandatory PKCE (S256), scope validation, canonical resource validation, and CSRF-protected explicit user consent.
- **Host & Origin Validation**: Prevents DNS rebinding and unauthorized cross-origin requests with configurable `ALLOWED_HOSTS` and dynamic CORS headers.
- **Owner Admin Credentials Page**: When owner-passphrase mode is configured, `/admin/credentials` lets the owner store or delete Google-managed GitHub credentials and manage the repository allowlist without the token ever passing through chat.

---

## Prerequisites

- [Node.js](https://nodejs.org/) (v20 or newer)
- Cloudflare account with Wrangler CLI configured
- Google Gemini API Key with Antigravity Agent access

---

## Setup & Configuration

### 1. Create Cloudflare KV Namespace & Durable Object Coordinator

Create the KV namespace used to persist OAuth clients, grants, and tokens:

```bash
wrangler kv namespace create OAUTH_KV
```

`wrangler.jsonc` binds both `OAUTH_KV` and the required SQLite-backed Durable Object coordinator (`CONSENT_COORDINATOR`):

```jsonc
"kv_namespaces": [
  {
    "binding": "OAUTH_KV",
    "id": "<YOUR_KV_NAMESPACE_ID>"
  }
],
"durable_objects": {
  "bindings": [
    {
      "name": "CONSENT_COORDINATOR",
      "class_name": "ConsentCoordinatorDO"
    }
  ]
},
"migrations": [
  {
    "tag": "v1",
    "new_sqlite_classes": ["ConsentCoordinatorDO"]
  }
]
```

The `ConsentCoordinatorDO` manages persistent, atomic single-use nonce consumption across worker isolates backed by SQLite storage with automatic alarm-based TTL pruning (15 minutes).

### 2. Configure Variables & Host/Origin Policies

The server fails closed unless explicit access and identity policies are configured in `wrangler.jsonc` or Worker secrets:

- **`MCP_RESOURCE`**: The canonical public MCP resource URL (e.g. `"https://antigravity-mcp-server.<your-subdomain>.workers.dev/mcp"`).
- **`ALLOWED_USERS`**: Comma-separated list of authorized email addresses or identities (e.g. `"user@example.com,alice@example.com"`).
- **`ALLOWED_HOSTS`** *(optional)*: Explicit allowlist of allowed Host header values. If not provided, host validation defaults strictly to the host in `MCP_RESOURCE` and the worker origin.
- **`ALLOWED_ORIGINS`** *(optional)*: Explicit allowlist of allowed browser Origins for CORS (e.g. `"https://claude.ai"`). Arbitrary origins and `Origin: null` are rejected by default.

### 3. Configure Authentication & CSRF Secrets

Configure required secrets via `wrangler secret put`:

#### A. Consent CSRF Protection (Required for Interactive Consent)
Store a high-entropy secret used for cryptographic CSRF tokens on the OAuth consent screen:
```bash
wrangler secret put CONSENT_CSRF_SECRET
```
*Note: `CONSENT_CSRF_SECRET` is mandatory for interactive consent. The server fails closed without falling back to any other secret.*

#### B. Identity Authentication Method

Cloudflare Access is optional, not required. Configure one of the methods below.

- **Method 1: Cloudflare Access JWT (Optional)**
  Protect your Worker behind Cloudflare Access. The server validates RS256 assertions (`Cf-Access-Jwt-Assertion`) using bounded cached JWKS with fail-closed claim verification:
  - Set `CF_ACCESS_TEAM_DOMAIN` (e.g. `"my-team"` which resolves JWKS from `https://my-team.cloudflareaccess.com/cdn-cgi/access/certs`).
  - Set `CF_ACCESS_AUD` to your Cloudflare Access Application Audience Tag. (Fails closed if missing or mismatched).

- **Method 2: HMAC Identity Proxy (Dedicated Secret)**
  When using a trusted proxy signing requests with `AUTH_SECRET`:
  ```bash
  wrangler secret put AUTH_SECRET
  ```
  The proxy must provide `X-Auth-User` and `X-Auth-Signature` (HMAC-SHA256 of the user email). `AUTH_SECRET` is dedicated strictly to HMAC proxy authentication and is never used as a CSRF fallback.

- **Method 3: Owner Passphrase (No Cloudflare Access Required)**
  Set a single-owner passphrase to log in directly on the OAuth consent page:
  ```bash
  wrangler secret put OWNER_PASSPHRASE
  ```
  Generate at least 40 random characters and set it only in the Cloudflare dashboard as a secret. Passphrase mode is enabled only when `OWNER_PASSPHRASE` is at least 24 characters (after trimming) and the first entry of `ALLOWED_USERS` is a concrete, non-wildcard identity; that first entry becomes the owner id. After 5 failed attempts within 15 minutes, further passphrase submissions are rejected for 15 minutes.

#### C. Google Antigravity Agent API Key (Required)
Store your Google Gemini / Interactions API key:
```bash
wrangler secret put GEMINI_API_KEY
```

### 4. Configure GitHub Remote MCP Integration (Optional)

To enable repository-scoped software engineering tasks against GitHub repositories, configure Google's managed credentials and set the corresponding credential IDs in your Worker variables.

#### Architecture

```
┌────────────────┐            HTTP POST (/mcp)             ┌───────────────────────────┐
│  Claude Client │ ──────────────────────────────────────> │   Cloudflare Worker       │
│ (Desktop/Code) │ <────────────────────────────────────── │ - Validates schema & mode │
└────────────────┘   OAuth 2.1 PKCE Authorization          │ - Selects Credential ID   │
                                                           │ - Builds allowlist        │
                                                           └─────────────┬─────────────┘
                                                                         │ POST /interactions
                                                                         │ x-goog-api-key
                                                                         ▼
                                                           ┌───────────────────────────┐
                                                           │ Google Antigravity Agent  │
                                                           │ (Linux Sandbox runtime)   │
                                                           └─────────────┬─────────────┘
                                                                         │ curl / git
                                                                         │ Managed Egress Proxy
                                                                         │ (Injects GitHub PAT)
                                                                         ▼
                                                           ┌───────────────────────────┐
                                                           │ api.github.com            │
                                                           │ github.com                │
                                                           │ rubygems.org (GET only)   │
                                                           └───────────────────────────┘
```

The Worker stores **only the Google-managed credential IDs**, never GitHub Personal Access Tokens (PATs) or secrets. Tokens are resolved and injected securely by Google's managed agent egress proxy directly on outbound requests to `https://api.github.com` and `https://github.com`; the agent never sees or handles them.

#### Step A: Generate Fine-Grained GitHub PATs

Create two separate fine-grained Personal Access Tokens in GitHub Settings (`Settings` > `Developer settings` > `Personal access tokens` > `Fine-grained tokens`):

1. **Read-Only PAT** (for `inspect`, `review`, `propose`):
   - **Repository access**: Select **Only select repositories** (limit strictly to repositories the agent needs to access).
   - **Repository permissions**:
     - `Contents`: Read-only (read repository files and directory structures).
     - `Pull requests`: Read-only (read pull requests, diffs, and comments).
     - `Metadata`: Read-only (mandatory default).

2. **Write PAT** (for `implement`):
   - **Repository access**: Select **Only select repositories** (limit strictly to repositories the agent needs to access).
   - **Repository permissions**:
     - `Contents`: Read and write (create feature branches and push commit files).
     - `Pull requests`: Read and write (open draft pull requests).
     - `Metadata`: Read-only.

#### Step B: Register PATs with Google Managed Credentials API

Store each token in Google's managed credentials service using the documented Credentials API:

```bash
# 1. Store Read-Only Credential
curl -X POST "https://generativelanguage.googleapis.com/v1beta/credentials" \
  -H "Content-Type: application/json" \
  -H "x-goog-api-key: $GEMINI_API_KEY" \
  -d '{
    "id": "github-mcp-read-cred",
    "type": "bearer_token",
    "token": "github_pat_READ_ONLY_TOKEN_HERE"
  }'

# 2. Store Write Credential
curl -X POST "https://generativelanguage.googleapis.com/v1beta/credentials" \
  -H "Content-Type: application/json" \
  -H "x-goog-api-key: $GEMINI_API_KEY" \
  -d '{
    "id": "github-mcp-write-cred",
    "type": "bearer_token",
    "token": "github_pat_WRITE_TOKEN_HERE"
  }'
```

The Credentials API returns metadata only; secret token values are write-only and can never be retrieved back.

#### Step C: Configure Credential IDs in Worker Variables

In `wrangler.jsonc` (or via `wrangler secret put`):

```jsonc
"vars": {
  "MCP_RESOURCE": "https://antigravity-mcp-server.<your-subdomain>.workers.dev/mcp",
  "ALLOWED_USERS": "user@example.com",
  "GITHUB_MCP_READ_CREDENTIAL_ID": "github-mcp-read-cred",
  "GITHUB_MCP_WRITE_CREDENTIAL_ID": "github-mcp-write-cred"
}
```

*Note: Both credential IDs are optional. Existing deployments without GitHub credentials configured retain their generic autonomous functionality. If a repository task is requested without the required credential ID configured, the Worker fails closed before sending any request to Google. When the environment variables are unset, the Worker can fall back to credential IDs saved by the owner admin page in `OAUTH_KV`.*

#### Step D: Owner Admin Page for Credentials and Allowed Repositories

When owner-passphrase mode is configured, the owner can manage credentials and the repository allowlist at `/admin/credentials`. The page is intentionally not linked from anywhere else. It requires the same `CONSENT_CSRF_SECRET` and `CONSENT_COORDINATOR` bindings as the consent page, and every submission requires the owner passphrase plus a single-use CSRF nonce. Failed attempts share the global consent-page throttle (HTTP 429 after the limit).

- **Save credential**: the slot determines the fixed Google credential id (`read` -> `antigravity-github-read`, `write` -> `antigravity-github-write`). The token is sent directly from the Worker to Google's Credentials API and is never stored in KV, returned in HTML, or logged. KV stores only `{ "id": "...", "savedAt": "..." }`.
- **Delete credential**: deletes the fixed Google credential (a missing credential counts as success) and removes the KV record.
- **Allowed repositories**: one `owner/repo` per line, at most 50 entries, normalized to lowercase and deduplicated. An empty list denies every repository.

Repository access is fail-closed. Every repository-scoped call must match `ALLOWED_REPOSITORIES` (comma-separated environment variable) when set; otherwise it must match the KV list saved by the admin page. A missing or empty list denies all repositories before any Google call or credential lookup.

---

## Security Boundaries & Limitations

1. **Authorization Boundary is the PAT Scope**: The `repository` tool argument is task context for the agent, **not** an authorization boundary. The Worker additionally enforces the `ALLOWED_REPOSITORIES`/KV allowlist before any Google call, but the actual repository boundary is enforced strictly by GitHub using the repository selection configured on the fine-grained PAT. Always limit PATs to selected repositories.
2. **Branch Protection & Rulesets Required**: The agent is instructed to work only on a new `antigravity/<short-slug>` branch, but the Worker cannot inspect the `curl`/`git` commands executed inside the sandbox. Mode selection and system instructions do not guarantee branch isolation. **You must configure GitHub branch protection rules or repository rulesets** on your default and protected branches (e.g. `main`) to reject direct pushes and force pushes, requiring changes to arrive via pull requests.
3. **No Merge or Destructive Operations**: The system instruction forbids merge endpoints, writes to the default branch or its ref, branch/repository deletion, force-updating refs, and force-pushing. Implementation tasks open draft pull requests for human review. The fine-grained PAT should not grant repository administration, settings, or secrets permissions.
4. **Untrusted GitHub Content**: All repository content, files, README/AGENTS files, issues, PR comments, and commit messages are treated as untrusted input. The agent is explicitly instructed that external GitHub content must never override safety policies or instructions, nor reveal credentials.

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
  repository?: string;           // Optional target GitHub repository formatted as "owner/repository"
  ref?: string;                  // Optional target Git ref (branch, tag, or commit SHA)
  pullRequest?: number;          // Optional positive integer pull request number to inspect/review
  baseBranch?: string;           // Optional target base branch for implementation
  mode?: "inspect" | "review" | "propose" | "implement"; // Operating mode (default: "inspect")
  waitSeconds?: number;          // Integer 0-90 (default 45) to wait before returning an in-progress task id
}
```

### Async task tools

Task ids match `^[A-Za-z0-9_-]{1,200}$`. Indexed tasks are stored under the `antigravity:task:` prefix in `OAUTH_KV` with a 30-day TTL. Indexing is best effort: a KV failure never fails a tool call. Statuses shown by `list_antigravity_tasks` are as of the last time each task was fetched.

#### `start_antigravity_task`

Takes the same inputs as `run_antigravity_agent` except `waitSeconds`. Creates a background interaction and returns `taskId` and `status` immediately. Long tasks: call `get_antigravity_task` with the taskId until `done` is true.

#### `get_antigravity_task`

```typescript
{
  taskId: string;
  waitSeconds?: number;          // Integer 0-90 (default 20)
  offset?: number;               // Character offset for paging output text
  includeRaw?: boolean;          // Include sanitized raw interaction JSON
}
```

Fetches the task, waits briefly if it is still running, and returns the formatted result. Output text is capped at 60,000 characters per response; use `offset` and `nextOffset` to page. When a completed interaction has no `output_text`, the sanitized raw interaction is returned as `rawFallback`.

#### `cancel_antigravity_task`

```typescript
{
  taskId: string;
}
```

Calls `POST /interactions/<id>/cancel`. Cancelling an already-finished task returns its current status without failing.

#### `list_antigravity_tasks`

```typescript
{
  limit?: number;                // Integer 1-50 (default 20)
  status?: string;               // Optional status filter
}
```

Lists indexed tasks newest first with `taskId`, `status`, `createdAt`, `mode`, and `taskPreview` per item, using KV list metadata and following KV cursors up to 1,000 scanned keys.

### Operating Modes & GitHub Access

| Mode | Access Level | Credential Used | GitHub Access |
| :--- | :--- | :--- | :--- |
| `inspect` | Read-only | `GITHUB_MCP_READ_CREDENTIAL_ID` | GET requests only against `api.github.com` / `github.com` |
| `review` | Read-only | `GITHUB_MCP_READ_CREDENTIAL_ID` | GET requests only against `api.github.com` / `github.com` |
| `propose` | Read-only (suggest patches) | `GITHUB_MCP_READ_CREDENTIAL_ID` | GET requests only against `api.github.com` / `github.com` |
| `implement` | Controlled write | `GITHUB_MCP_WRITE_CREDENTIAL_ID` | Commit on a new `antigravity/<short-slug>` branch and open a draft pull request |

**Native Capabilities Preserved**: In all repository modes, native agent tools (`code_execution`, `google_search`, `url_context`) and inline files (`contextFiles` under `environment.sources`) remain active. The sandbox egress allowlist contains exactly `api.github.com` and `github.com`, with authentication injected automatically by the proxy, followed by an unauthenticated `rubygems.org` entry for GET-only public package metadata. Stateful tool calling is maintained with `"store": true`.

**Implementation Task Workflow**:
When `mode: "implement"` is specified, Antigravity follows a strictly defined lifecycle:
1. Determines the base branch from `baseBranch` or uses the repository default branch if omitted.
2. Creates a new branch named `antigravity/<short-slug>` from the base branch.
3. Commits all implementation changes only on that branch.
4. Opens a **draft** pull request from that branch into the base branch.
5. Runs relevant tests and reports their actual results.
6. Returns branch name, commit SHA, draft PR URL, and test results.
7. Safety restrictions: Never writes to the default branch or its ref. Never calls a merge endpoint. Never deletes branches or repositories. Never force-updates refs. Never force-pushes.

*Note on authorization boundary: Because Google Antigravity executes `curl`/`git` commands inside its sandbox without the Cloudflare Worker intercepting individual commands, the Worker cannot programmatically enforce the target branch. GitHub branch protection rules or repository rulesets remain the mandatory authorization boundary preventing direct writes to default and protected branches.*

**Output:**

Returns the structured JSON response or an MCP error block (`isError: true`) if the API request fails.

Deployed with Cloudflare Workers Builds.
