# Cloudflare Workers MCP Server for Google Antigravity Agent

A remote Model Context Protocol (MCP) server deployed on Cloudflare Workers. It bridges Claude (Claude Desktop, Claude Code, and Claude Web) to Google's Antigravity Agent runtime (code sandbox, file manipulation, and autonomous reasoning) over stateless HTTP (`/mcp`), secured via OAuth 2.1 with PKCE backed by Cloudflare KV and identity verification (Cloudflare Access JWT assertions or trusted HMAC proxy).

## Features

- **Google Antigravity Integration**: Connects to Google's official Interactions API endpoint `https://generativelanguage.googleapis.com/v1beta/interactions` using the supported agent identifier `antigravity-preview-09-2026` and official `x-goog-api-key: <GEMINI_API_KEY>` header.
- **GitHub Official Remote MCP Integration**: Directly registers GitHub's official remote MCP endpoint (`https://api.githubcopilot.com/mcp/`) within Google Interactions API's `tools` array as an `mcp_server` authenticated via Google-managed credential IDs. No custom GitHub server or proxy required.
- **Controlled Operational Modes**: Restricts GitHub MCP tools across 4 explicit modes (`inspect`, `review`, `propose`, `implement`) using both Google's `allowed_tools` and GitHub remote headers (`X-MCP-Tools`, `X-MCP-Readonly`, `X-MCP-Exclude-Tools`).
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
                                                           │ - Builds tool allowlists  │
                                                           └─────────────┬─────────────┘
                                                                         │ POST /interactions
                                                                         │ x-goog-api-key
                                                                         ▼
                                                           ┌───────────────────────────┐
                                                           │ Google Antigravity Agent  │
                                                           │ (Linux Sandbox runtime)   │
                                                           └─────────────┬─────────────┘
                                                                         │ Managed Egress Proxy
                                                                         │ (Injects GitHub PAT)
                                                                         ▼
                                                           ┌───────────────────────────┐
                                                           │ GitHub Remote MCP Server  │
                                                           │ api.githubcopilot.com/mcp │
                                                           └───────────────────────────┘
```

The Worker stores **only the Google-managed credential IDs**, never GitHub Personal Access Tokens (PATs) or secrets. Tokens are resolved and injected securely by Google's managed agent egress proxy directly on outbound requests to `https://api.githubcopilot.com/mcp/`.

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

*Note: Both credential IDs are optional. Existing deployments without GitHub credentials configured retain their generic autonomous functionality. If a repository task is requested without the required credential ID configured, the Worker fails closed before sending any request to Google.*

---

## Security Boundaries & Limitations

1. **Authorization Boundary is the PAT Scope**: The `repository` tool argument is task context for the agent, **not** an authorization boundary. The actual repository boundary is enforced strictly by GitHub using the repository selection configured on the fine-grained PAT. Always limit PATs to selected repositories.
2. **Branch Protection & Rulesets Required**: The MCP tool allowlist permits `push_files`, but MCP tool allowlists cannot enforce which branch is passed as an argument to `push_files`. Mode selection in the application does not guarantee branch isolation. **You must configure GitHub branch protection rules or repository rulesets** on your default and protected branches (e.g. `main`) to reject direct pushes and force pushes, requiring changes to arrive via pull requests.
3. **No Merge Operations**: Merge tools (`merge_pull_request`), repository deletion/creation, branch-protection administration, repository settings, and secrets management are never exposed in any mode. Implementation tasks open draft pull requests for human review.
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

#### Running Optional Gated Live Integration Tests

The test suite includes gated live integration tests that test the live pathway (`Client HTTP Request -> Cloudflare Worker (/mcp) -> Bearer token validation -> MCP tools/call -> Google Interactions API -> Antigravity -> GitHub remote MCP -> GitHub`). These tests are disabled by default.

To run the live GitHub MCP integration test against an external environment:

```bash
RUN_LIVE_GITHUB_MCP_TESTS=true \
GEMINI_API_KEY="your-gemini-api-key" \
GITHUB_MCP_READ_CREDENTIAL_ID="your-read-credential-id" \
LIVE_TEST_GITHUB_REPO="your-org/your-private-test-repo" \
LIVE_TEST_EXPECTED_SNIPPET="expected file snippet" \
LIVE_TEST_GITHUB_PR=1 \
npm test
```

*Note on test execution & authorization scope: The live integration test exercises the Cloudflare Worker `/mcp` entry-point handler, JSON-RPC dispatch, and Bearer token validation using a valid synthetic access token provisioned directly into the test environment's `OAUTH_KV`. It does not test the interactive browser OAuth PKCE authorization or user consent screen flow. Furthermore, using a dedicated private test repository with a known file snippet is mandatory to verify fine-grained GitHub PAT repository authorization boundaries.*

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
}
```

### Operating Modes & GitHub Tool Restrictions

| Mode | Access Level | Credential Used | Exposed GitHub Tools | Headers Sent to GitHub MCP |
| :--- | :--- | :--- | :--- | :--- |
| `inspect` | Read-only | `GITHUB_MCP_READ_CREDENTIAL_ID` | `get_file_contents`, `search_code`, `pull_request_read`, `search_pull_requests` | `X-MCP-Tools: get_file_contents,search_code,pull_request_read,search_pull_requests`<br>`X-MCP-Readonly: true` |
| `review` | Read-only | `GITHUB_MCP_READ_CREDENTIAL_ID` | `get_file_contents`, `search_code`, `pull_request_read`, `search_pull_requests` | `X-MCP-Tools: get_file_contents,search_code,pull_request_read,search_pull_requests`<br>`X-MCP-Readonly: true` |
| `propose` | Read-only (suggest patches) | `GITHUB_MCP_READ_CREDENTIAL_ID` | `get_file_contents`, `search_code`, `pull_request_read`, `search_pull_requests` | `X-MCP-Tools: get_file_contents,search_code,pull_request_read,search_pull_requests`<br>`X-MCP-Readonly: true` |
| `implement` | Controlled write | `GITHUB_MCP_WRITE_CREDENTIAL_ID` | Read tools + `create_branch`, `push_files`, `create_pull_request` | `X-MCP-Tools: get_file_contents,search_code,pull_request_read,search_pull_requests,create_branch,push_files,create_pull_request`<br>`X-MCP-Exclude-Tools: merge_pull_request` |

**Native Capabilities Preserved**: In all modes, native agent tools (`code_execution`, `google_search`, `url_context`) and inline files (`contextFiles` under `environment.sources`) remain active. Stateful tool calling is maintained with `"store": true`.

**Implementation Task Workflow**:
When `mode: "implement"` is specified, Antigravity follows a strictly defined lifecycle:
1. Determines the base branch from `baseBranch` or uses the repository default branch if omitted.
2. Creates a dedicated feature branch named `antigravity/<descriptive-task-name>`.
3. Makes changes strictly on that feature branch.
4. `push_files` must target that feature branch. Never pushes directly to the base branch.
5. `create_pull_request` must be invoked with `draft: true`, using that feature branch as `head` and the specified `baseBranch` (or default branch) as `base`.
6. Runs relevant tests and reports their actual results.
7. Returns branch name, commit SHA, draft PR URL, and test results.
8. Safety restrictions: Never calls `merge_pull_request`. Never force-pushes.

*Note on authorization boundary: Because Google Antigravity invokes GitHub remote MCP tools directly without the Cloudflare Worker intercepting individual MCP tool arguments, the Worker cannot programmatically enforce the target branch string in `push_files`. GitHub branch protection rules or repository rulesets remain the mandatory authorization boundary preventing direct writes to default and protected branches.*

**Output:**

Returns the structured JSON response or an MCP error block (`isError: true`) if the API request fails.

Deployed with Cloudflare Workers Builds.
