declare module "cloudflare:test" {
  interface ProvidedEnv {
    CONSENT_COORDINATOR: DurableObjectNamespace;
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
    GITHUB_MCP_READ_CREDENTIAL_ID?: string;
    GITHUB_MCP_WRITE_CREDENTIAL_ID?: string;
  }
}
