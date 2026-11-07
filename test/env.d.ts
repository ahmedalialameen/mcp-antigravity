declare module "cloudflare:test" {
  interface ProvidedEnv {
    OAUTH_KV: KVNamespace;
    GEMINI_API_KEY: string;
    MCP_RESOURCE: string;
    MCP_SESSION: DurableObjectNamespace;
    ALLOWED_USERS?: string;
    AUTH_SECRET?: string;
  }
}
