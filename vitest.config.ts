import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
        isolatedStorage: false
      }
    },
    deps: {
      optimizer: {
        ssr: {
          enabled: true,
          include: ["statuses", "raw-body", "http-errors"]
        }
      }
    }
  }
});
