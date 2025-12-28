import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
    test: {
        poolOptions: {
            workers: {
                wrangler: { configPath: "./wrangler.jsonc" },
                miniflare: {
                    bindings: {
                        // Test secrets (these would be set via wrangler secret in production)
                        ENCRYPTION_KEY: "test-encryption-key-must-be-32chars!",
                        DISCORD_CLIENT_ID: "test-discord-client-id",
                        DISCORD_CLIENT_SECRET: "test-discord-client-secret",
                        DISCORD_ID_SALT: "test-discord-id-salt-for-testing",
                        POSTHOG_API_KEY: "test-posthog-api-key",
                    },
                },
            },
        },
    },
});