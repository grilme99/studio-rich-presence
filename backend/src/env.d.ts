declare module "cloudflare:test" {
    // ProvidedEnv controls the type of `import("cloudflare:test").env`
    interface ProvidedEnv extends Env { }
}

/**
 * Environment bindings for the Worker.
 * 
 * D1 Database and KV Namespace are bound via wrangler.jsonc.
 * Secrets are set via: wrangler secret put <NAME>
 */
export interface Env {
    DB: D1Database;
    KV: KVNamespace;

    // Secrets (set via wrangler secret put)
    ENCRYPTION_KEY: string;        // Server-side key for Discord token encryption
    DISCORD_CLIENT_ID: string;     // Discord OAuth app client ID  
    DISCORD_CLIENT_SECRET: string; // Discord OAuth app client secret
    DISCORD_ID_SALT: string;       // Salt for hashing Discord user IDs
    POSTHOG_API_KEY: string;       // Posthog project API key
}

/**
 * User record from the database.
 */
export interface DbUser {
    id: string;
    auth_token_hash: string;
    pending_token_hash: string | null;
    pending_token_expires: number | null;
    created_at: number;
    updated_at: number;
    last_activity_at: number;
}

/**
 * Discord account record from the database.
 */
export interface DbDiscordAccount {
    id: string;
    user_id: string;
    discord_user_id_hash: string;
    access_token_enc: string;
    refresh_token_enc: string;
    token_expires_at: number;
    created_at: number;
    updated_at: number;
}

/**
 * Auth session record from the database.
 */
export interface DbAuthSession {
    id: string;
    code: string;
    user_id: string | null;
    state: 'pending' | 'started' | 'completed' | 'failed';
    completion_code: string | null;
    pkce_code_verifier: string;
    result_token: string | null;
    result_client_key: string | null;
    error_message: string | null;
    expires_at: number;
    created_at: number;
}

