/**
 * Shared test utilities for accounts route tests.
 */

import { Hono } from 'hono';
import { accountsRouter } from '../index';
import type { Env } from '../../../env';
import { hashAuthToken, generateToken, deriveEncryptionKey, encryptDiscordTokens } from '../../../crypto';

// Extend the environment type to include the test env
type TestEnv = Env;

/**
 * Create test app with accounts routes mounted.
 */
export function createTestApp() {
    const app = new Hono<{ Bindings: TestEnv }>();
    app.route('/accounts', accountsRouter);
    return app;
}

/**
 * Helper to make HTTP requests to the test app.
 */
export async function makeRequest(
    app: Hono<{ Bindings: TestEnv }>,
    path: string,
    env: TestEnv,
    options: {
        method?: string;
        body?: object;
        headers?: Record<string, string>;
    } = {}
) {
    const { method = 'GET', body, headers = {} } = options;

    const request = new Request(`http://localhost${path}`, {
        method,
        headers: {
            'Content-Type': 'application/json',
            'cf-connecting-ip': '192.168.1.1',
            ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
    });

    return app.fetch(request, env);
}

/**
 * Helper to create a test user directly in DB.
 */
export async function createTestUser(
    db: D1Database,
    authToken: string,
    pepper: string
): Promise<string> {
    const userId = crypto.randomUUID();
    const tokenHash = await hashAuthToken(authToken, pepper);
    const now = Date.now();

    await db.prepare(`
        INSERT INTO users (
            id, auth_token_hash, pending_token_hash, pending_token_expires,
            created_at, updated_at, last_activity_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
        userId,
        tokenHash,
        null,
        null,
        now,
        now,
        now
    ).run();

    return userId;
}

/**
 * Helper to create a linked Discord account for a user.
 */
export async function createTestDiscordAccount(
    db: D1Database,
    userId: string,
    clientKey: string,
    serverSecret: string,
    options: {
        createdAt?: number;
    } = {}
): Promise<string> {
    const accountId = crypto.randomUUID();
    const discordUserIdHash = await hashAuthToken(crypto.randomUUID(), serverSecret);
    const now = Date.now();
    const createdAt = options.createdAt ?? now;

    const accessToken = 'test-access-token';
    const refreshToken = 'test-refresh-token';
    const tokenExpiresAt = now + 3600000; // 1 hour from now

    // Encrypt tokens
    const encryptionKey = await deriveEncryptionKey(serverSecret, clientKey, userId);
    const { accessTokenEnc, refreshTokenEnc } = await encryptDiscordTokens(
        accessToken,
        refreshToken,
        encryptionKey
    );

    await db.prepare(`
        INSERT INTO discord_accounts (
            id, user_id, discord_user_id_hash,
            access_token_enc, refresh_token_enc, token_expires_at,
            created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        accountId,
        userId,
        discordUserIdHash,
        accessTokenEnc,
        refreshTokenEnc,
        tokenExpiresAt,
        createdAt,
        now
    ).run();

    return accountId;
}

/**
 * Helper to clean up database.
 */
export async function cleanupDatabase(db: D1Database) {
    await db.prepare('DELETE FROM auth_sessions').run();
    await db.prepare('DELETE FROM discord_accounts').run();
    await db.prepare('DELETE FROM users').run();
}

/**
 * Helper to clean up KV.
 */
export async function cleanupKV(kv: KVNamespace) {
    const keys = await kv.list();
    for (const key of keys.keys) {
        await kv.delete(key.name);
    }
}

/**
 * Run migrations to create test database schema.
 */
export async function setupDatabase(db: D1Database) {
    await db.exec(
        "CREATE TABLE IF NOT EXISTS users (" +
        "id TEXT PRIMARY KEY, " +
        "auth_token_hash TEXT NOT NULL UNIQUE, " +
        "pending_token_hash TEXT, " +
        "pending_token_expires INTEGER, " +
        "created_at INTEGER NOT NULL, " +
        "updated_at INTEGER NOT NULL, " +
        "last_activity_at INTEGER NOT NULL)"
    );

    await db.exec(
        "CREATE TABLE IF NOT EXISTS discord_accounts (" +
        "id TEXT PRIMARY KEY, " +
        "user_id TEXT NOT NULL, " +
        "discord_user_id_hash TEXT NOT NULL UNIQUE, " +
        "access_token_enc TEXT NOT NULL, " +
        "refresh_token_enc TEXT NOT NULL, " +
        "token_expires_at INTEGER NOT NULL, " +
        "created_at INTEGER NOT NULL, " +
        "updated_at INTEGER NOT NULL, " +
        "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)"
    );

    await db.exec(
        "CREATE TABLE IF NOT EXISTS auth_sessions (" +
        "code TEXT PRIMARY KEY, " +
        "user_id TEXT, " +
        "state TEXT NOT NULL, " +
        "completion_code TEXT, " +
        "pkce_code_verifier TEXT NOT NULL, " +
        "result_token TEXT, " +
        "result_client_key TEXT, " +
        "error_message TEXT, " +
        "expires_at INTEGER NOT NULL, " +
        "created_at INTEGER NOT NULL, " +
        "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)"
    );
}

