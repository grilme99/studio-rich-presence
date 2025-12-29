/**
 * Shared test utilities for auth route tests.
 */

import { Hono } from 'hono';
import { auth } from '../index';
import type { Env } from '../../../env';
import { hashAuthToken, generateToken } from '../../../crypto';

// Extend the environment type to include the test env
type TestEnv = Env;

/**
 * Create test app with auth routes mounted.
 */
export function createTestApp() {
    const app = new Hono<{ Bindings: TestEnv }>();
    app.route('/api/auth', auth);  // Mount with /api prefix
    app.route('/auth', auth);      // Also mount without /api prefix for link/callback/sse
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
        INSERT INTO users (id, auth_token_hash, created_at, updated_at, last_activity_at)
        VALUES (?, ?, ?, ?, ?)
    `).bind(userId, tokenHash, now, now, now).run();

    return userId;
}

/**
 * Helper to create a test session directly in DB.
 */
export async function createTestSession(
    db: D1Database,
    options: {
        code: string;
        userId?: string | null;
        state?: string;
        completionCode?: string;
        codeVerifier?: string;
        resultToken?: string | null;
        resultClientKey?: string | null;
        errorMessage?: string | null;
        expiresAt?: number;
    }
) {
    const now = Date.now();
    const defaults = {
        userId: null,
        state: 'pending',
        completionCode: '12345',
        codeVerifier: generateToken(),  // 43 chars
        resultToken: null,
        resultClientKey: null,
        errorMessage: null,
        expiresAt: now + 300000,  // 5 minutes from now
    };

    const opts = { ...defaults, ...options };

    await db.prepare(`
        INSERT INTO auth_sessions (
            code, user_id, state, completion_code,
            pkce_code_verifier, result_token, result_client_key,
            error_message, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        opts.code,
        opts.userId,
        opts.state,
        opts.completionCode,
        opts.codeVerifier,
        opts.resultToken,
        opts.resultClientKey,
        opts.errorMessage,
        opts.expiresAt,
        now
    ).run();
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

/**
 * Helper to parse SSE events from response text.
 */
export function parseSseEvents(text: string): Array<{ event: string; data: unknown }> {
    const events: Array<{ event: string; data: unknown }> = [];
    const lines = text.split('\n');
    let currentEvent = '';
    let currentData = '';

    for (const line of lines) {
        if (line.startsWith('event: ')) {
            currentEvent = line.slice(7);
        } else if (line.startsWith('data: ')) {
            currentData = line.slice(6);
        } else if (line === '' && currentEvent) {
            try {
                events.push({
                    event: currentEvent,
                    data: currentData ? JSON.parse(currentData) : {},
                });
            } catch {
                events.push({ event: currentEvent, data: currentData });
            }
            currentEvent = '';
            currentData = '';
        }
    }

    return events;
}

