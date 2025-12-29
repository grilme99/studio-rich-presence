/**
 * Tests for authentication middleware.
 */

import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { env } from 'cloudflare:test';
import { Hono } from 'hono';
import type { Env } from '../../env';
import { requireAuth, optionalAuth, type AuthVariables } from '../auth';
import { generateToken, hashAuthToken } from '../../crypto';

/**
 * Create a test user in the database.
 */
async function createTestUser(
    db: D1Database,
    authToken: string,
    pepper: string,
    options?: {
        pendingTokenHash?: string;
        pendingTokenExpires?: number;
    }
): Promise<string> {
    const userId = crypto.randomUUID();
    const tokenHash = await hashAuthToken(authToken, pepper);
    const now = Date.now();

    await db.prepare(`
        INSERT INTO users (id, auth_token_hash, pending_token_hash, pending_token_expires, created_at, updated_at, last_activity_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
        userId,
        tokenHash,
        options?.pendingTokenHash ?? null,
        options?.pendingTokenExpires ?? null,
        now,
        now,
        now
    ).run();

    return userId;
}

/**
 * Set up database schema.
 */
async function setupDatabase(db: D1Database) {
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
}

/**
 * Clean up database.
 */
async function cleanupDatabase(db: D1Database) {
    await db.prepare('DELETE FROM users').run();
}

describe('requireAuth middleware', () => {
    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        await cleanupDatabase(env.DB);
    });

    describe('Authorization header', () => {
        it('should authenticate with valid Bearer token', async () => {
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.get('/test', (c) => c.json({ userId: c.get('userId') }));

            const request = new Request('http://localhost/test', {
                headers: { Authorization: `Bearer ${authToken}` },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(200);
            const data = await response.json() as { userId: string };
            expect(data.userId).toBe(userId);
        });

        it('should reject missing Authorization header', async () => {
            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.get('/test', (c) => c.json({ ok: true }));

            const request = new Request('http://localhost/test');
            const response = await app.fetch(request, env);

            expect(response.status).toBe(401);
            const data = await response.json() as { code: string };
            expect(data.code).toBe('UNAUTHORIZED');
        });

        it('should reject invalid token format (no Bearer prefix)', async () => {
            const authToken = generateToken();
            await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.get('/test', (c) => c.json({ ok: true }));

            const request = new Request('http://localhost/test', {
                headers: { Authorization: authToken },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(401);
        });

        it('should reject non-existent token', async () => {
            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.get('/test', (c) => c.json({ ok: true }));

            const request = new Request('http://localhost/test', {
                headers: { Authorization: `Bearer ${generateToken()}` },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(401);
        });
    });

    describe('Request body token', () => {
        it('should authenticate with auth_token in body (snake_case)', async () => {
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.post('/test', (c) => c.json({ userId: c.get('userId') }));

            const request = new Request('http://localhost/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ auth_token: authToken }),
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(200);
            const data = await response.json() as { userId: string };
            expect(data.userId).toBe(userId);
        });

        it('should authenticate with authToken in body (camelCase)', async () => {
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.post('/test', (c) => c.json({ userId: c.get('userId') }));

            const request = new Request('http://localhost/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ authToken: authToken }),
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(200);
            const data = await response.json() as { userId: string };
            expect(data.userId).toBe(userId);
        });

        it('should prefer header over body token', async () => {
            const headerToken = generateToken();
            const bodyToken = generateToken();
            const userId = await createTestUser(env.DB, headerToken, env.ENCRYPTION_KEY);

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.post('/test', (c) => c.json({ userId: c.get('userId') }));

            const request = new Request('http://localhost/test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${headerToken}`,
                },
                body: JSON.stringify({ auth_token: bodyToken }),
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(200);
            const data = await response.json() as { userId: string };
            expect(data.userId).toBe(userId);
        });
    });

    describe('Pending token (token rotation)', () => {
        it('should authenticate with valid pending token', async () => {
            const activeToken = generateToken();
            const pendingToken = generateToken();
            const pendingTokenHash = await hashAuthToken(pendingToken, env.ENCRYPTION_KEY);

            const userId = await createTestUser(env.DB, activeToken, env.ENCRYPTION_KEY, {
                pendingTokenHash,
                pendingTokenExpires: Date.now() + 300000, // 5 minutes from now
            });

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.get('/test', (c) => c.json({ userId: c.get('userId') }));

            const request = new Request('http://localhost/test', {
                headers: { Authorization: `Bearer ${pendingToken}` },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(200);
            const data = await response.json() as { userId: string };
            expect(data.userId).toBe(userId);
        });

        it('should reject expired pending token', async () => {
            const activeToken = generateToken();
            const pendingToken = generateToken();
            const pendingTokenHash = await hashAuthToken(pendingToken, env.ENCRYPTION_KEY);

            await createTestUser(env.DB, activeToken, env.ENCRYPTION_KEY, {
                pendingTokenHash,
                pendingTokenExpires: Date.now() - 1000, // Expired 1 second ago
            });

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.get('/test', (c) => c.json({ ok: true }));

            const request = new Request('http://localhost/test', {
                headers: { Authorization: `Bearer ${pendingToken}` },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(401);
        });
    });
});

describe('optionalAuth middleware', () => {
    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        await cleanupDatabase(env.DB);
    });

    it('should set userId for valid token', async () => {
        const authToken = generateToken();
        const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

        const app = new Hono<{ Bindings: Env; Variables: Partial<AuthVariables> }>();
        app.use('*', optionalAuth);
        app.get('/test', (c) => c.json({ userId: c.get('userId') ?? null }));

        const request = new Request('http://localhost/test', {
            headers: { Authorization: `Bearer ${authToken}` },
        });
        const response = await app.fetch(request, env);

        expect(response.status).toBe(200);
        const data = await response.json() as { userId: string | null };
        expect(data.userId).toBe(userId);
    });

    it('should continue without userId for missing token', async () => {
        const app = new Hono<{ Bindings: Env; Variables: Partial<AuthVariables> }>();
        app.use('*', optionalAuth);
        app.get('/test', (c) => c.json({ userId: c.get('userId') ?? null }));

        const request = new Request('http://localhost/test');
        const response = await app.fetch(request, env);

        expect(response.status).toBe(200);
        const data = await response.json() as { userId: string | null };
        expect(data.userId).toBeNull();
    });

    it('should continue without userId for invalid token', async () => {
        const app = new Hono<{ Bindings: Env; Variables: Partial<AuthVariables> }>();
        app.use('*', optionalAuth);
        app.get('/test', (c) => c.json({ userId: c.get('userId') ?? null }));

        const request = new Request('http://localhost/test', {
            headers: { Authorization: `Bearer ${generateToken()}` },
        });
        const response = await app.fetch(request, env);

        expect(response.status).toBe(200);
        const data = await response.json() as { userId: string | null };
        expect(data.userId).toBeNull();
    });

    it('should set userId for valid pending token', async () => {
        const activeToken = generateToken();
        const pendingToken = generateToken();
        const pendingTokenHash = await hashAuthToken(pendingToken, env.ENCRYPTION_KEY);

        const userId = await createTestUser(env.DB, activeToken, env.ENCRYPTION_KEY, {
            pendingTokenHash,
            pendingTokenExpires: Date.now() + 300000,
        });

        const app = new Hono<{ Bindings: Env; Variables: Partial<AuthVariables> }>();
        app.use('*', optionalAuth);
        app.get('/test', (c) => c.json({ userId: c.get('userId') ?? null }));

        const request = new Request('http://localhost/test', {
            headers: { Authorization: `Bearer ${pendingToken}` },
        });
        const response = await app.fetch(request, env);

        expect(response.status).toBe(200);
        const data = await response.json() as { userId: string | null };
        expect(data.userId).toBe(userId);
    });
});

