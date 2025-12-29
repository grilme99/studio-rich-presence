/**
 * Tests for activity tracking middleware.
 */

import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { env } from 'cloudflare:test';
import { Hono } from 'hono';
import type { Env } from '../../env';
import { trackActivity } from '../activityTracker';
import { requireAuth, type AuthVariables } from '../auth';
import { generateToken, hashAuthToken } from '../../crypto';

/**
 * Create a test user in the database.
 */
async function createTestUser(
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

describe('trackActivity middleware', () => {
    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        await cleanupDatabase(env.DB);
    });

    describe('successful requests', () => {
        it('should update last_activity_at on 200 response', async () => {
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            // Get initial timestamp
            const beforeUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();
            const initialTimestamp = beforeUser!.last_activity_at;

            // Small delay to ensure time difference
            await new Promise(resolve => setTimeout(resolve, 10));

            // Create test app with auth + activity tracker
            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.use('*', trackActivity);
            app.get('/test', (c) => c.json({ success: true }));

            const request = new Request('http://localhost/test', {
                headers: { Authorization: `Bearer ${authToken}` },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(200);

            // Wait for waitUntil to complete
            await new Promise(resolve => setTimeout(resolve, 50));

            // Check timestamp was updated
            const afterUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();

            expect(afterUser!.last_activity_at).toBeGreaterThan(initialTimestamp);
        });

        it('should update last_activity_at on 201 response', async () => {
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const beforeUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();

            await new Promise(resolve => setTimeout(resolve, 10));

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.use('*', trackActivity);
            app.post('/create', (c) => c.json({ created: true }, 201));

            const request = new Request('http://localhost/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${authToken}`,
                },
                body: JSON.stringify({}),
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(201);

            await new Promise(resolve => setTimeout(resolve, 50));

            const afterUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();

            expect(afterUser!.last_activity_at).toBeGreaterThan(beforeUser!.last_activity_at);
        });

        it('should update last_activity_at on 204 response', async () => {
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const beforeUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();

            await new Promise(resolve => setTimeout(resolve, 10));

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.use('*', trackActivity);
            app.delete('/delete', (c) => c.body(null, 204));

            const request = new Request('http://localhost/delete', {
                method: 'DELETE',
                headers: { Authorization: `Bearer ${authToken}` },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(204);

            await new Promise(resolve => setTimeout(resolve, 50));

            const afterUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();

            expect(afterUser!.last_activity_at).toBeGreaterThan(beforeUser!.last_activity_at);
        });
    });

    describe('failed requests', () => {
        it('should NOT update last_activity_at on 400 response', async () => {
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const beforeUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();
            const initialTimestamp = beforeUser!.last_activity_at;

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.use('*', trackActivity);
            app.get('/bad', (c) => c.json({ error: 'bad request' }, 400));

            const request = new Request('http://localhost/bad', {
                headers: { Authorization: `Bearer ${authToken}` },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(400);

            await new Promise(resolve => setTimeout(resolve, 50));

            const afterUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();

            // Timestamp should NOT have changed
            expect(afterUser!.last_activity_at).toBe(initialTimestamp);
        });

        it('should NOT update last_activity_at on 500 response', async () => {
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const beforeUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();
            const initialTimestamp = beforeUser!.last_activity_at;

            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.use('*', trackActivity);
            app.get('/error', (c) => c.json({ error: 'internal error' }, 500));

            const request = new Request('http://localhost/error', {
                headers: { Authorization: `Bearer ${authToken}` },
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(500);

            await new Promise(resolve => setTimeout(resolve, 50));

            const afterUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first<{ last_activity_at: number }>();

            expect(afterUser!.last_activity_at).toBe(initialTimestamp);
        });
    });

    describe('unauthenticated requests', () => {
        it('should NOT update anything when auth fails (401)', async () => {
            const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();
            app.use('*', requireAuth);
            app.use('*', trackActivity);
            app.get('/protected', (c) => c.json({ secret: true }));

            const request = new Request('http://localhost/protected', {
                headers: { Authorization: `Bearer ${generateToken()}` }, // Invalid token
            });
            const response = await app.fetch(request, env);

            expect(response.status).toBe(401);
            // No user to update, so nothing happens
        });
    });
});
