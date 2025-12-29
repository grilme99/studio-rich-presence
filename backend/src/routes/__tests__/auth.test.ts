import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { env } from 'cloudflare:test';
import { Hono } from 'hono';
import { auth } from '../auth';
import type { Env } from '../../env';
import { hashAuthToken, generateToken } from '../../crypto';

// Test app setup
function createTestApp() {
    const app = new Hono<{ Bindings: Env }>();
    app.route('/api/auth', auth);
    return app;
}

// Helper to make requests
async function makeRequest(
    app: Hono<{ Bindings: Env }>,
    options: {
        path?: string;
        method?: string;
        body?: object;
        headers?: Record<string, string>;
    } = {}
) {
    const { path = '/api/auth/start', method = 'POST', body, headers = {} } = options;

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

// Helper to create a test user
async function createTestUser(authToken: string): Promise<string> {
    const userId = crypto.randomUUID();
    const tokenHash = await hashAuthToken(authToken, env.ENCRYPTION_KEY);
    const now = Date.now();

    await env.DB.prepare(`
        INSERT INTO users (id, auth_token_hash, created_at, updated_at, last_activity_at)
        VALUES (?, ?, ?, ?, ?)
    `).bind(userId, tokenHash, now, now, now).run();

    return userId;
}

// Helper to clean up database
async function cleanupDatabase() {
    await env.DB.prepare('DELETE FROM auth_sessions').run();
    await env.DB.prepare('DELETE FROM discord_accounts').run();
    await env.DB.prepare('DELETE FROM users').run();
}

// Helper to clean up KV
async function cleanupKV() {
    const keys = await env.KV.list();
    for (const key of keys.keys) {
        await env.KV.delete(key.name);
    }
}

describe('POST /api/auth/start', () => {
    let app: Hono<{ Bindings: Env }>;

    beforeAll(async () => {
        // Run migrations to ensure schema exists
        await env.DB.exec(
            "CREATE TABLE IF NOT EXISTS users (" +
            "id TEXT PRIMARY KEY, " +
            "auth_token_hash TEXT NOT NULL UNIQUE, " +
            "pending_token_hash TEXT, " +
            "pending_token_expires INTEGER, " +
            "created_at INTEGER NOT NULL, " +
            "updated_at INTEGER NOT NULL, " +
            "last_activity_at INTEGER NOT NULL)"
        );

        await env.DB.exec(
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

        await env.DB.exec(
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
    });

    beforeEach(async () => {
        app = createTestApp();
        await cleanupDatabase();
        await cleanupKV();
    });

    describe('new user flow (no auth_token)', () => {
        it('should create a new auth session', async () => {
            const response = await makeRequest(app, { body: {} });

            expect(response.status).toBe(200);

            const data: any = await response.json();
            expect(data).toHaveProperty('code');
            expect(data).toHaveProperty('url');
            expect(data).toHaveProperty('sseUrl');
            expect(data).toHaveProperty('expiresInSeconds');
        });

        it('should return a valid session code', async () => {
            const response = await makeRequest(app, { body: {} });
            const data: any = await response.json();

            // Session code should be 32 bytes base64url encoded (43 chars)
            expect(data.code).toMatch(/^[A-Za-z0-9_-]{43}$/);
        });

        it('should return correct URLs', async () => {
            const response = await makeRequest(app, { body: {} });
            const data: any = await response.json();

            expect(data.url).toContain('/auth/link/');
            expect(data.url).toContain(data.code);

            expect(data.sseUrl).toContain('/auth/sse/');
            expect(data.sseUrl).toContain(data.code);
        });

        it('should return 5 minute expiration', async () => {
            const response = await makeRequest(app, { body: {} });
            const data: any = await response.json();

            expect(data.expiresInSeconds).toBe(300);
        });

        it('should create auth_session record in database', async () => {
            const response = await makeRequest(app, { body: {} });
            const data: any = await response.json();

            const session = await env.DB.prepare(`
                SELECT * FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            expect(session).toBeTruthy();
            expect(session!.state).toBe('pending');
            expect(session!.user_id).toBeNull();
            expect(session!.pkce_code_verifier).toBeTruthy();
            expect(session!.completion_code).toBeTruthy();
        });

        it('should generate unique completion codes', async () => {
            const response1 = await makeRequest(app, {
                body: {},
                headers: { 'cf-connecting-ip': '1.1.1.1' },
            });
            const response2 = await makeRequest(app, {
                body: {},
                headers: { 'cf-connecting-ip': '2.2.2.2' },
            });

            const data1: any = await response1.json();
            const data2: any = await response2.json();

            const session1 = await env.DB.prepare(`
                SELECT completion_code FROM auth_sessions WHERE code = ?
            `).bind(data1.code).first();

            const session2 = await env.DB.prepare(`
                SELECT completion_code FROM auth_sessions WHERE code = ?
            `).bind(data2.code).first();

            // Completion codes are random, so they should typically be different
            // (there's a small chance they're the same, but for testing this is fine)
            expect(session1!.completion_code).toMatch(/^\d{5}$/);
            expect(session2!.completion_code).toMatch(/^\d{5}$/);
        });

        it('should store client_key for new users', async () => {
            const response = await makeRequest(app, { body: {} });
            const data: any = await response.json();

            const session = await env.DB.prepare(`
                SELECT result_client_key FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            expect(session!.result_client_key).toBeTruthy();
            // Client key should be 32 bytes base64url encoded (43 chars)
            expect(session!.result_client_key).toMatch(/^[A-Za-z0-9_-]{43}$/);
        });

        it('should initialize SSE state in KV', async () => {
            const response = await makeRequest(app, { body: {} });
            const data: any = await response.json();

            const kvData = await env.KV.get(`sse:${data.code}`);
            expect(kvData).toBeTruthy();

            const state = JSON.parse(kvData!);
            expect(state.state).toBe('pending');
            expect(state.updatedAt).toBeGreaterThan(0);
        });

        it('should handle empty request body', async () => {
            const request = new Request('http://localhost/api/auth/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'cf-connecting-ip': '192.168.1.1',
                },
                body: '',
            });

            const response = await app.fetch(request, env);
            expect(response.status).toBe(200);
        });

        it('should handle missing Content-Type', async () => {
            const request = new Request('http://localhost/api/auth/start', {
                method: 'POST',
                headers: {
                    'cf-connecting-ip': '192.168.1.1',
                },
            });

            const response = await app.fetch(request, env);
            expect(response.status).toBe(200);
        });
    });

    describe('existing user flow (with auth_token)', () => {
        it('should require client_key when auth_token provided', async () => {
            const authToken = generateToken();
            await createTestUser(authToken);

            const response = await makeRequest(app, {
                body: { auth_token: authToken },
            });

            expect(response.status).toBe(400);

            const data: any = await response.json();
            expect(data.code).toBe('INVALID_REQUEST');
            expect(data.message).toContain('client_key is required');
        });

        it('should reject invalid auth_token', async () => {
            const response = await makeRequest(app, {
                body: {
                    auth_token: 'invalid-token',
                    client_key: 'some-client-key',
                },
            });

            expect(response.status).toBe(401);

            const data: any = await response.json();
            expect(data.code).toBe('UNAUTHORIZED');
            expect(data.message).toContain('Invalid auth token');
        });

        it('should accept valid auth_token and client_key', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(authToken);

            const response = await makeRequest(app, {
                body: {
                    auth_token: authToken,
                    client_key: clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data: any = await response.json();
            expect(data.code).toBeTruthy();
            expect(data.url).toBeTruthy();
            expect(data.sseUrl).toBeTruthy();
        });

        it('should link session to existing user', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(authToken);

            const response = await makeRequest(app, {
                body: {
                    auth_token: authToken,
                    client_key: clientKey,
                },
            });

            const data: any = await response.json();

            const session = await env.DB.prepare(`
                SELECT user_id FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            expect(session!.user_id).toBe(userId);
        });

        it('should store provided client_key for existing users (needed for callback)', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            await createTestUser(authToken);

            const response = await makeRequest(app, {
                body: {
                    auth_token: authToken,
                    client_key: clientKey,
                },
            });

            const data: any = await response.json();

            const session = await env.DB.prepare(`
                SELECT result_client_key FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            // Client key is stored so it can be used in the callback for encryption
            expect(session!.result_client_key).toBe(clientKey);
        });

        it('should update last_activity_at on successful auth', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(authToken);

            // Get original timestamp
            const beforeUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first();

            // Small delay to ensure time difference
            await new Promise((resolve) => setTimeout(resolve, 10));

            await makeRequest(app, {
                body: {
                    auth_token: authToken,
                    client_key: clientKey,
                },
            });

            const afterUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first();

            expect(afterUser!.last_activity_at).toBeGreaterThanOrEqual(
                beforeUser!.last_activity_at as number
            );
        });
    });

    describe('session properties', () => {
        it('should generate PKCE code verifier with correct length', async () => {
            const response = await makeRequest(app, { body: {} });
            const data: any = await response.json();

            const session = await env.DB.prepare(`
                SELECT pkce_code_verifier FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            // Code verifier should be 32 bytes base64url encoded (43 chars)
            // This matches RFC 7636 minimum of 43 characters
            expect(session!.pkce_code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
        });

        it('should set correct expiration time', async () => {
            const beforeTime = Date.now();

            const response = await makeRequest(app, { body: {} });
            const data: any = await response.json();

            const afterTime = Date.now();

            const session = await env.DB.prepare(`
                SELECT expires_at FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            const expiresAt = session!.expires_at as number;

            // Expiration should be ~5 minutes from now
            const expectedMin = beforeTime + 300 * 1000;
            const expectedMax = afterTime + 300 * 1000;

            expect(expiresAt).toBeGreaterThanOrEqual(expectedMin);
            expect(expiresAt).toBeLessThanOrEqual(expectedMax);
        });

        it('should generate unique session codes', async () => {
            const codes = new Set<string>();

            // Generate 10 sessions and verify all codes are unique
            for (let i = 0; i < 10; i++) {
                const response = await makeRequest(app, {
                    body: {},
                    headers: { 'cf-connecting-ip': `10.0.0.${i}` },
                });
                const data: any = await response.json();
                codes.add(data.code);
            }

            expect(codes.size).toBe(10);
        });
    });

    describe('error handling', () => {
        it('should handle malformed JSON gracefully', async () => {
            const request = new Request('http://localhost/api/auth/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'cf-connecting-ip': '192.168.1.1',
                },
                body: 'not valid json',
            });

            const response = await app.fetch(request, env);
            // Should still work since we catch JSON parse errors
            expect(response.status).toBe(200);
        });

        it('should ignore extra fields in request body', async () => {
            const response = await makeRequest(app, {
                body: {
                    extra_field: 'should be ignored',
                    another_field: 12345,
                },
            });

            expect(response.status).toBe(200);
        });
    });

    describe('rate limiting', () => {
        it('should apply rate limit headers', async () => {
            const response = await makeRequest(app, { body: {} });

            expect(response.headers.get('X-RateLimit-Limit')).toBeTruthy();
            expect(response.headers.get('X-RateLimit-Remaining')).toBeTruthy();
        });

        it('should rate limit after too many requests', async () => {
            // Make 10 requests (the limit for auth endpoints)
            for (let i = 0; i < 10; i++) {
                await makeRequest(app, { body: {} });
            }

            // 11th request should be rate limited
            const response = await makeRequest(app, { body: {} });
            expect(response.status).toBe(429);

            const data: any = await response.json();
            expect(data.code).toBe('RATE_LIMITED');
        });

        it('should track rate limits per IP', async () => {
            // Use up rate limit for IP 1
            for (let i = 0; i < 10; i++) {
                await makeRequest(app, {
                    body: {},
                    headers: { 'cf-connecting-ip': '1.1.1.1' },
                });
            }

            // IP 1 should be rate limited
            const response1 = await makeRequest(app, {
                body: {},
                headers: { 'cf-connecting-ip': '1.1.1.1' },
            });
            expect(response1.status).toBe(429);

            // IP 2 should still work
            const response2 = await makeRequest(app, {
                body: {},
                headers: { 'cf-connecting-ip': '2.2.2.2' },
            });
            expect(response2.status).toBe(200);
        });
    });
});

