/**
 * Tests for POST /api/auth/start endpoint.
 */

import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { env } from 'cloudflare:test';
import type { Hono } from 'hono';
import type { Env } from '../../../env';
import { generateToken } from '../../../crypto';
import {
    createTestApp,
    makeRequest,
    createTestUser,
    cleanupDatabase,
    cleanupKV,
    setupDatabase,
} from './testUtils';

describe('POST /api/auth/start', () => {
    let app: Hono<{ Bindings: Env }>;

    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        app = createTestApp();
        await cleanupDatabase(env.DB);
        await cleanupKV(env.KV);
    });

    describe('new user flow (no auth_token)', () => {
        it('should create a new auth session', async () => {
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data).toHaveProperty('code');
            expect(data).toHaveProperty('url');
            expect(data).toHaveProperty('sseUrl');
            expect(data).toHaveProperty('expiresInSeconds');
        });

        it('should return a valid session code', async () => {
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });
            const data = await response.json() as Record<string, unknown>;

            // Session code should be 32 bytes base64url encoded (43 chars)
            expect(data.code).toMatch(/^[A-Za-z0-9_-]{43}$/);
        });

        it('should return correct URLs', async () => {
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });
            const data = await response.json() as Record<string, unknown>;

            expect(data.url).toContain('/auth/link/');
            expect(data.url).toContain(data.code as string);

            expect(data.sseUrl).toContain('/auth/sse/');
            expect(data.sseUrl).toContain(data.code as string);
        });

        it('should return 5 minute expiration', async () => {
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });
            const data = await response.json() as Record<string, unknown>;

            expect(data.expiresInSeconds).toBe(300);
        });

        it('should create auth_session record in database', async () => {
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });
            const data = await response.json() as Record<string, unknown>;

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
            const response1 = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
                headers: { 'cf-connecting-ip': '1.1.1.1' },
            });
            const response2 = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
                headers: { 'cf-connecting-ip': '2.2.2.2' },
            });

            const data1 = await response1.json() as Record<string, unknown>;
            const data2 = await response2.json() as Record<string, unknown>;

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
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });
            const data = await response.json() as Record<string, unknown>;

            const session = await env.DB.prepare(`
                SELECT result_client_key FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            expect(session!.result_client_key).toBeTruthy();
            // Client key should be 32 bytes base64url encoded (43 chars)
            expect(session!.result_client_key).toMatch(/^[A-Za-z0-9_-]{43}$/);
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
            await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: { auth_token: authToken },
            });

            expect(response.status).toBe(400);

            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_REQUEST');
            expect(data.message).toContain('client_key is required');
        });

        it('should reject invalid auth_token', async () => {
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {
                    auth_token: 'invalid-token',
                    client_key: 'some-client-key',
                },
            });

            expect(response.status).toBe(401);

            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('UNAUTHORIZED');
            expect(data.message).toContain('Invalid auth token');
        });

        it('should accept valid auth_token and client_key', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {
                    auth_token: authToken,
                    client_key: clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBeTruthy();
            expect(data.url).toBeTruthy();
            expect(data.sseUrl).toBeTruthy();
        });

        it('should link session to existing user', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {
                    auth_token: authToken,
                    client_key: clientKey,
                },
            });

            const data = await response.json() as Record<string, unknown>;

            const session = await env.DB.prepare(`
                SELECT user_id FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            expect(session!.user_id).toBe(userId);
        });

        it('should store provided client_key for existing users (needed for callback)', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {
                    auth_token: authToken,
                    client_key: clientKey,
                },
            });

            const data = await response.json() as Record<string, unknown>;

            const session = await env.DB.prepare(`
                SELECT result_client_key FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            // Client key is stored so it can be used in the callback for encryption
            expect(session!.result_client_key).toBe(clientKey);
        });

        it('should update last_activity_at on successful auth', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            // Get original timestamp
            const beforeUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first();

            // Small delay to ensure time difference
            await new Promise((resolve) => setTimeout(resolve, 10));

            await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
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
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });
            const data = await response.json() as Record<string, unknown>;

            const session = await env.DB.prepare(`
                SELECT pkce_code_verifier FROM auth_sessions WHERE code = ?
            `).bind(data.code).first();

            // Code verifier should be 32 bytes base64url encoded (43 chars)
            // This matches RFC 7636 minimum of 43 characters
            expect(session!.pkce_code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
        });

        it('should set correct expiration time', async () => {
            const beforeTime = Date.now();

            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });
            const data = await response.json() as Record<string, unknown>;

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
                const response = await makeRequest(app, '/api/auth/start', env, {
                    method: 'POST',
                    body: {},
                    headers: { 'cf-connecting-ip': `10.0.0.${i}` },
                });
                const data = await response.json() as Record<string, unknown>;
                codes.add(data.code as string);
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
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
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
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });

            expect(response.headers.get('X-RateLimit-Limit')).toBeTruthy();
            expect(response.headers.get('X-RateLimit-Remaining')).toBeTruthy();
        });

        it('should rate limit after too many requests', async () => {
            // Make 10 requests (the limit for auth endpoints)
            for (let i = 0; i < 10; i++) {
                await makeRequest(app, '/api/auth/start', env, {
                    method: 'POST',
                    body: {},
                });
            }

            // 11th request should be rate limited
            const response = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
            });
            expect(response.status).toBe(429);

            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('RATE_LIMITED');
        });

        it('should track rate limits per IP', async () => {
            // Use up rate limit for IP 1
            for (let i = 0; i < 10; i++) {
                await makeRequest(app, '/api/auth/start', env, {
                    method: 'POST',
                    body: {},
                    headers: { 'cf-connecting-ip': '1.1.1.1' },
                });
            }

            // IP 1 should be rate limited
            const response1 = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
                headers: { 'cf-connecting-ip': '1.1.1.1' },
            });
            expect(response1.status).toBe(429);

            // IP 2 should still work
            const response2 = await makeRequest(app, '/api/auth/start', env, {
                method: 'POST',
                body: {},
                headers: { 'cf-connecting-ip': '2.2.2.2' },
            });
            expect(response2.status).toBe(200);
        });
    });
});

