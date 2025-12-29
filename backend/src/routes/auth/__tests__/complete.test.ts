/**
 * Tests for POST /api/auth/complete endpoint.
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
    createTestSession,
    cleanupDatabase,
    cleanupKV,
    setupDatabase,
} from './testUtils';

describe('POST /api/auth/complete', () => {
    let app: Hono<{ Bindings: Env }>;

    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        app = createTestApp();
        await cleanupDatabase(env.DB);
        await cleanupKV(env.KV);
    });

    describe('validation', () => {
        it('should require session code', async () => {
            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { completionCode: '12345' },
            });

            expect(response.status).toBe(400);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_REQUEST');
            expect(data.message).toContain('code');
        });

        it('should require completion code', async () => {
            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code: 'some-session-code' },
            });

            expect(response.status).toBe(400);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_REQUEST');
            expect((data.message as string).toLowerCase()).toContain('completion');
        });

        it('should return error for non-existent session', async () => {
            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: {
                    code: 'non-existent-code',
                    completionCode: '12345',
                },
            });

            expect(response.status).toBe(400);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_REQUEST');
        });

        it('should return error for expired session', async () => {
            const code = 'expired-session';
            await createTestSession(env.DB, {
                code,
                state: 'completed',
                expiresAt: Date.now() - 1000,
            });

            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });

            expect(response.status).toBe(400);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('SESSION_EXPIRED');
        });

        it('should return error for invalid completion code', async () => {
            const code = 'valid-session';
            await createTestSession(env.DB, {
                code,
                state: 'completed',
                completionCode: '12345',
            });

            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '99999' },  // Wrong code
            });

            expect(response.status).toBe(400);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_COMPLETION_CODE');
        });

        it('should return error for pending session', async () => {
            const code = 'pending-session';
            await createTestSession(env.DB, {
                code,
                state: 'pending',
                completionCode: '12345',
            });

            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });

            expect(response.status).toBe(400);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_REQUEST');
            expect(data.message).toContain('not yet completed');
        });

        it('should return error for started session', async () => {
            const code = 'started-session';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                completionCode: '12345',
            });

            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });

            expect(response.status).toBe(400);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_REQUEST');
            expect(data.message).toContain('in progress');
        });

        it('should return error for failed session', async () => {
            const code = 'failed-session';
            const errorMsg = 'User denied authorization';
            await createTestSession(env.DB, {
                code,
                state: 'failed',
                completionCode: '12345',
                errorMessage: errorMsg,
            });

            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });

            expect(response.status).toBe(400);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_REQUEST');
            expect(data.message).toContain(errorMsg);
        });
    });

    describe('successful completion', () => {
        it('should return auth_token and client_key for new users', async () => {
            const code = 'new-user-session';
            const authToken = generateToken();
            const clientKey = generateToken();

            await createTestSession(env.DB, {
                code,
                state: 'completed',
                completionCode: '12345',
                resultToken: authToken,
                resultClientKey: clientKey,
            });

            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });

            expect(response.status).toBe(200);
            const data = await response.json() as Record<string, unknown>;
            expect(data.authToken).toBe(authToken);
            expect(data.clientKey).toBe(clientKey);
        });

        it('should return empty object for existing users', async () => {
            const code = 'existing-user-session';
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            await createTestSession(env.DB, {
                code,
                state: 'completed',
                userId,
                completionCode: '12345',
                resultToken: null,  // No new token for existing users
                resultClientKey: generateToken(),  // Stored but not returned
            });

            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });

            expect(response.status).toBe(200);
            const data = await response.json() as Record<string, unknown>;
            // Should have empty optional fields
            expect(data.authToken).toBeUndefined();
            expect(data.clientKey).toBeUndefined();
        });

        it('should allow multiple completions of same session (idempotent)', async () => {
            const code = 'idempotent-session';
            const authToken = generateToken();
            const clientKey = generateToken();

            await createTestSession(env.DB, {
                code,
                state: 'completed',
                completionCode: '12345',
                resultToken: authToken,
                resultClientKey: clientKey,
            });

            // First completion
            const response1 = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });
            expect(response1.status).toBe(200);

            const data1 = await response1.json() as Record<string, unknown>;
            expect(data1.authToken).toBe(authToken);
            expect(data1.clientKey).toBe(clientKey);

            // Completing again should fail
            const response2 = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });
            expect(response2.status).toBe(400);

            const data2 = await response2.json() as Record<string, unknown>;
            expect(data2.code).toBe('INVALID_REQUEST');
            expect(data2.message).toContain('expired session');
        });
    });

    describe('constant-time comparison', () => {
        it('should reject wrong completion code regardless of length', async () => {
            const code = 'timing-safe-session';
            await createTestSession(env.DB, {
                code,
                state: 'completed',
                completionCode: '12345',
            });

            // Test various wrong codes
            const wrongCodes = ['1', '12', '123', '1234', '12346', '123456', '00000', 'abcde'];

            for (const wrongCode of wrongCodes) {
                const response = await makeRequest(app, '/api/auth/complete', env, {
                    method: 'POST',
                    body: { code, completionCode: wrongCode },
                });

                expect(response.status).toBe(400);
                const data = await response.json() as Record<string, unknown>;
                expect(data.code).toBe('INVALID_COMPLETION_CODE');
            }
        });
    });

    describe('rate limiting', () => {
        it('should apply rate limits', async () => {
            const code = 'rate-limit-session';
            await createTestSession(env.DB, {
                code,
                state: 'completed',
                completionCode: '12345',
            });

            // Make 10 requests (the limit for auth endpoints)
            for (let i = 0; i < 10; i++) {
                await makeRequest(app, '/api/auth/complete', env, {
                    method: 'POST',
                    body: { code, completionCode: '12345' },
                });
            }

            // 11th request should be rate limited
            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });

            expect(response.status).toBe(429);
            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('RATE_LIMITED');
        });
    });

    describe('JSON field names', () => {
        it('should accept snake_case field names in request', async () => {
            const code = 'snake-case-session';
            const authToken = generateToken();
            const clientKey = generateToken();

            await createTestSession(env.DB, {
                code,
                state: 'completed',
                completionCode: '12345',
                resultToken: authToken,
                resultClientKey: clientKey,
            });

            // Request uses snake_case (completion_code)
            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completion_code: '12345' },
            });

            expect(response.status).toBe(200);
        });

        it('should accept camelCase field names in request', async () => {
            const code = 'camel-case-session';
            const authToken = generateToken();
            const clientKey = generateToken();

            await createTestSession(env.DB, {
                code,
                state: 'completed',
                completionCode: '12345',
                resultToken: authToken,
                resultClientKey: clientKey,
            });

            // Request uses camelCase (completionCode)
            const response = await makeRequest(app, '/api/auth/complete', env, {
                method: 'POST',
                body: { code, completionCode: '12345' },
            });

            expect(response.status).toBe(200);
        });
    });
});

