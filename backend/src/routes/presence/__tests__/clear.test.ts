/**
 * Tests for POST /presence/clear endpoint.
 */

import { describe, it, expect, beforeEach, beforeAll, vi, afterEach } from 'vitest';
import { env } from 'cloudflare:test';
import type { Hono } from 'hono';
import type { Env } from '../../../env';
import { generateToken } from '../../../crypto';
import {
    createTestApp,
    makeRequest,
    createTestUser,
    createTestDiscordAccount,
    cleanupDatabase,
    cleanupKV,
    setupDatabase,
} from './testUtils';

// Mock the Discord API calls
vi.mock('../../../services/presence', async (importOriginal) => {
    const original = await importOriginal<typeof import('../../../services/presence')>();
    return {
        ...original,
        deleteHeadlessSession: vi.fn().mockResolvedValue(undefined),
    };
});

vi.mock('../../../services/discord', async (importOriginal) => {
    const original = await importOriginal<typeof import('../../../services/discord')>();
    return {
        ...original,
        refreshDiscordTokens: vi.fn().mockResolvedValue({
            access_token: 'new-access-token',
            refresh_token: 'new-refresh-token',
            token_type: 'Bearer',
            expires_in: 604800,
            scope: 'identify activities.write',
        }),
    };
});

// Import after mock setup
import { deleteHeadlessSession } from '../../../services/presence';

describe('POST /api/presence/clear', () => {
    let app: Hono<{ Bindings: Env }>;

    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        app = createTestApp();
        await cleanupDatabase(env.DB);
        await cleanupKV(env.KV);
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('authentication', () => {
        it('should require Authorization header', async () => {
            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'X-Client-Key': 'test-client-key',
                },
            });

            expect(response.status).toBe(401);

            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('UNAUTHORIZED');
        });

        it('should require X-Client-Key header', async () => {
            const authToken = generateToken();
            await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                },
            });

            expect(response.status).toBe(400);

            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('INVALID_REQUEST');
            expect(data.message).toContain('X-Client-Key');
        });

        it('should reject invalid auth token', async () => {
            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer invalid-token',
                    'X-Client-Key': 'test-client-key',
                },
            });

            expect(response.status).toBe(401);

            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('UNAUTHORIZED');
        });
    });

    describe('clearing presence', () => {
        it('should return cleared_accounts count when session exists', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            const accountId = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Pre-populate KV with a cached session token
            await env.KV.put(`presence-session:${accountId}`, 'existing-session-token', { expirationTtl: 1140 });

            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data.clearedAccounts).toBe(1);
            expect(data.failedAccounts ?? 0).toBe(0);

            // Verify deleteHeadlessSession was called
            expect(deleteHeadlessSession).toHaveBeenCalledWith(
                expect.any(String),
                'existing-session-token'
            );
        });

        it('should succeed when no session exists (nothing to clear)', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // No cached session token

            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data.clearedAccounts).toBe(1);
            expect(data.failedAccounts ?? 0).toBe(0);

            // Verify deleteHeadlessSession was NOT called (no session to delete)
            expect(deleteHeadlessSession).not.toHaveBeenCalled();
        });

        it('should handle multiple accounts', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            // Create multiple Discord accounts
            const accountId1 = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);
            const accountId2 = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Only one has an active session
            await env.KV.put(`presence-session:${accountId1}`, 'session-token-1', { expirationTtl: 1140 });

            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data.clearedAccounts).toBe(2);

            // Only one deleteHeadlessSession call (for the account with a session)
            expect(deleteHeadlessSession).toHaveBeenCalledTimes(1);
        });

        it('should handle user with no linked accounts', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data.clearedAccounts ?? 0).toBe(0);
            expect(data.failedAccounts ?? 0).toBe(0);
        });

        it('should delete cached session token from KV', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            const accountId = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Pre-populate KV
            await env.KV.put(`presence-session:${accountId}`, 'existing-session-token', { expirationTtl: 1140 });

            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            // Verify token was deleted from KV
            const cachedToken = await env.KV.get(`presence-session:${accountId}`);
            expect(cachedToken).toBeNull();
        });
    });

    describe('error handling', () => {
        it('should report failed accounts when Discord API fails', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            const accountId = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Pre-populate KV with a cached session token
            await env.KV.put(`presence-session:${accountId}`, 'existing-session-token', { expirationTtl: 1140 });

            // Mock Discord API to fail
            vi.mocked(deleteHeadlessSession).mockRejectedValueOnce(new Error('Discord API error'));

            const response = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data.clearedAccounts ?? 0).toBe(0);
            expect(data.failedAccounts).toBe(1);

            // Should still delete cached token even on failure
            const cachedToken = await env.KV.get(`presence-session:${accountId}`);
            expect(cachedToken).toBeNull();
        });
    });

    describe('rate limiting', () => {
        it('should rate limit clear requests', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // First request should succeed
            const response1 = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });
            expect(response1.status).toBe(200);

            // Second immediate request should be rate limited
            const response2 = await makeRequest(app, '/api/presence/clear', env, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });
            expect(response2.status).toBe(429);

            const data = await response2.json() as Record<string, unknown>;
            expect(data.code).toBe('RATE_LIMITED');
        });
    });
});

