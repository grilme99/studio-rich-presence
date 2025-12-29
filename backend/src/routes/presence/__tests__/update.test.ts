/**
 * Tests for POST /presence/update endpoint.
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

// Track mock call count outside the mock factory
let mockCallCount = 0;

// Mock the Discord API calls - only mock the network call, not KV caching functions
vi.mock('../../../services/presence', async (importOriginal) => {
    const original = await importOriginal<typeof import('../../../services/presence')>();
    return {
        ...original,
        updateHeadlessSession: vi.fn((_accessToken: string, _activity: unknown, sessionToken?: string) => {
            mockCallCount++;
            return Promise.resolve({
                activities: [],
                // Return a new token if no session token was provided, otherwise return same token
                token: sessionToken ?? `mock-session-token-${mockCallCount}`,
            });
        }),
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
import { updateHeadlessSession } from '../../../services/presence';

describe('POST /api/presence/update', () => {
    let app: Hono<{ Bindings: Env }>;

    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        app = createTestApp();
        await cleanupDatabase(env.DB);
        await cleanupKV(env.KV);
        vi.clearAllMocks();
        mockCallCount = 0;
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    describe('authentication', () => {
        it('should require Authorization header', async () => {
            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {},
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

            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {},
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
            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {},
                headers: {
                    'Authorization': 'Bearer invalid-token',
                    'X-Client-Key': 'test-client-key',
                },
            });

            expect(response.status).toBe(401);

            const data = await response.json() as Record<string, unknown>;
            expect(data.code).toBe('UNAUTHORIZED');
        });

        it('should accept valid credentials', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {
                    presence: {
                        details: 'Editing MyGame',
                        state: 'Workspace: 1,234 parts',
                    },
                },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);
        });
    });

    describe('presence update', () => {
        it('should return updated_accounts count', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {
                    presence: {
                        details: 'Editing MyGame',
                    },
                },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data.updatedAccounts).toBe(1);
            // Protobuf omits zero values, so failedAccounts may be undefined or 0
            expect(data.failedAccounts ?? 0).toBe(0);
        });

        it('should handle multiple accounts', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            // Create multiple Discord accounts
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {
                    presence: {},
                },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            expect(data.updatedAccounts).toBe(2);
        });

        it('should handle user with no linked accounts', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {
                    presence: {},
                },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as Record<string, unknown>;
            // Protobuf omits zero values, so both may be undefined or 0
            expect(data.updatedAccounts ?? 0).toBe(0);
            expect(data.failedAccounts ?? 0).toBe(0);
        });

        it('should update last_activity_at', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const beforeUser = await env.DB.prepare(`
                SELECT last_activity_at FROM users WHERE id = ?
            `).bind(userId).first();

            // Small delay
            await new Promise((resolve) => setTimeout(resolve, 10));

            await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {
                    presence: {},
                },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
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

    describe('presence data', () => {
        it('should accept presence with all fields', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {
                    presence: {
                        details: 'Editing MyGame',
                        state: 'Workspace: 1,234 parts',
                        timestamps: {
                            start_unix: Math.floor(Date.now() / 1000),
                        },
                        assets: {
                            large_image: 'roblox_studio',
                            large_text: 'Roblox Studio',
                            small_image: 'roblox_logo',
                            small_text: 'Roblox',
                        },
                    },
                },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);
        });

        it('should accept empty presence', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {
                    presence: {},
                },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);
        });

        it('should accept request without presence field', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: {},
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);
        });
    });

    describe('rate limiting', () => {
        it('should rate limit presence updates', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // First request should succeed
            const response1 = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: { presence: {} },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });
            expect(response1.status).toBe(200);

            // Second immediate request should be rate limited
            const response2 = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: { presence: {} },
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

    describe('session token caching', () => {
        it('should cache session token in KV after successful update', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            const accountId = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Make request
            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: { presence: { details: 'Test' } },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            // Verify token is cached in KV
            const cachedToken = await env.KV.get(`presence-session:${accountId}`);
            expect(cachedToken).toBe('mock-session-token-1');
        });

        it('should reuse cached session token on subsequent requests', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            const accountId = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Pre-populate KV with a cached token
            await env.KV.put(`presence-session:${accountId}`, 'existing-cached-token', { expirationTtl: 1140 });

            // Make request
            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: { presence: { details: 'Test' } },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            // Verify updateHeadlessSession was called with the cached token
            expect(updateHeadlessSession).toHaveBeenCalledWith(
                expect.any(String), // access token
                expect.any(Object), // activity
                'existing-cached-token' // cached session token
            );
        });

        it('should create new session when no cached token exists', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Make request (no cached token)
            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: { presence: { details: 'Test' } },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            // Verify updateHeadlessSession was called without a session token
            expect(updateHeadlessSession).toHaveBeenCalledWith(
                expect.any(String), // access token
                expect.any(Object), // activity
                undefined // no cached token
            );
        });

        it('should keep cached token when reusing session', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            const accountId = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Pre-populate with existing token (simulating a prior session)
            await env.KV.put(`presence-session:${accountId}`, 'existing-session-token', { expirationTtl: 1140 });

            // Make request
            const response = await makeRequest(app, '/api/presence/update', env, {
                method: 'POST',
                body: { presence: { details: 'Test' } },
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            // Verify updateHeadlessSession was called with the cached token
            expect(updateHeadlessSession).toHaveBeenCalledWith(
                expect.any(String),
                expect.any(Object),
                'existing-session-token'
            );

            // The cached token should remain (mock returns same token when one is provided)
            const cachedToken = await env.KV.get(`presence-session:${accountId}`);
            expect(cachedToken).toBe('existing-session-token');
        });
    });
});
