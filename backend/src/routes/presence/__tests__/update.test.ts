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

// Mock the Discord API calls
vi.mock('../../../services/presence', async (importOriginal) => {
    const original = await importOriginal<typeof import('../../../services/presence')>();
    return {
        ...original,
        updateHeadlessSession: vi.fn().mockResolvedValue({
            activities: [],
            token: 'mock-session-token',
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
});
