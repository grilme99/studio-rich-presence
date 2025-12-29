/**
 * Tests for GET /accounts endpoint.
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

// Mock Discord API
vi.mock('../../../services/discord', async (importOriginal) => {
    const original = await importOriginal<typeof import('../../../services/discord')>();
    return {
        ...original,
        fetchDiscordUser: vi.fn().mockResolvedValue({
            id: '123456789',
            username: 'testuser',
            discriminator: '0',
            avatar: 'abc123',
            global_name: 'Test User',
        }),
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
import { fetchDiscordUser } from '../../../services/discord';

describe('GET /accounts', () => {
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

    // Note: Don't use vi.restoreAllMocks() as it undoes module mocks

    describe('authentication', () => {
        it('should require Authorization header', async () => {
            const response = await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
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

            const response = await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
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
            const response = await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
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

    describe('listing accounts', () => {
        it('should return empty list when no accounts linked', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as { accounts?: unknown[] };
            // Protobuf omits empty arrays
            expect(data.accounts ?? []).toEqual([]);
        });

        it('should return linked accounts with Discord user info', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            const accountId = await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as { accounts: Array<Record<string, unknown>> };
            expect(data.accounts).toHaveLength(1);
            expect(data.accounts[0]?.id).toBe(accountId);
            expect(data.accounts[0]?.username).toBe('testuser');
            expect(data.accounts[0]?.displayName).toBe('Test User');
            expect(data.accounts[0]?.avatarUrl).toContain('cdn.discordapp.com');
            expect(data.accounts[0]?.linkedAt).toBeDefined();
        });

        it('should return multiple linked accounts', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            const response = await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as { accounts: Array<Record<string, unknown>> };
            expect(data.accounts).toHaveLength(2);
        });

        it('should fetch Discord user info using access token', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(fetchDiscordUser).toHaveBeenCalledTimes(1);
            expect(fetchDiscordUser).toHaveBeenCalledWith(expect.any(String));
        });
    });

    describe('error handling', () => {
        it('should return "Unknown" username when Discord API fails', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Mock Discord API failure
            vi.mocked(fetchDiscordUser).mockRejectedValueOnce(new Error('Discord API error'));

            const response = await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as { accounts: Array<Record<string, unknown>> };
            expect(data.accounts).toHaveLength(1);
            expect(data.accounts[0]?.username).toBe('Unknown');
        });
    });

    describe('avatar URL generation', () => {
        it('should return null avatar when user has no custom avatar', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            await createTestDiscordAccount(env.DB, userId, clientKey, env.ENCRYPTION_KEY);

            // Mock user with no avatar
            vi.mocked(fetchDiscordUser).mockResolvedValueOnce({
                id: '123456789',
                username: 'testuser',
                discriminator: '0',
                avatar: null,
                global_name: null,
            });

            const response = await makeRequest(app, '/accounts/list', env, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    'X-Client-Key': clientKey,
                },
            });

            expect(response.status).toBe(200);

            const data = await response.json() as { accounts: Array<Record<string, unknown>> };
            expect(data.accounts[0]?.avatarUrl).toBeUndefined();
            expect(data.accounts[0]?.displayName).toBeUndefined();
        });
    });
});

