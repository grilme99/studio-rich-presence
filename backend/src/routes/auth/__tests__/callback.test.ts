/**
 * Tests for GET /auth/callback endpoint.
 */

import { describe, it, expect, beforeEach, beforeAll, vi, afterEach } from 'vitest';
import { env } from 'cloudflare:test';
import type { Hono } from 'hono';
import type { Env } from '../../../env';
import { generateToken, hashDiscordId } from '../../../crypto';
import {
    createTestApp,
    makeRequest,
    createTestUser,
    createTestSession,
    cleanupDatabase,
    cleanupKV,
    setupDatabase,
} from './testUtils';

// Mock Discord API responses using vi.stubGlobal
function mockDiscordFetch(options: {
    tokenResponse?: {
        access_token: string;
        refresh_token: string;
        expires_in: number;
        token_type: string;
        scope: string;
    } | null;
    tokenError?: { status: number; body: unknown };
    userResponse?: {
        id: string;
        username: string;
        discriminator: string;
        avatar: string | null;
        global_name: string | null;
    } | null;
    userError?: { status: number; body: unknown };
}) {
    const mockFetch = vi.fn(async (url: string | URL) => {
        const urlString = url.toString();

        if (urlString.includes('discord.com/api/oauth2/token')) {
            if (options.tokenError) {
                return new Response(JSON.stringify(options.tokenError.body), {
                    status: options.tokenError.status,
                    headers: { 'Content-Type': 'application/json' },
                });
            }
            if (options.tokenResponse) {
                return new Response(JSON.stringify(options.tokenResponse), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' },
                });
            }
        }

        if (urlString.includes('discord.com/api/users/@me')) {
            if (options.userError) {
                return new Response(JSON.stringify(options.userError.body), {
                    status: options.userError.status,
                    headers: { 'Content-Type': 'application/json' },
                });
            }
            if (options.userResponse) {
                return new Response(JSON.stringify(options.userResponse), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' },
                });
            }
        }

        // For non-Discord URLs, return a basic response (shouldn't happen in tests)
        return new Response(null, { status: 404 });
    });

    vi.stubGlobal('fetch', mockFetch);
    return mockFetch;
}

describe('GET /auth/callback', () => {
    let app: Hono<{ Bindings: Env }>;

    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        app = createTestApp();
        await cleanupDatabase(env.DB);
        await cleanupKV(env.KV);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    describe('error handling', () => {
        it('should handle Discord OAuth error', async () => {
            const response = await makeRequest(
                app,
                '/auth/callback?error=access_denied&error_description=User%20denied%20access',
                env
            );

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('User denied access');
        });

        it('should return 400 for missing code parameter', async () => {
            const response = await makeRequest(
                app,
                '/auth/callback?state=some-state',
                env
            );

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('Missing authorization parameters');
        });

        it('should return 400 for missing state parameter', async () => {
            const response = await makeRequest(
                app,
                '/auth/callback?code=some-code',
                env
            );

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('Missing authorization parameters');
        });

        it('should return 400 for invalid session (not found)', async () => {
            const response = await makeRequest(
                app,
                '/auth/callback?code=discord-code&state=invalid-session',
                env
            );

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('Invalid session');
        });

        it('should return 410 for expired session', async () => {
            const code = 'expired-session';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                expiresAt: Date.now() - 1000,
            });

            const response = await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            expect(response.status).toBe(410);
            const text = await response.text();
            expect(text).toContain('expired');
        });

        it('should return 400 for session in wrong state (pending)', async () => {
            const code = 'pending-session';
            await createTestSession(env.DB, {
                code,
                state: 'pending',
            });

            const response = await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('Invalid session state');
        });

        it('should return 400 for session in wrong state (completed)', async () => {
            const code = 'completed-session';
            await createTestSession(env.DB, {
                code,
                state: 'completed',
            });

            const response = await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('Invalid session state');
        });

        it('should return 502 for Discord token exchange failure', async () => {
            const code = 'valid-session';
            const clientKey = generateToken();
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenError: { status: 400, body: { error: 'invalid_grant' } },
            });

            const response = await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            expect(response.status).toBe(502);
            const text = await response.text();
            expect(text).toContain('Discord API error');
        });

        it('should return 502 for Discord user fetch failure', async () => {
            const code = 'valid-session';
            const clientKey = generateToken();
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userError: { status: 401, body: { message: 'Unauthorized' } },
            });

            const response = await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            expect(response.status).toBe(502);
        });

        it('should update session state to failed on error', async () => {
            const code = 'valid-session';
            const clientKey = generateToken();
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenError: { status: 400, body: { error: 'invalid_grant' } },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            const session = await env.DB.prepare(`
                SELECT state, error_message FROM auth_sessions WHERE code = ?
            `).bind(code).first();

            expect(session!.state).toBe('failed');
            expect(session!.error_message).toContain('Discord API error');
        });
    });

    describe('new user flow', () => {
        it('should create a new user on successful callback', async () => {
            const code = 'new-user-session';
            const clientKey = generateToken();
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: 'abc123',
                    global_name: 'Test User',
                },
            });

            const response = await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            expect(response.status).toBe(200);

            // Check user was created
            const users = await env.DB.prepare('SELECT * FROM users').all();
            expect(users.results.length).toBe(1);
        });

        it('should create a Discord account link', async () => {
            const code = 'new-user-session';
            const clientKey = generateToken();
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: 'abc123',
                    global_name: 'Test User',
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            const accounts = await env.DB.prepare('SELECT * FROM discord_accounts').all();
            expect(accounts.results.length).toBe(1);
            expect(accounts.results[0]!.discord_user_id_hash).toBeTruthy();
            expect(accounts.results[0]!.access_token_enc).toBeTruthy();
            expect(accounts.results[0]!.refresh_token_enc).toBeTruthy();
        });

        it('should update session with result token for new users', async () => {
            const code = 'new-user-session';
            const clientKey = generateToken();
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: 'abc123',
                    global_name: 'Test User',
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            const session = await env.DB.prepare(`
                SELECT state, result_token, result_client_key FROM auth_sessions WHERE code = ?
            `).bind(code).first();

            expect(session!.state).toBe('completed');
            expect(session!.result_token).toBeTruthy();
            expect(session!.result_client_key).toBe(clientKey);
        });

        it('should show success page with completion code', async () => {
            const code = 'new-user-session';
            const clientKey = generateToken();
            const completionCode = '54321';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
                completionCode,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            const response = await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            expect(response.status).toBe(200);
            const text = await response.text();
            expect(text).toContain('Discord Connected');
            expect(text).toContain(completionCode);
        });

        it('should update KV state to completed', async () => {
            const code = 'new-user-session';
            const clientKey = generateToken();
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            const kvData = await env.KV.get(`sse:${code}`);
            expect(kvData).toBeTruthy();
            const state = JSON.parse(kvData!);
            expect(state.state).toBe('completed');
        });
    });

    describe('existing user flow', () => {
        it('should link Discord to existing user', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const code = 'existing-user-session';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                userId,
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            const response = await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            expect(response.status).toBe(200);

            // Check Discord account is linked to existing user
            const account = await env.DB.prepare(`
                SELECT user_id FROM discord_accounts
            `).first();

            expect(account!.user_id).toBe(userId);
        });

        it('should NOT create a new user for existing user flow', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const code = 'existing-user-session';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                userId,
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            const users = await env.DB.prepare('SELECT * FROM users').all();
            expect(users.results.length).toBe(1);  // Only the original user
        });

        it('should NOT set result_token for existing users', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            const code = 'existing-user-session';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                userId,
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'discord-access-token',
                    refresh_token: 'discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            const session = await env.DB.prepare(`
                SELECT result_token FROM auth_sessions WHERE code = ?
            `).bind(code).first();

            // result_token is empty string for existing users
            expect(session!.result_token).toBe('');
        });
    });

    describe('deduplication and cross-user unlinking', () => {
        it('should update tokens when same user re-links same Discord account', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);
            const discordId = '123456789012345678';

            // Create existing Discord account link
            const discordIdHash = await hashDiscordId(discordId, env.DISCORD_ID_SALT);
            await env.DB.prepare(`
                INSERT INTO discord_accounts (
                    id, user_id, discord_user_id_hash,
                    access_token_enc, refresh_token_enc, token_expires_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
                'existing-account-id',
                userId,
                discordIdHash,
                'old-access-token-enc',
                'old-refresh-token-enc',
                Date.now() - 3600000,  // Expired
                Date.now() - 7200000,
                Date.now() - 3600000
            ).run();

            // Create session for re-linking
            const code = 'relink-session';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                userId,
                resultClientKey: clientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'new-discord-access-token',
                    refresh_token: 'new-discord-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: discordId,
                    username: 'testuser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            // Should still only have one Discord account
            const accounts = await env.DB.prepare('SELECT * FROM discord_accounts').all();
            expect(accounts.results.length).toBe(1);

            // Tokens should be updated (not the old values)
            expect(accounts.results[0]!.access_token_enc).not.toBe('old-access-token-enc');
            expect(accounts.results[0]!.refresh_token_enc).not.toBe('old-refresh-token-enc');
        });

        it('should unlink Discord from previous user when new user links it', async () => {
            // Create first user with linked Discord
            const firstUserToken = generateToken();
            const firstUserId = await createTestUser(env.DB, firstUserToken, env.ENCRYPTION_KEY);
            const discordId = '123456789012345678';

            const discordIdHash = await hashDiscordId(discordId, env.DISCORD_ID_SALT);
            await env.DB.prepare(`
                INSERT INTO discord_accounts (
                    id, user_id, discord_user_id_hash,
                    access_token_enc, refresh_token_enc, token_expires_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
                'first-user-account',
                firstUserId,
                discordIdHash,
                'first-user-access-token',
                'first-user-refresh-token',
                Date.now() + 3600000,
                Date.now(),
                Date.now()
            ).run();

            // Create second user
            const secondUserToken = generateToken();
            const secondClientKey = generateToken();
            const secondUserId = await createTestUser(env.DB, secondUserToken, env.ENCRYPTION_KEY);

            // Second user tries to link the same Discord account
            const code = 'cross-user-link-session';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                userId: secondUserId,
                resultClientKey: secondClientKey,
            });

            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'second-user-access-token',
                    refresh_token: 'second-user-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: discordId,  // Same Discord ID
                    username: 'testuser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            // Should still only have one Discord account (old one deleted, new one created)
            const accounts = await env.DB.prepare('SELECT * FROM discord_accounts').all();
            expect(accounts.results.length).toBe(1);

            // Should now belong to second user
            expect(accounts.results[0]!.user_id).toBe(secondUserId);
        });

        it('should allow same user to link multiple different Discord accounts', async () => {
            const authToken = generateToken();
            const clientKey = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            // Create first Discord account link
            const firstDiscordId = '111111111111111111';
            const firstDiscordIdHash = await hashDiscordId(firstDiscordId, env.DISCORD_ID_SALT);
            await env.DB.prepare(`
                INSERT INTO discord_accounts (
                    id, user_id, discord_user_id_hash,
                    access_token_enc, refresh_token_enc, token_expires_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
                'first-discord-account',
                userId,
                firstDiscordIdHash,
                'first-access-token',
                'first-refresh-token',
                Date.now() + 3600000,
                Date.now(),
                Date.now()
            ).run();

            // Link second Discord account
            const code = 'second-discord-session';
            await createTestSession(env.DB, {
                code,
                state: 'started',
                userId,
                resultClientKey: clientKey,
            });

            const secondDiscordId = '222222222222222222';
            mockDiscordFetch({
                tokenResponse: {
                    access_token: 'second-access-token',
                    refresh_token: 'second-refresh-token',
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: secondDiscordId,  // Different Discord ID
                    username: 'seconduser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            // Should have two Discord accounts for the same user
            const accounts = await env.DB.prepare(`
                SELECT * FROM discord_accounts WHERE user_id = ?
            `).bind(userId).all();

            expect(accounts.results.length).toBe(2);
        });
    });

    describe('encryption', () => {
        it('should encrypt Discord tokens with derived key', async () => {
            const code = 'encryption-test-session';
            const clientKey = generateToken();
            await createTestSession(env.DB, {
                code,
                state: 'started',
                resultClientKey: clientKey,
            });

            const discordAccessToken = 'test-discord-access-token';
            const discordRefreshToken = 'test-discord-refresh-token';

            mockDiscordFetch({
                tokenResponse: {
                    access_token: discordAccessToken,
                    refresh_token: discordRefreshToken,
                    expires_in: 3600,
                    token_type: 'Bearer',
                    scope: 'identify activities.write',
                },
                userResponse: {
                    id: '123456789012345678',
                    username: 'testuser',
                    discriminator: '0',
                    avatar: null,
                    global_name: null,
                },
            });

            await makeRequest(
                app,
                `/auth/callback?code=discord-code&state=${code}`,
                env
            );

            const account = await env.DB.prepare(`
                SELECT access_token_enc, refresh_token_enc FROM discord_accounts
            `).first();

            // Encrypted tokens should not be the plaintext tokens
            expect(account!.access_token_enc).not.toBe(discordAccessToken);
            expect(account!.refresh_token_enc).not.toBe(discordRefreshToken);

            // Should be base64url encoded
            expect(account!.access_token_enc).toMatch(/^[A-Za-z0-9_-]+$/);
            expect(account!.refresh_token_enc).toMatch(/^[A-Za-z0-9_-]+$/);
        });
    });
});

