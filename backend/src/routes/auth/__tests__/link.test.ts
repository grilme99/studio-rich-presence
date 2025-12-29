/**
 * Tests for GET /auth/link/:code endpoint.
 */

import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { env } from 'cloudflare:test';
import type { Hono } from 'hono';
import type { Env } from '../../../env';
import {
    createTestApp,
    makeRequest,
    createTestSession,
    cleanupDatabase,
    cleanupKV,
    setupDatabase,
} from './testUtils';

describe('GET /auth/link/:code', () => {
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
        it('should return 404 for non-existent session', async () => {
            const response = await makeRequest(app, '/auth/link/non-existent-code', env);

            expect(response.status).toBe(404);
            const text = await response.text();
            expect(text).toContain('Link not found');
        });

        it('should return 410 for expired session', async () => {
            const code = 'expired-session-code';
            await createTestSession(env.DB, {
                code,
                expiresAt: Date.now() - 1000,  // Expired 1 second ago
            });

            const response = await makeRequest(app, `/auth/link/${code}`, env);

            expect(response.status).toBe(410);
            const text = await response.text();
            expect(text).toContain('expired');
        });

        it('should return 400 for already-used session (started state)', async () => {
            const code = 'started-session-code';
            await createTestSession(env.DB, {
                code,
                state: 'started',
            });

            const response = await makeRequest(app, `/auth/link/${code}`, env);

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('already been used');
        });

        it('should return 400 for completed session', async () => {
            const code = 'completed-session-code';
            await createTestSession(env.DB, {
                code,
                state: 'completed',
            });

            const response = await makeRequest(app, `/auth/link/${code}`, env);

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('already been used');
        });

        it('should return 400 for failed session', async () => {
            const code = 'failed-session-code';
            await createTestSession(env.DB, {
                code,
                state: 'failed',
            });

            const response = await makeRequest(app, `/auth/link/${code}`, env);

            expect(response.status).toBe(400);
            const text = await response.text();
            expect(text).toContain('already been used');
        });
    });

    describe('successful redirect', () => {
        it('should redirect to Discord OAuth', async () => {
            const code = 'valid-session-code';
            await createTestSession(env.DB, { code });

            const response = await makeRequest(app, `/auth/link/${code}`, env);

            expect(response.status).toBe(302);
            const location = response.headers.get('Location');
            expect(location).toContain('discord.com/oauth2/authorize');
        });

        it('should include correct OAuth parameters', async () => {
            const code = 'valid-session-code';
            await createTestSession(env.DB, { code });

            const response = await makeRequest(app, `/auth/link/${code}`, env);
            const location = response.headers.get('Location')!;
            const url = new URL(location);

            expect(url.searchParams.get('client_id')).toBe(env.DISCORD_CLIENT_ID);
            expect(url.searchParams.get('redirect_uri')).toBe(env.DISCORD_REDIRECT_URI);
            expect(url.searchParams.get('response_type')).toBe('code');
            expect(url.searchParams.get('scope')).toBe('identify sdk.social_layer_presence');
            expect(url.searchParams.get('state')).toBe(code);
            expect(url.searchParams.get('code_challenge_method')).toBe('S256');
            expect(url.searchParams.get('code_challenge')).toBeTruthy();
        });

        it('should update session state to started', async () => {
            const code = 'valid-session-code';
            await createTestSession(env.DB, { code });

            await makeRequest(app, `/auth/link/${code}`, env);

            const session = await env.DB.prepare(`
                SELECT state FROM auth_sessions WHERE code = ?
            `).bind(code).first();

            expect(session!.state).toBe('started');
        });
    });
});

