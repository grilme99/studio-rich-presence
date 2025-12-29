/**
 * Tests for GET /auth/sse/:code endpoint.
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
    parseSseEvents,
} from './testUtils';

describe('GET /auth/sse/:code', () => {
    let app: Hono<{ Bindings: Env }>;

    beforeAll(async () => {
        await setupDatabase(env.DB);
    });

    beforeEach(async () => {
        app = createTestApp();
        await cleanupDatabase(env.DB);
        await cleanupKV(env.KV);
    });

    describe('session validation', () => {
        it('should return expired event for non-existent session', async () => {
            const response = await makeRequest(app, '/auth/sse/non-existent-code', env);

            expect(response.status).toBe(200);
            expect(response.headers.get('Content-Type')).toBe('text/event-stream');

            const text = await response.text();
            const events = parseSseEvents(text);

            expect(events).toHaveLength(1);
            expect(events[0]!.event).toBe('expired');
            expect(events[0]!.data).toEqual({});
        });

        it('should return expired event for expired session', async () => {
            const code = 'expired-session';
            await createTestSession(env.DB, {
                code,
                expiresAt: Date.now() - 1000,
            });

            const response = await makeRequest(app, `/auth/sse/${code}`, env);

            expect(response.status).toBe(200);
            const text = await response.text();
            const events = parseSseEvents(text);

            expect(events).toHaveLength(1);
            expect(events[0]!.event).toBe('expired');
            expect(events[0]!.data).toEqual({});
        });
    });

    describe('terminal states', () => {
        it('should return completed event immediately for completed session', async () => {
            const code = 'completed-session';
            const authToken = generateToken();
            const clientKey = generateToken();

            await createTestSession(env.DB, {
                code,
                state: 'completed',
                resultToken: authToken,
                resultClientKey: clientKey,
            });

            const response = await makeRequest(app, `/auth/sse/${code}`, env);

            expect(response.status).toBe(200);
            const text = await response.text();
            const events = parseSseEvents(text);

            expect(events).toHaveLength(1);
            expect(events[0]!.event).toBe('completed');
            const data = events[0]!.data as Record<string, unknown>;
            expect(data).toHaveProperty('auth_token', authToken);
            expect(data).toHaveProperty('client_key', clientKey);
        });

        it('should return completed event without credentials for existing user', async () => {
            const code = 'completed-existing-user';
            const authToken = generateToken();
            const userId = await createTestUser(env.DB, authToken, env.ENCRYPTION_KEY);

            await createTestSession(env.DB, {
                code,
                state: 'completed',
                userId,  // Existing user
                resultToken: null,  // No token for existing users
                resultClientKey: generateToken(),  // Client key stored but not returned
            });

            const response = await makeRequest(app, `/auth/sse/${code}`, env);

            expect(response.status).toBe(200);
            const text = await response.text();
            const events = parseSseEvents(text);

            expect(events).toHaveLength(1);
            expect(events[0]!.event).toBe('completed');
            expect(events[0]!.data).toEqual({});  // No credentials for existing users
        });

        it('should return failed event with error message', async () => {
            const code = 'failed-session';
            const errorMsg = 'Discord API error: 401';

            await createTestSession(env.DB, {
                code,
                state: 'failed',
                errorMessage: errorMsg,
            });

            const response = await makeRequest(app, `/auth/sse/${code}`, env);

            expect(response.status).toBe(200);
            const text = await response.text();
            const events = parseSseEvents(text);

            expect(events).toHaveLength(1);
            expect(events[0]!.event).toBe('failed');
            const data = events[0]!.data as Record<string, unknown>;
            expect(data).toHaveProperty('error', errorMsg);
        });
    });

    describe('SSE headers', () => {
        it('should return correct SSE headers for completed session', async () => {
            // Use completed session for header test (returns immediately, no async loop)
            const code = 'completed-for-headers';
            await createTestSession(env.DB, {
                code,
                state: 'completed',
                resultToken: generateToken(),
                resultClientKey: generateToken(),
            });

            const response = await makeRequest(app, `/auth/sse/${code}`, env);

            expect(response.headers.get('Content-Type')).toBe('text/event-stream');
            expect(response.headers.get('Cache-Control')).toBe('no-cache');
        });
    });
});

