/**
 * GET /auth/sse/:code
 *
 * Server-Sent Events endpoint for real-time auth flow updates.
 * Uses KV polling internally - polls every 1.5 seconds for state changes.
 */

import { Hono } from 'hono';
import { streamSSE } from 'hono/streaming'
import type { Env } from '../../env';
import {
    AuthSession,
    getAuthSession,
    type AuthSessionState,
} from '../../services/authSession';
import { rateLimiters } from '../../middleware';

export const SSE_POLL_INTERVAL_MS = 1500;  // Poll DB every 1.5 seconds
export const SSE_HEARTBEAT_INTERVAL_MS = 20000;  // Send heartbeat every 20 seconds
export const SSE_CONNECTION_TIMEOUT_MS = 300000;  // 5 minutes

const sseRoute = new Hono<{ Bindings: Env }>();

/**
 * GET /sse/:code
 *
 * Server-Sent Events endpoint for real-time auth flow updates.
 */
sseRoute.get(
    '/:code',
    rateLimiters.sse,
    async (c) => {
        let id = 0;
        return streamSSE(c, async (stream) => {
            const code = c.req.param('code');

            // Validate session exists
            const session = await getAuthSession(c.env.DB, code);
            if (!session) {
                return await stream.writeSSE({
                    event: 'expired',
                    data: '',
                    id: String(id++),
                })
            }

            // Check expiration
            if (session.expiresAt < Date.now()) {
                return await stream.writeSSE({
                    event: 'expired',
                    data: '',
                    id: String(id++),
                })
            }

            // If already in terminal state, return immediately
            if (session.state === 'completed' || session.state === 'failed') {
                return await stream.writeSSE({
                    event: session.state,
                    data: JSON.stringify(formatSsePayload(session)),
                    id: String(id++),
                })
            }

            // Send an event for the current state
            await stream.writeSSE({
                event: session.state,
                data: JSON.stringify(formatSsePayload(session)),
                id: String(id++),
            })

            // Start polling for updates
            let lastState: AuthSessionState = session.state;
            let lastHeartbeat = Date.now();
            let startedAt = Date.now();
            while (true) {
                const currentSession = await getAuthSession(c.env.DB, code);
                if (!currentSession || currentSession.expiresAt < Date.now()) {
                    await stream.writeSSE({
                        event: 'expired',
                        data: '',
                        id: String(id++),
                    })
                    break;
                }

                // Check for state change
                if (currentSession.state !== lastState) {
                    lastState = currentSession.state;
                    await stream.writeSSE({
                        event: currentSession.state,
                        data: JSON.stringify(formatSsePayload(currentSession)),
                        id: String(id++),
                    })
                }

                // Send heartbeat if needed
                if (Date.now() - lastHeartbeat > SSE_HEARTBEAT_INTERVAL_MS) {
                    await stream.writeSSE({
                        event: 'heartbeat',
                        data: '',
                        id: String(id++),
                    })
                    lastHeartbeat = Date.now();
                }

                // Check for connection timeout
                if (Date.now() - startedAt > SSE_CONNECTION_TIMEOUT_MS) {
                    await stream.writeSSE({
                        event: 'expired',
                        data: '',
                        id: String(id++),
                    })
                    break;
                }

                await stream.sleep(SSE_POLL_INTERVAL_MS);
            }
        }, async (err, stream) => {
            stream.writeSSE({
                event: 'error',
                data: '',
                id: String(id++),
            })
            console.error(err)
        });
    });

function formatSsePayload(session: AuthSession | null): object {
    if (!session) {
        return {};
    }

    if (session.state === 'failed') {
        return {
            error: session.errorMessage ?? 'Unknown error',
        };
    }

    if (session.state === 'completed') {
        // Only return credentials for new users
        // New users have resultToken set, existing users don't
        const isNewUser = !!session.resultToken;
        const payload: Record<string, string> = {};

        if (session.resultToken) {
            payload.authToken = session.resultToken;
        }
        if (isNewUser && session.resultClientKey) {
            payload.clientKey = session.resultClientKey;
        }
        return payload;
    }

    return {};
}

export { sseRoute };

