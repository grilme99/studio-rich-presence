/**
 * Auth routes for Discord OAuth flow.
 */

import { Hono } from 'hono';
import type { Env } from '../env';
import { authenticateUser } from '../services/user';
import {
    createAuthSession,
    SESSION_EXPIRATION_SECONDS,
    updateSessionStateInKV,
} from '../services/authSession';
import { rateLimiters } from '../middleware/rateLimit';
import {
    validateBody,
    getValidatedBody,
    createResponse,
    AuthStartRequestSchema,
    AuthStartResponseSchema,
} from '../proto/validation';
import { errors } from '../proto/errors';

// Create router
const auth = new Hono<{ Bindings: Env }>();

/**
 * Base URL for auth links.
 * In production, this should be the deployed Worker URL.
 */
function getBaseUrl(c: { req: { url: string } }): string {
    const url = new URL(c.req.url);
    return `${url.protocol}//${url.host}`;
}

/**
 * POST /api/auth/start
 *
 * Initiates the Discord linking flow.
 *
 * Request: AuthStartRequest (auth.proto)
 * Response: AuthStartResponse (auth.proto)
 */
auth.post(
    '/start',
    rateLimiters.auth,
    validateBody(AuthStartRequestSchema),
    async (c) => {
        // Generated types use camelCase (authToken, clientKey)
        const body = getValidatedBody<typeof AuthStartRequestSchema>(c);
        let userId: string | undefined;

        // If authToken provided, validate it and get user
        if (body.authToken) {
            // clientKey is required for existing users
            if (!body.clientKey) {
                return errors.invalidRequest(
                    c,
                    'client_key is required when auth_token is provided',
                    { field: 'client_key' }
                );
            }

            const authResult = await authenticateUser(
                c.env.DB,
                body.authToken,
                c.env.ENCRYPTION_KEY
            );

            if (!authResult.success || !authResult.user) {
                return errors.unauthorized(c);
            }

            userId = authResult.user.id;
        }

        // Create auth session
        const session = await createAuthSession(c.env.DB, { userId });

        // Initialize SSE state in KV
        await updateSessionStateInKV(c.env.KV, session.code, 'pending');

        // Build response URLs
        const baseUrl = getBaseUrl(c);
        const authUrl = `${baseUrl}/auth/link/${session.code}`;
        const sseUrl = `${baseUrl}/auth/sse/${session.code}`;

        // Return typed response (toJson converts to snake_case for JSON)
        const response = createResponse(AuthStartResponseSchema, {
            code: session.code,
            url: authUrl,
            sseUrl: sseUrl,
            expiresInSeconds: SESSION_EXPIRATION_SECONDS,
        });

        return c.json(response);
    }
);

export { auth };
