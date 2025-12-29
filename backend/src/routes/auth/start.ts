/**
 * POST /api/auth/start
 *
 * Initiates the Discord linking flow.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { authenticateUser } from '../../services/user';
import {
    createAuthSession,
    SESSION_EXPIRATION_SECONDS,
} from '../../services/authSession';
import { rateLimiters } from '../../middleware/rateLimit';
import {
    validateBody,
    getValidatedBody,
    createResponse,
    AuthStartRequestSchema,
    AuthStartResponseSchema,
} from '../../proto/validation';
import { errors } from '../../proto/errors';
import { getBaseUrl } from './utils';

const startRoute = new Hono<{ Bindings: Env }>();

/**
 * POST /start
 *
 * Initiates the Discord linking flow.
 *
 * Request: AuthStartRequest (auth.proto)
 * Response: AuthStartResponse (auth.proto)
 */
startRoute.post(
    '/',
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
        // For existing users, store their client_key so we can use it in the callback
        const session = await createAuthSession(c.env.DB, {
            userId,
            clientKey: body.clientKey,  // Only used for existing users
        });

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

export { startRoute };

