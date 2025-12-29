/**
 * POST /api/auth/start
 *
 * Initiates the Discord linking flow.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { findUserByToken } from '../../services/user';
import {
    createAuthSession,
    SESSION_EXPIRATION_SECONDS,
} from '../../services/authSession';
import { rateLimiters, trackActivity } from '../../middleware';
import type { AuthVariables } from '../../middleware/auth';
import {
    validateBody,
    getValidatedBody,
    createResponse,
    AuthStartRequestSchema,
    AuthStartResponseSchema,
} from '../../proto/validation';
import { errors } from '../../proto/errors';
import { getBaseUrl } from './utils';

const startRoute = new Hono<{ Bindings: Env; Variables: Partial<AuthVariables> }>();

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
    // Custom auth logic for this route:
    // - auth_token is optional (new users don't have one)
    // - client_key is required when auth_token is provided
    async (c, next) => {
        const body = getValidatedBody<typeof AuthStartRequestSchema>(c);

        if (body.authToken) {
            // client_key is required for existing users
            if (!body.clientKey) {
                return errors.invalidRequest(
                    c,
                    'client_key is required when auth_token is provided',
                    { field: 'client_key' }
                );
            }

            const result = await findUserByToken(
                c.env.DB,
                body.authToken,
                c.env.ENCRYPTION_KEY
            );

            if (!result.found || !result.user) {
                return errors.unauthorized(c);
            }

            // Set userId in context for activity tracking middleware
            c.set('userId', result.user.id);
        }

        return next();
    },
    // Activity tracking middleware (only runs for successful responses)
    trackActivity,
    // Main route handler
    async (c) => {
        const body = getValidatedBody<typeof AuthStartRequestSchema>(c);
        const userId = c.get('userId');

        // Create auth session
        // For existing users, store their client_key so we can use it in the callback
        const session = await createAuthSession(c.env.DB, {
            userId,
            clientKey: body.clientKey,  // Only used for existing users
        });

        const baseUrl = getBaseUrl(c);
        const authUrl = `${baseUrl}/auth/link/${session.code}`;
        const sseUrl = `${baseUrl}/auth/sse/${session.code}`;

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
