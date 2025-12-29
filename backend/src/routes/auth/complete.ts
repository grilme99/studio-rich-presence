/**
 * POST /api/auth/complete
 *
 * Manual fallback for completing auth when SSE fails.
 * Requires both the session code and the 5-digit completion code.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { deleteAuthSession, getAuthSession } from '../../services/authSession';
import { rateLimiters } from '../../middleware/rateLimit';
import {
    validateBody,
    getValidatedBody,
    createResponse,
    AuthCompleteRequestSchema,
    AuthCompleteResponseSchema,
} from '../../proto/validation';
import { errors } from '../../proto/errors';
import { safeConstantTimeEqual } from './utils';

const completeRoute = new Hono<{ Bindings: Env }>();

/**
 * POST /complete
 *
 * Manual fallback for completing auth when SSE fails.
 * Requires both the session code and the 5-digit completion code.
 */
completeRoute.post(
    '/',
    rateLimiters.auth,
    validateBody(AuthCompleteRequestSchema),
    async (c) => {
        const body = getValidatedBody<typeof AuthCompleteRequestSchema>(c);

        // Validate required fields
        if (!body.code) {
            return errors.invalidRequest(c, 'Session code is required', { field: 'code' });
        }
        if (!body.completionCode) {
            return errors.invalidRequest(c, 'Completion code is required', { field: 'completion_code' });
        }

        // Get the session
        const session = await getAuthSession(c.env.DB, body.code);
        if (!session) {
            return errors.invalidRequest(c, 'Invalid or expired session code');
        }

        // Check expiration
        if (session.expiresAt < Date.now()) {
            return errors.sessionExpired(c);
        }

        // Verify completion code (constant-time comparison)
        if (!session.completionCode || !safeConstantTimeEqual(body.completionCode, session.completionCode)) {
            return errors.invalidCompletionCode(c);
        }

        // Check session state
        if (session.state === 'pending') {
            return errors.invalidRequest(
                c,
                'Authentication not yet completed. Please finish the Discord authorization first.',
                { state: 'pending' }
            );
        }

        if (session.state === 'failed') {
            return errors.invalidRequest(
                c,
                session.errorMessage ?? 'Authentication failed',
                { state: 'failed' }
            );
        }

        if (session.state === 'started') {
            return errors.invalidRequest(
                c,
                'Discord authorization in progress. Please complete it in your browser.',
                { state: 'started' }
            );
        }

        // Session is completed - return credentials for new users only
        // New users have resultToken set, existing users don't
        const isNewUser = !!session.resultToken;
        const response = createResponse(AuthCompleteResponseSchema, {
            authToken: session.resultToken || undefined,
            clientKey: isNewUser ? (session.resultClientKey || undefined) : undefined,
        });

        // Clear result from session to prevent replay
        await deleteAuthSession(c.env.DB, body.code);

        return c.json(response);
    }
);

export { completeRoute };

