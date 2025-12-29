/**
 * Authentication middleware.
 *
 * Validates auth tokens and sets userId in context for downstream handlers.
 */

import { createMiddleware } from 'hono/factory';
import type { Context } from 'hono';
import type { Env } from '../env';
import { findUserByToken } from '../services/user';
import { errors } from '../proto/errors';

/**
 * Variables set by auth middleware.
 */
export interface AuthVariables {
    /** The authenticated user's ID */
    userId: string;
}

/**
 * Extract auth token from request.
 *
 * Checks Authorization header first, then falls back to request body.
 */
async function extractToken(c: Context): Promise<string | undefined> {
    // Try Authorization header first
    const authHeader = c.req.header('authorization');
    if (authHeader) {
        const match = authHeader.match(/^Bearer\s+(.+)$/i);
        if (match?.[1]) {
            return match[1];
        }
    }

    // Fall back to request body
    try {
        const body = await c.req.json();
        return body?.auth_token ?? body?.authToken;
    } catch {
        return undefined;
    }
}

/**
 * Authentication middleware that requires a valid auth token.
 *
 * Supports two authentication methods:
 * 1. Authorization header: `Authorization: Bearer <token>`
 * 2. Request body: `{ "auth_token": "..." }` or `{ "authToken": "..." }`
 *
 * On success, sets `userId` in context for downstream handlers.
 * On failure, returns 401 Unauthorized.
 *
 * @example
 * app.use('/api/accounts/*', requireAuth, trackActivity);
 * app.get('/api/accounts', (c) => {
 *   const userId = c.get('userId');
 * });
 */
export const requireAuth = createMiddleware<{
    Bindings: Env;
    Variables: AuthVariables;
}>(async (c, next) => {
    const token = await extractToken(c);
    if (!token) {
        return errors.unauthorized(c, 'Missing auth token');
    }

    const result = await findUserByToken(c.env.DB, token, c.env.ENCRYPTION_KEY);
    if (!result.found || !result.user) {
        return errors.unauthorized(c, 'Invalid auth token');
    }

    c.set('userId', result.user.id);
    return next();
});

/**
 * Optional auth middleware that sets userId if token is valid, but doesn't require it.
 *
 * Use this for endpoints that behave differently for authenticated vs anonymous users.
 *
 * @example
 * app.use('/api/public/*', optionalAuth);
 * app.get('/api/public/info', (c) => {
 *   const userId = c.get('userId'); // May be undefined
 * });
 */
export const optionalAuth = createMiddleware<{
    Bindings: Env;
    Variables: Partial<AuthVariables>;
}>(async (c, next) => {
    const token = await extractToken(c);
    if (token) {
        const result = await findUserByToken(c.env.DB, token, c.env.ENCRYPTION_KEY);
        if (result.found && result.user) {
            c.set('userId', result.user.id);
        }
    }
    return next();
});
