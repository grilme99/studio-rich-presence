/**
 * Activity tracking middleware.
 *
 * Updates user's last_activity_at timestamp on successful authenticated requests.
 * Uses waitUntil() for non-blocking database updates.
 */

import { createMiddleware } from 'hono/factory';
import type { Env } from '../env';
import type { AuthVariables } from './auth';

/**
 * Update a user's last activity timestamp.
 *
 * This is a fire-and-forget operation - errors are logged but don't affect the response.
 */
async function updateLastActivity(db: D1Database, userId: string): Promise<void> {
    const now = Date.now();
    try {
        await db.prepare(`
            UPDATE users SET last_activity_at = ?, updated_at = ?
            WHERE id = ?
        `).bind(now, now, userId).run();
    } catch (error) {
        // Log but don't throw - activity tracking shouldn't break requests
        console.error('Failed to update last_activity_at:', error);
    }
}

/**
 * Middleware that tracks user activity by updating last_activity_at.
 *
 * Should be applied after requireAuth middleware that sets userId in context.
 * Uses waitUntil() to update the database without blocking the response.
 *
 * @example
 * // Apply to authenticated API routes
 * app.use('/api/accounts/*', requireAuth, trackActivity);
 * app.use('/api/presence/*', requireAuth, trackActivity);
 */
export const trackActivity = createMiddleware<{
    Bindings: Env;
    Variables: AuthVariables;
}>(async (c, next) => {
    // Process the request first
    await next();

    // Only track activity for successful responses (2xx status codes)
    const status = c.res.status;
    if (status < 200 || status >= 300) {
        return;
    }

    // Get userId from context (set by requireAuth middleware)
    const userId = c.get('userId');
    if (!userId) {
        return;
    }

    // Fire and forget - update activity without blocking response
    // waitUntil ensures the update completes even after response is sent
    // In test environments without ExecutionContext, fall back to direct execution
    const updatePromise = updateLastActivity(c.env.DB, userId);
    try {
        c.executionCtx.waitUntil(updatePromise);
    } catch {
        // No execution context (e.g., in tests) - just await the update
        await updatePromise;
    }
});
