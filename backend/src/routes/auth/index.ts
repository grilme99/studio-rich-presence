/**
 * Auth routes for Discord OAuth flow.
 *
 * Combines all auth-related routes into a single router.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { startRoute } from './start';
import { linkRoute } from './link';
import { callbackRoute } from './callback';
import { sseRoute } from './sse';
import { completeRoute } from './complete';

// Create combined auth router
const auth = new Hono<{ Bindings: Env }>();

// POST /api/auth/start -> /start
auth.route('/start', startRoute);

// GET /auth/link/:code -> /link/:code
auth.route('/link', linkRoute);

// GET /auth/callback -> /callback
auth.route('/callback', callbackRoute);

// GET /auth/sse/:code -> /sse/:code
auth.route('/sse', sseRoute);

// POST /api/auth/complete -> /complete
auth.route('/complete', completeRoute);

export { auth };

// Re-export utilities for tests
export * from './utils';

