/**
 * Presence API routes.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { updateRoute } from './update';

const presenceRouter = new Hono<{ Bindings: Env }>();

// POST /presence/update
presenceRouter.route('/update', updateRoute);

export { presenceRouter };

