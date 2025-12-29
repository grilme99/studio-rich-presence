/**
 * Presence API routes.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { updateRoute } from './update';
import { clearRoute } from './clear';

const presenceRouter = new Hono<{ Bindings: Env }>();

// POST /presence/update
presenceRouter.route('/update', updateRoute);

// POST /presence/clear
presenceRouter.route('/clear', clearRoute);

export { presenceRouter };

