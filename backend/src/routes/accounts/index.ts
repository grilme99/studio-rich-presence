/**
 * Accounts API routes.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { listRoute } from './list';

const accountsRouter = new Hono<{ Bindings: Env }>();

// GET /accounts/list
accountsRouter.route('/list', listRoute);

export { accountsRouter };

