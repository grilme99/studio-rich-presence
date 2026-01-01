/**
 * POST /api/presence/update
 *
 * Updates Discord presence for all linked accounts.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { getDiscordAccountsForUser, getValidAccessToken } from '../../services/discordAccount';
import {
    presenceToActivity,
    updateHeadlessSession,
    getCachedSessionToken,
    cacheSessionToken,
    type PresenceUpdateResult,
} from '../../services/presence';
import { deriveEncryptionKey } from '../../crypto';
import { requireAuth, trackActivity, rateLimiters } from '../../middleware';
import type { AuthVariables } from '../../middleware/auth';
import {
    validateBody,
    getValidatedBody,
    createResponse,
} from '../../proto/validation';
import { errors } from '../../proto/errors';
import {
    UpdatePresenceRequestSchema,
    UpdatePresenceResponseSchema,
} from '../../generated/presence_pb';
import { inspect } from 'util';

const updateRoute = new Hono<{ Bindings: Env; Variables: AuthVariables }>();

/**
 * POST /update
 *
 * Updates Discord presence for all linked accounts.
 *
 * Headers:
 *   Authorization: Bearer <auth_token>
 *   X-Client-Key: <client_key>
 *
 * Request: UpdatePresenceRequest (presence.proto) - only presence field is used
 * Response: UpdatePresenceResponse (presence.proto)
 */
updateRoute.post(
    '/',
    rateLimiters.presence,
    requireAuth,
    trackActivity,
    validateBody(UpdatePresenceRequestSchema),
    async (c) => {
        const body = getValidatedBody<typeof UpdatePresenceRequestSchema>(c);
        const userId = c.get('userId');

        // Get client key from header
        const clientKey = c.req.header('X-Client-Key');
        if (!clientKey) {
            return errors.invalidRequest(c, 'X-Client-Key header is required');
        }

        // Derive encryption key for Discord token decryption
        const encryptionKey = await deriveEncryptionKey(
            c.env.ENCRYPTION_KEY,
            clientKey,
            userId
        );

        const accounts = await getDiscordAccountsForUser(c.env.DB, userId);
        const activity = presenceToActivity(body.presence, c.env.DISCORD_CLIENT_ID);

        // Update presence for each account in parallel
        const results = await Promise.allSettled(
            accounts.map(async (account): Promise<PresenceUpdateResult> => {
                try {
                    // Get valid access token (refreshes if needed)
                    const accessToken = await getValidAccessToken({
                        db: c.env.DB,
                        account,
                        encryptionKey,
                        discordClientId: c.env.DISCORD_CLIENT_ID,
                        discordClientSecret: c.env.DISCORD_CLIENT_SECRET,
                    });

                    // Get cached session token if available
                    const cachedToken = await getCachedSessionToken(c.env.KV, account.id);

                    // Update presence via headless session (reusing existing session if cached)
                    const sessionResponse = await updateHeadlessSession(
                        accessToken,
                        activity,
                        cachedToken ?? undefined
                    );

                    // Cache the session token for future updates (19min TTL)
                    await cacheSessionToken(c.env.KV, account.id, sessionResponse.token);

                    return {
                        accountId: account.id,
                        success: true,
                        sessionToken: sessionResponse.token,
                    };
                } catch (error) {
                    console.error(`Failed to update presence for account ${account.id}:`, inspect(error, { depth: null }));
                    return {
                        accountId: account.id,
                        success: false,
                        error: error instanceof Error ? error.message : 'Unknown error',
                    };
                }
            })
        );

        // Count successes and failures
        let updatedAccounts = 0;
        let failedAccounts = 0;

        for (const result of results) {
            if (result.status === 'fulfilled' && result.value.success) {
                updatedAccounts++;
            } else {
                failedAccounts++;
            }
        }

        const response = createResponse(UpdatePresenceResponseSchema, {
            updatedAccounts,
            failedAccounts,
        });

        return c.json(response);
    }
);

export { updateRoute };
