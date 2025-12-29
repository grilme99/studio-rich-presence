/**
 * POST /api/presence/clear
 *
 * Clears Discord presence for all linked accounts by deleting headless sessions.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { getDiscordAccountsForUser, getValidAccessToken } from '../../services/discordAccount';
import {
    deleteHeadlessSession,
    getCachedSessionToken,
    deleteCachedSessionToken,
} from '../../services/presence';
import { deriveEncryptionKey } from '../../crypto';
import { requireAuth, trackActivity, rateLimiters } from '../../middleware';
import type { AuthVariables } from '../../middleware/auth';
import { createResponse } from '../../proto/validation';
import { errors } from '../../proto/errors';
import { ClearPresenceResponseSchema } from '../../generated/presence_pb';

const clearRoute = new Hono<{ Bindings: Env; Variables: AuthVariables }>();

/**
 * POST /clear
 *
 * Clears Discord presence for all linked accounts.
 *
 * Headers:
 *   Authorization: Bearer <auth_token>
 *   X-Client-Key: <client_key>
 *
 * Response: ClearPresenceResponse (presence.proto)
 */
clearRoute.post(
    '/',
    rateLimiters.presenceClear,
    requireAuth,
    trackActivity,
    async (c) => {
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

        // Clear presence for each account in parallel
        const results = await Promise.allSettled(
            accounts.map(async (account) => {
                try {
                    // Get cached session token - if none exists, nothing to clear
                    const sessionToken = await getCachedSessionToken(c.env.KV, account.id);
                    if (!sessionToken) {
                        // No active session, consider it successfully cleared
                        return { accountId: account.id, success: true, hadSession: false };
                    }

                    // Get valid access token (refreshes if needed)
                    const accessToken = await getValidAccessToken({
                        db: c.env.DB,
                        account,
                        encryptionKey,
                        discordClientId: c.env.DISCORD_CLIENT_ID,
                        discordClientSecret: c.env.DISCORD_CLIENT_SECRET,
                    });

                    // Delete the headless session on Discord
                    await deleteHeadlessSession(accessToken, sessionToken);

                    // Remove the cached session token
                    await deleteCachedSessionToken(c.env.KV, account.id);

                    return { accountId: account.id, success: true, hadSession: true };
                } catch (error) {
                    console.error(`Failed to clear presence for account ${account.id}:`, error);

                    // Still try to delete from cache even if Discord API failed
                    await deleteCachedSessionToken(c.env.KV, account.id).catch(() => { });

                    return {
                        accountId: account.id,
                        success: false,
                        error: error instanceof Error ? error.message : 'Unknown error',
                    };
                }
            })
        );

        // Count successes and failures
        let clearedAccounts = 0;
        let failedAccounts = 0;

        for (const result of results) {
            if (result.status === 'fulfilled' && result.value.success) {
                clearedAccounts++;
            } else {
                failedAccounts++;
            }
        }

        const response = createResponse(ClearPresenceResponseSchema, {
            clearedAccounts,
            failedAccounts,
        });

        return c.json(response);
    }
);

export { clearRoute };
