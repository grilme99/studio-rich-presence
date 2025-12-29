/**
 * POST /api/presence/update
 *
 * Updates Discord presence for all linked accounts.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { getDiscordAccountsForUser, updateDiscordAccountTokens } from '../../services/discordAccount';
import { refreshDiscordTokens } from '../../services/discord';
import {
    presenceToActivity,
    updateHeadlessSession,
    type PresenceUpdateResult,
} from '../../services/presence';
import {
    deriveEncryptionKey,
    decryptDiscordTokens,
    encryptDiscordTokens,
} from '../../crypto';
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

/** Token expiry buffer: refresh if token expires within 5 minutes */
const TOKEN_EXPIRY_BUFFER_MS = 5 * 60 * 1000;

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
        const now = Date.now();

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
                    // Decrypt tokens
                    const { accessToken, refreshToken } = await decryptDiscordTokens(
                        account.accessTokenEnc,
                        account.refreshTokenEnc,
                        encryptionKey
                    );

                    let currentAccessToken = accessToken;

                    // Check if token is expired or about to expire
                    if (account.tokenExpiresAt < now + TOKEN_EXPIRY_BUFFER_MS) {
                        // Refresh the token
                        const newTokens = await refreshDiscordTokens(
                            refreshToken,
                            c.env.DISCORD_CLIENT_ID,
                            c.env.DISCORD_CLIENT_SECRET
                        );

                        // Re-encrypt and store new tokens
                        const encrypted = await encryptDiscordTokens(
                            newTokens.access_token,
                            newTokens.refresh_token,
                            encryptionKey
                        );

                        const newExpiresAt = now + (newTokens.expires_in * 1000);

                        await updateDiscordAccountTokens(
                            c.env.DB,
                            account.id,
                            encrypted.accessTokenEnc,
                            encrypted.refreshTokenEnc,
                            newExpiresAt
                        );

                        currentAccessToken = newTokens.access_token;
                    }

                    // Update presence via headless session
                    await updateHeadlessSession(currentAccessToken, activity);

                    return {
                        accountId: account.id,
                        success: true,
                    };
                } catch (error) {
                    console.error(`Failed to update presence for account ${account.id}:`, error);
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
