/**
 * GET /api/accounts
 *
 * Lists all linked Discord accounts for the authenticated user.
 * Fetches Discord user info live to get current username/avatar.
 */

import { Hono } from 'hono';
import { create } from '@bufbuild/protobuf';
import type { Env } from '../../env';
import { getDiscordAccountsForUser, getValidAccessToken } from '../../services/discordAccount';
import { fetchDiscordUser, getDiscordAvatarUrl } from '../../services/discord';
import { deriveEncryptionKey } from '../../crypto';
import { requireAuth, trackActivity, rateLimiters } from '../../middleware';
import type { AuthVariables } from '../../middleware/auth';
import { createResponse } from '../../proto/validation';
import { errors } from '../../proto/errors';
import {
    ListAccountsResponseSchema,
    LinkedAccountSchema,
    type LinkedAccount,
} from '../../generated/accounts_pb';

const listRoute = new Hono<{ Bindings: Env; Variables: AuthVariables }>();

/**
 * GET /
 *
 * Lists all linked Discord accounts with their current Discord profile info.
 *
 * Headers:
 *   Authorization: Bearer <auth_token>
 *   X-Client-Key: <client_key>
 *
 * Response: ListAccountsResponse (presence.proto)
 */
listRoute.get(
    '/',
    rateLimiters.accounts,
    requireAuth,
    trackActivity,
    async (c) => {
        const userId = c.get('userId');

        // Get client key from header (needed to decrypt Discord tokens)
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

        // Fetch Discord user info and session status for each account
        const accountDetails: LinkedAccount[] = await Promise.all(
            accounts.map(async (account) => {
                try {
                    // Get valid access token (refreshes if needed)
                    const accessToken = await getValidAccessToken({
                        db: c.env.DB,
                        account,
                        encryptionKey,
                        discordClientId: c.env.DISCORD_CLIENT_ID,
                        discordClientSecret: c.env.DISCORD_CLIENT_SECRET,
                    });

                    // Fetch current Discord user info
                    const discordUser = await fetchDiscordUser(accessToken);

                    return create(LinkedAccountSchema, {
                        id: account.id,
                        username: discordUser.username,
                        displayName: discordUser.global_name ?? undefined,
                        avatarUrl: getDiscordAvatarUrl(discordUser.id, discordUser.avatar) ?? undefined,
                        linkedAt: BigInt(account.createdAt),
                    });
                } catch (error) {
                    // If we can't fetch Discord user info, return basic info
                    console.error(`Failed to fetch Discord user info for account ${account.id}:`, error);

                    return create(LinkedAccountSchema, {
                        id: account.id,
                        username: 'Unknown',
                        displayName: undefined,
                        avatarUrl: undefined,
                        linkedAt: BigInt(account.createdAt),
                    });
                }
            })
        );

        const response = createResponse(ListAccountsResponseSchema, {
            accounts: accountDetails,
        });

        return c.json(response);
    }
);

export { listRoute };
