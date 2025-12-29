/**
 * GET /auth/callback
 *
 * Discord redirects here after user authorization.
 * Exchanges code for tokens and completes the auth flow.
 */

import { Hono } from 'hono';
import type { Env } from '../../env';
import { createUser } from '../../services/user';
import {
    getAuthSession,
    updateAuthSessionState,
    setAuthSessionResult,
} from '../../services/authSession';
import {
    exchangeDiscordCode,
    fetchDiscordUser,
    DiscordApiError,
} from '../../services/discord';
import {
    findDiscordAccountByHash,
    createDiscordAccount,
    updateDiscordAccountTokens,
    deleteDiscordAccount,
} from '../../services/discordAccount';
import {
    hashDiscordId,
    deriveEncryptionKey,
    encryptDiscordTokens,
} from '../../crypto';
import { renderErrorPage, renderSuccessPage } from './utils';

const callbackRoute = new Hono<{ Bindings: Env }>();

/**
 * GET /callback
 *
 * Discord redirects here after user authorization.
 * Exchanges code for tokens and completes the auth flow.
 */
callbackRoute.get('/', async (c) => {
    const discordCode = c.req.query('code');
    const state = c.req.query('state');
    const error = c.req.query('error');
    const errorDescription = c.req.query('error_description');

    // Handle Discord OAuth errors
    if (error) {
        return c.html(
            renderErrorPage(`Discord authorization failed: ${errorDescription || error}`),
            400
        );
    }

    // Validate required params
    if (!discordCode || !state) {
        return c.html(renderErrorPage('Missing authorization parameters'), 400);
    }

    // Get and validate auth session
    const session = await getAuthSession(c.env.DB, state);
    if (!session) {
        return c.html(renderErrorPage('Invalid session. Please start over.'), 400);
    }

    if (session.expiresAt < Date.now()) {
        return c.html(renderErrorPage('Session expired. Please start over.'), 410);
    }

    if (session.state !== 'started') {
        return c.html(
            renderErrorPage('Invalid session state. The flow may have already completed.'),
            400
        );
    }

    try {
        // Exchange Discord code for tokens
        const tokenResponse = await exchangeDiscordCode(
            discordCode,
            session.codeVerifier,
            c.env.DISCORD_CLIENT_ID,
            c.env.DISCORD_CLIENT_SECRET,
            c.env.DISCORD_REDIRECT_URI
        );

        // Fetch Discord user info (for deduplication - not stored)
        const discordUser = await fetchDiscordUser(tokenResponse.access_token);

        // Determine user ID and client key
        let userId: string;
        let clientKey: string;
        let authToken: string | undefined;

        if (session.userId) {
            // Existing user linking new Discord account
            userId = session.userId;
            // Client key from session was set when flow started (existing user must have provided it)
            // For existing users, we don't return a new client key - they already have one
            clientKey = session.resultClientKey ?? '';
            if (!clientKey) {
                // This shouldn't happen for existing users, but handle gracefully
                return c.html(renderErrorPage('Missing client key for existing user'), 500);
            }
        } else {
            // New user - create user account
            const { user, authToken: newAuthToken } = await createUser(
                c.env.DB,
                c.env.ENCRYPTION_KEY
            );
            userId = user.id;
            authToken = newAuthToken;
            // Client key was pre-generated when session was created (for new users)
            clientKey = session.resultClientKey ?? '';
            if (!clientKey) {
                return c.html(renderErrorPage('Missing client key for new user'), 500);
            }
        }

        // Derive encryption key for Discord tokens
        const encryptionKey = await deriveEncryptionKey(
            c.env.ENCRYPTION_KEY,
            clientKey,
            userId
        );

        // Encrypt Discord tokens
        const tokenExpiresAt = Date.now() + tokenResponse.expires_in * 1000;
        const { accessTokenEnc, refreshTokenEnc } = await encryptDiscordTokens(
            tokenResponse.access_token,
            tokenResponse.refresh_token,
            encryptionKey
        );

        // Hash Discord user ID for deduplication
        const discordUserIdHash = await hashDiscordId(
            discordUser.id,
            c.env.DISCORD_ID_SALT
        );

        // Handle deduplication - check if Discord account is already linked
        const existingAccount = await findDiscordAccountByHash(c.env.DB, discordUserIdHash);

        if (existingAccount) {
            if (existingAccount.userId === userId) {
                // Same user re-linking same Discord account - just update tokens
                await updateDiscordAccountTokens(
                    c.env.DB,
                    existingAccount.id,
                    accessTokenEnc,
                    refreshTokenEnc,
                    tokenExpiresAt
                );
            } else {
                // Different user! Cross-user unlinking: delete old link, create new one
                await deleteDiscordAccount(c.env.DB, existingAccount.id);
                await createDiscordAccount(c.env.DB, {
                    userId,
                    discordUserIdHash,
                    accessTokenEnc,
                    refreshTokenEnc,
                    tokenExpiresAt,
                });
            }
        } else {
            // New Discord account - create link
            await createDiscordAccount(c.env.DB, {
                userId,
                discordUserIdHash,
                accessTokenEnc,
                refreshTokenEnc,
                tokenExpiresAt,
            });
        }

        // Update session with result
        await setAuthSessionResult(
            c.env.DB,
            state,
            authToken ?? '',  // Only set for new users
            session.userId ? undefined : clientKey  // Only set client_key for new users
        );

        // Return success page with completion code
        return c.html(renderSuccessPage(session.completionCode ?? ''), 200);
    } catch (err) {
        console.error('Auth callback error:', err);

        // Update session state to failed
        const errorMessage = err instanceof DiscordApiError
            ? `Discord API error: ${err.status}`
            : err instanceof Error
                ? err.message
                : 'Unknown error';

        await updateAuthSessionState(c.env.DB, state, 'failed', errorMessage);

        if (err instanceof DiscordApiError) {
            return c.html(
                renderErrorPage(`Discord API error. Please try again.`),
                502
            );
        }

        return c.html(renderErrorPage('An error occurred. Please try again.'), 500);
    }
});

export { callbackRoute };

