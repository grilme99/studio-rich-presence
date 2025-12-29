/**
 * Auth routes for Discord OAuth flow.
 */

import { Hono } from 'hono';
import type { Env } from '../env';
import { authenticateUser, createUser } from '../services/user';
import {
    createAuthSession,
    getAuthSession,
    updateAuthSessionState,
    setAuthSessionResult,
    SESSION_EXPIRATION_SECONDS,
    updateSessionStateInKV,
} from '../services/authSession';
import {
    exchangeDiscordCode,
    fetchDiscordUser,
    DiscordApiError,
} from '../services/discord';
import {
    findDiscordAccountByHash,
    createDiscordAccount,
    updateDiscordAccountTokens,
    deleteDiscordAccount,
} from '../services/discordAccount';
import {
    generatePkceCodeChallenge,
    hashDiscordId,
    deriveEncryptionKey,
    encryptDiscordTokens,
} from '../crypto';
import { rateLimiters } from '../middleware/rateLimit';
import {
    validateBody,
    getValidatedBody,
    createResponse,
    AuthStartRequestSchema,
    AuthStartResponseSchema,
} from '../proto/validation';
import { errors } from '../proto/errors';

// Create router
const auth = new Hono<{ Bindings: Env }>();

/**
 * Base URL for auth links.
 * In production, this should be the deployed Worker URL.
 */
function getBaseUrl(c: { req: { url: string } }): string {
    const url = new URL(c.req.url);
    return `${url.protocol}//${url.host}`;
}

/**
 * POST /api/auth/start
 *
 * Initiates the Discord linking flow.
 *
 * Request: AuthStartRequest (auth.proto)
 * Response: AuthStartResponse (auth.proto)
 */
auth.post(
    '/start',
    rateLimiters.auth,
    validateBody(AuthStartRequestSchema),
    async (c) => {
        // Generated types use camelCase (authToken, clientKey)
        const body = getValidatedBody<typeof AuthStartRequestSchema>(c);
        let userId: string | undefined;

        // If authToken provided, validate it and get user
        if (body.authToken) {
            // clientKey is required for existing users
            if (!body.clientKey) {
                return errors.invalidRequest(
                    c,
                    'client_key is required when auth_token is provided',
                    { field: 'client_key' }
                );
            }

            const authResult = await authenticateUser(
                c.env.DB,
                body.authToken,
                c.env.ENCRYPTION_KEY
            );

            if (!authResult.success || !authResult.user) {
                return errors.unauthorized(c);
            }

            userId = authResult.user.id;
        }

        // Create auth session
        // For existing users, store their client_key so we can use it in the callback
        const session = await createAuthSession(c.env.DB, {
            userId,
            clientKey: body.clientKey,  // Only used for existing users
        });

        // Initialize SSE state in KV
        await updateSessionStateInKV(c.env.KV, session.code, 'pending');

        // Build response URLs
        const baseUrl = getBaseUrl(c);
        const authUrl = `${baseUrl}/auth/link/${session.code}`;
        const sseUrl = `${baseUrl}/auth/sse/${session.code}`;

        // Return typed response (toJson converts to snake_case for JSON)
        const response = createResponse(AuthStartResponseSchema, {
            code: session.code,
            url: authUrl,
            sseUrl: sseUrl,
            expiresInSeconds: SESSION_EXPIRATION_SECONDS,
        });

        return c.json(response);
    }
);

/**
 * GET /auth/link/:code
 *
 * User visits this URL to start the Discord OAuth flow.
 * Redirects to Discord OAuth with PKCE.
 */
auth.get('/link/:code', async (c) => {
    const code = c.req.param('code');

    // Get the session
    const session = await getAuthSession(c.env.DB, code);
    if (!session) {
        return c.html(renderErrorPage('Link not found'), 404);
    }

    // Check expiration
    if (session.expiresAt < Date.now()) {
        return c.html(renderErrorPage('This link has expired. Please start over.'), 410);
    }

    // Check state is pending (prevent reuse)
    if (session.state !== 'pending') {
        return c.html(renderErrorPage('This link has already been used.'), 400);
    }

    // Update state to 'started' in both DB and KV
    await updateAuthSessionState(c.env.DB, code, 'started');
    await updateSessionStateInKV(c.env.KV, code, 'started');

    // Generate PKCE code challenge from verifier
    const codeChallenge = await generatePkceCodeChallenge(session.codeVerifier);

    // Build Discord OAuth URL
    const params = new URLSearchParams({
        client_id: c.env.DISCORD_CLIENT_ID,
        redirect_uri: c.env.DISCORD_REDIRECT_URI,
        response_type: 'code',
        scope: 'identify sdk.social_layer_presence',
        state: code,  // Our session code links callback back to session
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
    });

    return c.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

/**
 * GET /auth/callback
 *
 * Discord redirects here after user authorization.
 * Exchanges code for tokens and completes the auth flow.
 */
auth.get('/callback', async (c) => {
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

        // Update KV state for SSE
        await updateSessionStateInKV(c.env.KV, state, 'completed');

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
        await updateSessionStateInKV(c.env.KV, state, 'failed');

        if (err instanceof DiscordApiError) {
            return c.html(
                renderErrorPage(`Discord API error. Please try again.`),
                502
            );
        }

        return c.html(renderErrorPage('An error occurred. Please try again.'), 500);
    }
});

/**
 * Render an error page HTML.
 */
function renderErrorPage(message: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Studio Rich Presence</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 400px;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: #ff6b6b;
        }
        p {
            color: #a0aec0;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>Something went wrong</h1>
        <p>${escapeHtml(message)}</p>
    </div>
</body>
</html>`;
}

/**
 * Render a success page HTML with completion code.
 */
function renderSuccessPage(completionCode: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Success - Studio Rich Presence</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 400px;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
            color: #4ade80;
        }
        .subtitle {
            color: #a0aec0;
            margin-bottom: 2rem;
        }
        .code-container {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        .code-label {
            font-size: 0.875rem;
            color: #a0aec0;
            margin-bottom: 0.5rem;
        }
        .code {
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 3rem;
            font-weight: bold;
            letter-spacing: 0.5rem;
            color: #fff;
        }
        .hint {
            font-size: 0.875rem;
            color: #64748b;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h1>Discord Connected!</h1>
        <p class="subtitle">Enter this code in the plugin to complete setup</p>
        <div class="code-container">
            <div class="code-label">Your code</div>
            <div class="code">${escapeHtml(completionCode)}</div>
        </div>
        <p class="hint">If SSE is working, the plugin will detect completion automatically.</p>
    </div>
</body>
</html>`;
}

/**
 * Escape HTML special characters to prevent XSS.
 */
function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

export { auth };
