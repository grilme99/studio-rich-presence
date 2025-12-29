/**
 * Discord API service for OAuth token exchange and API interactions.
 */

/**
 * Discord OAuth token response.
 */
export interface DiscordTokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    scope: string;
}

/**
 * Discord user from /users/@me endpoint.
 * We only need the ID for deduplication (not stored).
 */
export interface DiscordUser {
    id: string;
    username: string;
    discriminator: string;
    avatar: string | null;
    global_name: string | null;
}

/**
 * Error thrown when Discord API call fails.
 */
export class DiscordApiError extends Error {
    constructor(
        public readonly status: number,
        public readonly body: unknown,
        message: string
    ) {
        super(message);
        this.name = 'DiscordApiError';
    }
}

/**
 * Exchange Discord authorization code for tokens.
 *
 * @param code Discord authorization code from OAuth callback
 * @param codeVerifier PKCE code verifier from auth session
 * @param clientId Discord app client ID
 * @param clientSecret Discord app client secret
 * @param redirectUri OAuth redirect URI
 * @returns Discord token response
 */
export async function exchangeDiscordCode(
    code: string,
    codeVerifier: string,
    clientId: string,
    clientSecret: string,
    redirectUri: string
): Promise<DiscordTokenResponse> {
    const body = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
    });

    const response = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
    });

    if (!response.ok) {
        const errorBody = await response.json().catch(() => null);
        throw new DiscordApiError(
            response.status,
            errorBody,
            `Discord token exchange failed: ${response.status}`
        );
    }

    return response.json() as Promise<DiscordTokenResponse>;
}

/**
 * Fetch the authenticated user's information from Discord.
 *
 * Used to:
 * 1. Verify the token works
 * 2. Get user ID for deduplication (hashed, not stored)
 *
 * @param accessToken Discord OAuth access token
 * @returns Discord user object
 */
export async function fetchDiscordUser(accessToken: string): Promise<DiscordUser> {
    const response = await fetch('https://discord.com/api/users/@me', {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });

    if (!response.ok) {
        const errorBody = await response.json().catch(() => null);
        throw new DiscordApiError(
            response.status,
            errorBody,
            `Failed to fetch Discord user: ${response.status}`
        );
    }

    return response.json() as Promise<DiscordUser>;
}

/**
 * Refresh Discord OAuth tokens.
 *
 * @param refreshToken Discord refresh token
 * @param clientId Discord app client ID
 * @param clientSecret Discord app client secret
 * @returns New token response
 */
export async function refreshDiscordTokens(
    refreshToken: string,
    clientId: string,
    clientSecret: string
): Promise<DiscordTokenResponse> {
    const body = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
    });

    const response = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
    });

    if (!response.ok) {
        const errorBody = await response.json().catch(() => null);
        throw new DiscordApiError(
            response.status,
            errorBody,
            `Discord token refresh failed: ${response.status}`
        );
    }

    return response.json() as Promise<DiscordTokenResponse>;
}

