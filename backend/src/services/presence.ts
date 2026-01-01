/**
 * Discord presence service for updating rich presence via headless sessions.
 *
 * Discord's headless sessions API allows setting presence without a Gateway connection.
 * Sessions last 20 minutes and must be refreshed or recreated.
 *
 * Session tokens are cached in KV with a 19-minute TTL (slightly less than Discord's
 * 20-minute session lifetime) to enable transparent session reuse.
 *
 * @see https://docs.discord.food/resources/presence#create-headless-session
 */

import type { DiscordPresence } from '../generated/presence_pb';
import { DiscordApiError } from './discord';

/** Headless session TTL in seconds (19 minutes, slightly less than Discord's 20min) */
const HEADLESS_SESSION_TTL_SECONDS = 19 * 60;

/** KV key prefix for headless session tokens */
const SESSION_TOKEN_KEY_PREFIX = 'presence-session:';

/**
 * Discord activity type enum.
 */
export enum ActivityType {
    PLAYING = 0,
    STREAMING = 1,
    LISTENING = 2,
    WATCHING = 3,
    CUSTOM = 4,
    COMPETING = 5,
}

/**
 * Discord activity object for presence updates.
 */
export interface DiscordActivity {
    name: string;
    type: ActivityType;
    application_id: string;
    platform: string;
    details?: string | null;
    state?: string | null;
    timestamps?: {
        start?: number;
        end?: number;
    };
    assets?: {
        large_image?: string;
        large_text?: string;
        small_image?: string;
        small_text?: string;
    };
}

/**
 * Response from creating/updating a headless session.
 */
export interface HeadlessSessionResponse {
    activities: DiscordActivity[];
    token: string;
}

/**
 * Convert our protobuf presence to Discord activity format.
 *
 * @param presence The presence data from the client
 * @param applicationId The Discord application ID
 * @returns Discord activity object
 */
export function presenceToActivity(
    presence: DiscordPresence | undefined,
    applicationId: string
): DiscordActivity {
    const activity: DiscordActivity = {
        application_id: applicationId,
        platform: 'desktop',

        // id: 'custom_status',
        name: 'Roblox Studio 1',

        type: ActivityType.PLAYING,
        details: 'Roblox Studio 2',
        state: 'Roblox Studio 3',

        assets: {
            large_image: 'studio-logo',
            large_text: 'Editing in Roblox Studio',
            // large_url: 'https://srp.brooke.sh',
            small_image: 'studio-logo',
        },
    };

    // if (presence?.details) {
    //     activity.details = presence.details;
    // }

    // if (presence?.state) {
    //     activity.state = presence.state;
    // }

    // if (presence?.timestamps) {
    //     activity.timestamps = {};
    //     // Proto uses seconds, Discord uses milliseconds
    //     if (presence.timestamps.startUnix !== undefined) {
    //         activity.timestamps.start = Number(presence.timestamps.startUnix) * 1000;
    //     }
    //     if (presence.timestamps.endUnix !== undefined) {
    //         activity.timestamps.end = Number(presence.timestamps.endUnix) * 1000;
    //     }
    // }

    // if (presence?.assets) {
    //     activity.assets = {};
    //     if (presence.assets.largeImage) {
    //         activity.assets.large_image = presence.assets.largeImage;
    //     }
    //     if (presence.assets.largeText) {
    //         activity.assets.large_text = presence.assets.largeText;
    //     }
    //     if (presence.assets.smallImage) {
    //         activity.assets.small_image = presence.assets.smallImage;
    //     }
    //     if (presence.assets.smallText) {
    //         activity.assets.small_text = presence.assets.smallText;
    //     }
    // }

    return activity;
}

/**
 * Create or update a Discord headless session for presence.
 *
 * @param accessToken Discord OAuth access token with activities.write scope
 * @param activity The activity to set
 * @param sessionToken Optional existing session token for updates
 * @returns The session response with token for future updates
 */
export async function updateHeadlessSession(
    accessToken: string,
    activity: DiscordActivity,
    sessionToken?: string
): Promise<HeadlessSessionResponse> {
    const body: { activities: DiscordActivity[]; token?: string } = {
        activities: [activity],
    };

    if (sessionToken) {
        body.token = sessionToken;
    }

    const response = await fetch('https://discord.com/api/v10/users/@me/headless-sessions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
    });

    if (!response.ok) {
        const errorBody = await response.json().catch(() => null);
        throw new DiscordApiError(
            response.status,
            errorBody,
            `Failed to update headless session: ${response.status}`
        );
    }

    return response.json() as Promise<HeadlessSessionResponse>;
}

/**
 * Delete a Discord headless session.
 *
 * @param accessToken Discord OAuth access token with activities.write scope
 * @param sessionToken The session token to delete
 */
export async function deleteHeadlessSession(
    accessToken: string,
    sessionToken: string
): Promise<void> {
    const response = await fetch('https://discord.com/api/v10/users/@me/headless-sessions/delete', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token: sessionToken }),
    });

    if (!response.ok && response.status !== 204) {
        const errorBody = await response.json().catch(() => null);
        throw new DiscordApiError(
            response.status,
            errorBody,
            `Failed to delete headless session: ${response.status}`
        );
    }
}

/**
 * Result of updating presence for a single Discord account.
 */
export interface PresenceUpdateResult {
    accountId: string;
    success: boolean;
    error?: string;
    sessionToken?: string;
}

/**
 * Get KV key for a Discord account's headless session token.
 */
function getSessionTokenKey(discordAccountId: string): string {
    return `${SESSION_TOKEN_KEY_PREFIX}${discordAccountId}`;
}

/**
 * Get cached headless session token from KV.
 *
 * @param kv KV namespace
 * @param discordAccountId The Discord account ID
 * @returns The cached session token or null if not found/expired
 */
export async function getCachedSessionToken(
    kv: KVNamespace,
    discordAccountId: string
): Promise<string | null> {
    return kv.get(getSessionTokenKey(discordAccountId));
}

/**
 * Cache a headless session token in KV.
 *
 * @param kv KV namespace
 * @param discordAccountId The Discord account ID
 * @param sessionToken The session token to cache
 */
export async function cacheSessionToken(
    kv: KVNamespace,
    discordAccountId: string,
    sessionToken: string
): Promise<void> {
    await kv.put(
        getSessionTokenKey(discordAccountId),
        sessionToken,
        { expirationTtl: HEADLESS_SESSION_TTL_SECONDS }
    );
}

/**
 * Delete a cached headless session token from KV.
 *
 * @param kv KV namespace
 * @param discordAccountId The Discord account ID
 */
export async function deleteCachedSessionToken(
    kv: KVNamespace,
    discordAccountId: string
): Promise<void> {
    await kv.delete(getSessionTokenKey(discordAccountId));
}

