/**
 * Discord account service for managing linked Discord accounts in the database.
 */

import { generateUuid } from '../crypto';
import type { DbDiscordAccount } from '../env';

/**
 * Discord account as returned by queries.
 */
export interface DiscordAccount {
    id: string;
    userId: string;
    discordUserIdHash: string;
    accessTokenEnc: string;
    refreshTokenEnc: string;
    tokenExpiresAt: number;
    createdAt: number;
    updatedAt: number;
}

/**
 * Options for creating a new Discord account link.
 */
export interface CreateDiscordAccountOptions {
    userId: string;
    discordUserIdHash: string;
    accessTokenEnc: string;
    refreshTokenEnc: string;
    tokenExpiresAt: number;
}

/**
 * Find a Discord account by its hashed Discord user ID.
 * This allows instant O(1) deduplication checks.
 */
export async function findDiscordAccountByHash(
    db: D1Database,
    discordUserIdHash: string
): Promise<DiscordAccount | null> {
    const result = await db.prepare(`
        SELECT * FROM discord_accounts WHERE discord_user_id_hash = ?
    `).bind(discordUserIdHash).first<DbDiscordAccount>();

    if (!result) return null;
    return mapDbAccount(result);
}

/**
 * Get all Discord accounts for a user.
 */
export async function getDiscordAccountsForUser(
    db: D1Database,
    userId: string
): Promise<DiscordAccount[]> {
    const result = await db.prepare(`
        SELECT * FROM discord_accounts WHERE user_id = ?
    `).bind(userId).all<DbDiscordAccount>();

    return result.results.map(mapDbAccount);
}

/**
 * Create a new Discord account link.
 */
export async function createDiscordAccount(
    db: D1Database,
    options: CreateDiscordAccountOptions
): Promise<DiscordAccount> {
    const id = generateUuid();
    const now = Date.now();

    await db.prepare(`
        INSERT INTO discord_accounts (
            id, user_id, discord_user_id_hash,
            access_token_enc, refresh_token_enc, token_expires_at,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        id,
        options.userId,
        options.discordUserIdHash,
        options.accessTokenEnc,
        options.refreshTokenEnc,
        options.tokenExpiresAt,
        now,
        now
    ).run();

    return {
        id,
        userId: options.userId,
        discordUserIdHash: options.discordUserIdHash,
        accessTokenEnc: options.accessTokenEnc,
        refreshTokenEnc: options.refreshTokenEnc,
        tokenExpiresAt: options.tokenExpiresAt,
        createdAt: now,
        updatedAt: now,
    };
}

/**
 * Update an existing Discord account's tokens.
 */
export async function updateDiscordAccountTokens(
    db: D1Database,
    id: string,
    accessTokenEnc: string,
    refreshTokenEnc: string,
    tokenExpiresAt: number
): Promise<boolean> {
    const now = Date.now();

    const result = await db.prepare(`
        UPDATE discord_accounts
        SET access_token_enc = ?, refresh_token_enc = ?, token_expires_at = ?, updated_at = ?
        WHERE id = ?
    `).bind(accessTokenEnc, refreshTokenEnc, tokenExpiresAt, now, id).run();

    return (result.meta.changes ?? 0) > 0;
}

/**
 * Delete a Discord account by ID.
 */
export async function deleteDiscordAccount(
    db: D1Database,
    id: string
): Promise<boolean> {
    const result = await db.prepare(`
        DELETE FROM discord_accounts WHERE id = ?
    `).bind(id).run();

    return (result.meta.changes ?? 0) > 0;
}

/**
 * Delete all Discord accounts for a user.
 */
export async function deleteAllDiscordAccountsForUser(
    db: D1Database,
    userId: string
): Promise<number> {
    const result = await db.prepare(`
        DELETE FROM discord_accounts WHERE user_id = ?
    `).bind(userId).run();

    return result.meta.changes ?? 0;
}

/**
 * Map database row to DiscordAccount interface.
 */
function mapDbAccount(row: DbDiscordAccount): DiscordAccount {
    return {
        id: row.id,
        userId: row.user_id,
        discordUserIdHash: row.discord_user_id_hash,
        accessTokenEnc: row.access_token_enc,
        refreshTokenEnc: row.refresh_token_enc,
        tokenExpiresAt: row.token_expires_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}

