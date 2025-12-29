/**
 * User service for authentication and user management.
 */

import { hashAuthToken, generateToken, generateUuid } from '../crypto';
import type { DbUser } from '../env';

/**
 * Result of authenticating a user by token.
 */
export interface AuthResult {
    success: boolean;
    user?: DbUser;
    error?: string;
}

/**
 * Find a user by their auth token.
 *
 * Uses direct hash lookup for O(1) authentication.
 * Checks both active and pending token hashes.
 * Updates last_activity_at on successful auth.
 *
 * @param db D1Database binding
 * @param token The auth token provided by the client
 * @param pepper The ENCRYPTION_KEY secret for token verification
 * @returns AuthResult with user if found
 */
export async function authenticateUser(
    db: D1Database,
    token: string,
    pepper: string
): Promise<AuthResult> {
    if (!token || typeof token !== 'string') {
        return { success: false, error: 'Missing auth token' };
    }

    // Compute the deterministic hash for direct lookup
    const tokenHash = await hashAuthToken(token, pepper);

    // First, try to find by active token hash (most common case)
    const userByActiveToken = await db.prepare(`
        SELECT * FROM users WHERE auth_token_hash = ?
    `).bind(tokenHash).first<DbUser>();

    if (userByActiveToken) {
        await updateLastActivity(db, userByActiveToken.id);
        return { success: true, user: userByActiveToken };
    }

    // Check pending token hash (for token rotation)
    const now = Date.now();
    const userByPendingToken = await db.prepare(`
        SELECT * FROM users 
        WHERE pending_token_hash = ? 
        AND pending_token_expires > ?
    `).bind(tokenHash, now).first<DbUser>();

    if (userByPendingToken) {
        await updateLastActivity(db, userByPendingToken.id);
        return { success: true, user: userByPendingToken };
    }

    return { success: false, error: 'Invalid auth token' };
}

/**
 * Update a user's last activity timestamp.
 */
async function updateLastActivity(db: D1Database, userId: string): Promise<void> {
    const now = Date.now();
    await db.prepare(`
        UPDATE users SET last_activity_at = ?, updated_at = ?
        WHERE id = ?
    `).bind(now, now, userId).run();
}

/**
 * Get a user by ID.
 */
export async function getUserById(
    db: D1Database,
    userId: string
): Promise<DbUser | null> {
    const result = await db.prepare(`
        SELECT * FROM users WHERE id = ?
    `).bind(userId).first<DbUser>();

    return result ?? null;
}

/**
 * Result of creating a new user.
 */
export interface CreateUserResult {
    user: DbUser;
    authToken: string;  // Plaintext token (only returned once)
}

/**
 * Create a new user.
 *
 * @param db D1Database binding
 * @param pepper The ENCRYPTION_KEY secret for token hashing
 * @returns New user and the plaintext auth token (only returned once)
 */
export async function createUser(
    db: D1Database,
    pepper: string
): Promise<CreateUserResult> {
    const userId = generateUuid();
    const authToken = generateToken();
    const tokenHash = await hashAuthToken(authToken, pepper);
    const now = Date.now();

    await db.prepare(`
        INSERT INTO users (id, auth_token_hash, created_at, updated_at, last_activity_at)
        VALUES (?, ?, ?, ?, ?)
    `).bind(userId, tokenHash, now, now, now).run();

    const user: DbUser = {
        id: userId,
        auth_token_hash: tokenHash,
        pending_token_hash: null,
        pending_token_expires: null,
        created_at: now,
        updated_at: now,
        last_activity_at: now,
    };

    return { user, authToken };
}

/**
 * Delete a user and all associated data.
 * Due to CASCADE, this also deletes discord_accounts and auth_sessions.
 */
export async function deleteUser(
    db: D1Database,
    userId: string
): Promise<boolean> {
    const result = await db.prepare(`
        DELETE FROM users WHERE id = ?
    `).bind(userId).run();

    return (result.meta.changes ?? 0) > 0;
}

