/**
 * Auth session service for managing OAuth flow sessions.
 */

import {
    generateSessionCode,
    generateClientKey,
    generateCompletionCode,
    generatePkceCodeVerifier,
} from '../crypto';
import type { DbAuthSession } from '../env';

export type AuthSessionState = 'pending' | 'started' | 'completed' | 'failed';

export interface CreateAuthSessionOptions {
    /** User ID if linking to existing user */
    userId?: string;
    /** Session expiration in seconds (default 300 = 5 minutes) */
    expiresInSeconds?: number;
}

export interface CreateAuthSessionResult {
    /** Session code (primary key, used in URLs and SSE) */
    code: string;
    /** PKCE code verifier for OAuth */
    codeVerifier: string;
    /** 5-digit completion code */
    completionCode: string;
    /** Client key (only for new users) */
    clientKey?: string;
    /** Expiration timestamp */
    expiresAt: number;
}

/**
 * Auth session as returned by queries.
 */
export interface AuthSession {
    code: string;
    userId: string | null;
    state: AuthSessionState;
    completionCode: string | null;
    codeVerifier: string;
    resultToken: string | null;
    resultClientKey: string | null;
    errorMessage: string | null;
    expiresAt: number;
    createdAt: number;
}

export const SESSION_EXPIRATION_SECONDS = 300; // 5 minutes

/**
 * Create a new auth session.
 *
 * @param db D1Database binding
 * @param options Session options
 * @returns Created session details
 */
export async function createAuthSession(
    db: D1Database,
    options: CreateAuthSessionOptions = {}
): Promise<CreateAuthSessionResult> {
    const { userId, expiresInSeconds = SESSION_EXPIRATION_SECONDS } = options;

    const code = generateSessionCode();
    const codeVerifier = generatePkceCodeVerifier();
    const completionCode = generateCompletionCode();
    const now = Date.now();
    const expiresAt = now + expiresInSeconds * 1000;

    // Generate client key only for new users (no userId)
    const clientKey = userId ? undefined : generateClientKey();

    await db.prepare(`
        INSERT INTO auth_sessions (
            code, user_id, state, completion_code,
            pkce_code_verifier, result_client_key,
            expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        code,
        userId ?? null,
        'pending',
        completionCode,
        codeVerifier,
        clientKey ?? null, // Store client key for new users
        expiresAt,
        now
    ).run();

    return {
        code,
        codeVerifier,
        completionCode,
        clientKey,
        expiresAt,
    };
}

/**
 * Get an auth session by code.
 */
export async function getAuthSession(
    db: D1Database,
    code: string
): Promise<AuthSession | null> {
    const result = await db.prepare(`
        SELECT * FROM auth_sessions WHERE code = ?
    `).bind(code).first<DbAuthSession>();

    if (!result) return null;

    return mapDbSession(result);
}

/**
 * Update an auth session's state.
 */
export async function updateAuthSessionState(
    db: D1Database,
    code: string,
    state: AuthSessionState,
    errorMessage?: string
): Promise<boolean> {
    const result = await db.prepare(`
        UPDATE auth_sessions
        SET state = ?, error_message = ?
        WHERE code = ?
    `).bind(state, errorMessage ?? null, code).run();

    return (result.meta.changes ?? 0) > 0;
}

/**
 * Set the result for a completed auth session.
 */
export async function setAuthSessionResult(
    db: D1Database,
    code: string,
    resultToken: string,
    resultClientKey?: string
): Promise<boolean> {
    const result = await db.prepare(`
        UPDATE auth_sessions
        SET state = 'completed', result_token = ?, result_client_key = COALESCE(?, result_client_key)
        WHERE code = ?
    `).bind(resultToken, resultClientKey ?? null, code).run();

    return (result.meta.changes ?? 0) > 0;
}

/**
 * Check if an auth session is valid (exists and not expired).
 */
export async function isAuthSessionValid(
    db: D1Database,
    code: string
): Promise<boolean> {
    const session = await getAuthSession(db, code);
    if (!session) return false;

    const now = Date.now();
    return session.expiresAt > now;
}

/**
 * Delete an auth session.
 */
export async function deleteAuthSession(
    db: D1Database,
    code: string
): Promise<boolean> {
    const result = await db.prepare(`
        DELETE FROM auth_sessions WHERE code = ?
    `).bind(code).run();

    return (result.meta.changes ?? 0) > 0;
}

/**
 * Map database row to AuthSession interface.
 */
function mapDbSession(row: DbAuthSession): AuthSession {
    return {
        code: row.code,
        userId: row.user_id,
        state: row.state,
        completionCode: row.completion_code,
        codeVerifier: row.pkce_code_verifier,
        resultToken: row.result_token,
        resultClientKey: row.result_client_key,
        errorMessage: row.error_message,
        expiresAt: row.expires_at,
        createdAt: row.created_at,
    };
}

/**
 * Update KV with session state for SSE polling.
 *
 * @param kv KV namespace binding
 * @param code Session code
 * @param state Session state
 * @param ttlSeconds TTL for the KV entry
 */
export async function updateSessionStateInKV(
    kv: KVNamespace,
    code: string,
    state: AuthSessionState,
    ttlSeconds: number = SESSION_EXPIRATION_SECONDS
): Promise<void> {
    const kvKey = `sse:${code}`;
    await kv.put(kvKey, JSON.stringify({
        state,
        updatedAt: Date.now(),
    }), {
        expirationTtl: ttlSeconds,
    });
}

/**
 * Get session state from KV for SSE.
 */
export async function getSessionStateFromKV(
    kv: KVNamespace,
    code: string
): Promise<{ state: AuthSessionState; updatedAt: number } | null> {
    const kvKey = `sse:${code}`;
    const data = await kv.get(kvKey);
    if (!data) return null;

    try {
        return JSON.parse(data);
    } catch {
        return null;
    }
}

