/**
 * Token generation utilities.
 *
 * Uses crypto.getRandomValues for cryptographically secure random generation.
 */

import { base64urlEncode } from './base64url';
import { CryptoValidationError, validatePositiveInt, validateToken } from './validation';

/**
 * Maximum token size in bytes (256 bytes = 2048 bits).
 * This is generous - typical tokens are 32 bytes.
 */
const MAX_TOKEN_BYTES = 256;

/**
 * Generate a cryptographically secure random token.
 *
 * @param bytes Number of random bytes (default 32 = 256 bits)
 * @returns Base64url-encoded token string
 * @throws CryptoValidationError if bytes is invalid
 *
 * @example
 * const authToken = generateToken(32);  // 256-bit token
 * const clientKey = generateToken(32);  // 256-bit key
 */
export function generateToken(bytes: number = 32): string {
    validatePositiveInt(bytes, 'bytes', MAX_TOKEN_BYTES);

    const buffer = new Uint8Array(bytes);
    crypto.getRandomValues(buffer);
    return base64urlEncode(buffer);
}

/**
 * Generate a random session code for auth URLs.
 *
 * Uses 32 bytes (256 bits) of randomness, making brute-force impossible.
 *
 * @returns URL-safe session code
 */
export function generateSessionCode(): string {
    return generateToken(32);
}

/**
 * Generate a client encryption key.
 *
 * This key is stored in the plugin and combined with the server secret
 * for zero-knowledge encryption of Discord tokens.
 *
 * @returns 32-byte (256-bit) base64url-encoded key
 */
export function generateClientKey(): string {
    return generateToken(32);
}

/**
 * Generate a 5-digit completion code for manual auth entry.
 *
 * This is shown to the user on the success page and entered in the plugin
 * as a fallback when SSE fails.
 *
 * Note: This is NOT the primary security mechanism - the session code is.
 * This just confirms the user completed the right flow.
 *
 * @returns 5-digit string (e.g., "12345")
 */
export function generateCompletionCode(): string {
    // Generate a random number between 10000 and 99999
    const buffer = new Uint8Array(4);
    crypto.getRandomValues(buffer);

    // Convert to number and take modulo to get 5 digits
    const view = new DataView(buffer.buffer);
    const randomNum = view.getUint32(0, true);
    const code = 10000 + (randomNum % 90000);

    return code.toString();
}

/**
 * Generate a PKCE code verifier for OAuth.
 *
 * Per RFC 7636, code verifier should be 43-128 characters.
 * We use 32 bytes = 43 base64url characters.
 *
 * @returns Base64url-encoded code verifier
 */
export function generatePkceCodeVerifier(): string {
    return generateToken(32);
}

/**
 * Generate a PKCE code challenge from a code verifier.
 *
 * The challenge is SHA-256(verifier), base64url-encoded.
 * Per RFC 7636, this must be plain SHA-256 (no HMAC).
 *
 * @param codeVerifier The code verifier to hash
 * @returns Base64url-encoded SHA-256 hash
 * @throws CryptoValidationError if codeVerifier is invalid
 */
export async function generatePkceCodeChallenge(codeVerifier: string): Promise<string> {
    validateToken(codeVerifier, 'codeVerifier');

    // RFC 7636 requires minimum 43 characters
    if (codeVerifier.length < 43) {
        throw new CryptoValidationError(
            'PKCE code verifier must be at least 43 characters'
        );
    }

    // RFC 7636 requires maximum 128 characters
    if (codeVerifier.length > 128) {
        throw new CryptoValidationError(
            'PKCE code verifier must be at most 128 characters'
        );
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return base64urlEncode(new Uint8Array(hashBuffer));
}

/**
 * Generate a UUID v4.
 *
 * Uses crypto.randomUUID() which is available in Cloudflare Workers.
 *
 * @returns UUID v4 string (e.g., "550e8400-e29b-41d4-a716-446655440000")
 */
export function generateUuid(): string {
    return crypto.randomUUID();
}
