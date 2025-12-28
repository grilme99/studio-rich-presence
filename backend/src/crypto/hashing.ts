/**
 * Hashing utilities for tokens and identifiers.
 *
 * Uses HMAC-SHA256 via Web Crypto API for keyed hashing.
 * This prevents rainbow table attacks and provides domain separation.
 */

import { base64urlEncode, base64urlDecode } from './base64url';
import {
    CryptoValidationError,
    validateToken,
    validateSecret,
    validateNonEmptyString,
    validateBase64url,
    validateUint8Array,
} from './validation';

/**
 * HMAC-SHA256 key import helper.
 */
async function importHmacKey(keyMaterial: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        'raw',
        keyMaterial,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
}

/**
 * Compute HMAC-SHA256.
 */
async function hmacSha256(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
    const signature = await crypto.subtle.sign('HMAC', key, data);
    return new Uint8Array(signature);
}

/**
 * Length-prefix a string to prevent concatenation attacks.
 *
 * Format: 4-byte big-endian length + UTF-8 encoded string
 * This ensures "ab" + "cd" !== "a" + "bcd"
 */
function lengthPrefix(str: string): Uint8Array {
    const encoder = new TextEncoder();
    const strBytes = encoder.encode(str);
    const result = new Uint8Array(4 + strBytes.length);

    // Write 4-byte big-endian length
    const view = new DataView(result.buffer);
    view.setUint32(0, strBytes.length, false); // big-endian

    // Write string bytes
    result.set(strBytes, 4);

    return result;
}

/**
 * Combine multiple inputs with length-prefixing.
 * Prevents concatenation attacks where inputs could be shifted.
 */
function combineWithLengthPrefix(...inputs: string[]): Uint8Array {
    const prefixed = inputs.map(lengthPrefix);
    const totalLength = prefixed.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);

    let offset = 0;
    for (const arr of prefixed) {
        result.set(arr, offset);
        offset += arr.length;
    }

    return result;
}

/**
 * Hash an auth token using HMAC-SHA256 with per-hash salt.
 *
 * Format: salt (16 bytes) || HMAC-SHA256(pepper, salt || token)
 *
 * The salt is randomly generated per token and stored with the hash.
 * The pepper is the server's ENCRYPTION_KEY (acts as HMAC key).
 *
 * @param token The plaintext token to hash
 * @param pepper The server's ENCRYPTION_KEY (used as HMAC key)
 * @returns Base64url-encoded string: salt || mac
 * @throws CryptoValidationError if inputs are invalid
 */
export async function hashToken(token: string, pepper: string): Promise<string> {
    validateToken(token, 'token');
    validateSecret(pepper, 'pepper');

    const encoder = new TextEncoder();

    // Generate random 16-byte salt
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // Create HMAC key from pepper
    const hmacKey = await importHmacKey(encoder.encode(pepper));

    // HMAC over length-prefixed salt and token
    // This prevents any concatenation attacks
    const dataToHash = combineWithLengthPrefix(
        base64urlEncode(salt), // Include salt in HMAC input
        token
    );

    const mac = await hmacSha256(hmacKey, dataToHash);

    // Combine salt + mac for storage
    const result = new Uint8Array(salt.length + mac.length);
    result.set(salt, 0);
    result.set(mac, salt.length);

    return base64urlEncode(result);
}

/**
 * Verify a token against its stored hash.
 *
 * Uses constant-time comparison to prevent timing attacks.
 *
 * @param providedToken The token provided by the client
 * @param storedHash The hash stored in the database
 * @param pepper The server's ENCRYPTION_KEY (used as HMAC key)
 * @returns true if the token matches the hash
 * @throws CryptoValidationError if inputs are invalid
 */
export async function verifyToken(
    providedToken: string,
    storedHash: string,
    pepper: string
): Promise<boolean> {
    validateToken(providedToken, 'providedToken');
    validateBase64url(storedHash, 'storedHash');
    validateSecret(pepper, 'pepper');

    const encoder = new TextEncoder();

    // Decode stored hash to extract salt and expected MAC
    const combined = base64urlDecode(storedHash);

    // Validate length (16 bytes salt + 32 bytes MAC = 48 bytes)
    // Use constant-time length check
    const expectedLength = 48;
    const lengthOk = constantTimeCompareNumbers(combined.length, expectedLength);

    // Even if length is wrong, continue with dummy values to avoid timing leak
    const salt = combined.length >= 16
        ? combined.slice(0, 16)
        : new Uint8Array(16);
    const expectedMac = combined.length >= 48
        ? combined.slice(16, 48)
        : new Uint8Array(32);

    // Compute MAC for provided token with extracted salt
    const hmacKey = await importHmacKey(encoder.encode(pepper));
    const dataToHash = combineWithLengthPrefix(
        base64urlEncode(salt),
        providedToken
    );
    const computedMac = await hmacSha256(hmacKey, dataToHash);

    // Constant-time comparison of MACs
    const macOk = constantTimeEqualBytes(computedMac, expectedMac);

    // Both length and MAC must be correct
    // Use bitwise AND to combine without branching
    return lengthOk && macOk;
}

/**
 * Hash a Discord user ID with HMAC-SHA256.
 *
 * Uses the salt as the HMAC key (not concatenation).
 * This provides proper domain separation and prevents rainbow tables.
 *
 * @param discordUserId The Discord user ID (snowflake string)
 * @param salt The DISCORD_ID_SALT secret from environment
 * @returns Base64url-encoded HMAC-SHA256
 * @throws CryptoValidationError if inputs are invalid
 */
export async function hashDiscordId(discordUserId: string, salt: string): Promise<string> {
    validateNonEmptyString(discordUserId, 'discordUserId');
    validateSecret(salt, 'salt');

    // Discord snowflakes are 17-19 digit strings
    if (!/^\d{17,19}$/.test(discordUserId)) {
        throw new CryptoValidationError(
            'discordUserId must be a valid Discord snowflake (17-19 digits)'
        );
    }

    const encoder = new TextEncoder();

    // Use salt as HMAC key (proper keyed hash)
    const hmacKey = await importHmacKey(encoder.encode(salt));

    // HMAC the Discord user ID with a domain separator
    const dataToHash = combineWithLengthPrefix(
        'discord-user-id-v1', // Domain separator/version tag
        discordUserId
    );

    const mac = await hmacSha256(hmacKey, dataToHash);
    return base64urlEncode(mac);
}

/**
 * Constant-time comparison for two numbers.
 *
 * Returns true only if a === b, without leaking which one is larger.
 */
function constantTimeCompareNumbers(a: number, b: number): boolean {
    // XOR is 0 only if equal, then check if result is 0
    // This avoids branching based on the comparison result
    return ((a ^ b) | 0) === 0;
}

/**
 * Constant-time comparison for Uint8Array.
 *
 * CRITICAL: This function MUST:
 * 1. Always iterate the full length of the longer array
 * 2. Never return early
 * 3. Accumulate all differences before making the final decision
 *
 * @param a First array
 * @param b Second array
 * @returns true if arrays are equal
 * @throws CryptoValidationError if inputs are invalid
 */
export function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
    validateUint8Array(a, 'a');
    validateUint8Array(b, 'b');

    // Accumulate differences - will be non-zero if any byte differs
    let diff = 0;

    // XOR the lengths - non-zero if different
    // This contributes to diff without early return
    diff |= a.length ^ b.length;

    // Iterate over the longer array
    // We use Math.max but still access both arrays safely
    const maxLen = Math.max(a.length, b.length);

    for (let i = 0; i < maxLen; i++) {
        // Safe access: if index out of bounds, use 0
        // The length difference is already captured in diff
        const byteA = i < a.length ? (a[i] ?? 0) : 0;
        const byteB = i < b.length ? (b[i] ?? 0) : 0;
        diff |= byteA ^ byteB;
    }

    // Only return at the very end
    // Convert diff to boolean: 0 means equal
    return diff === 0;
}

/**
 * Constant-time string comparison.
 *
 * Converts to bytes and uses constantTimeEqualBytes.
 *
 * @param a First string
 * @param b Second string
 * @returns true if strings are equal
 * @throws CryptoValidationError if inputs are invalid
 */
export function constantTimeEqual(a: string, b: string): boolean {
    validateNonEmptyString(a, 'a');
    validateNonEmptyString(b, 'b');

    const encoder = new TextEncoder();
    return constantTimeEqualBytes(encoder.encode(a), encoder.encode(b));
}
