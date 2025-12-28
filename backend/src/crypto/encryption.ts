/**
 * Zero-knowledge encryption for Discord OAuth tokens.
 *
 * Discord tokens are encrypted using a key derived from BOTH:
 * 1. Server secret (ENCRYPTION_KEY) - stored in Cloudflare secrets
 * 2. Client key - stored in plugin settings, sent with each request
 *
 * This means:
 * - Database breach: Attacker cannot decrypt tokens (missing client key)
 * - Server compromise: Cannot decrypt tokens at rest (needs client key per-request)
 * - Client key loss: Tokens become permanently unrecoverable (user re-links)
 *
 * Uses HKDF for key derivation and AES-GCM for encryption.
 */

import { base64urlEncode, base64urlDecode } from './base64url';
import {
    CryptoValidationError,
    validateSecret,
    validateNonEmptyString,
    validateBase64url,
} from './validation';

/**
 * Minimum encrypted data length: 12 (IV) + 16 (auth tag) + 1 (ciphertext) = 29 bytes
 */
const MIN_ENCRYPTED_LENGTH = 29;

/**
 * Length-prefix a string to prevent concatenation attacks.
 *
 * Format: 4-byte big-endian length + UTF-8 encoded string
 */
function lengthPrefix(str: string): Uint8Array {
    const encoder = new TextEncoder();
    const strBytes = encoder.encode(str);
    const result = new Uint8Array(4 + strBytes.length);

    const view = new DataView(result.buffer);
    view.setUint32(0, strBytes.length, false);
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
 * Derive an encryption key from server secret and client key using HKDF.
 *
 * HKDF (HMAC-based Key Derivation Function) securely combines multiple
 * key materials into a single encryption key.
 *
 * Key combination strategy:
 * 1. Input Key Material (IKM): Length-prefixed combination of server + client keys
 *    This prevents "serverA" + "clientB" == "serverAc" + "lientB"
 * 2. Salt: User ID (provides domain separation per user)
 * 3. Info: Context string with version (allows future key rotation)
 *
 * @param serverSecret The ENCRYPTION_KEY from environment secrets
 * @param clientKey The client-provided key (stored in plugin)
 * @param userId The user ID (used as salt for domain separation)
 * @returns AES-GCM CryptoKey ready for encrypt/decrypt operations
 * @throws CryptoValidationError if inputs are invalid
 */
export async function deriveEncryptionKey(
    serverSecret: string,
    clientKey: string,
    userId: string
): Promise<CryptoKey> {
    validateSecret(serverSecret, 'serverSecret');
    validateSecret(clientKey, 'clientKey');
    validateNonEmptyString(userId, 'userId');

    const encoder = new TextEncoder();

    // Combine server secret and client key with length-prefixing
    // This prevents concatenation attacks where key boundaries could shift
    const combinedKeyMaterial = combineWithLengthPrefix(
        serverSecret,
        clientKey
    );

    // Import as raw key material for HKDF
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        combinedKeyMaterial,
        'HKDF',
        false,
        ['deriveKey']
    );

    // Derive an AES-GCM key using HKDF
    // Salt: length-prefixed user ID (prevents cross-user attacks)
    // Info: versioned context string (allows future algorithm changes)
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: lengthPrefix(userId),
            info: encoder.encode('discord-token-encryption-v1'),
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt a Discord OAuth token (or any string) using AES-GCM.
 *
 * AES-GCM provides both confidentiality and authenticity:
 * - Confidentiality: encrypted data cannot be read without the key
 * - Authenticity: any tampering is detected during decryption
 *
 * The IV (initialization vector) is randomly generated and prepended
 * to the ciphertext for storage.
 *
 * @param plaintext The token to encrypt
 * @param key The AES-GCM key from deriveEncryptionKey()
 * @returns Base64url-encoded string: IV (12 bytes) + ciphertext + auth tag
 * @throws CryptoValidationError if plaintext is invalid
 * @throws TypeError if key is invalid
 */
export async function encryptToken(plaintext: string, key: CryptoKey): Promise<string> {
    validateNonEmptyString(plaintext, 'plaintext');

    if (!(key instanceof CryptoKey)) {
        throw new CryptoValidationError('key must be a CryptoKey');
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    // Generate a random 12-byte IV (96 bits, recommended for AES-GCM)
    // CRITICAL: IV must never be reused with the same key
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt with AES-GCM (includes authentication tag automatically)
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
    );

    // Combine IV + ciphertext for storage
    // IV is not secret, but must be unique per encryption
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    return base64urlEncode(combined);
}

/**
 * Decrypt a Discord OAuth token (or any string) using AES-GCM.
 *
 * @param encrypted Base64url-encoded string from encryptToken()
 * @param key The AES-GCM key from deriveEncryptionKey()
 * @returns The decrypted plaintext
 * @throws CryptoValidationError if encrypted data is invalid
 * @throws Error if decryption fails (wrong key, corrupted data, or tampered)
 */
export async function decryptToken(encrypted: string, key: CryptoKey): Promise<string> {
    validateBase64url(encrypted, 'encrypted');

    if (!(key instanceof CryptoKey)) {
        throw new CryptoValidationError('key must be a CryptoKey');
    }

    const combined = base64urlDecode(encrypted);

    // Minimum length: 12 (IV) + 16 (auth tag) + 1 (at least 1 byte ciphertext) = 29
    if (combined.length < MIN_ENCRYPTED_LENGTH) {
        throw new CryptoValidationError(
            `Encrypted data too short: expected at least ${MIN_ENCRYPTED_LENGTH} bytes, got ${combined.length}`
        );
    }

    // Extract IV (first 12 bytes) and ciphertext (rest, includes auth tag)
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    // Decrypt with AES-GCM
    // This will throw if:
    // - Wrong key
    // - Data was tampered with (auth tag verification fails)
    // - Corrupted ciphertext
    let decrypted: ArrayBuffer;
    try {
        decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );
    } catch (error) {
        // Re-throw with more helpful message
        throw new CryptoValidationError(
            'Decryption failed: data may be corrupted or key may be incorrect'
        );
    }

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}

/**
 * Encrypt Discord OAuth tokens (access + refresh) together.
 *
 * Convenience function that encrypts both tokens with the same derived key.
 * Each token gets its own random IV, so they can be stored/updated independently.
 *
 * @param accessToken Discord OAuth access token
 * @param refreshToken Discord OAuth refresh token
 * @param key The AES-GCM key from deriveEncryptionKey()
 * @returns Object with encrypted versions of both tokens
 * @throws CryptoValidationError if tokens are invalid
 */
export async function encryptDiscordTokens(
    accessToken: string,
    refreshToken: string,
    key: CryptoKey
): Promise<{ accessTokenEnc: string; refreshTokenEnc: string }> {
    validateNonEmptyString(accessToken, 'accessToken');
    validateNonEmptyString(refreshToken, 'refreshToken');

    const [accessTokenEnc, refreshTokenEnc] = await Promise.all([
        encryptToken(accessToken, key),
        encryptToken(refreshToken, key),
    ]);

    return { accessTokenEnc, refreshTokenEnc };
}

/**
 * Decrypt Discord OAuth tokens (access + refresh) together.
 *
 * Convenience function that decrypts both tokens with the same derived key.
 *
 * @param accessTokenEnc Encrypted access token from database
 * @param refreshTokenEnc Encrypted refresh token from database
 * @param key The AES-GCM key from deriveEncryptionKey()
 * @returns Object with decrypted versions of both tokens
 * @throws CryptoValidationError if encrypted data is invalid
 * @throws Error if decryption fails
 */
export async function decryptDiscordTokens(
    accessTokenEnc: string,
    refreshTokenEnc: string,
    key: CryptoKey
): Promise<{ accessToken: string; refreshToken: string }> {
    validateBase64url(accessTokenEnc, 'accessTokenEnc');
    validateBase64url(refreshTokenEnc, 'refreshTokenEnc');

    const [accessToken, refreshToken] = await Promise.all([
        decryptToken(accessTokenEnc, key),
        decryptToken(refreshTokenEnc, key),
    ]);

    return { accessToken, refreshToken };
}

/**
 * Re-encrypt Discord tokens with a new derived key.
 *
 * This is used when refreshing tokens - we decrypt with the current key,
 * get new tokens from Discord, and re-encrypt with the same key.
 *
 * Note: The key should be the same (derived from same server+client keys).
 * This function is mainly for clarity in the codebase.
 *
 * @param newAccessToken New access token from Discord refresh
 * @param newRefreshToken New refresh token from Discord refresh
 * @param key The AES-GCM key (same as used for original encryption)
 * @returns Object with encrypted versions of new tokens
 */
export async function reencryptDiscordTokens(
    newAccessToken: string,
    newRefreshToken: string,
    key: CryptoKey
): Promise<{ accessTokenEnc: string; refreshTokenEnc: string }> {
    return encryptDiscordTokens(newAccessToken, newRefreshToken, key);
}
