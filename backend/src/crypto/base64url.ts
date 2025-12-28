/**
 * Base64url encoding/decoding utilities.
 *
 * Base64url is URL-safe variant of base64:
 * - Uses '-' instead of '+'
 * - Uses '_' instead of '/'
 * - No padding ('=')
 */

import {
    CryptoValidationError,
    validateUint8Array,
    validateString,
    MAX_STRING_LENGTH,
} from './validation';

/**
 * Maximum encoded string length to prevent DoS.
 */
const MAX_ENCODED_LENGTH = MAX_STRING_LENGTH;

/**
 * Encode a Uint8Array to base64url string.
 *
 * @param data The bytes to encode
 * @returns Base64url-encoded string
 * @throws CryptoValidationError if input is invalid
 */
export function base64urlEncode(data: Uint8Array): string {
    validateUint8Array(data, 'data');

    if (data.length === 0) {
        return '';
    }

    // Prevent encoding extremely large data
    if (data.length > MAX_ENCODED_LENGTH) {
        throw new CryptoValidationError(
            `Data exceeds maximum length of ${MAX_ENCODED_LENGTH} bytes`
        );
    }

    // Convert to regular base64
    const base64 = btoa(String.fromCharCode(...data));

    // Convert to base64url (URL-safe)
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, ''); // Remove padding
}

/**
 * Decode a base64url string to Uint8Array.
 *
 * @param str The base64url string to decode
 * @returns Decoded bytes
 * @throws CryptoValidationError if input is invalid
 */
export function base64urlDecode(str: string): Uint8Array {
    validateString(str, 'str');

    if (str.length === 0) {
        return new Uint8Array(0);
    }

    if (str.length > MAX_ENCODED_LENGTH) {
        throw new CryptoValidationError(
            `String exceeds maximum length of ${MAX_ENCODED_LENGTH} characters`
        );
    }

    // Validate base64url characters
    const base64urlRegex = /^[A-Za-z0-9_-]*$/;
    if (!base64urlRegex.test(str)) {
        throw new CryptoValidationError('String contains invalid base64url characters');
    }

    // Add padding back if needed
    const paddingNeeded = (4 - (str.length % 4)) % 4;
    const padded = str + '='.repeat(paddingNeeded);

    // Convert from base64url to regular base64
    const base64 = padded
        .replace(/-/g, '+')
        .replace(/_/g, '/');

    // Decode
    let binary: string;
    try {
        binary = atob(base64);
    } catch {
        throw new CryptoValidationError('Invalid base64url encoding');
    }

    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Encode a string to base64url.
 *
 * @param str The string to encode
 * @returns Base64url-encoded string
 * @throws CryptoValidationError if input is invalid
 */
export function stringToBase64url(str: string): string {
    validateString(str, 'str');

    if (str.length > MAX_ENCODED_LENGTH) {
        throw new CryptoValidationError(
            `String exceeds maximum length of ${MAX_ENCODED_LENGTH} characters`
        );
    }

    const encoder = new TextEncoder();
    return base64urlEncode(encoder.encode(str));
}

/**
 * Decode a base64url string to string.
 *
 * @param base64url The base64url string to decode
 * @returns Decoded string
 * @throws CryptoValidationError if input is invalid
 */
export function base64urlToString(base64url: string): string {
    const decoder = new TextDecoder();
    return decoder.decode(base64urlDecode(base64url));
}
