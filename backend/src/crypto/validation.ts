/**
 * Input validation utilities for crypto functions.
 *
 * Validates inputs to prevent:
 * - Type confusion attacks
 * - DoS via oversized inputs
 * - Null/undefined handling issues
 */

/**
 * Maximum allowed string length (1MB) to prevent DoS.
 */
export const MAX_STRING_LENGTH = 1024 * 1024;

/**
 * Maximum allowed token/key length (1KB) - tokens should be much smaller.
 */
export const MAX_TOKEN_LENGTH = 1024;

/**
 * Minimum pepper/salt length (16 bytes = 128 bits).
 */
export const MIN_SECRET_LENGTH = 16;

/**
 * Error thrown when input validation fails.
 */
export class CryptoValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'CryptoValidationError';
    }
}

/**
 * Validate that a value is a non-empty string.
 */
export function validateString(value: unknown, name: string): string {
    if (typeof value !== 'string') {
        throw new CryptoValidationError(`${name} must be a string, got ${typeof value}`);
    }
    return value;
}

/**
 * Validate that a string is non-empty and within length limits.
 */
export function validateNonEmptyString(
    value: unknown,
    name: string,
    maxLength: number = MAX_STRING_LENGTH
): string {
    const str = validateString(value, name);

    if (str.length === 0) {
        throw new CryptoValidationError(`${name} must not be empty`);
    }

    if (str.length > maxLength) {
        throw new CryptoValidationError(
            `${name} exceeds maximum length of ${maxLength} characters`
        );
    }

    return str;
}

/**
 * Validate a token or key string.
 */
export function validateToken(value: unknown, name: string): string {
    return validateNonEmptyString(value, name, MAX_TOKEN_LENGTH);
}

/**
 * Validate a secret (pepper, salt, encryption key).
 * Must be non-empty and at least MIN_SECRET_LENGTH characters.
 */
export function validateSecret(value: unknown, name: string): string {
    const str = validateNonEmptyString(value, name, MAX_STRING_LENGTH);

    if (str.length < MIN_SECRET_LENGTH) {
        throw new CryptoValidationError(
            `${name} must be at least ${MIN_SECRET_LENGTH} characters`
        );
    }

    return str;
}

/**
 * Validate a positive integer.
 */
export function validatePositiveInt(value: unknown, name: string, max?: number): number {
    if (typeof value !== 'number' || !Number.isInteger(value)) {
        throw new CryptoValidationError(`${name} must be an integer, got ${typeof value}`);
    }

    if (value <= 0) {
        throw new CryptoValidationError(`${name} must be positive, got ${value}`);
    }

    if (max !== undefined && value > max) {
        throw new CryptoValidationError(`${name} exceeds maximum of ${max}, got ${value}`);
    }

    return value;
}

/**
 * Validate a base64url encoded string.
 * Checks that the string only contains valid base64url characters.
 */
export function validateBase64url(value: unknown, name: string): string {
    const str = validateNonEmptyString(value, name, MAX_STRING_LENGTH);

    // Base64url alphabet: A-Z, a-z, 0-9, -, _
    // No padding (=) in base64url
    const base64urlRegex = /^[A-Za-z0-9_-]+$/;

    if (!base64urlRegex.test(str)) {
        throw new CryptoValidationError(`${name} contains invalid base64url characters`);
    }

    return str;
}

/**
 * Validate a Uint8Array.
 */
export function validateUint8Array(value: unknown, name: string): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new CryptoValidationError(`${name} must be a Uint8Array`);
    }
    return value;
}

/**
 * Validate a Uint8Array with minimum length requirement.
 */
export function validateUint8ArrayMinLength(
    value: unknown,
    name: string,
    minLength: number
): Uint8Array {
    const arr = validateUint8Array(value, name);

    if (arr.length < minLength) {
        throw new CryptoValidationError(
            `${name} must be at least ${minLength} bytes, got ${arr.length}`
        );
    }

    return arr;
}

