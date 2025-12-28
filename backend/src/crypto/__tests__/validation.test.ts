import { describe, it, expect } from 'vitest';
import {
    CryptoValidationError,
    validateString,
    validateNonEmptyString,
    validateToken,
    validateSecret,
    validatePositiveInt,
    validateBase64url,
    validateUint8Array,
    validateUint8ArrayMinLength,
    MAX_STRING_LENGTH,
    MAX_TOKEN_LENGTH,
    MIN_SECRET_LENGTH,
} from '../validation';

describe('validation', () => {
    describe('validateString', () => {
        it('should accept valid strings', () => {
            expect(validateString('hello', 'test')).toBe('hello');
            expect(validateString('', 'test')).toBe('');
            expect(validateString('a'.repeat(1000), 'test')).toBe('a'.repeat(1000));
        });

        it('should reject non-strings', () => {
            expect(() => validateString(null, 'test')).toThrow(CryptoValidationError);
            expect(() => validateString(undefined, 'test')).toThrow(CryptoValidationError);
            expect(() => validateString(123, 'test')).toThrow(CryptoValidationError);
            expect(() => validateString({}, 'test')).toThrow(CryptoValidationError);
            expect(() => validateString([], 'test')).toThrow(CryptoValidationError);
        });

        it('should include field name in error message', () => {
            expect(() => validateString(123, 'myField')).toThrow(/myField/);
        });
    });

    describe('validateNonEmptyString', () => {
        it('should accept valid non-empty strings', () => {
            expect(validateNonEmptyString('hello', 'test')).toBe('hello');
            expect(validateNonEmptyString('x', 'test')).toBe('x');
        });

        it('should reject empty strings', () => {
            expect(() => validateNonEmptyString('', 'test')).toThrow(CryptoValidationError);
            expect(() => validateNonEmptyString('', 'test')).toThrow(/must not be empty/);
        });

        it('should reject strings exceeding max length', () => {
            const longString = 'a'.repeat(MAX_STRING_LENGTH + 1);
            expect(() => validateNonEmptyString(longString, 'test')).toThrow(CryptoValidationError);
            expect(() => validateNonEmptyString(longString, 'test')).toThrow(/exceeds maximum length/);
        });

        it('should accept custom max length', () => {
            expect(validateNonEmptyString('hello', 'test', 10)).toBe('hello');
            expect(() => validateNonEmptyString('hello world', 'test', 10)).toThrow(/exceeds maximum length/);
        });
    });

    describe('validateToken', () => {
        it('should accept valid tokens', () => {
            const token = 'abc123XYZ_-';
            expect(validateToken(token, 'test')).toBe(token);
        });

        it('should reject empty tokens', () => {
            expect(() => validateToken('', 'test')).toThrow(CryptoValidationError);
        });

        it('should reject tokens exceeding max length', () => {
            const longToken = 'a'.repeat(MAX_TOKEN_LENGTH + 1);
            expect(() => validateToken(longToken, 'test')).toThrow(CryptoValidationError);
        });
    });

    describe('validateSecret', () => {
        it('should accept valid secrets', () => {
            const secret = 'a'.repeat(MIN_SECRET_LENGTH);
            expect(validateSecret(secret, 'test')).toBe(secret);
        });

        it('should reject secrets shorter than minimum', () => {
            const shortSecret = 'a'.repeat(MIN_SECRET_LENGTH - 1);
            expect(() => validateSecret(shortSecret, 'test')).toThrow(CryptoValidationError);
            expect(() => validateSecret(shortSecret, 'test')).toThrow(/at least/);
        });

        it('should reject empty secrets', () => {
            expect(() => validateSecret('', 'test')).toThrow(CryptoValidationError);
        });
    });

    describe('validatePositiveInt', () => {
        it('should accept positive integers', () => {
            expect(validatePositiveInt(1, 'test')).toBe(1);
            expect(validatePositiveInt(100, 'test')).toBe(100);
            expect(validatePositiveInt(999999, 'test')).toBe(999999);
        });

        it('should reject zero', () => {
            expect(() => validatePositiveInt(0, 'test')).toThrow(CryptoValidationError);
            expect(() => validatePositiveInt(0, 'test')).toThrow(/must be positive/);
        });

        it('should reject negative numbers', () => {
            expect(() => validatePositiveInt(-1, 'test')).toThrow(CryptoValidationError);
            expect(() => validatePositiveInt(-100, 'test')).toThrow(CryptoValidationError);
        });

        it('should reject non-integers', () => {
            expect(() => validatePositiveInt(1.5, 'test')).toThrow(CryptoValidationError);
            expect(() => validatePositiveInt(NaN, 'test')).toThrow(CryptoValidationError);
            expect(() => validatePositiveInt(Infinity, 'test')).toThrow(CryptoValidationError);
        });

        it('should reject non-numbers', () => {
            expect(() => validatePositiveInt('1' as any, 'test')).toThrow(CryptoValidationError);
            expect(() => validatePositiveInt(null as any, 'test')).toThrow(CryptoValidationError);
        });

        it('should enforce max limit when provided', () => {
            expect(validatePositiveInt(10, 'test', 100)).toBe(10);
            expect(() => validatePositiveInt(101, 'test', 100)).toThrow(/exceeds maximum/);
        });
    });

    describe('validateBase64url', () => {
        it('should accept valid base64url strings', () => {
            expect(validateBase64url('abc123', 'test')).toBe('abc123');
            expect(validateBase64url('ABC-xyz_09', 'test')).toBe('ABC-xyz_09');
        });

        it('should reject strings with invalid characters', () => {
            expect(() => validateBase64url('abc+123', 'test')).toThrow(CryptoValidationError);
            expect(() => validateBase64url('abc/123', 'test')).toThrow(CryptoValidationError);
            expect(() => validateBase64url('abc=123', 'test')).toThrow(CryptoValidationError);
            expect(() => validateBase64url('abc 123', 'test')).toThrow(CryptoValidationError);
        });

        it('should reject empty strings', () => {
            expect(() => validateBase64url('', 'test')).toThrow(CryptoValidationError);
        });
    });

    describe('validateUint8Array', () => {
        it('should accept Uint8Array', () => {
            const arr = new Uint8Array([1, 2, 3]);
            expect(validateUint8Array(arr, 'test')).toBe(arr);
        });

        it('should accept empty Uint8Array', () => {
            const arr = new Uint8Array(0);
            expect(validateUint8Array(arr, 'test')).toBe(arr);
        });

        it('should reject non-Uint8Array', () => {
            expect(() => validateUint8Array([1, 2, 3], 'test')).toThrow(CryptoValidationError);
            expect(() => validateUint8Array(new ArrayBuffer(3), 'test')).toThrow(CryptoValidationError);
            expect(() => validateUint8Array('abc', 'test')).toThrow(CryptoValidationError);
            expect(() => validateUint8Array(null, 'test')).toThrow(CryptoValidationError);
        });
    });

    describe('validateUint8ArrayMinLength', () => {
        it('should accept arrays meeting minimum length', () => {
            const arr = new Uint8Array([1, 2, 3, 4, 5]);
            expect(validateUint8ArrayMinLength(arr, 'test', 5)).toBe(arr);
            expect(validateUint8ArrayMinLength(arr, 'test', 3)).toBe(arr);
        });

        it('should reject arrays shorter than minimum', () => {
            const arr = new Uint8Array([1, 2, 3]);
            expect(() => validateUint8ArrayMinLength(arr, 'test', 5)).toThrow(CryptoValidationError);
            expect(() => validateUint8ArrayMinLength(arr, 'test', 5)).toThrow(/at least 5 bytes/);
        });
    });
});

