import { describe, it, expect } from 'vitest';
import {
    base64urlEncode,
    base64urlDecode,
    stringToBase64url,
    base64urlToString,
} from '../base64url';
import { CryptoValidationError } from '../validation';

describe('base64url', () => {
    describe('base64urlEncode', () => {
        it('should encode bytes to base64url', () => {
            // Test known values
            const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
            expect(base64urlEncode(data)).toBe('SGVsbG8');
        });

        it('should handle empty array', () => {
            expect(base64urlEncode(new Uint8Array(0))).toBe('');
        });

        it('should use URL-safe characters (- instead of +, _ instead of /)', () => {
            // This byte sequence would produce + and / in standard base64
            const data = new Uint8Array([251, 239, 190]); // produces "++" in standard base64
            const encoded = base64urlEncode(data);
            expect(encoded).not.toContain('+');
            expect(encoded).not.toContain('/');
            expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
        });

        it('should not include padding', () => {
            const data = new Uint8Array([1]);
            const encoded = base64urlEncode(data);
            expect(encoded).not.toContain('=');
        });

        it('should reject non-Uint8Array input', () => {
            expect(() => base64urlEncode('hello' as any)).toThrow(CryptoValidationError);
            expect(() => base64urlEncode([1, 2, 3] as any)).toThrow(CryptoValidationError);
            expect(() => base64urlEncode(null as any)).toThrow(CryptoValidationError);
        });
    });

    describe('base64urlDecode', () => {
        it('should decode base64url to bytes', () => {
            const decoded = base64urlDecode('SGVsbG8');
            expect(Array.from(decoded)).toEqual([72, 101, 108, 108, 111]);
        });

        it('should handle empty string', () => {
            const decoded = base64urlDecode('');
            expect(decoded.length).toBe(0);
        });

        it('should handle strings without padding', () => {
            // These would normally need padding
            expect(base64urlDecode('YQ').length).toBe(1);
            expect(base64urlDecode('YWI').length).toBe(2);
            expect(base64urlDecode('YWJj').length).toBe(3);
        });

        it('should handle URL-safe characters', () => {
            // Encode then decode should round-trip
            const data = new Uint8Array([251, 239, 190]);
            const encoded = base64urlEncode(data);
            const decoded = base64urlDecode(encoded);
            expect(Array.from(decoded)).toEqual(Array.from(data));
        });

        it('should reject invalid base64url characters', () => {
            expect(() => base64urlDecode('abc+def')).toThrow(CryptoValidationError);
            expect(() => base64urlDecode('abc/def')).toThrow(CryptoValidationError);
            expect(() => base64urlDecode('abc=def')).toThrow(CryptoValidationError);
            expect(() => base64urlDecode('abc def')).toThrow(CryptoValidationError);
        });

        it('should reject non-string input', () => {
            expect(() => base64urlDecode(123 as any)).toThrow(CryptoValidationError);
            expect(() => base64urlDecode(null as any)).toThrow(CryptoValidationError);
        });
    });

    describe('stringToBase64url', () => {
        it('should encode strings', () => {
            expect(stringToBase64url('Hello')).toBe('SGVsbG8');
            expect(stringToBase64url('Hello, World!')).toBe('SGVsbG8sIFdvcmxkIQ');
        });

        it('should handle empty string', () => {
            expect(stringToBase64url('')).toBe('');
        });

        it('should handle Unicode', () => {
            const emoji = '👋';
            const encoded = stringToBase64url(emoji);
            expect(base64urlToString(encoded)).toBe(emoji);
        });

        it('should reject non-string input', () => {
            expect(() => stringToBase64url(123 as any)).toThrow(CryptoValidationError);
        });
    });

    describe('base64urlToString', () => {
        it('should decode to strings', () => {
            expect(base64urlToString('SGVsbG8')).toBe('Hello');
            expect(base64urlToString('SGVsbG8sIFdvcmxkIQ')).toBe('Hello, World!');
        });

        it('should handle empty input', () => {
            expect(base64urlToString('')).toBe('');
        });
    });

    describe('round-trip encoding/decoding', () => {
        it('should round-trip bytes', () => {
            const testCases = [
                new Uint8Array([]),
                new Uint8Array([0]),
                new Uint8Array([255]),
                new Uint8Array([0, 1, 2, 3, 4, 5]),
                new Uint8Array(Array.from({ length: 256 }, (_, i) => i)),
            ];

            for (const data of testCases) {
                const encoded = base64urlEncode(data);
                const decoded = base64urlDecode(encoded);
                expect(Array.from(decoded)).toEqual(Array.from(data));
            }
        });

        it('should round-trip strings', () => {
            const testCases = [
                '',
                'a',
                'Hello',
                'Hello, World!',
                '👋🌍',
                '日本語テスト',
                'a'.repeat(1000),
            ];

            for (const str of testCases) {
                const encoded = stringToBase64url(str);
                const decoded = base64urlToString(encoded);
                expect(decoded).toBe(str);
            }
        });
    });
});

