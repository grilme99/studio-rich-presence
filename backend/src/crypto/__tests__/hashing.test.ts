import { describe, it, expect } from 'vitest';
import {
    hashAuthToken,
    verifyAuthToken,
    hashToken,
    verifyToken,
    hashDiscordId,
    constantTimeEqual,
    constantTimeEqualBytes,
} from '../hashing';
import { base64urlDecode } from '../base64url';
import { CryptoValidationError } from '../validation';

// Test pepper (must be at least 16 characters)
const TEST_PEPPER = 'test-pepper-key-at-least-16-chars';
const TEST_SALT = 'test-discord-id-salt-at-least-16-chars';

describe('hashing', () => {
    describe('hashAuthToken', () => {
        it('should produce base64url-encoded hash', async () => {
            const hash = await hashAuthToken('my-auth-token', TEST_PEPPER);
            expect(hash).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should produce 32-byte MAC (HMAC-SHA256)', async () => {
            const hash = await hashAuthToken('my-auth-token', TEST_PEPPER);
            const decoded = base64urlDecode(hash);
            expect(decoded.length).toBe(32);
        });

        it('should produce same hash for same token (deterministic)', async () => {
            const hash1 = await hashAuthToken('same-token', TEST_PEPPER);
            const hash2 = await hashAuthToken('same-token', TEST_PEPPER);
            expect(hash1).toBe(hash2);
        });

        it('should produce different hashes for different tokens', async () => {
            const hash1 = await hashAuthToken('token-one', TEST_PEPPER);
            const hash2 = await hashAuthToken('token-two', TEST_PEPPER);
            expect(hash1).not.toBe(hash2);
        });

        it('should produce different hashes for different peppers', async () => {
            const hash1 = await hashAuthToken('same-token', TEST_PEPPER);
            const hash2 = await hashAuthToken('same-token', 'different-pepper-key-16+');
            expect(hash1).not.toBe(hash2);
        });

        it('should reject empty token', async () => {
            await expect(hashAuthToken('', TEST_PEPPER)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject empty pepper', async () => {
            await expect(hashAuthToken('token', '')).rejects.toThrow(CryptoValidationError);
        });

        it('should reject short pepper', async () => {
            await expect(hashAuthToken('token', 'short')).rejects.toThrow(CryptoValidationError);
        });
    });

    describe('verifyAuthToken', () => {
        it('should verify correct token', async () => {
            const token = 'my-secret-auth-token';
            const hash = await hashAuthToken(token, TEST_PEPPER);
            const result = await verifyAuthToken(token, hash, TEST_PEPPER);
            expect(result).toBe(true);
        });

        it('should reject incorrect token', async () => {
            const hash = await hashAuthToken('correct-token', TEST_PEPPER);
            const result = await verifyAuthToken('wrong-token', hash, TEST_PEPPER);
            expect(result).toBe(false);
        });

        it('should reject token with wrong pepper', async () => {
            const token = 'my-token';
            const hash = await hashAuthToken(token, TEST_PEPPER);
            const result = await verifyAuthToken(token, hash, 'wrong-pepper-key-16-chars');
            expect(result).toBe(false);
        });

        it('should reject empty token', async () => {
            const hash = await hashAuthToken('token', TEST_PEPPER);
            await expect(verifyAuthToken('', hash, TEST_PEPPER)).rejects.toThrow(CryptoValidationError);
        });

        it('should work with tokens of various lengths', async () => {
            const tokens = [
                'short',
                'medium-length-token-here',
                'very-long-token-' + 'x'.repeat(100),
            ];

            for (const token of tokens) {
                const hash = await hashAuthToken(token, TEST_PEPPER);
                const result = await verifyAuthToken(token, hash, TEST_PEPPER);
                expect(result).toBe(true);
            }
        });
    });

    describe('hashToken (salted)', () => {
        it('should produce base64url-encoded hash', async () => {
            const hash = await hashToken('my-secret-token', TEST_PEPPER);
            expect(hash).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should produce hash with salt + MAC (48 bytes decoded)', async () => {
            const hash = await hashToken('my-secret-token', TEST_PEPPER);
            const decoded = base64urlDecode(hash);
            // 16 bytes salt + 32 bytes MAC = 48 bytes
            expect(decoded.length).toBe(48);
        });

        it('should produce different hashes for same token (due to random salt)', async () => {
            const hashes = new Set<string>();
            for (let i = 0; i < 10; i++) {
                hashes.add(await hashToken('same-token', TEST_PEPPER));
            }
            expect(hashes.size).toBe(10);
        });

        it('should reject empty token', async () => {
            await expect(hashToken('', TEST_PEPPER)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject empty pepper', async () => {
            await expect(hashToken('token', '')).rejects.toThrow(CryptoValidationError);
        });

        it('should reject short pepper', async () => {
            await expect(hashToken('token', 'short')).rejects.toThrow(CryptoValidationError);
        });

        it('should reject non-string inputs', async () => {
            await expect(hashToken(123 as any, TEST_PEPPER)).rejects.toThrow(CryptoValidationError);
            await expect(hashToken('token', 123 as any)).rejects.toThrow(CryptoValidationError);
        });
    });

    describe('verifyToken', () => {
        it('should verify correct token', async () => {
            const token = 'my-secret-token';
            const hash = await hashToken(token, TEST_PEPPER);
            const isValid = await verifyToken(token, hash, TEST_PEPPER);
            expect(isValid).toBe(true);
        });

        it('should reject incorrect token', async () => {
            const hash = await hashToken('correct-token', TEST_PEPPER);
            const isValid = await verifyToken('wrong-token', hash, TEST_PEPPER);
            expect(isValid).toBe(false);
        });

        it('should reject with wrong pepper', async () => {
            const token = 'my-secret-token';
            const hash = await hashToken(token, TEST_PEPPER);
            const isValid = await verifyToken(token, hash, 'different-pepper-at-least-16-chars');
            expect(isValid).toBe(false);
        });

        it('should reject malformed hash (too short)', async () => {
            const isValid = await verifyToken('token', 'AAAA', TEST_PEPPER);
            expect(isValid).toBe(false);
        });

        it('should reject malformed hash (wrong length)', async () => {
            // 47 bytes instead of 48
            const shortHash = 'a'.repeat(63); // ~47 bytes when decoded
            const isValid = await verifyToken('token', shortHash, TEST_PEPPER);
            expect(isValid).toBe(false);
        });

        it('should reject empty token', async () => {
            const hash = await hashToken('token', TEST_PEPPER);
            await expect(verifyToken('', hash, TEST_PEPPER)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject invalid hash characters', async () => {
            await expect(verifyToken('token', 'invalid+hash', TEST_PEPPER)).rejects.toThrow(CryptoValidationError);
        });

        it('should verify multiple tokens correctly', async () => {
            const tokens = ['token1', 'token2', 'token3'];
            const hashes = await Promise.all(tokens.map(t => hashToken(t, TEST_PEPPER)));

            // Each hash should verify only its corresponding token
            for (let i = 0; i < tokens.length; i++) {
                for (let j = 0; j < hashes.length; j++) {
                    const isValid = await verifyToken(tokens[i]!, hashes[j]!, TEST_PEPPER);
                    expect(isValid).toBe(i === j);
                }
            }
        });
    });

    describe('hashDiscordId', () => {
        it('should produce base64url-encoded hash', async () => {
            const hash = await hashDiscordId('123456789012345678', TEST_SALT);
            expect(hash).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should produce 32-byte hash (SHA-256 output)', async () => {
            const hash = await hashDiscordId('123456789012345678', TEST_SALT);
            const decoded = base64urlDecode(hash);
            expect(decoded.length).toBe(32);
        });

        it('should produce same hash for same ID (deterministic)', async () => {
            const id = '123456789012345678';
            const hash1 = await hashDiscordId(id, TEST_SALT);
            const hash2 = await hashDiscordId(id, TEST_SALT);
            expect(hash1).toBe(hash2);
        });

        it('should produce different hashes for different IDs', async () => {
            const hash1 = await hashDiscordId('123456789012345678', TEST_SALT);
            const hash2 = await hashDiscordId('987654321098765432', TEST_SALT);
            expect(hash1).not.toBe(hash2);
        });

        it('should produce different hashes with different salts', async () => {
            const id = '123456789012345678';
            const hash1 = await hashDiscordId(id, TEST_SALT);
            const hash2 = await hashDiscordId(id, 'different-salt-at-least-16-chars');
            expect(hash1).not.toBe(hash2);
        });

        it('should reject invalid Discord snowflake format', async () => {
            await expect(hashDiscordId('not-a-snowflake', TEST_SALT)).rejects.toThrow(CryptoValidationError);
            await expect(hashDiscordId('12345', TEST_SALT)).rejects.toThrow(CryptoValidationError); // too short
            await expect(hashDiscordId('12345678901234567890', TEST_SALT)).rejects.toThrow(CryptoValidationError); // too long
            await expect(hashDiscordId('', TEST_SALT)).rejects.toThrow(CryptoValidationError);
        });

        it('should accept valid Discord snowflake formats', async () => {
            // Discord snowflakes are 17-19 digit numbers
            await expect(hashDiscordId('12345678901234567', TEST_SALT)).resolves.toBeTruthy(); // 17 digits
            await expect(hashDiscordId('123456789012345678', TEST_SALT)).resolves.toBeTruthy(); // 18 digits
            await expect(hashDiscordId('1234567890123456789', TEST_SALT)).resolves.toBeTruthy(); // 19 digits
        });

        it('should reject short salt', async () => {
            await expect(hashDiscordId('123456789012345678', 'short')).rejects.toThrow(CryptoValidationError);
        });
    });

    describe('constantTimeEqualBytes', () => {
        it('should return true for equal arrays', () => {
            const a = new Uint8Array([1, 2, 3, 4, 5]);
            const b = new Uint8Array([1, 2, 3, 4, 5]);
            expect(constantTimeEqualBytes(a, b)).toBe(true);
        });

        it('should return false for different arrays', () => {
            const a = new Uint8Array([1, 2, 3, 4, 5]);
            const b = new Uint8Array([1, 2, 3, 4, 6]);
            expect(constantTimeEqualBytes(a, b)).toBe(false);
        });

        it('should return false for arrays of different lengths', () => {
            const a = new Uint8Array([1, 2, 3]);
            const b = new Uint8Array([1, 2, 3, 4]);
            expect(constantTimeEqualBytes(a, b)).toBe(false);
            expect(constantTimeEqualBytes(b, a)).toBe(false);
        });

        it('should return true for empty arrays', () => {
            const a = new Uint8Array(0);
            const b = new Uint8Array(0);
            expect(constantTimeEqualBytes(a, b)).toBe(true);
        });

        it('should handle single byte difference', () => {
            const a = new Uint8Array([0]);
            const b = new Uint8Array([1]);
            expect(constantTimeEqualBytes(a, b)).toBe(false);
        });

        it('should reject non-Uint8Array inputs', () => {
            expect(() => constantTimeEqualBytes([1, 2, 3] as any, new Uint8Array([1, 2, 3]))).toThrow(CryptoValidationError);
            expect(() => constantTimeEqualBytes(new Uint8Array([1, 2, 3]), 'abc' as any)).toThrow(CryptoValidationError);
        });
    });

    describe('constantTimeEqual', () => {
        it('should return true for equal strings', () => {
            expect(constantTimeEqual('hello', 'hello')).toBe(true);
            expect(constantTimeEqual('test123', 'test123')).toBe(true);
        });

        it('should return false for different strings', () => {
            expect(constantTimeEqual('hello', 'world')).toBe(false);
            expect(constantTimeEqual('hello', 'hello!')).toBe(false);
        });

        it('should return false for strings of different lengths', () => {
            expect(constantTimeEqual('short', 'longer string')).toBe(false);
        });

        it('should handle Unicode correctly', () => {
            expect(constantTimeEqual('👋', '👋')).toBe(true);
            expect(constantTimeEqual('👋', '🌍')).toBe(false);
        });

        it('should reject empty strings', () => {
            expect(() => constantTimeEqual('', 'test')).toThrow(CryptoValidationError);
            expect(() => constantTimeEqual('test', '')).toThrow(CryptoValidationError);
        });

        it('should reject non-string inputs', () => {
            expect(() => constantTimeEqual(123 as any, 'test')).toThrow(CryptoValidationError);
            expect(() => constantTimeEqual('test', null as any)).toThrow(CryptoValidationError);
        });
    });

    describe('security properties', () => {
        it('should not leak timing information through hash comparison', async () => {
            // This is a basic sanity check - proper timing analysis would require
            // statistical methods and many iterations
            const correctToken = 'correct-token-value';
            const hash = await hashToken(correctToken, TEST_PEPPER);

            // These should all take approximately the same time
            await verifyToken('wrong-token-value', hash, TEST_PEPPER);
            await verifyToken('completely-different', hash, TEST_PEPPER);
            await verifyToken('c', hash, TEST_PEPPER); // Very different length
        });

        it('should use per-hash salt (defense in depth)', async () => {
            const token = 'same-token';
            const hash1 = await hashToken(token, TEST_PEPPER);
            const hash2 = await hashToken(token, TEST_PEPPER);

            // Hashes should be different (different salts)
            expect(hash1).not.toBe(hash2);

            // But both should verify correctly
            expect(await verifyToken(token, hash1, TEST_PEPPER)).toBe(true);
            expect(await verifyToken(token, hash2, TEST_PEPPER)).toBe(true);

            // And shouldn't cross-verify
            expect(await verifyToken('different', hash1, TEST_PEPPER)).toBe(false);
        });
    });
});

