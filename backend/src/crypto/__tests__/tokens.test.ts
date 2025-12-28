import { describe, it, expect } from 'vitest';
import {
    generateToken,
    generateSessionCode,
    generateClientKey,
    generateCompletionCode,
    generatePkceCodeVerifier,
    generatePkceCodeChallenge,
    generateUuid,
} from '../tokens';
import { base64urlDecode } from '../base64url';
import { CryptoValidationError } from '../validation';

describe('tokens', () => {
    describe('generateToken', () => {
        it('should generate base64url-encoded token', () => {
            const token = generateToken();
            expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should generate token of correct length', () => {
            // 32 bytes = 43 base64url characters (no padding)
            const token = generateToken(32);
            const decoded = base64urlDecode(token);
            expect(decoded.length).toBe(32);
        });

        it('should generate different tokens each call', () => {
            const tokens = new Set<string>();
            for (let i = 0; i < 100; i++) {
                tokens.add(generateToken());
            }
            expect(tokens.size).toBe(100);
        });

        it('should accept custom byte length', () => {
            const token16 = generateToken(16);
            const token64 = generateToken(64);
            expect(base64urlDecode(token16).length).toBe(16);
            expect(base64urlDecode(token64).length).toBe(64);
        });

        it('should reject invalid byte counts', () => {
            expect(() => generateToken(0)).toThrow(CryptoValidationError);
            expect(() => generateToken(-1)).toThrow(CryptoValidationError);
            expect(() => generateToken(1000)).toThrow(CryptoValidationError); // exceeds max
            expect(() => generateToken(1.5 as any)).toThrow(CryptoValidationError);
        });
    });

    describe('generateSessionCode', () => {
        it('should generate 32-byte session code', () => {
            const code = generateSessionCode();
            const decoded = base64urlDecode(code);
            expect(decoded.length).toBe(32);
        });

        it('should be URL-safe', () => {
            const code = generateSessionCode();
            expect(code).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should generate unique codes', () => {
            const codes = new Set<string>();
            for (let i = 0; i < 100; i++) {
                codes.add(generateSessionCode());
            }
            expect(codes.size).toBe(100);
        });
    });

    describe('generateClientKey', () => {
        it('should generate 32-byte client key', () => {
            const key = generateClientKey();
            const decoded = base64urlDecode(key);
            expect(decoded.length).toBe(32);
        });

        it('should be URL-safe', () => {
            const key = generateClientKey();
            expect(key).toMatch(/^[A-Za-z0-9_-]+$/);
        });
    });

    describe('generateCompletionCode', () => {
        it('should generate 5-digit string', () => {
            const code = generateCompletionCode();
            expect(code).toMatch(/^\d{5}$/);
        });

        it('should generate codes in range 10000-99999', () => {
            for (let i = 0; i < 100; i++) {
                const code = parseInt(generateCompletionCode(), 10);
                expect(code).toBeGreaterThanOrEqual(10000);
                expect(code).toBeLessThanOrEqual(99999);
            }
        });

        it('should generate varying codes', () => {
            const codes = new Set<string>();
            for (let i = 0; i < 100; i++) {
                codes.add(generateCompletionCode());
            }
            // Should have significant variety (at least 90 unique out of 100)
            expect(codes.size).toBeGreaterThan(90);
        });
    });

    describe('generatePkceCodeVerifier', () => {
        it('should generate valid PKCE code verifier', () => {
            const verifier = generatePkceCodeVerifier();
            // RFC 7636 requires 43-128 characters
            expect(verifier.length).toBeGreaterThanOrEqual(43);
            expect(verifier.length).toBeLessThanOrEqual(128);
        });

        it('should only contain valid characters (A-Z, a-z, 0-9, -, _, .)', () => {
            const verifier = generatePkceCodeVerifier();
            // Our implementation uses base64url which is a subset of allowed chars
            expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
        });
    });

    describe('generatePkceCodeChallenge', () => {
        it('should generate valid code challenge from verifier', async () => {
            const verifier = generatePkceCodeVerifier();
            const challenge = await generatePkceCodeChallenge(verifier);

            // Should be base64url encoded SHA-256 (32 bytes = 43 chars)
            expect(challenge.length).toBe(43);
            expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should produce same challenge for same verifier', async () => {
            const verifier = generatePkceCodeVerifier();
            const challenge1 = await generatePkceCodeChallenge(verifier);
            const challenge2 = await generatePkceCodeChallenge(verifier);
            expect(challenge1).toBe(challenge2);
        });

        it('should produce different challenges for different verifiers', async () => {
            const verifier1 = generatePkceCodeVerifier();
            const verifier2 = generatePkceCodeVerifier();
            const challenge1 = await generatePkceCodeChallenge(verifier1);
            const challenge2 = await generatePkceCodeChallenge(verifier2);
            expect(challenge1).not.toBe(challenge2);
        });

        it('should reject verifier shorter than 43 characters', async () => {
            await expect(generatePkceCodeChallenge('short')).rejects.toThrow(CryptoValidationError);
        });

        it('should reject verifier longer than 128 characters', async () => {
            const longVerifier = 'a'.repeat(129);
            await expect(generatePkceCodeChallenge(longVerifier)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject empty verifier', async () => {
            await expect(generatePkceCodeChallenge('')).rejects.toThrow(CryptoValidationError);
        });
    });

    describe('generateUuid', () => {
        it('should generate valid UUID v4 format', () => {
            const uuid = generateUuid();
            // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
            // where y is 8, 9, a, or b
            const uuidV4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            expect(uuid).toMatch(uuidV4Regex);
        });

        it('should generate unique UUIDs', () => {
            const uuids = new Set<string>();
            for (let i = 0; i < 100; i++) {
                uuids.add(generateUuid());
            }
            expect(uuids.size).toBe(100);
        });

        it('should be lowercase', () => {
            const uuid = generateUuid();
            expect(uuid).toBe(uuid.toLowerCase());
        });
    });
});

