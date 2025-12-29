import { describe, it, expect, beforeAll } from 'vitest';
import {
    deriveEncryptionKey,
    encryptToken,
    decryptToken,
    encryptDiscordTokens,
    decryptDiscordTokens,
    reencryptDiscordTokens,
} from '../encryption';
import { base64urlDecode } from '../base64url';
import { CryptoValidationError } from '../validation';

// Test secrets (must be at least 16 characters)
const TEST_SERVER_SECRET = 'test-server-secret-at-least-16-chars';
const TEST_CLIENT_KEY = 'test-client-key-at-least-16-chars';
const TEST_USER_ID = 'user-123';

describe('encryption', () => {
    describe('deriveEncryptionKey', () => {
        it('should derive a CryptoKey', async () => {
            const key = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
            expect(key).toBeInstanceOf(CryptoKey);
        });

        it('should derive same key for same inputs', async () => {
            const key1 = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
            const key2 = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);

            // Keys can't be directly compared, but they should encrypt/decrypt interchangeably
            const plaintext = 'test-data';
            const encrypted = await encryptToken(plaintext, key1);
            const decrypted = await decryptToken(encrypted, key2);
            expect(decrypted).toBe(plaintext);
        });

        it('should derive different keys for different server secrets', async () => {
            const key1 = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
            const key2 = await deriveEncryptionKey('different-server-secret-16-chars', TEST_CLIENT_KEY, TEST_USER_ID);

            const plaintext = 'test-data';
            const encrypted = await encryptToken(plaintext, key1);

            // Should fail to decrypt with different key
            await expect(decryptToken(encrypted, key2)).rejects.toThrow();
        });

        it('should derive different keys for different client keys', async () => {
            const key1 = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
            const key2 = await deriveEncryptionKey(TEST_SERVER_SECRET, 'different-client-key-16-chars', TEST_USER_ID);

            const plaintext = 'test-data';
            const encrypted = await encryptToken(plaintext, key1);

            await expect(decryptToken(encrypted, key2)).rejects.toThrow();
        });

        it('should derive different keys for different user IDs', async () => {
            const key1 = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
            const key2 = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, 'different-user');

            const plaintext = 'test-data';
            const encrypted = await encryptToken(plaintext, key1);

            await expect(decryptToken(encrypted, key2)).rejects.toThrow();
        });

        it('should reject short server secret', async () => {
            await expect(deriveEncryptionKey('short', TEST_CLIENT_KEY, TEST_USER_ID)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject short client key', async () => {
            await expect(deriveEncryptionKey(TEST_SERVER_SECRET, 'short', TEST_USER_ID)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject empty user ID', async () => {
            await expect(deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, '')).rejects.toThrow(CryptoValidationError);
        });

        it('should prevent key confusion from concatenation', async () => {
            // Test that "serverA" + "clientB" !== "serverAc" + "lientB"
            const key1 = await deriveEncryptionKey('serverA-padding-16', 'clientB-padding-16', TEST_USER_ID);
            const key2 = await deriveEncryptionKey('serverAc-padding-16', 'lientB-padding-16-', TEST_USER_ID);

            const plaintext = 'test-data';
            const encrypted = await encryptToken(plaintext, key1);

            await expect(decryptToken(encrypted, key2)).rejects.toThrow();
        });
    });

    describe('encryptToken', () => {
        let key: CryptoKey;

        beforeAll(async () => {
            key = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
        });

        it('should produce base64url-encoded ciphertext', async () => {
            const encrypted = await encryptToken('test-token', key);
            expect(encrypted).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should include IV prefix (12 bytes)', async () => {
            const encrypted = await encryptToken('test-token', key);
            const decoded = base64urlDecode(encrypted);
            // 12 bytes IV + at least 16 bytes auth tag + ciphertext
            expect(decoded.length).toBeGreaterThanOrEqual(29);
        });

        it('should produce different ciphertext for same plaintext (random IV)', async () => {
            const ciphertexts = new Set<string>();
            for (let i = 0; i < 10; i++) {
                ciphertexts.add(await encryptToken('same-token', key));
            }
            expect(ciphertexts.size).toBe(10);
        });

        it('should reject empty plaintext', async () => {
            await expect(encryptToken('', key)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject invalid key', async () => {
            await expect(encryptToken('test', 'not-a-key' as any)).rejects.toThrow(CryptoValidationError);
            await expect(encryptToken('test', null as any)).rejects.toThrow(CryptoValidationError);
        });
    });

    describe('decryptToken', () => {
        let key: CryptoKey;

        beforeAll(async () => {
            key = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
        });

        it('should decrypt to original plaintext', async () => {
            const plaintext = 'my-secret-discord-token-12345';
            const encrypted = await encryptToken(plaintext, key);
            const decrypted = await decryptToken(encrypted, key);
            expect(decrypted).toBe(plaintext);
        });

        it('should handle long tokens', async () => {
            const plaintext = 'a'.repeat(1000);
            const encrypted = await encryptToken(plaintext, key);
            const decrypted = await decryptToken(encrypted, key);
            expect(decrypted).toBe(plaintext);
        });

        it('should handle Unicode', async () => {
            const plaintext = '🔐 secret 日本語 токен';
            const encrypted = await encryptToken(plaintext, key);
            const decrypted = await decryptToken(encrypted, key);
            expect(decrypted).toBe(plaintext);
        });

        it('should reject invalid base64url', async () => {
            await expect(decryptToken('invalid+base64', key)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject empty encrypted data', async () => {
            await expect(decryptToken('', key)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject ciphertext too short', async () => {
            const shortData = 'AAAA'; // Only a few bytes
            await expect(decryptToken(shortData, key)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject tampered ciphertext', async () => {
            const encrypted = await encryptToken('test-token', key);
            // Tamper with the ciphertext (flip a bit in the middle)
            const bytes = base64urlDecode(encrypted);
            bytes[20] = bytes[20]! ^ 0xff;
            const tampered = btoa(String.fromCharCode(...bytes))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');

            await expect(decryptToken(tampered, key)).rejects.toThrow(CryptoValidationError);
        });

        it('should reject wrong key', async () => {
            const encrypted = await encryptToken('test-token', key);
            const wrongKey = await deriveEncryptionKey(
                'different-server-secret-16',
                TEST_CLIENT_KEY,
                TEST_USER_ID
            );
            await expect(decryptToken(encrypted, wrongKey)).rejects.toThrow(CryptoValidationError);
        });
    });

    describe('encryptDiscordTokens', () => {
        let key: CryptoKey;

        beforeAll(async () => {
            key = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
        });

        it('should encrypt both tokens', async () => {
            const result = await encryptDiscordTokens('access-token-123', 'refresh-token-456', key);

            expect(result).toHaveProperty('accessTokenEnc');
            expect(result).toHaveProperty('refreshTokenEnc');
            expect(result.accessTokenEnc).toMatch(/^[A-Za-z0-9_-]+$/);
            expect(result.refreshTokenEnc).toMatch(/^[A-Za-z0-9_-]+$/);
        });

        it('should produce different ciphertexts for each token', async () => {
            const result = await encryptDiscordTokens('same-value', 'same-value', key);
            // Even with same plaintext, random IV means different ciphertext
            expect(result.accessTokenEnc).not.toBe(result.refreshTokenEnc);
        });

        it('should reject empty tokens', async () => {
            await expect(encryptDiscordTokens('', 'refresh', key)).rejects.toThrow(CryptoValidationError);
            await expect(encryptDiscordTokens('access', '', key)).rejects.toThrow(CryptoValidationError);
        });
    });

    describe('decryptDiscordTokens', () => {
        let key: CryptoKey;

        beforeAll(async () => {
            key = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
        });

        it('should decrypt both tokens', async () => {
            const access = 'access-token-abc123';
            const refresh = 'refresh-token-xyz789';

            const encrypted = await encryptDiscordTokens(access, refresh, key);
            const decrypted = await decryptDiscordTokens(
                encrypted.accessTokenEnc,
                encrypted.refreshTokenEnc,
                key
            );

            expect(decrypted.accessToken).toBe(access);
            expect(decrypted.refreshToken).toBe(refresh);
        });

        it('should reject invalid encrypted data', async () => {
            await expect(decryptDiscordTokens('invalid', 'alsoinvalid', key)).rejects.toThrow();
        });
    });

    describe('reencryptDiscordTokens', () => {
        let key: CryptoKey;

        beforeAll(async () => {
            key = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
        });

        it('should encrypt new tokens', async () => {
            const newAccess = 'new-access-token-123';
            const newRefresh = 'new-refresh-token-456';

            const result = await reencryptDiscordTokens(newAccess, newRefresh, key);

            // Should be able to decrypt
            const decrypted = await decryptDiscordTokens(
                result.accessTokenEnc,
                result.refreshTokenEnc,
                key
            );

            expect(decrypted.accessToken).toBe(newAccess);
            expect(decrypted.refreshToken).toBe(newRefresh);
        });
    });

    describe('round-trip encryption', () => {
        it('should handle full encryption lifecycle', async () => {
            // Simulate the real flow:
            // 1. User links Discord account
            // 2. We encrypt tokens with derived key
            // 3. Later, we decrypt to use the tokens
            // 4. If tokens refresh, we re-encrypt

            const serverSecret = 'prod-server-secret-key-32-chars';
            const clientKey = 'client-specific-key-32-chars!';
            const userId = 'user-uuid-123';

            // Step 1: Derive key
            const key = await deriveEncryptionKey(serverSecret, clientKey, userId);

            // Step 2: Encrypt initial tokens
            const initialAccess = 'discord-access-token-initial';
            const initialRefresh = 'discord-refresh-token-initial';
            const encrypted = await encryptDiscordTokens(initialAccess, initialRefresh, key);

            // Step 3: Later, decrypt to use
            const decrypted = await decryptDiscordTokens(
                encrypted.accessTokenEnc,
                encrypted.refreshTokenEnc,
                key
            );
            expect(decrypted.accessToken).toBe(initialAccess);
            expect(decrypted.refreshToken).toBe(initialRefresh);

            // Step 4: Tokens refresh, re-encrypt
            const newAccess = 'discord-access-token-refreshed';
            const newRefresh = 'discord-refresh-token-refreshed';
            const reencrypted = await reencryptDiscordTokens(newAccess, newRefresh, key);

            // Verify new tokens
            const decrypted2 = await decryptDiscordTokens(
                reencrypted.accessTokenEnc,
                reencrypted.refreshTokenEnc,
                key
            );
            expect(decrypted2.accessToken).toBe(newAccess);
            expect(decrypted2.refreshToken).toBe(newRefresh);
        });
    });

    describe('security properties', () => {
        it('should require both server secret and client key', async () => {
            const key1 = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
            const encrypted = await encryptToken('sensitive-data', key1);

            // Try with only server secret (wrong client key)
            const keyOnlyServer = await deriveEncryptionKey(
                TEST_SERVER_SECRET,
                'wrong-client-key-16-chars!',
                TEST_USER_ID
            );
            await expect(decryptToken(encrypted, keyOnlyServer)).rejects.toThrow();

            // Try with only client key (wrong server secret)
            const keyOnlyClient = await deriveEncryptionKey(
                'wrong-server-secret-16-chars',
                TEST_CLIENT_KEY,
                TEST_USER_ID
            );
            await expect(decryptToken(encrypted, keyOnlyClient)).rejects.toThrow();
        });

        it('should use unique IV per encryption (nonce reuse prevention)', async () => {
            const key = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
            const plaintext = 'same-token-encrypted-multiple-times';

            const ciphertexts: string[] = [];
            for (let i = 0; i < 100; i++) {
                ciphertexts.push(await encryptToken(plaintext, key));
            }

            // All ciphertexts should be unique (different IVs)
            const uniqueCiphertexts = new Set(ciphertexts);
            expect(uniqueCiphertexts.size).toBe(100);

            // First 12 bytes (IV) should all be different
            const ivs = ciphertexts.map(c => base64urlDecode(c).slice(0, 12));
            const uniqueIvs = new Set(ivs.map(iv => Array.from(iv).join(',')));
            expect(uniqueIvs.size).toBe(100);
        });

        it('should detect any bit flip in ciphertext', async () => {
            const key = await deriveEncryptionKey(TEST_SERVER_SECRET, TEST_CLIENT_KEY, TEST_USER_ID);
            const encrypted = await encryptToken('test-data', key);
            const bytes = base64urlDecode(encrypted);

            // Try flipping each bit position
            for (let byteIndex = 0; byteIndex < Math.min(bytes.length, 50); byteIndex++) {
                const tamperedBytes = new Uint8Array(bytes);
                tamperedBytes[byteIndex] = tamperedBytes[byteIndex]! ^ 0x01; // Flip one bit

                const tampered = btoa(String.fromCharCode(...tamperedBytes))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');

                await expect(decryptToken(tampered, key)).rejects.toThrow();
            }
        });
    });
});

