import { describe, it, expect } from 'vitest';
import { create, toJson } from '@bufbuild/protobuf';
import {
    parseRequest,
    serializeResponse,
    createResponse,
    AuthStartRequestSchema,
    AuthStartResponseSchema,
    AuthCompleteRequestSchema,
} from '../validation';

describe('protobuf validation', () => {
    describe('parseRequest', () => {
        describe('AuthStartRequest', () => {
            it('should parse empty object', () => {
                const result = parseRequest(AuthStartRequestSchema, {});
                expect(result.authToken).toBeUndefined();
                expect(result.clientKey).toBeUndefined();
            });

            it('should parse null/undefined as empty message', () => {
                const resultNull = parseRequest(AuthStartRequestSchema, null);
                const resultUndef = parseRequest(AuthStartRequestSchema, undefined);

                expect(resultNull.authToken).toBeUndefined();
                expect(resultUndef.authToken).toBeUndefined();
            });

            it('should parse valid auth_token (snake_case JSON)', () => {
                const result = parseRequest(AuthStartRequestSchema, {
                    auth_token: 'my-token',
                });
                expect(result.authToken).toBe('my-token');
            });

            it('should parse valid authToken (camelCase JSON)', () => {
                const result = parseRequest(AuthStartRequestSchema, {
                    authToken: 'my-token',
                });
                expect(result.authToken).toBe('my-token');
            });

            it('should parse both fields', () => {
                const result = parseRequest(AuthStartRequestSchema, {
                    auth_token: 'token',
                    client_key: 'key',
                });
                expect(result.authToken).toBe('token');
                expect(result.clientKey).toBe('key');
            });

            it('should ignore unknown fields', () => {
                // With ignoreUnknownFields: true, extra fields are ignored
                const result = parseRequest(AuthStartRequestSchema, {
                    auth_token: 'token',
                    unknown_field: 'ignored',
                });
                expect(result.authToken).toBe('token');
                expect((result as any).unknownField).toBeUndefined();
            });
        });

        describe('AuthCompleteRequest', () => {
            it('should parse valid request', () => {
                const result = parseRequest(AuthCompleteRequestSchema, {
                    code: 'session-code',
                    completion_code: '12345',
                });
                expect(result.code).toBe('session-code');
                expect(result.completionCode).toBe('12345');
            });

            it('should use default empty string for missing required fields', () => {
                const result = parseRequest(AuthCompleteRequestSchema, {});
                // Proto3 uses default values for missing fields
                expect(result.code).toBe('');
                expect(result.completionCode).toBe('');
            });
        });
    });

    describe('serializeResponse', () => {
        it('should serialize AuthStartResponse to JSON with snake_case', () => {
            const message = create(AuthStartResponseSchema, {
                code: 'abc123',
                url: 'https://example.com/auth/link/abc123',
                sseUrl: 'https://example.com/auth/sse/abc123',
                expiresInSeconds: 300,
            });

            const json = serializeResponse(AuthStartResponseSchema, message);

            expect(json).toEqual({
                code: 'abc123',
                url: 'https://example.com/auth/link/abc123',
                sseUrl: 'https://example.com/auth/sse/abc123',
                expiresInSeconds: 300,
            });
        });
    });

    describe('createResponse', () => {
        it('should create and serialize response in one step', () => {
            const json = createResponse(AuthStartResponseSchema, {
                code: 'abc123',
                url: 'https://example.com/auth/link/abc123',
                sseUrl: 'https://example.com/auth/sse/abc123',
                expiresInSeconds: 300,
            });

            expect(json).toEqual({
                code: 'abc123',
                url: 'https://example.com/auth/link/abc123',
                sseUrl: 'https://example.com/auth/sse/abc123',
                expiresInSeconds: 300,
            });
        });

        it('should omit default values from JSON output', () => {
            const json = createResponse(AuthStartResponseSchema, {
                code: 'abc123',
            });

            // Proto3 JSON omits fields with default values (0, "")
            // Only non-default values are included
            expect(json).toEqual({
                code: 'abc123',
            });
        });
    });

    describe('generated types', () => {
        it('should have correct field names in generated types', () => {
            const message = create(AuthStartRequestSchema, {
                authToken: 'token',
                clientKey: 'key',
            });

            expect(message.authToken).toBe('token');
            expect(message.clientKey).toBe('key');
        });

        it('should serialize to JSON with correct field names', () => {
            const message = create(AuthStartRequestSchema, {
                authToken: 'token',
                clientKey: 'key',
            });

            const json = toJson(AuthStartRequestSchema, message);

            // Default is camelCase in proto-es v2
            expect(json).toMatchObject({
                authToken: 'token',
                clientKey: 'key',
            });
        });
    });
});
