/**
 * Error response utilities for protobuf-based API.
 */

import { Context } from 'hono';

/**
 * Error codes matching the protobuf ErrorCode enum.
 */
export enum ErrorCode {
    UNSPECIFIED = 'UNSPECIFIED',
    INVALID_REQUEST = 'INVALID_REQUEST',
    UNAUTHORIZED = 'UNAUTHORIZED',
    FORBIDDEN = 'FORBIDDEN',
    NOT_FOUND = 'NOT_FOUND',
    RATE_LIMITED = 'RATE_LIMITED',
    INTERNAL = 'INTERNAL',
    DISCORD_API_ERROR = 'DISCORD_API_ERROR',
    SESSION_EXPIRED = 'SESSION_EXPIRED',
    INVALID_COMPLETION_CODE = 'INVALID_COMPLETION_CODE',
}

/**
 * Error response structure matching the protobuf ErrorResponse message.
 */
export interface ErrorResponse {
    code: ErrorCode;
    message: string;
    details?: Record<string, string>;
}

// Use a generic context type to avoid type conflicts with route-specific variables
type AnyContext = Context<any, any, any>;

/**
 * Create a JSON error response.
 */
export function errorResponse(
    c: AnyContext,
    status: number,
    code: ErrorCode,
    message: string,
    details?: Record<string, string>
): Response {
    const body: ErrorResponse = { code, message };
    if (details) {
        body.details = details;
    }
    return c.json(body, status as any);
}

/**
 * Common error responses.
 */
export const errors = {
    invalidRequest: (c: AnyContext, message: string, details?: Record<string, string>) =>
        errorResponse(c, 400, ErrorCode.INVALID_REQUEST, message, details),

    unauthorized: (c: AnyContext, message = 'Invalid auth token') =>
        errorResponse(c, 401, ErrorCode.UNAUTHORIZED, message),

    forbidden: (c: AnyContext, message = 'Access denied') =>
        errorResponse(c, 403, ErrorCode.FORBIDDEN, message),

    notFound: (c: AnyContext, message = 'Resource not found') =>
        errorResponse(c, 404, ErrorCode.NOT_FOUND, message),

    rateLimited: (c: AnyContext, retryAfter: number) =>
        errorResponse(c, 429, ErrorCode.RATE_LIMITED, 'Too many requests', {
            retry_after: retryAfter.toString(),
        }),

    internal: (c: AnyContext, message = 'Internal server error') =>
        errorResponse(c, 500, ErrorCode.INTERNAL, message),

    sessionExpired: (c: AnyContext) =>
        errorResponse(c, 400, ErrorCode.SESSION_EXPIRED, 'Auth session has expired'),

    invalidCompletionCode: (c: AnyContext) =>
        errorResponse(c, 400, ErrorCode.INVALID_COMPLETION_CODE, 'Invalid completion code'),
};

