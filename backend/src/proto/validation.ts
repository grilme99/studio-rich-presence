/**
 * Request/response validation using generated protobuf types.
 *
 * Uses @bufbuild/protobuf's fromJson/toJson for parsing and validation.
 */

import { create, fromJson, toJson, type MessageShape, type DescMessage } from '@bufbuild/protobuf';
import { Context, MiddlewareHandler } from 'hono';
import type { Env } from '../env';
import { errorResponse, ErrorCode } from './errors';

// Re-export generated types for convenience
export {
    type AuthStartRequest,
    type AuthStartResponse,
    type AuthCompleteRequest,
    type AuthCompleteResponse,
    type AuthSseEvent,
    AuthStartRequestSchema,
    AuthStartResponseSchema,
    AuthCompleteRequestSchema,
    AuthCompleteResponseSchema,
    AuthSseEventSchema,
    AuthEventType,
} from '../generated/auth_pb';

export {
    type ErrorResponse,
    type Timestamp,
    ErrorResponseSchema,
    TimestampSchema,
    ErrorCode as ProtoErrorCode,
} from '../generated/common_pb';

export {
    type UpdatePresenceRequest,
    type UpdatePresenceResponse,
    type ClearPresenceRequest,
    type ClearPresenceResponse,
    type DiscordPresence,
    type PresenceTimestamps,
    type PresenceAssets,
    UpdatePresenceRequestSchema,
    UpdatePresenceResponseSchema,
    ClearPresenceRequestSchema,
    ClearPresenceResponseSchema,
    DiscordPresenceSchema,
    PresenceTimestampsSchema,
    PresenceAssetsSchema,
} from '../generated/presence_pb';

/**
 * Parse and validate JSON request body against a protobuf schema.
 *
 * @param schema The protobuf message schema
 * @param json The JSON data to parse
 * @returns The validated message
 * @throws Error if validation fails
 */
export function parseRequest<T extends DescMessage>(
    schema: T,
    json: unknown
): MessageShape<T> {
    // Handle empty/null body - create empty message
    if (json === null || json === undefined) {
        return create(schema);
    }

    // fromJson validates and parses the JSON
    // ignoreUnknownFields allows clients to send extra fields without errors
    return fromJson(schema, json as any, { ignoreUnknownFields: true });
}

/**
 * Serialize a protobuf message to JSON for response.
 *
 * @param schema The protobuf message schema
 * @param message The message to serialize
 * @returns JSON object
 */
export function serializeResponse<T extends DescMessage>(
    schema: T,
    message: MessageShape<T>
): object {
    return toJson(schema, message) as object;
}

/**
 * Create a middleware that validates the request body against a protobuf schema.
 *
 * @param schema The protobuf message schema to validate against
 * @returns Hono middleware that sets validated body in context
 */
export function validateBody<T extends DescMessage>(
    schema: T
): MiddlewareHandler<{ Bindings: Env; Variables: { validatedBody: MessageShape<T> } }> {
    return async (c, next) => {
        let body: unknown;

        try {
            body = await c.req.json();
        } catch {
            // Empty or invalid JSON - pass undefined to parser
            body = undefined;
        }

        try {
            const validated = parseRequest(schema, body);
            c.set('validatedBody', validated);
            await next();
        } catch (err) {
            // fromJson throws on validation errors
            const message = err instanceof Error ? err.message : 'Invalid request body';

            return errorResponse(
                c as any,
                400,
                ErrorCode.INVALID_REQUEST,
                message
            );
        }
    };
}

/**
 * Get the validated body from context.
 * Uses `any` for the context type to work with middleware-extended contexts.
 */
export function getValidatedBody<T extends DescMessage>(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    c: Context<any, any, any>
): MessageShape<T> {
    return c.get('validatedBody') as MessageShape<T>;
}

/**
 * Helper to create and serialize a response message.
 */
export function createResponse<T extends DescMessage>(
    schema: T,
    data: Partial<MessageShape<T>>
): object {
    const message = create(schema, data as any);
    return serializeResponse(schema, message);
}

