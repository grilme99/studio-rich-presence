/**
 * Protocol buffer validation and serialization utilities.
 *
 * This module provides runtime validation for API request/response bodies
 * based on the protobuf schema definitions in /protos.
 *
 * The actual generated types are in src/generated/ after running:
 *   npm run proto:generate
 */

export * from './validation';
export { errors, errorResponse, ErrorCode } from './errors';
