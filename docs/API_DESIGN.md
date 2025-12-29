# API Design

## Overview

This document outlines the API design for Studio Rich Presence, a Roblox Studio plugin that updates Discord rich presence. The system supports multiple Discord accounts per plugin installation.

### Technology Stack

- **Backend**: Cloudflare Workers with Hono framework
- **Database**: Cloudflare D1 (SQLite)
- **API Format**: Protocol Buffers (protobuf) for type-safe, efficient serialization
- **Real-time**: Server-Sent Events via KV polling
- **Telemetry**: Posthog for analytics
- **QR Codes**: Client-side generation (Luau library in plugin)

### Privacy-First Design

**No plaintext PII is stored in the database.** We intentionally do not store:

- Discord user IDs in plaintext (only SHA-256 hashed for deduplication)
- Discord usernames
- Roblox user IDs
- Any platform-specific identifiers in plaintext

This means if the database is ever breached, attackers cannot identify which Discord accounts belong to which users:

- **Hashed Discord IDs** - SHA-256 hash with server salt, cannot be reversed to get actual ID
- **Encrypted OAuth tokens** - useless without client key (stored only in the plugin)

When the plugin needs account details (username, avatar), we fetch them on-demand from Discord's API using the stored access tokens.

### Key Security Features

- **Token Rotation with Acknowledgment**: Auth tokens are rotated on presence updates with a safe acknowledgment protocol that prevents token loss on network failures
- **Zero-Knowledge Encryption**: Discord tokens encrypted with server + client key (HKDF derived)
- **PKCE**: OAuth flow uses Proof Key for Code Exchange

---

## Design Feedback & Analysis

### What Works Well

1. **Separation of concerns**: Backend-managed OAuth flow keeps Discord credentials secure - the plugin never sees OAuth tokens directly.
2. **SSE for real-time updates**: Roblox Studio now supports Server-Sent Events via `WebStreamClient`, enabling real-time auth completion notifications without polling overhead.
3. **Multi-account support**: Supporting multiple Discord accounts per installation is a great UX feature.
4. **Short link pattern**: Users copying a link is more reliable than attempting to open a browser from Luau.
5. **QR code support**: The same short link can be displayed as a QR code, allowing users to scan with their phone and complete the OAuth flow on mobile.

### Security Concerns Identified

| Issue | Severity | Description | Mitigation |
| ----- | -------- | ----------- | ---------- |
| Code Exposure | Medium | The random code in the short link is visible to the user and could be shared | Use short expiration (5 min), single-use enforcement, rate limiting |
| Token Lifetime | Medium | Long-lived backend auth tokens increase blast radius if leaked | Consider refresh token rotation or periodic re-auth |
| SSE Connection Hijack | Low | If attacker knows the code, they could listen on SSE | Code is single-use, expires quickly, and auth token only sent once |
| Completion Code Alone | ~~Medium~~ **Mitigated** | 5-digit codes have only 100k combinations | Requires session code (256-bit) + completion code - brute force impossible |
| PKCE Missing | High | Standard OAuth without PKCE is vulnerable to interception | **Must implement PKCE** for Discord OAuth |
| No Rate Limiting | High | SSE and auth endpoints could be abused | Implement per-IP and per-token rate limits |
| Discord Token Theft | High | If attacker gets database + server secret, can decrypt tokens | **Zero-knowledge encryption** - also requires client key from plugin |

### Critical Recommendations

1. **Implement PKCE**: Discord supports PKCE (Proof Key for Code Exchange). The backend should generate the `code_verifier` and `code_challenge` since it initiates and completes the OAuth flow - this is secure since the plugin never participates in the OAuth redirect.

2. **Use SSE over Polling**: With Roblox Studio's `WebStreamClient` supporting SSE, the plugin should subscribe to an SSE endpoint for real-time auth completion notifications. This eliminates polling overhead and provides instant feedback.

3. **Token Rotation with Safe Acknowledgment**: Auth tokens are rotated on presence updates, but use a two-phase commit to prevent token loss on network failures. The response includes a pending token that must be acknowledged before the old token is invalidated. This limits the window of exposure if a token is compromised while ensuring clients never lose access due to transient failures.

### Design Decisions

- **No Account Recovery**: Each plugin installation is independent. If a user reinstalls Studio or switches machines, they simply re-link their Discord accounts. This keeps the system simple and avoids security concerns around account takeover.

---

## Protocol Buffers Schema

All API requests and responses use Protocol Buffers for type-safe, efficient serialization. The plugin uses a Luau protobuf library to encode/decode messages.

### Common Types (`common.proto`)

```protobuf
syntax = "proto3";
package srp;

// Error response body (only sent on 4xx/5xx status codes)
message ErrorResponse {
  ErrorCode code = 1;
  string message = 2;
  map<string, string> details = 3;  // Additional context
}

enum ErrorCode {
  ERROR_CODE_UNSPECIFIED = 0;
  ERROR_CODE_INVALID_REQUEST = 1;
  ERROR_CODE_UNAUTHORIZED = 2;
  ERROR_CODE_FORBIDDEN = 3;
  ERROR_CODE_NOT_FOUND = 4;
  ERROR_CODE_RATE_LIMITED = 5;
  ERROR_CODE_INTERNAL = 6;
  ERROR_CODE_DISCORD_API_ERROR = 7;
  ERROR_CODE_SESSION_EXPIRED = 8;
  ERROR_CODE_INVALID_COMPLETION_CODE = 9;
}

// Timestamps use Unix milliseconds
message Timestamp {
  int64 unix_ms = 1;
}
```

### Auth Types (`auth.proto`)

```protobuf
syntax = "proto3";
package srp.auth;

import "common.proto";

// POST /api/auth/start
message AuthStartRequest {
  optional string auth_token = 1;   // Existing token if linking additional account
  optional string client_key = 2;   // Required if auth_token provided
}

message AuthStartResponse {
  string code = 1;                  // Session code (256-bit, base64url)
  string url = 2;                   // Auth link URL
  string sse_url = 3;               // SSE endpoint URL
  int32 expires_in_seconds = 4;     // Time until expiration (300s)
}

// POST /api/auth/complete
message AuthCompleteRequest {
  string code = 1;                  // Session code
  string completion_code = 2;       // 5-digit code from success page
}

message AuthCompleteResponse {
  optional string auth_token = 1;   // New user only
  optional string client_key = 2;   // New user only
}

// SSE Events (JSON-encoded in SSE data field)
message AuthSseEvent {
  AuthEventType type = 1;
  optional AuthCompleteResponse completion = 2;
  optional string error_message = 3;
}

enum AuthEventType {
  AUTH_EVENT_TYPE_UNSPECIFIED = 0;
  AUTH_EVENT_TYPE_HEARTBEAT = 1;
  AUTH_EVENT_TYPE_STARTED = 2;      // User clicked link, flow started
  AUTH_EVENT_TYPE_COMPLETED = 3;
  AUTH_EVENT_TYPE_FAILED = 4;
  AUTH_EVENT_TYPE_EXPIRED = 5;
}
```

### Accounts Types (`accounts.proto`)

```protobuf
syntax = "proto3";
package srp.accounts;

import "common.proto";

// GET /api/accounts
message GetAccountsRequest {
  // Auth via header: Authorization: Bearer <token>
  // Client key via header: X-Client-Key: <key>
}

message GetAccountsResponse {
  repeated DiscordAccount accounts = 1;
}

message DiscordAccount {
  string id = 1;                    // Internal UUID
  optional string username = 2;     // From Discord API (null if fetch failed)
  optional string display_name = 3; // global_name from Discord
  optional string avatar_url = 4;   // CDN URL
  srp.Timestamp linked_at = 5;
  optional string fetch_error = 6;  // Error message if Discord API failed
}

// DELETE /api/accounts/{id}
message DeleteAccountRequest {
  string account_id = 1;
}

message DeleteAccountResponse {
  // Empty on success
}

// DELETE /api/user
message DeleteUserRequest {
  // Auth via header
}

message DeleteUserResponse {
  // Empty on success
}
```

### Presence Types (`presence.proto`)

```protobuf
syntax = "proto3";
package srp.presence;

import "common.proto";

// POST /api/presence/update
// Header: X-Ack-Token (optional) - acknowledges pending token from previous response
message UpdatePresenceRequest {
  string auth_token = 1;
  string client_key = 2;
  DiscordPresence presence = 3;
}

message UpdatePresenceResponse {
  optional string pending_auth_token = 1;  // New pending token to acknowledge on next request
  int32 updated_accounts = 2;
  int32 failed_accounts = 3;
}

message DiscordPresence {
  optional string details = 1;      // Line 1 (e.g., "Editing MyGame")
  optional string state = 2;        // Line 2 (e.g., "Workspace: 1,234 parts")
  optional PresenceTimestamps timestamps = 3;
  optional PresenceAssets assets = 4;
}

message PresenceTimestamps {
  optional int64 start_unix = 1;    // Session start time
  optional int64 end_unix = 2;      // Optional end time
}

message PresenceAssets {
  optional string large_image = 1;  // Asset key or URL
  optional string large_text = 2;   // Hover text
  optional string small_image = 3;
  optional string small_text = 4;
}
```

### Telemetry Types (`telemetry.proto`)

```protobuf
syntax = "proto3";
package srp.telemetry;

import "common.proto";

// POST /api/telemetry/capture
message CaptureEventsRequest {
  string anonymous_id = 1;          // Anonymized user ID (hashed, 64 chars)
  repeated TelemetryEvent events = 2;
}

// Each event has a timestamp and exactly one event-specific payload
message TelemetryEvent {
  srp.Timestamp timestamp = 1;
  
  oneof event {
    // Plugin lifecycle
    PluginOpenedEvent plugin_opened = 10;
    PluginClosedEvent plugin_closed = 11;
    
    // Auth events
    AuthStartedEvent auth_started = 20;
    AuthCompletedEvent auth_completed = 21;
    AuthFailedEvent auth_failed = 22;
    
    // Account events
    AccountLinkedEvent account_linked = 30;
    AccountUnlinkedEvent account_unlinked = 31;
    AllDataClearedEvent all_data_cleared = 32;
    
    // Presence events
    PresenceUpdatedEvent presence_updated = 40;
    PresenceErrorEvent presence_error = 41;
    
    // Generic error
    ErrorEvent error = 100;
  }
}

// ============================================
// Plugin Lifecycle Events
// ============================================

message PluginOpenedEvent {
  string plugin_version = 1;        // e.g., "1.0.0"
  string studio_version = 2;        // e.g., "0.600.0.123456"
  int32 linked_account_count = 3;   // Number of linked Discord accounts
}

message PluginClosedEvent {
  int32 session_duration_seconds = 1;  // How long plugin was open
  int32 presence_update_count = 2;     // Number of presence updates sent
}

// ============================================
// Auth Events
// ============================================

message AuthStartedEvent {
  bool is_first_account = 1;        // True if no accounts linked yet
}

message AuthCompletedEvent {
  AuthMethod method = 1;            // How user completed auth
  bool is_first_account = 2;
  int32 time_to_complete_seconds = 3;  // Time from start to completion
}

message AuthFailedEvent {
  AuthMethod method = 1;
  AuthFailureReason reason = 2;
}

enum AuthMethod {
  AUTH_METHOD_UNSPECIFIED = 0;
  AUTH_METHOD_SSE = 1;              // Automatic via SSE
  AUTH_METHOD_CODE = 2;             // Manual code entry
}

enum AuthFailureReason {
  AUTH_FAILURE_REASON_UNSPECIFIED = 0;
  AUTH_FAILURE_REASON_USER_DENIED = 1;
  AUTH_FAILURE_REASON_EXPIRED = 2;
  AUTH_FAILURE_REASON_SSE_FAILED = 3;
  AUTH_FAILURE_REASON_INVALID_CODE = 4;
  AUTH_FAILURE_REASON_NETWORK_ERROR = 5;
}

// ============================================
// Account Events
// ============================================

message AccountLinkedEvent {
  int32 total_account_count = 1;    // Total accounts after linking
}

message AccountUnlinkedEvent {
  int32 total_account_count = 1;    // Total accounts after unlinking
}

message AllDataClearedEvent {
  int32 accounts_removed = 1;       // Number of accounts that were removed
}

// ============================================
// Presence Events
// ============================================

message PresenceUpdatedEvent {
  int32 account_count = 1;          // Number of accounts updated
  int32 successful_count = 2;       // Number that succeeded
  int32 failed_count = 3;           // Number that failed
}

message PresenceErrorEvent {
  PresenceErrorType error_type = 1;
  int32 account_count = 2;
}

enum PresenceErrorType {
  PRESENCE_ERROR_TYPE_UNSPECIFIED = 0;
  PRESENCE_ERROR_TYPE_UNAUTHORIZED = 1;     // Token invalid/expired
  PRESENCE_ERROR_TYPE_RATE_LIMITED = 2;     // Discord rate limit
  PRESENCE_ERROR_TYPE_DISCORD_API = 3;      // Discord API error
  PRESENCE_ERROR_TYPE_NETWORK = 4;          // Network failure
}

// ============================================
// Generic Error Event
// ============================================

message ErrorEvent {
  string error_code = 1;            // Application error code
  string context = 2;               // Where error occurred (e.g., "presence_update")
  optional string message = 3;      // Error message (sanitized, no PII)
}
```

---

## Error Handling & Response Format

API responses use standard HTTP status codes. Success responses return the data directly; error responses return error details.

### Response Format

```typescript
// Success (HTTP 200/201/204)
// Returns endpoint-specific data directly, no wrapper
{
  "code": "abc123xyz",
  "url": "https://...",
  "sse_url": "https://..."
}

// Error (HTTP 4xx/5xx)
// Returns error details
{
  "code": "UNAUTHORIZED",
  "message": "Invalid or expired auth token",
  "details": {
    "hint": "Token may have been rotated. Use the latest token from presence update response."
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request body or missing required fields |
| `UNAUTHORIZED` | 401 | Missing or invalid auth token |
| `FORBIDDEN` | 403 | Valid token but not permitted for this action |
| `NOT_FOUND` | 404 | Resource doesn't exist |
| `RATE_LIMITED` | 429 | Too many requests, try again later |
| `INTERNAL` | 500 | Server error (logged, not exposed to client) |
| `DISCORD_API_ERROR` | 502 | Discord API call failed |
| `SESSION_EXPIRED` | 410 | Auth session expired, restart flow |
| `INVALID_COMPLETION_CODE` | 400 | Wrong completion code entered |

### Hono Error Handling Middleware

```typescript
// src/middleware/errorHandler.ts

import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public statusCode: number = 400,
    public details?: Record<string, string>
  ) {
    super(message);
  }
}

export const errorHandler = async (c: Context, next: Next) => {
  try {
    await next();
  } catch (error) {
    if (error instanceof ApiError) {
      return c.json({
        code: error.code,
        message: error.message,
        details: error.details,
      }, error.statusCode);
    }
    
    if (error instanceof HTTPException) {
      return c.json({
        code: 'INTERNAL',
        message: 'An unexpected error occurred',
      }, error.status);
    }
    
    // Log unexpected errors
    console.error('Unexpected error:', error);
    
    return c.json({
      code: 'INTERNAL',
      message: 'An unexpected error occurred',
    }, 500);
  }
};

// Usage in routes:
app.use('*', errorHandler);

// Throwing errors:
throw new ApiError('UNAUTHORIZED', 'Invalid auth token', 401);
throw new ApiError('RATE_LIMITED', 'Too many requests', 429, {
  retry_after: '15',
});
```

### Plugin Error Handling

```lua
-- src/Api/handleApiResponse.luau

export type ApiError = {
  code: string,
  message: string,
  details: { [string]: string }?,
}

local function handleApiResponse<T>(response: HttpResponse): (boolean, T?, ApiError?)
  local isSuccess = response.StatusCode >= 200 and response.StatusCode < 300
  local body = HttpService:JSONDecode(response.Body)
  
  if isSuccess then
    return true, body, nil
  else
    return false, nil, body  -- Error response is the body itself
  end
end

-- Usage:
local success, data, error = handleApiResponse(response)
if not success then
  if error.code == "UNAUTHORIZED" then
    -- Token might be rotated, prompt re-auth
    promptReAuth()
  elseif error.code == "RATE_LIMITED" then
    -- Wait and retry
    local retryAfter = tonumber(error.details and error.details.retry_after) or 15
    task.wait(retryAfter)
  else
    -- Show error to user
    showError(error.message)
  end
end
```

---

## Data Model

### Database Schema (Cloudflare D1 / KV)

```
┌─────────────────────────────────────────────────────────────────┐
│                           users                                  │
├─────────────────────────────────────────────────────────────────┤
│ id                      │ TEXT PRIMARY KEY  │ UUID v4            │
│ auth_token_hash         │ TEXT NOT NULL     │ HMAC-SHA256 (lookupable) │
│ pending_token_hash      │ TEXT              │ HMAC-SHA256 (lookupable) │
│ pending_token_expires   │ INTEGER           │ Unix timestamp     │
│ created_at              │ INTEGER NOT NULL  │ Unix timestamp     │
│ updated_at              │ INTEGER NOT NULL  │ Unix timestamp     │
│ last_activity_at        │ INTEGER NOT NULL  │ Unix timestamp     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ 1:N
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      discord_accounts                            │
├─────────────────────────────────────────────────────────────────┤
│ id                    │ TEXT PRIMARY KEY  │ UUID v4             │
│ user_id               │ TEXT NOT NULL     │ FK → users.id       │
│ discord_user_id_hash  │ TEXT NOT NULL     │ SHA-256(id + salt)  │
│ access_token_enc      │ TEXT NOT NULL     │ Encrypted OAuth tok │
│ refresh_token_enc     │ TEXT NOT NULL     │ Encrypted refresh   │
│ token_expires_at      │ INTEGER NOT NULL  │ Unix timestamp      │
│ created_at            │ INTEGER NOT NULL  │ Unix timestamp      │
│ updated_at            │ INTEGER NOT NULL  │ Unix timestamp      │
│ UNIQUE(discord_user_id_hash)  -- Global uniqueness              │
└─────────────────────────────────────────────────────────────────┘

Note: `discord_user_id_hash` is SHA-256(discord_user_id + server_salt). This enables:
- Instant duplicate detection without API calls
- Global uniqueness (one Discord account = one link at a time)
- Privacy preservation (hash cannot be reversed)
- Cross-user unlinking (if re-linked, old link is removed)

┌─────────────────────────────────────────────────────────────────┐
│                      auth_sessions                               │
├─────────────────────────────────────────────────────────────────┤
│ code              │ TEXT PRIMARY KEY  │ Random URL-safe string  │
│ user_id           │ TEXT              │ FK → users.id (nullable)│
│ state             │ TEXT NOT NULL     │ pending/started/completed/failed │
│ pkce_code_verifier│ TEXT NOT NULL     │ PKCE verifier           │
│ completion_code   │ TEXT              │ 5-digit manual entry code│
│ result_token      │ TEXT              │ New auth token if created│
│ result_client_key │ TEXT              │ New client key if created│
│ error_message     │ TEXT              │ Error details if failed │
│ created_at        │ INTEGER NOT NULL  │ Unix timestamp          │
│ expires_at        │ INTEGER NOT NULL  │ created_at + 5 minutes  │
└─────────────────────────────────────────────────────────────────┘

Note: `code` is the primary key—no separate `id` field needed since sessions are
short-lived (5 min) and all operations are keyed by the URL-exposed code.
```

### Key Design Decisions

1. **`auth_token_hash`**: Store deterministic HMAC-SHA256 hashes for direct database lookup. Auth tokens are 256-bit random values, so per-token salts are unnecessary—the server pepper provides sufficient protection. This enables O(1) authentication via `WHERE auth_token_hash = ?`.
2. **`pending_token_hash` / `pending_token_expires`**: Two-phase token rotation. Pending tokens must be acknowledged before becoming active. Expires after 5 minutes if not acknowledged, allowing the old token to continue working.
3. **`access_token_enc`**: Encrypt Discord tokens using a key derived from BOTH server secret AND client-provided key (zero-knowledge storage).
4. **`auth_sessions.user_id`**: Nullable because first-time users don't have an account yet.
5. **`result_token`**: Only populated for new users; existing users already have their token.
6. **`completion_code`**: Short 5-digit code shown to user on success page for manual entry fallback.
7. **`last_activity_at`**: Updated on every authenticated API call. Used for automatic cleanup of inactive accounts.

---

## Authentication Flow

### Sequence Diagram (SSE with Manual Code Fallback)

```
┌──────────┐          ┌──────────┐          ┌──────────┐          ┌──────────┐
│  Plugin  │          │  Backend │          │  Discord │          │  User    │
└────┬─────┘          └────┬─────┘          └────┬─────┘          └────┬─────┘
     │                     │                     │                     │
     │ POST /auth/start    │                     │                     │
     │ {auth_token?,       │                     │                     │
     │  client_key?}       │                     │                     │
     │────────────────────>│                     │                     │
     │                     │                     │                     │
     │                     │ Generate:           │                     │
     │                     │ - code (URL-safe)   │                     │
     │                     │ - code_verifier     │                     │
     │                     │ - completion_code   │                     │
     │                     │ - client_key (new)  │                     │
     │                     │ Store auth_session  │                     │
     │                     │                     │                     │
     │ {short_url, code,   │                     │                     │
     │  sse_url}           │                     │                     │
     │<────────────────────│                     │                     │
     │                     │                     │                     │
     │ GET /auth/sse/:code │                     │                     │
     │ (SSE connection)    │                     │                     │
     │════════════════════>│                     │                     │
     │                     │                     │                     │
     │─────────────────────────────────────────────────────────────────>
     │                     │                     │         Display URL │
     │                     │                     │         User copies │
     │                     │                     │                     │
     │                     │                     │<────────────────────│
     │                     │                     │      Opens URL      │
     │                     │                     │                     │
     │                     │<────────────────────│                     │
     │                     │ GET /auth/link/:code│                     │
     │                     │                     │                     │
     │                     │ 302 Redirect        │                     │
     │                     │────────────────────>│                     │
     │                     │                     │────────────────────>│
     │                     │                     │    OAuth consent    │
     │                     │                     │<────────────────────│
     │                     │                     │    User approves    │
     │                     │                     │                     │
     │                     │<────────────────────│                     │
     │                     │ GET /auth/callback  │                     │
     │                     │ ?code=X&state=code  │                     │
     │                     │                     │                     │
     │                     │ Exchange code +     │                     │
     │                     │ store encrypted     │                     │
     │                     │ Discord tokens      │                     │
     │                     │────────────────────>│                     │
     │                     │<────────────────────│                     │
     │                     │                     │                     │
     │                     │                     │────────────────────>│
     │                     │                     │  Success page with  │
     │                     │                     │  code: "12345"      │
     │                     │                     │                     │
     ├─────────────────────┼─────────────────────┼─────────────────────┤
     │        EITHER: SSE notifies plugin automatically                │
     ├─────────────────────┼─────────────────────┼─────────────────────┤
     │                     │                     │                     │
     │ SSE: event=complete │                     │                     │
     │ {auth_token?,       │                     │                     │
     │  client_key?}       │                     │                     │
     │<════════════════════│                     │                     │
     │                     │                     │                     │
     ├─────────────────────┼─────────────────────┼─────────────────────┤
     │        OR: User enters code manually (if SSE fails)             │
     ├─────────────────────┼─────────────────────┼─────────────────────┤
     │                     │                     │                     │
     │                     │                     │<────────────────────│
     │                     │                     │  User reads "12345" │
     │<────────────────────────────────────────────────────────────────│
     │                     │                     │  User enters code   │
     │                     │                     │                     │
     │ POST /auth/complete │                     │                     │
     │ {completion_code}   │                     │                     │
     │────────────────────>│                     │                     │
     │                     │                     │                     │
     │ {auth_token?,       │                     │                     │
     │  client_key?}       │                     │                     │
     │<────────────────────│                     │                     │
     │                     │                     │                     │
     ▼                     ▼                     ▼                     ▼
```

**Legend:** `═══` represents the persistent SSE connection

---

## API Endpoints

### `POST /api/auth/start`

Initiates the Discord linking flow.

**Request:**

```json
{
  "auth_token": "existing-token-if-any",  // Optional - for linking additional accounts
  "client_key": "existing-client-key"     // Required if auth_token provided
}
```

**Response:**

```json
{
  "code": "abc123xyz",
  "url": "https://srp.example.com/auth/link/abc123xyz",
  "sse_url": "https://srp.example.com/auth/sse/abc123xyz",
  "expires_in": 300
}
```

Note: QR code is generated client-side from `url`, no server endpoint needed.

**Error Response (401):**

```json
{
  "code": "UNAUTHORIZED",
  "message": "Invalid auth token"
}
```

**Logic:**

1. If `auth_token` provided, validate it and get `user_id`; require `client_key` for existing users
2. Generate cryptographically random `code` (32 bytes, base64url encoded)
3. Generate PKCE `code_verifier` (32 bytes) and `code_challenge` (SHA-256)
4. Generate 5-digit `completion_code` for manual fallback
5. If new user, generate `client_key` (32 bytes) to be returned on completion
6. Create `auth_session` record with 5-minute expiration
7. Return short URL for user to visit and SSE URL for real-time updates

**Rate Limiting:** 10 requests per minute per IP

**QR Code Display:** The plugin generates the QR code client-side from the `url`:

1. Copyable text link  
2. QR code generated locally in Luau (no server round-trip)

This allows users to complete the OAuth flow on their mobile device if preferred.

---

## QR Code & Mobile OAuth Flow

### How It Works

The same URL returned by `/auth/start` works for both desktop and mobile:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Plugin UI                                    │
│  ┌─────────────┐                                                │
│  │ ▄▄▄▄▄ ▄▄▄▄▄ │  Link your Discord account:                    │
│  │ █   █ █   █ │                                                │
│  │ █ ▄▄█ █▄▄ █ │  • Scan QR code with your phone, OR            │
│  │ █   █ █   █ │  • Copy link: https://srp.example.com/auth/... │
│  │ ▀▀▀▀▀ ▀▀▀▀▀ │                                                │
│  └─────────────┘  [Copy Link]                                   │
│                                                                  │
│  Or enter code from success page: [_____] [Submit]              │
└─────────────────────────────────────────────────────────────────┘
```

### Mobile Flow

1. User scans QR code → opens in mobile browser
2. Discord OAuth page loads (may prompt to open Discord app)
3. User authorizes in Discord app or mobile browser
4. Redirect to callback → success page with completion code
5. **Either**:
   - SSE notifies plugin automatically (if connection alive)
   - User types 5-digit code into plugin (if SSE failed)

### Discord Mobile App Behavior

Discord's OAuth2 flow works on mobile:

- If Discord app is installed: Browser may offer to open Discord app for authorization
- If not installed: OAuth completes in mobile browser
- Either way, the redirect back to our callback works normally

**No special API changes needed** - the same flow works for QR code scanning.

### Plugin QR Code Generation (Client-Side)

QR codes are generated entirely client-side in Luau, eliminating a server round-trip and reducing latency.

**Luau Implementation:**

```lua
-- Use a Luau QR code library (e.g., qrcode-lua or similar)
local QRCode = require(Plugin.Packages.QRCode)

local function generateQRCode(url: string): ImageLabel
  local qrData = QRCode.encode(url, {
    errorCorrection = "M",  -- Medium error correction
    minVersion = 1,
  })
  
  -- Convert QR matrix to ImageLabel or render to EditableImage
  local image = Instance.new("ImageLabel")
  image.Size = UDim2.fromOffset(200, 200)
  
  -- Render QR code pixels...
  -- (Implementation depends on chosen library)
  
  return image
end

-- Usage in auth flow:
local function showAuthUI(authResponse)
  local qrImage = generateQRCode(authResponse.url)
  qrImage.Parent = authDialog.QRCodeContainer
end
```

**Benefits of Client-Side Generation:**

- No additional HTTP request needed
- Instant display after receiving auth URL
- Works offline (QR generation doesn't need network)
- Reduces server load

---

### `GET /auth/link/:code`

User visits this URL in their browser. Redirects to Discord OAuth.

**Response:** 302 redirect to Discord OAuth URL

**Logic:**

1. Validate `code` exists and is not expired
2. Check `state` is `pending` (prevent reuse)
3. **Update session state to `started`** (triggers SSE "started" event)
4. Build Discord OAuth URL:
   - `client_id`: Your Discord app client ID
   - `redirect_uri`: `https://srp.example.com/auth/callback`
   - `response_type`: `code`
   - `scope`: `identify activities.write`
   - `state`: The `code` (links callback back to session)
   - `code_challenge`: From session
   - `code_challenge_method`: `S256`
5. Redirect user to Discord

**Hono Implementation:**

```typescript
app.get('/auth/link/:code', async (c) => {
  const { code } = c.req.param();
  
  const session = await getAuthSession(c.env.DB, code);
  if (!session || session.expires_at < Date.now()) {
    return c.html(renderErrorPage('Link expired. Please start over.'), 404);
  }
  
  if (session.state !== 'pending') {
    return c.html(renderErrorPage('This link has already been used.'), 400);
  }
  
  // Mark as started - SSE will pick this up
  await c.env.DB.prepare(`
    UPDATE auth_sessions SET state = 'started' WHERE code = ?
  `).bind(code).run();
  
  // Build Discord OAuth URL
  const params = new URLSearchParams({
    client_id: c.env.DISCORD_CLIENT_ID,
    redirect_uri: c.env.DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify activities.write',
    state: code,
    code_challenge: session.code_challenge,
    code_challenge_method: 'S256',
  });
  
  return c.redirect(`https://discord.com/oauth2/authorize?${params}`);
});
```

---

### `GET /auth/callback`

Discord redirects here after user authorization.

**Query Parameters:**

- `code`: Discord authorization code
- `state`: Our session code

**Response:** HTML success/error page

**Logic:**

1. Validate `state` matches a pending `auth_session`
2. Exchange Discord `code` for tokens using PKCE:

   ```http
   POST https://discord.com/api/oauth2/token
   Content-Type: application/x-www-form-urlencoded
   
   client_id=...&
   client_secret=...&
   grant_type=authorization_code&
   code=...&
   redirect_uri=...&
   code_verifier=...
   ```

3. Fetch Discord user info: `GET https://discord.com/api/users/@me` (only to verify token works, **do not store**)
4. If `auth_session.user_id` is null (new user):
   - Create new `user` with generated auth token
   - Store auth token hash
   - Generate new `client_key` and store in session
   - Set `result_token` and `result_client_key` in session
5. Else (existing user linking new Discord):
   - Use existing `user_id` and `client_key` from session
6. Derive encryption key using HKDF(server_secret, client_key, user_id)
7. Encrypt Discord OAuth tokens with derived key
8. Handle Discord account deduplication (instant via hash, with cross-user unlinking):

   ```typescript
   const discordUserId = discordUserResponse.id; // From step 3
   const discordUserIdHash = await hashDiscordId(discordUserId, env.DISCORD_ID_SALT);
   
   // Check if this Discord account is linked ANYWHERE (any user) - instant O(1) lookup
   const existingLink = await env.DB.prepare(`
     SELECT id, user_id FROM discord_accounts WHERE discord_user_id_hash = ?
   `).bind(discordUserIdHash).first<{ id: string; user_id: string }>();
   
   if (existingLink) {
     if (existingLink.user_id === userId) {
       // Same user re-linking same Discord account - just update tokens
       await updateDiscordAccount(existingLink.id, encryptedTokens);
     } else {
       // Different user! The person with Discord credentials wins.
       // Delete old link and create new one for this user.
       await env.DB.prepare(`DELETE FROM discord_accounts WHERE id = ?`)
         .bind(existingLink.id).run();
       await createDiscordAccount(userId, discordUserIdHash, encryptedTokens);
     }
   } else {
     // New Discord account, create link
     await createDiscordAccount(userId, discordUserIdHash, encryptedTokens);
   }
   ```

   **Cross-user unlinking rationale**: If someone has the Discord credentials to complete OAuth, they are the rightful owner of that Discord account. The previous link (possibly from a shared computer, sold account, or compromised token) should be invalidated.
9. Update `auth_session.state` to `completed`
10. Return success HTML page displaying the `completion_code` (e.g., "Your code: **12345**")

---

### `GET /auth/sse/:code`

Server-Sent Events endpoint for real-time auth flow updates. The plugin connects to this immediately after receiving the code from `/auth/start`.

**Implementation:** Uses KV polling internally - the SSE handler polls KV/D1 every 1-2 seconds for state changes. A few seconds of latency is acceptable for this use case.

**Response:** `Content-Type: text/event-stream`

**Event Types:**

```
event: heartbeat
data: {}

event: started
data: {}

event: completed
data: {"auth_token": "new-token", "client_key": "new-key"}

event: completed
data: {}

event: failed
data: {"error": "User denied authorization"}

event: expired
data: {}
```

**Event Descriptions:**

| Event | Trigger | Plugin Action |
|-------|---------|---------------|
| `heartbeat` | Every 20 seconds | Keep connection alive |
| `started` | User clicked auth link | Switch to "waiting" UI |
| `completed` | OAuth flow succeeded | Store token, show success |
| `failed` | User denied or error | Show error message |
| `expired` | Session timed out | Prompt to restart |

**Logic (KV Polling Implementation):**

```typescript
// SSE endpoint with KV polling
app.get('/auth/sse/:code', async (c) => {
  const { code } = c.req.param();
  
  // Validate session
  const session = await getAuthSession(c.env.DB, code);
  if (!session || session.expires_at < Date.now()) {
    return sseResponse([{ event: 'expired', data: {} }]);
  }
  
  // If already in terminal state, return immediately
  if (session.state !== 'pending' && session.state !== 'started') {
    return sseResponse([formatSessionEvent(session)]);
  }
  
  // Stream with KV polling
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  
  const sendEvent = async (event: string, data: object) => {
    await writer.write(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
  };
  
  // Background polling loop
  c.executionCtx.waitUntil((async () => {
    const POLL_INTERVAL = 1500; // 1.5 seconds
    const HEARTBEAT_INTERVAL = 20000;
    let lastHeartbeat = Date.now();
    let lastState = session.state;
    
    try {
      while (true) {
        const currentSession = await getAuthSession(c.env.DB, code);
        
        // Check expiry
        if (!currentSession || currentSession.expires_at < Date.now()) {
          await sendEvent('expired', {});
          break;
        }
        
        // Check for state change
        if (currentSession.state !== lastState) {
          lastState = currentSession.state;
          
          if (currentSession.state === 'started') {
            await sendEvent('started', {});
            // Continue polling for completion
          } else {
            // Terminal state
            await sendEvent(currentSession.state, formatEventData(currentSession));
            break;
          }
        }
        
        // Send heartbeat
        if (Date.now() - lastHeartbeat > HEARTBEAT_INTERVAL) {
          await sendEvent('heartbeat', {});
          lastHeartbeat = Date.now();
        }
        
        await sleep(POLL_INTERVAL);
      }
    } finally {
      await writer.close();
    }
  })());
  
  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    },
  });
});
```

**Connection Behavior:**

- Connection timeout: 5 minutes (matches session expiry)
- Internal poll interval: 1.5 seconds (acceptable latency for auth flow)
- Heartbeat interval: 20 seconds (keeps Roblox connection alive)
- Auto-close on terminal event

**Rate Limiting:** 1 concurrent connection per code

---

### `POST /api/auth/complete`

Manual fallback for completing auth when SSE fails. Requires both:

1. The session `code` from `/auth/start` (only known to the plugin)
2. The 5-digit `completion_code` shown on the success page (only known to the user)

This two-factor approach prevents third parties from completing auth even if they guess the short code.

**Request:**

```json
{
  "code": "abc123xyz-long-session-code",
  "completion_code": "12345"
}
```

**Response (success - new user):**

```json
{
  "auth_token": "new-token-for-plugin-to-store",
  "client_key": "new-client-encryption-key"
}
```

**Response (200 - existing user):**

```json
{}
```

**Response (400 - invalid/expired):**

```json
{
  "code": "INVALID_COMPLETION_CODE",
  "message": "Invalid or expired code"
}
```

**Response (400 - not yet completed):**

```json
{
  "code": "SESSION_PENDING",
  "message": "Authentication not yet completed. Please finish the Discord authorization first."
}
```

**Logic:**

1. Look up `auth_session` by `code` (the long session code)
2. If not found or expired, return 400 error
3. Verify `completion_code` matches (constant-time comparison)
4. If session state is `pending`, return 400 "not yet completed" error
5. If session state is `failed`, return 400 with the error message
6. If session state is `completed`:
   - Return `auth_token` and `client_key` if new user (then clear from session)
   - Return empty object for existing user
7. Mark completion_code as used (prevent replay)

**Rate Limiting:** 10 requests per minute per IP

**Security Note:** The `code` parameter provides primary security (256-bit random, impossible to brute force). The `completion_code` is a UX convenience that lets the user confirm they completed the right flow - not the primary security mechanism.

---

### `POST /api/presence/update`

Updates Discord presence for all linked accounts. **Returns a new rotated auth token** that must be used for the next request.

**Request:**

```json
{
  "auth_token": "current-auth-token",
  "client_key": "plugin-stored-client-key",
  "presence": {
    "details": "Editing MyGame",
    "state": "Workspace: 1,234 parts",
    "timestamps": {
      "start": 1703789000
    },
    "assets": {
      "large_image": "roblox_studio",
      "large_text": "Roblox Studio"
    }
  }
}
```

**Request Headers (for token acknowledgment):**

```
X-Ack-Token: <pending_token_from_previous_response>
```

If this header is present and valid, the pending token is promoted to active before processing the request.

**Response:**

```json
{
  "pending_auth_token": "new-token-to-acknowledge",
  "updated_accounts": 2,
  "failed_accounts": 0
}
```

**Token Rotation with Safe Acknowledgment:**

The `pending_auth_token` is a proposed new token. The current token remains valid until the pending token is acknowledged. To acknowledge:

1. Include `X-Ack-Token: <pending_token>` header on the **next** request
2. Server validates both tokens (current via `Authorization`, pending via header)
3. If valid, pending becomes active, old is invalidated
4. If pending expires (5 min) without acknowledgment, it's discarded and old token continues working

This prevents token loss if the client crashes or loses network before receiving the response.

**Logic:**

1. Validate `auth_token` (constant-time hash comparison against `auth_token_hash`)
2. **Check for `X-Ack-Token` header** - if present and matches `pending_token_hash`:
   - Promote pending to active (`auth_token_hash = pending_token_hash`)
   - Clear pending fields
3. **Check for expired pending token** - if `pending_token_expires < now`, clear pending fields
4. **Generate new pending token** (only if no pending exists):
   - Create new token, store hash in `pending_token_hash`
   - Set `pending_token_expires` to now + 5 minutes
5. Derive encryption key from server secret + `client_key` using HKDF
6. Get all `discord_accounts` for user
7. For each account (in parallel):
   - Decrypt Discord tokens using derived key
   - Check if access token expired, refresh if needed (re-encrypt with same key)
   - Call Discord API to update presence
   - Track success/failure
8. Return summary with `pending_auth_token` (or omit if no new pending was generated)

**Hono Implementation:**

```typescript
const PENDING_TOKEN_TTL_MS = 5 * 60 * 1000; // 5 minutes

app.post('/api/presence/update', async (c) => {
  const body = await c.req.json<UpdatePresenceRequest>();
  
  // Validate current token
  const user = await validateAuthToken(c.env.DB, body.auth_token);
  if (!user) {
    return c.json({ code: 'UNAUTHORIZED', message: 'Invalid auth token' }, 401);
  }
  
  const now = Date.now();
  let pendingAuthToken: string | null = null;
  
  // Step 1: Check for token acknowledgment
  const ackToken = c.req.header('X-Ack-Token');
  if (ackToken && user.pending_token_hash) {
    const ackTokenHash = await hashToken(ackToken);
    if (constantTimeEqual(ackTokenHash, user.pending_token_hash)) {
      // Promote pending to active
      await c.env.DB.prepare(`
        UPDATE users 
        SET auth_token_hash = pending_token_hash,
            pending_token_hash = NULL,
            pending_token_expires = NULL,
            updated_at = ?
        WHERE id = ?
      `).bind(now, user.id).run();
      
      // Refresh user data after promotion
      user.auth_token_hash = user.pending_token_hash;
      user.pending_token_hash = null;
      user.pending_token_expires = null;
    }
    // If ack token doesn't match, ignore silently (could be stale)
  }
  
  // Step 2: Clean up expired pending token
  if (user.pending_token_expires && user.pending_token_expires < now) {
    await c.env.DB.prepare(`
      UPDATE users 
      SET pending_token_hash = NULL, pending_token_expires = NULL, updated_at = ?
      WHERE id = ?
    `).bind(now, user.id).run();
    user.pending_token_hash = null;
    user.pending_token_expires = null;
  }
  
  // Step 3: Generate new pending token if none exists
  if (!user.pending_token_hash) {
    pendingAuthToken = generateToken(32);
    const pendingTokenHash = await hashToken(pendingAuthToken);
    const pendingExpires = now + PENDING_TOKEN_TTL_MS;
    
    await c.env.DB.prepare(`
      UPDATE users 
      SET pending_token_hash = ?, pending_token_expires = ?, updated_at = ?
      WHERE id = ?
    `).bind(pendingTokenHash, pendingExpires, now, user.id).run();
  }
  
  // Step 4: Derive encryption key and update presence
  const encryptionKey = await deriveEncryptionKey(
    c.env.ENCRYPTION_KEY,
    body.client_key,
    user.id
  );
  
  const accounts = await getDiscordAccountsForUser(c.env.DB, user.id);
  const results = await Promise.allSettled(
    accounts.map(account => updateDiscordPresence(account, encryptionKey, body.presence))
  );
  
  const updated = results.filter(r => r.status === 'fulfilled').length;
  const failed = results.filter(r => r.status === 'rejected').length;
  
  // Update activity timestamp (fire and forget)
  c.executionCtx.waitUntil(updateLastActivity(c.env.DB, user.id));
  
  const response: UpdatePresenceResponse = {
    updated_accounts: updated,
    failed_accounts: failed,
  };
  
  // Only include pending token if we generated a new one
  if (pendingAuthToken) {
    response.pending_auth_token = pendingAuthToken;
  }
  
  return c.json(response);
});
```

**Rate Limiting:**

- 1 request per 15 seconds per user (Discord's rate limit for presence updates)

---

### Token Rotation Protocol

Token rotation limits the window of exposure if a token is compromised. However, naive rotation (invalidate old immediately) risks locking out clients if the response is lost. This protocol solves that with a two-phase acknowledgment.

#### State Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Token Rotation States                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    presence update    ┌───────────────────┐               │
│  │ Active Only  │ ───────────────────> │ Active + Pending   │               │
│  │              │                       │ (5 min TTL)        │               │
│  └──────────────┘                       └───────────────────┘               │
│         ▲                                     │       │                      │
│         │                                     │       │                      │
│         │  pending expires                    │       │ X-Ack-Token header   │
│         │  (5 min timeout)                    │       │ on next request      │
│         │                                     │       │                      │
│         └─────────────────────────────────────┘       ▼                      │
│                                               ┌───────────────────┐          │
│                                               │ Pending → Active  │          │
│                                               │ (old invalidated) │          │
│                                               └───────────────────┘          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Protocol Flow

```
Client                                  Server
   │                                       │
   │─── POST /presence/update ────────────>│
   │    Auth: Bearer <token_A>             │ Creates pending_token_B
   │                                       │ token_A still valid
   │<── { pending_auth_token: "B" } ───────│
   │                                       │
   │    (client stores B locally)          │
   │                                       │
   │─── POST /presence/update ────────────>│
   │    Auth: Bearer <token_A>             │ Validates A (still active)
   │    X-Ack-Token: <token_B>             │ Validates B matches pending
   │                                       │ Promotes B → active
   │                                       │ Invalidates A
   │                                       │ Creates pending_token_C
   │<── { pending_auth_token: "C" } ───────│
   │                                       │
```

#### Edge Cases

| Scenario | Behavior |
|----------|----------|
| Response lost before client receives pending token | Old token still works. Next request generates new pending. |
| Client crashes before acknowledging | Old token still works. Pending expires after 5 min. |
| Client sends stale X-Ack-Token | Silently ignored (hash won't match). Old token still works. |
| Attacker intercepts pending token | Can't acknowledge without also having the active token (required in Authorization header). |
| Multiple rapid requests | Only one pending at a time. Returns existing pending if not expired. |
| Pending token used directly | Rejected - pending is not valid for Authorization header. |

#### Security Properties

1. **Both tokens required for promotion**: Authorization header (current) + X-Ack-Token header (pending) must both be valid.
2. **Constant-time comparison**: All token comparisons use timing-safe equality checks.
3. **No replay after promotion**: Once acknowledged, old token hash is overwritten.
4. **Bounded exposure window**: Even without acknowledgment, pending expires in 5 minutes.

#### Plugin Implementation

```lua
-- src/Api/PresenceService.luau

local PresenceService = {}

-- Store pending token locally
local pendingToken: string? = nil

function PresenceService.updatePresence(authToken: string, clientKey: string, presence: DiscordPresence)
  local headers = {
    ["Content-Type"] = "application/json",
    ["Authorization"] = "Bearer " .. authToken,
  }
  
  -- Include acknowledgment header if we have a pending token
  if pendingToken then
    headers["X-Ack-Token"] = pendingToken
  end
  
  local response = HttpService:RequestAsync({
    Url = API_BASE .. "/api/presence/update",
    Method = "POST",
    Headers = headers,
    Body = HttpService:JSONEncode({
      auth_token = authToken,
      client_key = clientKey,
      presence = presence,
    }),
  })
  
  if response.StatusCode == 200 then
    local body = HttpService:JSONDecode(response.Body)
    
    -- Store new pending token for next request
    if body.pending_auth_token then
      pendingToken = body.pending_auth_token
      -- Also persist to local storage in case of crash
      PluginSettings:Set("pendingAuthToken", pendingToken)
    end
    
    return true, body
  else
    return false, HttpService:JSONDecode(response.Body)
  end
end

-- On plugin load, restore pending token
function PresenceService.initialize()
  pendingToken = PluginSettings:Get("pendingAuthToken")
end

return PresenceService
```

---

### `GET /api/accounts`

Lists linked Discord accounts for the user. Since we don't store Discord user details (privacy), this endpoint fetches them on-demand from Discord's API.

**Request Headers:**

```
Authorization: Bearer <auth_token>
X-Client-Key: <client_key>
```

**Response:**

```json
{
  "accounts": [
    {
      "id": "discord-account-uuid",
      "username": "cooluser",
      "display_name": "Cool User",
      "avatar_url": "https://cdn.discordapp.com/avatars/123456789/abcdef.png",
      "linked_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

**Response (Discord API temporarily unavailable):**

```json
{
  "accounts": [
    {
      "id": "discord-account-uuid",
      "username": null,
      "display_name": null,
      "avatar_url": null,
      "linked_at": "2024-01-15T10:30:00Z",
      "fetch_error": "Discord API unavailable"
    }
  ]
}
```

**Logic:**

1. Validate `auth_token` and get user
2. Derive encryption key from server secret + `client_key`
3. Get all `discord_accounts` for user
4. For each account (in parallel):
   - Decrypt access token
   - Refresh token if expired
   - Call Discord API: `GET https://discord.com/api/users/@me`
   - Extract username, global_name (display name), and avatar
   - Build avatar URL: `https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png`
5. Return aggregated results

**Discord API Response (for reference):**

```json
{
  "id": "123456789",
  "username": "cooluser",
  "global_name": "Cool User",
  "avatar": "abcdef123456",
  "discriminator": "0"
}
```

**Avatar URL Construction:**

```typescript
function buildAvatarUrl(userId: string, avatarHash: string | null): string | null {
  if (!avatarHash) {
    // Default avatar based on user ID
    const defaultIndex = (BigInt(userId) >> 22n) % 6n;
    return `https://cdn.discordapp.com/embed/avatars/${defaultIndex}.png`;
  }
  const ext = avatarHash.startsWith('a_') ? 'gif' : 'png';
  return `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.${ext}`;
}
```

**Rate Limiting:** 10 requests per minute per user

**Caching Consideration:** Consider caching Discord user info in memory (not database) for a short period (e.g., 5 minutes) to reduce API calls if plugin refreshes frequently.

---

### `DELETE /api/accounts/:id`

Unlinks a specific Discord account.

**Request Headers:**

```
Authorization: Bearer <auth_token>
```

**Response:** `204 No Content`

**Error Response (404):**

```json
{
  "code": "NOT_FOUND",
  "message": "Account not found"
}
```

---

### `DELETE /api/user`

Deletes all user data (the "clear all data" button).

**Request Headers:**

```
Authorization: Bearer <auth_token>
```

**Response:** `204 No Content`

**Logic:**

1. Validate auth token
2. Delete all `discord_accounts` for user
3. Delete `user` record
4. Delete any pending `auth_sessions` for user

---

## Automatic Account Cleanup

Accounts with no activity for 3 months are automatically deleted to:

- Reduce storage costs
- Minimize data retention (privacy)
- Clean up abandoned accounts

### What Counts as Activity

The `last_activity_at` timestamp is updated on these API calls:

| Endpoint | Updates Activity? |
|----------|-------------------|
| `POST /api/presence/update` | ✅ Yes |
| `GET /api/accounts` | ✅ Yes |
| `DELETE /api/accounts/:id` | ✅ Yes |
| `POST /api/auth/start` (existing user) | ✅ Yes |
| `POST /api/auth/start` (new user) | N/A (creates account) |
| `DELETE /api/user` | N/A (deletes account) |

### Cloudflare Cron Trigger Implementation

Cloudflare Workers support scheduled execution via Cron Triggers. The cleanup job runs daily and deletes accounts inactive for 90+ days.

**wrangler.jsonc configuration:**

```jsonc
{
  // ... existing config ...
  
  "triggers": {
    "crons": [
      "0 3 * * *"  // Run daily at 3:00 AM UTC
    ]
  }
}
```

**Worker implementation:**

```typescript
// src/index.ts

export default {
  // Regular HTTP handler
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return app.fetch(request, env, ctx);
  },
  
  // Scheduled handler for cron triggers
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(cleanupInactiveAccounts(env));
  },
};

// src/cleanup.ts

const INACTIVITY_THRESHOLD_DAYS = 90;

export async function cleanupInactiveAccounts(env: Env): Promise<void> {
  const thresholdTimestamp = Date.now() - (INACTIVITY_THRESHOLD_DAYS * 24 * 60 * 60 * 1000);
  
  // Find inactive users
  const inactiveUsers = await env.DB.prepare(`
    SELECT id FROM users 
    WHERE last_activity_at < ?
    LIMIT 100
  `).bind(thresholdTimestamp).all<{ id: string }>();
  
  if (!inactiveUsers.results || inactiveUsers.results.length === 0) {
    console.log('No inactive accounts to clean up');
    return;
  }
  
  console.log(`Found ${inactiveUsers.results.length} inactive accounts to delete`);
  
  // Delete in batches (D1 has transaction limits)
  for (const user of inactiveUsers.results) {
    try {
      // CASCADE will handle discord_accounts, but explicit for clarity
      await env.DB.batch([
        env.DB.prepare('DELETE FROM discord_accounts WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM auth_sessions WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
      ]);
      
      console.log(`Deleted inactive user: ${user.id}`);
    } catch (error) {
      console.error(`Failed to delete user ${user.id}:`, error);
    }
  }
  
  // If we hit the limit, there may be more - next run will catch them
  if (inactiveUsers.results.length === 100) {
    console.log('More inactive accounts may exist, will process in next run');
  }
}
```

### Expired Session Cleanup

Also clean up expired auth sessions (not tied to account inactivity):

```typescript
export async function cleanupExpiredSessions(env: Env): Promise<void> {
  const now = Date.now();
  
  const result = await env.DB.prepare(`
    DELETE FROM auth_sessions 
    WHERE expires_at < ?
  `).bind(now).run();
  
  console.log(`Deleted ${result.meta.changes} expired auth sessions`);
}

export async function cleanupExpiredPendingTokens(env: Env): Promise<void> {
  const now = Date.now();
  
  // Clear expired pending tokens (these are cleaned up during requests too,
  // but this catches any that weren't accessed)
  const result = await env.DB.prepare(`
    UPDATE users 
    SET pending_token_hash = NULL, pending_token_expires = NULL
    WHERE pending_token_expires IS NOT NULL AND pending_token_expires < ?
  `).bind(now).run();
  
  console.log(`Cleared ${result.meta.changes} expired pending tokens`);
}

// Call all in the scheduled handler
async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
  ctx.waitUntil(Promise.all([
    cleanupInactiveAccounts(env),
    cleanupExpiredSessions(env),
    cleanupExpiredPendingTokens(env),
  ]));
}
```

### Activity Tracking Middleware

Create middleware to update `last_activity_at` on authenticated requests:

```typescript
// src/middleware/activityTracker.ts

import { createMiddleware } from 'hono/factory';

export const trackActivity = createMiddleware<{ Bindings: Env }>(async (c, next) => {
  await next();
  
  // Only track successful authenticated requests
  if (c.res.status >= 200 && c.res.status < 300) {
    const userId = c.get('userId');
    if (userId) {
      // Fire and forget - don't block response
      c.executionCtx.waitUntil(
        c.env.DB.prepare(`
          UPDATE users SET last_activity_at = ? WHERE id = ?
        `).bind(Date.now(), userId).run()
      );
    }
  }
});

// Usage in router
app.use('/api/*', authMiddleware, trackActivity);
```

### Cleanup Observability

Monitor cleanup jobs via Cloudflare's observability:

```typescript
// Log structured data for monitoring
console.log(JSON.stringify({
  event: 'account_cleanup',
  deleted_count: inactiveUsers.results.length,
  threshold_days: INACTIVITY_THRESHOLD_DAYS,
  timestamp: new Date().toISOString(),
}));
```

View logs in Cloudflare Dashboard → Workers → Logs, or use `wrangler tail` during development.

### Configuration

| Setting | Value | Notes |
|---------|-------|-------|
| Inactivity threshold | 90 days | Configurable via env var if needed |
| Cron schedule | `0 3 * * *` | Daily at 3 AM UTC (low traffic) |
| Batch size | 100 | Prevents timeout on large cleanups |
| Session expiry cleanup | Same cron | Runs alongside account cleanup |

---

## Telemetry with Posthog

The plugin sends anonymous telemetry to help understand usage patterns and improve the product. Telemetry is opt-in and respects user privacy.

### Posthog Integration

Posthog is used for:

1. **Standard engagement KPIs** - DAU, MAU, retention (built into Posthog)
2. **Custom application events** - Auth flows, presence updates, errors

### Telemetry Endpoint

#### `POST /api/telemetry/capture`

Receives batched telemetry events from the plugin and forwards them to Posthog.

**Request:**

```json
{
  "anonymous_id": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
  "events": [
    {
      "timestamp": 1703789000000,
      "plugin_opened": {
        "plugin_version": "1.0.0",
        "studio_version": "0.600.0.123456",
        "linked_account_count": 2
      }
    },
    {
      "timestamp": 1703789005000,
      "auth_completed": {
        "method": "sse",
        "is_first_account": false,
        "time_to_complete_seconds": 15
      }
    },
    {
      "timestamp": 1703789010000,
      "presence_updated": {
        "account_count": 2,
        "successful_count": 2,
        "failed_count": 0
      }
    }
  ]
}
```

Each event has a `timestamp` and exactly **one** event-specific field (the `oneof` in protobuf). The server validates that the properties match the expected schema for that event type.

**Response:** `202 Accepted`

Empty body - telemetry is fire-and-forget.

**Logic:**

1. Validate event names against allowed list (protobuf enum)
2. Sanitize properties (remove any potential PII)
3. Forward to Posthog Capture API (async, don't wait)
4. Always return 202 (never fail the plugin on telemetry errors)

### Posthog Capture API Integration

```typescript
// src/telemetry/posthog.ts

interface PosthogEvent {
  event: string;
  distinct_id: string;
  timestamp?: string;
  properties?: Record<string, any>;
}

interface PosthogBatchRequest {
  api_key: string;
  batch: PosthogEvent[];
}

interface PosthogEventData {
  event: string;
  timestamp: number;
  properties: Record<string, any>;
}

export async function sendToPosthog(
  env: Env,
  anonymousId: string,
  events: PosthogEventData[]
): Promise<void> {
  const batch: PosthogEvent[] = events.map(event => ({
    event: event.event,
    distinct_id: anonymousId,
    timestamp: new Date(event.timestamp).toISOString(),
    properties: {
      ...event.properties,
      $lib: 'studio-rich-presence-backend',
      $lib_version: '1.0.0',
    },
  }));
  
  const response = await fetch('https://app.posthog.com/batch', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      api_key: env.POSTHOG_API_KEY,
      batch,
    } as PosthogBatchRequest),
  });
  
  if (!response.ok) {
    console.error('Posthog batch failed:', await response.text());
    // Don't throw - telemetry failures shouldn't break the app
  }
}
```

### Hono Endpoint Implementation

```typescript
// src/endpoints/telemetry.ts

import { Hono } from 'hono';
import { sendToPosthog } from '../telemetry/posthog';
import { validateTelemetryEvent, extractEventData } from '../telemetry/validation';

app.post('/api/telemetry/capture', async (c) => {
  try {
    const body = await c.req.json<CaptureEventsRequest>();
    
    // Validate anonymous_id format (should be SHA-256 hash)
    if (!body.anonymous_id || body.anonymous_id.length !== 64) {
      return c.body(null, 202); // Still return 202, don't fail on bad telemetry
    }
    
    // Validate and transform events
    const validEvents = body.events
      .filter(e => validateTelemetryEvent(e))
      .map(e => extractEventData(e));
    
    if (validEvents.length > 0) {
      // Fire and forget - don't await
      c.executionCtx.waitUntil(
        sendToPosthog(c.env, body.anonymous_id, validEvents)
      );
    }
    
    return c.body(null, 202);
  } catch (error) {
    // Never fail on telemetry
    console.error('Telemetry error:', error);
    return c.body(null, 202);
  }
});
```

### Event Validation

```typescript
// src/telemetry/validation.ts

import { z } from 'zod';

// Schema for each event type with required properties
const PluginOpenedSchema = z.object({
  plugin_version: z.string(),
  studio_version: z.string(),
  linked_account_count: z.number().int().min(0),
});

const PluginClosedSchema = z.object({
  session_duration_seconds: z.number().int().min(0),
  presence_update_count: z.number().int().min(0),
});

const AuthStartedSchema = z.object({
  is_first_account: z.boolean(),
});

const AuthCompletedSchema = z.object({
  method: z.enum(['sse', 'code']),
  is_first_account: z.boolean(),
  time_to_complete_seconds: z.number().int().min(0),
});

const AuthFailedSchema = z.object({
  method: z.enum(['sse', 'code']),
  reason: z.enum(['user_denied', 'expired', 'sse_failed', 'invalid_code', 'network_error']),
});

const AccountLinkedSchema = z.object({
  total_account_count: z.number().int().min(1),
});

const AccountUnlinkedSchema = z.object({
  total_account_count: z.number().int().min(0),
});

const AllDataClearedSchema = z.object({
  accounts_removed: z.number().int().min(0),
});

const PresenceUpdatedSchema = z.object({
  account_count: z.number().int().min(0),
  successful_count: z.number().int().min(0),
  failed_count: z.number().int().min(0),
});

const PresenceErrorSchema = z.object({
  error_type: z.enum(['unauthorized', 'rate_limited', 'discord_api', 'network']),
  account_count: z.number().int().min(0),
});

const ErrorEventSchema = z.object({
  error_code: z.string().max(50),
  context: z.string().max(100),
  message: z.string().max(500).optional(),
});

// Map event type to schema
const EVENT_SCHEMAS: Record<string, z.ZodType> = {
  plugin_opened: PluginOpenedSchema,
  plugin_closed: PluginClosedSchema,
  auth_started: AuthStartedSchema,
  auth_completed: AuthCompletedSchema,
  auth_failed: AuthFailedSchema,
  account_linked: AccountLinkedSchema,
  account_unlinked: AccountUnlinkedSchema,
  all_data_cleared: AllDataClearedSchema,
  presence_updated: PresenceUpdatedSchema,
  presence_error: PresenceErrorSchema,
  error: ErrorEventSchema,
};

export function validateTelemetryEvent(event: TelemetryEvent): boolean {
  // Get the event type from the oneof field
  const eventType = getEventType(event);
  if (!eventType) return false;
  
  const schema = EVENT_SCHEMAS[eventType];
  if (!schema) return false;
  
  const properties = getEventProperties(event, eventType);
  const result = schema.safeParse(properties);
  
  if (!result.success) {
    console.warn(`Invalid telemetry event ${eventType}:`, result.error);
    return false;
  }
  
  return true;
}

export function extractEventData(event: TelemetryEvent): PosthogEventData {
  const eventType = getEventType(event)!;
  const properties = getEventProperties(event, eventType);
  
  return {
    event: eventType,
    timestamp: event.timestamp,
    properties,
  };
}

function getEventType(event: TelemetryEvent): string | null {
  // Returns the name of the oneof field that is set
  const eventFields = [
    'plugin_opened', 'plugin_closed',
    'auth_started', 'auth_completed', 'auth_failed',
    'account_linked', 'account_unlinked', 'all_data_cleared',
    'presence_updated', 'presence_error',
    'error',
  ];
  
  for (const field of eventFields) {
    if (event[field] !== undefined) {
      return field;
    }
  }
  return null;
}

function getEventProperties(event: TelemetryEvent, eventType: string): Record<string, any> {
  return event[eventType] || {};
}
```

### Event Definitions

Events are validated server-side using Zod schemas derived from the protobuf definitions. Each event has specific required properties.

| Event | Required Properties | Description |
|-------|---------------------|-------------|
| `plugin_opened` | `plugin_version: string`, `studio_version: string`, `linked_account_count: int` | Plugin widget opened |
| `plugin_closed` | `session_duration_seconds: int`, `presence_update_count: int` | Plugin widget closed |
| `auth_started` | `is_first_account: bool` | User initiated Discord linking |
| `auth_completed` | `method: enum`, `is_first_account: bool`, `time_to_complete_seconds: int` | Successfully linked Discord |
| `auth_failed` | `method: enum`, `reason: enum` | Auth flow failed |
| `account_linked` | `total_account_count: int` | New Discord account linked |
| `account_unlinked` | `total_account_count: int` | Discord account removed |
| `all_data_cleared` | `accounts_removed: int` | User cleared all data |
| `presence_updated` | `account_count: int`, `successful_count: int`, `failed_count: int` | Presence update sent |
| `presence_error` | `error_type: enum`, `account_count: int` | Presence update failed |
| `error` | `error_code: string`, `context: string`, `message?: string` | Generic error event |

**Enum Values:**

| Enum | Values |
|------|--------|
| `AuthMethod` | `sse`, `code` |
| `AuthFailureReason` | `user_denied`, `expired`, `sse_failed`, `invalid_code`, `network_error` |
| `PresenceErrorType` | `unauthorized`, `rate_limited`, `discord_api`, `network` |

### Plugin-Side Telemetry

```lua
-- src/Telemetry/TelemetryService.luau

local HttpService = game:GetService("HttpService")

export type AuthMethod = "sse" | "code"
export type AuthFailureReason = "user_denied" | "expired" | "sse_failed" | "invalid_code" | "network_error"
export type PresenceErrorType = "unauthorized" | "rate_limited" | "discord_api" | "network"

-- Typed event constructors
export type TelemetryEvent = 
  | { timestamp: number, plugin_opened: { plugin_version: string, studio_version: string, linked_account_count: number } }
  | { timestamp: number, plugin_closed: { session_duration_seconds: number, presence_update_count: number } }
  | { timestamp: number, auth_started: { is_first_account: boolean } }
  | { timestamp: number, auth_completed: { method: AuthMethod, is_first_account: boolean, time_to_complete_seconds: number } }
  | { timestamp: number, auth_failed: { method: AuthMethod, reason: AuthFailureReason } }
  | { timestamp: number, account_linked: { total_account_count: number } }
  | { timestamp: number, account_unlinked: { total_account_count: number } }
  | { timestamp: number, all_data_cleared: { accounts_removed: number } }
  | { timestamp: number, presence_updated: { account_count: number, successful_count: number, failed_count: number } }
  | { timestamp: number, presence_error: { error_type: PresenceErrorType, account_count: number } }
  | { timestamp: number, error: { error_code: string, context: string, message: string? } }

local TelemetryService = {}

local eventQueue: { TelemetryEvent } = {}
local BATCH_INTERVAL = 30 -- seconds
local BATCH_SIZE = 10

-- Type-safe event capture functions
function TelemetryService.pluginOpened(pluginVersion: string, studioVersion: string, linkedAccountCount: number)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    plugin_opened = {
      plugin_version = pluginVersion,
      studio_version = studioVersion,
      linked_account_count = linkedAccountCount,
    },
  })
end

function TelemetryService.pluginClosed(sessionDurationSeconds: number, presenceUpdateCount: number)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    plugin_closed = {
      session_duration_seconds = sessionDurationSeconds,
      presence_update_count = presenceUpdateCount,
    },
  })
  TelemetryService.flush() -- Flush immediately on close
end

function TelemetryService.authStarted(isFirstAccount: boolean)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    auth_started = { is_first_account = isFirstAccount },
  })
end

function TelemetryService.authCompleted(method: AuthMethod, isFirstAccount: boolean, timeToCompleteSeconds: number)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    auth_completed = {
      method = method,
      is_first_account = isFirstAccount,
      time_to_complete_seconds = timeToCompleteSeconds,
    },
  })
end

function TelemetryService.authFailed(method: AuthMethod, reason: AuthFailureReason)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    auth_failed = { method = method, reason = reason },
  })
end

function TelemetryService.accountLinked(totalAccountCount: number)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    account_linked = { total_account_count = totalAccountCount },
  })
end

function TelemetryService.accountUnlinked(totalAccountCount: number)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    account_unlinked = { total_account_count = totalAccountCount },
  })
end

function TelemetryService.allDataCleared(accountsRemoved: number)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    all_data_cleared = { accounts_removed = accountsRemoved },
  })
end

function TelemetryService.presenceUpdated(accountCount: number, successfulCount: number, failedCount: number)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    presence_updated = {
      account_count = accountCount,
      successful_count = successfulCount,
      failed_count = failedCount,
    },
  })
end

function TelemetryService.presenceError(errorType: PresenceErrorType, accountCount: number)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    presence_error = { error_type = errorType, account_count = accountCount },
  })
end

function TelemetryService.error(errorCode: string, context: string, message: string?)
  TelemetryService._enqueue({
    timestamp = DateTime.now().UnixTimestampMillis,
    error = { error_code = errorCode, context = context, message = message },
  })
end

-- Internal functions
function TelemetryService._enqueue(event: TelemetryEvent)
  table.insert(eventQueue, event)
  
  if #eventQueue >= BATCH_SIZE then
    TelemetryService.flush()
  end
end

function TelemetryService.flush()
  if #eventQueue == 0 then return end
  
  local events = eventQueue
  eventQueue = {}
  
  task.spawn(function()
    pcall(function()
      HttpService:RequestAsync({
        Url = API_BASE .. "/api/telemetry/capture",
        Method = "POST",
        Headers = { ["Content-Type"] = "application/json" },
        Body = HttpService:JSONEncode({
          anonymous_id = getAnonymizedUserId(),
          events = events,
        }),
      })
    end)
  end)
end

-- Flush periodically
task.spawn(function()
  while true do
    task.wait(BATCH_INTERVAL)
    TelemetryService.flush()
  end
end)

return TelemetryService
```

**Usage:**

```lua
local Telemetry = require(Plugin.Source.Telemetry.TelemetryService)

-- Plugin lifecycle
Telemetry.pluginOpened("1.0.0", "0.600.0.123456", 2)
Telemetry.pluginClosed(3600, 120)

-- Auth flow
Telemetry.authStarted(false)
Telemetry.authCompleted("sse", false, 15)
-- or on failure:
Telemetry.authFailed("code", "invalid_code")

-- Presence
Telemetry.presenceUpdated(2, 2, 0)
Telemetry.presenceError("rate_limited", 2)

-- Errors
Telemetry.error("NETWORK_TIMEOUT", "presence_update", "Request timed out after 30s")
```

### Posthog Configuration

**wrangler.jsonc secrets:**

```bash
wrangler secret put POSTHOG_API_KEY
# Enter your Posthog project API key
```

**Posthog Dashboard Setup:**

1. Create a new project in Posthog
2. Copy the project API key
3. Set up dashboards for:
   - Daily/Weekly/Monthly Active Users
   - Auth funnel (started → completed)
   - Feature usage (QR vs link vs code)
   - Error rates
4. Set up alerts for error rate spikes

---

## Security Implementation Details

### Token Generation

```typescript
// Use crypto.getRandomValues for cryptographic randomness
function generateToken(bytes: number = 32): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return base64url.encode(buffer);
}
```

### Token Hashing

```typescript
async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64url.encode(new Uint8Array(hashBuffer));
}
```

### Discord User ID Hashing

Hash Discord user IDs for privacy-preserving deduplication:

```typescript
// DISCORD_ID_SALT should be a 32-byte random value stored in Cloudflare secrets
// This prevents rainbow table attacks against the hash

async function hashDiscordId(discordUserId: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(discordUserId + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64url.encode(new Uint8Array(hashBuffer));
}

// Usage in OAuth callback:
const discordUserIdHash = await hashDiscordId(discordUser.id, env.DISCORD_ID_SALT);

// Lookup existing link (instant, O(1)):
const existing = await env.DB.prepare(`
  SELECT * FROM discord_accounts WHERE discord_user_id_hash = ?
`).bind(discordUserIdHash).first();
```

**Why salt?** Without a salt, attackers could precompute hashes of all possible Discord user IDs (they're sequential integers) and reverse them. The salt (kept secret) prevents this.

### Constant-Time Comparison

```typescript
async function verifyToken(provided: string, storedHash: string): Promise<boolean> {
  const providedHash = await hashToken(provided);
  
  // Constant-time comparison
  if (providedHash.length !== storedHash.length) return false;
  
  let result = 0;
  for (let i = 0; i < providedHash.length; i++) {
    result |= providedHash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  }
  return result === 0;
}
```

### Zero-Knowledge Token Encryption

Discord OAuth tokens are encrypted using a key derived from BOTH:

1. **Server secret** - stored in Cloudflare secrets, never leaves the server
2. **Client key** - stored in plugin settings, sent with each request

This means:

- **Database breach**: Attacker cannot decrypt tokens (missing client key)
- **Server compromise**: Cannot decrypt tokens at rest (needs client key per-request)
- **Client key loss**: Tokens become permanently unrecoverable (user re-links accounts)

```typescript
// Key derivation using HKDF
async function deriveEncryptionKey(
  serverSecret: string,
  clientKey: string,
  userId: string
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  
  // Import combined key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(serverSecret + clientKey),
    'HKDF',
    false,
    ['deriveKey']
  );
  
  // Derive AES-GCM key using HKDF
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(userId),
      info: encoder.encode('discord-token-encryption'),
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt token with derived key
async function encryptToken(token: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(token);
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  
  // Prepend IV to ciphertext
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  
  return base64url.encode(combined);
}

// Decrypt token with derived key
async function decryptToken(encrypted: string, key: CryptoKey): Promise<string> {
  const combined = base64url.decode(encrypted);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  
  return new TextDecoder().decode(decrypted);
}
```

### Security Properties of Zero-Knowledge Storage

| Scenario | Data Protected? | Notes |
|----------|-----------------|-------|
| Database breach | ✅ Yes | Attacker has ciphertext but no keys |
| Server secret leaked | ✅ Yes | Still needs client key to decrypt |
| Client key leaked | ✅ Yes | Still needs server secret to decrypt |
| Both keys leaked | ❌ No | Full compromise - but requires breaching both |
| Plugin reinstalled | 🔄 Re-link | Client key lost, tokens unrecoverable |
| Server processes request | ⚠️ In memory | Keys combined only during request |

**Important**: This is "zero-knowledge storage", not "zero-knowledge computation". The server does see decrypted tokens in memory while calling Discord's API. The guarantee is that stored data cannot be decrypted without client cooperation.

---

## Plugin Implementation Notes

### Local Storage Schema

The plugin should store in its settings:

```lua
type AuthStorage = {
  authToken: string?,           -- Backend auth token (nil if not linked)
  clientKey: string?,           -- Client-side encryption key (nil if not linked)
  pendingLinkCode: string?,     -- Code for in-progress OAuth flow
  pendingSseUrl: string?,       -- SSE URL for in-progress flow
}
```

**Note**: Linked account details (username, avatar) are NOT stored locally. They are fetched fresh from `GET /api/accounts` when the plugin opens. This ensures:

- Data is always up-to-date (users can change Discord usernames)
- No PII persists on disk
- Simpler state management

**Critical**: The `clientKey` is essential for decrypting Discord tokens on the server. If lost (plugin settings cleared), the user must re-link all Discord accounts. This is by design - it ensures zero-knowledge storage.

### SSE Implementation (Primary)

Roblox Studio supports Server-Sent Events via the `WebStreamClient` class. This is the preferred method for receiving auth completion notifications.

**Key Limitations:**

- Studio-only feature (not available in live experiences) - perfect for plugins
- Maximum 4 concurrent `WebStreamClient` connections per plugin
- Connections may timeout after 30 minutes (we use 5-minute sessions, so this is fine)
- Requires heartbeat from server every ~20 seconds to maintain connection

```lua
local HttpService = game:GetService("HttpService")

export type AuthResult = {
  status: "completed" | "failed" | "expired",
  auth_token: string?,
  client_key: string?,
  error: string?,
}

local function waitForAuthCompletionSSE(sseUrl: string): Promise<AuthResult>
  return Promise.new(function(resolve, reject, onCancel)
    local sseClient = HttpService:CreateWebStreamClient(Enum.WebStreamClientType.SSE, {
      Url = sseUrl,
    })
    
    local resolved = false
    
    local function cleanup()
      if sseClient then
        pcall(function()
          sseClient:Close()
        end)
      end
    end
    
    onCancel(cleanup)
    
    sseClient.MessageReceived:Connect(function(eventType: string, data: string)
      if resolved then return end
      
      -- Ignore heartbeat events
      if eventType == "heartbeat" then
        return
      end
      
      resolved = true
      local parsedData = HttpService:JSONDecode(data)
      
      if eventType == "completed" then
        cleanup()
        resolve({
          status = "completed",
          auth_token = parsedData.auth_token,  -- nil for existing users
          client_key = parsedData.client_key,  -- nil for existing users
        })
      elseif eventType == "failed" then
        cleanup()
        reject(parsedData.error or "Authentication failed")
      elseif eventType == "expired" then
        cleanup()
        reject("Link expired")
      end
    end)
    
    sseClient.ConnectionClosed:Connect(function()
      if not resolved then
        resolved = true
        reject("Connection closed unexpectedly")
      end
    end)
    
    -- Start the SSE connection
    local success, err = pcall(function()
      sseClient:Start()
    end)
    
    if not success then
      resolved = true
      reject(`Failed to start SSE connection: {err}`)
    end
  end)
end
```

### Manual Code Entry (Fallback)

If SSE fails, show a text input for the user to enter the 5-digit code displayed on the success page. The plugin must also send the session `code` (stored in memory from `/auth/start`).

```lua
local function completeAuthWithCode(sessionCode: string, completionCode: string): Promise<AuthResult>
  return Promise.new(function(resolve, reject)
    local response = HttpService:RequestAsync({
      Url = `{API_BASE}/api/auth/complete`,
      Method = "POST",
      Headers = {
        ["Content-Type"] = "application/json",
      },
      Body = HttpService:JSONEncode({
        code = sessionCode,            -- Long session code from /auth/start
        completion_code = completionCode,  -- 5-digit code user entered
      }),
    })
    
    local data = HttpService:JSONDecode(response.Body)
    
    if data.success then
      resolve({
        status = "completed",
        auth_token = data.auth_token,
        client_key = data.client_key,
      })
    else
      reject(data.error or "Invalid code")
    end
  end)
end
```

### Combined Auth Flow

```lua
export type AuthResult = {
  status: "completed" | "failed" | "expired",
  auth_token: string?,
  client_key: string?,
  error: string?,
}

local function startAuthFlow(existingToken: string?, existingClientKey: string?): Promise<AuthResult>
  -- 1. Request auth session from backend
  return requestAuthSession(existingToken, existingClientKey):andThen(function(session)
    -- 2. Display URL to user
    displayLinkUrl(session.url)
    
    -- 3. Start SSE connection
    local ssePromise = waitForAuthCompletionSSE(session.sse_url)
    
    -- 4. Also show manual code input (user can use either)
    --    The UI should show: "Waiting for authorization... or enter code:"
    --    When user submits code, cancel SSE and use manual completion
    
    return ssePromise
  end)
end

-- Alternative: Race between SSE and manual code entry
local function waitForAuthCompletion(
  sessionCode: string,
  sseUrl: string,
  onShowCodeInput: () -> Promise<string>
): Promise<AuthResult>
  return Promise.new(function(resolve, reject, onCancel)
    local resolved = false
    
    -- Start SSE
    local ssePromise = waitForAuthCompletionSSE(sseUrl)
    
    ssePromise:andThen(function(result)
      if not resolved then
        resolved = true
        resolve(result)
      end
    end):catch(function(err)
      -- SSE failed, but user might still enter code manually
      warn(`SSE connection failed: {err}`)
    end)
    
    -- Show code input UI - resolves when user submits the 5-digit code
    onShowCodeInput():andThen(function(completionCode)
      return completeAuthWithCode(sessionCode, completionCode)
    end):andThen(function(result)
      if not resolved then
        resolved = true
        ssePromise:cancel()
        resolve(result)
      end
    end):catch(function(err)
      if not resolved then
        resolved = true
        reject(err)
      end
    end)
    
    onCancel(function()
      ssePromise:cancel()
    end)
  end)
end
```

---

## Cloudflare Configuration

### Required Bindings (wrangler.jsonc)

```jsonc
{
  // ... existing config ...
  
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "studio-rich-presence",
      "database_id": "your-database-id"
    }
  ],
  
  "vars": {
    "DISCORD_CLIENT_ID": "your-discord-client-id",
    "DISCORD_REDIRECT_URI": "https://srp.example.com/auth/callback"
  }
  
  // Set via `wrangler secret put`:
  // - DISCORD_CLIENT_SECRET
  // - ENCRYPTION_KEY (base64-encoded 32-byte key for token encryption)
  // - DISCORD_ID_SALT (base64-encoded 32-byte key for hashing Discord user IDs)
}
```

### SSE Implementation on Cloudflare Workers

Cloudflare Workers can serve SSE responses, but there's a challenge: the OAuth callback runs in a separate Worker invocation from the SSE connection. We need a way to notify the waiting SSE connection when auth completes.

**Approach: KV-based polling within SSE handler**

The SSE endpoint polls KV/D1 for session state changes while keeping the connection open:

```typescript
// SSE endpoint implementation
export async function handleSSE(code: string, env: Env): Promise<Response> {
  // Validate session exists
  const session = await getAuthSession(env.DB, code);
  if (!session || session.expires_at < Date.now()) {
    return sseResponse([{ event: 'expired', data: {} }]);
  }
  
  // If already completed, return immediately
  if (session.state !== 'pending') {
    return sseResponse([formatSessionEvent(session)]);
  }
  
  // Create a streaming response that polls for updates
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  
  const sendEvent = async (event: string, data: object) => {
    await writer.write(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
  };
  
  // Poll loop (runs in background)
  (async () => {
    const POLL_INTERVAL = 1000; // 1 second internal poll
    const HEARTBEAT_INTERVAL = 20000; // 20 seconds
    let lastHeartbeat = Date.now();
    
    try {
      while (true) {
        const currentSession = await getAuthSession(env.DB, code);
        
        if (!currentSession || currentSession.expires_at < Date.now()) {
          await sendEvent('expired', {});
          break;
        }
        
        if (currentSession.state !== 'pending') {
          await sendEvent(currentSession.state, formatEventData(currentSession));
          break;
        }
        
        // Send heartbeat if needed
        if (Date.now() - lastHeartbeat > HEARTBEAT_INTERVAL) {
          await sendEvent('heartbeat', {});
          lastHeartbeat = Date.now();
        }
        
        await sleep(POLL_INTERVAL);
      }
    } finally {
      await writer.close();
    }
  })();
  
  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    },
  });
}
```

**Alternative: Durable Objects**

For lower latency, Durable Objects can coordinate between the SSE connection and OAuth callback:

```typescript
// AuthSessionDO - one instance per auth code
export class AuthSessionDO implements DurableObject {
  private waitingConnections: Set<WritableStreamDefaultWriter> = new Set();
  
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    
    if (url.pathname === '/subscribe') {
      // SSE subscription
      return this.handleSubscribe();
    } else if (url.pathname === '/complete') {
      // Called by OAuth callback
      const data = await request.json();
      return this.handleComplete(data);
    }
  }
  
  private handleSubscribe(): Response {
    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    this.waitingConnections.add(writer);
    
    // Clean up on close
    writer.closed.finally(() => {
      this.waitingConnections.delete(writer);
    });
    
    return new Response(readable, {
      headers: { 'Content-Type': 'text/event-stream' },
    });
  }
  
  private async handleComplete(data: CompleteData): Promise<Response> {
    const encoder = new TextEncoder();
    const event = `event: completed\ndata: ${JSON.stringify(data)}\n\n`;
    
    for (const writer of this.waitingConnections) {
      await writer.write(encoder.encode(event));
      await writer.close();
    }
    this.waitingConnections.clear();
    
    return new Response('OK');
  }
}
```

**Recommendation**: Start with KV-based polling (simpler, no additional Cloudflare products). If latency becomes an issue, migrate to Durable Objects.

---

### D1 Schema Migration

```sql
-- migrations/0001_initial.sql

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  auth_token_hash TEXT NOT NULL UNIQUE,
  pending_token_hash TEXT,
  pending_token_expires INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_activity_at INTEGER NOT NULL
);

CREATE INDEX idx_users_last_activity_at ON users(last_activity_at);

CREATE TABLE discord_accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  discord_user_id_hash TEXT NOT NULL UNIQUE,
  access_token_enc TEXT NOT NULL,
  refresh_token_enc TEXT NOT NULL,
  token_expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX idx_discord_accounts_user_id ON discord_accounts(user_id);
CREATE INDEX idx_discord_accounts_hash ON discord_accounts(discord_user_id_hash);

-- discord_user_id_hash = SHA-256(discord_user_id + DISCORD_ID_SALT)
-- UNIQUE constraint ensures one Discord account can only be linked once globally
-- If user B links an account already linked to user A, the old link is deleted first

CREATE TABLE auth_sessions (
  code TEXT PRIMARY KEY,                  -- Random code (primary key, no separate id)
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  state TEXT NOT NULL DEFAULT 'pending',  -- pending/started/completed/failed
  completion_code TEXT,                   -- 5-digit code for manual entry
  pkce_code_verifier TEXT NOT NULL,       -- PKCE verifier for OAuth
  result_token TEXT,                      -- Auth token to return (new users only)
  result_client_key TEXT,                 -- Client key to return (new users only)
  error_message TEXT,                     -- Error details if failed
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions(expires_at);
```

---

## Implementation Checklist

### Backend (Priority Order)

- [x] Set up D1 database with schema
- [x] Create `Env` type with bindings
- [x] Implement crypto utilities:
  - [x] Token generation (auth tokens, client keys, completion codes)
  - [x] Auth token hashing (deterministic HMAC-SHA256 for O(1) lookup)
  - [x] Generic token hashing (HMAC-SHA256 with per-hash salt)
  - [x] Discord user ID hashing (HMAC-SHA256 with server salt)
  - [x] HKDF key derivation (server + client key → encryption key)
  - [x] AES-GCM encryption/decryption for Discord tokens
- [x] Implement rate limiting middleware
- [x] `POST /api/auth/start` - Initiate auth flow
- [x] `GET /auth/link/:code` - Redirect to Discord + set state to "started"
- [x] `GET /auth/callback` - Handle OAuth callback + show completion code + cross-user unlinking
- [X] `GET /auth/sse/:code` - SSE endpoint via KV polling
- [X] `POST /api/auth/complete` - Manual code entry completion
- [ ] `POST /api/presence/update` - Update presence with token rotation
- [ ] `GET /api/accounts` - List linked accounts (fetch from Discord API)
- [ ] `DELETE /api/accounts/:id` - Unlink account
- [ ] `DELETE /api/user` - Delete all data
- [ ] `POST /api/telemetry/capture` - Posthog telemetry forwarding
- [x] Activity tracking middleware (update `last_activity_at`)
- [ ] Token rotation with acknowledgment protocol:
  - [ ] Generate pending token on presence update
  - [ ] Handle X-Ack-Token header to promote pending → active
  - [ ] Auto-expire pending tokens after 5 minutes
- [ ] Cron trigger for automatic cleanup:
  - [ ] Expired session cleanup
  - [ ] Inactive account cleanup (90 days)
  - [ ] Expired pending token cleanup
- [ ] Discord token refresh logic (re-encrypt with same derived key)

### Plugin (Priority Order)

- [ ] Create `AuthStore` for managing auth state:
  - [ ] Store active auth_token and client_key
  - [ ] Store pending_auth_token for acknowledgment
  - [ ] Include X-Ack-Token header on requests when pending exists
  - [ ] Persist pending token to survive plugin restarts
- [ ] Create "Link Discord" button UI
- [ ] Implement `startLinkFlow()` - calls start, shows URL + client-generated QR code
- [ ] Implement QR code generation in Luau (client-side)
- [ ] Implement SSE-based auth completion via `WebStreamClient`
- [ ] Handle "started" SSE event (switch to waiting UI)
- [ ] Implement manual code entry UI (fallback for SSE failure)
- [ ] Create linked accounts list UI (fetch details from `/api/accounts`)
- [ ] Implement "Unlink" button per account
- [ ] Implement "Clear All Data" button with confirmation
- [ ] Implement presence update loop (handle token rotation in response)
- [ ] Implement telemetry service with batching
- [ ] Handle auth errors (re-auth prompt)

---

## Open Questions

1. **Presence conflicts**: If user has plugin open on 2 machines linked to the same Discord account, which presence wins?
   - Decision: Last-write-wins (no coordination needed)
   - Note: Each installation is independent, so this only matters if user links the same Discord account to multiple installations

2. **Offline handling**: What happens when Discord API is down?
   - Decision: Retry with exponential backoff, log errors, return partial success in response

3. **Telemetry opt-out**: How to handle users who opt out?
   - Decision: Plugin checks local setting before calling telemetry API
   - Server still validates/sanitizes but doesn't store opt-out preference

---

## Revision History

| Date | Author | Changes |
| ---- | ------ | ------- |
| 2025-12-28 | Initial | Initial design document |
| 2025-12-28 | Update | Added SSE support via WebStreamClient, removed account recovery |
| 2025-12-28 | Update | Replaced polling with manual code entry, added zero-knowledge encryption |
| 2025-12-28 | Update | Added session code requirement to /auth/complete for two-factor verification |
| 2025-12-28 | Update | Added automatic account cleanup via Cloudflare Cron Triggers (90-day inactivity) |
| 2025-12-28 | Update | Renamed to API Design; removed PII storage (no Discord user IDs); fetch account details on-demand |
| 2025-12-28 | Update | Added hashed Discord ID for instant deduplication; cross-user unlinking; QR code support for mobile |
| 2025-12-28 | Update | Major revision: Protobuf schema, token rotation, SSE "started" event, KV polling for SSE, client-side QR, Posthog telemetry, Hono code samples |
| 2025-12-28 | Update | Safe token rotation with acknowledgment protocol - prevents token loss on network failures |
| 2025-12-28 | Update | Typed telemetry events with per-event property validation |
| 2025-12-28 | Update | Simplified API responses - use HTTP status codes, no success wrapper |
