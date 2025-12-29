/**
 * Rate limiting middleware for Cloudflare Workers.
 *
 * Uses KV for distributed rate limit state with sliding window algorithm.
 * Supports both IP-based and token-based rate limiting.
 */

import { Context, Next, MiddlewareHandler } from "hono";
import { Env } from "../env";

/**
 * Rate limit configuration.
 */
export interface RateLimitConfig {
    /** Maximum requests allowed in the window */
    limit: number;
    /** Window size in seconds */
    windowSeconds: number;
    /** Key prefix for KV storage */
    keyPrefix: string;
    /** Function to extract the rate limit key (e.g., IP, user ID) */
    keyExtractor: (c: Context<{ Bindings: Env }>) => string | null;
    /** Optional: skip rate limiting for certain requests */
    skip?: (c: Context<{ Bindings: Env }>) => boolean;
}

/**
 * Rate limit state stored in KV.
 */
interface RateLimitState {
    /** Timestamps of requests in the current window */
    timestamps: number[];
    /** Window start time */
    windowStart: number;
}

/**
 * Rate limit result returned by checkRateLimit.
 */
export interface RateLimitResult {
    /** Whether the request is allowed */
    allowed: boolean;
    /** Current request count in window */
    current: number;
    /** Maximum allowed requests */
    limit: number;
    /** Seconds until rate limit resets */
    resetIn: number;
    /** Seconds until retry is allowed (0 if allowed) */
    retryAfter: number;
}

/**
 * Default key extractor that uses client IP.
 */
export function extractClientIp(c: Context<{ Bindings: Env }>): string | null {
    // Cloudflare provides the client IP in CF-Connecting-IP header
    const cfIp = c.req.header("cf-connecting-ip");
    if (cfIp) return cfIp;

    // Fallback for local development
    const xForwardedFor = c.req.header("x-forwarded-for");
    if (xForwardedFor) return xForwardedFor.split(",")[0]?.trim() ?? null;

    const xRealIp = c.req.header("x-real-ip");
    if (xRealIp) return xRealIp;

    // Last resort - may not be available in Workers
    return "unknown";
}

/**
 * Key extractor that uses the Authorization token.
 */
export function extractAuthToken(c: Context<{ Bindings: Env }>): string | null {
    const auth = c.req.header("authorization");
    if (!auth) return null;

    // Extract token from "Bearer <token>" format
    const match = auth.match(/^Bearer\s+(.+)$/i);
    if (!match?.[1]) return null;

    // Hash the token to avoid storing it in KV
    // We use a simple hash since this is just for rate limiting keys
    return simpleHash(match[1]);
}

/**
 * Simple hash function for rate limit keys.
 * Not cryptographically secure, just for key generation.
 */
function simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
}

/**
 * Check rate limit for a given key.
 *
 * Uses sliding window algorithm:
 * - Keeps track of request timestamps in the window
 * - Removes expired timestamps on each check
 * - Allows request if count < limit
 */
export async function checkRateLimit(
    kv: KVNamespace,
    key: string,
    config: Pick<RateLimitConfig, "limit" | "windowSeconds" | "keyPrefix">
): Promise<RateLimitResult> {
    const now = Date.now();
    const windowMs = config.windowSeconds * 1000;
    const kvKey = `${config.keyPrefix}:${key}`;

    // Get current state from KV
    const stateJson = await kv.get(kvKey);
    let state: RateLimitState;

    if (stateJson) {
        try {
            state = JSON.parse(stateJson);
        } catch {
            // Invalid state, reset
            state = { timestamps: [], windowStart: now };
        }
    } else {
        state = { timestamps: [], windowStart: now };
    }

    // Filter out expired timestamps (sliding window)
    const windowStart = now - windowMs;
    state.timestamps = state.timestamps.filter(ts => ts > windowStart);

    // Check if we're over the limit
    const current = state.timestamps.length;
    const allowed = current < config.limit;

    if (allowed) {
        // Add current request timestamp
        state.timestamps.push(now);

        // Store updated state in KV
        // TTL should be slightly longer than window to handle edge cases
        await kv.put(kvKey, JSON.stringify(state), {
            expirationTtl: config.windowSeconds + 60,
        });
    }

    // Calculate resetIn: time until oldest request expires (and a slot opens)
    // For a sliding window, this is when the next slot becomes available
    let resetIn = 0;
    let retryAfter = 0;

    if (state.timestamps.length > 0) {
        const oldestTimestamp = Math.min(...state.timestamps);
        resetIn = Math.ceil((oldestTimestamp + windowMs - now) / 1000);
        resetIn = Math.max(0, resetIn);
    }

    // retryAfter is only relevant when rate limited
    if (!allowed) {
        retryAfter = Math.max(1, resetIn); // At least 1 second
    }

    return {
        allowed,
        current: allowed ? current + 1 : current,
        limit: config.limit,
        resetIn,
        retryAfter,
    };
}

/**
 * Create rate limiting middleware.
 *
 * @param config Rate limit configuration
 * @returns Hono middleware handler
 *
 * @example
 * // 10 requests per minute per IP
 * app.use('/api/*', createRateLimiter({
 *   limit: 10,
 *   windowSeconds: 60,
 *   keyPrefix: 'rl:api',
 *   keyExtractor: extractClientIp,
 * }));
 *
 * // 1 request per 15 seconds per user (for presence updates)
 * app.use('/api/presence/*', createRateLimiter({
 *   limit: 1,
 *   windowSeconds: 15,
 *   keyPrefix: 'rl:presence',
 *   keyExtractor: extractAuthToken,
 * }));
 */
export function createRateLimiter(
    config: RateLimitConfig
): MiddlewareHandler<{ Bindings: Env }> {
    return async (c: Context<{ Bindings: Env }>, next: Next) => {
        // Check if rate limiting should be skipped
        if (config.skip?.(c)) {
            return next();
        }

        // Extract rate limit key
        const key = config.keyExtractor(c);
        if (!key) {
            // Can't rate limit without a key, allow the request
            return next();
        }

        // Check rate limit
        const result = await checkRateLimit(c.env.KV, key, config);

        // Set rate limit headers
        c.header("X-RateLimit-Limit", result.limit.toString());
        c.header("X-RateLimit-Remaining", Math.max(0, result.limit - result.current).toString());
        c.header("X-RateLimit-Reset", result.resetIn.toString());

        if (!result.allowed) {
            c.header("Retry-After", result.retryAfter.toString());

            return c.json(
                {
                    code: "RATE_LIMITED",
                    message: "Too many requests. Please try again later.",
                    details: {
                        retry_after: result.retryAfter.toString(),
                        limit: result.limit.toString(),
                        window_seconds: config.windowSeconds.toString(),
                    },
                },
                429
            );
        }

        return next();
    };
}

/**
 * Pre-configured rate limiters for common use cases.
 */
export const rateLimiters = {
    /**
     * General API rate limit: 60 requests per minute per IP.
     */
    api: createRateLimiter({
        limit: 60,
        windowSeconds: 60,
        keyPrefix: "rl:api",
        keyExtractor: extractClientIp,
    }),

    /**
     * Auth endpoint rate limit: 10 requests per minute per IP.
     * More restrictive to prevent brute force.
     */
    auth: createRateLimiter({
        limit: 10,
        windowSeconds: 60,
        keyPrefix: "rl:auth",
        keyExtractor: extractClientIp,
    }),

    /**
     * Auth completion rate limit: 5 attempts per minute per IP.
     * Very restrictive to prevent code guessing.
     */
    authComplete: createRateLimiter({
        limit: 5,
        windowSeconds: 60,
        keyPrefix: "rl:auth-complete",
        keyExtractor: extractClientIp,
    }),

    /**
     * Presence update rate limit: 1 request per 15 seconds per user.
     * Matches Discord's rate limit for presence updates.
     */
    presence: createRateLimiter({
        limit: 1,
        windowSeconds: 15,
        keyPrefix: "rl:presence",
        keyExtractor: extractAuthToken,
    }),

    /**
     * Presence clear rate limit: 1 request per 15 seconds per user.
     * Matches Discord's rate limit for presence clears.
     */
    presenceClear: createRateLimiter({
        limit: 1,
        windowSeconds: 15,
        keyPrefix: "rl:presence-clear",
        keyExtractor: extractAuthToken,
    }),

    /**
     * Account listing rate limit: 10 requests per minute per user.
     */
    accounts: createRateLimiter({
        limit: 10,
        windowSeconds: 60,
        keyPrefix: "rl:accounts",
        keyExtractor: extractAuthToken,
    }),

    /**
     * SSE connection rate limit: 5 connection per code.
     */
    sse: createRateLimiter({
        limit: 5,
        windowSeconds: 300, // 5 minutes (session duration)
        keyPrefix: "rl:sse",
        keyExtractor: (c) => c.req.param("code") ?? null,
    }),

    /**
     * Telemetry rate limit: 100 events per minute per anonymous ID.
     */
    telemetry: createRateLimiter({
        limit: 100,
        windowSeconds: 60,
        keyPrefix: "rl:telemetry",
        keyExtractor: extractClientIp,
    }),
};

