import { describe, it, expect, beforeEach } from "vitest";
import { env } from "cloudflare:test";
import { Hono } from "hono";
import {
    createRateLimiter,
    checkRateLimit,
    extractClientIp,
    extractAuthToken,
    RateLimitConfig,
} from "../rateLimit";
import { Env } from "../../env";

// Test app setup
function createTestApp(config: RateLimitConfig) {
    const app = new Hono<{ Bindings: Env }>();
    app.use("*", createRateLimiter(config));
    app.get("/test", (c) => c.json({ message: "ok" }));
    app.post("/test", (c) => c.json({ message: "ok" }));
    return app;
}

// Helper to make requests
async function makeRequest(
    app: Hono<{ Bindings: Env }>,
    options: {
        path?: string;
        method?: string;
        headers?: Record<string, string>;
    } = {}
) {
    const { path = "/test", method = "GET", headers = {} } = options;

    const request = new Request(`http://localhost${path}`, {
        method,
        headers: {
            "cf-connecting-ip": "192.168.1.1",
            ...headers,
        },
    });

    return app.fetch(request, env);
}

describe("rateLimit middleware", () => {
    beforeEach(async () => {
        // Clear KV between tests
        const keys = await env.KV.list();
        for (const key of keys.keys) {
            await env.KV.delete(key.name);
        }
    });

    describe("checkRateLimit", () => {
        it("should allow requests under the limit", async () => {
            const result = await checkRateLimit(env.KV, "test-key", {
                limit: 5,
                windowSeconds: 60,
                keyPrefix: "test",
            });

            expect(result.allowed).toBe(true);
            expect(result.current).toBe(1);
            expect(result.limit).toBe(5);
        });

        it("should track request count correctly", async () => {
            const config = { limit: 5, windowSeconds: 60, keyPrefix: "test" };

            for (let i = 1; i <= 5; i++) {
                const result = await checkRateLimit(env.KV, "test-key", config);
                expect(result.allowed).toBe(true);
                expect(result.current).toBe(i);
            }
        });

        it("should block requests over the limit", async () => {
            const config = { limit: 3, windowSeconds: 60, keyPrefix: "test" };

            // Make 3 allowed requests
            for (let i = 0; i < 3; i++) {
                const result = await checkRateLimit(env.KV, "test-key", config);
                expect(result.allowed).toBe(true);
            }

            // 4th request should be blocked
            const result = await checkRateLimit(env.KV, "test-key", config);
            expect(result.allowed).toBe(false);
            expect(result.current).toBe(3);
            expect(result.retryAfter).toBeGreaterThan(0);
        });

        it("should use separate counters for different keys", async () => {
            const config = { limit: 2, windowSeconds: 60, keyPrefix: "test" };

            // Key 1: 2 requests
            await checkRateLimit(env.KV, "key1", config);
            await checkRateLimit(env.KV, "key1", config);

            // Key 1 should be at limit
            const result1 = await checkRateLimit(env.KV, "key1", config);
            expect(result1.allowed).toBe(false);

            // Key 2 should still have capacity
            const result2 = await checkRateLimit(env.KV, "key2", config);
            expect(result2.allowed).toBe(true);
            expect(result2.current).toBe(1);
        });

        it("should use separate counters for different prefixes", async () => {
            const config1 = { limit: 1, windowSeconds: 60, keyPrefix: "prefix1" };
            const config2 = { limit: 1, windowSeconds: 60, keyPrefix: "prefix2" };

            // Use up limit on prefix1
            await checkRateLimit(env.KV, "same-key", config1);
            const result1 = await checkRateLimit(env.KV, "same-key", config1);
            expect(result1.allowed).toBe(false);

            // prefix2 should still have capacity
            const result2 = await checkRateLimit(env.KV, "same-key", config2);
            expect(result2.allowed).toBe(true);
        });

        it("should return correct resetIn value", async () => {
            const result = await checkRateLimit(env.KV, "test-key", {
                limit: 5,
                windowSeconds: 60,
                keyPrefix: "test",
            });

            // resetIn should be close to windowSeconds for first request
            expect(result.resetIn).toBeGreaterThan(0);
            expect(result.resetIn).toBeLessThanOrEqual(60);
        });

        it("should handle corrupted KV data gracefully", async () => {
            // Store invalid JSON
            await env.KV.put("test:corrupted-key", "not-valid-json");

            const result = await checkRateLimit(env.KV, "corrupted-key", {
                limit: 5,
                windowSeconds: 60,
                keyPrefix: "test",
            });

            // Should reset and allow
            expect(result.allowed).toBe(true);
            expect(result.current).toBe(1);
        });
    });

    describe("middleware integration", () => {
        it("should allow requests under limit", async () => {
            const app = createTestApp({
                limit: 5,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            const response = await makeRequest(app);

            expect(response.status).toBe(200);
            expect(response.headers.get("X-RateLimit-Limit")).toBe("5");
            expect(response.headers.get("X-RateLimit-Remaining")).toBe("4");
        });

        it("should return 429 when rate limited", async () => {
            const app = createTestApp({
                limit: 2,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            // Use up the limit
            await makeRequest(app);
            await makeRequest(app);

            // Third request should be rate limited
            const response = await makeRequest(app);

            expect(response.status).toBe(429);
            expect(response.headers.get("Retry-After")).toBeTruthy();

            const body = await response.json();
            expect(body).toMatchObject({
                code: "RATE_LIMITED",
                message: expect.stringContaining("Too many requests"),
            });
        });

        it("should set correct rate limit headers", async () => {
            const app = createTestApp({
                limit: 10,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            // Make a few requests
            await makeRequest(app);
            await makeRequest(app);
            const response = await makeRequest(app);

            expect(response.headers.get("X-RateLimit-Limit")).toBe("10");
            expect(response.headers.get("X-RateLimit-Remaining")).toBe("7");
            expect(response.headers.get("X-RateLimit-Reset")).toBeTruthy();
        });

        it("should track different IPs separately", async () => {
            const app = createTestApp({
                limit: 1,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            // First IP uses up limit
            const response1 = await makeRequest(app, {
                headers: { "cf-connecting-ip": "1.1.1.1" },
            });
            expect(response1.status).toBe(200);

            // First IP is rate limited
            const response2 = await makeRequest(app, {
                headers: { "cf-connecting-ip": "1.1.1.1" },
            });
            expect(response2.status).toBe(429);

            // Second IP is not rate limited
            const response3 = await makeRequest(app, {
                headers: { "cf-connecting-ip": "2.2.2.2" },
            });
            expect(response3.status).toBe(200);
        });

        it("should skip rate limiting when skip returns true", async () => {
            const app = createTestApp({
                limit: 1,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
                skip: (c) => c.req.header("x-skip-rate-limit") === "true",
            });

            // Normal request uses up limit
            await makeRequest(app);

            // Normal request is rate limited
            const response1 = await makeRequest(app);
            expect(response1.status).toBe(429);

            // Request with skip header is allowed
            const response2 = await makeRequest(app, {
                headers: { "x-skip-rate-limit": "true" },
            });
            expect(response2.status).toBe(200);
        });

        it("should allow request when key extractor returns null", async () => {
            const app = createTestApp({
                limit: 1,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: () => null, // Always returns null
            });

            // Both requests should be allowed (no key = no rate limiting)
            const response1 = await makeRequest(app);
            const response2 = await makeRequest(app);

            expect(response1.status).toBe(200);
            expect(response2.status).toBe(200);
        });
    });

    describe("extractClientIp", () => {
        it("should extract IP from cf-connecting-ip header", async () => {
            const app = new Hono<{ Bindings: Env }>();
            let extractedIp: string | null = null;

            app.get("/test", (c) => {
                extractedIp = extractClientIp(c);
                return c.json({ ip: extractedIp });
            });

            await app.fetch(
                new Request("http://localhost/test", {
                    headers: { "cf-connecting-ip": "203.0.113.50" },
                }),
                env
            );

            expect(extractedIp).toBe("203.0.113.50");
        });

        it("should fallback to x-forwarded-for", async () => {
            const app = new Hono<{ Bindings: Env }>();
            let extractedIp: string | null = null;

            app.get("/test", (c) => {
                extractedIp = extractClientIp(c);
                return c.json({ ip: extractedIp });
            });

            await app.fetch(
                new Request("http://localhost/test", {
                    headers: { "x-forwarded-for": "198.51.100.178, 192.168.1.1" },
                }),
                env
            );

            expect(extractedIp).toBe("198.51.100.178");
        });

        it("should fallback to x-real-ip", async () => {
            const app = new Hono<{ Bindings: Env }>();
            let extractedIp: string | null = null;

            app.get("/test", (c) => {
                extractedIp = extractClientIp(c);
                return c.json({ ip: extractedIp });
            });

            await app.fetch(
                new Request("http://localhost/test", {
                    headers: { "x-real-ip": "192.0.2.1" },
                }),
                env
            );

            expect(extractedIp).toBe("192.0.2.1");
        });

        it("should return 'unknown' when no IP headers present", async () => {
            const app = new Hono<{ Bindings: Env }>();
            let extractedIp: string | null = null;

            app.get("/test", (c) => {
                extractedIp = extractClientIp(c);
                return c.json({ ip: extractedIp });
            });

            await app.fetch(new Request("http://localhost/test"), env);

            expect(extractedIp).toBe("unknown");
        });
    });

    describe("extractAuthToken", () => {
        it("should extract and hash Bearer token", async () => {
            const app = new Hono<{ Bindings: Env }>();
            let extractedKey: string | null = null;

            app.get("/test", (c) => {
                extractedKey = extractAuthToken(c);
                return c.json({ key: extractedKey });
            });

            await app.fetch(
                new Request("http://localhost/test", {
                    headers: { authorization: "Bearer my-secret-token" },
                }),
                env
            );

            expect(extractedKey).toBeTruthy();
            expect(extractedKey).not.toBe("my-secret-token"); // Should be hashed
        });

        it("should produce same hash for same token", async () => {
            const app = new Hono<{ Bindings: Env }>();
            const keys: (string | null)[] = [];

            app.get("/test", (c) => {
                keys.push(extractAuthToken(c));
                return c.json({});
            });

            const headers = { authorization: "Bearer consistent-token" };

            await app.fetch(new Request("http://localhost/test", { headers }), env);
            await app.fetch(new Request("http://localhost/test", { headers }), env);

            expect(keys[0]).toBe(keys[1]);
        });

        it("should produce different hashes for different tokens", async () => {
            const app = new Hono<{ Bindings: Env }>();
            const keys: (string | null)[] = [];

            app.get("/test", (c) => {
                keys.push(extractAuthToken(c));
                return c.json({});
            });

            await app.fetch(
                new Request("http://localhost/test", {
                    headers: { authorization: "Bearer token-one" },
                }),
                env
            );

            await app.fetch(
                new Request("http://localhost/test", {
                    headers: { authorization: "Bearer token-two" },
                }),
                env
            );

            expect(keys[0]).not.toBe(keys[1]);
        });

        it("should return null for missing Authorization header", async () => {
            const app = new Hono<{ Bindings: Env }>();
            let extractedKey: string | null = null;

            app.get("/test", (c) => {
                extractedKey = extractAuthToken(c);
                return c.json({});
            });

            await app.fetch(new Request("http://localhost/test"), env);

            expect(extractedKey).toBeNull();
        });

        it("should return null for non-Bearer auth", async () => {
            const app = new Hono<{ Bindings: Env }>();
            let extractedKey: string | null = null;

            app.get("/test", (c) => {
                extractedKey = extractAuthToken(c);
                return c.json({});
            });

            await app.fetch(
                new Request("http://localhost/test", {
                    headers: { authorization: "Basic dXNlcjpwYXNz" },
                }),
                env
            );

            expect(extractedKey).toBeNull();
        });

        it("should return null for malformed Bearer header", async () => {
            const app = new Hono<{ Bindings: Env }>();
            let extractedKey: string | null = null;

            app.get("/test", (c) => {
                extractedKey = extractAuthToken(c);
                return c.json({});
            });

            await app.fetch(
                new Request("http://localhost/test", {
                    headers: { authorization: "Bearer " }, // Empty token
                }),
                env
            );

            expect(extractedKey).toBeNull();
        });
    });

    describe("rate limit response format", () => {
        it("should return proper error response body", async () => {
            const app = createTestApp({
                limit: 1,
                windowSeconds: 30,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            await makeRequest(app);
            const response = await makeRequest(app);

            expect(response.status).toBe(429);

            const body = await response.json();
            expect(body).toEqual({
                code: "RATE_LIMITED",
                message: "Too many requests. Please try again later.",
                details: {
                    retry_after: expect.any(String),
                    limit: "1",
                    window_seconds: "30",
                },
            });
        });

        it("should include Retry-After header on 429", async () => {
            const app = createTestApp({
                limit: 1,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            await makeRequest(app);
            const response = await makeRequest(app);

            const retryAfter = response.headers.get("Retry-After");
            expect(retryAfter).toBeTruthy();

            const retrySeconds = parseInt(retryAfter!, 10);
            expect(retrySeconds).toBeGreaterThan(0);
            expect(retrySeconds).toBeLessThanOrEqual(60);
        });
    });

    describe("edge cases", () => {
        it("should handle very short windows", async () => {
            const app = createTestApp({
                limit: 2,
                windowSeconds: 1,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            const response1 = await makeRequest(app);
            const response2 = await makeRequest(app);

            expect(response1.status).toBe(200);
            expect(response2.status).toBe(200);

            const response3 = await makeRequest(app);
            expect(response3.status).toBe(429);
        });

        it("should handle limit of 1", async () => {
            const app = createTestApp({
                limit: 1,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            const response1 = await makeRequest(app);
            expect(response1.status).toBe(200);
            expect(response1.headers.get("X-RateLimit-Remaining")).toBe("0");

            const response2 = await makeRequest(app);
            expect(response2.status).toBe(429);
        });

        it("should handle concurrent requests correctly", async () => {
            const app = createTestApp({
                limit: 5,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            // Make 10 concurrent requests
            const responses = await Promise.all(
                Array.from({ length: 10 }, () => makeRequest(app))
            );

            const successCount = responses.filter(r => r.status === 200).length;
            const rateLimitedCount = responses.filter(r => r.status === 429).length;

            // At least 5 should succeed, at most 5 should be rate limited
            // (exact numbers may vary due to race conditions)
            expect(successCount).toBeGreaterThanOrEqual(5);
            expect(successCount + rateLimitedCount).toBe(10);
        });

        it("should handle POST requests the same as GET", async () => {
            const app = createTestApp({
                limit: 2,
                windowSeconds: 60,
                keyPrefix: "test",
                keyExtractor: extractClientIp,
            });

            const response1 = await makeRequest(app, { method: "GET" });
            const response2 = await makeRequest(app, { method: "POST" });

            expect(response1.status).toBe(200);
            expect(response2.status).toBe(200);

            const response3 = await makeRequest(app, { method: "GET" });
            expect(response3.status).toBe(429);
        });
    });
});


