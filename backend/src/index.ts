import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import type { Env } from "./env";

// Create Hono app with typed environment
const app = new Hono<{ Bindings: Env }>();

// Middleware
app.use("*", logger());
app.use("*", cors({
	origin: "*", // Roblox Studio doesn't send Origin header
	allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
	allowHeaders: ["Content-Type", "Authorization", "X-Ack-Token", "X-Client-Key"],
}));

// Health check
app.get("/", (c) => {
	return c.json({ status: "ok", service: "studio-rich-presence" });
});

// TODO: Register API routes
// app.route("/auth", authRoutes);
// app.route("/api", apiRoutes);

// Export for Cloudflare Workers
export default {
	fetch: app.fetch,

	// Scheduled handler for cron triggers (cleanup jobs)
	async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
		console.log(`Cron trigger fired at ${event.cron}`);

		ctx.waitUntil(Promise.all([
			cleanupInactiveAccounts(env),
			cleanupExpiredSessions(env),
			cleanupExpiredPendingTokens(env),
		]));
	},
};

// Cleanup functions (will be moved to separate file later)
async function cleanupInactiveAccounts(env: Env): Promise<void> {
	const INACTIVITY_THRESHOLD_DAYS = 90;
	const thresholdTimestamp = Date.now() - (INACTIVITY_THRESHOLD_DAYS * 24 * 60 * 60 * 1000);

	// Delete inactive users (CASCADE will delete their discord_accounts)
	const result = await env.DB.prepare(`
		DELETE FROM users 
		WHERE last_activity_at < ?
	`).bind(thresholdTimestamp).run();

	console.log(JSON.stringify({
		event: "cleanup_inactive_accounts",
		deleted_count: result.meta.changes,
		threshold_days: INACTIVITY_THRESHOLD_DAYS,
	}));
}

async function cleanupExpiredSessions(env: Env): Promise<void> {
	const now = Date.now();

	const result = await env.DB.prepare(`
		DELETE FROM auth_sessions 
		WHERE expires_at < ?
	`).bind(now).run();

	console.log(JSON.stringify({
		event: "cleanup_expired_sessions",
		deleted_count: result.meta.changes,
	}));
}

async function cleanupExpiredPendingTokens(env: Env): Promise<void> {
	const now = Date.now();

	const result = await env.DB.prepare(`
		UPDATE users 
		SET pending_token_hash = NULL, pending_token_expires = NULL
		WHERE pending_token_expires IS NOT NULL AND pending_token_expires < ?
	`).bind(now).run();

	console.log(JSON.stringify({
		event: "cleanup_expired_pending_tokens",
		cleared_count: result.meta.changes,
	}));
}
