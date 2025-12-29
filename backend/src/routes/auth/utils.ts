/**
 * Shared utilities for auth routes.
 */

import type { AuthSession } from '../../services/authSession';
import { constantTimeEqual } from '../../crypto';

/**
 * Base URL for auth links.
 * In production, this should be the deployed Worker URL.
 */
export function getBaseUrl(c: { req: { url: string } }): string {
    const url = new URL(c.req.url);
    return `${url.protocol}//${url.host}`;
}

/**
 * Constant-time string comparison that handles empty strings safely.
 */
export function safeConstantTimeEqual(a: string, b: string): boolean {
    // Handle edge cases where constantTimeEqual might throw
    if (!a || !b) {
        return false;
    }
    try {
        return constantTimeEqual(a, b);
    } catch {
        return false;
    }
}

/**
 * Escape HTML special characters to prevent XSS.
 */
export function escapeHtml(str: string): string {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Render an error page HTML.
 */
export function renderErrorPage(message: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Studio Rich Presence</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 400px;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: #ff6b6b;
        }
        p {
            color: #a0aec0;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>Something went wrong</h1>
        <p>${escapeHtml(message)}</p>
    </div>
</body>
</html>`;
}

/**
 * Render a success page HTML with completion code.
 */
export function renderSuccessPage(completionCode: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Success - Studio Rich Presence</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 400px;
        }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
            color: #4ade80;
        }
        .subtitle {
            color: #a0aec0;
            margin-bottom: 2rem;
        }
        .code-container {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        .code-label {
            font-size: 0.875rem;
            color: #a0aec0;
            margin-bottom: 0.5rem;
        }
        .code {
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 3rem;
            font-weight: bold;
            letter-spacing: 0.5rem;
            color: #fff;
        }
        .hint {
            font-size: 0.875rem;
            color: #64748b;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✅</div>
        <h1>Discord Connected!</h1>
        <p class="subtitle">Enter this code in the plugin to complete setup</p>
        <div class="code-container">
            <div class="code-label">Your code</div>
            <div class="code">${escapeHtml(completionCode)}</div>
        </div>
        <p class="hint">If SSE is working, the plugin will detect completion automatically.</p>
    </div>
</body>
</html>`;
}

