import { apiError, type ApiErrorResult } from "../api/errors";
import { authorizeRequest, type AccessTier, type RequestContext } from "../api/policy";

/**
 * Admin authentication boundary.
 *
 * This module enforces that administrative operations are authenticated via a
 * dedicated internal worker secret, completely separate from user sessions or
 * agent API keys. This preserves funded-state safety by ensuring that only
 * trusted operational infrastructure can trigger state-changing admin actions.
 *
 * Key properties:
 * - Uses the `internal_worker` access tier policy.
 * - Refuses if the worker secret is not configured (fail-closed).
 * - Uses constant-time-ish comparison to prevent timing leaks.
 * - Does not accept user wallets, signatures, or API keys.
 */

export interface AdminAuthResult {
  allowed: boolean;
  error?: ApiErrorResult;
}

/**
 * Authenticate an administrative request.
 *
 * Validates the request against the `internal_worker` tier policy. This ensures
 * that admin routes are only accessible via the shared operational secret,
 * maintaining a clear boundary from user-facing authentication mechanisms.
 *
 * @param secret - The secret presented by the caller (e.g., from Authorization header).
 * @param route - The route being accessed, used for rate limiting context.
 * @param ip - The client IP, used for rate limiting context.
 * @returns Result indicating whether the request is allowed.
 */
export async function authenticateAdminRequest(
  secret: string | null | undefined,
  route: string,
  ip?: string,
): Promise<AdminAuthResult> {
  const tier: AccessTier = "internal_worker";

  const ctx: RequestContext = {
    route,
    ip,
    presentedSecret: secret,
    expectedSecret: process.env.WORKER_SECRET,
    mutatesValue: true, // Admin actions are assumed to mutate state
  };

  const result = authorizeRequest(tier, ctx);

  if (!result.allowed) {
    return {
      allowed: false,
      error: result.error,
    };
  }

  return { allowed: true };
}

/**
 * Check if the admin secret is configured.
 *
 * Returns false if the WORKER_SECRET environment variable is not set.
 * This allows for early validation in deployment pipelines or health checks.
 */
export function isAdminAuthConfigured(): boolean {
  return !!process.env.WORKER_SECRET;
}