/**
 * Access tiers for API routes (#11).
 *
 * Five kinds of caller reach these routes and they need different things checked.
 * Before this, each route decided for itself — which is how one of them ends up
 * reading a secret from the wrong header, or forgetting a rate limit, and nobody
 * notices because there is no single place to look.
 *
 *   public_read        anyone, including an OG scraper with no session
 *   authenticated_user a wallet acting for itself
 *   registered_agent   an agent acting under a signed, replay-protected envelope
 *   api_key_agent     an agent presenting a bearer API key
 *   internal_worker    a cron or worker holding the shared secret
 *   admin_operator      an operator presenting the admin secret, distinct from user sessions
 *
 * The rules that make this worth having:
 *
 *  - **A tier declares its requirements; a route only names its tier.** A route
 *    cannot accidentally be laxer than its tier, because it does not get to
 *    choose.
 *  - **Money- or authority-changing calls demand an idempotency key** at any tier
 *    above public read. A retried payment without one is a second payment.
 *  - **The secret comparison is length-checked and constant-time-ish.** A plain
 *    `===` on a secret leaks its length through timing; that is a small leak, but
 *    it is free to avoid.
 *  - **A missing configured secret refuses everything.** An unset CRON_SECRET must
 *    not mean "no auth required" — that turns a deploy mistake into an open
 *    endpoint. The same applies to ADMIN_SECRET: admin auth is not a user session
 *    and must not fall back to one.
 */

import { apiError, type ApiErrorCode, type ApiErrorResult } from "./errors";
import { consume, DEFAULT_RULES, type LimitRule, type RateLimitKeys } from "./rate-limit";

export const ACCESS_TIERS = [
  "public_read",
  "authenticated_user",
  "registered_agent",
  "api_key_agent",
  "internal_worker",
  "admin_operator",
] as const;
export type AccessTier = (typeof ACCESS_TIERS)[number];

export function isAccessTier(value: string): value is AccessTier {
  return (ACCESS_TIERS as readonly string[]).includes(value);
}

export interface TierPolicy {
  tier: AccessTier;
  /** A wallet address must be present and proven. */
  requiresWallet: boolean;
  /** A signed request envelope must verify. */
  requiresSignature: boolean;
  /** The shared worker secret must match. */
  requiresWorkerSecret: boolean;
  /** The admin secret must match. Distinct from the worker secret. */
  requiresAdminSecret: boolean;
  /** Requires browser-origin validation for mutating requests (CSRF protection). */
  requiresOriginValidation: boolean;
  /** Rate-limit dimensions that apply. */
  limitDimensions: LimitRule["dimension"][];
}

export const TIER_POLICIES: Record<AccessTier, TierPolicy> = {
  public_read: {
    tier: "public_read",
    requiresWallet: false,
    requiresSignature: false,
    requiresWorkerSecret: false,
    requiresAdminSecret: false,
    requiresOriginValidation: false,
    // IP and route only: an anonymous caller has no wallet to bucket by.
    limitDimensions: ["ip", "route"],
  },
  authenticated_user: {
    tier: "authenticated_user",
    requiresWallet: true,
    requiresSignature: false,
    requiresWorkerSecret: false,
    requiresAdminSecret: false,
    requiresOriginValidation: true,
    limitDimensions: ["ip", "wallet", "route"],
  },
  registered_agent: {
    tier: "registered_agent",
    requiresWallet: true,
    requiresSignature: true,
    requiresWorkerSecret: false,
    requiresAdminSecret: false,
    requiresOriginValidation: false,
    limitDimensions: ["agent", "route"],
  },
  /**
   * A registered agent presenting an API key instead of signing every envelope.
   *
   * No wallet and no per-request signature: the key is the credential, and what the
   * key can *spend* is bounded separately by the owner-signed spend permission. A
   * leaked key therefore costs at most the remaining allowance, not the account.
   *
   * Bucketed by agent first — the meaningful key for BYOA, since one developer's
   * fleet may share an IP and one agent may rotate IPs freely.
   */
  api_key_agent: {
    tier: "api_key_agent",
    requiresWallet: false,
    requiresSignature: false,
    requiresWorkerSecret: false,
    requiresAdminSecret: false,
    requiresOriginValidation: false,
    limitDimensions: ["agent", "ip", "route"],
  },
  internal_worker: {
    tier: "internal_worker",
    requiresWallet: false,
    requiresSignature: false,
    requiresWorkerSecret: true,
    requiresAdminSecret: false,
    requiresOriginValidation: false,
    // Route only: a worker's own bursts are a scheduling problem, not abuse, and
    // bucketing by IP would rate-limit an entire serverless region together.
    limitDimensions: ["route"],
  },
  /**
   * An operator tool caller presenting the admin secret.
   *
   * Admin authentication is deliberately not a user session and not the worker
   * secret: an admin operator is not a wallet acting for itself, and a cron job
   * is not an operator. Mixing them means a compromised worker credential
   * could drive operational actions, or a logged-in user could reach them.
   *
   * Bucketed by IP and route: the admin secret is shared, so there is no stable
   * per-operator identity to bucket by, and an exhausted operator should not be
   * able to look up the secret by brute forcing.
   */
  admin_operator: {
    tier: "admin_operator",
    requiresWallet: false,
    requiresSignature: false,
    requiresWorkerSecret: false,
    requiresAdminSecret: true,
    requiresOriginValidation: false,
    limitDimensions: ["ip", "route"],
  },
};

export interface RequestContext {
  route: string;
  ip?: string;
  wallet?: string;
  agentId?: string;
  /** Result of verifying the signed envelope, when the caller did that. */
  signatureVerified?: boolean;
  /** Secret presented by the caller, e.g. from an Authorization header. */
  presentedSecret?: string;
  /** Secret the server expects for the worker tier. Undefined means none is configured. */
  expectedSecret?: string;
  /** Admin secret presented by the caller. Distinct from the worker secret. */
  presentedAdminSecret?: string;
  /** Admin secret the server expects. Undefined means none is configured. */
  expectedAdminSecret?: string;
  /** True when this call moves money or changes authority. */
  mutatesValue?: boolean;
  idempotencyKey?: string;
  /** True if the origin was verified against the host. */
  originValid?: boolean;
}

export interface AuthorizeResult {
  allowed: boolean;
  /** Present when refused — ready to return. */
  error?: ApiErrorResult;
  /** The tier the request was evaluated against. */
  tier: AccessTier;
}

/**
 * Compare two secrets without an early return on the first differing byte.
 *
 * Not a substitute for a real constant-time primitive, but it removes the trivial
 * length-and-prefix oracle that `===` gives away.
 */
function secretsMatch(presented: string, expected: string): boolean {
  if (presented.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < presented.length; i += 1) {
    diff |= presented.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

export function authorizeRequest(
  tier: AccessTier,
  ctx: RequestContext,
  rules: LimitRule[] = DEFAULT_RULES,
  now = Date.now(),
): AuthorizeResult {
  const policy = TIER_POLICIES[tier];
  const refuse = (code: ApiErrorCode, detail: string): AuthorizeResult => ({
    allowed: false,
    error: apiError(code, detail),
    tier,
  });

  if (policy.requiresWorkerSecret) {
    const expected = ctx.expectedSecret?.trim();
    // An unset secret refuses rather than waves everyone through: a deploy that
    // forgets it must fail closed, not open.
    if (!expected) return refuse("forbidden", "worker secret is not configured");
    const presented = ctx.presentedSecret?.trim() ?? "";
    if (!presented || !secretsMatch(presented, expected)) {
      return refuse("unauthenticated", "invalid worker credentials");
    }
  }

  if (policy.requiresAdminSecret) {
    const expected = ctx.expectedAdminSecret?.trim();
    // Admin auth fails closed too. An unset ADMIN_SECRET must not fall back to
    // a user session or the worker secret — those are different trust boundaries.
    if (!expected) return refuse("forbidden", "admin secret is not configured");
    const presented = ctx.presentedAdminSecret?.trim() ?? "";
    if (!presented || !secretsMatch(presented, expected)) {
      return refuse("unauthenticated", "invalid admin credentials");
    }
  }

  if (policy.requiresWallet && !ctx.wallet) {
    return refuse("unauthenticated", "a wallet is required for this route");
  }

  if (policy.requiresSignature) {
    if (!ctx.agentId) return refuse("unauthenticated", "an agent id is required");
    // Explicitly false vs undefined: "not verified" and "verification never ran"
    // are both refusals, and treating undefined as a pass is the classic hole.
    if (ctx.signatureVerified !== true) {
      return refuse("invalid_signature", "request signature did not verify");
    }
  }

  // A retried money-moving call without an idempotency key is a second payment.
  if (ctx.mutatesValue && tier !== "public_read" && !ctx.idempotencyKey?.trim()) {
    return refuse("invalid_request", "an idempotency key is required for this operation");
  }

  // Enforce browser-origin policy (CSRF) for mutating requests.
  if (ctx.mutatesValue && policy.requiresOriginValidation) {
    if (ctx.originValid !== true) {
      return refuse("forbidden", "cross-origin mutations are not allowed");
    }
  }

  const keys: RateLimitKeys = {
    route: ctx.route,
    ip: policy.limitDimensions.includes("ip") ? ctx.ip : undefined,
    wallet: policy.limitDimensions.includes("wallet") ? ctx.wallet : undefined,
    agentId: policy.limitDimensions.includes("agent") ? ctx.agentId : undefined,
  };
  const applicable = rules.filter((rule) => policy.limitDimensions.includes(rule.dimension));
  const decision = consume(keys, applicable, now);
  if (!decision.allowed) {
    return refuse(
      "rate_limited",
      `${decision.exceeded} limit exceeded; retry in ${decision.retryAfterSeconds ?? 60}s`,
    );
  }

  return { allowed: true, tier };
}

/**
 * A public read route must never be able to move value.
 *
 * Enforced as its own assertion rather than folded into authorizeRequest, so the
 * mistake is caught where the route is declared instead of only when a request
 * happens to arrive.
 */
export function assertTierCanMutate(tier: AccessTier): void {
  if (tier === "public_read") {
    throw new Error("public_read routes cannot move value or change authority");
  }
}
