/**
 * Cron: mark queued/in-review market proposals past their deadline as stale.
 *
 * Authorization: same `CRON_SECRET` bearer pattern as the other cron routes. The
 * tier fails closed when `CRON_SECRET` is unset, so a deploy that forgets
 * the secret returns 403 rather than leaving the sweep publicly callable.
 *
 * Admin authentication is deliberately separate from user sessions: this
 * route never consults cookie-based user sessions and only accepts the
 * internal-worker bearer secret. This keeps operational actions from being
 * reachable through funded user flows and preserves Soroban-state authority.
 */

import { NextResponse } from "next/server";
import { authorizeRequest } from "@/lib/api/policy";
import { isDbConfigured, markStaleProposals } from "@/lib/db";

export const runtime = "nodejs";

const ROUTE = "/api/cron/proposals/mark-stale";

export async function POST(request: Request): Promise<NextResponse> {
  // Admin/operational auth only: no user-session fallback. Missing, malformed,
  // or stale credentials fail closed via the policy tier.
  const header = request.headers.get("authorization") ?? "";
  const presented = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const auth = authorizeRequest("internal_worker", {
    route: ROUTE,
    presentedSecret: presented,
    expectedSecret: process.env.CRON_SECRET,
  });
  if (!auth.allowed && auth.error) {
    return NextResponse.json(auth.error.body, {
      status: auth.error.status,
      headers: auth.error.headers,
    });
  }

  if (!isDbConfigured()) {
    return NextResponse.json({ error: { message: "Database not configured" } }, { status: 503 });
  }

  try {
    const nowSeconds = Math.floor(Date.now() / 1000);
    // Idempotent sweep: repeated or duplicate invocations only touch rows
    // still in a non-terminal queued/in-review state, so already-stale
    // proposals are not re-processed.
    const count = await markStaleProposals(nowSeconds);

    return NextResponse.json(
      {
        success: true,
        markedStale: count,
        timestamp: new Date().toISOString(),
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (err) {
    // Dependency failure (DB down, transaction aborted) is reported as a 500
    // without leaking credentials or row details. Soroban state remains
    // authoritative; this sweep only marks deadline-expired proposals.
    console.error("[cron/proposals/mark-stale] Error:", err instanceof Error ? err.message : "Unknown error");
    return NextResponse.json(
      { error: { message: "Internal error" } },
      { status: 500, headers: { "Cache-Control": "no-store" } },
    );
  }
}
