/**
 * Per-cycle evidence cache.
 *
 * 10 personas often look at the same claim in a single poll cycle.
 * Without caching, that's 10 HTTP fetches of the same resolution URL
 * per claim per cycle — wasteful and rate-limit-prone.
 *
 * The runner builds one of these per cycle and the LLM evaluators ask
 * it before doing a fetch. Cleared between cycles to avoid serving
 * stale evidence at settlement time.
 */

import { sha256Hex } from "../../../lib/content-hash";
import {
  fetchEvidence as fetchEvidenceShared,
  EvidenceFetchError,
} from "../../../lib/server/evidence-fetcher";
import type { EvidenceCacheEntry } from "./types";

const MAX_CONTENT_CHARS = 8_000;

/** The fetch used on a cache miss; injectable so tests need no network. */
export type EvidenceFetcher = typeof fetchEvidenceShared;

/** Result of an integrity check on a cache entry. */
export interface EvidenceIntegrityResult {
  /** True if the entry passed all integrity checks. */
  success: boolean;
  /** Reason for failure, or empty string on success. */
  reason: string;
}

/**
 * Validate that a cached evidence entry is consistent with its hash and text.
 *
 * This check ensures that:
 * - The hash is a valid SHA-256 hex string (64 hex characters).
 * - The hash matches the actual SHA-256 of the text content.
 * - The text is neither empty nor longer than the fetch cap.
 * - The entry names the fetcher that produced it.
 */
export function validateEvidenceIntegrity(entry: EvidenceCacheEntry): EvidenceIntegrityResult {
  if (!entry.hash || typeof entry.hash !== "string") {
    return { success: false, reason: "missing or invalid hash field" };
  }
  if (!/^[0-9a-fA-F]{64}$/.test(entry.hash)) {
    return { success: false, reason: "invalid hash format - expected 32-byte hex" };
  }
  if (typeof entry.text !== "string") {
    return { success: false, reason: "missing or invalid text field" };
  }
  if (entry.text.length === 0) {
    return { success: false, reason: "evidence text is empty" };
  }
  if (entry.text.length > MAX_CONTENT_CHARS) {
    return { success: false, reason: "evidence text exceeds maximum length" };
  }
  if (sha256Hex(entry.text) !== entry.hash) {
    return { success: false, reason: "hash mismatch - data may be tampered or stale" };
  }
  if (!entry.fetcher || typeof entry.fetcher !== "string") {
    return { success: false, reason: "missing or invalid fetcher field" };
  }
  return { success: true, reason: "" };
}

export async function getOrFetchEvidence(
  claimId: number,
  resolutionUrl: string,
  cache: Map<number, EvidenceCacheEntry>,
  fetcher: EvidenceFetcher = fetchEvidenceShared,
): Promise<EvidenceCacheEntry> {
  const hit = cache.get(claimId);
  if (hit) return hit;

  if (!resolutionUrl?.startsWith("http")) {
    const empty: EvidenceCacheEntry = {
      text:    "(No resolution URL provided)",
      fetcher: "none",
      hash:    sha256Hex("(No resolution URL provided)"),
    };
    cache.set(claimId, empty);
    return empty;
  }

  try {
    const snap = await fetcher(resolutionUrl, {
      maxChars:  MAX_CONTENT_CHARS,
      userAgent: "Mimir-Council/1.0",
    });
    const entry: EvidenceCacheEntry = {
      text:      snap.text,
      fetcher:   snap.fetcher,
      hash:      sha256Hex(snap.text),
      fetchedAt: snap.fetchedAt,
      sourceUrl: snap.sourceUrl,
    };
    cache.set(claimId, entry);
    return entry;
  } catch (err: unknown) {
    const msg =
      err instanceof EvidenceFetchError
        ? err.message
        : err instanceof Error
          ? err.message
          : "unknown";
    const failed: EvidenceCacheEntry = {
      text:    `(Failed to fetch: ${msg})`,
      fetcher: "none",
      hash:    sha256Hex(`(Failed to fetch: ${msg})`),
    };
    cache.set(claimId, failed);
    return failed;
  }
}
