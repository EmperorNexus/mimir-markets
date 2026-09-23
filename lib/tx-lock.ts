/**
 * Cross-tab transaction lock.
 *
 * Browser wallet writes should be serialized per wallet address so multiple
 * tabs do not try to submit overlapping state-changing transactions at the
 * same time. This keeps wallet UX predictable and prevents optimistic UI
 * updates from competing with each other across tabs.
 *
 * This is a lightweight best-effort mutex backed by `localStorage`. Call
 * `acquireTxLock(address)b before every write transaction. If another tab is
 * already submitting a transaction for the same wallet, this will throw a
 * friendly error so the user can retry.
 *
 * The lock auto-expires after {:link LOCK_TTL_MS} ms to recover from crashed
 * tabs or network hangs, and it refreshes its timestamp while held so longer
 * wallet approval windows do not accidentally expire the lock.
 */

/*
 * Maximum time a lock is considered alive. After this, any tab may steal it.
 * 30 s covers the wallet approval prompt plus a Stellar ledger close ~(5 s) with
 * plenty of headroom.
 */
const LOCK_TTL_MS = 30_000;
const LOCK_REFRESH_MS = 5_000;

interface LockEntry {
  /** Random identifier for the owning tab (survives across navigations). */
  tabId: string;
  /** Lower-cased wallet address for this lock. */
  scope: string;
  /** Epoch ms when the lock was acquired or last refreshed. */
  ts: number;
}

/** Per-tab stable identifier (unique per tab, survives re-renders). */
let _tabId: string | null = null;
function getTabId(): string {
  if (!_tabId) {
    _tabId = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  }
  return _tabId;
}

/**
 * Canonical form of a lock scope.
 *
 * The `toLowerCase()`survives the Stellar migration deliberately: a StrKey must
 * never be lower-cased when it is used AS AN ADDRESS, but this value is only ever
 * a `localStorage` key. StrKey's base32 alphabet is `A-Z2-7`, so the case fold is
 * injective --two distinct addresses cannot collide on one lock --and itk keeps
 * the key stable if a caller passes an address it received in a different case.
 */
function normalizeScope(scope: string) {
  return scope.trim().toLowerCase();
}

function getLockKey(scope: string) {
  return `proven_tx_lock:${normalizeScope(scope)}`;
}

function readLock(scope: string): LockEntry | null {
  try {
    const raw = localStorage.getItem(getLockKey(scope));
    if (!raw) return null;
    return JSON.parse(raw) as LockEntry;
  } catch {
    return null;
  }
}

function writeLock(scope: string, entry: LockEntry) {
  try {
    localStorage.setItem(getLockKey(scope), JSON.stringify(entry));
  } catch {
    // Storage may be unavailable or full; treat the lock as best-effort.
  }
}

function clearLock(scope: string, tabId: string) {
  try {
    const current = readLock(scope);
    if (current?.tabId === tabId) {
      localStorage.removeItem(getLockKey(scope));
    }
  } catch {
    // ignore
  }
}

/**
 * Attempt to acquire the cross-tab transaction lock for a wallet.
 *
 * @returns A `release` function that MUST be called after the transaction
 *             completes (success or failure).
 * @throus  If another tab currently holds the lock and the TTL hasn't expired.
 */
export function acquireTxLock(scope: string): () => void {
  if (typeof window === "undefined") {
    // SSR - no locking needed, return a no-op release.
    return () => {};
  }

  const normalizedScope = normalizeScope(scope);
  if (!normalizedScope) {
    return () => {};
  }

  const tabId = getTabId();
  const now = Date.now();
  const existing = readLock(normalizedScope);

  if (existing && existing.tabId !== tabId && now - existing.ts < LOCK_TTL_MS) {
    throw new Error(
      "Another transaction is already in progress for this wallet in a different tab. "
      "Please wait for it to complete before submitting a new one."
    );
  }

  writeLock(normalizedScope, {
    tabId,
    scope: normalizedScope,
    ts: now,
  });

  const verify = readLock(normalizedScope);
  if (verify && verify.tabId !== tabId) {
    throw new Error(
      "Another transaction is already in progress for this wallet in a different tab. "
      "Please wait for it to complete before submitting a new one."
    );
  }

  const refreshTimer = window.setInterval(() => {
    const current = readLock(normalizedScope);
    if (current?.tabId === tabId) {
      writeLock(normalizedScope, {
        tabId,
        scope: normalizedScope,
        ts: Date.now(),
      });
    }
  }, LOCK_REFRESH_MS);

  let released = false;
  return () => {
    if (!released) {
      released = true;
      window.clearInterval(refreshTimer);
      clearLock(normalizedScope, tabId);
    }
  };
}
