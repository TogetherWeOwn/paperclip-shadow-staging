/**
 * Frontend/API contract the E2E suite drives.
 *
 * The SvelteKit app (sibling card) implements these `data-testid` hooks and
 * JSON endpoints; the specs below are the executable side of that contract.
 * If the app drifts (renamed hook, reshaped body), the failing assertion
 * names the contract key — that failure IS the signal, not noise.
 */

// UI hooks (data-testid) the app must render.
export const TESTIDS = {
  appRoot: 'app-root',
  signupEmail: 'signup-email',
  signupSubmit: 'signup-submit',
  signupError: 'signup-error',
  byopHost: 'byop-host',
  byopPort: 'byop-port',
  byopUser: 'byop-user',
  byopPass: 'byop-pass',
  byopTls: 'byop-tls',
  byopTest: 'byop-test-connection',
  byopSave: 'byop-save',
  byopStatus: 'byop-status',
  importFile: 'import-file',
  importStatus: 'import-status',
  libraryItem: 'library-item',
  audioPlayer: 'audio-player',
  usageMeter: 'usage-meter',
  planLimitNotice: 'plan-limit-notice',
} as const;

// API endpoints (relative to STAGING_BASE_URL).
export const API = {
  health: '/api/health',
  ready: '/api/ready',
  testAccounts: '/api/test-accounts',
  ingest: '/api/ingest',
  ingestStatus: (id: string) => `/api/ingest/${id}`,
  library: '/api/library',
  stream: (id: string) => `/api/stream/${id}`,
  usage: '/api/usage',
} as const;

/** HTTP statuses the API uses to signal plan-limit enforcement. */
export const PLAN_LIMIT_STATUSES = [402, 429] as const;

/** A fresh, collision-free test mailbox per run (example.test never routes). */
export function uniqueTestEmail(prefix = 'e2e'): string {
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '');
  const rand = Math.floor(Math.random() * 1_000_000)
    .toString()
    .padStart(6, '0');
  return `${prefix}+${stamp}-${rand}@example.test`;
}

/**
 * Pull a streamed-bytes counter out of a usage body, tolerating field-name
 * drift by checking the known keys. Throws listing the actual keys so a
 * contract change shows up as an explicit diff, not a silent zero.
 */
export function extractUsageBytes(body: unknown): number {
  if (typeof body !== 'object' || body === null) {
    throw new Error(`[usage] expected a JSON object, got ${typeof body}.`);
  }
  const record = body as Record<string, unknown>;
  const candidates = ['bytes_streamed', 'streamed_bytes', 'usage_bytes', 'used_bytes'];
  for (const key of candidates) {
    const value = record[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  // One level of common nesting ({ usage: {...} } / { data: {...} }).
  for (const nest of ['usage', 'data']) {
    const inner = record[nest];
    if (typeof inner === 'object' && inner !== null) {
      try {
        return extractUsageBytes(inner);
      } catch {
        // fall through to the contract error below
      }
    }
  }
  throw new Error(
    `[usage] no known byte counter (${candidates.join(', ')}) in response keys: ` +
      `${Object.keys(record).join(', ') || '(empty)'}. ` +
      'If the metering card renamed the field, update extractUsageBytes + this spec together.',
  );
}

/** Pull plan-limit metadata ({ limit, used, tier }) tolerating key drift. */
export function extractPlanMeta(body: unknown): { limit: number; used: number; tier: string } {
  if (typeof body !== 'object' || body === null) {
    throw new Error(`[usage] expected a JSON object for plan metadata, got ${typeof body}.`);
  }
  const record = body as Record<string, unknown>;
  const pick = (keys: string[]): unknown => {
    for (const key of keys) {
      if (record[key] !== undefined) return record[key];
    }
    const inner = (record.usage ?? record.data) as Record<string, unknown> | undefined;
    if (typeof inner === 'object' && inner !== null) {
      for (const key of keys) {
        if (inner[key] !== undefined) return inner[key];
      }
    }
    return undefined;
  };
  const limit = pick(['limit_bytes', 'plan_limit_bytes', 'limit']);
  const used = pick(['used_bytes', 'usage_bytes', 'used']);
  const tier = pick(['plan', 'plan_tier', 'tier']);
  if (typeof limit !== 'number' || typeof used !== 'number' || typeof tier !== 'string') {
    throw new Error(
      '[usage] plan metadata incomplete: expected numeric limit/used + string tier, ' +
        `got keys: ${Object.keys(record).join(', ') || '(empty)'}.`,
    );
  }
  return { limit, used, tier };
}
