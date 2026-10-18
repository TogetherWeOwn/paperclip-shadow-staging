/**
 * Cloudflare Access service-token handling for staging.
 *
 * Staging sits behind Cloudflare Access; CI authenticates with a QA service
 * token passed as the CF-Access-Client-Id / CF-Access-Client-Secret headers.
 * Only secret NAMES appear here — values come from the environment
 * (GitHub Actions secrets on CI, shell exports locally). Nothing here may
 * log or persist a secret value.
 */

export interface WallProbe {
  status: number;
  headers: Record<string, string>;
  bodyText: string;
  url: string;
}

/** Extra headers to attach to every staging request (page + API). */
export function accessHeaders(): Record<string, string> {
  const id = process.env.CF_ACCESS_CLIENT_ID;
  const secret = process.env.CF_ACCESS_CLIENT_SECRET;
  if (id && secret) {
    return {
      'CF-Access-Client-Id': id,
      'CF-Access-Client-Secret': secret,
    };
  }
  if (process.env.STAGING_BASE_URL?.trim() || id || secret) {
    throw new Error(
      'Cloudflare Access misconfigured: configured staging requires both ' +
        'CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET (secret names only — never values).',
    );
  }
  return {};
}

/** Bearer header for the staging test-account seam, when configured. */
export function qaAuthHeader(): Record<string, string> {
  const token = process.env.QA_AUTH_TOKEN;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/**
 * Same-origin gate for credentialed browser traffic (review finding: the
 * Access service token and session bearer must never go to every origin).
 * `extraHTTPHeaders` / `setExtraHTTPHeaders` attach to cross-origin
 * subresources too, so pages scope headers through this predicate in a
 * `context.route` handler instead: staging origin → attach, anything else →
 * continue unmodified. Pure function so the two-origin behavior is pinned by
 * offline self-tests without launching a browser.
 */
export function isStagingOrigin(requestUrl: string, baseURL: string): boolean {
  try {
    return new URL(requestUrl).origin === new URL(baseURL).origin;
  } catch {
    return false;
  }
}

/**
 * Fail closed when a response is the Cloudflare Access wall instead of the
 * app: a wall-status code (401/403/302) TOGETHER WITH Access markers means
 * the service token is missing or wrong. Status and markers are checked
 * jointly so a legitimate app 401/403 is never misreported as a wall.
 * Never silently treat the wall as an app response.
 */
export function assertNoAccessWall(probe: WallProbe, context: string): void {
  const headerDump = Object.entries(probe.headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
  const location = probe.headers['location'] ?? probe.headers['Location'] ?? '';
  const redirectToAccess =
    probe.status === 302 && /cloudflareaccess\.com|\/cdn-cgi\/access/i.test(location);
  const wallStatus =
    probe.status === 401 || probe.status === 403 || probe.status === 302 || redirectToAccess;
  const hasMarkers =
    /cf-access|cf_authorization|cf-mitigated|cf_clearance/i.test(headerDump) ||
    /cloudflare.?access/i.test(headerDump) ||
    /cloudflare.?access/i.test(probe.bodyText) ||
    /<title>\s*Access/i.test(probe.bodyText) ||
    redirectToAccess;
  if (wallStatus && hasMarkers) {
    throw new Error(
      `[${context}] hit the Cloudflare Access wall at ${probe.url} ` +
        `(HTTP ${probe.status}). Set CF_ACCESS_CLIENT_ID + ` +
        'CF_ACCESS_CLIENT_SECRET for a QA service token with staging access. ' +
        'See e2e/README.md. No secret values are logged here by design.',
    );
  }
}

interface ApiResponseLike {
  status(): number;
  headers(): Record<string, string>;
  text(): Promise<string>;
}

/**
 * Read an API response body, probe it for the Access wall, and return the
 * text for the caller to parse. Use for JSON/error bodies (small). For
 * binary success bodies (e.g. 206 stream segments) probe headers only via
 * assertNoAccessWall with an empty bodyText instead of buffering megabytes.
 */
export async function readApiBody(
  res: ApiResponseLike,
  url: string,
  context: string,
): Promise<string> {
  const bodyText = await res.text().catch(() => '');
  assertNoAccessWall({ status: res.status(), headers: res.headers(), bodyText, url }, context);
  return bodyText;
}

/**
 * Resolve the staging base URL.
 * - Returns null when unconfigured: callers skip with a notice (pre-deploy).
 * - Throws when `required` and unconfigured: callers fail closed (post-deploy).
 */
export function stagingBaseUrl(required: 'skip' | 'fail-closed', context: string): string | null {
  const raw = (process.env.STAGING_BASE_URL || '').trim().replace(/\/+$/, '');
  if (!raw) {
    if (required === 'fail-closed') {
      throw new Error(
        `[${context}] STAGING_BASE_URL is not set. Staging is expected to be ` +
          'configured — refusing to pass silently. See e2e/README.md.',
      );
    }
    return null;
  }
  if (!/^https:\/\//i.test(raw)) {
    throw new Error(
      `[${context}] STAGING_BASE_URL must be an https:// URL, got a non-https value. ` +
        'Refusing to run against a non-TLS staging target.',
    );
  }
  accessHeaders(); // Validate the pair before any caller can use the protected URL.
  return raw;
}

/** Synthetic NNTP endpoint the BYOP wizard points at (hosted fixture server or test provider). */
export interface NntpEndpoint {
  host: string;
  port: number;
  user: string;
  tls: boolean;
}

/**
 * NNTP endpoint config. Host/user have fixture defaults (not secrets); the
 * password has NO default and stays in the environment. TLS defaults on.
 */
export function syntheticNntpEndpoint(): NntpEndpoint & { hasPassword: boolean } {
  const host = (process.env.SYNTHETIC_NNTP_HOST || 'synthetic-nntp').trim();
  const port = Number(process.env.SYNTHETIC_NNTP_PORT || '563');
  const user = (process.env.SYNTHETIC_NNTP_USER || 'e2e').trim();
  const tls = (process.env.SYNTHETIC_NNTP_TLS || 'on').toLowerCase() !== 'off';
  if (!host) throw new Error('[byop] SYNTHETIC_NNTP_HOST is empty.');
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error('[byop] SYNTHETIC_NNTP_PORT must be a valid TCP port number.');
  }
  return { host, port, user, tls, hasPassword: Boolean(process.env.SYNTHETIC_NNTP_PASS) };
}
