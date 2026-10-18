/**
 * Typed client for the billing/usage REST surface `apps/web` consumes.
 *
 * Expected backend contract (sibling backend cards implement; this file is
 * the frontend half of that handshake):
 *
 * - GET /v1/plans -> { plans: PlanDTO[] }
 * - GET /v1/me/usage -> { period, streamSecondsMonth, concurrentNow, libraryTracks, ingestToday }
 * - GET /v1/me/subscription -> { planId, status, currentPeriodEnd, trialEndsAt }
 * - POST /v1/billing/checkout { planId } -> { url } (Stripe Checkout, 303-style body)
 * - POST /v1/billing/portal {} -> { url } (Stripe customer portal)
 *
 * Auth: session cookie (credentials: include). Entitlement checks run
 * server-side on every stream start; these endpoints are display + redirect
 * helpers only. No Stripe secret ever touches this code.
 */

import type { UsageSnapshot } from './usage';

export interface PlanDTO {
	id: string;
	priceCents: number;
	streamHoursMonth: number;
	maxConcurrentStreams: number;
	maxLibraryTracks: number;
	ingestJobsDay: number;
	cachePriority: string;
}

export interface SubscriptionDTO {
	planId: string;
	/**
	 * ADR 0002 statuses (`trialing`/`active`/`past_due`/`canceled`/`expired`),
	 * plus Stripe's `incomplete` tolerated while payment confirms — never
	 * entitlement-granting either way.
	 */
	status: 'trialing' | 'active' | 'past_due' | 'canceled' | 'expired' | 'incomplete';
	currentPeriodEnd: string | null;
	trialEndsAt: string | null;
	/** End of the past-due grace window (ADR 0002 rule 4); absent when the backend sends none. */
	graceUntil?: string | null;
}

/**
 * Typed fetch failure carrying the HTTP status so loaders can tell a signed-out
 * visitor (401) or a missing record (404) apart from a backend outage. The
 * message keeps the status code so existing `toThrow('404')` assertions hold.
 */
export class BillingApiError extends Error {
	readonly status: number;

	constructor(status: number, label: string, hint = '') {
		super(`${label} failed (${status})${hint}`);
		this.name = 'BillingApiError';
		this.status = status;
	}
}

async function readJson<T>(res: Response, label: string): Promise<T> {
	if (!res.ok) {
		let hint = '';
		try {
			const body = await res.json();
			if (body && typeof body === 'object' && 'error' in body)
				hint = `: ${(body as { error: unknown }).error}`;
		} catch {
			/* non-JSON error body: keep generic */
		}
		throw new BillingApiError(res.status, label, hint);
	}
	return (await res.json()) as T;
}

export async function fetchPlans(fetchFn: typeof fetch = fetch): Promise<PlanDTO[]> {
	const res = await fetchFn('/v1/plans', { credentials: 'include' });
	const data = await readJson<{ plans: PlanDTO[] }>(res, 'Load plans');
	return data.plans;
}

export async function fetchUsage(
	fetchFn: typeof fetch = fetch
): Promise<UsageSnapshot & { period: string }> {
	const res = await fetchFn('/v1/me/usage', { credentials: 'include' });
	return await readJson(res, 'Load usage');
}

export async function fetchSubscription(fetchFn: typeof fetch = fetch): Promise<SubscriptionDTO> {
	const res = await fetchFn('/v1/me/subscription', { credentials: 'include' });
	return await readJson(res, 'Load subscription');
}

export async function startCheckout(
	planId: string,
	fetchFn: typeof fetch = fetch
): Promise<string> {
	if (!planId || /[^a-z0-9-]/.test(planId)) throw new Error('Invalid plan');
	const res = await fetchFn('/v1/billing/checkout', {
		method: 'POST',
		credentials: 'include',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ planId })
	});
	const data = await readJson<{ url: string }>(res, 'Start checkout');
	if (!data.url.startsWith('https://')) throw new Error('Invalid checkout URL');
	return data.url;
}

/**
 * Signup URL for a signed-out visitor whose checkout attempt failed with
 * 401. Returns null for any other error — those stay as inline alerts.
 * The chosen plan rides along so /signup can continue into checkout.
 */
export function signupUrlForCheckoutFailure(planId: string, err: unknown): string | null {
	if (err instanceof BillingApiError && err.status === 401) {
		return `/signup?plan=${encodeURIComponent(planId)}`;
	}
	return null;
}

export async function openPortal(fetchFn: typeof fetch = fetch): Promise<string> {
	const res = await fetchFn('/v1/billing/portal', {
		method: 'POST',
		credentials: 'include',
		headers: { 'content-type': 'application/json' },
		body: '{}'
	});
	const data = await readJson<{ url: string }>(res, 'Open billing portal');
	if (!data.url.startsWith('https://')) throw new Error('Invalid portal URL');
	return data.url;
}
