/**
 * Plan matrix for NNTune v2 billing UI.
 *
 * Mirrors the `plans` table shape (ADR 0002) and the accepted tiers
 * (ADR 0004: Free 14-day trial, Plus, Pro 5x, Pro 20x). Prices and caps are
 * data here so the table can later be hydrated from `GET /v1/plans` without
 * changing components. Changing numbers needs no deploy on the backend;
 * this file is the frontend fallback + contract reference.
 *
 * Security: this module is display-only. Enforcement happens server-side
 * (API worker reads `subscriptions` + `plans` + `usage_ledger` via
 * Hyperdrive). Never gate access on these client values.
 */

export type CachePriority = 'low' | 'standard' | 'high' | 'highest';

export interface Plan {
	id: string;
	name: string;
	priceCents: number;
	streamHoursMonth: number;
	maxConcurrentStreams: number;
	maxLibraryTracks: number;
	ingestJobsDay: number;
	cachePriority: CachePriority;
	blurb: string;
}

export const PLANS: Plan[] = [
	{
		id: 'free',
		name: 'Free trial',
		priceCents: 0,
		streamHoursMonth: 10,
		maxConcurrentStreams: 1,
		maxLibraryTracks: 1000,
		ingestJobsDay: 5,
		cachePriority: 'low',
		blurb: '14-day trial. Bring your own Usenet provider.'
	},
	{
		id: 'plus',
		name: 'Plus',
		priceCents: 800,
		streamHoursMonth: 100,
		maxConcurrentStreams: 2,
		maxLibraryTracks: 25000,
		ingestJobsDay: 25,
		cachePriority: 'standard',
		blurb: 'Base paid tier for everyday listening.'
	},
	{
		id: 'pro-5x',
		name: 'Pro 5x',
		priceCents: 3000,
		streamHoursMonth: 500,
		maxConcurrentStreams: 4,
		maxLibraryTracks: 100000,
		ingestJobsDay: 100,
		cachePriority: 'high',
		blurb: '5x usage for heavy listeners and big libraries.'
	},
	{
		id: 'pro-20x',
		name: 'Pro 20x',
		priceCents: 10000,
		streamHoursMonth: 2000,
		maxConcurrentStreams: 8,
		maxLibraryTracks: 500000,
		ingestJobsDay: 400,
		cachePriority: 'highest',
		blurb: '20x usage for households and collectors.'
	}
];

export function getPlan(id: string): Plan | undefined {
	return PLANS.find((p) => p.id === id);
}

export function listPlans(): Plan[] {
	return [...PLANS];
}

export function isTrialPlan(id: string): boolean {
	return id === 'free';
}

export function formatPrice(plan: Plan): string {
	if (plan.priceCents === 0) return '$0';
	return `$${plan.priceCents / 100}`;
}

export function formatPricePerMonth(plan: Plan): string {
	if (plan.priceCents === 0) return '$0 · 14 days, then pick a plan';
	return `$${plan.priceCents / 100}/mo`;
}

/** Stream cap in seconds (plans table stores hours). */
export function streamCapSeconds(plan: Plan): number {
	return plan.streamHoursMonth * 3600;
}

/**
 * Minimal subscription shape for plan resolution. Kept structural (instead
 * of importing SubscriptionDTO) so this module stays dependency-free.
 */
export interface SubscriptionRef {
	planId: string;
	status: string;
	/** End of the past-due grace window (ADR 0002 rule 4); null/omitted when none. */
	graceUntil?: string | null;
}

export interface EffectivePlan {
	plan: Plan;
	/**
	 * True when the subscription is missing, unknown, or not entitlement-
	 * granting: the caller is seeing trial defaults, not the user's real
	 * plan, and must say so instead of naming a paid tier.
	 */
	planUnknown: boolean;
}

const ENTITLED_STATUSES = new Set(['active', 'trialing']);

/**
 * True while a past-due subscription is still inside its grace window
 * (ADR 0002 rule 4): the server keeps enforcing the real plan's caps, so
 * the UI must score usage against them too. An unparseable or missing
 * window fails closed to lapsed.
 */
function inGraceWindow(subscription: SubscriptionRef, now: Date): boolean {
	if (subscription.status !== 'past_due') return false;
	if (!subscription.graceUntil) return false;
	return new Date(subscription.graceUntil).getTime() > now.getTime();
}

/**
 * Effective plan per ADR 0004: the subscription's plan while it grants
 * entitlement (`active`/`trialing`, plus `past_due` inside its grace
 * window per ADR 0002 rule 4) and names a known tier; the free trial
 * row otherwise. Never invents a paid tier for an unknown state.
 */
export function resolveEffectivePlan(
	subscription: SubscriptionRef | null,
	now: Date = new Date()
): EffectivePlan {
	const plan = subscription ? getPlan(subscription.planId) : undefined;
	if (
		subscription &&
		plan &&
		(ENTITLED_STATUSES.has(subscription.status) || inGraceWindow(subscription, now))
	) {
		return { plan, planUnknown: false };
	}
	return { plan: getPlan('free')!, planUnknown: true };
}

/** Next upgrade step for prompts, or null when already at the top. */
export function nextPlan(id: string): Plan | undefined {
	const order = ['free', 'plus', 'pro-5x', 'pro-20x'];
	const idx = order.indexOf(id);
	if (idx < 0 || idx >= order.length - 1) return undefined;
	return getPlan(order[idx + 1]);
}
