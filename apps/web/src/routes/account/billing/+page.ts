import type { PageLoad } from './$types';
import {
	BillingApiError,
	fetchSubscription,
	fetchUsage,
	type SubscriptionDTO
} from '#lib/billing/billingClient.js';
import { resolveEffectivePlan } from '#lib/billing/plans.js';
import { evaluateUsage, type LimitStatus, type UsageSnapshot } from '#lib/billing/usage.js';

export type UsageDTO = UsageSnapshot & { period: string };

/** Subscription states whose entitlement has lapsed: portal, never checkout. */
const LAPSED = new Set(['past_due', 'canceled', 'expired', 'incomplete']);

interface LoadOutcome<T> {
	value: T | null;
	/** HTTP status when the call failed with one; null for network failures. */
	status: number | null;
	failed: boolean;
}

async function loadOne<T>(read: () => Promise<T>): Promise<LoadOutcome<T>> {
	try {
		return { value: await read(), status: null, failed: false };
	} catch (err) {
		return {
			value: null,
			status: err instanceof BillingApiError ? err.status : null,
			failed: true
		};
	}
}

/**
 * Billing page loader. Backend endpoints are implemented by sibling cards.
 *
 * The plan is never invented: without an entitlement-granting subscription
 * the page shows trial defaults and says so (ADR 0004). Usage is scored
 * against caps only when the plan is confirmed — otherwise no usage alert
 * or upgrade button is rendered, because the caps being compared against
 * would be the wrong plan's. Lapsed subscriptions (past_due / canceled /
 * expired / incomplete) resolve to the billing portal, never to a new
 * checkout, so a paying user can neither be downgraded nor double-subscribed.
 * A 401 is reported as signed-out, not as an outage. No secrets here —
 * session cookie only.
 *
 * Client-rendered on purpose (`ssr = false`): this page is session-gated,
 * so SSR buys nothing, and a server-side `fetch('/v1/...')` never leaves
 * the web worker (SvelteKit internal fetch) — it 404s against the app's
 * own routes instead of reaching the API worker. In the browser the same
 * relative URLs go over the network through the edge route table.
 */
export const ssr = false;

export const load: PageLoad = async ({ fetch }) => {
	const sub = await loadOne(() => fetchSubscription(fetch));
	const use = await loadOne(() => fetchUsage(fetch));

	// A 404 on the subscription is a failure, not "no record yet": signup
	// always writes a trialing row (ADR 0002 rule 4), so a missing record
	// means the backend didn't answer — surface the notice with a Retry.
	// A 404 on usage stays non-fatal: a fresh account may genuinely have
	// nothing metered yet, and the meters simply don't render.
	const subscription: SubscriptionDTO | null = sub.value;
	const usage: UsageDTO | null = use.status === 404 ? null : use.value;
	const subFailed = sub.failed;
	const usageFailed = use.failed && use.status !== 404;
	const signedOut = sub.status === 401 || use.status === 401;

	const { plan, planUnknown } = resolveEffectivePlan(subscription);
	const manageBillingOnly = subscription !== null && LAPSED.has(subscription.status);
	let usageStatus: LimitStatus | null =
		!planUnknown && usage ? evaluateUsage(plan, usage) : null;
	// Portal-only: clearing the upgrade target keeps usage scored for display
	// while the page renders Manage billing as the sole action. A lapsed
	// subscriber must never start a new checkout — that would double-subscribe
	// them next to the invoice they already owe.
	if (manageBillingOnly && usageStatus) usageStatus = { ...usageStatus, upgradeTo: null };

	const notices: string[] = [];
	if (signedOut) {
		notices.push('You are signed out — sign in to see your billing.');
	} else if (subFailed && usageFailed) {
		notices.push('Billing backend is not reachable yet — showing trial defaults.');
	} else {
		if (subFailed)
			notices.push('Could not load your subscription — showing trial defaults.');
		else if (planUnknown && subscription)
			notices.push(
				`Subscription is ${subscription.status} — manage billing to resolve; showing trial limits meanwhile.`
			);
		else if (manageBillingOnly && subscription)
			// Only reachable for in-grace past_due: every other lapsed state
			// is planUnknown, and only past_due has a grace window. The plan
			// is confirmed so no other notice renders, yet the failed payment
			// still needs attention before the window closes.
			notices.push(
				'Your last payment failed — manage billing to resolve; your plan stays active during the grace period.'
			);
		if (usageFailed) notices.push('Could not load usage.');
	}

	return {
		planId: plan.id,
		planUnknown,
		signedOut,
		hadFetchError: !signedOut && (subFailed || usageFailed),
		manageBillingOnly,
		subscription,
		usage,
		usageStatus,
		loadError: notices.length > 0 ? notices.join(' ') : null
	};
};
