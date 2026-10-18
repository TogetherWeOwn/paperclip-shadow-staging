<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { getPlan } from '#lib/billing/plans.js';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	// The loader only emits known plan ids; free is the last-resort fallback
	// so the page can never promote an unknown state to a paid tier.
	const plan = $derived(getPlan(data.planId) ?? getPlan('free')!);
	// A lapsed subscriber still owns their plan: name it with its status
	// instead of printing "Free trial" above a past_due line. The
	// "couldn't confirm" wording is reserved for no-subscription-at-all.
	const headingPlan = $derived(
		!data.planUnknown || data.signedOut
			? plan
			: data.subscription
				? (getPlan(data.subscription.planId) ?? plan)
				: plan
	);
	// usageStatus is null unless the plan is confirmed AND usage loaded: no
	// usage-vs-cap alert or upgrade button is rendered otherwise.
	const status = $derived(data.usageStatus);

	let actionError: string | null = $state(null);
	let busy: 'checkout' | 'portal' | null = $state(null);

	async function checkout() {
		// Belt and braces with the loader (which nulls upgradeTo for
		// portal-only subscriptions): never start a checkout from here when
		// the subscriber already holds a plan that needs the portal instead.
		if (!status?.upgradeTo || data.manageBillingOnly) return;
		actionError = null;
		busy = 'checkout';
		try {
			const { startCheckout } = await import('#lib/billing/billingClient.js');
			window.location.href = await startCheckout(status.upgradeTo);
		} catch (err) {
			actionError = err instanceof Error ? err.message : 'Checkout failed';
			busy = null;
		}
	}

	async function portal() {
		actionError = null;
		busy = 'portal';
		try {
			const { openPortal } = await import('#lib/billing/billingClient.js');
			window.location.href = await openPortal();
		} catch (err) {
			actionError = err instanceof Error ? err.message : 'Portal failed';
			busy = null;
		}
	}
</script>

<svelte:head>
	<title>Billing — NNTune v2</title>
</svelte:head>

<main>
	<h1>Billing</h1>

	{#if data.loadError}
		<p role="alert">{data.loadError}</p>
	{/if}

	{#if data.planUnknown && !data.signedOut}
		<p role="status">We couldn&apos;t confirm your plan — showing trial defaults.</p>
	{/if}

	{#if data.signedOut}
		<p><a href="/signup">Sign in</a> to see your billing.</p>
	{/if}

	{#if data.hadFetchError}
		<button onclick={() => invalidateAll()}>Retry</button>
	{/if}

	<section aria-labelledby="plan">
		<h2 id="plan">Current plan: {headingPlan.name}</h2>
		{#if data.subscription}
			<p>
				Status: {data.subscription.status}
				{#if data.subscription.currentPeriodEnd}
					· renews {new Date(data.subscription.currentPeriodEnd).toLocaleDateString()}
				{/if}
				{#if data.subscription.trialEndsAt}
					· trial ends {new Date(data.subscription.trialEndsAt).toLocaleDateString()}
				{/if}
			</p>
		{/if}
	</section>

	{#if data.usage && status}
		<section aria-labelledby="usage" aria-live="polite">
			<h2 id="usage">Usage for {data.usage.period}</h2>
			<ul>
				<li>
					Streaming: {(data.usage.streamSecondsMonth / 3600).toFixed(1)} / {plan.streamHoursMonth} hrs
					<progress
						max={plan.streamHoursMonth * 3600}
						value={Math.min(data.usage.streamSecondsMonth, plan.streamHoursMonth * 3600)}
					>
						{Math.round(status.streamFraction * 100)}%
					</progress>
				</li>
				<li>Concurrent streams: {data.usage.concurrentNow} / {plan.maxConcurrentStreams}</li>
				<li>
					Library: {data.usage.libraryTracks.toLocaleString()} / {plan.maxLibraryTracks.toLocaleString()}
				</li>
				<li>Ingest today: {data.usage.ingestToday} / {plan.ingestJobsDay}</li>
			</ul>

			{#if status.state !== 'ok'}
				<div role={status.state === 'hard' ? 'alert' : 'status'}>
					<p><strong>{status.headline}</strong></p>
					{#if status.detail}<p>{status.detail}</p>{/if}
				</div>
			{/if}
		</section>
	{/if}

	{#if actionError}
		<p role="alert">{actionError}</p>
	{/if}

	{#if !data.signedOut}
		<div>
			{#if status?.upgradeTo && !data.manageBillingOnly}
				<button disabled={busy !== null} onclick={checkout}>
					{busy === 'checkout' ? 'Starting…' : `Upgrade to ${status.upgradeTo}`}
				</button>
			{/if}
			<button disabled={busy !== null} onclick={portal}>
				{busy === 'portal'
					? 'Opening…'
					: data.manageBillingOnly
						? 'Manage billing to resolve'
						: 'Manage billing'}
			</button>
		</div>
	{/if}

	<p><a href="/pricing">Compare all plans</a></p>
</main>

<style>
	main {
		max-width: 44rem;
		margin: 2rem auto;
		padding: 0 1rem;
		font-family: system-ui, sans-serif;
	}
	progress {
		width: 100%;
	}
	div:has(button) {
		display: flex;
		gap: 0.75rem;
		margin-top: 1rem;
	}
</style>
