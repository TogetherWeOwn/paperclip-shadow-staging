<script lang="ts">
	import { goto } from '$app/navigation';
	import { listPlans, formatPricePerMonth } from '#lib/billing/plans.js';
	import { startCheckout, signupUrlForCheckoutFailure } from '#lib/billing/billingClient.js';

	const plans = listPlans();
	let checkoutError: string | null = $state(null);
	let pendingPlan: string | null = $state(null);

	async function choose(planId: string) {
		checkoutError = null;
		pendingPlan = planId;
		try {
			const url = await startCheckout(planId);
			window.location.href = url;
		} catch (err) {
			// Signed-out visitors have no session cookie: send them to signup
			// with the plan carried along instead of a raw 401 alert.
			const signup = signupUrlForCheckoutFailure(planId, err);
			if (signup) await goto(signup);
			else checkoutError = err instanceof Error ? err.message : 'Checkout failed';
		} finally {
			pendingPlan = null;
		}
	}
</script>

<svelte:head>
	<title>Plans and pricing — NNTune v2</title>
	<meta
		name="description"
		content="NNTune v2 plans: 14-day free trial, Plus, Pro 5x and Pro 20x. No overage bills — streams degrade gracefully past the cap."
	/>
</svelte:head>

<main>
	<h1>Plans and pricing</h1>
	<p>
		NNTune never bundles Usenet access — you bring your own provider, and plans meter
		<em>our</em> service (streaming hours, concurrent streams, library size, ingest).
	</p>

	{#if checkoutError}
		<p role="alert">{checkoutError}</p>
	{/if}

	<table>
		<caption>Monthly plans. Free is a 14-day trial, not a forever tier.</caption>
		<thead>
			<tr>
				<th scope="col">Plan</th>
				<th scope="col">Price</th>
				<th scope="col">Stream hrs/mo</th>
				<th scope="col">Concurrent</th>
				<th scope="col">Library</th>
				<th scope="col">Ingest/day</th>
				<th scope="col">Cache</th>
				<th scope="col"><span class="visually-hidden">Action</span></th>
			</tr>
		</thead>
		<tbody>
			{#each plans as plan (plan.id)}
				<tr>
					<th scope="row">{plan.name}<br /><small>{plan.blurb}</small></th>
					<td>{formatPricePerMonth(plan)}</td>
					<td>{plan.streamHoursMonth}</td>
					<td>{plan.maxConcurrentStreams}</td>
					<td>{plan.maxLibraryTracks.toLocaleString()}</td>
					<td>{plan.ingestJobsDay}</td>
					<td>{plan.cachePriority}</td>
					<td>
						{#if plan.id === 'free'}
							<a href="/signup?plan=free">Start trial</a>
						{:else}
							<button disabled={pendingPlan === plan.id} onclick={() => choose(plan.id)}>
								{pendingPlan === plan.id ? 'Starting…' : 'Choose'}
							</button>
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>

	<section aria-labelledby="overage">
		<h2 id="overage">What happens past the cap</h2>
		<p>
			No overage bills, ever. Streams past your monthly hours continue at a lower bitrate until the
			next period; artwork stays full quality. Concurrent, library and ingest limits reset on their
			natural cadence — upgrade any time for 5x / 20x headroom.
		</p>
		<p><a href="/account/billing">Check your current usage</a></p>
	</section>
</main>

<style>
	main {
		max-width: 60rem;
		margin: 2rem auto;
		padding: 0 1rem;
		font-family: system-ui, sans-serif;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		margin: 1.5rem 0;
	}
	th,
	td {
		border: 1px solid #ccc;
		padding: 0.5rem 0.6rem;
		text-align: left;
		vertical-align: top;
	}
	small {
		font-weight: normal;
		color: #444;
	}
	.visually-hidden {
		position: absolute;
		clip: rect(0 0 0 0);
	}
</style>
