<script lang="ts">
	import { PUBLIC_API_BASE_URL } from '$app/env/public';
	import { ApiClient } from '#lib/api/client.js';
	import {
		serializePublicKeyCredential,
		toCreationOptions,
		type RegistrationOptionsJSON
	} from '#lib/webauthn.js';

	const client = new ApiClient({ baseUrl: PUBLIC_API_BASE_URL });

	let email = $state('');
	let status = $state<'idle' | 'working' | 'created' | 'unsupported' | 'error'>('idle');

	const passkeysSupported =
		typeof window !== 'undefined' &&
		typeof window.PublicKeyCredential !== 'undefined';

	async function createAccount(event: SubmitEvent) {
		event.preventDefault();
		if (status === 'working' || email.trim().length === 0) return;
		if (!passkeysSupported) {
			status = 'unsupported';
			return;
		}
		status = 'working';
		try {
			const options = await client.post<RegistrationOptionsJSON>(
				'/v1/auth/passkey/register/options',
				{ email: email.trim() }
			);
			const credential = await navigator.credentials.create({
				publicKey: toCreationOptions(options)
			});
			if (!(credential instanceof PublicKeyCredential)) {
				throw new Error('no public-key credential');
			}
			await client.post(
				'/v1/auth/passkey/register/verify',
				serializePublicKeyCredential(credential)
			);
			status = 'created';
			window.location.href = '/onboarding/provider';
		} catch {
			// Generic: account creation never says which step failed.
			status = 'error';
		}
	}
</script>

<svelte:head>
	<title>NNTune — get started</title>
	<meta name="description" content="Create your NNTune account and connect your Usenet provider." />
</svelte:head>

<main class="nt-wrap">
	<h1>Get started</h1>
	<p>
		Create your account with a passkey — no password to phish or leak. Then connect your own
		Usenet provider in the next step.
	</p>
	<form onsubmit={createAccount}>
		<label>
			Email
			<input
				type="email"
				name="email"
				required
				autocomplete="email"
				bind:value={email}
				disabled={status === 'working'}
			/>
		</label>
		<button class="nt-button" type="submit" disabled={status === 'working'}>
			{status === 'working' ? 'Creating…' : 'Create account with passkey'}
		</button>
	</form>
	{#if status === 'unsupported'}
		<p role="status">
			This browser does not support passkeys. <a href="/login">Sign in with an email link</a>
			instead.
		</p>
	{:else if status === 'error'}
		<p role="alert">Something went wrong. Try again.</p>
	{:else if status === 'created'}
		<p role="status">Account created — taking you to provider setup…</p>
	{/if}
	<p>Already have an account? <a href="/login">Sign in</a>.</p>
</main>

<style>
	form {
		display: grid;
		gap: var(--nt-space-2);
		max-width: 28rem;
		margin-block: var(--nt-space-2);
	}
	label {
		display: grid;
		gap: var(--nt-space-1);
		font-weight: 600;
	}
	input {
		padding: var(--nt-space-2);
		border: 1px solid var(--nt-border);
		border-radius: var(--nt-radius);
		font: inherit;
	}
</style>
