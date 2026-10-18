<script lang="ts">
	import { PUBLIC_API_BASE_URL } from '$app/env/public';
	import { ApiClient } from '#lib/api/client.js';
	import {
		serializePublicKeyCredential,
		toRequestOptions,
		type AuthenticationOptionsJSON
	} from '#lib/webauthn.js';

	const client = new ApiClient({ baseUrl: PUBLIC_API_BASE_URL });

	let email = $state('');
	let status = $state<'idle' | 'sending' | 'sent' | 'error'>('idle');
	let passkeyStatus = $state<'idle' | 'working' | 'unsupported' | 'error'>('idle');

	const passkeysSupported =
		typeof window !== 'undefined' &&
		typeof window.PublicKeyCredential !== 'undefined';

	async function sendMagicLink(event: SubmitEvent) {
		event.preventDefault();
		if (status === 'sending') return;
		status = 'sending';
		try {
			await client.requestMagicLink(email.trim());
			// Generic either way: the API never reveals which emails exist.
			status = 'sent';
		} catch {
			status = 'error';
		}
	}

	async function signInWithPasskey() {
		if (!passkeysSupported) {
			passkeyStatus = 'unsupported';
			return;
		}
		passkeyStatus = 'working';
		try {
			const options = await client.post<AuthenticationOptionsJSON>(
				'/v1/auth/passkey/authenticate/options',
				{}
			);
			const assertion = await navigator.credentials.get({
				publicKey: toRequestOptions(options)
			});
			if (!(assertion instanceof PublicKeyCredential)) {
				throw new Error('no public-key credential');
			}
			await client.post(
				'/v1/auth/passkey/authenticate/verify',
				serializePublicKeyCredential(assertion)
			);
			window.location.href = '/onboarding/provider';
		} catch {
			// Generic: login errors stay non-enumerating, like the API.
			passkeyStatus = 'error';
		}
	}
</script>

<svelte:head>
	<title>NNTune — sign in</title>
	<meta name="description" content="Sign in to NNTune with a passkey or an email magic link." />
</svelte:head>

<main class="nt-wrap">
	<h1>Sign in</h1>

	<section aria-labelledby="passkey-heading">
		<h2 id="passkey-heading">Passkey</h2>
		<button class="nt-button" type="button" onclick={signInWithPasskey}>
			Sign in with passkey
		</button>
		{#if passkeyStatus === 'unsupported'}
			<p role="status">This browser does not support passkeys — use an email link instead.</p>
		{:else if passkeyStatus === 'error'}
			<p role="alert">Sign-in failed. Try again or use an email link.</p>
		{/if}
	</section>

	<section aria-labelledby="magic-link-heading">
		<h2 id="magic-link-heading">Email link</h2>
		<form onsubmit={sendMagicLink}>
			<label>
				Email
				<input
					type="email"
					name="email"
					required
					autocomplete="email"
					bind:value={email}
					disabled={status === 'sending'}
				/>
			</label>
			<button class="nt-button nt-button--ghost" type="submit" disabled={status === 'sending'}>
				{status === 'sending' ? 'Sending…' : 'Email me a sign-in link'}
			</button>
		</form>
		{#if status === 'sent'}
			<p role="status">Check your inbox for a sign-in link.</p>
		{:else if status === 'error'}
			<p role="alert">Something went wrong. Try again.</p>
		{/if}
	</section>

	<p>New here? <a href="/signup">Create an account</a>.</p>
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
