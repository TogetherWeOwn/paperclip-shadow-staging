import { describe, expect, it, vi } from 'vitest';

import { ApiClient, ApiError, toProviderTestInput } from './client.js';

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'content-type': 'application/json' }
	});
}

describe('toProviderTestInput', () => {
	it('trims the provider host to match validation and server rules', () => {
		expect(
			toProviderTestInput(
				{
					host: ' news.example.com ',
					port: 563,
					tls: true,
					allowInsecurePlaintext: false,
					username: 'alice',
					password: 's3cret',
					maxConnections: 4
				},
				'',
				''
			).host
		).toBe('news.example.com');
	});

	it('uses the API field names and omits an unset indexer', () => {
		expect(
			toProviderTestInput(
				{
					host: 'news.example.com',
					port: 563,
					tls: true,
					allowInsecurePlaintext: false,
					username: 'alice',
					password: 's3cret',
					maxConnections: 4
				},
				'',
				''
			)
		).toEqual({
			host: 'news.example.com',
			port: 563,
			tls: true,
			allow_insecure_plaintext: false,
			username: 'alice',
			password: 's3cret',
			max_connections: 4
		});
	});

	it('only sends the plaintext opt-in with TLS disabled and acknowledged', () => {
		const base = {
			host: 'news.example.com',
			port: 119,
			username: 'alice',
			password: 's3cret',
			maxConnections: 4
		};
		expect(
			toProviderTestInput({ ...base, tls: false, allowInsecurePlaintext: true }, '', '')
				.allow_insecure_plaintext
		).toBe(true);
		expect(
			toProviderTestInput({ ...base, tls: false, allowInsecurePlaintext: false }, '', '')
				.allow_insecure_plaintext
		).toBe(false);
		// A stale acknowledgement with TLS on must never reach the server.
		expect(
			toProviderTestInput({ ...base, tls: true, allowInsecurePlaintext: true }, '', '')
				.allow_insecure_plaintext
		).toBe(false);
	});
});

describe('ApiClient', () => {
	it('joins baseUrl and path without double slashes', async () => {
		const seenUrls: unknown[] = [];
		const fetchFn = (async (url: unknown) => {
			seenUrls.push(url);
			return jsonResponse({ ok: true });
		}) as unknown as typeof fetch;
		const client = new ApiClient({ baseUrl: 'https://api.example.com/', fetchFn });

		await client.get('/health');

		expect(seenUrls).toEqual(['https://api.example.com/health']);
	});

	it('sends a Bearer token when one is set', async () => {
		const seenInits: unknown[] = [];
		const fetchFn = (async (_url: unknown, init: unknown) => {
			seenInits.push(init);
			return jsonResponse({ ok: true });
		}) as unknown as typeof fetch;
		const client = new ApiClient({ baseUrl: 'https://api.example.com', fetchFn });
		client.setToken('secret-token');

		await client.get('/me');

		expect(seenInits).toEqual([
			expect.objectContaining({
				headers: expect.objectContaining({ authorization: 'Bearer secret-token' })
			})
		]);
	});

	it('returns parsed JSON on success', async () => {
		const fetchFn = vi.fn(async () => jsonResponse({ user: 'ada' }));
		const client = new ApiClient({ baseUrl: 'https://api.example.com', fetchFn });

		await expect(client.get('/me')).resolves.toEqual({ user: 'ada' });
	});

	it('throws ApiError with status on error responses', async () => {
		const fetchFn = vi.fn(async () => jsonResponse({ error: 'boom' }, 500));
		const client = new ApiClient({ baseUrl: 'https://api.example.com', fetchFn });

		const failure = await client.get('/me').catch((error: unknown) => error);
		expect(failure).toBeInstanceOf(ApiError);
		expect((failure as ApiError).status).toBe(500);
	});

	it('maps 401 to the unauthorized code', async () => {
		const fetchFn = vi.fn(async () => jsonResponse({ error: 'nope' }, 401));
		const client = new ApiClient({ baseUrl: 'https://api.example.com', fetchFn });

		const failure = await client.get('/me').catch((error: unknown) => error);
		expect(failure).toBeInstanceOf(ApiError);
		expect((failure as ApiError).code).toBe('unauthorized');
	});

	it('posts JSON bodies with the right content type', async () => {
		const seen: unknown[] = [];
		const fetchFn = (async (_url: unknown, init: unknown) => {
			seen.push(init);
			return jsonResponse({ ok: true });
		}) as unknown as typeof fetch;
		const client = new ApiClient({ baseUrl: 'https://api.example.com', fetchFn });

		await client.post('/v1/auth/magic-link', { email: 'alice@example.com' });

		expect(seen).toEqual([
			expect.objectContaining({
				method: 'POST',
				credentials: 'include',
				headers: expect.objectContaining({ 'content-type': 'application/json' })
			})
		]);
	});

	it('requests a magic link without leaking which emails exist', async () => {
		const seenUrls: unknown[] = [];
		const fetchFn = (async (url: unknown) => {
			seenUrls.push(url);
			return jsonResponse({ ok: true });
		}) as unknown as typeof fetch;
		const client = new ApiClient({ baseUrl: 'https://api.example.com', fetchFn });

		await expect(
			client.requestMagicLink('alice@example.com')
		).resolves.toEqual({ ok: true });
		expect(seenUrls).toEqual(['https://api.example.com/v1/auth/magic-link']);
	});

	it('tests a provider connection and returns the redacted result', async () => {
		const seenBodies: unknown[] = [];
		const fetchFn = (async (_url: unknown, init: { body?: string } & RequestInit) => {
			seenBodies.push(JSON.parse(String(init.body)));
			return jsonResponse({ ok: true, latencyMs: 120 });
		}) as unknown as typeof fetch;
		const client = new ApiClient({ baseUrl: 'https://api.example.com', fetchFn });

		const result = await client.testProviderConnection(
			toProviderTestInput(
				{
					host: 'news.example.com',
					port: 563,
					tls: true,
					allowInsecurePlaintext: false,
					username: 'alice',
					password: 's3cret',
					maxConnections: 4
				},
				'https://index.example.com/api',
				'indexer-key'
			)
		);

		expect(result).toEqual({ ok: true, latencyMs: 120 });
		expect(seenBodies).toEqual([
			{
				host: 'news.example.com',
				port: 563,
				tls: true,
				allow_insecure_plaintext: false,
				username: 'alice',
				password: 's3cret',
				max_connections: 4,
				indexer: { url: 'https://index.example.com/api', api_key: 'indexer-key' }
			}
		]);
	});

	it('saves a tested provider config to the vault endpoint', async () => {
		const seenUrls: unknown[] = [];
		const fetchFn = (async (url: unknown) => {
			seenUrls.push(url);
			return jsonResponse({ ok: true });
		}) as unknown as typeof fetch;
		const client = new ApiClient({ baseUrl: 'https://api.example.com', fetchFn });

		await expect(
			client.saveProviderConfig(
				toProviderTestInput(
					{
						host: 'news.example.com',
						port: 563,
						tls: true,
						allowInsecurePlaintext: false,
						username: 'alice',
						password: 's3cret',
						maxConnections: 4
					},
					'',
					''
				)
			)
		).resolves.toEqual({ ok: true });
		expect(seenUrls).toEqual(['https://api.example.com/v1/vault']);
	});

	it('uses the global fetch without an Illegal-invocation receiver', async () => {
		const originalFetch = globalThis.fetch;
		// Mimic browsers/workerd: a bare global fetch throws when `this` is wrong.
		function strictFetch(this: unknown): Promise<Response> {
			if (this !== undefined && this !== globalThis) {
				throw new TypeError(
					"Illegal invocation: function called with incorrect this reference"
				);
			}
			return Promise.resolve(jsonResponse({ pong: true }));
		}
		vi.stubGlobal('fetch', strictFetch as typeof fetch);
		try {
			const client = new ApiClient({ baseUrl: 'https://api.example.com' });
			await expect(client.get('/health')).resolves.toEqual({ pong: true });
		} finally {
			vi.unstubAllGlobals();
			globalThis.fetch = originalFetch;
		}
	});
});
