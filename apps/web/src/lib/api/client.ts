/**
 * Typed fetch client for `workers/api`. The web app talks only to the API
 * worker — never directly to NNTP providers, Hyperdrive, R2 or KV.
 *
 * The request/response shapes here mirror the API worker's OpenAPI spec
 * (published by the backend cards); once codegen lands, the hand-written
 * types below are replaced by the generated client without changing call
 * sites, because all requests flow through {@link ApiClient}.
 */

import type { ProviderForm } from '../vault-validation.js';

export type FetchFn = typeof fetch;

export interface ApiClientOptions {
	baseUrl: string;
	fetchFn?: FetchFn;
}

export class ApiError extends Error {
	readonly status: number;
	readonly code: string;

	constructor(status: number, code: string, message: string) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
		this.code = code;
	}
}

export interface MagicLinkResult {
	ok: true;
}

export interface IndexerConfigInput {
	url: string;
	api_key: string;
}

/** Wire shape used by workers/api's serde ProviderConfig and IndexerConfig. */
export interface ProviderTestInput {
	host: string;
	port: number;
	tls: boolean;
	allow_insecure_plaintext: boolean;
	username: string;
	password: string;
	max_connections: number;
	indexer?: IndexerConfigInput;
}

export function toProviderTestInput(
	provider: ProviderForm,
	indexerUrl: string,
	indexerApiKey: string
): ProviderTestInput {
	return {
		host: provider.host.trim(),
		port: provider.port,
		tls: provider.tls,
		// Only send the opt-in with plaintext: with TLS it is always false so
		// the server never records a spurious acknowledgement.
		allow_insecure_plaintext: !provider.tls && provider.allowInsecurePlaintext,
		username: provider.username,
		password: provider.password,
		max_connections: provider.maxConnections,
		...(indexerUrl.trim().length > 0
			? { indexer: { url: indexerUrl.trim(), api_key: indexerApiKey } }
			: {})
	};
}

export interface ProviderTestResult {
	ok: boolean;
	latencyMs?: number;
	error?: string;
}

export class ApiClient {
	private readonly baseUrl: string;
	private readonly fetchFn: FetchFn;
	private token: string | null = null;

	constructor({ baseUrl, fetchFn }: ApiClientOptions) {
		this.baseUrl = baseUrl.replace(/\/+$/, '');
		// Default to a wrapper (not a bare `fetch` reference): calling a stored
		// `fetch` as `this.fetchFn(...)` sets `this` to the client instance and
		// browsers/workerd reject it with "Illegal invocation".
		this.fetchFn = fetchFn ?? ((input, init) => fetch(input, init));
	}

	setToken(token: string | null): void {
		this.token = token;
	}

	async get<T>(path: string): Promise<T> {
		return this.request<T>(path, { method: 'GET' });
	}

	async post<T>(path: string, body: unknown): Promise<T> {
		return this.request<T>(path, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(body)
		});
	}

	/**
	 * Request an email magic link. Always resolves the same way for unknown
	 * and known addresses (the API never reveals which emails exist).
	 */
	async requestMagicLink(email: string): Promise<MagicLinkResult> {
		return this.post<MagicLinkResult>('/v1/auth/magic-link', { email });
	}

	/**
	 * Live-test a provider (+ optional indexer) config without storing it.
	 * The API validates (SSRF guard), dials, and returns a redacted result —
	 * secrets never come back in the response.
	 */
	async testProviderConnection(input: ProviderTestInput): Promise<ProviderTestResult> {
		return this.post<ProviderTestResult>('/v1/vault/test', input);
	}

	/**
	 * Store a tested provider (+ optional indexer) config in the encrypted
	 * vault. The API seals secrets with envelope encryption; responses are
	 * redacted summaries, never secret material.
	 */
	async saveProviderConfig(input: ProviderTestInput): Promise<MagicLinkResult> {
		return this.post<MagicLinkResult>('/v1/vault', input);
	}

	private async request<T>(path: string, init: RequestInit): Promise<T> {
		const headers: Record<string, string> = {
			...((init.headers as Record<string, string> | undefined) ?? {}),
			accept: 'application/json'
		};
		if (this.token !== null) headers['authorization'] = `Bearer ${this.token}`;

		const response = await this.fetchFn(`${this.baseUrl}${path}`, {
			...init,
			headers,
			credentials: 'include'
		});
		if (!response.ok) {
			throw new ApiError(response.status, this.errorCode(response.status), await this.message(response));
		}
		return (await response.json()) as T;
	}

	private errorCode(status: number): string {
		if (status === 401) return 'unauthorized';
		if (status === 403) return 'forbidden';
		if (status === 404) return 'not_found';
		if (status === 429) return 'rate_limited';
		return 'request_failed';
	}

	private async message(response: Response): Promise<string> {
		try {
			const body = (await response.json()) as { error?: unknown };
			if (typeof body.error === 'string' && body.error.length > 0) return body.error;
		} catch {
			// Fall through to the status-based message below.
		}
		return `request failed with status ${response.status}`;
	}
}
