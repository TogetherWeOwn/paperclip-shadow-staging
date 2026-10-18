/**
 * Typed fetch client for `workers/api`. The web app talks only to the API
 * worker — never directly to NNTP providers, Hyperdrive, R2 or KV.
 *
 * The request/response shapes here mirror the API worker's OpenAPI spec
 * (published by the backend cards); once codegen lands, the hand-written
 * types below are replaced by the generated client without changing call
 * sites, because all requests flow through {@link ApiClient}.
 */

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

	private async request<T>(path: string, init: RequestInit): Promise<T> {
		const headers: Record<string, string> = { accept: 'application/json' };
		if (this.token !== null) headers['authorization'] = `Bearer ${this.token}`;

		const response = await this.fetchFn(`${this.baseUrl}${path}`, { ...init, headers });
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
