import { defineEnvVars } from '@sveltejs/kit/env';

/**
 * Public runtime environment for the web frontend. Declared here (SvelteKit 3
 * `defineEnvVars`) so `$app/env/public` is typed; consumed by the auth and
 * BYOP pages through {@link ApiClient}.
 *
 * `PUBLIC_API_BASE_URL` is empty by default, which makes the client use
 * same-origin relative URLs (e.g. `/v1/auth/magic-link`). Set it to the
 * `workers/api` URL when the API deploys separately (wrangler `[vars]` or
 * platform env). ApiClient includes credentials so the HttpOnly session cookie
 * is sent. For a different origin, the API must allow the exact frontend origin
 * with credentialed CORS (never `*`); because the cookie is SameSite=Lax, the
 * frontend and API must also be same-site over HTTPS. No secrets here: public
 * vars ship to the browser.
 */
export const variables = defineEnvVars({
	PUBLIC_API_BASE_URL: {
		public: true,
		description: 'Base URL of the workers/api worker. Empty means same-origin.',
		schema: (value) => value ?? ''
	}
});
