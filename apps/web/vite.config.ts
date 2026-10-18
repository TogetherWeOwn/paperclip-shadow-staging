/// <reference types="vitest/config" />
import adapter from '@sveltejs/adapter-cloudflare';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// Cloudflare Workers (serverless). Wrangler config lands with the
			// DevOps provisioning card; the adapter works without one locally.
			adapter: adapter()
		})
	],
	test: {
		include: ['src/**/*.test.ts']
	}
});
