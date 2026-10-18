import { expect, test } from '@playwright/test';

test('landing explains BYOP and links to signup and pricing', async ({ page, request }) => {
	await page.goto('/');

	await expect(page.getByRole('heading', { level: 1 })).toContainText('NNTune');
	// \s+ because SSR may wrap the copy across lines.
	await expect(page.getByRole('main')).toContainText(/bring your\s+own/i);
	await expect(page.getByRole('link', { name: /get started/i })).toHaveAttribute('href', '/signup');
	await expect(page.getByRole('link', { name: /plans/i }).first()).toHaveAttribute(
		'href',
		'/pricing'
	);

	// Every landing CTA must resolve to a real route (no 404 placeholders).
	for (const href of ['/signup', '/pricing']) {
		const response = await request.get(href);
		expect(response.status(), `${href} should not 404`).not.toBe(404);
		expect(response.ok()).toBe(true);
	}
});

test('health endpoint reports ok', async ({ request }) => {
	const response = await request.get('/api/health');

	expect(response.ok()).toBe(true);
	await expect(response.json()).resolves.toEqual({ ok: true });
});

test('signup collects an email for passkey creation', async ({ page }) => {
	await page.goto('/signup');

	await expect(page.getByRole('heading', { level: 1 })).toContainText('Get started');
	await expect(page.locator('input[type="email"]')).toBeVisible();
	await expect(
		page.getByRole('button', { name: /create account with passkey/i })
	).toBeVisible();
});

test('login offers passkey and email-link sign-in', async ({ page }) => {
	await page.goto('/login');

	await expect(page.getByRole('heading', { level: 1 })).toContainText('Sign in');
	await expect(
		page.getByRole('button', { name: /sign in with passkey/i })
	).toBeVisible();
	await expect(page.locator('input[type="email"]')).toBeVisible();
});

test('provider wizard walks provider, indexer and test steps', async ({ page, request }) => {
	for (const href of ['/login', '/signup', '/onboarding/provider']) {
		const response = await request.get(href);
		expect(response.status(), `${href} should not 404`).not.toBe(404);
		expect(response.ok()).toBe(true);
	}

	await page.goto('/onboarding/provider');
	await expect(page.getByRole('heading', { level: 1 })).toContainText('Connect your provider');

	await page.locator('input[name="host"]').fill('news.example.com');
	await page.locator('input[name="username"]').fill('alice');
	await page.locator('input[name="password"]').fill('s3cret');
	await page.getByRole('button', { name: 'Continue' }).click();

	await expect(page.getByText(/indexer improves search/i)).toBeVisible();
	await page.getByRole('button', { name: 'Continue' }).click();

	await expect(page.getByRole('heading', { level: 2 })).toContainText('Test the connection');
	await expect(
		page.getByRole('button', { name: /test connection/i })
	).toBeVisible();
});
