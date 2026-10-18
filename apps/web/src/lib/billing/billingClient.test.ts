import { describe, expect, it, vi } from 'vitest';
import {
	BillingApiError,
	openPortal,
	signupUrlForCheckoutFailure,
	startCheckout
} from './billingClient';

function ok(body: unknown): Response {
	return new Response(JSON.stringify(body), { status: 200 });
}

describe('billingClient redirects', () => {
	it('returns the checkout url for a valid plan', async () => {
		const fetchFn = vi.fn(async () => ok({ url: 'https://checkout.stripe.com/c/pay_123' }));
		await expect(startCheckout('plus', fetchFn as typeof fetch)).resolves.toBe(
			'https://checkout.stripe.com/c/pay_123'
		);
		expect(fetchFn).toHaveBeenCalledOnce();
	});

	it('rejects invalid plan ids before any request', async () => {
		const fetchFn = vi.fn();
		await expect(startCheckout('../etc', fetchFn as typeof fetch)).rejects.toThrow('Invalid plan');
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('rejects non-https redirect targets', async () => {
		const fetchFn = vi.fn(async () => ok({ url: 'javascript:alert(1)' }));
		await expect(startCheckout('plus', fetchFn as typeof fetch)).rejects.toThrow(
			'Invalid checkout URL'
		);
	});

	it('returns the portal url', async () => {
		const fetchFn = vi.fn(async () => ok({ url: 'https://billing.stripe.com/p/session_1' }));
		await expect(openPortal(fetchFn as typeof fetch)).resolves.toBe(
			'https://billing.stripe.com/p/session_1'
		);
	});

	it('surfaces server errors without leaking bodies', async () => {
		const fetchFn = vi.fn(
			async () => new Response(JSON.stringify({ error: 'no such subscription' }), { status: 404 })
		);
		await expect(openPortal(fetchFn as typeof fetch)).rejects.toThrow('404');
	});
});

describe('signupUrlForCheckoutFailure', () => {
	it('routes a 401 to signup with the chosen plan', () => {
		expect(signupUrlForCheckoutFailure('pro-5x', new BillingApiError(401, 'Start checkout'))).toBe(
			'/signup?plan=pro-5x'
		);
	});

	it('returns null for non-401 failures and non-API errors', () => {
		expect(signupUrlForCheckoutFailure('plus', new BillingApiError(500, 'Start checkout'))).toBeNull();
		expect(signupUrlForCheckoutFailure('plus', new Error('nope'))).toBeNull();
	});
});
