import { describe, expect, it } from 'vitest';
import {
	formatPricePerMonth,
	getPlan,
	isTrialPlan,
	listPlans,
	nextPlan,
	resolveEffectivePlan,
	streamCapSeconds
} from './plans';

describe('plan matrix', () => {
	it('exposes the four accepted tiers in order', () => {
		expect(listPlans().map((p) => p.id)).toEqual(['free', 'plus', 'pro-5x', 'pro-20x']);
	});

	it('caps match the accepted matrix', () => {
		expect(getPlan('free')?.streamHoursMonth).toBe(10);
		expect(getPlan('plus')?.streamHoursMonth).toBe(100);
		expect(getPlan('pro-5x')?.streamHoursMonth).toBe(500);
		expect(getPlan('pro-20x')?.streamHoursMonth).toBe(2000);
		expect(getPlan('plus')?.maxConcurrentStreams).toBe(2);
		expect(getPlan('pro-20x')?.maxConcurrentStreams).toBe(8);
	});

	it('marks only free as trial', () => {
		expect(isTrialPlan('free')).toBe(true);
		expect(isTrialPlan('plus')).toBe(false);
	});

	it('formats trial copy distinctly from paid tiers', () => {
		expect(formatPricePerMonth(getPlan('free')!)).toContain('14 days');
		expect(formatPricePerMonth(getPlan('plus')!)).toBe('$8/mo');
		expect(formatPricePerMonth(getPlan('pro-20x')!)).toBe('$100/mo');
	});

	it('converts hours to seconds for ledger comparison', () => {
		expect(streamCapSeconds(getPlan('plus')!)).toBe(100 * 3600);
	});

	it('walks the upgrade ladder and stops at the top', () => {
		expect(nextPlan('free')?.id).toBe('plus');
		expect(nextPlan('plus')?.id).toBe('pro-5x');
		expect(nextPlan('pro-5x')?.id).toBe('pro-20x');
		expect(nextPlan('pro-20x')).toBeUndefined();
	});
});

describe('resolveEffectivePlan', () => {
	it('uses the subscription plan when active', () => {
		expect(resolveEffectivePlan({ planId: 'plus', status: 'active' })).toEqual({
			plan: getPlan('plus'),
			planUnknown: false
		});
	});

	it('uses the subscription plan while trialing', () => {
		const r = resolveEffectivePlan({ planId: 'pro-5x', status: 'trialing' });
		expect(r.plan.id).toBe('pro-5x');
		expect(r.planUnknown).toBe(false);
	});

	it('falls back to the trial row when there is no subscription', () => {
		const r = resolveEffectivePlan(null);
		expect(r.plan.id).toBe('free');
		expect(r.planUnknown).toBe(true);
	});

	it('falls back to the trial row on an unknown plan id', () => {
		const r = resolveEffectivePlan({ planId: 'legacy-2019', status: 'active' });
		expect(r.plan.id).toBe('free');
		expect(r.planUnknown).toBe(true);
	});

	it.each(['past_due', 'canceled', 'expired', 'incomplete'] as const)(
		'falls back to the trial row when status is %s',
		(status) => {
			const r = resolveEffectivePlan({ planId: 'pro-5x', status });
			expect(r.plan.id).toBe('free');
			expect(r.planUnknown).toBe(true);
		}
	);

	it('keeps the real plan for past_due inside the grace window', () => {
		const now = new Date('2026-10-15T12:00:00Z');
		const r = resolveEffectivePlan(
			{ planId: 'pro-5x', status: 'past_due', graceUntil: '2026-10-20T00:00:00Z' },
			now
		);
		expect(r.plan.id).toBe('pro-5x');
		expect(r.planUnknown).toBe(false);
	});

	it('treats past_due past the grace window (or with none) as lapsed', () => {
		const now = new Date('2026-10-15T12:00:00Z');
		for (const sub of [
			{ planId: 'pro-5x', status: 'past_due', graceUntil: '2026-10-10T00:00:00Z' },
			{ planId: 'pro-5x', status: 'past_due', graceUntil: null },
			{ planId: 'pro-5x', status: 'past_due' }
		] as const) {
			const r = resolveEffectivePlan(sub, now);
			expect(r.plan.id).toBe('free');
			expect(r.planUnknown).toBe(true);
		}
	});
});
