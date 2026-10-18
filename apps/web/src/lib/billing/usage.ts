/**
 * Usage-vs-cap evaluation for display only.
 *
 * Enforcement lives in the API/stream workers (server reads
 * `subscriptions` + `plans` + `usage_ledger`; see ADR 0004). This module
 * turns the same numbers into UI states: soft-limit nudges at 80%+,
 * hard-limit degrade messaging at 100%+, and upgrade prompts.
 *
 * Overage policy (ADR 0004): no overage billing, ever. Streams past the
 * monthly cap degrade gracefully (lower bitrate; artwork stays full
 * quality) until the next period.
 */

import { nextPlan, streamCapSeconds, type Plan } from './plans';

export interface UsageSnapshot {
	/** Seconds streamed this calendar month (SUM from usage_ledger). */
	streamSecondsMonth: number;
	/** Currently playing streams. */
	concurrentNow: number;
	/** Tracks in the user's library. */
	libraryTracks: number;
	/** Ingest jobs started today. */
	ingestToday: number;
}

export type LimitState = 'ok' | 'soft' | 'hard';

export interface LimitStatus {
	state: LimitState;
	/** 0..1+ fraction of the monthly stream cap consumed. */
	streamFraction: number;
	streamHardCapped: boolean;
	concurrentBlocked: boolean;
	libraryBlocked: boolean;
	ingestBlocked: boolean;
	/** Plan id to suggest, if any. */
	upgradeTo: string | null;
	/** Short human-readable line for banners. */
	headline: string;
	/** Longer degrade/upgrade explanation. Empty when `ok`. */
	detail: string;
}

const SOFT_AT = 0.8;

function pct(fraction: number): string {
	return `${Math.min(999, Math.round(fraction * 100))}%`;
}

export function evaluateUsage(plan: Plan, usage: UsageSnapshot): LimitStatus {
	const cap = streamCapSeconds(plan);
	const streamFraction = cap > 0 ? usage.streamSecondsMonth / cap : 0;
	const streamHardCapped = usage.streamSecondsMonth >= cap;
	const concurrentBlocked = usage.concurrentNow >= plan.maxConcurrentStreams;
	const libraryBlocked = usage.libraryTracks >= plan.maxLibraryTracks;
	const ingestBlocked = usage.ingestToday >= plan.ingestJobsDay;

	const libraryFraction = usage.libraryTracks / Math.max(1, plan.maxLibraryTracks);
	const ingestFraction = usage.ingestToday / Math.max(1, plan.ingestJobsDay);
	const concurrentFraction = usage.concurrentNow / Math.max(1, plan.maxConcurrentStreams);

	const anyHard = streamHardCapped || concurrentBlocked || libraryBlocked || ingestBlocked;
	const soft =
		!anyHard &&
		(streamFraction >= SOFT_AT ||
			concurrentFraction >= SOFT_AT ||
			libraryFraction >= SOFT_AT ||
			ingestFraction >= SOFT_AT);

	const upgrade = nextPlan(plan.id);
	const upgradeTo = upgrade ? upgrade.id : null;

	if (streamHardCapped) {
		return {
			state: 'hard',
			streamFraction,
			streamHardCapped,
			concurrentBlocked,
			libraryBlocked,
			ingestBlocked,
			upgradeTo,
			headline: `You've used ${pct(streamFraction)} of your ${plan.name} streaming hours.`,
			detail:
				`Streams continue at a lower bitrate until your next period — artwork stays full quality. ` +
				`No surprise bills, ever.` +
				(upgrade ? ` Upgrade to ${upgrade.name} for ${upgrade.streamHoursMonth} hrs/mo.` : '')
		};
	}

	if (concurrentBlocked) {
		return {
			state: 'hard',
			streamFraction,
			streamHardCapped,
			concurrentBlocked,
			libraryBlocked,
			ingestBlocked,
			upgradeTo,
			headline: `All ${plan.maxConcurrentStreams} ${plan.name} streams are in use.`,
			detail:
				`Stop one stream or upgrade for more concurrent streams.` +
				(upgrade ? ` ${upgrade.name} allows ${upgrade.maxConcurrentStreams}.` : '')
		};
	}

	if (ingestBlocked || libraryBlocked) {
		return {
			state: 'hard',
			streamFraction,
			streamHardCapped,
			concurrentBlocked,
			libraryBlocked,
			ingestBlocked,
			upgradeTo,
			headline: ingestBlocked
				? `Daily ingest limit reached (${plan.ingestJobsDay}/day on ${plan.name}).`
				: `Library is full (${plan.maxLibraryTracks.toLocaleString()} tracks on ${plan.name}).`,
			detail: upgrade
				? `Upgrade to ${upgrade.name} to raise the limit. Limits reset on their natural cadence.`
				: `Limits reset on their natural cadence.`
		};
	}

	if (soft) {
		// Name the dimension closest to its cap so the banner never reports
		// a floored number from an unrelated dimension.
		const candidates = [
			{
				fraction: streamFraction,
				headline: `You're at ${pct(streamFraction)} of your ${plan.name} streaming hours.`
			},
			{
				fraction: concurrentFraction,
				headline: `You're using ${usage.concurrentNow} of ${plan.maxConcurrentStreams} ${plan.name} streams.`
			},
			{
				fraction: libraryFraction,
				headline: `Library is at ${pct(libraryFraction)} of ${plan.name} (${usage.libraryTracks.toLocaleString()} tracks).`
			},
			{
				fraction: ingestFraction,
				headline: `Ingest is at ${pct(ingestFraction)} of today's ${plan.name} limit.`
			}
		];
		let top = candidates[0];
		for (const c of candidates.slice(1)) {
			if (c.fraction > top.fraction) top = c;
		}
		return {
			state: 'soft',
			streamFraction,
			streamHardCapped,
			concurrentBlocked,
			libraryBlocked,
			ingestBlocked,
			upgradeTo,
			headline: top.headline,
			detail: upgrade
				? `Heads up before anything degrades: ${upgrade.name} raises every limit.`
				: `Heads up before anything degrades.`
		};
	}

	return {
		state: 'ok',
		streamFraction,
		streamHardCapped: false,
		concurrentBlocked: false,
		libraryBlocked: false,
		ingestBlocked: false,
		upgradeTo,
		headline: `${pct(streamFraction)} of ${plan.name} streaming hours used.`,
		detail: ''
	};
}

/** Remaining whole stream-minutes for meter display. Never negative. */
export function remainingStreamMinutes(plan: Plan, usedSeconds: number): number {
	return Math.max(0, Math.floor((streamCapSeconds(plan) - usedSeconds) / 60));
}
