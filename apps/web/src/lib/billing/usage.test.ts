import { describe, expect, it } from 'vitest';
import { getPlan } from './plans';
import { evaluateUsage, remainingStreamMinutes } from './usage';

const plus = getPlan('plus')!;

describe('evaluateUsage', () => {
	it('is ok well under every cap', () => {
		const s = evaluateUsage(plus, {
			streamSecondsMonth: 10 * 3600,
			concurrentNow: 0,
			libraryTracks: 100,
			ingestToday: 1
		});
		expect(s.state).toBe('ok');
		expect(s.detail).toBe('');
	});

	it('nudges softly at 80%+ of stream hours', () => {
		const s = evaluateUsage(plus, {
			streamSecondsMonth: 85 * 3600,
			concurrentNow: 0,
			libraryTracks: 100,
			ingestToday: 1
		});
		expect(s.state).toBe('soft');
		expect(s.upgradeTo).toBe('pro-5x');
		expect(s.detail).toContain('degrades');
	});

	it('degrades (never bills) past the monthly cap', () => {
		const s = evaluateUsage(plus, {
			streamSecondsMonth: 100 * 3600 + 1,
			concurrentNow: 0,
			libraryTracks: 100,
			ingestToday: 1
		});
		expect(s.state).toBe('hard');
		expect(s.streamHardCapped).toBe(true);
		expect(s.detail).toContain('lower bitrate');
		expect(s.detail).toContain('No surprise bills');
	});

	it('blocks concurrent streams at the cap with an upgrade hint', () => {
		const s = evaluateUsage(plus, {
			streamSecondsMonth: 0,
			concurrentNow: 2,
			libraryTracks: 100,
			ingestToday: 1
		});
		expect(s.state).toBe('hard');
		expect(s.concurrentBlocked).toBe(true);
		expect(s.detail).toContain('4');
	});

	it('blocks ingest at the daily cap', () => {
		const s = evaluateUsage(plus, {
			streamSecondsMonth: 0,
			concurrentNow: 0,
			libraryTracks: 100,
			ingestToday: 25
		});
		expect(s.state).toBe('hard');
		expect(s.ingestBlocked).toBe(true);
	});

	it('names the real dimension when the library drives the soft state', () => {
		const s = evaluateUsage(plus, {
			streamSecondsMonth: 10 * 3600,
			concurrentNow: 0,
			libraryTracks: 24000,
			ingestToday: 1
		});
		expect(s.state).toBe('soft');
		expect(s.headline).toContain('96%');
		expect(s.headline).toContain('Library');
	});

	it('names the real dimension when ingest drives the soft state', () => {
		const s = evaluateUsage(plus, {
			streamSecondsMonth: 0,
			concurrentNow: 0,
			libraryTracks: 100,
			ingestToday: 24
		});
		expect(s.state).toBe('soft');
		expect(s.headline).toContain('96%');
		expect(s.headline).toContain('Ingest');
	});

	it('reports stream hours when streaming drives the soft state', () => {
		const s = evaluateUsage(plus, {
			streamSecondsMonth: 85 * 3600,
			concurrentNow: 0,
			libraryTracks: 100,
			ingestToday: 1
		});
		expect(s.state).toBe('soft');
		expect(s.headline).toContain('85%');
	});

	it('has no upgrade left at the top tier', () => {
		const top = getPlan('pro-20x')!;
		const s = evaluateUsage(top, {
			streamSecondsMonth: 2001 * 3600,
			concurrentNow: 0,
			libraryTracks: 0,
			ingestToday: 0
		});
		expect(s.state).toBe('hard');
		expect(s.upgradeTo).toBeNull();
	});
});

describe('remainingStreamMinutes', () => {
	it('floors at zero past the cap', () => {
		expect(remainingStreamMinutes(plus, 0)).toBe(6000);
		expect(remainingStreamMinutes(plus, 100 * 3600 + 5000)).toBe(0);
	});
});
