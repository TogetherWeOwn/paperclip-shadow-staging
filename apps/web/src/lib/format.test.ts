import { describe, expect, it } from 'vitest';

import { formatBytes, formatDuration } from './format.js';

describe('formatDuration', () => {
	it('formats zero as 0:00', () => {
		expect(formatDuration(0)).toBe('0:00');
	});

	it('formats seconds under a minute as m:ss', () => {
		expect(formatDuration(65)).toBe('1:05');
		expect(formatDuration(5)).toBe('0:05');
	});

	it('formats hours as h:mm:ss', () => {
		expect(formatDuration(3600)).toBe('1:00:00');
		expect(formatDuration(3723)).toBe('1:02:03');
	});

	it('floors fractional seconds', () => {
		expect(formatDuration(65.9)).toBe('1:05');
	});
});

describe('formatBytes', () => {
	it('formats zero bytes', () => {
		expect(formatBytes(0)).toBe('0 B');
	});

	it('formats kilobytes with one decimal', () => {
		expect(formatBytes(1536)).toBe('1.5 KB');
	});

	it('formats megabytes', () => {
		expect(formatBytes(5 * 1024 * 1024)).toBe('5 MB');
	});

	it('rolls over to the next unit when rounding reaches 1024', () => {
		expect(formatBytes(1048575)).toBe('1 MB');
		expect(formatBytes(1073741823)).toBe('1 GB');
	});

	it('handles sub-byte and non-finite input as zero bytes', () => {
		expect(formatBytes(0.5)).toBe('0.5 B');
		expect(formatBytes(NaN)).toBe('0 B');
		expect(formatBytes(Infinity)).toBe('0 B');
	});
});
