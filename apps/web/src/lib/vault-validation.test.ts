import { describe, expect, it } from 'vitest';

import { validateIndexerUrl, validateProviderConfig } from './vault-validation.js';

// Client-side validation mirrors the API worker's vault rules for fast UX
// feedback. It is UX-only: the server re-validates everything (SSRF guard,
// envelope encryption) and is the authority.

describe('validateProviderConfig', () => {
	const good = {
		host: 'news.example.com',
		port: 563,
		tls: true,
		allowInsecurePlaintext: false,
		username: 'alice',
		password: 's3cret',
		maxConnections: 10
	};

	it('accepts a well-formed provider config', () => {
		expect(validateProviderConfig(good)).toEqual([]);
	});

	it('rejects empty hosts and hosts with scheme or path', () => {
		for (const host of ['', 'https://news.example.com/', 'news.example.com/x', 'has space.com']) {
			const errors = validateProviderConfig({ ...good, host });
			expect(errors.length, `host rejected: ${host}`).toBeGreaterThan(0);
		}
	});

	it('rejects private, loopback and link-local literal IPs', () => {
		for (const host of [
			'10.1.2.3',
			'127.0.0.1',
			'169.254.169.254',
			'192.168.1.1',
			'172.16.0.5',
			'224.0.0.1',
			'198.51.100.1',
			'203.0.113.1',
			'::1',
			'fc00::1',
			'fd00::1',
			'2001:db8::1',
			'2002::1',
			'3fff::1',
			'ff02::1'
		]) {
			const errors = validateProviderConfig({ ...good, host });
			expect(errors.length, `host rejected: ${host}`).toBeGreaterThan(0);
		}
	});

	it('accepts hostnames beginning with fc or fd', () => {
		for (const host of ['fcnews.example.com', 'fdn.example.com', 'fdfiber.net']) {
			expect(validateProviderConfig({ ...good, host }), `host accepted: ${host}`).toEqual([]);
		}
	});

	it('rejects out-of-range ports and connection counts', () => {
		expect(validateProviderConfig({ ...good, maxConnections: 0 }).length).toBeGreaterThan(0);
		expect(validateProviderConfig({ ...good, maxConnections: 50 })).toEqual([]);
		expect(validateProviderConfig({ ...good, maxConnections: 51 }).length).toBeGreaterThan(0);
	});

	it('only allows the NNTP ports 119 and 563', () => {
		expect(validateProviderConfig({ ...good, port: 119 })).toEqual([]);
		expect(validateProviderConfig({ ...good, port: 563 })).toEqual([]);
		for (const port of [0, 80, 443, 1234, 65536]) {
			expect(validateProviderConfig({ ...good, port }).length, `port rejected: ${port}`).toBeGreaterThan(
				0
			);
		}
	});

	it('requires an explicit acknowledgement for plaintext auth', () => {
		expect(
			validateProviderConfig({ ...good, tls: false, allowInsecurePlaintext: false }).length
		).toBeGreaterThan(0);
		expect(
			validateProviderConfig({ ...good, tls: false, allowInsecurePlaintext: true })
		).toEqual([]);
		expect(
			validateProviderConfig({ ...good, tls: true, allowInsecurePlaintext: false })
		).toEqual([]);
	});

	it('requires a username and a password', () => {
		expect(validateProviderConfig({ ...good, username: '' }).length).toBeGreaterThan(0);
		expect(validateProviderConfig({ ...good, password: '' }).length).toBeGreaterThan(0);
	});
});

describe('validateIndexerUrl', () => {
	it('treats an empty URL as valid (indexer is optional)', () => {
		expect(validateIndexerUrl('', '')).toBeNull();
		expect(validateIndexerUrl('', 'orphaned-key')).not.toBeNull();
	});

	it('accepts an https indexer URL with an API key', () => {
		expect(validateIndexerUrl('https://index.example.com/api', 'indexer-key')).toBeNull();
	});

	it('accepts a public literal address', () => {
		expect(validateIndexerUrl('https://8.8.8.8/api', 'indexer-key')).toBeNull();
		expect(validateIndexerUrl('https://[2001:4860:4860::8888]/api', 'indexer-key')).toBeNull();
	});

	it('requires an API key when an indexer URL is set', () => {
		expect(validateIndexerUrl('https://index.example.com/api', '')).not.toBeNull();
	});

	it('rejects non-https, unparsable and non-public URLs', () => {
		for (const url of [
			'http://169.254.169.254/latest/meta-data/',
			'https://127.0.0.1:8080/',
			'https://[::1]:8080/',
			'https://[::]:8080/',
			'https://[2001:db8::1]/',
			'https://[2002::1]/',
			'https://[3fff::1]/',
			'https://[ff02::1]/',
			'https://224.0.0.1/',
			'https://198.51.100.1/',
			'https://203.0.113.1/',
			'https://localhost:8080/',
			'https://localhost./api',
			'https://service.localhost./api',
			'ftp://index.example.com/',
			'not-a-url'
		]) {
			expect(validateIndexerUrl(url, 'indexer-key'), `url rejected: ${url}`).not.toBeNull();
		}
	});
});
