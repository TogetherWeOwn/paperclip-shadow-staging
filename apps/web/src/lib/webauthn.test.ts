import { describe, expect, it } from 'vitest';

import {
	decodeBase64Url,
	encodeBase64Url,
	serializePublicKeyCredential,
	toCreationOptions,
	toRequestOptions
} from './webauthn.js';

describe('decodeBase64Url', () => {
	it('decodes unpadded base64url to raw bytes', () => {
		// "Hello" in base64url without padding.
		expect(Array.from(decodeBase64Url('SGVsbG8'))).toEqual([72, 101, 108, 108, 111]);
	});

	it('handles the base64url alphabet (- and _)', () => {
		// 0xfb 0xff 0xfe encodes with +//+ in base64, -__- in base64url.
		expect(Array.from(decodeBase64Url('-__-'))).toEqual([251, 255, 254]);
	});

	it('decodes an empty string to empty bytes', () => {
		expect(decodeBase64Url('').length).toBe(0);
	});
});

describe('encodeBase64Url', () => {
	it('encodes bytes with the URL-safe alphabet and no padding', () => {
		expect(encodeBase64Url(new Uint8Array([251, 255, 254]))).toBe('-__-');
	});

	it('encodes only the selected view range', () => {
		const bytes = new Uint8Array([9, 251, 255, 8]);
		expect(encodeBase64Url(bytes.subarray(1, 3))).toBe('-_8');
	});
});

describe('WebAuthn options', () => {
	it('passes through server algorithms and requires a discoverable credential', () => {
		const options = toCreationOptions({
			challenge: 'AQID',
			rp: { name: 'NNTune', id: 'example.com' },
			user: { id: 'BAUG', name: 'ada@example.com', displayName: 'Ada' },
			pubKeyCredParams: [
				{ alg: -7, type: 'public-key' },
				{ alg: -257, type: 'public-key' }
			],
			excludeCredentials: [{ id: 'Bwg', transports: ['internal'] }],
			authenticatorSelection: { residentKey: 'preferred' },
			timeout: 60_000
		});

		expect(Array.from(new Uint8Array(options.challenge as ArrayBuffer))).toEqual([1, 2, 3]);
		expect(Array.from(new Uint8Array(options.user.id as ArrayBuffer))).toEqual([4, 5, 6]);
		expect(options.pubKeyCredParams).toEqual([
			{ alg: -7, type: 'public-key' },
			{ alg: -257, type: 'public-key' }
		]);
		expect(options.excludeCredentials?.[0]?.id).toEqual(decodeBase64Url('Bwg'));
		expect(options.excludeCredentials?.[0]?.transports).toEqual(['internal']);
		expect(options.authenticatorSelection).toEqual({
			residentKey: 'required',
			requireResidentKey: true
		});
		expect(options.timeout).toBe(60_000);
	});

	it('omits allowCredentials for discoverable usernameless login', () => {
		const options = toRequestOptions({ challenge: 'AQID', rpId: 'example.com' });

		expect(Array.from(new Uint8Array(options.challenge as ArrayBuffer))).toEqual([1, 2, 3]);
		expect(options.rpId).toBe('example.com');
		expect('allowCredentials' in options).toBe(false);
	});

	it('decodes allowCredentials when the server provides them', () => {
		const options = toRequestOptions({
			challenge: 'AQID',
			allowCredentials: [{ id: 'BAUG', transports: ['internal'] }]
		});

		expect(options.allowCredentials).toEqual([
			{ id: decodeBase64Url('BAUG'), type: 'public-key', transports: ['internal'] }
		]);
	});
});

describe('serializePublicKeyCredential', () => {
	it('serializes attestation buffers without a credential toJSON method', () => {
		const credential = {
			id: 'credential-id',
			rawId: new Uint8Array([251, 255]).buffer,
			type: 'public-key',
			authenticatorAttachment: 'platform',
			response: {
				clientDataJSON: new Uint8Array([1, 2]).buffer,
				attestationObject: new Uint8Array([3, 4]).buffer,
				getTransports: () => ['internal']
			},
			getClientExtensionResults: () => ({ credProps: { rk: true } })
		} as unknown as PublicKeyCredential;

		expect('toJSON' in credential).toBe(false);
		expect(serializePublicKeyCredential(credential)).toEqual({
			id: 'credential-id',
			rawId: '-_8',
			type: 'public-key',
			authenticatorAttachment: 'platform',
			response: {
				clientDataJSON: 'AQI',
				attestationObject: 'AwQ',
				transports: ['internal']
			},
			clientExtensionResults: { credProps: { rk: true } }
		});
	});

	it('serializes assertion buffers including the optional user handle', () => {
		const credential = {
			id: 'credential-id',
			rawId: new Uint8Array([5]).buffer,
			type: 'public-key',
			authenticatorAttachment: null,
			response: {
				clientDataJSON: new Uint8Array([1]).buffer,
				authenticatorData: new Uint8Array([2]).buffer,
				signature: new Uint8Array([3]).buffer,
				userHandle: null
			},
			getClientExtensionResults: () => ({})
		} as unknown as PublicKeyCredential;

		expect(serializePublicKeyCredential(credential)).toEqual({
			id: 'credential-id',
			rawId: 'BQ',
			type: 'public-key',
			authenticatorAttachment: null,
			response: {
				clientDataJSON: 'AQ',
				authenticatorData: 'Ag',
				signature: 'Aw',
				userHandle: null
			},
			clientExtensionResults: {}
		});
	});
});
