/**
 * WebAuthn wire-format helpers shared by the signup and login pages.
 *
 * The API speaks base64url (no padding); the `navigator.credentials` API
 * wants raw bytes (`BufferSource`). Centralized here so both pages decode
 * identically and send portable JSON in browsers with or without `toJSON()`.
 */

export interface CredentialDescriptorJSON {
	id: string;
	type?: PublicKeyCredentialType;
	transports?: AuthenticatorTransport[];
}

export interface RegistrationOptionsJSON {
	challenge: string;
	rp: PublicKeyCredentialRpEntity;
	user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string };
	pubKeyCredParams: PublicKeyCredentialParameters[];
	timeout?: number;
	excludeCredentials?: CredentialDescriptorJSON[];
	authenticatorSelection?: AuthenticatorSelectionCriteria;
	attestation?: AttestationConveyancePreference;
	extensions?: AuthenticationExtensionsClientInputs;
}

export interface AuthenticationOptionsJSON {
	challenge: string;
	rpId?: string;
	timeout?: number;
	allowCredentials?: CredentialDescriptorJSON[];
	userVerification?: UserVerificationRequirement;
	extensions?: AuthenticationExtensionsClientInputs;
}

/** Decode a base64url string to raw bytes. */
export function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
	const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
	const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

/** Encode an ArrayBuffer or view as unpadded base64url. */
export function encodeBase64Url(value: ArrayBuffer | ArrayBufferView): string {
	const bytes =
		value instanceof ArrayBuffer
			? new Uint8Array(value)
			: new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Convert API JSON creation options into browser options, requiring discoverable credentials. */
export function toCreationOptions(
	options: RegistrationOptionsJSON
): PublicKeyCredentialCreationOptions {
	const { challenge, user, excludeCredentials, authenticatorSelection, ...rest } = options;
	return {
		...rest,
		challenge: decodeBase64Url(challenge),
		user: { ...user, id: decodeBase64Url(user.id) },
		excludeCredentials: excludeCredentials?.map(toCredentialDescriptor),
		authenticatorSelection: {
			...authenticatorSelection,
			residentKey: 'required',
			requireResidentKey: true
		}
	};
}

/** Convert API JSON request options; omitted allowCredentials enables usernameless login. */
export function toRequestOptions(
	options: AuthenticationOptionsJSON
): PublicKeyCredentialRequestOptions {
	const { challenge, allowCredentials, ...rest } = options;
	return {
		...rest,
		challenge: decodeBase64Url(challenge),
		...(allowCredentials === undefined
			? {}
			: { allowCredentials: allowCredentials.map(toCredentialDescriptor) })
	};
}

function toCredentialDescriptor(
	descriptor: CredentialDescriptorJSON
): PublicKeyCredentialDescriptor {
	return {
		id: decodeBase64Url(descriptor.id),
		type: descriptor.type ?? 'public-key',
		transports: descriptor.transports
	};
}

/** Serialize credential response buffers without relying on newer `toJSON()` support. */
export function serializePublicKeyCredential(
	credential: PublicKeyCredential
): Record<string, unknown> {
	const response = credential.response;
	const serializedResponse: Record<string, unknown> = {
		clientDataJSON: encodeBase64Url(response.clientDataJSON)
	};

	if ('attestationObject' in response) {
		const attestation = response as AuthenticatorAttestationResponse;
		serializedResponse.attestationObject = encodeBase64Url(attestation.attestationObject);
		if (typeof attestation.getTransports === 'function') {
			serializedResponse.transports = attestation.getTransports();
		}
	} else {
		const assertion = response as AuthenticatorAssertionResponse;
		serializedResponse.authenticatorData = encodeBase64Url(assertion.authenticatorData);
		serializedResponse.signature = encodeBase64Url(assertion.signature);
		serializedResponse.userHandle =
			assertion.userHandle === null ? null : encodeBase64Url(assertion.userHandle);
	}

	return {
		id: credential.id,
		rawId: encodeBase64Url(credential.rawId),
		type: credential.type,
		authenticatorAttachment: credential.authenticatorAttachment,
		response: serializedResponse,
		clientExtensionResults: credential.getClientExtensionResults()
	};
}
