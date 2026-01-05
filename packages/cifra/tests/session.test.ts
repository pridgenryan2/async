import { expect, test } from "bun:test";
import {
	buildSessionAad,
	computeTranscriptHash,
	createClientHello,
	createDhKeyPair,
	createServerHello,
	createSigningKeyPair,
	decodeJson,
	deriveSessionKeys,
	deriveSharedSecret,
	encryptPayload,
	toBase64Url,
	verifyClientHello,
	verifyServerHello,
	decryptPayload,
	encodeJson,
} from "../src/session";

test("handshake derives matching session keys", () => {
	const sessionId = "session-1";
	const clientSign = createSigningKeyPair();
	const clientDh = createDhKeyPair();
	const serverSign = createSigningKeyPair();
	const serverDh = createDhKeyPair();

	const clientHello = createClientHello(sessionId, clientSign, clientDh);
	const clientCheck = verifyClientHello(clientHello);
	expect(clientCheck.ok).toBe(true);

	const serverHello = createServerHello(clientHello, serverSign, serverDh);
	const serverCheck = verifyServerHello(clientHello, serverHello);
	expect(serverCheck.ok).toBe(true);

	const transcriptHash = computeTranscriptHash(clientHello, serverHello);
	const clientShared = deriveSharedSecret(clientDh.privateKey, serverCheck.serverDhPub);
	const serverShared = deriveSharedSecret(serverDh.privateKey, clientCheck.clientDhPub);

	const clientKeys = deriveSessionKeys(clientShared, transcriptHash);
	const serverKeys = deriveSessionKeys(serverShared, transcriptHash);

	expect(Array.from(clientKeys.clientToServerKey)).toEqual(
		Array.from(serverKeys.clientToServerKey),
	);
	expect(Array.from(clientKeys.serverToClientKey)).toEqual(
		Array.from(serverKeys.serverToClientKey),
	);
});

test("client payload encrypts and decrypts with derived key", () => {
	const sessionId = "session-2";
	const clientSign = createSigningKeyPair();
	const clientDh = createDhKeyPair();
	const serverSign = createSigningKeyPair();
	const serverDh = createDhKeyPair();

	const clientHello = createClientHello(sessionId, clientSign, clientDh);
	const serverHello = createServerHello(clientHello, serverSign, serverDh);
	const transcriptHash = computeTranscriptHash(clientHello, serverHello);

	const clientShared = deriveSharedSecret(clientDh.privateKey, serverDh.publicKey);
	const serverShared = deriveSharedSecret(serverDh.privateKey, clientDh.publicKey);
	const clientKeys = deriveSessionKeys(clientShared, transcriptHash);
	const serverKeys = deriveSessionKeys(serverShared, transcriptHash);

	const payload = encodeJson({ piIndex: 42 });
	const aad = buildSessionAad(sessionId);
	const envelope = encryptPayload(
		clientKeys.clientToServerKey,
		transcriptHash,
		"c2s",
		0,
		payload,
		aad,
	);
	const decrypted = decryptPayload(
		serverKeys.clientToServerKey,
		transcriptHash,
		"c2s",
		envelope.index,
		envelope.ciphertext,
		aad,
	);
	expect(decodeJson(decrypted)).toEqual({ piIndex: 42 });

	expect(() =>
		decryptPayload(
			serverKeys.clientToServerKey,
			transcriptHash,
			"c2s",
			envelope.index,
			envelope.ciphertext,
			buildSessionAad("wrong-session"),
		),
	).toThrow();
});

test("tampered client hello fails signature validation", () => {
	const sessionId = "session-3";
	const clientSign = createSigningKeyPair();
	const clientDh = createDhKeyPair();
	const clientHello = createClientHello(sessionId, clientSign, clientDh);

	const tampered = { ...clientHello, sessionId: "session-3-tamper" };
	const result = verifyClientHello(tampered);
	expect(result.ok).toBe(false);
});

test("handshake payloads do not expose private keys", () => {
	const sessionId = "session-4";
	const clientSignPriv = new Uint8Array(32).fill(1);
	const clientDhPriv = new Uint8Array(32).fill(2);
	const serverSignPriv = new Uint8Array(32).fill(3);
	const serverDhPriv = new Uint8Array(32).fill(4);
	const clientSign = createSigningKeyPair(clientSignPriv);
	const clientDh = createDhKeyPair(clientDhPriv);
	const serverSign = createSigningKeyPair(serverSignPriv);
	const serverDh = createDhKeyPair(serverDhPriv);

	const clientHello = createClientHello(sessionId, clientSign, clientDh);
	const serverHello = createServerHello(clientHello, serverSign, serverDh);

	const clientPayload = JSON.stringify(clientHello);
	const serverPayload = JSON.stringify(serverHello);

	expect(clientPayload.includes(toBase64Url(clientSignPriv))).toBe(false);
	expect(clientPayload.includes(toBase64Url(clientDhPriv))).toBe(false);
	expect(serverPayload.includes(toBase64Url(serverSignPriv))).toBe(false);
	expect(serverPayload.includes(toBase64Url(serverDhPriv))).toBe(false);
});
