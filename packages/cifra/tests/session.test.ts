import { expect, test } from "bun:test";
import {
	buildSessionAad,
	computeTranscriptHash,
	createDhKeyPair,
	createHello,
	createReply,
	createSigningKeyPair,
	decodeJson,
	decryptPayload,
	deriveSessionKeys,
	deriveSharedSecret,
	encodeJson,
	encryptPayload,
	toBase64Url,
	verifyHello,
	verifyReply,
} from "../src/session";

test("handshake derives matching session keys", () => {
	const sessionId = "session-1";
	const initiatorSign = createSigningKeyPair();
	const initiatorDh = createDhKeyPair();
	const responderSign = createSigningKeyPair();
	const responderDh = createDhKeyPair();

	const hello = createHello(sessionId, initiatorSign, initiatorDh);
	const helloCheck = verifyHello(hello);
	expect(helloCheck.ok).toBe(true);

	const reply = createReply(hello, responderSign, responderDh);
	const replyCheck = verifyReply(hello, reply);
	expect(replyCheck.ok).toBe(true);

	const transcriptHash = computeTranscriptHash(hello, reply);
	const initiatorShared = deriveSharedSecret(initiatorDh.privateKey, replyCheck.dhPub);
	const responderShared = deriveSharedSecret(responderDh.privateKey, helloCheck.dhPub);

	const initiatorKeys = deriveSessionKeys(initiatorShared, transcriptHash, "initiator");
	const responderKeys = deriveSessionKeys(responderShared, transcriptHash, "responder");

	expect(Array.from(initiatorKeys.sendKey)).toEqual(Array.from(responderKeys.recvKey));
	expect(Array.from(initiatorKeys.recvKey)).toEqual(Array.from(responderKeys.sendKey));
});

test("payload encrypts and decrypts with derived key", () => {
	const sessionId = "session-2";
	const initiatorSign = createSigningKeyPair();
	const initiatorDh = createDhKeyPair();
	const responderSign = createSigningKeyPair();
	const responderDh = createDhKeyPair();

	const hello = createHello(sessionId, initiatorSign, initiatorDh);
	const reply = createReply(hello, responderSign, responderDh);
	const transcriptHash = computeTranscriptHash(hello, reply);

	const initiatorShared = deriveSharedSecret(initiatorDh.privateKey, responderDh.publicKey);
	const responderShared = deriveSharedSecret(responderDh.privateKey, initiatorDh.publicKey);
	const initiatorKeys = deriveSessionKeys(initiatorShared, transcriptHash, "initiator");
	const responderKeys = deriveSessionKeys(responderShared, transcriptHash, "responder");

	const payload = encodeJson({ piIndex: 42 });
	const aad = buildSessionAad(sessionId);
	const envelope = encryptPayload(initiatorKeys.sendKey, initiatorKeys.transcriptHash, 0, payload, aad);
	const decrypted = decryptPayload(
		responderKeys.recvKey,
		responderKeys.transcriptHash,
		envelope.index,
		envelope.ciphertext,
		aad,
	);
	expect(decodeJson(decrypted)).toEqual({ piIndex: 42 });

	expect(() =>
		decryptPayload(
			responderKeys.recvKey,
			responderKeys.transcriptHash,
			envelope.index,
			envelope.ciphertext,
			buildSessionAad("wrong-session"),
		),
	).toThrow();
});

test("tampered hello fails signature validation", () => {
	const sessionId = "session-3";
	const initiatorSign = createSigningKeyPair();
	const initiatorDh = createDhKeyPair();
	const hello = createHello(sessionId, initiatorSign, initiatorDh);

	const tampered = { ...hello, sessionId: "session-3-tamper" };
	const result = verifyHello(tampered);
	expect(result.ok).toBe(false);
});

test("handshake payloads do not expose private keys", () => {
	const sessionId = "session-4";
	const initiatorSignPriv = new Uint8Array(32).fill(1);
	const initiatorDhPriv = new Uint8Array(32).fill(2);
	const responderSignPriv = new Uint8Array(32).fill(3);
	const responderDhPriv = new Uint8Array(32).fill(4);
	const initiatorSign = createSigningKeyPair(initiatorSignPriv);
	const initiatorDh = createDhKeyPair(initiatorDhPriv);
	const responderSign = createSigningKeyPair(responderSignPriv);
	const responderDh = createDhKeyPair(responderDhPriv);

	const hello = createHello(sessionId, initiatorSign, initiatorDh);
	const reply = createReply(hello, responderSign, responderDh);

	const helloPayload = JSON.stringify(hello);
	const replyPayload = JSON.stringify(reply);

	expect(helloPayload.includes(toBase64Url(initiatorSignPriv))).toBe(false);
	expect(helloPayload.includes(toBase64Url(initiatorDhPriv))).toBe(false);
	expect(replyPayload.includes(toBase64Url(responderSignPriv))).toBe(false);
	expect(replyPayload.includes(toBase64Url(responderDhPriv))).toBe(false);
});
