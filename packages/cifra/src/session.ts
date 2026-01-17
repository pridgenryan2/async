import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const PROTOCOL_ID = "cifra-channel-v1";
const TEXT_ENCODER = new TextEncoder();

export type KeyPair = {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
};

export type Hello = {
	sessionId: string;
	signPub: string;
	dhPub: string;
	signature: string;
};

export type Reply = {
	sessionId: string;
	signPub: string;
	dhPub: string;
	signature: string;
};

export type Role = "initiator" | "responder";

export type SessionKeys = {
	sendKey: Uint8Array;
	recvKey: Uint8Array;
	transcriptHash: Uint8Array;
};

export type SecureEnvelope = {
	index: number;
	nonce: string;
	ciphertext: string;
};

export function buildSessionAad(sessionId: string): Uint8Array {
	return encodeFrame(
		textToBytes(PROTOCOL_ID),
		textToBytes("session-aad"),
		textToBytes(sessionId),
	);
}

export function createSigningKeyPair(privateKey?: Uint8Array): KeyPair {
	const secret = privateKey ?? ed25519.utils.randomSecretKey();
	return { privateKey: secret, publicKey: ed25519.getPublicKey(secret) };
}

export function createDhKeyPair(privateKey?: Uint8Array): KeyPair {
	const secret = privateKey ?? x25519.utils.randomSecretKey();
	return { privateKey: secret, publicKey: x25519.getPublicKey(secret) };
}

export function signBytes(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
	return ed25519.sign(message, privateKey);
}

export function verifySignature(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
	return ed25519.verify(signature, message, publicKey);
}

export function createHello(sessionId: string, signingKey: KeyPair, dhKey: KeyPair): Hello {
	const transcript = buildHelloTranscript(sessionId, signingKey.publicKey, dhKey.publicKey);
	const signature = signBytes(transcript, signingKey.privateKey);
	return {
		sessionId,
		signPub: toBase64Url(signingKey.publicKey),
		dhPub: toBase64Url(dhKey.publicKey),
		signature: toBase64Url(signature),
	};
}

export function verifyHello(
	hello: Hello,
	expectedSignPub?: Uint8Array,
): { ok: boolean; signPub: Uint8Array; dhPub: Uint8Array; transcript: Uint8Array } {
	const signPub = fromBase64Url(hello.signPub);
	const dhPub = fromBase64Url(hello.dhPub);
	const signature = fromBase64Url(hello.signature);
	const transcript = buildHelloTranscript(hello.sessionId, signPub, dhPub);

	if (expectedSignPub && !bytesEqual(expectedSignPub, signPub)) {
		return { ok: false, signPub, dhPub, transcript };
	}
	const ok = verifySignature(transcript, signature, signPub);
	return { ok, signPub, dhPub, transcript };
}

export function createReply(hello: Hello, signingKey: KeyPair, dhKey: KeyPair): Reply {
	const helloSignPub = fromBase64Url(hello.signPub);
	const helloDhPub = fromBase64Url(hello.dhPub);
	const transcript = buildReplyTranscript(
		hello.sessionId,
		helloSignPub,
		helloDhPub,
		signingKey.publicKey,
		dhKey.publicKey,
	);
	const signature = signBytes(transcript, signingKey.privateKey);
	return {
		sessionId: hello.sessionId,
		signPub: toBase64Url(signingKey.publicKey),
		dhPub: toBase64Url(dhKey.publicKey),
		signature: toBase64Url(signature),
	};
}

export function verifyReply(
	hello: Hello,
	reply: Reply,
	expectedSignPub?: Uint8Array,
): { ok: boolean; signPub: Uint8Array; dhPub: Uint8Array; transcript: Uint8Array } {
	if (hello.sessionId !== reply.sessionId) {
		return {
			ok: false,
			signPub: fromBase64Url(reply.signPub),
			dhPub: fromBase64Url(reply.dhPub),
			transcript: new Uint8Array(),
		};
	}
	const helloSignPub = fromBase64Url(hello.signPub);
	const helloDhPub = fromBase64Url(hello.dhPub);
	const replySignPub = fromBase64Url(reply.signPub);
	const replyDhPub = fromBase64Url(reply.dhPub);
	const signature = fromBase64Url(reply.signature);
	const transcript = buildReplyTranscript(
		hello.sessionId,
		helloSignPub,
		helloDhPub,
		replySignPub,
		replyDhPub,
	);

	if (expectedSignPub && !bytesEqual(expectedSignPub, replySignPub)) {
		return { ok: false, signPub: replySignPub, dhPub: replyDhPub, transcript };
	}
	const ok = verifySignature(transcript, signature, replySignPub);
	return { ok, signPub: replySignPub, dhPub: replyDhPub, transcript };
}

export function deriveSharedSecret(localDhPrivateKey: Uint8Array, remoteDhPublicKey: Uint8Array): Uint8Array {
	return x25519.getSharedSecret(localDhPrivateKey, remoteDhPublicKey);
}

export function computeTranscriptHash(hello: Hello, reply: Reply): Uint8Array {
	const helloSignPub = fromBase64Url(hello.signPub);
	const helloDhPub = fromBase64Url(hello.dhPub);
	const replySignPub = fromBase64Url(reply.signPub);
	const replyDhPub = fromBase64Url(reply.dhPub);
	const transcript = buildReplyTranscript(
		hello.sessionId,
		helloSignPub,
		helloDhPub,
		replySignPub,
		replyDhPub,
	);
	return sha256(transcript);
}

export function deriveSessionKeys(sharedSecret: Uint8Array, transcriptHash: Uint8Array, role: Role): SessionKeys {
	const masterKey = hkdf(sha256, sharedSecret, transcriptHash, textToBytes("cifra-master"), 32);
	const initiatorToResponderKey = hkdf(
		sha256,
		masterKey,
		transcriptHash,
		textToBytes("cifra-i2r"),
		32,
	);
	const responderToInitiatorKey = hkdf(
		sha256,
		masterKey,
		transcriptHash,
		textToBytes("cifra-r2i"),
		32,
	);

	if (role === "initiator") {
		return { sendKey: initiatorToResponderKey, recvKey: responderToInitiatorKey, transcriptHash };
	}
	return { sendKey: responderToInitiatorKey, recvKey: initiatorToResponderKey, transcriptHash };
}

export function encryptPayload(
	key: Uint8Array,
	transcriptHash: Uint8Array,
	index: number,
	plaintext: Uint8Array,
	aad?: Uint8Array,
): SecureEnvelope {
	const nonce = deriveNonce(key, transcriptHash, index);
	const cipher = xchacha20poly1305(key, nonce, aad);
	const ciphertext = cipher.encrypt(plaintext);
	return {
		index,
		nonce: toBase64Url(nonce),
		ciphertext: toBase64Url(ciphertext),
	};
}

export function decryptPayload(
	key: Uint8Array,
	transcriptHash: Uint8Array,
	index: number,
	ciphertext: Uint8Array | string,
	aad?: Uint8Array,
): Uint8Array {
	const nonce = deriveNonce(key, transcriptHash, index);
	const cipher = xchacha20poly1305(key, nonce, aad);
	const data = typeof ciphertext === "string" ? fromBase64Url(ciphertext) : ciphertext;
	return cipher.decrypt(data);
}

export function encodeJson(value: unknown): Uint8Array {
	return textToBytes(JSON.stringify(value));
}

export function decodeJson(bytes: Uint8Array): unknown {
	return JSON.parse(bytesToText(bytes));
}

export function toBase64Url(bytes: Uint8Array): string {
	const base64 = bytesToBase64(bytes);
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64Url(value: string): Uint8Array {
	const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
	const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
	return base64ToBytes(padded);
}

function buildHelloTranscript(sessionId: string, signPub: Uint8Array, dhPub: Uint8Array): Uint8Array {
	return encodeFrame(
		textToBytes(PROTOCOL_ID),
		textToBytes("hello"),
		textToBytes(sessionId),
		signPub,
		dhPub,
	);
}

function buildReplyTranscript(
	sessionId: string,
	helloSignPub: Uint8Array,
	helloDhPub: Uint8Array,
	replySignPub: Uint8Array,
	replyDhPub: Uint8Array,
): Uint8Array {
	return encodeFrame(
		textToBytes(PROTOCOL_ID),
		textToBytes("reply"),
		textToBytes(sessionId),
		helloSignPub,
		helloDhPub,
		replySignPub,
		replyDhPub,
	);
}

function deriveNonce(baseKey: Uint8Array, transcriptHash: Uint8Array, index: number): Uint8Array {
	if (!Number.isInteger(index) || index < 0) {
		throw new Error("nonce_index_invalid");
	}
	const info = textToBytes(`cifra-nonce:${index}`);
	return hkdf(sha256, baseKey, transcriptHash, info, 24);
}

function encodeFrame(...parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const part of parts) {
		total += 4 + part.length;
	}
	const out = new Uint8Array(total);
	let offset = 0;
	for (const part of parts) {
		out[offset++] = (part.length >>> 24) & 0xff;
		out[offset++] = (part.length >>> 16) & 0xff;
		out[offset++] = (part.length >>> 8) & 0xff;
		out[offset++] = part.length & 0xff;
		out.set(part, offset);
		offset += part.length;
	}
	return out;
}

function textToBytes(value: string): Uint8Array {
	return TEXT_ENCODER.encode(value);
}

function bytesToText(bytes: Uint8Array): string {
	return new TextDecoder().decode(bytes);
}

function bytesToBase64(bytes: Uint8Array): string {
	if (typeof Buffer !== "undefined") {
		return Buffer.from(bytes).toString("base64");
	}
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
	if (typeof Buffer !== "undefined") {
		return new Uint8Array(Buffer.from(value, "base64"));
	}
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) {
		return false;
	}
	for (let i = 0; i < left.length; i += 1) {
		if (left[i] !== right[i]) {
			return false;
		}
	}
	return true;
}
