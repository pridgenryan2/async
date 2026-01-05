import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const PROTOCOL_ID = "pi-queue-v1";
const TEXT_ENCODER = new TextEncoder();

export type KeyPair = {
	publicKey: Uint8Array;
	privateKey: Uint8Array;
};

export type ClientHello = {
	sessionId: string;
	clientSignPub: string;
	clientDhPub: string;
	signature: string;
};

export type ServerHello = {
	sessionId: string;
	serverSignPub: string;
	serverDhPub: string;
	signature: string;
};

export type SessionKeys = {
	clientToServerKey: Uint8Array;
	serverToClientKey: Uint8Array;
	transcriptHash: Uint8Array;
};

export type Direction = "c2s" | "s2c";

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

export function createClientHello(
	sessionId: string,
	signingKey: KeyPair,
	dhKey: KeyPair,
): ClientHello {
	const transcript = buildClientHelloTranscript(sessionId, signingKey.publicKey, dhKey.publicKey);
	const signature = signBytes(transcript, signingKey.privateKey);
	return {
		sessionId,
		clientSignPub: toBase64Url(signingKey.publicKey),
		clientDhPub: toBase64Url(dhKey.publicKey),
		signature: toBase64Url(signature),
	};
}

export function verifyClientHello(
	hello: ClientHello,
	expectedClientSignPub?: Uint8Array,
): { ok: boolean; clientSignPub: Uint8Array; clientDhPub: Uint8Array; transcript: Uint8Array } {
	const clientSignPub = fromBase64Url(hello.clientSignPub);
	const clientDhPub = fromBase64Url(hello.clientDhPub);
	const signature = fromBase64Url(hello.signature);
	const transcript = buildClientHelloTranscript(hello.sessionId, clientSignPub, clientDhPub);

	if (expectedClientSignPub && !bytesEqual(expectedClientSignPub, clientSignPub)) {
		return { ok: false, clientSignPub, clientDhPub, transcript };
	}
	const ok = verifySignature(transcript, signature, clientSignPub);
	return { ok, clientSignPub, clientDhPub, transcript };
}

export function createServerHello(
	clientHello: ClientHello,
	signingKey: KeyPair,
	dhKey: KeyPair,
): ServerHello {
	const clientSignPub = fromBase64Url(clientHello.clientSignPub);
	const clientDhPub = fromBase64Url(clientHello.clientDhPub);
	const transcript = buildServerHelloTranscript(
		clientHello.sessionId,
		clientSignPub,
		clientDhPub,
		signingKey.publicKey,
		dhKey.publicKey,
	);
	const signature = signBytes(transcript, signingKey.privateKey);
	return {
		sessionId: clientHello.sessionId,
		serverSignPub: toBase64Url(signingKey.publicKey),
		serverDhPub: toBase64Url(dhKey.publicKey),
		signature: toBase64Url(signature),
	};
}

export function verifyServerHello(
	clientHello: ClientHello,
	serverHello: ServerHello,
	expectedServerSignPub?: Uint8Array,
): { ok: boolean; serverSignPub: Uint8Array; serverDhPub: Uint8Array; transcript: Uint8Array } {
	if (clientHello.sessionId !== serverHello.sessionId) {
		return {
			ok: false,
			serverSignPub: fromBase64Url(serverHello.serverSignPub),
			serverDhPub: fromBase64Url(serverHello.serverDhPub),
			transcript: new Uint8Array(),
		};
	}
	const clientSignPub = fromBase64Url(clientHello.clientSignPub);
	const clientDhPub = fromBase64Url(clientHello.clientDhPub);
	const serverSignPub = fromBase64Url(serverHello.serverSignPub);
	const serverDhPub = fromBase64Url(serverHello.serverDhPub);
	const signature = fromBase64Url(serverHello.signature);
	const transcript = buildServerHelloTranscript(
		clientHello.sessionId,
		clientSignPub,
		clientDhPub,
		serverSignPub,
		serverDhPub,
	);

	if (expectedServerSignPub && !bytesEqual(expectedServerSignPub, serverSignPub)) {
		return { ok: false, serverSignPub, serverDhPub, transcript };
	}
	const ok = verifySignature(transcript, signature, serverSignPub);
	return { ok, serverSignPub, serverDhPub, transcript };
}

export function deriveSharedSecret(localDhPrivateKey: Uint8Array, remoteDhPublicKey: Uint8Array): Uint8Array {
	return x25519.getSharedSecret(localDhPrivateKey, remoteDhPublicKey);
}

export function computeTranscriptHash(clientHello: ClientHello, serverHello: ServerHello): Uint8Array {
	const clientSignPub = fromBase64Url(clientHello.clientSignPub);
	const clientDhPub = fromBase64Url(clientHello.clientDhPub);
	const serverSignPub = fromBase64Url(serverHello.serverSignPub);
	const serverDhPub = fromBase64Url(serverHello.serverDhPub);
	const transcript = buildServerHelloTranscript(
		clientHello.sessionId,
		clientSignPub,
		clientDhPub,
		serverSignPub,
		serverDhPub,
	);
	return sha256(transcript);
}

export function deriveSessionKeys(sharedSecret: Uint8Array, transcriptHash: Uint8Array): SessionKeys {
	const masterKey = hkdf(
		sha256,
		sharedSecret,
		transcriptHash,
		textToBytes("pi-queue-master"),
		32,
	);
	const clientToServerKey = hkdf(
		sha256,
		masterKey,
		transcriptHash,
		textToBytes("pi-queue-c2s"),
		32,
	);
	const serverToClientKey = hkdf(
		sha256,
		masterKey,
		transcriptHash,
		textToBytes("pi-queue-s2c"),
		32,
	);
	return { clientToServerKey, serverToClientKey, transcriptHash };
}

export function encryptPayload(
	key: Uint8Array,
	transcriptHash: Uint8Array,
	direction: Direction,
	index: number,
	plaintext: Uint8Array,
	aad?: Uint8Array,
): SecureEnvelope {
	const nonce = deriveNonce(key, transcriptHash, direction, index);
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
	direction: Direction,
	index: number,
	ciphertext: Uint8Array | string,
	aad?: Uint8Array,
): Uint8Array {
	const nonce = deriveNonce(key, transcriptHash, direction, index);
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

function buildClientHelloTranscript(
	sessionId: string,
	clientSignPub: Uint8Array,
	clientDhPub: Uint8Array,
): Uint8Array {
	return encodeFrame(
		textToBytes(PROTOCOL_ID),
		textToBytes("client-hello"),
		textToBytes(sessionId),
		clientSignPub,
		clientDhPub,
	);
}

function buildServerHelloTranscript(
	sessionId: string,
	clientSignPub: Uint8Array,
	clientDhPub: Uint8Array,
	serverSignPub: Uint8Array,
	serverDhPub: Uint8Array,
): Uint8Array {
	return encodeFrame(
		textToBytes(PROTOCOL_ID),
		textToBytes("server-hello"),
		textToBytes(sessionId),
		clientSignPub,
		clientDhPub,
		serverSignPub,
		serverDhPub,
	);
}

function deriveNonce(
	baseKey: Uint8Array,
	transcriptHash: Uint8Array,
	direction: Direction,
	index: number,
): Uint8Array {
	if (!Number.isInteger(index) || index < 0) {
		throw new Error("nonce_index_invalid");
	}
	const info = textToBytes(`pi-queue-nonce:${direction}:${index}`);
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
