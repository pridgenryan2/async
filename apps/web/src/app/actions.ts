"use server";

import { computePiHash, MAX_PI_INDEX } from "../lib/pi";
import {
	buildSessionAad,
	computeTranscriptHash,
	createClientHello,
	createDhKeyPair,
	createSigningKeyPair,
	decodeJson,
	decryptPayload,
	deriveSessionKeys,
	deriveSharedSecret,
	encodeJson,
	encryptPayload,
	verifyServerHello,
	type ClientHello,
	type SecureEnvelope,
	type ServerHello,
} from "../lib/session";

type ApiResult<T> = { ok: boolean; status: number; data: T | null };

export type OpenSessionResult = {
	ok: boolean;
	sessionId?: string;
	payload?: Record<string, unknown>;
	error?: string;
};

export type CommandResult = {
	ok: boolean;
	status?: number;
	error?: string;
	data?: Record<string, unknown>;
};

export type StatusResult = {
	ok: boolean;
	status?: number;
	data?: Record<string, unknown>;
	error?: string;
};

export type EndSessionResult = {
	ok: boolean;
	status?: number;
	error?: string;
};

function apiBase(): string {
	const base =
		process.env.PI_QUEUE_API_URL ??
		process.env.NEXT_PUBLIC_PI_QUEUE_API_URL ??
		"http://localhost:8787";
	return base.endsWith("/") ? base.slice(0, -1) : base;
}

function apiUrl(path: string): string {
	const base = apiBase();
	if (!base) {
		return path;
	}
	return `${base}${path}`;
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
	const response = await fetch(apiUrl(path), {
		...init,
		cache: "no-store",
		headers: {
			"content-type": "application/json",
			...(init?.headers ?? {}),
		},
	});
	let data: T | null = null;
	try {
		data = (await response.json()) as T;
	} catch {
		data = null;
	}
	return { ok: response.ok, status: response.status, data };
}

export async function openSessionAction(input: { piIndex: string | number }): Promise<OpenSessionResult> {
	const parsed = typeof input.piIndex === "number" ? input.piIndex : Number(input.piIndex);
	if (!Number.isInteger(parsed) || parsed < 0) {
		return { ok: false, error: "pi_index_required" };
	}
	if (parsed > MAX_PI_INDEX) {
		return { ok: false, error: "pi_index_limit" };
	}

	const sessionId = crypto.randomUUID();
	const clientSign = createSigningKeyPair();
	const clientDh = createDhKeyPair();
	const clientHello: ClientHello = createClientHello(sessionId, clientSign, clientDh);

	const helloResult = await fetchJson<{ serverHello?: ServerHello; error?: string }>("/session/hello", {
		method: "POST",
		body: JSON.stringify(clientHello),
	});

	if (!helloResult.ok || !helloResult.data?.serverHello) {
		return { ok: false, error: helloResult.data?.error ?? "hello_failed" };
	}

	const serverHello = helloResult.data.serverHello;
	const verify = verifyServerHello(clientHello, serverHello);
	if (!verify.ok) {
		return { ok: false, error: "invalid_server_signature" };
	}

	const sharedSecret = deriveSharedSecret(clientDh.privateKey, verify.serverDhPub);
	const transcriptHash = computeTranscriptHash(clientHello, serverHello);
	const keys = deriveSessionKeys(sharedSecret, transcriptHash);

	const aad = buildSessionAad(sessionId);
	const envelope: SecureEnvelope = encryptPayload(
		keys.clientToServerKey,
		keys.transcriptHash,
		"c2s",
		0,
		encodeJson({ piIndex: parsed }),
		aad,
	);

	const openResult = await fetchJson<{ envelope?: SecureEnvelope; error?: string }>("/session/open", {
		method: "POST",
		body: JSON.stringify({ sessionId, envelope }),
	});

	if (!openResult.ok || !openResult.data?.envelope) {
		return { ok: false, error: openResult.data?.error ?? "open_failed" };
	}

	let payload: unknown;
	try {
		const decrypted = decryptPayload(
			keys.serverToClientKey,
			keys.transcriptHash,
			"s2c",
			openResult.data.envelope.index,
			openResult.data.envelope.ciphertext,
			aad,
		);
		payload = decodeJson(decrypted);
	} catch {
		return { ok: false, error: "decrypt_failed" };
	}

	if (!payload || typeof payload !== "object") {
		return { ok: false, error: "invalid_payload" };
	}

	return { ok: true, sessionId, payload: payload as Record<string, unknown> };
}

export async function refreshSessionAction(): Promise<StatusResult> {
	const result = await fetchJson<Record<string, unknown>>("/session", { method: "GET" });
	if (!result.ok) {
		return { ok: false, status: result.status, error: (result.data as { error?: string } | null)?.error };
	}
	return { ok: true, status: result.status, data: result.data ?? {} };
}

export async function endSessionAction(): Promise<EndSessionResult> {
	const result = await fetchJson<Record<string, unknown>>("/session", { method: "DELETE" });
	if (!result.ok) {
		return { ok: false, status: result.status, error: (result.data as { error?: string } | null)?.error };
	}
	return { ok: true, status: result.status };
}

export async function sendCommandAction(input: {
	command: string;
	nextPiIndex: number | string;
}): Promise<CommandResult> {
	const command = input.command?.trim();
	if (!command) {
		return { ok: false, error: "command_required" };
	}
	const parsedIndex =
		typeof input.nextPiIndex === "number" ? input.nextPiIndex : Number(input.nextPiIndex);
	if (!Number.isInteger(parsedIndex) || parsedIndex < 0) {
		return { ok: false, error: "pi_index_required" };
	}

	let piHash: string;
	try {
		piHash = await computePiHash(parsedIndex);
	} catch (err) {
		return { ok: false, error: (err as Error).message ?? "pi_hash_failed" };
	}

	const result = await fetchJson<Record<string, unknown>>("/commands", {
		method: "POST",
		body: JSON.stringify({ command, piHash }),
	});

	if (!result.ok) {
		return { ok: false, status: result.status, data: result.data ?? {} };
	}
	return { ok: true, status: result.status, data: result.data ?? {} };
}
