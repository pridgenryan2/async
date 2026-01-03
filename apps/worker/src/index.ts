import {
	buildSessionAad,
	computePiFractionDigits,
	computePiHashFromDigits,
	computeTranscriptHash,
	createDhKeyPair,
	createServerHello,
	createSigningKeyPair,
	decodeJson,
	decryptPayload,
	deriveSessionKeys,
	deriveSharedSecret,
	encodeJson,
	fromBase64Url,
	toBase64Url,
	verifyClientHello,
	type ClientHello,
	type SecureEnvelope,
	type ServerHello,
} from "@queue/core";

const SESSION_DO_NAME = "singleton";
const STATE_KEY = "state";
const HANDSHAKE_KEY = "handshake";
const SESSION_TIMEOUT_MS = 30_000;
const HANDSHAKE_TIMEOUT_MS = 60_000;
const MAX_EVENTS = 50;
const MAX_WAIT_MS = 25_000;

const PI_CACHE_KEY = "pi:digits";
const PI_CACHE_STEP = 100;
const MAX_PI_INDEX = 10_000;

const CORS_HEADERS: Record<string, string> = {
	"access-control-allow-origin": "*",
	"access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
	"access-control-allow-headers": "Content-Type, X-Pi-Hash",
	"access-control-max-age": "86400",
};

type SessionState = {
	sessionEpoch: string | null;
	piStartIndex: number | null;
	commitCount: number;
	lastUserActivityAt: number | null;
	head: number;
	tail: number;
	headTimestamp: number | null;
};

type SessionRequest = {
	piIndex: number;
};

type CommandRequest = {
	command: string;
	piHash?: string;
	meta?: Record<string, unknown>;
};

type CommandMessage = {
	sessionEpoch: string;
	requestId: string;
	command: string;
	createdAt: number;
	piIndex: number;
	piHash: string;
	meta?: Record<string, unknown>;
};

type ResponseRequest = {
	event?: unknown;
	meta?: Record<string, unknown>;
	responseId?: string;
	piHash?: string;
};

type ResponseMessage = {
	sessionEpoch: string;
	responseId: string;
	createdAt: number;
	event: unknown;
	piIndex: number;
	piHash: string;
	meta?: Record<string, unknown>;
};

type HandshakeState = {
	sessionId: string;
	clientHello: ClientHello;
	serverHello: ServerHello;
	serverDhPriv: string;
	createdAt: number;
};

type SessionOpenRequest = {
	sessionId: string;
	envelope: SecureEnvelope;
};

type StoredEvent = {
	sequence: number;
	id: string;
	timestamp: number;
	responseId: string;
	payload: unknown;
	piIndex: number;
	piHash: string;
	meta?: Record<string, unknown>;
};

type AppendEnvelope = {
	events: Array<{
		id: string;
		timestamp: number;
		body: ResponseMessage;
	}>;
};

const DEFAULT_STATE: SessionState = {
	sessionEpoch: null,
	piStartIndex: null,
	commitCount: 0,
	lastUserActivityAt: null,
	head: 0,
	tail: 0,
	headTimestamp: null,
};

export interface Env {
	COMMANDS_QUEUE: Queue;
	RESPONSES_QUEUE: Queue;
	SESSION_DO: DurableObjectNamespace;
}

function withCors(headers?: HeadersInit): Headers {
	const result = new Headers(headers);
	for (const [key, value] of Object.entries(CORS_HEADERS)) {
		result.set(key, value);
	}
	return result;
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
	const headers = withCors(init.headers);
	headers.set("content-type", "application/json; charset=utf-8");
	return new Response(JSON.stringify(body), { ...init, headers });
}

function clampNumber(value: number, min: number, max: number): number {
	if (Number.isNaN(value)) {
		return min;
	}
	return Math.min(Math.max(value, min), max);
}

async function parseJsonBody<T>(request: Request): Promise<{ value: T | null; error: string | null }> {
	const text = await request.text();
	if (!text) {
		return { value: null, error: null };
	}
	try {
		return { value: JSON.parse(text) as T, error: null };
	} catch {
		return { value: null, error: "invalid_json" };
	}
}

function extractEventPayload(body: unknown): unknown {
	if (body && typeof body === "object") {
		const record = body as Record<string, unknown>;
		if ("event" in record) {
			return record.event;
		}
		const {
			responseId: _rid,
			piHash: _ph,
			piIndex: _pi,
			meta: _meta,
			...rest
		} = record;
		return rest;
	}
	return body;
}

function parsePiIndex(value: unknown): number | null {
	if (typeof value === "number") {
		return Number.isSafeInteger(value) && value >= 0 ? value : null;
	}
	if (typeof value === "string") {
		const trimmed = value.trim();
		if (trimmed.length === 0) {
			return null;
		}
		const num = Number(trimmed);
		return Number.isSafeInteger(num) && num >= 0 ? num : null;
	}
	return null;
}

function extractPiIndex(request: Request, body?: unknown): number | null {
	const url = new URL(request.url);
	const query = url.searchParams.get("piIndex") ?? url.searchParams.get("index");
	if (query !== null) {
		return parsePiIndex(query);
	}
	if (body && typeof body === "object") {
		const record = body as Record<string, unknown>;
		if ("piIndex" in record) {
			return parsePiIndex(record.piIndex);
		}
		if ("index" in record) {
			return parsePiIndex(record.index);
		}
	}
	return null;
}

function extractPiHash(request: Request, body?: unknown): string | null {
	const header = request.headers.get("x-pi-hash");
	if (header) {
		return header;
	}
	if (body && typeof body === "object") {
		const record = body as Record<string, unknown>;
		const maybe = record.piHash;
		if (typeof maybe === "string" && maybe.trim().length > 0) {
			return maybe;
		}
	}
	return null;
}

function isNonEmptyString(value: unknown): value is string {
	return typeof value === "string" && value.trim().length > 0;
}

function asClientHello(value: unknown): ClientHello | null {
	if (!value || typeof value !== "object") {
		return null;
	}
	const record = value as Record<string, unknown>;
	if (
		!isNonEmptyString(record.sessionId) ||
		!isNonEmptyString(record.clientSignPub) ||
		!isNonEmptyString(record.clientDhPub) ||
		!isNonEmptyString(record.signature)
	) {
		return null;
	}
	return {
		sessionId: record.sessionId,
		clientSignPub: record.clientSignPub,
		clientDhPub: record.clientDhPub,
		signature: record.signature,
	};
}

function asSecureEnvelope(value: unknown): SecureEnvelope | null {
	if (!value || typeof value !== "object") {
		return null;
	}
	const record = value as Record<string, unknown>;
	const index = typeof record.index === "number" && Number.isInteger(record.index) ? record.index : null;
	const ciphertext = isNonEmptyString(record.ciphertext) ? record.ciphertext : null;
	const nonce = typeof record.nonce === "string" ? record.nonce : "";
	if (index === null || !ciphertext) {
		return null;
	}
	return { index, ciphertext, nonce };
}

function normalizeHash(value: string): string {
	return value.trim().toLowerCase();
}


export class SessionDurableObject {
	private state: DurableObjectState;
	private env: Env;
	private waiters: Array<() => void> = [];

	constructor(state: DurableObjectState, env: Env) {
		this.state = state;
		this.env = env;
	}

	async fetch(request: Request): Promise<Response> {
		if (request.method === "OPTIONS") {
			return new Response(null, { status: 204, headers: withCors() });
		}

		const url = new URL(request.url);
		switch (url.pathname) {
			case "/session":
				if (request.method === "POST") {
					return this.handleSessionCreate(request);
				}
				if (request.method === "GET") {
					return this.handleSessionStatus();
				}
				if (request.method === "DELETE") {
					return this.handleSessionEnd();
				}
				return jsonResponse({ error: "method_not_allowed" }, { status: 405 });
			case "/session/hello":
				if (request.method === "POST") {
					return this.handleSessionHello(request);
				}
				return jsonResponse({ error: "method_not_allowed" }, { status: 405 });
			case "/session/open":
				if (request.method === "POST") {
					return this.handleSessionOpen(request);
				}
				return jsonResponse({ error: "method_not_allowed" }, { status: 405 });
			case "/commands":
				if (request.method === "POST") {
					return this.handleCommand(request);
				}
				return jsonResponse({ error: "method_not_allowed" }, { status: 405 });
			case "/events":
				if (request.method === "POST") {
					return this.handleEventPost(request);
				}
				if (request.method === "GET") {
					return this.handleEventGet(request);
				}
				return jsonResponse({ error: "method_not_allowed" }, { status: 405 });
			case "/internal/append":
				if (request.method === "POST") {
					return this.handleInternalAppend(request);
				}
				return jsonResponse({ error: "method_not_allowed" }, { status: 405 });
			default:
				return jsonResponse({ error: "not_found" }, { status: 404 });
		}
	}

	private async handleSessionCreate(request: Request): Promise<Response> {
		const { value: body, error } = await parseJsonBody<SessionRequest>(request);
		if (error) {
			return jsonResponse({ error }, { status: 400 });
		}
		const piIndex = extractPiIndex(request, body ?? undefined);
		if (piIndex === null) {
			return jsonResponse({ error: "pi_index_required" }, { status: 400 });
		}
		if (piIndex > MAX_PI_INDEX) {
			return jsonResponse(
				{ error: "pi_index_limit", maxPiIndex: MAX_PI_INDEX },
				{ status: 400 },
			);
		}

		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const state = await this.getState();
			if (state.piStartIndex !== null && this.isSessionActive(state, now)) {
				return jsonResponse(
					{
						error: "session_active",
						nextPiIndex: this.expectedPiIndex(state),
						lastUserActivityAt: state.lastUserActivityAt,
					},
					{ status: 409 },
				);
			}

			await this.state.storage.deleteAll();
			const sessionEpoch = crypto.randomUUID();
			const nextState: SessionState = {
				...DEFAULT_STATE,
				sessionEpoch,
				piStartIndex: piIndex,
				commitCount: 0,
				lastUserActivityAt: now,
			};
			await this.saveState(nextState);

			const acceptHash = await this.computePiHash(piIndex);
			return jsonResponse(
				{
					status: "created",
					piIndex,
					acceptHash,
					nextPiIndex: piIndex + 1,
					expiresInMs: SESSION_TIMEOUT_MS,
				},
				{ status: 201 },
			);
		});
	}

	private async handleSessionHello(request: Request): Promise<Response> {
		const { value: body, error } = await parseJsonBody<unknown>(request);
		if (error) {
			return jsonResponse({ error }, { status: 400 });
		}
		const clientHello = asClientHello(body);
		if (!clientHello) {
			return jsonResponse({ error: "invalid_client_hello" }, { status: 400 });
		}

		let verified: ReturnType<typeof verifyClientHello>;
		try {
			verified = verifyClientHello(clientHello);
		} catch {
			return jsonResponse({ error: "invalid_client_hello" }, { status: 400 });
		}
		if (!verified.ok) {
			return jsonResponse({ error: "invalid_signature" }, { status: 401 });
		}

		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const existing = await this.getHandshake();
			if (existing && existing.sessionId === clientHello.sessionId && this.isHandshakeActive(existing, now)) {
				const remaining = Math.max(HANDSHAKE_TIMEOUT_MS - (now - existing.createdAt), 0);
				return jsonResponse(
					{ serverHello: existing.serverHello, expiresInMs: remaining },
					{ status: 200 },
				);
			}

			const serverSign = createSigningKeyPair();
			const serverDh = createDhKeyPair();
			const serverHello = createServerHello(clientHello, serverSign, serverDh);
			const handshake: HandshakeState = {
				sessionId: clientHello.sessionId,
				clientHello,
				serverHello,
				serverDhPriv: toBase64Url(serverDh.privateKey),
				createdAt: now,
			};
			await this.saveHandshake(handshake);

			return jsonResponse({ serverHello, expiresInMs: HANDSHAKE_TIMEOUT_MS }, { status: 200 });
		});
	}

	private async handleSessionOpen(request: Request): Promise<Response> {
		const { value: body, error } = await parseJsonBody<unknown>(request);
		if (error) {
			return jsonResponse({ error }, { status: 400 });
		}
		if (!body || typeof body !== "object") {
			return jsonResponse({ error: "invalid_payload" }, { status: 400 });
		}
		const record = body as Record<string, unknown>;
		if (!isNonEmptyString(record.sessionId)) {
			return jsonResponse({ error: "session_id_required" }, { status: 400 });
		}
		const envelope = asSecureEnvelope(record.envelope);
		if (!envelope) {
			return jsonResponse({ error: "invalid_envelope" }, { status: 400 });
		}
		const sessionId = record.sessionId;

		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const handshake = await this.getHandshake();
			if (!handshake || handshake.sessionId !== sessionId || !this.isHandshakeActive(handshake, now)) {
				await this.clearHandshake();
				return jsonResponse({ error: "handshake_missing" }, { status: 409 });
			}

			let keys: ReturnType<typeof deriveSessionKeys>;
			try {
				const serverDhPriv = fromBase64Url(handshake.serverDhPriv);
				const clientDhPub = fromBase64Url(handshake.clientHello.clientDhPub);
				const sharedSecret = deriveSharedSecret(serverDhPriv, clientDhPub);
				const transcriptHash = computeTranscriptHash(handshake.clientHello, handshake.serverHello);
				keys = deriveSessionKeys(sharedSecret, transcriptHash);
			} catch {
				await this.clearHandshake();
				return jsonResponse({ error: "handshake_invalid" }, { status: 400 });
			}

			const aad = buildSessionAad(sessionId);
			let decrypted: unknown;
			try {
				const plaintext = decryptPayload(
					keys.clientToServerKey,
					keys.transcriptHash,
					"c2s",
					envelope.index,
					envelope.ciphertext,
					aad,
				);
				decrypted = decodeJson(plaintext);
			} catch {
				await this.clearHandshake();
				return jsonResponse({ error: "decrypt_failed" }, { status: 400 });
			}

			const piIndex = parsePiIndex((decrypted as Record<string, unknown> | null)?.piIndex);
			const state = await this.getState();
			let responsePayload: Record<string, unknown>;

			if (piIndex === null) {
				responsePayload = { accepted: false, reason: "pi_index_required" };
			} else if (piIndex > MAX_PI_INDEX) {
				responsePayload = { accepted: false, reason: "pi_index_limit", maxPiIndex: MAX_PI_INDEX };
			} else if (state.piStartIndex !== null && this.isSessionActive(state, now)) {
				responsePayload = { accepted: false, reason: "session_active" };
			} else {
				await this.state.storage.deleteAll();
				const sessionEpoch = crypto.randomUUID();
				const nextState: SessionState = {
					...DEFAULT_STATE,
					sessionEpoch,
					piStartIndex: piIndex,
					commitCount: 0,
					lastUserActivityAt: now,
				};
				await this.saveState(nextState);
				const acceptHash = await this.computePiHash(piIndex);
				responsePayload = {
					accepted: true,
					piIndex,
					acceptHash,
					nextPiIndex: piIndex + 1,
					expiresInMs: SESSION_TIMEOUT_MS,
				};
			}

			const responseIndex = envelope.index + 1;
			const responseEnvelope = encryptPayload(
				keys.serverToClientKey,
				keys.transcriptHash,
				"s2c",
				responseIndex,
				encodeJson(responsePayload),
				aad,
			);

			await this.clearHandshake();
			return jsonResponse({ envelope: responseEnvelope }, { status: 200 });
		});
	}

	private async handleSessionStatus(): Promise<Response> {
		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const state = await this.getState();
			if (state.piStartIndex === null) {
				return jsonResponse({ error: "no_session" }, { status: 409 });
			}
			const active = this.isSessionActive(state, now);
			const queueDepth = Math.max(state.tail - state.head, 0);
			const headAgeMs =
				state.headTimestamp === null ? null : Math.max(now - state.headTimestamp, 0);
			const nextPiIndex = this.expectedPiIndex(state);
			let nextPiHash: string | null = null;
			if (nextPiIndex !== null && nextPiIndex <= MAX_PI_INDEX) {
				nextPiHash = await this.computePiHash(nextPiIndex);
			}
			return jsonResponse(
				{
					active,
					piStartIndex: state.piStartIndex,
					commitCount: state.commitCount,
					nextPiIndex,
					nextPiHash,
					lastUserActivityAt: state.lastUserActivityAt,
					queueDepth,
					headAgeMs,
				},
				{ status: 200 },
			);
		});
	}

	private async handleSessionEnd(): Promise<Response> {
		return this.state.blockConcurrencyWhile(async () => {
			const state = await this.getState();
			if (state.piStartIndex === null) {
				return jsonResponse({ error: "no_session" }, { status: 409 });
			}
			await this.clearSession();
			return jsonResponse({ status: "ended" }, { status: 200 });
		});
	}

	private async handleCommand(request: Request): Promise<Response> {
		const { value: body, error } = await parseJsonBody<CommandRequest>(request);
		if (error) {
			return jsonResponse({ error }, { status: 400 });
		}
		if (!body || typeof body.command !== "string" || body.command.trim().length === 0) {
			return jsonResponse({ error: "command_required" }, { status: 400 });
		}
		const providedHash = extractPiHash(request, body);
		if (!providedHash) {
			return jsonResponse({ error: "pi_hash_required" }, { status: 400 });
		}
		const normalizedHash = normalizeHash(providedHash);

		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const state = await this.getState();
			const errorResponse = await this.ensureSession(state, now);
			if (errorResponse) {
				return errorResponse;
			}
			const expectedIndex = this.expectedPiIndex(state);
			if (expectedIndex === null) {
				return jsonResponse({ error: "no_session" }, { status: 409 });
			}
			if (expectedIndex > MAX_PI_INDEX) {
				return jsonResponse(
					{ error: "pi_index_limit", maxPiIndex: MAX_PI_INDEX },
					{ status: 409 },
				);
			}

			const expectedHash = await this.computePiHash(expectedIndex);
			if (normalizedHash !== expectedHash) {
				return jsonResponse(
					{ error: "pi_mismatch", expectedPiIndex: expectedIndex },
					{ status: 409 },
				);
			}

			const sessionEpoch = state.sessionEpoch;
			if (!sessionEpoch) {
				return jsonResponse({ error: "no_session" }, { status: 409 });
			}
			const requestId = crypto.randomUUID();
			const message: CommandMessage = {
				sessionEpoch,
				requestId,
				command: body.command,
				createdAt: now,
				piIndex: expectedIndex,
				piHash: expectedHash,
				meta: body.meta,
			};
			await this.env.COMMANDS_QUEUE.send(message, { contentType: "json" });

			state.commitCount += 1;
			state.lastUserActivityAt = now;
			await this.saveState(state);

			return jsonResponse(
				{ requestId, piIndex: expectedIndex, nextPiIndex: expectedIndex + 1 },
				{ status: 202 },
			);
		});
	}

	private async handleEventPost(request: Request): Promise<Response> {
		const { value: body, error } = await parseJsonBody<ResponseRequest>(request);
		if (error) {
			return jsonResponse({ error }, { status: 400 });
		}
		const providedHash = extractPiHash(request, body ?? undefined);
		if (!providedHash) {
			return jsonResponse({ error: "pi_hash_required" }, { status: 400 });
		}
		const normalizedHash = normalizeHash(providedHash);
		const eventPayload = extractEventPayload(body);
		const responseId =
			body && typeof body.responseId === "string" && body.responseId.length > 0
				? body.responseId
				: crypto.randomUUID();

		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const state = await this.getState();
			const errorResponse = await this.ensureSession(state, now);
			if (errorResponse) {
				return errorResponse;
			}
			const expectedIndex = this.expectedPiIndex(state);
			if (expectedIndex === null) {
				return jsonResponse({ error: "no_session" }, { status: 409 });
			}
			if (expectedIndex > MAX_PI_INDEX) {
				return jsonResponse(
					{ error: "pi_index_limit", maxPiIndex: MAX_PI_INDEX },
					{ status: 409 },
				);
			}
			const expectedHash = await this.computePiHash(expectedIndex);
			if (normalizedHash !== expectedHash) {
				return jsonResponse(
					{ error: "pi_mismatch", expectedPiIndex: expectedIndex },
					{ status: 409 },
				);
			}

			const sessionEpoch = state.sessionEpoch;
			if (!sessionEpoch) {
				return jsonResponse({ error: "no_session" }, { status: 409 });
			}
			const message: ResponseMessage = {
				sessionEpoch,
				responseId,
				createdAt: now,
				event: eventPayload,
				piIndex: expectedIndex,
				piHash: expectedHash,
				meta: body?.meta,
			};
			await this.env.RESPONSES_QUEUE.send(message);

			state.commitCount += 1;
			await this.saveState(state);

			return jsonResponse(
				{ responseId, piIndex: expectedIndex, nextPiIndex: expectedIndex + 1 },
				{ status: 202 },
			);
		});
	}

	private async handleEventGet(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const max = clampNumber(Number(url.searchParams.get("max") ?? 20), 1, MAX_EVENTS);
		const waitMs = clampNumber(Number(url.searchParams.get("wait") ?? 0), 0, MAX_WAIT_MS);

		const touchResult = await this.touchSession();
		if (!touchResult.ok) {
			return touchResult.response;
		}
		if (waitMs > 0 && touchResult.state.tail === touchResult.state.head) {
			await this.waitForEvent(waitMs);
		}

		return this.consumeEvents(max);
	}

	private async handleInternalAppend(request: Request): Promise<Response> {
		const { value: body, error } = await parseJsonBody<AppendEnvelope>(request);
		if (error || !body || !Array.isArray(body.events)) {
			return jsonResponse({ error: "invalid_payload" }, { status: 400 });
		}

		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const state = await this.getState();
			if (!state.sessionEpoch || state.piStartIndex === null || !this.isSessionActive(state, now)) {
				await this.clearSession();
				return jsonResponse({ ok: true, stored: 0, dropped: body.events.length }, { status: 200 });
			}

			const wasEmpty = state.head === state.tail;
			let stored = 0;
			let dropped = 0;
			const writes: Record<string, StoredEvent | SessionState> = {};
			let nextTail = state.tail;
			let headTimestamp = state.headTimestamp;

			for (const event of body.events) {
				const message = event.body;
				if (!message || message.sessionEpoch !== state.sessionEpoch) {
					dropped += 1;
					continue;
				}
				const sequence = nextTail;
				nextTail += 1;
				const storedEvent: StoredEvent = {
					sequence,
					id: event.id,
					timestamp: event.timestamp,
					responseId: message.responseId,
					payload: message.event,
					piIndex: message.piIndex,
					piHash: message.piHash,
					meta: message.meta,
				};
				writes[this.eventKey(sequence)] = storedEvent;
				if (wasEmpty && stored === 0) {
					headTimestamp = event.timestamp;
				}
				stored += 1;
			}

			if (stored > 0) {
				state.tail = nextTail;
				state.headTimestamp = headTimestamp ?? state.headTimestamp;
				writes[STATE_KEY] = state;
				await this.state.storage.put(writes);
				this.notifyWaiters();
			}

			return jsonResponse({ ok: true, stored, dropped }, { status: 200 });
		});
	}

	private async consumeEvents(max: number): Promise<Response> {
		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const state = await this.getState();
			const errorResponse = await this.ensureSession(state, now);
			if (errorResponse) {
				return errorResponse;
			}

			const available = Math.max(state.tail - state.head, 0);
			if (available === 0) {
				return jsonResponse(
					{
						events: [],
						queueDepth: 0,
						headAgeMs:
							state.headTimestamp === null ? null : Math.max(now - state.headTimestamp, 0),
					},
					{ status: 200 },
				);
			}

			const count = Math.min(max, available);
			const keys = Array.from({ length: count }, (_, index) => this.eventKey(state.head + index));
			const eventMap = await this.state.storage.get<StoredEvent>(keys);
			const events: StoredEvent[] = [];
			for (const key of keys) {
				const event = eventMap.get(key);
				if (event) {
					events.push(event);
				}
			}

			const deleteKeys = events.map((event) => this.eventKey(event.sequence));
			state.head += events.length;

			if (state.head >= state.tail) {
				state.headTimestamp = null;
			} else {
				const nextEvent = await this.state.storage.get<StoredEvent>(this.eventKey(state.head));
				state.headTimestamp = nextEvent?.timestamp ?? state.headTimestamp;
			}

			if (deleteKeys.length > 0) {
				await this.state.storage.delete(deleteKeys);
			}
			await this.saveState(state);

			const queueDepth = Math.max(state.tail - state.head, 0);
			const headAgeMs =
				state.headTimestamp === null ? null : Math.max(now - state.headTimestamp, 0);
			return jsonResponse(
				{
					events,
					queueDepth,
					headAgeMs,
				},
				{ status: 200 },
			);
		});
	}

	private async touchSession(): Promise<{ ok: true; state: SessionState } | { ok: false; response: Response }> {
		return this.state.blockConcurrencyWhile(async () => {
			const now = Date.now();
			const state = await this.getState();
			const errorResponse = await this.ensureSession(state, now);
			if (errorResponse) {
				return { ok: false, response: errorResponse };
			}
			state.lastUserActivityAt = now;
			await this.saveState(state);
			return { ok: true, state };
		});
	}

	private async ensureSession(state: SessionState, now: number): Promise<Response | null> {
		if (state.piStartIndex === null || !state.sessionEpoch) {
			return jsonResponse({ error: "no_session" }, { status: 409 });
		}
		if (!this.isSessionActive(state, now)) {
			await this.clearSession();
			return jsonResponse({ error: "session_expired" }, { status: 410 });
		}
		return null;
	}

	private isSessionActive(state: SessionState, now: number): boolean {
		if (state.piStartIndex === null || state.lastUserActivityAt === null) {
			return false;
		}
		return now - state.lastUserActivityAt <= SESSION_TIMEOUT_MS;
	}

	private expectedPiIndex(state: SessionState): number | null {
		if (state.piStartIndex === null) {
			return null;
		}
		return state.piStartIndex + state.commitCount + 1;
	}

	private async computePiHash(index: number): Promise<string> {
		const digits = await this.getPiDigits(index + 2);
		return computePiHashFromDigits(index, digits);
	}

	private async getPiDigits(targetLength: number): Promise<string> {
		const cached = await this.state.storage.get<string>(PI_CACHE_KEY);
		const cachedDigits = typeof cached === "string" ? cached : "";
		if (cachedDigits.length >= targetLength) {
			return cachedDigits;
		}
		const nextLength = Math.max(targetLength, cachedDigits.length + PI_CACHE_STEP);
		const computed = computePiFractionDigits(nextLength);
		await this.state.storage.put(PI_CACHE_KEY, computed);
		return computed;
	}

	private async getHandshake(): Promise<HandshakeState | null> {
		const stored = await this.state.storage.get<HandshakeState>(HANDSHAKE_KEY);
		return stored ?? null;
	}

	private async saveHandshake(handshake: HandshakeState): Promise<void> {
		await this.state.storage.put(HANDSHAKE_KEY, handshake);
	}

	private async clearHandshake(): Promise<void> {
		await this.state.storage.delete(HANDSHAKE_KEY);
	}

	private isHandshakeActive(handshake: HandshakeState, now: number): boolean {
		return now - handshake.createdAt <= HANDSHAKE_TIMEOUT_MS;
	}

	private eventKey(sequence: number): string {
		return `event:${sequence}`;
	}

	private async getState(): Promise<SessionState> {
		const stored = await this.state.storage.get<SessionState>(STATE_KEY);
		return stored ? { ...DEFAULT_STATE, ...stored } : { ...DEFAULT_STATE };
	}

	private async saveState(state: SessionState): Promise<void> {
		await this.state.storage.put(STATE_KEY, state);
	}

	private async clearSession(): Promise<void> {
		await this.state.storage.deleteAll();
		await this.saveState({ ...DEFAULT_STATE });
	}

	private async waitForEvent(waitMs: number): Promise<void> {
		if (waitMs <= 0) {
			return;
		}
		await new Promise<void>((resolve) => {
			const timeout = setTimeout(resolve, waitMs);
			this.waiters.push(() => {
				clearTimeout(timeout);
				resolve();
			});
		});
	}

	private notifyWaiters(): void {
		if (this.waiters.length === 0) {
			return;
		}
		const waiters = this.waiters;
		this.waiters = [];
		for (const notify of waiters) {
			notify();
		}
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const id = env.SESSION_DO.idFromName(SESSION_DO_NAME);
		return env.SESSION_DO.get(id).fetch(request);
	},
	async queue(batch: MessageBatch<ResponseMessage>, env: Env): Promise<void> {
		const id = env.SESSION_DO.idFromName(SESSION_DO_NAME);
		const stub = env.SESSION_DO.get(id);
		const events = batch.messages.map((message) => ({
			id: message.id,
			timestamp: message.timestamp.getTime(),
			body: message.body,
		}));

		const response = await stub.fetch("https://session.internal/internal/append", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ events }),
		});

		if (!response.ok) {
			const details = await response.text();
			throw new Error(`Failed to append responses: ${response.status} ${details}`);
		}

		batch.ackAll();
	},
} satisfies ExportedHandler<Env, Error>;
