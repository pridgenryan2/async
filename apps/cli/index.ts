import { consola } from "consola";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";
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
	type Hello,
	type Reply,
	type SecureEnvelope,
	type SessionKeys,
} from "@siguiente/cifra";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 46321;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

const MAX_PROMPT_LENGTH = 4000;

type WireHello = {
	type: "hello";
	hello: Hello;
};

type WireReply = {
	type: "reply";
	reply: Reply;
};

type WireData = {
	type: "data";
	envelope: SecureEnvelope;
};

type WireMessage = WireHello | WireReply | WireData;

type Payload =
	| { kind: "ready" }
	| { kind: "input"; data: string }
	| { kind: "output"; stream: "stdout" | "stderr"; data: string }
	| { kind: "complete" }
	| { kind: "error"; message: string }
	| { kind: "exit"; reason?: string };

type RemotePeer = {
	address: string;
	port: number;
};

type SessionState = {
	sessionId: string;
	peer: RemotePeer;
	keys: SessionKeys;
	sendIndex: number;
	recvIndex: number;
	aad: Uint8Array;
};

function encodeMessage(message: WireMessage): Uint8Array {
	return TEXT_ENCODER.encode(JSON.stringify(message));
}

function decodeMessage(data: Uint8Array): WireMessage | null {
	try {
		return JSON.parse(TEXT_DECODER.decode(data)) as WireMessage;
	} catch {
		return null;
	}
}

function parseArgs(argv: string[]) {
	const args = new Map<string, string>();
	let mode: "server" | "client" | null = null;
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "server" || arg === "client") {
			mode = arg;
			continue;
		}
		if (arg.startsWith("--")) {
			const key = arg.slice(2);
			const next = argv[i + 1];
			if (!next || next.startsWith("--")) {
				args.set(key, "true");
				continue;
			}
			args.set(key, next);
			i += 1;
		}
	}
	return { mode, args };
}

function resolveBunx(): string {
	if (process.env.BUNX_PATH) {
		return process.env.BUNX_PATH;
	}
	const home = process.env.USERPROFILE ?? process.env.HOME ?? "";
	const candidate = path.join(home, ".bun", "bin", process.platform === "win32" ? "bunx.exe" : "bunx");
	if (home && existsSync(candidate)) {
		return candidate;
	}
	return "bunx";
}

function isPayload(value: unknown): value is Payload {
	if (!value || typeof value !== "object") {
		return false;
	}
	const record = value as Record<string, unknown>;
	const kind = record.kind;
	if (kind === "ready" || kind === "complete") {
		return true;
	}
	if (kind === "input") {
		return typeof record.data === "string";
	}
	if (kind === "output") {
		return (
			record.stream === "stdout" ||
			record.stream === "stderr"
		) && typeof record.data === "string";
	}
	if (kind === "error") {
		return typeof record.message === "string";
	}
	if (kind === "exit") {
		return record.reason === undefined || typeof record.reason === "string";
	}
	return false;
}

function safePrompt(value: string): string {
	if (value.length <= MAX_PROMPT_LENGTH) {
		return value;
	}
	return `${value.slice(0, MAX_PROMPT_LENGTH)}...`;
}

function debugLog(enabled: boolean, message: string, data?: Record<string, unknown>) {
	if (!enabled) {
		return;
	}
	if (data) {
		consola.info({ message, ...data });
		return;
	}
	consola.info(message);
}

async function runServer(host: string, port: number, debug: boolean): Promise<void> {
	let session: SessionState | null = null;
	const queue: string[] = [];
	let running = false;

	const socket = await Bun.udpSocket({
		port,
		hostname: host,
		socket: {
			data(_socket, data, remotePort, remoteAddress) {
				const message = decodeMessage(data);
				if (!message) {
					return;
				}

				if (message.type === "hello") {
					if (session && (session.peer.address !== remoteAddress || session.peer.port !== remotePort)) {
						debugLog(debug, "Rejecting hello from unexpected peer.", {
							remoteAddress,
							remotePort,
						});
						return;
					}

					const helloResult = verifyHello(message.hello);
					if (!helloResult.ok) {
						debugLog(debug, "Hello verification failed.");
						return;
					}

					const responderSign = createSigningKeyPair();
					const responderDh = createDhKeyPair();
					const reply = createReply(message.hello, responderSign, responderDh);
					const sharedSecret = deriveSharedSecret(responderDh.privateKey, helloResult.dhPub);
					const transcriptHash = computeTranscriptHash(message.hello, reply);
					const keys = deriveSessionKeys(sharedSecret, transcriptHash, "responder");
					const aad = buildSessionAad(message.hello.sessionId);

					session = {
						sessionId: message.hello.sessionId,
						peer: { address: remoteAddress, port: remotePort },
						keys,
						sendIndex: 0,
						recvIndex: 0,
						aad,
					};

					socket.send(
						encodeMessage({ type: "reply", reply }),
						remotePort,
						remoteAddress,
					);
					debugLog(debug, "Reply sent.", {
						sessionId: session.sessionId,
						peer: `${remoteAddress}:${remotePort}`,
						signPub: toBase64Url(responderSign.publicKey),
						dhPub: toBase64Url(responderDh.publicKey),
						transcript: toBase64Url(transcriptHash),
					});

					sendEncrypted(session, { kind: "ready" });
					return;
				}

				if (!session || session.peer.address !== remoteAddress || session.peer.port !== remotePort) {
					return;
				}

				if (message.type === "data") {
					const payload = decryptMessage(session, message.envelope, debug);
					if (!payload) {
						return;
					}
					if (payload.kind === "input") {
						enqueueInput(payload.data);
						return;
					}
					if (payload.kind === "exit") {
						debugLog(debug, "Client exit requested.", { reason: payload.reason ?? "unknown" });
						queue.length = 0;
						running = false;
						session = null;
						return;
					}
				}
			},
		},
	});

	function sendEncrypted(active: SessionState, payload: Payload) {
		const envelope = encryptPayload(
			active.keys.sendKey,
			active.keys.transcriptHash,
			active.sendIndex,
			encodeJson(payload),
			active.aad,
		);
		debugLog(debug, "Sending encrypted payload.", {
			kind: payload.kind,
			index: active.sendIndex,
		});
		active.sendIndex += 1;
		socket.send(encodeMessage({ type: "data", envelope }), active.peer.port, active.peer.address);
	}

	function decryptMessage(active: SessionState, envelope: SecureEnvelope, isDebug: boolean): Payload | null {
		if (envelope.index !== active.recvIndex) {
			debugLog(isDebug, "Unexpected envelope index.", {
				expected: active.recvIndex,
				received: envelope.index,
			});
			return null;
		}
		try {
			const plaintext = decryptPayload(
				active.keys.recvKey,
				active.keys.transcriptHash,
				envelope.index,
				envelope.ciphertext,
				active.aad,
			);
			const decoded = decodeJson(plaintext);
			if (!isPayload(decoded)) {
				debugLog(isDebug, "Invalid payload received.");
				return null;
			}
			active.recvIndex += 1;
			return decoded;
		} catch (err) {
			debugLog(isDebug, "Failed to decrypt payload.", {
				error: err instanceof Error ? err.message : String(err),
			});
			return null;
		}
	}

	function enqueueInput(input: string) {
		queue.push(input);
		void runNext();
	}

	function runNext() {
		if (!session || running || queue.length === 0) {
			return;
		}
		const next = queue.shift() ?? "";
		const prompt = safePrompt(next.replace(/\r?\n$/, ""));
		if (!prompt.trim()) {
			sendEncrypted(session, { kind: "complete" });
			void runNext();
			return;
		}

		const bunx = resolveBunx();
		const args = [
			"@openai/codex@latest",
			"exec",
			"--sandbox",
			"danger-full-access",
			"--color",
			"never",
			prompt,
		];

		debugLog(debug, "Launching codex exec.", { prompt });
		running = true;
		const child = spawn(bunx, args, {
			stdio: ["ignore", "pipe", "pipe"],
			shell: process.platform === "win32",
			env: { ...process.env },
		});

		child.stdout?.on("data", (chunk: Buffer) => {
			if (!session) {
				return;
			}
			sendEncrypted(session, { kind: "output", stream: "stdout", data: chunk.toString("utf8") });
		});
		child.stderr?.on("data", (chunk: Buffer) => {
			if (!session) {
				return;
			}
			sendEncrypted(session, { kind: "output", stream: "stderr", data: chunk.toString("utf8") });
		});
		child.on("exit", () => {
			running = false;
			if (session) {
				sendEncrypted(session, { kind: "complete" });
			}
			void runNext();
		});
		child.on("error", (err) => {
			running = false;
			if (session) {
				sendEncrypted(session, { kind: "error", message: err.message });
			}
			void runNext();
		});
	}

	consola.ready(`UDP server listening on ${host}:${socket.port}.`);
	process.on("SIGINT", () => {
		consola.info("Shutting down server.");
		queue.length = 0;
		socket.close();
		process.exit(0);
	});
}

async function runClient(host: string, port: number, debug: boolean): Promise<void> {
	const sessionId = randomUUID();
	const initiatorSign = createSigningKeyPair();
	const initiatorDh = createDhKeyPair();
	let session: SessionState | null = null;
	const pending: string[] = [];

	const socket = await Bun.udpSocket({
		port: 0,
		hostname: DEFAULT_HOST,
		socket: {
			data(_socket, data, remotePort, remoteAddress) {
				const message = decodeMessage(data);
				if (!message) {
					return;
				}
				if (message.type === "reply") {
					const replyCheck = verifyReply(hello, message.reply);
					if (!replyCheck.ok) {
						consola.error("Reply signature invalid.");
						return;
					}
					const sharedSecret = deriveSharedSecret(initiatorDh.privateKey, replyCheck.dhPub);
					const transcriptHash = computeTranscriptHash(hello, message.reply);
					const keys = deriveSessionKeys(sharedSecret, transcriptHash, "initiator");
					const aad = buildSessionAad(sessionId);

					session = {
						sessionId,
						peer: { address: remoteAddress, port: remotePort },
						keys,
						sendIndex: 0,
						recvIndex: 0,
						aad,
					};

					debugLog(debug, "Session established.", {
						sessionId,
						signPub: toBase64Url(initiatorSign.publicKey),
						dhPub: toBase64Url(initiatorDh.publicKey),
						transcript: toBase64Url(transcriptHash),
					});
					flushPending();
					return;
				}

				if (message.type === "data") {
					if (!session) {
						debugLog(debug, "Received data before session established.");
						return;
					}
					const payload = decryptMessage(session, message.envelope, debug);
					if (!payload) {
						return;
					}
					handlePayload(payload);
				}
			},
		},
	});

	const hello = createHello(sessionId, initiatorSign, initiatorDh);
	socket.send(encodeMessage({ type: "hello", hello }), port, host);

	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
		terminal: true,
	});

	rl.on("line", (line) => {
		const value = `${line}\n`;
		if (!session) {
			pending.push(value);
			return;
		}
		sendEncrypted(session, { kind: "input", data: value });
	});

	process.on("SIGINT", () => {
		consola.info("Closing session.");
		if (session) {
			sendEncrypted(session, { kind: "exit", reason: "client_exit" });
		}
		socket.close();
		rl.close();
		process.exit(0);
	});

	consola.ready(`Connected to ${host}:${port}. Waiting for handshake...`);

	function sendEncrypted(active: SessionState, payload: Payload) {
		const envelope = encryptPayload(
			active.keys.sendKey,
			active.keys.transcriptHash,
			active.sendIndex,
			encodeJson(payload),
			active.aad,
		);
		debugLog(debug, "Sending encrypted payload.", {
			kind: payload.kind,
			index: active.sendIndex,
		});
		active.sendIndex += 1;
		socket.send(encodeMessage({ type: "data", envelope }), active.peer.port, active.peer.address);
	}

	function decryptMessage(active: SessionState, envelope: SecureEnvelope, isDebug: boolean): Payload | null {
		if (envelope.index !== active.recvIndex) {
			debugLog(isDebug, "Unexpected envelope index.", {
				expected: active.recvIndex,
				received: envelope.index,
			});
			return null;
		}
		try {
			const plaintext = decryptPayload(
				active.keys.recvKey,
				active.keys.transcriptHash,
				envelope.index,
				envelope.ciphertext,
				active.aad,
			);
			const decoded = decodeJson(plaintext);
			if (!isPayload(decoded)) {
				debugLog(isDebug, "Invalid payload received.");
				return null;
			}
			active.recvIndex += 1;
			return decoded;
		} catch (err) {
			debugLog(isDebug, "Failed to decrypt payload.", {
				error: err instanceof Error ? err.message : String(err),
			});
			return null;
		}
	}

	function flushPending() {
		if (!session) {
			return;
		}
		while (pending.length > 0) {
			const value = pending.shift();
			if (value) {
				sendEncrypted(session, { kind: "input", data: value });
			}
		}
	}

	function handlePayload(payload: Payload) {
		switch (payload.kind) {
			case "ready":
				consola.success("Session ready.");
				break;
			case "output":
				if (payload.stream === "stderr") {
					process.stderr.write(payload.data);
				} else {
					process.stdout.write(payload.data);
				}
				break;
			case "complete":
				consola.info("Remote command complete.");
				break;
			case "error":
				consola.error(payload.message);
				break;
			case "exit":
				consola.info("Remote session ended.");
				process.exit(0);
				break;
			default:
				break;
		}
	}
}

async function main() {
	const { mode, args } = parseArgs(process.argv.slice(2));
	const host = args.get("host") ?? DEFAULT_HOST;
	const port = Number(args.get("port") ?? DEFAULT_PORT);
	const debug = args.get("debug") === "true";

	if (!mode) {
		consola.info(
			"Usage: bun index.ts <server|client> [--host 127.0.0.1] [--port 46321] [--debug]",
		);
		process.exit(1);
	}

	if (!Number.isFinite(port)) {
		consola.error("Port must be a number.");
		process.exit(1);
	}

	if (mode === "server") {
		await runServer(host, port, debug);
		return;
	}

	await runClient(host, port, debug);
}

main().catch((err) => {
	consola.error(err instanceof Error ? err.message : String(err));
	process.exit(1);
});
