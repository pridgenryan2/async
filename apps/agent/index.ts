/* eslint-disable no-console */

import { PiCache, parseCommandBody, type QueueMessage } from "./core";

declare const Bun: {
	spawn: (options: {
		cmd: string[];
		stdin?: "pipe" | "ignore";
		stdout?: "pipe" | "ignore";
		stderr?: "pipe" | "ignore";
		cwd?: string;
	}) => {
		stdin?: { write: (data: string) => void; end: () => void };
		stdout: ReadableStream<Uint8Array>;
		stderr: ReadableStream<Uint8Array>;
		exited: Promise<number>;
		kill: () => void;
	};
};

type PullResponse = {
	success: boolean;
	errors?: unknown[];
	result?: {
		message_backlog_count?: number;
		messages?: QueueMessage[];
	};
};

type AckResponse = {
	success: boolean;
	errors?: unknown[];
	result?: unknown;
};

type SessionStatus = {
	active: boolean;
	nextPiIndex?: number;
	nextPiHash?: string | null;
};

type Config = {
	accountId: string;
	queueId: string;
	apiToken: string;
	apiBase: string;
	workerBase: string;
	batchSize: number;
	visibilityTimeoutMs: number;
	pollIntervalMs: number;
	maxResponseRetries: number;
	maxOutputChars: number;
	codexMode: "echo" | "exec";
	codexBin: string;
	codexArgs: string[];
	codexCwd?: string;
	codexTimeoutMs: number;
};

type FetchResult<T> = { ok: boolean; status: number; data: T | null };

type CodexResult = {
	ok: boolean;
	output: string;
	error?: string;
	durationMs: number;
};

const DEFAULT_API_BASE = "https://api.cloudflare.com/client/v4";
const DEFAULT_WORKER_BASE = "http://localhost:8787";
const DEFAULT_BATCH_SIZE = 1;
const DEFAULT_VISIBILITY_TIMEOUT_MS = 30_000;
const DEFAULT_POLL_INTERVAL_MS = 1_500;
const DEFAULT_MAX_RESPONSE_RETRIES = 3;
const DEFAULT_MAX_OUTPUT_CHARS = 12_000;
const DEFAULT_CODEX_TIMEOUT_MS = 120_000;

function log(message: string, data?: Record<string, unknown>): void {
	const stamp = new Date().toISOString();
	const suffix = data ? ` ${JSON.stringify(data)}` : "";
	console.log(`[codex-server] ${stamp} ${message}${suffix}`);
}

function readEnv(name: string, fallback?: string): string | undefined {
	const value = process.env[name];
	if (value && value.trim().length > 0) {
		return value.trim();
	}
	return fallback;
}

function readNumberEnv(name: string, fallback: number): number {
	const value = readEnv(name);
	if (!value) {
		return fallback;
	}
	const parsed = Number(value);
	if (!Number.isFinite(parsed)) {
		return fallback;
	}
	return parsed;
}

function requiredEnv(names: string[]): string {
	for (const name of names) {
		const value = readEnv(name);
		if (value) {
			return value;
		}
	}
	throw new Error(`Missing required env var: ${names.join(" or ")}`);
}

function parseArgs(value: string | undefined): string[] {
	if (!value) {
		return [];
	}
	const trimmed = value.trim();
	if (!trimmed) {
		return [];
	}
	try {
		const parsed = JSON.parse(trimmed);
		if (Array.isArray(parsed) && parsed.every((item) => typeof item === "string")) {
			return parsed;
		}
	} catch {
		// Fall back to whitespace split.
	}
	return trimmed.split(/\s+/);
}

function loadConfig(): Config {
	const accountId = requiredEnv(["CF_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID"]);
	const queueId = requiredEnv([
		"CF_COMMANDS_QUEUE_ID",
		"CF_QUEUE_ID",
		"COMMANDS_QUEUE_ID",
	]);
	const apiToken = requiredEnv(["CF_API_TOKEN", "CLOUDFLARE_API_TOKEN"]);
	const apiBase = readEnv("CF_API_BASE", DEFAULT_API_BASE) ?? DEFAULT_API_BASE;
	const workerBase = readEnv("PI_QUEUE_API_URL", DEFAULT_WORKER_BASE) ?? DEFAULT_WORKER_BASE;
	const batchSize = readNumberEnv("PULL_BATCH_SIZE", DEFAULT_BATCH_SIZE);
	const visibilityTimeoutMs = readNumberEnv(
		"PULL_VISIBILITY_TIMEOUT_MS",
		DEFAULT_VISIBILITY_TIMEOUT_MS,
	);
	const pollIntervalMs = readNumberEnv("POLL_INTERVAL_MS", DEFAULT_POLL_INTERVAL_MS);
	const maxResponseRetries = readNumberEnv("MAX_RESPONSE_RETRIES", DEFAULT_MAX_RESPONSE_RETRIES);
	const maxOutputChars = readNumberEnv("MAX_OUTPUT_CHARS", DEFAULT_MAX_OUTPUT_CHARS);
	const codexModeRaw = readEnv("CODEX_MODE", "echo") ?? "echo";
	const codexMode = codexModeRaw === "exec" ? "exec" : "echo";
	const codexBin = readEnv("CODEX_BIN", "codex") ?? "codex";
	const codexArgs = parseArgs(readEnv("CODEX_ARGS_JSON") ?? readEnv("CODEX_ARGS"));
	const codexCwd = readEnv("CODEX_WORKDIR");
	const codexTimeoutMs = readNumberEnv("CODEX_TIMEOUT_MS", DEFAULT_CODEX_TIMEOUT_MS);
	return {
		accountId,
		queueId,
		apiToken,
		apiBase,
		workerBase,
		batchSize: Math.max(1, Math.min(batchSize, 100)),
		visibilityTimeoutMs: Math.max(1000, visibilityTimeoutMs),
		pollIntervalMs: Math.max(250, pollIntervalMs),
		maxResponseRetries: Math.max(0, maxResponseRetries),
		maxOutputChars: Math.max(0, maxOutputChars),
		codexMode,
		codexBin,
		codexArgs,
		codexCwd,
		codexTimeoutMs: Math.max(1000, codexTimeoutMs),
	};
}

function queueUrl(config: Config, action: "pull" | "ack"): string {
	const base = config.apiBase.replace(/\/$/, "");
	return `${base}/accounts/${config.accountId}/queues/${config.queueId}/messages/${action}`;
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<FetchResult<T>> {
	const response = await fetch(url, {
		...init,
		headers: {
			...(init?.headers ?? {}),
			"content-type": "application/json",
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

async function pullMessages(config: Config): Promise<QueueMessage[]> {
	const { ok, data, status } = await fetchJson<PullResponse>(queueUrl(config, "pull"), {
		method: "POST",
		headers: {
			authorization: `Bearer ${config.apiToken}`,
		},
		body: JSON.stringify({
			visibility_timeout_ms: config.visibilityTimeoutMs,
			batch_size: config.batchSize,
		}),
	});
	if (!ok || !data?.success) {
		log("Pull failed", { status, errors: data?.errors ?? [] });
		return [];
	}
	const messages = data.result?.messages ?? [];
	if (messages.length > 0) {
		log("Pulled messages", { count: messages.length, backlog: data.result?.message_backlog_count });
	}
	return messages;
}

async function ackMessages(
	config: Config,
	acks: Array<{ lease_id: string }>,
	retries: Array<{ lease_id: string; delay_seconds?: number }>,
): Promise<void> {
	if (acks.length === 0 && retries.length === 0) {
		return;
	}
	const { ok, data, status } = await fetchJson<AckResponse>(queueUrl(config, "ack"), {
		method: "POST",
		headers: {
			authorization: `Bearer ${config.apiToken}`,
		},
		body: JSON.stringify({ acks, retries }),
	});
	if (!ok || !data?.success) {
		log("Ack failed", { status, errors: data?.errors ?? [] });
		return;
	}
	log("Acked messages", { acks: acks.length, retries: retries.length });
}

async function fetchSessionStatus(config: Config): Promise<FetchResult<SessionStatus>> {
	const base = config.workerBase.replace(/\/$/, "");
	return fetchJson<SessionStatus>(`${base}/session`, { method: "GET" });
}

async function postEvent(
	config: Config,
	payload: Record<string, unknown>,
	piHash: string,
): Promise<FetchResult<Record<string, unknown>>> {
	const base = config.workerBase.replace(/\/$/, "");
	return fetchJson<Record<string, unknown>>(`${base}/events`, {
		method: "POST",
		body: JSON.stringify({ event: payload, piHash }),
	});
}

function truncateText(value: string, maxChars: number): string {
	if (maxChars <= 0 || value.length <= maxChars) {
		return value;
	}
	return `${value.slice(0, maxChars)}...`;
}

async function runCodex(command: string, config: Config): Promise<CodexResult> {
	const start = Date.now();
	if (config.codexMode === "echo") {
		return { ok: true, output: command, durationMs: Date.now() - start };
	}
	if (!Bun || typeof Bun.spawn !== "function") {
		throw new Error("bun_required_for_exec");
	}
	const hasInlineCommand = config.codexArgs.some((arg) => arg.includes("{command}"));
	const args = config.codexArgs.map((arg) =>
		arg.includes("{command}") ? arg.replaceAll("{command}", command) : arg,
	);
	const useStdin = !hasInlineCommand;
	const proc = Bun.spawn({
		cmd: [config.codexBin, ...args],
		stdin: "pipe",
		stdout: "pipe",
		stderr: "pipe",
		cwd: config.codexCwd,
	});
	if (useStdin && proc.stdin) {
		proc.stdin.write(`${command}\n`);
		proc.stdin.end();
	}
	let timedOut = false;
	const timeout = setTimeout(() => {
		timedOut = true;
		proc.kill();
	}, config.codexTimeoutMs);
	const [stdout, stderr, exitCode] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	clearTimeout(timeout);
	const durationMs = Date.now() - start;
	if (timedOut) {
		return { ok: false, output: "", error: "codex_timeout", durationMs };
	}
	const cleanedStdout = truncateText(stdout.trim(), config.maxOutputChars);
	const cleanedStderr = truncateText(stderr.trim(), config.maxOutputChars);
	const ok = exitCode === 0;
	return {
		ok,
		output: cleanedStdout,
		error: ok ? cleanedStderr || undefined : cleanedStderr || "codex_failed",
		durationMs,
	};
}

async function sendResponse(
	config: Config,
	piCache: PiCache,
	payload: Record<string, unknown>,
): Promise<{ ok: boolean; status?: number; error?: string }> {
	let nextIndex: number | null = null;
	let nextHash: string | null = null;
	let attempts = 0;

	while (attempts <= config.maxResponseRetries) {
		if (nextIndex === null) {
			const status = await fetchSessionStatus(config);
			if (!status.ok || !status.data) {
				return { ok: false, status: status.status, error: "session_status_failed" };
			}
			if (!status.data.active) {
				return { ok: false, status: status.status, error: "session_inactive" };
			}
			if (typeof status.data.nextPiIndex !== "number") {
				return { ok: false, status: status.status, error: "pi_index_missing" };
			}
			nextIndex = status.data.nextPiIndex;
			if (typeof status.data.nextPiHash === "string") {
				nextHash = status.data.nextPiHash;
			} else {
				try {
					nextHash = await piCache.hash(nextIndex);
				} catch {
					return { ok: false, status: status.status, error: "pi_hash_failed" };
				}
			}
		}

		const result = await postEvent(config, payload, nextHash);
		if (result.ok) {
			return { ok: true, status: result.status };
		}
		if (result.status === 409 && typeof result.data?.expectedPiIndex === "number") {
			attempts += 1;
			nextIndex = result.data.expectedPiIndex;
			try {
				nextHash = await piCache.hash(nextIndex);
			} catch {
				return { ok: false, status: result.status, error: "pi_hash_failed" };
			}
			continue;
		}
		if (result.status === 410) {
			return { ok: false, status: result.status, error: "session_expired" };
		}
		return {
			ok: false,
			status: result.status,
			error: typeof result.data?.error === "string" ? result.data.error : "event_failed",
		};
	}
	return { ok: false, error: "pi_retry_exhausted" };
}

async function processMessage(
	config: Config,
	piCache: PiCache,
	message: QueueMessage,
): Promise<{ action: "ack" | "retry" }> {
	const parsed = parseCommandBody(message);
	if (!parsed.ok) {
		log("Invalid command payload", { id: message.id, error: parsed.error });
		return { action: "ack" };
	}
	const command = parsed.value;
	const startedAt = Date.now();
	let result: CodexResult;
	try {
		result = await runCodex(command.command, config);
	} catch (err) {
		result = {
			ok: false,
			output: "",
			error: (err as Error).message ?? "codex_error",
			durationMs: Date.now() - startedAt,
		};
	}
	const payload: Record<string, unknown> = {
		type: "codex_result",
		requestId: command.requestId ?? message.id,
		command: command.command,
		ok: result.ok,
		output: result.output,
		error: result.error,
		durationMs: result.durationMs,
		receivedAt: message.timestamp_ms,
		completedAt: Date.now(),
	};
	if (command.meta) {
		payload.meta = command.meta;
	}
	const response = await sendResponse(config, piCache, payload);
	if (!response.ok) {
		log("Failed to post response", { id: message.id, error: response.error, status: response.status });
		if (response.error === "session_inactive" || response.error === "session_expired") {
			return { action: "ack" };
		}
		return { action: "retry" };
	}
	return { action: "ack" };
}

async function run(): Promise<void> {
	const config = loadConfig();
	const piCache = new PiCache();
	log("Starting codex server", {
		queue: config.queueId,
		worker: config.workerBase,
		mode: config.codexMode,
	});
	let running = true;
	const stop = () => {
		running = false;
	};
	process.on("SIGINT", stop);
	process.on("SIGTERM", stop);

	while (running) {
		const messages = await pullMessages(config);
		if (messages.length === 0) {
			await new Promise((resolve) => setTimeout(resolve, config.pollIntervalMs));
			continue;
		}
		for (const message of messages) {
			if (!running) {
				break;
			}
			const outcome = await processMessage(config, piCache, message);
			if (outcome.action === "ack") {
				await ackMessages(config, [{ lease_id: message.lease_id }], []);
			} else {
				await ackMessages(
					config,
					[],
					[{ lease_id: message.lease_id, delay_seconds: 1 }],
				);
			}
		}
	}
	log("Shutting down.");
}

run().catch((err) => {
	log("Fatal error", { error: (err as Error).message ?? "unknown" });
	process.exit(1);
});
