import { computePiFractionDigits, computePiHashFromDigits } from "@queue/core";

export type CommandMessage = {
	sessionEpoch?: string;
	requestId?: string;
	command: string;
	createdAt?: number;
	piIndex?: number;
	piHash?: string;
	meta?: Record<string, unknown>;
};

export type QueueMessage = {
	id: string;
	timestamp_ms: number;
	attempts: number;
	body: string;
	metadata?: Record<string, string>;
	lease_id: string;
};

const MAX_PI_INDEX = 10_000;

export function base64ToString(value: string): string {
	if (typeof Buffer !== "undefined") {
		return Buffer.from(value, "base64").toString("utf8");
	}
	const binary = atob(value);
	let result = "";
	for (let i = 0; i < binary.length; i += 1) {
		result += String.fromCharCode(binary.charCodeAt(i));
	}
	return result;
}

export function readMetadataValue(
	metadata: Record<string, string> | undefined,
	key: string,
): string | undefined {
	if (!metadata) {
		return undefined;
	}
	if (metadata[key]) {
		return metadata[key];
	}
	const lowerKey = key.toLowerCase();
	for (const [entryKey, entryValue] of Object.entries(metadata)) {
		if (entryKey.toLowerCase() === lowerKey) {
			return entryValue;
		}
	}
	return undefined;
}

export function parseCommandBody(
	message: QueueMessage,
): { ok: true; value: CommandMessage } | { ok: false; error: string } {
	const contentType = readMetadataValue(message.metadata, "CF-Content-Type") ?? "json";
	let raw: unknown;
	if (contentType === "json") {
		try {
			raw = JSON.parse(base64ToString(message.body));
		} catch {
			return { ok: false, error: "invalid_json" };
		}
	} else if (contentType === "text") {
		raw = { command: message.body };
	} else {
		return { ok: false, error: `unsupported_content_type:${contentType}` };
	}
	if (!raw || typeof raw !== "object") {
		return { ok: false, error: "invalid_payload" };
	}
	const record = raw as Record<string, unknown>;
	if (typeof record.command !== "string" || record.command.trim().length === 0) {
		return { ok: false, error: "command_required" };
	}
	const meta =
		record.meta && typeof record.meta === "object" && !Array.isArray(record.meta)
			? (record.meta as Record<string, unknown>)
			: undefined;
	return {
		ok: true,
		value: {
			sessionEpoch: typeof record.sessionEpoch === "string" ? record.sessionEpoch : undefined,
			requestId: typeof record.requestId === "string" ? record.requestId : undefined,
			command: record.command.trim(),
			createdAt: typeof record.createdAt === "number" ? record.createdAt : undefined,
			piIndex: typeof record.piIndex === "number" ? record.piIndex : undefined,
			piHash: typeof record.piHash === "string" ? record.piHash : undefined,
			meta,
		},
	};
}

export class PiCache {
	private digits = "";

	async hash(index: number): Promise<string> {
		if (!Number.isInteger(index) || index < 0) {
			throw new Error("pi_index_invalid");
		}
		if (index > MAX_PI_INDEX) {
			throw new Error("pi_index_limit");
		}
		if (this.digits.length < index + 2) {
			this.digits = computePiFractionDigits(index + 2);
		}
		return computePiHashFromDigits(index, this.digits);
	}
}
