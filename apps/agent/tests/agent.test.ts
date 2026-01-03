import { describe, expect, test } from "bun:test";
import {
	PiCache,
	base64ToString,
	parseCommandBody,
	readMetadataValue,
	type QueueMessage,
} from "../core";
import { computePiFractionDigits, computePiHashFromDigits } from "@queue/core";

function makeMessage(overrides: Partial<QueueMessage>): QueueMessage {
	return {
		id: "msg-1",
		timestamp_ms: 123,
		attempts: 1,
		body: "",
		lease_id: "lease-1",
		...overrides,
	};
}

describe("agent core parsing", () => {
	test("base64ToString decodes JSON payload", () => {
		const payload = { command: "hello" };
		const encoded = Buffer.from(JSON.stringify(payload)).toString("base64");
		expect(base64ToString(encoded)).toBe(JSON.stringify(payload));
	});

	test("readMetadataValue matches case-insensitive keys", () => {
		const value = readMetadataValue({ "cf-content-type": "text" }, "CF-Content-Type");
		expect(value).toBe("text");
	});

	test("parseCommandBody handles json content", () => {
		const payload = { command: "ls", meta: { answer: 42 } };
		const body = Buffer.from(JSON.stringify(payload)).toString("base64");
		const message = makeMessage({
			body,
			metadata: { "CF-Content-Type": "json" },
		});
		const result = parseCommandBody(message);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.command).toBe("ls");
			expect(result.value.meta?.answer).toBe(42);
		}
	});

	test("parseCommandBody handles text content", () => {
		const message = makeMessage({
			body: "echo hello",
			metadata: { "CF-Content-Type": "text" },
		});
		const result = parseCommandBody(message);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.command).toBe("echo hello");
		}
	});

	test("parseCommandBody rejects unsupported content type", () => {
		const message = makeMessage({
			body: "ignored",
			metadata: { "CF-Content-Type": "bytes" },
		});
		const result = parseCommandBody(message);
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error).toBe("unsupported_content_type:bytes");
		}
	});
});

describe("PiCache", () => {
	test("hash matches computed digits", async () => {
		const cache = new PiCache();
		const index = 4;
		const digits = computePiFractionDigits(index + 2);
		const expected = await computePiHashFromDigits(index, digits);
		await expect(cache.hash(index)).resolves.toBe(expected);
	});
});
