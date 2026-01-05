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
	verifyHello,
	verifyReply,
	type Hello,
	type Reply,
	type SecureEnvelope,
	type SessionKeys,
} from "../../src/session";

type Message =
	| { type: "hello"; hello: Hello }
	| { type: "reply"; reply: Reply }
	| { type: "open"; sessionId: string; envelope: SecureEnvelope }
	| { type: "opened"; envelope: SecureEnvelope };

type Queue<T> = {
	push: (value: T) => void;
	next: (timeoutMs: number) => Promise<T>;
};

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

function encodeMessage(message: Message): Uint8Array {
	return TEXT_ENCODER.encode(JSON.stringify(message));
}

function decodeMessage(data: Uint8Array): Message {
	return JSON.parse(TEXT_DECODER.decode(data)) as Message;
}

function createQueue<T>(): Queue<T> {
	const values: T[] = [];
	const waiters: Array<(value: T) => void> = [];

	return {
		push(value: T) {
			const waiter = waiters.shift();
			if (waiter) {
				waiter(value);
				return;
			}
			values.push(value);
		},
		async next(timeoutMs: number) {
			if (values.length > 0) {
				return values.shift() as T;
			}
			return await new Promise<T>((resolve, reject) => {
				const timer = setTimeout(() => {
					reject(new Error("udp_timeout"));
				}, timeoutMs);
				waiters.push((value) => {
					clearTimeout(timer);
					resolve(value);
				});
			});
		},
	};
}

test("udp channel handshake and encrypted payload", async () => {
	const sessionId = `udp-${crypto.randomUUID()}`;
	const initiatorSign = createSigningKeyPair();
	const initiatorDh = createDhKeyPair();

	let responderKeys: SessionKeys | null = null;
	let responderSessionId: string | null = null;

	const server = await Bun.udpSocket({
		port: 0,
		hostname: "127.0.0.1",
		socket: {
			data(socket, data, port, address) {
				let message: Message;
				try {
					message = decodeMessage(data);
				} catch {
					return;
				}

				if (message.type === "hello") {
					const helloCheck = verifyHello(message.hello);
					if (!helloCheck.ok) {
						return;
					}
					const responderSign = createSigningKeyPair();
					const responderDh = createDhKeyPair();
					const reply = createReply(message.hello, responderSign, responderDh);
					const sharedSecret = deriveSharedSecret(responderDh.privateKey, helloCheck.dhPub);
					const transcriptHash = computeTranscriptHash(message.hello, reply);
					responderKeys = deriveSessionKeys(sharedSecret, transcriptHash, "responder");
					responderSessionId = message.hello.sessionId;
					socket.send(encodeMessage({ type: "reply", reply }), port, address);
					return;
				}

				if (message.type === "open" && responderKeys && responderSessionId) {
					if (message.sessionId !== responderSessionId) {
						return;
					}
					const aad = buildSessionAad(message.sessionId);
					let decrypted: unknown;
					try {
						const plaintext = decryptPayload(
							responderKeys.recvKey,
							responderKeys.transcriptHash,
							message.envelope.index,
							message.envelope.ciphertext,
							aad,
						);
						decrypted = decodeJson(plaintext);
					} catch {
						return;
					}

					const responseEnvelope = encryptPayload(
						responderKeys.sendKey,
						responderKeys.transcriptHash,
						message.envelope.index + 1,
						encodeJson({ ok: true, received: decrypted }),
						aad,
					);
					socket.send(encodeMessage({ type: "opened", envelope: responseEnvelope }), port, address);
				}
			},
		},
	});

	const clientQueue = createQueue<Message>();
	const client = await Bun.udpSocket({
		port: 0,
		hostname: "127.0.0.1",
		socket: {
			data(_socket, data) {
				try {
					clientQueue.push(decodeMessage(data));
				} catch {
					return;
				}
			},
		},
	});

	try {
		const hello = createHello(sessionId, initiatorSign, initiatorDh);
		client.send(encodeMessage({ type: "hello", hello }), server.port, "127.0.0.1");

		const replyMessage = await clientQueue.next(2_000);
		expect(replyMessage.type).toBe("reply");
		if (replyMessage.type !== "reply") {
			throw new Error("reply_missing");
		}

		const reply = replyMessage.reply;
		const replyCheck = verifyReply(hello, reply);
		expect(replyCheck.ok).toBe(true);

		const sharedSecret = deriveSharedSecret(initiatorDh.privateKey, replyCheck.dhPub);
		const transcriptHash = computeTranscriptHash(hello, reply);
		const keys = deriveSessionKeys(sharedSecret, transcriptHash, "initiator");
		const aad = buildSessionAad(sessionId);

		const envelope = encryptPayload(
			keys.sendKey,
			keys.transcriptHash,
			0,
			encodeJson({ ping: "pong" }),
			aad,
		);
		client.send(
			encodeMessage({ type: "open", sessionId, envelope }),
			server.port,
			"127.0.0.1",
		);

		const openedMessage = await clientQueue.next(2_000);
		expect(openedMessage.type).toBe("opened");
		if (openedMessage.type !== "opened") {
			throw new Error("opened_missing");
		}

		const responseEnvelope = openedMessage.envelope;
		const responsePlaintext = decryptPayload(
			keys.recvKey,
			keys.transcriptHash,
			responseEnvelope.index,
			responseEnvelope.ciphertext,
			aad,
		);
		expect(decodeJson(responsePlaintext)).toEqual({ ok: true, received: { ping: "pong" } });
	} finally {
		client.close();
		server.close();
	}
});
