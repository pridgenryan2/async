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
	type SessionKeys,
} from "../../src/session";

type LogTarget = "initiator" | "responder";

const initiatorLog = document.getElementById("initiator-log") as HTMLUListElement | null;
const responderLog = document.getElementById("responder-log") as HTMLUListElement | null;
const statusEl = document.getElementById("exchange-status");

function appendLog(target: LogTarget, label: string, detail: string): void {
	const list = target === "initiator" ? initiatorLog : responderLog;
	if (!list) {
		return;
	}
	const item = document.createElement("li");
	item.textContent = `${label}: ${detail}`;
	item.dataset.event = label.toLowerCase().replace(/\s+/g, "-");
	list.appendChild(item);
}

function setStatus(state: string, detail: string): void {
	if (!statusEl) {
		return;
	}
	const label = statusEl.querySelector("span");
	const body = statusEl.querySelector("div");
	if (label) {
		label.textContent = state;
	}
	if (body) {
		body.textContent = detail;
	}
}

function exchange(): void {
	setStatus("Running", "Exchanging hello/reply and encrypted payload.");

	const sessionId = `http-${crypto.randomUUID()}`;
	const initiatorSign = createSigningKeyPair();
	const initiatorDh = createDhKeyPair();
	const responderSign = createSigningKeyPair();
	const responderDh = createDhKeyPair();

	const hello = createHello(sessionId, initiatorSign, initiatorDh);
	const helloCheck = verifyHello(hello);
	appendLog("initiator", "Hello", `Signed hello for ${sessionId.slice(0, 8)}.`);

	if (!helloCheck.ok) {
		setStatus("Error", "Initiator hello signature failed.");
		appendLog("initiator", "Error", "Hello signature rejected.");
		return;
	}

	const reply = createReply(hello, responderSign, responderDh);
	const replyCheck = verifyReply(hello, reply);
	appendLog("responder", "Reply", "Reply signed and ready.");

	if (!replyCheck.ok) {
		setStatus("Error", "Responder reply signature failed.");
		appendLog("responder", "Error", "Reply signature rejected.");
		return;
	}

	const transcriptHash = computeTranscriptHash(hello, reply);
	const initiatorShared = deriveSharedSecret(initiatorDh.privateKey, replyCheck.dhPub);
	const responderShared = deriveSharedSecret(responderDh.privateKey, helloCheck.dhPub);
	const initiatorKeys = deriveSessionKeys(initiatorShared, transcriptHash, "initiator");
	const responderKeys = deriveSessionKeys(responderShared, transcriptHash, "responder");

	appendLog("initiator", "Keys", "Initiator send/recv keys derived.");
	appendLog("responder", "Keys", "Responder send/recv keys derived.");

	const aad = buildSessionAad(sessionId);
	const payload = encodeJson({ ping: "pong", timestamp: Date.now() });
	const envelope = encryptPayload(
		initiatorKeys.sendKey,
		initiatorKeys.transcriptHash,
		0,
		payload,
		aad,
	);
	appendLog("initiator", "Encrypt", "Encrypted open payload." );

	const received = decryptIncoming(responderKeys, envelope, aad);
	if (!received) {
		return;
	}
	appendLog("responder", "Decrypt", "Decrypted open payload." );

	const responseEnvelope = encryptPayload(
		responderKeys.sendKey,
		responderKeys.transcriptHash,
		1,
		encodeJson({ ok: true, received }),
		aad,
	);
	appendLog("responder", "Encrypt", "Encrypted response payload." );

	const response = decryptPayload(
		initiatorKeys.recvKey,
		initiatorKeys.transcriptHash,
		responseEnvelope.index,
		responseEnvelope.ciphertext,
		aad,
	);

	const decoded = decodeJson(response) as { ok: boolean; received: unknown } | null;
	appendLog("initiator", "Opened", decoded?.ok ? "Responder accepted." : "Responder rejected.");

	setStatus("Complete", "Handshake verified and encrypted payload round-trip completed.");
}

function decryptIncoming(keys: SessionKeys, envelope: { index: number; ciphertext: string }, aad: Uint8Array) {
	try {
		const plaintext = decryptPayload(
			keys.recvKey,
			keys.transcriptHash,
			envelope.index,
			envelope.ciphertext,
			aad,
		);
		return decodeJson(plaintext);
	} catch {
		setStatus("Error", "Responder failed to decrypt payload.");
		appendLog("responder", "Error", "Decrypt failed.");
		return null;
	}
}

exchange();
