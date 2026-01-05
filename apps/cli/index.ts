import { consola } from "consola";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import readline from "node:readline";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 46321;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

type HelloMessage = {
	type: "hello";
	sessionId: string;
	clientName?: string;
};

type ReadyMessage = {
	type: "ready";
	sessionId: string;
};

type InputMessage = {
	type: "input";
	data: string;
};

type OutputMessage = {
	type: "output";
	stream: "stdout" | "stderr";
	data: string;
};

type ExitMessage = {
	type: "exit";
	code?: number | null;
	signal?: string | null;
	reason?: string;
};

type ErrorMessage = {
	type: "error";
	message: string;
};

type Message = HelloMessage | ReadyMessage | InputMessage | OutputMessage | ExitMessage | ErrorMessage;

type RemotePeer = {
	address: string;
	port: number;
	sessionId: string;
};

function encodeMessage(message: Message): Uint8Array {
	return TEXT_ENCODER.encode(JSON.stringify(message));
}

function decodeMessage(data: Uint8Array): Message | null {
	try {
		return JSON.parse(TEXT_DECODER.decode(data)) as Message;
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
			const value = argv[i + 1] ?? "";
			args.set(key, value);
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

function describePeer(peer: RemotePeer) {
	return `${peer.address}:${peer.port}`;
}

async function runServer(host: string, port: number): Promise<void> {
	let peer: RemotePeer | null = null;
	let child: ReturnType<typeof spawn> | null = null;

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
					if (peer && (peer.address !== remoteAddress || peer.port !== remotePort)) {
						consola.warn(`Rejecting ${remoteAddress}:${remotePort}, session already active.`);
						return;
					}
					peer = { address: remoteAddress, port: remotePort, sessionId: message.sessionId };
					consola.info(`Client connected from ${describePeer(peer)}.`);
					startSession();
					send({ type: "ready", sessionId: message.sessionId });
					return;
				}

				if (!peer || remoteAddress !== peer.address || remotePort !== peer.port) {
					return;
				}

				if (message.type === "input") {
					if (child?.stdin) {
						child.stdin.write(message.data);
					}
					return;
				}

				if (message.type === "exit") {
					consola.info(`Client requested exit: ${message.reason ?? "session_end"}`);
					stopSession();
				}
			},
		},
	});

	function send(message: Message) {
		if (!peer) {
			return;
		}
		socket.send(encodeMessage(message), peer.port, peer.address);
	}

	function startSession() {
		if (child) {
			return;
		}
		const bunx = resolveBunx();
		const args = ["@openai/codex@latest", "--sandbox", "danger-full-access"];
		consola.start(`Launching ${bunx} ${args.join(" ")}`);
		child = spawn(bunx, args, {
			stdio: "pipe",
			shell: process.platform === "win32",
			env: { ...process.env },
		});

		child.stdout?.on("data", (chunk: Buffer) => {
			send({ type: "output", stream: "stdout", data: chunk.toString("utf8") });
		});
		child.stderr?.on("data", (chunk: Buffer) => {
			send({ type: "output", stream: "stderr", data: chunk.toString("utf8") });
		});
		child.on("exit", (code, signal) => {
			send({ type: "exit", code, signal });
			child = null;
		});
		child.on("error", (err) => {
			send({ type: "error", message: err.message });
		});
	}

	function stopSession() {
		if (!child) {
			return;
		}
		child.kill();
		child = null;
	}

	consola.ready(`UDP server listening on ${host}:${socket.port}.`);
	process.on("SIGINT", () => {
		consola.info("Shutting down server.");
		stopSession();
		socket.close();
		process.exit(0);
	});
}

async function runClient(host: string, port: number): Promise<void> {
	const sessionId = randomUUID();
	const socket = await Bun.udpSocket({
		port: 0,
		hostname: DEFAULT_HOST,
		socket: {
			data(_socket, data) {
				const message = decodeMessage(data);
				if (!message) {
					return;
				}
				switch (message.type) {
					case "ready":
						consola.success(`Session ready (${message.sessionId}).`);
						break;
					case "output":
						if (message.stream === "stderr") {
							process.stderr.write(message.data);
						} else {
							process.stdout.write(message.data);
						}
						break;
					case "error":
						consola.error(message.message);
						break;
					case "exit":
						consola.info("Remote session ended.");
						process.exit(0);
				}
			},
		},
	});

	const hello: HelloMessage = { type: "hello", sessionId, clientName: "remote-cli" };
	socket.send(encodeMessage(hello), port, host);

	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
		terminal: true,
	});

	rl.on("line", (line) => {
		socket.send(encodeMessage({ type: "input", data: `${line}\n` }), port, host);
	});

	process.on("SIGINT", () => {
		consola.info("Closing session.");
		socket.send(encodeMessage({ type: "exit", reason: "client_exit" }), port, host);
		socket.close();
		rl.close();
		process.exit(0);
	});

	consola.ready(`Connected to ${host}:${port}. Type commands to send.`);
}

async function main() {
	const { mode, args } = parseArgs(process.argv.slice(2));
	const host = args.get("host") ?? DEFAULT_HOST;
	const port = Number(args.get("port") ?? DEFAULT_PORT);

	if (!mode) {
		consola.info("Usage: bun index.ts <server|client> [--host 127.0.0.1] [--port 46321]");
		process.exit(1);
	}

	if (!Number.isFinite(port)) {
		consola.error("Port must be a number.");
		process.exit(1);
	}

	if (mode === "server") {
		await runServer(host, port);
		return;
	}

	await runClient(host, port);
}

main().catch((err) => {
	consola.error(err instanceof Error ? err.message : String(err));
	process.exit(1);
});
