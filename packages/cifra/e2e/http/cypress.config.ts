import { spawn } from "node:child_process";
import net from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { defineConfig } from "cypress";

function resolveBunPath(): string {
	if (process.env.BUN_PATH) {
		return process.env.BUN_PATH;
	}
	if (process.env.BUN) {
		return process.env.BUN;
	}
	if (process.env.USERPROFILE) {
		return path.join(process.env.USERPROFILE, ".bun", "bin", "bun");
	}
	return "bun";
}

async function waitForPort(port: number, timeoutMs: number): Promise<void> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		try {
			await new Promise<void>((resolve, reject) => {
				const socket = net.connect({ port, host: "127.0.0.1" }, () => {
					socket.end();
					resolve();
				});
				socket.on("error", reject);
			});
			return;
		} catch {
			await delay(100);
		}
	}
	throw new Error("server_start_timeout");
}

const root = path.dirname(fileURLToPath(import.meta.url));
const serverEntry = path.join(root, "server.ts");
const port = Number(process.env.CIFRA_E2E_PORT ?? 4173);

let serverProcess: ReturnType<typeof spawn> | null = null;

export default defineConfig({
	e2e: {
		baseUrl: `http://127.0.0.1:${port}`,
		specPattern: "cypress/e2e/**/*.cy.ts",
		supportFile: false,
		setupNodeEvents(on) {
			on("before:run", async () => {
				const bunPath = resolveBunPath();
				serverProcess = spawn(bunPath, [serverEntry], {
					cwd: root,
					stdio: "inherit",
					env: { ...process.env, PORT: String(port) },
				});
				await waitForPort(port, 10_000);
			});

			on("after:run", () => {
				if (serverProcess) {
					serverProcess.kill();
					serverProcess = null;
				}
			});
		},
	},
});
