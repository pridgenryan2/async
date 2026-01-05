import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const publicDir = join(root, "public");
const entry = join(root, "app.ts");
const port = Number(process.env.PORT ?? 4173);

await mkdir(publicDir, { recursive: true });

const buildResult = await Bun.build({
	entrypoints: [entry],
	outdir: publicDir,
	target: "browser",
	minify: false,
	sourcemap: "inline",
});

if (!buildResult.success) {
	for (const log of buildResult.logs) {
		console.error(log.message);
	}
	process.exit(1);
}

const server = Bun.serve({
	port,
	fetch(request) {
		const url = new URL(request.url);
		const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
		const filePath = join(publicDir, pathname.slice(1));
		if (!existsSync(filePath)) {
			return new Response("Not found", { status: 404 });
		}
		const ext = extname(filePath).toLowerCase();
		const headers = new Headers();
		if (ext === ".html") {
			headers.set("content-type", "text/html; charset=utf-8");
		} else if (ext === ".js") {
			headers.set("content-type", "text/javascript; charset=utf-8");
		}
		return new Response(Bun.file(filePath), { headers });
	},
});

console.log(`cifra http e2e server running at http://127.0.0.1:${server.port}`);

process.on("SIGINT", () => {
	server.stop();
	process.exit(0);
});
