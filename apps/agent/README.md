# Codex Pull Consumer

This agent pulls commands from the Cloudflare `commands-queue`, runs the Codex CLI (or echoes),
and posts ordered responses to the worker `/events` endpoint using the pi-hash sequence.

## Requirements

- Bun (default path assumed: `~/.bun/bin/bun`)
- Cloudflare API token with Queues read/write
- Worker running and reachable (`PI_QUEUE_API_URL`)

## Quick start

```sh
cp apps/agent/.env.example apps/agent/.env
source apps/agent/.env
npm --workspace @queue/agent run dev
```

## Environment variables

Required:
- `CF_ACCOUNT_ID` - Cloudflare account ID
- `CF_API_TOKEN` - API token with Queues read/write
- `CF_COMMANDS_QUEUE_ID` - queue ID or name for `commands-queue`
- `PI_QUEUE_API_URL` - worker base URL (ex: `http://localhost:8787`)

Optional:
- `CODEX_MODE` - `echo` (default) or `exec`
- `CODEX_BIN` - Codex CLI binary (default `codex`)
- `CODEX_ARGS_JSON` - JSON array of args, supports `{command}` placeholder
- `CODEX_ARGS` - space-separated args (fallback if JSON not set)
- `CODEX_WORKDIR` - working directory for the Codex process
- `CODEX_TIMEOUT_MS` - kill Codex after timeout (default 120000)
- `PULL_BATCH_SIZE` - queue pull batch size (default 1, max 100)
- `PULL_VISIBILITY_TIMEOUT_MS` - queue visibility timeout (default 30000)
- `POLL_INTERVAL_MS` - delay between empty polls (default 1500)
- `MAX_OUTPUT_CHARS` - trim Codex output length (default 12000)
- `MAX_RESPONSE_RETRIES` - pi-hash retry attempts (default 3)

Notes:
- If `CODEX_ARGS_JSON` or `CODEX_ARGS` includes `{command}`, the agent substitutes the prompt in
  the args. Otherwise it writes the command to stdin.
- The agent acks invalid payloads and session-expired responses; other errors are retried.
