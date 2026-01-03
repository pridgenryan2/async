# Queue Monorepo

This monorepo hosts the Cloudflare queue worker, Next.js console client, Codex pull-consumer agent, and the shared pi/session protocol library.

## Apps

- `apps/worker`: Cloudflare Queues worker + Durable Object session API
- `apps/web`: Next.js console client (server actions + event stream)
- `apps/agent`: Bun-based Codex CLI pull consumer

## Packages

- `packages/queue-core`: shared pi hashing + session crypto utilities

## Common commands

```sh
npm install

# run a specific app
npm --workspace @queue/worker run dev
npm --workspace @queue/web run dev
npm --workspace @queue/agent run dev

# run tests
npm --workspace @queue/core run test
```

Turbo shortcuts are still available (`npm run dev`, `npm run build`, `npm run test`) with filters if needed.
