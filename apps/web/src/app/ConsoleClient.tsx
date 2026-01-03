"use client";

import { useCallback, useEffect, useMemo, useState, useTransition } from "react";
import {
	endSessionAction,
	openSessionAction,
	refreshSessionAction,
	sendCommandAction,
	type CommandResult,
	type OpenSessionResult,
	type StatusResult,
} from "./actions";

type StatusKind = "idle" | "active" | "expired";

type EventItem = {
	id: string;
	piIndex: number | null;
	timestamp: number | null;
	responseId?: string;
	payload: unknown;
};

type LogEntry = {
	id: string;
	type: "info" | "warn" | "error" | "success";
	message: string;
	timestamp: number;
};

const EVENT_LIMIT = 200;
const LOG_LIMIT = 120;

function formatTime(timestamp: number | null): string {
	if (!timestamp) {
		return "-";
	}
	return new Date(timestamp).toLocaleTimeString();
}

function formatPayload(value: unknown): string {
	if (value === null || value === undefined) {
		return "";
	}
	if (typeof value === "string") {
		return value;
	}
	if (typeof value === "number" || typeof value === "boolean") {
		return String(value);
	}
	try {
		return JSON.stringify(value, null, 2);
	} catch {
		return String(value);
	}
}

function useLogger() {
	const [logs, setLogs] = useState<LogEntry[]>([]);
	const push = useCallback((type: LogEntry["type"], message: string) => {
		setLogs((prev) => {
			const next = prev.concat({
				id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
				type,
				message,
				timestamp: Date.now(),
			});
			if (next.length > LOG_LIMIT) {
				next.splice(0, next.length - LOG_LIMIT);
			}
			return next;
		});
	}, []);
	return { logs, push };
}

export default function ConsoleClient() {
	const [status, setStatus] = useState<StatusKind>("idle");
	const [acceptHash, setAcceptHash] = useState("");
	const [nextPiIndex, setNextPiIndex] = useState<number | null>(null);
	const [lastActivity, setLastActivity] = useState<number | null>(null);
	const [queueDepth, setQueueDepth] = useState<number | null>(null);
	const [piIndexInput, setPiIndexInput] = useState("0");
	const [command, setCommand] = useState("");
	const [events, setEvents] = useState<EventItem[]>([]);
	const [sessionId, setSessionId] = useState<string | null>(null);
	const [isPending, startTransition] = useTransition();
	const { logs, push } = useLogger();

	const apiBase = useMemo(
		() => process.env.NEXT_PUBLIC_PI_QUEUE_API_URL ?? "http://localhost:8787",
		[],
	);
	const buildApiUrl = useCallback((path: string) => {
		const base = apiBase.endsWith("/") ? apiBase.slice(0, -1) : apiBase;
		return `${base}${path}`;
	}, [apiBase]);

	const statusClass = `status status--${status}`;

	const applyOpenResult = (result: OpenSessionResult) => {
		if (!result.ok) {
			push("error", `Session open failed: ${result.error ?? "unknown error"}.`);
			return;
		}
		const payload = result.payload ?? {};
		const accepted = Boolean(payload.accepted);
		if (!accepted) {
			const reason = typeof payload.reason === "string" ? payload.reason : "rejected";
			push("warn", `Session rejected: ${reason}.`);
			return;
		}
		setStatus("active");
		setAcceptHash(typeof payload.acceptHash === "string" ? payload.acceptHash : "");
		setNextPiIndex(typeof payload.nextPiIndex === "number" ? payload.nextPiIndex : null);
		setLastActivity(Date.now());
		setQueueDepth(null);
		setEvents([]);
		setSessionId(result.sessionId ?? null);
		push("success", "Session opened with encrypted pi index.");
	};

	const applyStatusResult = (result: StatusResult) => {
		if (!result.ok) {
			setStatus("idle");
			setNextPiIndex(null);
			setQueueDepth(null);
			push("warn", "No active session.");
			return;
		}
		const data = result.data ?? {};
		const active = Boolean(data.active);
		setStatus(active ? "active" : "idle");
		setNextPiIndex(typeof data.nextPiIndex === "number" ? data.nextPiIndex : null);
		setLastActivity(typeof data.lastUserActivityAt === "number" ? data.lastUserActivityAt : null);
		setQueueDepth(typeof data.queueDepth === "number" ? data.queueDepth : null);
		push("info", "Session status refreshed.");
	};

	const applyCommandResult = (result: CommandResult) => {
		if (!result.ok) {
			const data = result.data ?? {};
			if (result.status === 410) {
				setStatus("expired");
				push("warn", "Session expired.");
				return;
			}
			if (typeof data.expectedPiIndex === "number") {
				setNextPiIndex(data.expectedPiIndex);
			}
			const error = typeof data.error === "string" ? data.error : result.error ?? "command_failed";
			push("error", `Command rejected: ${error}.`);
			return;
		}
		const data = result.data ?? {};
		if (typeof data.nextPiIndex === "number") {
			setNextPiIndex(data.nextPiIndex);
		} else if (nextPiIndex !== null) {
			setNextPiIndex(nextPiIndex + 1);
		}
		setCommand("");
		setLastActivity(Date.now());
		push("success", "Command queued.");
	};

	const handleOpenSession = () => {
		startTransition(async () => {
			const result = await openSessionAction({ piIndex: piIndexInput });
			applyOpenResult(result);
		});
	};

	const handleRefresh = () => {
		startTransition(async () => {
			const result = await refreshSessionAction();
			applyStatusResult(result);
		});
	};

	const handleEndSession = () => {
		startTransition(async () => {
			const result = await endSessionAction();
			if (!result.ok) {
				push("warn", "Failed to end session.");
				return;
			}
			setStatus("idle");
			setAcceptHash("");
			setNextPiIndex(null);
			setLastActivity(null);
			setQueueDepth(null);
			setEvents([]);
			setSessionId(null);
			push("info", "Session ended.");
		});
	};

	const handleSendCommand = () => {
		if (!command.trim()) {
			push("warn", "Command payload is empty.");
			return;
		}
		if (nextPiIndex === null) {
			push("warn", "No pi index available yet.");
			return;
		}
		startTransition(async () => {
			const result = await sendCommandAction({ command, nextPiIndex });
			applyCommandResult(result);
		});
	};

	useEffect(() => {
		if (status !== "active") {
			return;
		}
		let cancelled = false;
		const poll = async () => {
			while (!cancelled) {
				let response: Response;
				try {
					response = await fetch(buildApiUrl("/events?wait=25000&max=20"), {
						cache: "no-store",
					});
				} catch {
					push("warn", "Event poll failed. Retrying.");
					await new Promise((resolve) => setTimeout(resolve, 1000));
					continue;
				}
				if (cancelled) {
					return;
				}
				if (response.status === 410) {
					setStatus("expired");
					push("warn", "Session expired.");
					return;
				}
				let data: any = null;
				try {
					data = await response.json();
				} catch {
					data = null;
				}
				if (!response.ok) {
					push("warn", "Event poll error.");
					await new Promise((resolve) => setTimeout(resolve, 1000));
					continue;
				}
				if (Array.isArray(data?.events) && data.events.length > 0) {
					const normalized = data.events.map((event: any) => ({
						id: event.responseId ?? event.id ?? `${Math.random()}`,
						piIndex: typeof event.piIndex === "number" ? event.piIndex : null,
						timestamp: typeof event.timestamp === "number" ? event.timestamp : null,
						payload: event.payload ?? event.event ?? event,
						responseId: event.responseId,
					}));
					setEvents((prev) => {
						const next = prev.concat(normalized);
						if (next.length > EVENT_LIMIT) {
							next.splice(0, next.length - EVENT_LIMIT);
						}
						return next;
					});
					const last = normalized[normalized.length - 1];
					if (last && typeof last.piIndex === "number") {
						setNextPiIndex((prev) => {
							const candidate = last.piIndex + 1;
							if (prev === null || candidate > prev) {
								return candidate;
							}
							return prev;
						});
					}
					setLastActivity(Date.now());
					setQueueDepth((prev) =>
						typeof data.queueDepth === "number" ? data.queueDepth : prev,
					);
					push("info", `Received ${normalized.length} event(s).`);
				}
			}
		};
		poll();
		return () => {
			cancelled = true;
		};
	}, [status, buildApiUrl, push]);

	const eventItems = events.length
		? events.map((event) => (
				<div className="event-card" key={event.id}>
					<div className="event-meta">
						<span>pi {event.piIndex ?? "-"}</span>
						<span>{formatTime(event.timestamp)}</span>
						<span>{event.responseId ? event.responseId.slice(0, 8) : "-"}</span>
					</div>
					<pre className="event-body">{formatPayload(event.payload)}</pre>
				</div>
			))
		: [
				<div className="empty" key="empty-events">
					No events yet. Open a session and send a command.
				</div>,
			];

	const logItems = logs.length
		? logs.map((log) => (
				<div className="log-item" key={log.id}>
					<div className="log-head">
						<span className={`log-type ${log.type}`}>{log.type}</span>
						<span className="chip">{formatTime(log.timestamp)}</span>
					</div>
					<div className="log-message">{log.message}</div>
				</div>
			))
		: [
				<div className="empty" key="empty-logs">
					Session logs will appear here.
				</div>,
			];

	return (
		<div className="page">
			<div className="orb orb--one" aria-hidden="true" />
			<div className="orb orb--two" aria-hidden="true" />
			<header className="hero">
				<div>
					<div className="hero__badge">pi-queue</div>
					<h1>Secure Pi Session Console</h1>
					<p>Encrypted session open, deterministic sequence, and ordered event delivery.</p>
				</div>
				<div className="hero__stats">
					<div className="stat">
						<span className="stat__label">Session</span>
						<span className="stat__value">
							<span className={statusClass}>{status}</span>
						</span>
					</div>
					<div className="stat">
						<span className="stat__label">Next pi index</span>
						<span className="stat__value">{nextPiIndex ?? "-"}</span>
					</div>
					<div className="stat">
						<span className="stat__label">Accept hash</span>
						<span className="stat__value">
							{acceptHash ? `${acceptHash.slice(0, 10)}...` : "-"}
						</span>
					</div>
					<div className="stat">
						<span className="stat__label">Queue depth</span>
						<span className="stat__value">{queueDepth ?? "-"}</span>
					</div>
				</div>
			</header>

			<main className="grid">
				<section className="panel">
					<h2>Session control</h2>
					<p>Encrypted handshake using Ed25519 + X25519. Pi index stays sealed.</p>
					<div className="field-row">
						<label className="field">
							<span>Start index</span>
							<input
								value={piIndexInput}
								onChange={(event) => setPiIndexInput(event.target.value)}
								placeholder="0"
								inputMode="numeric"
							/>
						</label>
						<button className="btn secondary" onClick={handleOpenSession} disabled={isPending}>
							Open session
						</button>
					</div>
					<div className="meta-row">
						<button className="btn ghost" onClick={handleRefresh} disabled={isPending}>
							Refresh status
						</button>
						<button
							className="btn ghost"
							onClick={handleEndSession}
							disabled={isPending || status === "idle"}
						>
							End session
						</button>
						<span>Last activity: {formatTime(lastActivity)}</span>
					</div>
					<div className="meta-row">
						<span className="chip">Session id</span>
						<span>{sessionId ?? "-"}</span>
					</div>
				</section>

				<section className="panel">
					<h2>Command</h2>
					<label className="field">
						<span>Command payload</span>
						<textarea
							value={command}
							onChange={(event) => setCommand(event.target.value)}
							placeholder="Send a command to the agent..."
						/>
					</label>
					<div className="meta-row">
						<button className="btn" onClick={handleSendCommand} disabled={isPending || status !== "active"}>
							Send command
						</button>
						<span>Pi hash computed server-side.</span>
					</div>
				</section>

				<section className="panel span-2">
					<div className="panel__header">
						<h2>Event stream</h2>
						<div className="chip">{events.length} events</div>
					</div>
					<div className="stack">{eventItems}</div>
				</section>

				<section className="panel span-2">
					<div className="panel__header">
						<h2>Activity log</h2>
						<div className="chip">Secure channel</div>
					</div>
					<div className="stack">{logItems}</div>
				</section>
			</main>
		</div>
	);
}
