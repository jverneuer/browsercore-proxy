/**
 * Adapter from an injected TCP {@link Socket} to the duplex {@link Transport}
 * the handshakes speak.
 *
 * `connectViaProxy` dials the proxy through `Platform.network.tcp`, which
 * yields the callback-based Socket contract; this module bridges it to the
 * promise-based pull Transport. The write promise resolves from the socket's
 * own write callback, so a not-yet-connected socket transparently buffers in
 * the kernel and flushes on connect — no connect-state machine needed here.
 */

import type { CloseReason, Socket, Transport, TransportState } from "@browsercore/contracts";
import { ProxyError } from "./errors.js";

/** Listener shape of the canonical {@link Transport} event surface. */
type Listener = (...args: unknown[]) => void;

let nextTransportId = 0;

/**
 * Wrap an injected TCP socket as a {@link Transport}.
 *
 * The socket must be freshly returned by `Net.connect` — the adapter takes
 * over its `"data"`, `"error"`, and `"close"` events for the read side.
 */
export function createSocketTransport(socket: Socket): Transport {
    nextTransportId += 1;
    return new SocketTransport(socket, `proxy-socket-${nextTransportId}`);
}

class SocketTransport implements Transport {
    public readonly id: string;

    private stateValue: TransportState = { state: "open" };
    private readonly socket: Socket;
    private readonly readQueue: Uint8Array[] = [];
    /**
     * Local listener registry backing the canonical `Transport` event surface.
     * The Socket contract offers only literal-event `on`/`once` and no removal,
     * so `off`/`removeListener`/`emit`/`listenerCount`/`removeAllListeners`
     * cannot be delegated to it. Instead the adapter's own socket wiring
     * (below) translates the three Transport events into this registry, which
     * implements the full surface.
     */
    private readonly listeners = new Map<string, Set<Listener>>();
    private readonly onceListeners = new Map<string, Set<Listener>>();
    private pendingRead: ((data: Uint8Array) => void) | undefined;
    private pendingReadReject: ((error: Error) => void) | undefined;

    constructor(socket: Socket, id: string) {
        this.socket = socket;
        this.id = id;
        socket.on("data", (chunk) => {
            this.onSocketData(chunk);
        });
        socket.on("error", (error) => {
            this.onSocketError(error);
        });
        // `on("close")` (not `once`) because the adapter must observe every
        // close-shaped event to keep registry subscribers in sync; the
        // handler is idempotent once closed.
        socket.on("close", (hadError: boolean) => {
            this.onSocketClose(hadError);
        });
    }

    public get state(): TransportState {
        return this.stateValue;
    }

    public write(data: Uint8Array): Promise<void> {
        if (this.stateValue.state === "closed") {
            return Promise.reject(this.closedError("write"));
        }
        return new Promise((resolve, reject) => {
            this.socket.write(data, (err) => {
                if (err !== undefined && err !== null) {
                    reject(new ProxyError(`Write failed on transport ${this.id}`, { id: this.id }, { cause: err }));
                    return;
                }
                resolve();
            });
        });
    }

    public read(): Promise<Uint8Array> {
        const queued = this.readQueue.shift();
        if (queued !== undefined) {
            return Promise.resolve(queued);
        }
        if (this.stateValue.state === "closed") {
            return Promise.reject(this.closedError("read"));
        }
        return new Promise((resolve, reject) => {
            this.pendingRead = resolve;
            this.pendingReadReject = reject;
        });
    }

    public close(reason?: CloseReason): Promise<void> {
        if (this.stateValue.state !== "closed") {
            this.stateValue = { state: "closed", reason: reason ?? { kind: "client_close" } };
            this.rejectPendingRead();
            // end() is the graceful shutdown; the socket's own "close" event
            // follows, which our handler ignores since state is already final.
            this.socket.end();
        }
        return Promise.resolve();
    }

    public on(event: string, listener: Listener): void {
        this.register(this.listeners, event, listener);
    }

    public once(event: string, listener: Listener): void {
        this.register(this.onceListeners, event, listener);
    }

    public off(event: string, listener: Listener): void {
        this.unregister(event, listener);
    }

    public removeListener(event: string, listener: Listener): void {
        this.unregister(event, listener);
    }

    public emit(event: string, ...args: unknown[]): boolean {
        return this.notify(event, ...args);
    }

    public listenerCount(event: string): number {
        return (this.listeners.get(event)?.size ?? 0) + (this.onceListeners.get(event)?.size ?? 0);
    }

    public removeAllListeners(event?: string): void {
        if (event === undefined) {
            this.listeners.clear();
            this.onceListeners.clear();
            return;
        }
        this.listeners.delete(event);
        this.onceListeners.delete(event);
    }

    private register(registry: Map<string, Set<Listener>>, event: string, listener: Listener): void {
        const existing = registry.get(event);
        if (existing !== undefined) {
            existing.add(listener);
            return;
        }
        registry.set(event, new Set([listener]));
    }

    private unregister(event: string, listener: Listener): void {
        this.listeners.get(event)?.delete(listener);
        this.onceListeners.get(event)?.delete(listener);
    }

    /**
     * Dispatch an event to the registry: one-shot listeners first (retiring
     * each before it runs, so a throwing listener is still one-shot), then
     * persistent listeners over a snapshot — a listener unsubscribing itself
     * mid-dispatch must not change who else sees the event.
     *
     * Returns whether any listener was registered, per the EventProvider
     * `emit` contract.
     */
    private notify(event: string, ...args: unknown[]): boolean {
        const oneShot = this.onceListeners.get(event);
        let delivered = oneShot !== undefined && oneShot.size > 0;
        if (oneShot !== undefined) {
            for (const listener of oneShot) {
                oneShot.delete(listener);
                listener(...args);
            }
            this.onceListeners.delete(event);
        }
        const persistent = this.listeners.get(event);
        delivered = delivered || (persistent !== undefined && persistent.size > 0);
        for (const listener of Array.from(persistent ?? [])) {
            listener(...args);
        }
        return delivered;
    }

    private onSocketData(chunk: Uint8Array): void {
        this.notify("data", chunk);

        const pending = this.pendingRead;
        if (pending !== undefined) {
            this.pendingRead = undefined;
            this.pendingReadReject = undefined;
            pending(chunk);
            return;
        }
        this.readQueue.push(chunk);
    }

    private onSocketError(error: Error): void {
        if (this.stateValue.state !== "closed") {
            this.stateValue = { state: "closed", reason: { kind: "error", error } };
            this.rejectPendingRead();
            // Force teardown — relying on the peer to close after an error hangs readers.
            this.socket.destroy();
        }
        // State is finalized before the dispatch so listeners observe the
        // closed state; delivery happens even when it was already final,
        // matching the socket's own every-listener-sees-every-event behavior.
        this.notify("error", error);
    }

    private onSocketClose(hadError: boolean): void {
        // Translate the socket's boolean hadError into the transport's
        // CloseReason union once — both persistent and one-shot subscribers
        // see the true reason (the former `once("close")` benign-case
        // assumption died with the direct socket delegation).
        const reason: CloseReason = hadError
            ? { kind: "error", error: new Error("socket closed after error") }
            : { kind: "remote_close" };
        if (this.stateValue.state !== "closed") {
            this.stateValue = { state: "closed", reason };
            this.rejectPendingRead();
        }
        this.notify("close", reason);
    }

    private rejectPendingRead(): void {
        const reject = this.pendingReadReject;
        if (reject !== undefined) {
            this.pendingRead = undefined;
            this.pendingReadReject = undefined;
            reject(this.closedError("read"));
        }
    }

    private closedError(operation: string): ProxyError {
        const reason = this.stateValue.state === "closed" ? this.stateValue.reason.kind : "unknown";
        return new ProxyError(
            `Cannot ${operation} — transport ${this.id} is closed (${reason})`,
            { id: this.id, operation, reason },
        );
    }
}
