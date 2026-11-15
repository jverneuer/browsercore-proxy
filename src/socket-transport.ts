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

    private stateValue: TransportState = { state: "open", bytesTransferred: 0 };
    private readonly socket: Socket;
    private readonly readQueue: Uint8Array[] = [];
    /**
     * One-shot `"data"` subscribers. The Socket contract has `once` only for
     * connect/close/error and no listener removal, so one-shot data
     * subscriptions are dispatched and retired here instead.
     */
    private readonly onceDataListeners = new Set<(data: Uint8Array) => void>();
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
        // `on("close")` (not `once`) because the Socket contract's
        // `once("close")` listener takes no hadError argument; the persistent
        // listener is harmless — the handler is idempotent once closed.
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
                this.recordTransfer(data.length);
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

    public on(event: "data", listener: (data: Uint8Array) => void): void;
    public on(event: "close", listener: (reason: CloseReason) => void): void;
    public on(event: "error", listener: (error: Error) => void): void;
    public on(event: string, listener: (...args: never[]) => void): void {
        this.subscribe("on", event, listener as (data: unknown) => void);
    }

    public once(event: "data", listener: (data: Uint8Array) => void): void;
    public once(event: "close", listener: (reason: CloseReason) => void): void;
    public once(event: "error", listener: (error: Error) => void): void;
    public once(event: string, listener: (...args: never[]) => void): void {
        this.subscribe("once", event, listener as (data: unknown) => void);
    }

    private subscribe(
        method: "on" | "once",
        event: string,
        listener: (data: unknown) => void,
    ): void {
        if (event === "close") {
            // Translate the socket's boolean hadError into the transport's
            // CloseReason union. `once("close")` loses hadError in the Socket
            // contract (its listener takes no args), so it assumes the benign
            // case — good enough for advisory subscribers.
            const adapted = (hadError: boolean): void => {
                listener(hadError
                    ? { kind: "error", error: new Error("socket closed after error") }
                    : { kind: "remote_close" });
            };
            if (method === "on") {
                this.socket.on("close", adapted);
            } else {
                this.socket.once("close", () => {
                    adapted(false);
                });
            }
            return;
        }
        if (event === "data") {
            if (method === "once") {
                this.onceDataListeners.add(listener as (data: Uint8Array) => void);
            } else {
                this.socket.on("data", listener as (data: Uint8Array) => void);
            }
            return;
        }
        if (event === "error") {
            const errorListener = listener as (error: Error) => void;
            if (method === "on") {
                this.socket.on("error", errorListener);
            } else {
                this.socket.once("error", errorListener);
            }
        }
    }

    private onSocketData(chunk: Uint8Array): void {
        this.recordTransfer(chunk.length);

        // One-shot subscribers retire after their first dispatch. Deleting the
        // current entry mid-iteration is defined Set behavior, so the loop can
        // iterate the set directly.
        for (const listener of this.onceDataListeners) {
            this.onceDataListeners.delete(listener);
            listener(chunk);
        }

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
        if (this.stateValue.state === "closed") {
            return; // a close always follows; state is already final
        }
        this.stateValue = { state: "closed", reason: { kind: "error", error } };
        this.rejectPendingRead();
        // Force teardown — relying on the peer to close after an error hangs readers.
        this.socket.destroy();
    }

    private onSocketClose(hadError: boolean): void {
        if (this.stateValue.state === "closed") {
            return; // close() or onSocketError() already finalized the state
        }
        this.stateValue = {
            state: "closed",
            reason: hadError
                ? { kind: "error", error: new Error("socket closed after error") }
                : { kind: "remote_close" },
        };
        this.rejectPendingRead();
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

    /** Keep the state's byte counter current — observable via `state.bytesTransferred`. */
    private recordTransfer(byteCount: number): void {
        if (this.stateValue.state === "open") {
            this.stateValue = {
                state: "open",
                bytesTransferred: this.stateValue.bytesTransferred + byteCount,
            };
        }
    }
}
