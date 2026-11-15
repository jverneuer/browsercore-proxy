/**
 * Post-handshake transport selection.
 *
 * A handshake may consume a chunk that carried more than the handshake
 * message (e.g. a CONNECT response and the first target bytes in one TCP
 * segment). Those leftover bytes belong to the tunnel; because `Transport`
 * is pull-based they cannot be pushed back, so a thin replaying wrapper
 * yields them on the first `read()` and delegates everything else.
 */

import type { CloseReason, Transport, TransportState } from "@browsercore/contracts";

/**
 * Return the transport to use for tunnel data after a handshake.
 *
 * With no leftover bytes this is the transport itself, unchanged — zero
 * overhead on the common path. With leftovers it is a {@link ReplayingTransport}.
 */
export function tunnelTransport(transport: Transport, leftover: Uint8Array): Transport {
    if (leftover.length === 0) {
        return transport;
    }
    return new ReplayingTransport(transport, leftover);
}

/**
 * Delegates to the underlying transport, replaying the handshake's leftover
 * bytes on the first `read()`.
 *
 * Constructed only through {@link tunnelTransport} with a non-empty leftover,
 * so the replay path is always live.
 */
class ReplayingTransport implements Transport {
    public readonly id: string;
    private readonly underlying: Transport;
    private pendingReplay: Uint8Array;
    private replayed = false;

    constructor(underlying: Transport, leftover: Uint8Array) {
        this.id = underlying.id;
        this.underlying = underlying;
        this.pendingReplay = leftover;
    }

    public get state(): TransportState {
        return this.underlying.state;
    }

    public read(): Promise<Uint8Array> {
        if (this.replayed) {
            return this.underlying.read();
        }
        this.replayed = true;
        return Promise.resolve(this.pendingReplay);
    }

    public write(data: Uint8Array): Promise<void> {
        return this.underlying.write(data);
    }

    public close(reason?: CloseReason): Promise<void> {
        return this.underlying.close(reason);
    }

    public on(event: "data", listener: (data: Uint8Array) => void): void;
    public on(event: "close", listener: (reason: CloseReason) => void): void;
    public on(event: "error", listener: (error: Error) => void): void;
    public on(event: string, listener: (...args: never[]) => void): void {
        // The replay only affects the pull side; event subscribers see the
        // underlying transport's stream unchanged, so delegation is exact.
        this.underlying.on(event as "data", listener as (data: Uint8Array) => void);
    }

    public once(event: "data", listener: (data: Uint8Array) => void): void;
    public once(event: "close", listener: (reason: CloseReason) => void): void;
    public once(event: "error", listener: (error: Error) => void): void;
    public once(event: string, listener: (...args: never[]) => void): void {
        this.underlying.once(event as "data", listener as (data: Uint8Array) => void);
    }
}
