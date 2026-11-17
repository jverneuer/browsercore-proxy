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

/** Listener shape of the canonical {@link Transport} event surface. */
type Listener = (...args: unknown[]) => void;

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

    // The replay only affects the pull side; event subscribers see the
    // underlying transport's stream unchanged, so delegation is exact for
    // the entire canonical event surface.
    public on(event: string, listener: Listener): void {
        this.underlying.on(event, listener);
    }

    public once(event: string, listener: Listener): void {
        this.underlying.once(event, listener);
    }

    public off(event: string, listener: Listener): void {
        this.underlying.off(event, listener);
    }

    public removeListener(event: string, listener: Listener): void {
        this.underlying.removeListener(event, listener);
    }

    public emit(event: string, ...args: unknown[]): boolean {
        return this.underlying.emit(event, ...args);
    }

    public listenerCount(event: string): number {
        return this.underlying.listenerCount(event);
    }

    public removeAllListeners(event?: string): void {
        this.underlying.removeAllListeners(event);
    }
}
