/**
 * Shared test fixtures for @browsercore/proxy tests.
 *
 * - {@link MemoryTransport} / {@link createTransportPair}: a synthetic duplex
 *   Transport pair in the house style (adapted from @browsercore/http2's
 *   fake-transport). Everything written to one side is readable on the other;
 *   tests script the "proxy" side byte-for-byte.
 * - {@link FakeSocket}: a callback-based Socket (the @browsercore/contracts
 *   surface) for driving `createSocketTransport` and `connectViaProxy`.
 * - {@link testPlatform}: a Platform whose unused bundles are inert stubs —
 *   the proxy code paths only ever touch `network`.
 */

import type {
    CloseReason,
    CompressionProvider,
    Crypto,
    DatagramTransport,
    EventProvider,
    Network,
    Platform,
    Socket,
    Telemetry,
    Time,
    Transport,
    TransportState,
} from "@browsercore/contracts";

type Listener = (...args: unknown[]) => void;

/**
 * A registry entry: `original` is the caller-supplied listener (the identity
 * `off`/`removeListener` match against), `call` is what dispatches — the
 * caller's listener for `on`, a self-retiring wrapper for `once`.
 */
interface RegisteredListener {
    readonly original: Listener;
    readonly call: Listener;
}

/** A synthetic duplex byte-stream transport. */
export class MemoryTransport implements Transport {
    public readonly id: string;
    public stateValue: TransportState = { state: "open" };
    /** Bytes this side wrote, as a log for assertions. */
    public readonly writes: Uint8Array[] = [];

    private readonly incoming: Uint8Array[] = [];
    private readonly listeners = new Map<string, Set<RegisteredListener>>();
    private peerRef: MemoryTransport | undefined;
    private pendingRead: ((data: Uint8Array) => void) | undefined;
    private pendingReadReject: ((error: Error) => void) | undefined;

    public constructor(id: string) {
        this.id = id;
    }

    public get state(): TransportState {
        return this.stateValue;
    }

    /** Wire this transport to its far end (used by {@link createTransportPair}). */
    public connectPeer(peer: MemoryTransport): void {
        this.peerRef = peer;
    }

    /** Test seam: bytes "arrive from the peer". */
    public deliver(data: Uint8Array): void {
        const pending = this.pendingRead;
        if (pending !== undefined) {
            this.pendingRead = undefined;
            this.pendingReadReject = undefined;
            pending(data);
            return;
        }
        this.incoming.push(data);
    }

    /** Test seam: the connection dies with an error. */
    public fail(error: Error): void {
        this.stateValue = { state: "closed", reason: { kind: "error", error } };
        const reject = this.pendingReadReject;
        if (reject !== undefined) {
            this.pendingRead = undefined;
            this.pendingReadReject = undefined;
            reject(error);
        }
    }

    public write(data: Uint8Array): Promise<void> {
        if (this.stateValue.state !== "open") {
            return Promise.reject(new Error(`transport ${this.id} is not open`));
        }
        this.writes.push(data);
        const peer = this.peerRef;
        if (peer === undefined) {
            return Promise.resolve();
        }
        peer.deliver(data);
        return Promise.resolve();
    }

    public read(): Promise<Uint8Array> {
        const next = this.incoming.shift();
        if (next !== undefined) {
            return Promise.resolve(next);
        }
        if (this.stateValue.state === "closed") {
            return Promise.reject(new Error(`transport ${this.id} is closed`));
        }
        return new Promise((resolve, reject) => {
            this.pendingRead = resolve;
            this.pendingReadReject = reject;
        });
    }

    public close(reason?: CloseReason): Promise<void> {
        this.stateValue = { state: "closed", reason: reason ?? { kind: "client_close" } };
        const reject = this.pendingReadReject;
        if (reject !== undefined) {
            this.pendingRead = undefined;
            this.pendingReadReject = undefined;
            reject(new Error(`transport ${this.id} is closed`));
        }
        return Promise.resolve();
    }

    public on(event: string, listener: Listener): void {
        this.register(event, { original: listener, call: listener });
    }

    public once(event: string, listener: Listener): void {
        const entry: RegisteredListener = {
            original: listener,
            call: (...args) => {
                this.listeners.get(event)?.delete(entry);
                listener(...args);
            },
        };
        this.register(event, entry);
    }

    public off(event: string, listener: Listener): void {
        this.unregister(event, listener);
    }

    public removeListener(event: string, listener: Listener): void {
        this.unregister(event, listener);
    }

    public emit(event: string, ...args: unknown[]): boolean {
        return this.emitTest(event, ...args);
    }

    public listenerCount(event: string): number {
        return this.listeners.get(event)?.size ?? 0;
    }

    public removeAllListeners(event?: string): void {
        if (event === undefined) {
            this.listeners.clear();
            return;
        }
        this.listeners.delete(event);
    }

    /** Test seam: notify event subscribers; returns whether any were registered. */
    public emitTest(event: string, ...args: unknown[]): boolean {
        const registered = [...(this.listeners.get(event) ?? [])];
        for (const listener of registered) {
            listener.call(...args);
        }
        return registered.length > 0;
    }

    private register(event: string, entry: RegisteredListener): void {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event)?.add(entry);
    }

    private unregister(event: string, listener: Listener): void {
        for (const entry of [...(this.listeners.get(event) ?? [])]) {
            if (entry.original === listener) {
                this.listeners.get(event)?.delete(entry);
            }
        }
    }
}

/** Two transports wired back-to-back: writes on one are readable on the other. */
export function createTransportPair(): { client: MemoryTransport; server: MemoryTransport } {
    const client = new MemoryTransport("client");
    const server = new MemoryTransport("server");
    client.connectPeer(server);
    server.connectPeer(client);
    return { client, server };
}

/** Callback-based fake of the contracts Socket surface. */
export class FakeSocket implements Socket {
    public readonly written: Uint8Array[] = [];
    public destroyed = false;
    /** When set, the next `write` callback receives this error instead of null. */
    public nextWriteError: Error | undefined;
    /** When set, the next `write` callback fires with NO argument at all (edge-shaped adapter). */
    public bareWriteCallback = false;

    private readonly listeners = new Map<string, Set<Listener>>();
    private readonly onceListeners = new Map<string, Set<Listener>>();

    public write(data: Uint8Array, cb?: (err?: Error | null) => void): boolean {
        this.written.push(data);
        if (this.bareWriteCallback) {
            this.bareWriteCallback = false;
            cb?.();
            return true;
        }
        const error = this.nextWriteError ?? null;
        this.nextWriteError = undefined;
        cb?.(error);
        return true;
    }

    public end(): void {
        this.emitCustom("close", false);
    }

    public destroy(error?: Error): void {
        if (this.destroyed) {
            return;
        }
        this.destroyed = true;
        if (error !== undefined) {
            this.emitCustom("error", error);
        }
        this.emitCustom("close", true);
    }

    public once(event: "connect" | "close", listener: () => void): void;
    public once(event: "error", listener: (err: Error) => void): void;
    public once(event: string, listener: Listener): void {
        if (!this.onceListeners.has(event)) {
            this.onceListeners.set(event, new Set());
        }
        this.onceListeners.get(event)?.add(listener);
    }

    public on(event: "data", listener: (chunk: Uint8Array) => void): void;
    public on(event: "drain" | "end", listener: () => void): void;
    public on(event: "error", listener: (err: Error) => void): void;
    public on(event: "close", listener: (hadError: boolean) => void): void;
    public on(event: string, listener: Listener): void {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event)?.add(listener);
    }

    /** Test seam: deliver bytes as if they arrived from the network. */
    public pushData(chunk: Uint8Array): void {
        this.emitCustom("data", chunk);
    }

    /** Test seam: fire an arbitrary event at registered listeners. */
    public emitCustom(event: string, ...args: unknown[]): void {
        for (const listener of [...(this.onceListeners.get(event) ?? [])]) {
            this.onceListeners.get(event)?.delete(listener);
            listener(...args);
        }
        for (const listener of [...(this.listeners.get(event) ?? [])]) {
            listener(...args);
        }
    }
}

/**
 * A Platform whose non-network bundles throw if touched — `connectViaProxy`
 * must only ever use `platform.network`, and this fixture proves it at test
 * time instead of trusting the type.
 */
export function testPlatform(network: Network): Platform {
    return {
        network,
        crypto: unused<Crypto>("platform.crypto"),
        compression: unused<CompressionProvider>("platform.compression"),
        events: unused<EventProvider>("platform.events"),
        telemetry: unused<Telemetry>("platform.telemetry"),
        time: unused<Time>("platform.time"),
    };
}

/** A Network whose UDP slot is inert — the proxy code never sends datagrams. */
export function testNetwork(tcp: Network["tcp"], dns?: Network["dns"]): Network {
    return {
        tcp,
        dns: dns ?? unused<Network["dns"]>("network.dns"),
        udp: unused<DatagramTransport>("network.udp"),
    };
}

/** A DnsResolver stub returning one fixed address (records every lookup). */
export function scriptedDns(address = "203.0.113.7"): Network["dns"] & { calls: string[] } {
    const dns = {
        calls: [] as string[],
        lookup(hostname: string, family: 4 | 6): Promise<{ address: string; family: 4 | 6 }[]> {
            dns.calls.push(`${hostname}/${family}`);
            return Promise.resolve([{ address, family }]);
        },
    };
    return dns;
}

/** A DnsResolver stub returning an empty address list. */
export const emptyDns: Network["dns"] = {
    lookup(): Promise<{ address: string; family: 4 | 6 }[]> {
        return Promise.resolve([]);
    },
};

/**
 * Build a bundle whose every property access throws — any touch names the
 * culprit in the failure message. The single cast is the point: the bundle is
 * unused by contract, so it has no honest implementation.
 */
function unused<T>(label: string): T {
    return new Proxy({} as object, {
        get(_target, property) {
            throw new Error(`unexpected access to ${label}.${String(property)} — proxy code must not touch this bundle`);
        },
    }) as T;
}

/** Poll until `predicate` holds; fails the test after a generous budget. */
export async function waitFor(predicate: () => boolean, what: string): Promise<void> {
    for (let attempt = 0; attempt < 500; attempt += 1) {
        if (predicate()) {
            return;
        }
        await new Promise((resolve) => setTimeout(resolve, 2));
    }
    throw new Error(`timed out waiting for: ${what}`);
}

/** Encode a string as bytes (test-facing alias for readable golden vectors). */
export function bytes(text: string): Uint8Array {
    return new TextEncoder().encode(text);
}

/** Decode bytes as text for readable assertions. */
export function text(data: Uint8Array): string {
    return new TextDecoder().decode(data);
}

/**
 * Capture a promise's rejection value so its fields can be asserted —
 * `expect(...).rejects` matchers return void, not the error.
 */
export async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
    try {
        await promise;
    } catch (e) {
        return e;
    }
    throw new Error("expected the promise to reject, but it resolved");
}
