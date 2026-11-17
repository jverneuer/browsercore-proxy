/**
 * SocketTransport adapter tests — the Socket → Transport bridge used by
 * connectViaProxy. Covers the write/read lifecycle, error paths, and event
 * translation.
 */

import { describe, expect, it } from "vitest";
import { ProxyError } from "../src/index.js";
import { createSocketTransport } from "../src/socket-transport.js";
import { FakeSocket, bytes, closeKindOf, rejectionOf } from "./helpers.js";

describe("createSocketTransport", () => {
    it("resolves writes from the socket callback and stays open", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);

        await transport.write(bytes("hello"));
        expect(socket.written).toEqual([bytes("hello")]);
        expect(transport.state).toEqual({ state: "open" });
    });

    it("rejects a write whose socket callback reports an error, with cause", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        socket.nextWriteError = new Error("EPIPE");

        const failure = await rejectionOf(transport.write(bytes("x"))) as ProxyError;
        expect(failure).toBeInstanceOf(ProxyError);
        expect(failure.cause).toBeInstanceOf(Error);
    });

    it("resolves a write whose callback fires with no argument at all", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        socket.bareWriteCallback = true;
        await expect(transport.write(bytes("x"))).resolves.toBeUndefined();
    });

    it("rejects writes after close", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        await transport.close({ kind: "client_close" });

        await expect(transport.write(bytes("x"))).rejects.toBeInstanceOf(ProxyError);
    });

    it("resolves queued reads in FIFO order", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        socket.pushData(bytes("one"));
        socket.pushData(bytes("two"));

        await expect(transport.read()).resolves.toEqual(bytes("one"));
        await expect(transport.read()).resolves.toEqual(bytes("two"));
    });

    it("resolves a pending read when data arrives", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);

        const pending = transport.read();
        socket.pushData(bytes("later"));
        await expect(pending).resolves.toEqual(bytes("later"));
    });

    it("rejects reads after the socket closed remotely", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        socket.emitCustom("close", false);

        expect(transport.state).toEqual({ state: "closed", reason: { kind: "remote_close" } });
        await expect(transport.read()).rejects.toBeInstanceOf(ProxyError);
    });

    it("rejects a pending read when the socket closes", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);

        const pending = transport.read();
        socket.emitCustom("close", true); // close-after-error

        await expect(pending).rejects.toBeInstanceOf(ProxyError);
        expect(transport.state.state).toBe("closed");
    });

    it("closes the transport with an error reason on a socket error", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);

        const boom = new Error("boom");
        socket.destroy(boom); // emits error then close

        expect(transport.state).toEqual({ state: "closed", reason: { kind: "error", error: boom } });
        expect(socket.destroyed).toBe(true);
        await expect(transport.read()).rejects.toBeInstanceOf(ProxyError);
    });

    it("ignores a second close after an error finalized the state", () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        socket.destroy(new Error("first"));
        socket.emitCustom("close", true); // the close event following the error

        expect(transport.state.state).toBe("closed");
    });

    it("ends the socket on close() and stays idempotent", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        let closeSeen: string | undefined;
        transport.on("close", (reason) => {
            closeSeen = closeKindOf(reason);
        });

        await transport.close();
        await transport.close(); // second close is a no-op

        expect(socket.written).toEqual([]);
        // end() produced the socket-level close event; subscribers see it
        // translated (benign close → remote_close).
        expect(closeSeen).toBe("remote_close");
    });

    it("defaults to a client_close reason when close() gets no argument", async () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        await transport.close();
        expect(transport.state).toEqual({ state: "closed", reason: { kind: "client_close" } });
    });

    it("ignores data arriving after close (state stays final)", () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);
        socket.emitCustom("close", false);
        socket.pushData(bytes("late"));
        expect(transport.state).toEqual({ state: "closed", reason: { kind: "remote_close" } });
    });

    it("forwards data and error events to on()/once() subscribers", () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);

        const seen: unknown[] = [];
        transport.on("data", (chunk) => seen.push(["on-data", chunk]));
        transport.once("data", (chunk) => seen.push(["once-data", chunk]));
        const boom = new Error("evt");
        transport.once("error", (error) => seen.push(["once-error", error]));

        socket.pushData(bytes("a"));
        socket.pushData(bytes("b"));
        socket.emitCustom("error", boom);

        expect(seen).toEqual([
            ["once-data", bytes("a")], // one-shot listeners dispatch first (fixture ordering)
            ["on-data", bytes("a")],
            ["on-data", bytes("b")], // once fired only for the first event
            ["once-error", boom],
        ]);
    });

    it("translates socket close events into CloseReason values for on()/once()", () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);

        const reasons: string[] = [];
        transport.on("close", (reason) => reasons.push(`on:${closeKindOf(reason)}`));
        transport.once("close", (reason) => reasons.push(`once:${closeKindOf(reason)}`));

        socket.emitCustom("close", true);
        socket.emitCustom("close", false);

        // One-shot listeners dispatch first and, like persistent ones, see
        // the true translated reason — close-after-error is an error.
        expect(reasons).toEqual(["once:error", "on:error", "on:remote_close"]);
    });

    it("serves the full canonical event surface: emit, off, counts, removeAllListeners", () => {
        const socket = new FakeSocket();
        const transport = createSocketTransport(socket);

        const seen: unknown[] = [];
        const first = (): void => {
            seen.push("first");
        };
        const second = (): void => {
            seen.push("second");
        };
        transport.on("custom", first);
        transport.on("custom", second);

        expect(transport.listenerCount("custom")).toBe(2);
        expect(transport.emit("custom")).toBe(true);
        expect(seen).toEqual(["first", "second"]);

        transport.off("custom", first);
        expect(transport.listenerCount("custom")).toBe(1);

        transport.removeListener("custom", second);
        expect(transport.listenerCount("custom")).toBe(0);
        expect(transport.emit("custom")).toBe(false);

        // Removal also covers one-shot registrations before they fire.
        const never: () => void = () => seen.push("never");
        transport.once("data", never);
        transport.removeAllListeners("data");
        socket.pushData(bytes("x"));
        expect(seen).toEqual(["first", "second"]);

        // Untargeted removeAllListeners() clears every event at once.
        transport.on("data", never);
        transport.on("close", never);
        transport.removeAllListeners();
        expect(transport.listenerCount("data")).toBe(0);
        expect(transport.listenerCount("close")).toBe(0);
    });
});
