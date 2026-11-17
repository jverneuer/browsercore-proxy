/**
 * tunnelTransport tests — the leftover-replay wrapper and its delegation.
 */

import { describe, expect, it } from "vitest";
import { tunnelTransport } from "../src/tunnel.js";
import { MemoryTransport, bytes } from "./helpers.js";

describe("tunnelTransport", () => {
    it("returns the transport itself when there are no leftovers", () => {
        const transport = new MemoryTransport("t");
        expect(tunnelTransport(transport, new Uint8Array(0))).toBe(transport);
    });

    it("replays leftover bytes on the first read, then delegates", async () => {
        const transport = new MemoryTransport("t");
        const tunneled = tunnelTransport(transport, bytes("EARLY"));

        expect(tunneled).not.toBe(transport);
        expect(tunneled.id).toBe("t");

        await expect(tunneled.read()).resolves.toEqual(bytes("EARLY"));
        transport.deliver(bytes("NEXT"));
        await expect(tunneled.read()).resolves.toEqual(bytes("NEXT"));
    });

    it("delegates writes, close, and state to the underlying transport", async () => {
        const transport = new MemoryTransport("t");
        const tunneled = tunnelTransport(transport, bytes("X"));

        await tunneled.write(bytes("ping"));
        expect(transport.writes).toEqual([bytes("ping")]);

        expect(tunneled.state).toBe(transport.state);
        await tunneled.close({ kind: "client_close" });
        expect(transport.state).toEqual({ state: "closed", reason: { kind: "client_close" } });
    });

    it("forwards on()/once() event subscriptions to the underlying transport", () => {
        const transport = new MemoryTransport("t");
        const tunneled = tunnelTransport(transport, bytes("X"));

        const seen: unknown[] = [];
        tunneled.on("data", (data) => seen.push(["on", data]));
        tunneled.once("error", (error) => seen.push(["once", error]));

        transport.emitTest("data", bytes("d"));
        const boom = new Error("b");
        transport.emitTest("error", boom);
        transport.emitTest("error", boom); // once fires only once

        expect(seen).toEqual([["on", bytes("d")], ["once", boom]]);
    });

    it("delegates the full canonical event surface to the underlying transport", () => {
        const transport = new MemoryTransport("t");
        const tunneled = tunnelTransport(transport, bytes("X"));

        const seen: unknown[] = [];
        const listener = (): void => {
            seen.push("hit");
        };
        tunneled.on("custom", listener);

        expect(tunneled.listenerCount("custom")).toBe(1);
        expect(tunneled.emit("custom")).toBe(true);
        expect(seen).toEqual(["hit"]);

        tunneled.off("custom", listener);
        expect(tunneled.listenerCount("custom")).toBe(0);
        expect(tunneled.emit("custom")).toBe(false);

        tunneled.on("custom", listener);
        tunneled.once("custom", listener);
        tunneled.removeListener("custom", listener);
        expect(tunneled.listenerCount("custom")).toBe(0);

        tunneled.on("custom", listener);
        tunneled.removeAllListeners("custom");
        expect(tunneled.listenerCount("custom")).toBe(0);

        tunneled.on("custom", listener);
        tunneled.removeAllListeners();
        expect(transport.listenerCount("custom")).toBe(0);
    });
});
