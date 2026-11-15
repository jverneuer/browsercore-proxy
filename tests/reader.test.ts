/**
 * TransportReader tests — chunk reassembly, delimiter scanning, leftover
 * preservation, and failure wrapping.
 */

import { describe, expect, it } from "vitest";
import { createTransportReader } from "../src/reader.js";
import { ProxyHandshakeError } from "../src/index.js";
import { MemoryTransport, bytes, rejectionOf } from "./helpers.js";

describe("createTransportReader", () => {
    it("reads exact counts across multiple chunks", async () => {
        const transport = new MemoryTransport("t");
        const reader = createTransportReader(transport);

        transport.deliver(bytes("ab"));
        transport.deliver(bytes("cd"));
        transport.deliver(bytes("ef"));

        await expect(reader.readExact(4)).resolves.toEqual(bytes("abcd"));
        await expect(reader.readExact(2)).resolves.toEqual(bytes("ef"));
    });

    it("waits for more bytes when the buffer is short", async () => {
        const transport = new MemoryTransport("t");
        const reader = createTransportReader(transport);

        const pending = reader.readExact(3);
        transport.deliver(bytes("xy"));
        transport.deliver(bytes("z"));
        await expect(pending).resolves.toEqual(bytes("xyz"));
    });

    it("reads until a delimiter that spans chunks", async () => {
        const transport = new MemoryTransport("t");
        const reader = createTransportReader(transport);

        const pending = reader.readUntilDelimiter(bytes("\r\n\r\n"), 1024);
        transport.deliver(bytes("HTTP/1.1 200 OK\r"));
        transport.deliver(bytes("\nX: 1\r\n\r"));
        transport.deliver(bytes("\nAFTER"));

        await expect(pending).resolves.toEqual(bytes("HTTP/1.1 200 OK\r\nX: 1\r\n\r\n"));
        await expect(reader.remaining()).toEqual(bytes("AFTER"));
    });

    it("returns the delimiter-inclusive head from already-buffered bytes", async () => {
        const transport = new MemoryTransport("t");
        const reader = createTransportReader(transport);
        transport.deliver(bytes("abc\r\n\r\nrest"));

        await expect(reader.readUntilDelimiter(bytes("\r\n\r\n"), 1024)).resolves.toEqual(bytes("abc\r\n\r\n"));
        await expect(reader.remaining()).toEqual(bytes("rest"));
    });

    it("throws ProxyHandshakeError when maxBytes is exceeded without a delimiter", async () => {
        const transport = new MemoryTransport("t");
        const reader = createTransportReader(transport);
        transport.deliver(new Uint8Array(2048).fill(0x41));

        await expect(reader.readUntilDelimiter(bytes("\r\n\r\n"), 1024)).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("wraps transport read failures in ProxyHandshakeError with the cause", async () => {
        const transport = new MemoryTransport("t");
        const reader = createTransportReader(transport);

        const pending = reader.readExact(2);
        const reset = new Error("ECONNRESET");
        transport.fail(reset);

        const failure = await rejectionOf(pending) as ProxyHandshakeError;
        expect(failure).toBeInstanceOf(ProxyHandshakeError);
        expect(failure.cause).toBe(reset);
    });

    it("wraps non-Error read rejections without crashing", async () => {
        // Hostile/buggy transports may reject with anything — the reader must
        // still produce a typed error.
        const hostile: Pick<MemoryTransport, "read"> = {
            read(): Promise<Uint8Array> {
                return Promise.reject("kaboom");
            },
        };
        const reader = createTransportReader(hostile as MemoryTransport);

        const failure = await rejectionOf(reader.readExact(1)) as ProxyHandshakeError;
        expect(failure).toBeInstanceOf(ProxyHandshakeError);
        expect(failure.message).toContain("kaboom");
        expect(failure.cause).toBeInstanceOf(Error);
        expect(failure.cause?.message).toBe("kaboom");
    });
});
