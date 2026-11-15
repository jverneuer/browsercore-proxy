/**
 * connectViaProxy tests — platform dispatch, scheme routing, and the
 * socks5/socks5h DNS split. Driven entirely through a FakeSocket platform.
 */

import { describe, expect, it } from "vitest";
import type { Network } from "@browsercore/contracts";
import {
    ProxyAuthError,
    ProxyError,
    ProxyTunnelError,
    connectViaProxy,
    parseProxyUrl,
} from "../src/index.js";
import {
    FakeSocket,
    bytes,
    emptyDns,
    rejectionOf,
    scriptedDns,
    testNetwork,
    testPlatform,
    text,
    waitFor,
} from "./helpers.js";

const target = { host: "example.com", port: 443 };

function connectCounting(socket: FakeSocket): { network: Network; dialCount: () => number } {
    let dials = 0;
    const tcp = {
        connect(): FakeSocket {
            dials += 1;
            return socket;
        },
    };
    return { network: testNetwork(tcp), dialCount: () => dials };
}

describe("connectViaProxy — scheme dispatch", () => {
    it("runs HTTP CONNECT over the dialed socket (http scheme)", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const tunnel = connectViaProxy(parseProxyUrl("http://proxy.internal:8080"), target, testPlatform(network));

        await waitFor(() => socket.written.length >= 1, "CONNECT request");
        expect(text(socket.written[0] ?? new Uint8Array())).toContain("CONNECT example.com:443 HTTP/1.1");
        socket.pushData(bytes("HTTP/1.1 200 Connection established\r\n\r\n"));

        await expect(tunnel).resolves.toBeDefined();
    });

    it("sends Proxy-Authorization when the URL carries credentials", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const tunnel = connectViaProxy(
            parseProxyUrl("http://user:pass@proxy.internal:8080"),
            target,
            testPlatform(network),
        );

        await waitFor(() => socket.written.length >= 1, "CONNECT request");
        expect(text(socket.written[0] ?? new Uint8Array())).toContain("Proxy-Authorization: Basic dXNlcjpwYXNz");
        socket.pushData(bytes("HTTP/1.1 200 OK\r\n\r\n"));
        await expect(tunnel).resolves.toBeDefined();
    });

    it("resolves the target locally for socks5 and sends the resolved IP", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const dns = scriptedDns("203.0.113.7");
        const tunnel = connectViaProxy(
            parseProxyUrl("socks5://proxy.internal:1080"),
            target,
            testPlatform({ ...network, dns }),
        );

        await waitFor(() => socket.written.length >= 1, "SOCKS5 greeting");
        expect(socket.written[0]).toEqual(Uint8Array.from([0x05, 0x01, 0x00]));
        socket.pushData(Uint8Array.of(0x05, 0x00));

        await waitFor(() => socket.written.length >= 2, "SOCKS5 CONNECT request");
        expect(socket.written[1]).toEqual(Uint8Array.from([
            0x05, 0x01, 0x00, 0x01,
            203, 0, 113, 7, // resolved by the injected DNS, not sent as a name
            0x01, 0xbb,
        ]));
        expect(dns.calls).toEqual(["example.com/4"]);
        socket.pushData(Uint8Array.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        await expect(tunnel).resolves.toBeDefined();
    });

    it("skips DNS for socks5 when the target is already an IP literal", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const dns = scriptedDns();
        const tunnel = connectViaProxy(
            parseProxyUrl("socks5://proxy.internal:1080"),
            { host: "192.0.2.10", port: 80 },
            testPlatform({ ...network, dns }),
        );

        await waitFor(() => socket.written.length >= 1, "greeting");
        socket.pushData(Uint8Array.of(0x05, 0x00));
        await waitFor(() => socket.written.length >= 2, "CONNECT");
        expect(socket.written[1]).toEqual(Uint8Array.from([
            0x05, 0x01, 0x00, 0x01,
            192, 0, 2, 10, // literal target — ATYP 0x01, no DNS
            0x00, 0x50,
        ]));
        expect(dns.calls).toEqual([]); // literal — the resolver was never consulted
        socket.pushData(Uint8Array.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        await expect(tunnel).resolves.toBeDefined();
    });

    it("never resolves locally for socks5h — the hostname goes on the wire", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const dns = scriptedDns();
        const tunnel = connectViaProxy(
            parseProxyUrl("socks5h://proxy.internal:1080"),
            target,
            testPlatform({ ...network, dns }),
        );

        await waitFor(() => socket.written.length >= 1, "greeting");
        socket.pushData(Uint8Array.of(0x05, 0x00));
        await waitFor(() => socket.written.length >= 2, "CONNECT");

        const connectBytes = socket.written[1] ?? new Uint8Array(0);
        expect(connectBytes[3]).toBe(0x03); // ATYP domain
        expect(text(connectBytes.subarray(5, 16))).toBe("example.com");
        expect(dns.calls).toEqual([]);
        socket.pushData(Uint8Array.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        await expect(tunnel).resolves.toBeDefined();
    });

    it("runs RFC 1929 auth for socks5h with URL credentials", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const tunnel = connectViaProxy(
            parseProxyUrl("socks5h://user:pass@proxy.internal:1080"),
            target,
            testPlatform(network),
        );

        await waitFor(() => socket.written.length >= 1, "greeting");
        expect(socket.written[0]).toEqual(Uint8Array.from([0x05, 0x02, 0x00, 0x02]));
        socket.pushData(Uint8Array.of(0x05, 0x02));

        await waitFor(() => socket.written.length >= 2, "auth request");
        socket.pushData(Uint8Array.of(0x01, 0x00));

        await waitFor(() => socket.written.length >= 3, "CONNECT request");
        socket.pushData(Uint8Array.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        await expect(tunnel).resolves.toBeDefined();
    });

    it("propagates typed handshake failures from the SOCKS5 layer", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const tunnel = connectViaProxy(parseProxyUrl("socks5h://proxy:1080"), target, testPlatform(network));

        await waitFor(() => socket.written.length >= 1, "greeting");
        socket.pushData(Uint8Array.of(0x05, 0x00));
        await waitFor(() => socket.written.length >= 2, "CONNECT");
        socket.pushData(Uint8Array.of(0x05, 0x05, 0x00, 0x01)); // connection refused

        const failure = await rejectionOf(tunnel) as ProxyTunnelError;
        expect(failure).toBeInstanceOf(ProxyTunnelError);
        expect(failure.code).toBe(0x05);
    });

    it("propagates typed auth failures from the HTTP layer", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const tunnel = connectViaProxy(
            parseProxyUrl("http://user:pass@proxy:8080"),
            target,
            testPlatform(network),
        );

        await waitFor(() => socket.written.length >= 1, "CONNECT");
        socket.pushData(bytes("HTTP/1.1 407 Denied\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n"));

        const failure = await rejectionOf(tunnel) as ProxyAuthError;
        expect(failure).toBeInstanceOf(ProxyAuthError);
        expect(failure.challenge).toBe('Basic realm="x"');
    });

    it("treats a username-only URL as an empty password (RFC 1929 plen=0)", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const tunnel = connectViaProxy(
            parseProxyUrl("socks5h://justuser@proxy.internal:1080"),
            target,
            testPlatform(network),
        );

        await waitFor(() => socket.written.length >= 1, "greeting");
        socket.pushData(Uint8Array.of(0x05, 0x02)); // proxy demands the offered auth
        await waitFor(() => socket.written.length >= 2, "auth request");

        expect(socket.written[1]).toEqual(Uint8Array.from([
            0x01, 0x08, ...bytes("justuser"),
            0x00, // empty password, zero length
        ]));
        socket.pushData(Uint8Array.of(0x01, 0x00));
        await waitFor(() => socket.written.length >= 3, "CONNECT request");
        socket.pushData(Uint8Array.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        await expect(tunnel).resolves.toBeDefined();
    });

    it("dials exactly one TCP connection per call", async () => {
        const socket = new FakeSocket();
        const { network, dialCount } = connectCounting(socket);
        const tunnel = connectViaProxy(parseProxyUrl("http://proxy:8080"), target, testPlatform(network));
        await waitFor(() => socket.written.length >= 1, "CONNECT");
        socket.pushData(bytes("HTTP/1.1 200 OK\r\n\r\n"));
        await tunnel;

        expect(dialCount()).toBe(1);
    });
});

describe("connectViaProxy — platform requirements", () => {
    it("throws a typed error when the platform has no network.tcp", async () => {
        const network = testNetwork(undefined as never); // a Platform assembled without tcp
        const failure = await rejectionOf(
            connectViaProxy(parseProxyUrl("http://proxy:8080"), target, testPlatform(network)),
        ) as ProxyError;
        expect(failure).toBeInstanceOf(ProxyError);
        expect(failure.kind).toBe("ProxyError");
        expect(String(failure.message)).toContain("network.tcp");
    });

    it("throws a typed error for socks5 with a hostname and no network.dns", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);
        const withoutDns: Network = { ...network, dns: undefined as never };

        const failure = await rejectionOf(
            connectViaProxy(parseProxyUrl("socks5://proxy:1080"), target, testPlatform(withoutDns)),
        ) as ProxyError;
        expect(failure).toBeInstanceOf(ProxyError);
        expect(failure.message).toContain("socks5h");
    });

    it("throws a typed error when DNS resolves to no addresses", async () => {
        const socket = new FakeSocket();
        const { network } = connectCounting(socket);

        const failure = await rejectionOf(
            connectViaProxy(
                parseProxyUrl("socks5://proxy:1080"),
                target,
                testPlatform({ ...network, dns: emptyDns }),
            ),
        ) as ProxyError;
        expect(failure).toBeInstanceOf(ProxyError);
        expect(failure.message).toContain("no addresses");
    });
});
