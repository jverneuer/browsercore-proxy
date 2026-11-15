/**
 * HTTP CONNECT handshake tests — exact request bytes, status-line handling,
 * header parsing, and every failure classification.
 */

import { describe, expect, it } from "vitest";
import {
    ProxyAuthError,
    ProxyHandshakeError,
    ProxyTunnelError,
    establishHttpConnectTunnel,
} from "../src/index.js";
import { bytes, createTransportPair, rejectionOf, text } from "./helpers.js";

const target = { host: "example.com", port: 443 };

describe("establishHttpConnectTunnel", () => {
    it("sends the exact CONNECT request (no credentials)", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);

        const request = await server.read();
        expect(text(request)).toBe(
            "CONNECT example.com:443 HTTP/1.1\r\n" +
            "Host: example.com:443\r\n" +
            "Proxy-Connection: keep-alive\r\n" +
            "\r\n",
        );
        await server.write(bytes("HTTP/1.1 200 Connection established\r\n\r\n"));
        await expect(tunnel).resolves.toBe(client);
    });

    it("adds Basic Proxy-Authorization only when credentials are present", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target, { username: "user", password: "pass" });

        const request = await server.read();
        expect(text(request)).toBe(
            "CONNECT example.com:443 HTTP/1.1\r\n" +
            "Host: example.com:443\r\n" +
            "Proxy-Connection: keep-alive\r\n" +
            "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" + // base64("user:pass")
            "\r\n",
        );
        await server.write(bytes("HTTP/1.1 200 OK\r\n\r\n"));
        await expect(tunnel).resolves.toBe(client);
    });

    it("establishes the tunnel on 200 and preserves early target bytes", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        client.deliver(bytes("HTTP/1.1 200 Connection established\r\n\r\nEARLY-BYTES"));

        const tunneled = await tunnel;
        expect(tunneled).not.toBe(client);
        expect(text(await tunneled.read())).toBe("EARLY-BYTES");
    });

    it("reassembles a response head split across chunks", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        client.deliver(bytes("HTTP/1.1 200 Conn"));
        client.deliver(bytes("ection established\r\nVia: h1\r"));
        client.deliver(bytes("\n\r\n"));
        await expect(tunnel).resolves.toBe(client);
    });

    it("accepts any 2xx, not just 200", async () => {
        for (const status of [201, 204]) {
            const { client, server } = createTransportPair();
            const tunnel = establishHttpConnectTunnel(client, target);
            await server.read();
            await server.write(bytes(`HTTP/1.1 ${status} Fine\r\n\r\n`));
            await expect(tunnel).resolves.toBe(client);
        }
    });

    it("tolerates HTTP/1.0 status lines", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes("HTTP/1.0 200 OK\r\n\r\n"));
        await expect(tunnel).resolves.toBe(client);
    });

    it("matches header names case-insensitively (407 challenge)", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target, { username: "u", password: "p" });
        await server.read();
        await server.write(bytes(
            'HTTP/1.1 407 Proxy Authentication Required\r\n' +
            'PROXY-AUTHENTICATE: Basic realm="corp"\r\n' +
            '\r\n',
        ));

        const failure = await rejectionOf(tunnel) as ProxyAuthError;
        expect(failure).toBeInstanceOf(ProxyAuthError);
        expect(failure.scheme).toBe("http");
        expect(failure.challenge).toBe('Basic realm="corp"');
    });

    it("raises ProxyAuthError without a challenge when 407 omits Proxy-Authenticate", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes("HTTP/1.1 407 Unauthorized\r\n\r\n"));

        const failure = await rejectionOf(tunnel) as ProxyAuthError;
        expect(failure).toBeInstanceOf(ProxyAuthError);
        expect(failure.challenge).toBeUndefined();
    });

    it("keeps the first occurrence of a repeated header", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes(
            'HTTP/1.1 407 No\r\n' +
            'Proxy-Authenticate: Basic realm="first"\r\n' +
            'Proxy-Authenticate: Basic realm="second"\r\n' +
            '\r\n',
        ));

        const failure = await rejectionOf(tunnel) as ProxyAuthError;
        expect(failure.challenge).toBe('Basic realm="first"');
    });

    it("raises ProxyTunnelError for non-2xx statuses with status and reason", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes("HTTP/1.1 502 Bad Gateway\r\n\r\n"));

        const failure = await rejectionOf(tunnel) as ProxyTunnelError;
        expect(failure).toBeInstanceOf(ProxyTunnelError);
        expect(failure.scheme).toBe("http");
        expect(failure.code).toBe(502);
        expect(failure.meaning).toBe("Bad Gateway");
    });

    it("raises ProxyTunnelError for 3xx/4xx (non-407) statuses", async () => {
        for (const status of [301, 403, 404]) {
            const { client, server } = createTransportPair();
            const tunnel = establishHttpConnectTunnel(client, target);
            await server.read();
            await server.write(bytes(`HTTP/1.1 ${status} No Tunnel\r\n\r\n`));
            const failure = await rejectionOf(tunnel) as ProxyTunnelError;
            expect(failure).toBeInstanceOf(ProxyTunnelError);
            expect(failure.code).toBe(status);
        }
    });

    it("raises ProxyHandshakeError for a garbage status line", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes("not-http-at-all\r\n\r\n"));

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("raises ProxyHandshakeError for a non-HTTP/1.x version", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes("HTTP/2 200 OK\r\n\r\n"));

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("raises ProxyHandshakeError for HTTP/1.9 (outside the accepted pair)", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes("HTTP/1.9 200 OK\r\n\r\n"));

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("tolerates junk header lines without a colon", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes("HTTP/1.1 200 OK\r\nnonsense-line\r\nX-A: 1\r\n\r\n"));
        await expect(tunnel).resolves.toBe(client);
    });

    it("accepts a status line with no reason phrase", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        await server.write(bytes("HTTP/1.1 204\r\n\r\n"));
        await expect(tunnel).resolves.toBe(client);
    });

    it("rejects a response head that exceeds the size cap without terminating", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        client.deliver(new Uint8Array(70_000).fill(0x58)); // "XXXX..." forever

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("wraps a peer that dies mid-response-head with a cause", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishHttpConnectTunnel(client, target);
        await server.read();
        client.deliver(bytes("HTTP/1.1 200 half")); // no terminator yet
        // Let the reader issue its next read before killing the stream, so the
        // rejection carries the socket error rather than a closed-state error.
        await new Promise((resolve) => setTimeout(resolve, 1));
        const reset = new Error("socket hang up");
        client.fail(reset);

        const failure = await rejectionOf(tunnel) as ProxyHandshakeError;
        expect(failure).toBeInstanceOf(ProxyHandshakeError);
        expect(failure.cause).toBe(reset);
    });
});
