/**
 * SOCKS5 handshake tests — golden byte sequences both directions.
 *
 * Every test scripts the "proxy" side of a synthetic transport pair and
 * asserts the exact bytes the client writes (greeting, RFC 1929 auth, CONNECT
 * request) plus the typed outcomes for every reply shape.
 */

import { describe, expect, it } from "vitest";
import {
    ProxyAuthError,
    ProxyConfigError,
    ProxyHandshakeError,
    ProxyTunnelError,
    establishSocks5Tunnel,
    socks5ReplyMeaning,
    validateSocks5Credentials,
} from "../src/index.js";
import { bytes, createTransportPair, rejectionOf, text } from "./helpers.js";

const domainTarget = { host: "example.com", port: 443 };

/** Golden CONNECT request bytes for a domain target ("example.com:443"). */
const goldenDomainConnect = Uint8Array.from([
    0x05, 0x01, 0x00, // VER, CMD=CONNECT, RSV
    0x03, 0x0b, ...bytes("example.com"), // ATYP=domain, len=11
    0x01, 0xbb, // port 443
]);

/** Successful reply: VER REP RSV ATYP + BND.ADDR(IPv4) + BND.PORT. */
const successReplyIpv4Bnd = Uint8Array.from([
    0x05, 0x00, 0x00, 0x01,
    192, 0, 2, 1,
    0x00, 0x00,
]);

describe("establishSocks5Tunnel", () => {
    it("performs the no-auth handshake with exact golden bytes (domain target)", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);

        expect([...(await server.read())]).toEqual([0x05, 0x01, 0x00]); // greeting: only method 0x00
        await server.write(Uint8Array.of(0x05, 0x00)); // select no-auth

        expect([...(await server.read())]).toEqual([...goldenDomainConnect]);
        await server.write(successReplyIpv4Bnd);

        const tunneled = await tunnel;
        expect(tunneled).toBe(client); // same transport, returned tunneled
    });

    it("sends IPv4 literals as ATYP 0x01 without DNS", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, { host: "93.184.216.34", port: 80 });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));

        expect([...(await server.read())]).toEqual([
            0x05, 0x01, 0x00, 0x01,
            93, 184, 216, 34,
            0x00, 0x50,
        ]);
        await server.write(successReplyIpv4Bnd);
        await expect(tunnel).resolves.toBe(client);
    });

    it("sends IPv6 literals as ATYP 0x04 (auto mode)", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, { host: "2001:db8::1", port: 443 });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));

        expect([...(await server.read())]).toEqual([
            0x05, 0x01, 0x00, 0x04,
            0x20, 0x01, 0x0d, 0xb8, // 2001:db8
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // five compressed zero groups (10 bytes)
            0x00, 0x01, // :1
            0x01, 0xbb,
        ]);
        await server.write(successReplyIpv4Bnd);
        await expect(tunnel).resolves.toBe(client);
    });

    it("skips a domain BND.ADDR (reads its length prefix) in the reply", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        await server.read();

        await server.write(Uint8Array.from([
            0x05, 0x00, 0x00, 0x03,
            0x09, ...bytes("localhost"),
            0x1f, 0x90,
        ]));
        await expect(tunnel).resolves.toBe(client);
    });

    it("skips a 16-byte IPv6 BND.ADDR in the reply", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        await server.read();

        await server.write(Uint8Array.from([
            0x05, 0x00, 0x00, 0x04,
            ...new Uint8Array(16),
            0x1f, 0x90,
        ]));
        await expect(tunnel).resolves.toBe(client);
    });

    it("reassembles a reply split across arbitrary chunk boundaries", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        await server.read();

        // Head, then BND.ADDR split across pieces, then BND.PORT — chunk
        // boundaries carry no meaning. Post-head bytes total exactly the
        // 4-byte BND.ADDR + 2-byte BND.PORT so nothing spills into the tunnel.
        client.deliver(Uint8Array.of(0x05, 0x00, 0x00, 0x01, 10));
        client.deliver(Uint8Array.of(0, 20, 30));
        client.deliver(Uint8Array.of(0x00, 0x50));
        await expect(tunnel).resolves.toBe(client);
    });

    it("preserves early tunnel bytes that arrived with the reply", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        await server.read();

        const early = bytes("EARLY-TARGET-DATA");
        client.deliver(Uint8Array.from([...successReplyIpv4Bnd, ...early]));

        const tunneled = await tunnel;
        expect(tunneled).not.toBe(client); // wrapped, because leftovers exist
        expect(text(await tunneled.read())).toBe("EARLY-TARGET-DATA");
        // After the replay, reads pass through to the underlying transport.
        client.deliver(bytes("NEXT"));
        await expect(tunneled.read()).resolves.toEqual(bytes("NEXT"));
    });

    it("runs RFC 1929 username/password auth when the proxy selects method 0x02", async () => {
        const { client, server } = createTransportPair();
        const credentials = { username: "user", password: "pass" };
        const tunnel = establishSocks5Tunnel(client, domainTarget, credentials);

        expect([...(await server.read())]).toEqual([0x05, 0x02, 0x00, 0x02]); // both methods offered
        await server.write(Uint8Array.of(0x05, 0x02)); // proxy picks user/pass

        expect([...(await server.read())]).toEqual([
            0x01, 0x04, ...bytes("user"),
            0x04, ...bytes("pass"),
        ]);
        await server.write(Uint8Array.of(0x01, 0x00)); // auth OK

        expect([...(await server.read())]).toEqual([...goldenDomainConnect]);
        await server.write(successReplyIpv4Bnd);
        await expect(tunnel).resolves.toBe(client);
    });

    it("proceeds without auth when the proxy selects 0x00 despite offered credentials", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget, { username: "u", password: "p" });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00)); // proxy: no auth needed

        expect([...(await server.read())]).toEqual([...goldenDomainConnect]);
        await server.write(successReplyIpv4Bnd);
        await expect(tunnel).resolves.toBe(client);
    });

    it("rejects the handshake when the proxy answers 0xFF (no acceptable methods)", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget, { username: "u", password: "p" });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0xff));

        const failure = await rejectionOf(tunnel) as ProxyAuthError;
        expect(failure).toBeInstanceOf(ProxyAuthError);
        expect(failure.scheme).toBe("socks5");
    });

    it("rejects when the proxy demands auth but none is configured", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x02));

        await expect(tunnel).rejects.toThrow(/no credentials were configured/);
        await expect(tunnel).rejects.toBeInstanceOf(ProxyAuthError);
    });

    it("rejects RFC 1929 auth failure status", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget, { username: "u", password: "bad" });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x02));
        await server.read();
        await server.write(Uint8Array.of(0x01, 0x01)); // auth failed

        const failure = await rejectionOf(tunnel) as ProxyAuthError;
        expect(failure).toBeInstanceOf(ProxyAuthError);
        expect(failure.scheme).toBe("socks5");
    });

    it("rejects a wrong RFC 1929 version byte in the auth reply", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget, { username: "u", password: "p" });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x02));
        await server.read();
        await server.write(Uint8Array.of(0x02, 0x00));

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("rejects a wrong version in the method-selection reply", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x04, 0x00)); // SOCKS4?

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("rejects a method byte that was never offered", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x01)); // GSSAPI, unoffered

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("rejects a wrong version in the CONNECT reply", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        await server.read();
        await server.write(Uint8Array.from([0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("rejects an unknown ATYP in the CONNECT reply", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00, 0x00, 0x02)); // ATYP 0x02 is not defined

        await expect(tunnel).rejects.toBeInstanceOf(ProxyHandshakeError);
    });

    it("maps reply codes 1-8 to ProxyTunnelError with RFC 1928 meanings", async () => {
        const meanings: ReadonlyArray<readonly [number, string]> = [
            [0x01, "general SOCKS server failure"],
            [0x02, "connection not allowed by ruleset"],
            [0x03, "network unreachable"],
            [0x04, "host unreachable"],
            [0x05, "connection refused"],
            [0x06, "TTL expired"],
            [0x07, "command not supported"],
            [0x08, "address type not supported"],
        ];
        for (const [code, meaning] of meanings) {
            const { client, server } = createTransportPair();
            const tunnel = establishSocks5Tunnel(client, domainTarget);
            await server.read();
            await server.write(Uint8Array.of(0x05, 0x00));
            await server.read();
            await server.write(Uint8Array.of(0x05, code, 0x00, 0x01));

            const failure = await rejectionOf(tunnel) as ProxyTunnelError;
            expect(failure).toBeInstanceOf(ProxyTunnelError);
            expect(failure.code).toBe(code);
            expect(failure.meaning).toBe(meaning);
            expect(socks5ReplyMeaning(code)).toBe(meaning);
        }
    });

    it("labels unassigned reply codes as such", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x7f, 0x00, 0x01));

        const failure = await rejectionOf(tunnel) as ProxyTunnelError;
        expect(failure).toBeInstanceOf(ProxyTunnelError);
        expect(failure.meaning).toBe("unassigned reply code");
    });

    it("wraps a peer that dies mid-reply in ProxyHandshakeError with cause", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget);
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        await server.read();
        client.deliver(Uint8Array.of(0x05, 0x00, 0x00, 0x01)); // truncated head
        // Let the handshake issue its next read before killing the stream, so
        // the rejection carries the socket error rather than a closed-state error.
        await new Promise((resolve) => setTimeout(resolve, 1));
        const reset = new Error("ECONNRESET");
        client.fail(reset);

        const failure = await rejectionOf(tunnel) as ProxyHandshakeError;
        expect(failure).toBeInstanceOf(ProxyHandshakeError);
        expect(failure.cause).toBe(reset);
    });
});

describe("establishSocks5Tunnel — atyp modes", () => {
    it('atyp "domain" sends a domain even for an IP literal', async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, { host: "192.0.2.9", port: 80 }, undefined, { atyp: "domain" });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));

        expect([...(await server.read())]).toEqual([
            0x05, 0x01, 0x00, 0x03, 0x09,
            ...bytes("192.0.2.9"),
            0x00, 0x50,
        ]);
        await server.write(successReplyIpv4Bnd);
        await expect(tunnel).resolves.toBe(client);
    });

    it('atyp "ipv4" rejects a non-literal host', async () => {
        const { client } = createTransportPair();
        await expect(
            establishSocks5Tunnel(client, domainTarget, undefined, { atyp: "ipv4" }),
        ).rejects.toBeInstanceOf(ProxyConfigError);
    });

    it('atyp "ipv4" sends a literal as ATYP 0x01', async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, { host: "192.0.2.9", port: 80 }, undefined, { atyp: "ipv4" });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        expect([...(await server.read())]).toEqual([
            0x05, 0x01, 0x00, 0x01, 192, 0, 2, 9, 0x00, 0x50,
        ]);
        await server.write(successReplyIpv4Bnd);
        await expect(tunnel).resolves.toBe(client);
    });

    it('atyp "ipv6" rejects a non-literal host', async () => {
        const { client } = createTransportPair();
        await expect(
            establishSocks5Tunnel(client, domainTarget, undefined, { atyp: "ipv6" }),
        ).rejects.toBeInstanceOf(ProxyConfigError);
    });

    it('atyp "ipv6" sends a literal as ATYP 0x04', async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, { host: "::1", port: 443 }, undefined, { atyp: "ipv6" });
        await server.read();
        await server.write(Uint8Array.of(0x05, 0x00));
        const request = await server.read();
        expect(request[3]).toBe(0x04);
        expect(request.length).toBe(4 + 16 + 2);
        await server.write(successReplyIpv4Bnd);
        await expect(tunnel).resolves.toBe(client);
    });

    it("rejects a domain name longer than 255 bytes", async () => {
        const { client } = createTransportPair();
        const longHost = `${"a".repeat(64)}.${"b".repeat(64)}.${"c".repeat(64)}.${"d".repeat(64)}.example.com`; // 270 bytes
        await expect(
            establishSocks5Tunnel(client, { host: longHost, port: 443 }),
        ).rejects.toBeInstanceOf(ProxyConfigError);
    });
});

describe("validateSocks5Credentials", () => {
    it("accepts plain credentials", () => {
        expect(() => validateSocks5Credentials({ username: "user", password: "pass" })).not.toThrow();
    });

    it("rejects a NUL byte in the username before any bytes hit the wire", () => {
        expect(() => validateSocks5Credentials({ username: "us\u0000er", password: "p" }))
            .toThrow(ProxyConfigError);
    });

    it("rejects a NUL byte in the password", () => {
        expect(() => validateSocks5Credentials({ username: "u", password: "pa\u0000ss" }))
            .toThrow(ProxyConfigError);
    });

    it("rejects a 256-byte username (one-byte length prefix)", () => {
        expect(() => validateSocks5Credentials({ username: "u".repeat(256), password: "p" }))
            .toThrow(ProxyConfigError);
    });

    it("rejects a 256-byte password", () => {
        expect(() => validateSocks5Credentials({ username: "u", password: "p".repeat(256) }))
            .toThrow(ProxyConfigError);
    });

    it("accepts a 255-byte field — the boundary value", () => {
        expect(() => validateSocks5Credentials({ username: "u".repeat(255), password: "" })).not.toThrow();
    });

    it("validates before the greeting is written (no bytes consumed)", async () => {
        const { client, server } = createTransportPair();
        const tunnel = establishSocks5Tunnel(client, domainTarget, { username: "u\u0000", password: "p" });
        await expect(tunnel).rejects.toBeInstanceOf(ProxyConfigError);
        expect(server.writes).toEqual([]); // nothing was sent to the proxy
    });
});
