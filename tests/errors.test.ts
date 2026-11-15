/**
 * Typed error hierarchy tests — kind discriminators, structured fields, and
 * the unknown → ProxyError narrowing helper.
 */

import { describe, expect, it } from "vitest";
import {
    ProxyAuthError,
    ProxyConfigError,
    ProxyError,
    ProxyHandshakeError,
    ProxyTunnelError,
    ensureProxyError,
} from "../src/index.js";

describe("proxy error hierarchy", () => {
    it("carries kind, details, and name on the base class", () => {
        const error = new ProxyError("missing capability", { missing: "network.tcp" });
        expect(error).toBeInstanceOf(Error);
        expect(error.kind).toBe("ProxyError");
        expect(error.name).toBe("ProxyError");
        expect(error.details).toEqual({ missing: "network.tcp" });
    });

    it("preserves a cause for wrapped lower-level failures", () => {
        const cause = new Error("ECONNRESET");
        const error = new ProxyHandshakeError("peer died", { byte: 4 }, { cause });
        expect(error.kind).toBe("ProxyHandshakeError");
        expect(error.name).toBe("ProxyHandshakeError");
        expect(error.cause).toBe(cause);
        expect(error.details).toEqual({ byte: 4 });
    });

    it("discriminates subclasses via kind and instanceof", () => {
        const errors = [
            [new ProxyConfigError("bad url"), "ProxyConfigError"],
            [new ProxyAuthError("407", { scheme: "http", challenge: "Basic" }), "ProxyAuthError"],
            [new ProxyTunnelError("refused", { scheme: "socks5", code: 5, meaning: "connection refused" }), "ProxyTunnelError"],
            [new ProxyHandshakeError("bad bytes"), "ProxyHandshakeError"],
        ] as const;
        for (const [error, expectedKind] of errors) {
            expect(error).toBeInstanceOf(ProxyError);
            expect(error.kind).toBe(expectedKind);
            expect(error.name).toBe(expectedKind);
        }
    });

    it("exposes auth and tunnel fields directly", () => {
        const auth = new ProxyAuthError("407", { scheme: "http", status: 407, challenge: 'Basic realm="x"' });
        expect(auth.scheme).toBe("http");
        expect(auth.challenge).toBe('Basic realm="x"');

        const tunnel = new ProxyTunnelError("refused", { scheme: "socks5", code: 0x05, meaning: "connection refused" });
        expect(tunnel.code).toBe(0x05);
        expect(tunnel.meaning).toBe("connection refused");
        expect(tunnel.details).toEqual({ scheme: "socks5", code: 0x05, meaning: "connection refused" });
    });
});

describe("ensureProxyError", () => {
    it("passes ProxyError instances through unchanged", () => {
        const original = new ProxyConfigError("bad");
        expect(ensureProxyError(original)).toBe(original);
    });

    it("wraps a plain Error, keeping it as cause", () => {
        const original = new Error("boom");
        const wrapped = ensureProxyError(original);
        expect(wrapped).toBeInstanceOf(ProxyError);
        expect(wrapped.message).toBe("boom");
        expect(wrapped.cause).toBe(original);
    });

    it("wraps a string rejection reason", () => {
        expect(ensureProxyError("nope").message).toBe("nope");
    });

    it("wraps non-error values generically", () => {
        expect(ensureProxyError(42).message).toBe("unknown proxy error");
        expect(ensureProxyError({ odd: true }).message).toBe("unknown proxy error");
    });
});
