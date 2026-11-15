/**
 * Barrel test — the public API surface is re-exported and nameable.
 */

import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";

describe("@browsercore/proxy public API", () => {
    it("exports the documented surface", () => {
        expect(typeof api.parseProxyUrl).toBe("function");
        expect(typeof api.establishSocks5Tunnel).toBe("function");
        expect(typeof api.establishHttpConnectTunnel).toBe("function");
        expect(typeof api.connectViaProxy).toBe("function");
        expect(typeof api.validateSocks5Credentials).toBe("function");
        expect(typeof api.socks5ReplyMeaning).toBe("function");
        expect(typeof api.ensureProxyError).toBe("function");
        for (const errorClass of [
            api.ProxyError,
            api.ProxyConfigError,
            api.ProxyAuthError,
            api.ProxyTunnelError,
            api.ProxyHandshakeError,
        ]) {
            expect(typeof errorClass).toBe("function");
        }
    });

    it("maps every documented SOCKS5 reply meaning", () => {
        const all = Array.from({ length: 9 }, (_, i) => api.socks5ReplyMeaning(i));
        expect(all[0]).toBe("unassigned reply code"); // 0 is success, never an error meaning
        expect(all.slice(1)).toEqual([
            "general SOCKS server failure",
            "connection not allowed by ruleset",
            "network unreachable",
            "host unreachable",
            "connection refused",
            "TTL expired",
            "command not supported",
            "address type not supported",
        ]);
    });
});
