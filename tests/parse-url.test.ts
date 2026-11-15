/**
 * parseProxyUrl table tests — the configuration boundary.
 */

import { describe, expect, it } from "vitest";
import { ProxyConfigError, parseProxyUrl } from "../src/index.js";

describe("parseProxyUrl — accepted URLs", () => {
    it.each([
        {
            url: "socks5://proxy.example.com:1080",
            expected: { scheme: "socks5", host: "proxy.example.com", port: 1080 },
        },
        {
            url: "socks5h://user:pass@127.0.0.1:1080",
            expected: { scheme: "socks5h", host: "127.0.0.1", port: 1080, username: "user", password: "pass" },
        },
        {
            url: "http://proxy.internal:8080",
            expected: { scheme: "http", host: "proxy.internal", port: 8080 },
        },
        { url: "http://proxy.internal", expected: { scheme: "http", host: "proxy.internal", port: 80 } },
        { url: "socks5://p.example", expected: { scheme: "socks5", host: "p.example", port: 1080 } },
        { url: "socks5h://p.example", expected: { scheme: "socks5h", host: "p.example", port: 1080 } },
        {
            url: "SOCKS5://Proxy.Example.COM:1080",
            expected: { scheme: "socks5", host: "proxy.example.com", port: 1080 },
        },
        {
            url: "http://[::1]:8080",
            expected: { scheme: "http", host: "::1", port: 8080 },
        },
        {
            url: "socks5://user@proxy.example:1080",
            expected: { scheme: "socks5", host: "proxy.example", port: 1080, username: "user" },
        },
        {
            url: "http://us%40er:p%40ss@proxy:8080",
            expected: { scheme: "http", host: "proxy", port: 8080, username: "us@er", password: "p@ss" },
        },
    ])("parses $url", ({ url, expected }) => {
        expect(parseProxyUrl(url)).toEqual(expected);
    });
});

describe("parseProxyUrl — rejected URLs", () => {
    it.each([
        ["not a url at all"],
        [""],
        ["proxy.example.com:1080"], // no scheme
        ["ftp://proxy:21"], // unsupported scheme
        ["https://proxy:443"], // https deliberately unsupported in v0.1.0
        ["http://"], // empty host
        ["http://proxy:0"], // port below range
        ["http://proxy:65536"], // port above range (rejected by URL or schema)
        ["http://user%zz@proxy:80"], // malformed percent-encoding
    ])("throws ProxyConfigError for %s", (url) => {
        expect(() => parseProxyUrl(url)).toThrow(ProxyConfigError);
    });

    it("includes Zod issue details for schema violations", () => {
        let failure: ProxyConfigError | undefined;
        try {
            parseProxyUrl("http://proxy:0");
        } catch (e) {
            failure = e as ProxyConfigError;
        }
        expect(failure).toBeInstanceOf(ProxyConfigError);
        expect(failure?.details["issues"]).toBeInstanceOf(Array);
    });
});
