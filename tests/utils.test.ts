/**
 * Utility tests — base64 vectors, IP literal parsing (the runtime-free
 * replacements for node:net helpers), and byte helpers.
 */

import { describe, expect, it } from "vitest";
import { concatBytes, encodeBase64, isIpLiteral, parseIpv4Address, parseIpv6Address } from "../src/utils.js";
import { bytes } from "./helpers.js";

describe("encodeBase64", () => {
    it.each([
        ["", ""], // 0 bytes → empty, no padding
        ["f", "Zg=="],
        ["fo", "Zm8="],
        ["foo", "Zm9v"],
        ["foob", "Zm9vYg=="],
        ["fooba", "Zm9vYmE="],
        ["foobar", "Zm9vYmFy"],
        ["user:pass", "dXNlcjpwYXNz"],
    ])("encodes %s → %s", (input, expected) => {
        expect(encodeBase64(bytes(input))).toBe(expected);
    });
});

describe("parseIpv4Address", () => {
    it("parses valid dotted quads into wire bytes", () => {
        expect(parseIpv4Address("127.0.0.1")).toEqual(Uint8Array.of(127, 0, 0, 1));
        expect(parseIpv4Address("93.184.216.34")).toEqual(Uint8Array.of(93, 184, 216, 34));
        expect(parseIpv4Address("0.0.0.0")).toEqual(Uint8Array.of(0, 0, 0, 0));
        expect(parseIpv4Address("255.255.255.255")).toEqual(Uint8Array.of(255, 255, 255, 255));
    });

    it.each([
        "256.1.1.1", // octet overflow
        "1.2.3", // too few parts
        "1.2.3.4.5", // too many parts
        "01.2.3.4", // leading zero — treated as a domain name (URL semantics)
        "1.2.3.-4", // negative
        "1.2.3.x", // non-numeric
        "example.com",
        "",
    ])("rejects %s", (host) => {
        expect(parseIpv4Address(host)).toBeUndefined();
    });
});

describe("parseIpv6Address", () => {
    it("parses the unspecified and loopback forms", () => {
        expect(parseIpv6Address("::")).toEqual(new Uint8Array(16));
        expect(parseIpv6Address("::1")).toEqual(Uint8Array.from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
    });

    it("parses compressed forms", () => {
        expect(parseIpv6Address("2001:db8::1")).toEqual(Uint8Array.from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        expect(parseIpv6Address("1::")).toEqual(Uint8Array.from([
            0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        expect(parseIpv6Address("1:2:3:4:5:6:7::")).toEqual(Uint8Array.from([
            0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0,
        ]));
    });

    it("parses the full 8-group form", () => {
        expect(parseIpv6Address("2001:0db8:0000:0000:0000:0000:0000:0001")).toEqual(
            parseIpv6Address("2001:db8::1"),
        );
    });

    it("parses an embedded IPv4 tail", () => {
        // ::ffff:192.0.2.1 → five zero groups, 0xffff, then the IPv4 as two groups.
        expect(parseIpv6Address("::ffff:192.0.2.1")).toEqual(Uint8Array.from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0xff, 0xff, 0xc0, 0x00, 0x02, 0x01,
        ]));
    });

    it.each([
        "1:2:3:4:5:6:7", // 7 groups, no compression
        "1:2:3:4:5:6:7:8:9", // 9 groups
        "1::2::3", // two compressions
        ":1:2::3", // stray leading colon
        "1:2::3:", // stray trailing colon
        "::ffff:192.0.2.256", // bad embedded IPv4
        "fe80::1%eth0", // zone id — not representable in SOCKS5
        "1:2:3:4:5:6:7:8.1", // IPv4 not in final position
        "12345::", // group too long
        "g::1", // non-hex
        "",
    ])("rejects %s", (host) => {
        expect(parseIpv6Address(host)).toBeUndefined();
    });
});

describe("isIpLiteral", () => {
    it("accepts IPv4 and IPv6 literals", () => {
        expect(isIpLiteral("192.0.2.1")).toBe(true);
        expect(isIpLiteral("::1")).toBe(true);
        expect(isIpLiteral("2001:db8::1")).toBe(true);
    });

    it("rejects names and junk", () => {
        expect(isIpLiteral("example.com")).toBe(false);
        expect(isIpLiteral("01.2.3.4")).toBe(false);
        expect(isIpLiteral("")).toBe(false);
    });
});

describe("concatBytes", () => {
    it("concatenates in order and handles empty inputs", () => {
        expect(concatBytes([bytes("ab"), new Uint8Array(0), bytes("cd")])).toEqual(bytes("abcd"));
        expect(concatBytes([])).toEqual(new Uint8Array(0));
    });
});
