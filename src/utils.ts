/**
 * Small shared helpers for @browsercore/proxy.
 *
 * Runtime-free by design: everything here is pure ES plus the platform
 * `TextEncoder`/`TextDecoder`/`DataView` globals — no `node:*` imports — so
 * the package stays portable across Node, Bun, Deno, and Workers. The IP
 * literal parsers exist because `node:net` is off-limits and SOCKS5 needs
 * the raw 4/16-byte encodings anyway.
 */

/**
 * Exhaustiveness check for `switch`/`if-else` over discriminated unions.
 * Call in the `default` branch: `default: assertNever(x)`.
 * Adding a new union member forces every handler to compile-error until handled.
 */
export function assertNever(x: never): never {
    throw new Error(`Unexpected value: ${JSON.stringify(x)}`);
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Base64-encode bytes (RFC 4648, with padding).
 *
 * Hand-rolled because `btoa`/`Buffer` are runtime-specific; HTTP Basic auth
 * is the only consumer and it is worth keeping the package runtime-free.
 */
export function encodeBase64(bytes: Uint8Array): string {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
        const b0 = bytes[i] ?? 0;
        const b1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
        const b2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;
        const triplet = (b0 << 16) | ((b1 ?? 0) << 8) | (b2 ?? 0);
        out += BASE64_ALPHABET.charAt((triplet >> 18) & 0x3f);
        out += BASE64_ALPHABET.charAt((triplet >> 12) & 0x3f);
        // One or two trailing '=' replace the sextets whose source bytes were absent.
        out += b1 === undefined ? "=" : BASE64_ALPHABET.charAt((triplet >> 6) & 0x3f);
        out += b2 === undefined ? "=" : BASE64_ALPHABET.charAt(triplet & 0x3f);
    }
    return out;
}

const utf8Encoder = new TextEncoder();
// Non-fatal by default: a domain name with stray high bytes should tunnel, not crash.
const utf8Decoder = new TextDecoder("utf-8");

/** UTF-8 encode a string. The single sanctioned encoder for wire fields. */
export function utf8Encode(text: string): Uint8Array {
    return utf8Encoder.encode(text);
}

/** UTF-8 decode bytes, tolerating invalid sequences. */
export function utf8Decode(bytes: Uint8Array): string {
    return utf8Decoder.decode(bytes);
}

/** Concatenate byte chunks into a fresh array. Inputs are never mutated. */
export function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
    const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

/**
 * Parse a dotted-quad IPv4 literal into its 4 wire bytes.
 *
 * Returns `undefined` for anything that is not a strict IPv4 literal —
 * leading-zero octets are rejected (WHATWG URL semantics) so `"01.2.3.4"`
 * is treated as a domain name, not an address.
 */
export function parseIpv4Address(host: string): Uint8Array | undefined {
    const parts = host.split(".");
    if (parts.length !== 4) {
        return undefined;
    }
    const octets: number[] = [];
    for (const part of parts) {
        if (!/^\d{1,3}$/u.test(part)) {
            return undefined;
        }
        const value = Math.trunc(Number(part));
        if (value > 255) {
            return undefined;
        }
        if (part.length > 1 && part.startsWith("0")) {
            return undefined;
        }
        octets.push(value);
    }
    return Uint8Array.from(octets);
}

/**
 * Parse an IPv6 literal (RFC 4291 textual form) into its 16 wire bytes.
 *
 * Handles `::` zero compression, an embedded IPv4 tail (`::ffff:192.0.2.1`),
 * and the full 8-group form. Returns `undefined` for malformed addresses and
 * for zone-scoped addresses (`fe80::1%eth0`) — the zone id has no SOCKS5
 * representation.
 */
export function parseIpv6Address(host: string): Uint8Array | undefined {
    if (host === "" || host.includes("%")) {
        return undefined;
    }
    const doubleColonAt = host.indexOf("::");
    const hasExpansion = doubleColonAt !== -1;
    if (hasExpansion && host.includes("::", doubleColonAt + 1)) {
        return undefined; // two "::" — ambiguous compression
    }
    const headText = hasExpansion ? host.slice(0, doubleColonAt) : host;
    const tailText = hasExpansion ? host.slice(doubleColonAt + 2) : "";
    // A stray single colon at either boundary (":1:2::3", "1:2::3:") is malformed.
    if (
        headText.startsWith(":") || headText.endsWith(":") ||
        tailText.startsWith(":") || tailText.endsWith(":")
    ) {
        return undefined;
    }
    const headGroups = parseIpv6Groups(headText);
    const tailGroups = parseIpv6Groups(tailText);
    if (headGroups === undefined || tailGroups === undefined) {
        return undefined;
    }
    const explicit = headGroups.length + tailGroups.length;
    // Without "::" exactly 8 groups are required; with it, at least one group
    // must be compressed (7 explicit max) or the address is over/underspecified.
    if ((!hasExpansion && explicit !== 8) || (hasExpansion && explicit > 7)) {
        return undefined;
    }
    const zeros = hasExpansion ? Array.from({ length: 8 - explicit }, () => 0) : [];
    const groups = [...headGroups, ...zeros, ...tailGroups];
    const bytes = new Uint8Array(16);
    for (const [index, group] of groups.entries()) {
        bytes[index * 2] = group >> 8;
        bytes[index * 2 + 1] = group & 0xff;
    }
    return bytes;
}

/**
 * Parse the colon-separated groups of one side of a (possible) `::`.
 *
 * The final group may be an embedded IPv4 address, which contributes two
 * groups. Returns `undefined` on any malformed group.
 */
function parseIpv6Groups(text: string): number[] | undefined {
    if (text === "") {
        return [];
    }
    const rawGroups = text.split(":");
    const groups: number[] = [];
    for (let i = 0; i < rawGroups.length; i++) {
        const raw = rawGroups[i];
        if (raw === undefined) {
            return undefined;
        }
        if (raw.includes(".")) {
            // Embedded IPv4 is only legal as the very last group.
            if (i !== rawGroups.length - 1) {
                return undefined;
            }
            const ipv4 = parseIpv4Address(raw);
            if (ipv4 === undefined) {
                return undefined;
            }
            const view = new DataView(ipv4.buffer, ipv4.byteOffset, ipv4.byteLength);
            groups.push(view.getUint16(0), view.getUint16(2));
            continue;
        }
        if (!/^[0-9a-fA-F]{1,4}$/u.test(raw)) {
            return undefined;
        }
        groups.push(Number.parseInt(raw, 16));
    }
    return groups;
}

/**
 * Whether a host string is an IP literal (IPv4 or IPv6).
 *
 * Drives the socks5 short-circuit: literals are sent as `ATYP 0x01`/`0x04`
 * without consulting DNS.
 */
export function isIpLiteral(host: string): boolean {
    return parseIpv4Address(host) !== undefined || parseIpv6Address(host) !== undefined;
}
