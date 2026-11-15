/**
 * SOCKS5 tunnel establishment — RFC 1928 method negotiation + CONNECT,
 * RFC 1929 username/password subnegotiation.
 *
 * Operates on an already-open duplex {@link Transport} and returns it
 * tunneled: after this resolves, the stream speaks directly to the target.
 * The function is a pure byte exchange — the transport may be a real socket
 * via `connectViaProxy` or any synthetic stream in tests.
 */

import type { Transport } from "@browsercore/contracts";
import { ProxyAuthError, ProxyConfigError, ProxyHandshakeError, ProxyTunnelError } from "./errors.js";
import { createTransportReader, type TransportReader } from "./reader.js";
import { tunnelTransport } from "./tunnel.js";
import type { ProxyCredentials, ProxyTarget, Socks5AddressMode, Socks5TunnelOptions } from "./types.js";
import { assertNever, concatBytes, parseIpv4Address, parseIpv6Address, utf8Encode } from "./utils.js";

/** SOCKS protocol version (RFC 1928 VER). */
const SOCKS5_VERSION = 0x05;
/** RFC 1928 method: NO AUTHENTICATION REQUIRED. */
const METHOD_NO_AUTH = 0x00;
/** RFC 1928 method: USERNAME/PASSWORD (RFC 1929). */
const METHOD_USERNAME_PASSWORD = 0x02;
/** RFC 1928 method: NO ACCEPTABLE METHODS — the server rejected the offer. */
const METHOD_NO_ACCEPTABLE = 0xff;
/** RFC 1929 subnegotiation version byte. */
const RFC1929_VERSION = 0x01;
/** RFC 1928 address types. */
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;
const ATYP_IPV6 = 0x04;
/** RFC 1928 CONNECT command — the only command a browser stack needs. */
const SOCKS_CMD_CONNECT = 0x01;
/** RFC 1928 RSV — reserved, must be zero. */
const RESERVED = 0x00;
/** RFC 1929 fields carry a one-byte length prefix, so 255 bytes is the hard cap. */
const MAX_FIELD_BYTES = 255;

/**
 * Establish a SOCKS5 CONNECT tunnel to `target` over an open transport.
 *
 * Flow: method greeting → (optional RFC 1929 auth) → CONNECT request → reply.
 * The greeting offers `0x00` plus `0x02` when credentials are configured.
 * Credentials are validated (no NUL bytes, each field ≤255 bytes) before any
 * bytes hit the wire — misconfiguration should not consume a proxy socket.
 *
 * @param transport - Open transport to the SOCKS5 proxy.
 * @param target - Destination to tunnel to.
 * @param credentials - Username/password for RFC 1929 (method 0x02).
 * @param options - Address-type control; `atyp: "domain"` forces remote DNS
 *   regardless of the target string (the `socks5h` semantics).
 * @returns The same transport, now tunneled to the target. Bytes the peer
 *   sent past the handshake (early target data) are preserved.
 * @throws {@link ProxyConfigError} credentials cannot be encoded, or the
 *   `atyp` mode contradicts the target string.
 * @throws {@link ProxyAuthError} the proxy rejected the method offer (0xFF),
 *   demanded auth without credentials being configured, or auth failed.
 * @throws {@link ProxyTunnelError} the proxy refused CONNECT (reply 1–8).
 * @throws {@link ProxyHandshakeError} the peer's bytes are malformed.
 *
 * @since 0.1.0
 */
export async function establishSocks5Tunnel(
    transport: Transport,
    target: ProxyTarget,
    credentials?: ProxyCredentials,
    options?: Socks5TunnelOptions,
): Promise<Transport> {
    // Fail fast on unencodable configuration before any bytes hit the wire —
    // a misconfigured target or credentials should not consume a proxy socket.
    if (credentials !== undefined) {
        validateSocks5Credentials(credentials);
    }
    const address = encodeAddressForSocks5(target.host, options?.atyp ?? "auto");
    const reader = createTransportReader(transport);

    await transport.write(buildGreeting(credentials !== undefined));
    const selection = interpretMethodSelection(await readMethodSelection(reader));
    switch (selection.kind) {
        case "noAuth":
            break;
        case "usernamePassword":
            if (credentials === undefined) {
                throw new ProxyAuthError(
                    "SOCKS5 proxy requires username/password authentication (method 0x02) but no credentials were configured",
                    { scheme: "socks5" },
                );
            }
            await performUsernamePasswordAuth(transport, reader, credentials);
            break;
        case "rejected":
            throw new ProxyAuthError(
                "SOCKS5 proxy rejected all offered authentication methods (0xFF)",
                { scheme: "socks5" },
            );
        case "unknown":
            throw new ProxyHandshakeError(
                `SOCKS5 proxy selected method 0x${selection.method.toString(16)} which was not offered`,
                { method: selection.method },
            );
        default:
            assertNever(selection);
    }

    await transport.write(buildConnectRequest(address, target.port));
    await readConnectReply(reader);
    return tunnelTransport(transport, reader.remaining());
}

/** What the proxy's method-selection byte means for this client. */
type MethodSelection =
    | { readonly kind: "noAuth" }
    | { readonly kind: "usernamePassword" }
    | { readonly kind: "rejected" }
    | { readonly kind: "unknown"; readonly method: number };

function interpretMethodSelection(method: number): MethodSelection {
    if (method === METHOD_NO_AUTH) {
        return { kind: "noAuth" };
    }
    if (method === METHOD_USERNAME_PASSWORD) {
        return { kind: "usernamePassword" };
    }
    if (method === METHOD_NO_ACCEPTABLE) {
        return { kind: "rejected" };
    }
    return { kind: "unknown", method };
}

/** Read and version-check the 2-byte method-selection reply. */
async function readMethodSelection(reader: TransportReader): Promise<number> {
    const reply = await reader.readExact(2);
    const view = new DataView(reply.buffer, reply.byteOffset, reply.byteLength);
    const version = view.getUint8(0);
    if (version !== SOCKS5_VERSION) {
        throw new ProxyHandshakeError(
            `SOCKS5 method-selection reply had version ${version}, expected 5 — not a SOCKS5 proxy?`,
            { version },
        );
    }
    return view.getUint8(1);
}

/** RFC 1929 username/password subnegotiation; throws on failure status. */
async function performUsernamePasswordAuth(
    transport: Transport,
    reader: TransportReader,
    credentials: ProxyCredentials,
): Promise<void> {
    await transport.write(buildUsernamePasswordRequest(credentials));
    const reply = await reader.readExact(2);
    const view = new DataView(reply.buffer, reply.byteOffset, reply.byteLength);
    const version = view.getUint8(0);
    const status = view.getUint8(1);
    if (version !== RFC1929_VERSION) {
        throw new ProxyHandshakeError(
            `RFC 1929 auth reply had version ${version}, expected ${RFC1929_VERSION}`,
            { version },
        );
    }
    if (status !== 0x00) {
        throw new ProxyAuthError(
            `SOCKS5 username/password authentication failed (status 0x${status.toString(16)})`,
            { scheme: "socks5", status },
        );
    }
}

/**
 * Validate credentials against RFC 1929's wire constraints.
 *
 * The subnegotiation prefixes each field with a one-byte length and the
 * username/password separator is positional — a NUL byte cannot be escaped,
 * so such credentials are rejected before dialing rather than mid-handshake.
 */
export function validateSocks5Credentials(credentials: ProxyCredentials): void {
    validateSocks5Field("username", credentials.username);
    validateSocks5Field("password", credentials.password);
}

function validateSocks5Field(fieldName: string, value: string): void {
    const bytes = utf8Encode(value);
    if (bytes.includes(0x00)) {
        throw new ProxyConfigError(
            `SOCKS5 ${fieldName} must not contain NUL bytes — RFC 1929 has no escaping`,
            { field: fieldName },
        );
    }
    if (bytes.length > MAX_FIELD_BYTES) {
        throw new ProxyConfigError(
            `SOCKS5 ${fieldName} is ${bytes.length} bytes — RFC 1929 fields are limited to ${MAX_FIELD_BYTES}`,
            { field: fieldName, length: bytes.length },
        );
    }
}

/** Greeting: VER=5, NMETHODS, METHODS ([0x00] or [0x00, 0x02] with credentials). */
function buildGreeting(hasCredentials: boolean): Uint8Array {
    const methods = hasCredentials
        ? [METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD]
        : [METHOD_NO_AUTH];
    return concatBytes([Uint8Array.of(SOCKS5_VERSION, methods.length), Uint8Array.from(methods)]);
}

/** RFC 1929 request: VER=1, ULEN, UNAME, PLEN, PASSWD. */
function buildUsernamePasswordRequest(credentials: ProxyCredentials): Uint8Array {
    const username = utf8Encode(credentials.username);
    const password = utf8Encode(credentials.password);
    return concatBytes([
        Uint8Array.of(RFC1929_VERSION, username.length),
        username,
        Uint8Array.of(password.length),
        password,
    ]);
}

/** The encoded target address of a SOCKS5 CONNECT request. */
interface Socks5Address {
    /** RFC 1928 ATYP byte. */
    readonly atyp: number;
    /** ATYP-specific address bytes (4 for IPv4, [len, ...] for domain, 16 for IPv6). */
    readonly bytes: Uint8Array;
}

/** CONNECT request: VER, CMD=CONNECT, RSV, ATYP, DST.ADDR, DST.PORT. */
function buildConnectRequest(address: Socks5Address, port: number): Uint8Array {
    const portHigh = (port >> 8) & 0xff;
    const portLow = port & 0xff;
    return concatBytes([
        Uint8Array.of(SOCKS5_VERSION, SOCKS_CMD_CONNECT, RESERVED, address.atyp),
        address.bytes,
        Uint8Array.of(portHigh, portLow),
    ]);
}

function encodeAddressForSocks5(host: string, mode: Socks5AddressMode): Socks5Address {
    switch (mode) {
        case "ipv4": {
            const ipv4 = parseIpv4Address(host);
            if (ipv4 === undefined) {
                throw new ProxyConfigError(
                    `SOCKS5 atyp "ipv4" requires an IPv4 literal, got "${host}"`,
                    { host, mode },
                );
            }
            return { atyp: ATYP_IPV4, bytes: ipv4 };
        }
        case "ipv6": {
            const ipv6 = parseIpv6Address(host);
            if (ipv6 === undefined) {
                throw new ProxyConfigError(
                    `SOCKS5 atyp "ipv6" requires an IPv6 literal, got "${host}"`,
                    { host, mode },
                );
            }
            return { atyp: ATYP_IPV6, bytes: ipv6 };
        }
        case "domain":
            return encodeDomainAddress(host);
        case "auto": {
            // Literal IPs go on the wire as addresses; everything else is a
            // name for the proxy to resolve.
            const ipv4 = parseIpv4Address(host);
            if (ipv4 !== undefined) {
                return { atyp: ATYP_IPV4, bytes: ipv4 };
            }
            const ipv6 = parseIpv6Address(host);
            if (ipv6 !== undefined) {
                return { atyp: ATYP_IPV6, bytes: ipv6 };
            }
            return encodeDomainAddress(host);
        }
        default:
            return assertNever(mode);
    }
}

function encodeDomainAddress(host: string): Socks5Address {
    const name = utf8Encode(host);
    if (name.length > MAX_FIELD_BYTES) {
        throw new ProxyConfigError(
            `Target host is ${name.length} bytes — SOCKS5 domain names are limited to ${MAX_FIELD_BYTES}`,
            { host },
        );
    }
    return { atyp: ATYP_DOMAIN, bytes: concatBytes([Uint8Array.of(name.length), name]) };
}

/** Read the CONNECT reply: head (VER/REP/RSV/ATYP) then skip BND.ADDR/PORT. */
async function readConnectReply(reader: TransportReader): Promise<void> {
    const head = await reader.readExact(4);
    const view = new DataView(head.buffer, head.byteOffset, head.byteLength);
    const version = view.getUint8(0);
    const replyCode = view.getUint8(1);
    const atyp = view.getUint8(3);
    if (version !== SOCKS5_VERSION) {
        throw new ProxyHandshakeError(
            `SOCKS5 CONNECT reply had version ${version}, expected 5`,
            { version },
        );
    }
    if (replyCode !== 0x00) {
        const meaning = socks5ReplyMeaning(replyCode);
        throw new ProxyTunnelError(
            `SOCKS5 CONNECT failed (0x${replyCode.toString(16)}): ${meaning}`,
            { scheme: "socks5", code: replyCode, meaning },
        );
    }
    const boundLength = boundAddressByteLength(atyp);
    if (boundLength === undefined) {
        throw new ProxyHandshakeError(
            `SOCKS5 reply used unknown address type 0x${atyp.toString(16)}`,
            { atyp },
        );
    }
    // BND.ADDR/BND.PORT report the proxy's bound address — informational for
    // CONNECT, but must be consumed so the tunnel stream starts at the first
    // true payload byte. A domain BND carries its own length prefix.
    let skip = boundLength;
    if (atyp === ATYP_DOMAIN) {
        const lengthByte = await reader.readExact(1);
        const lengthView = new DataView(lengthByte.buffer, lengthByte.byteOffset, lengthByte.byteLength);
        skip = lengthView.getUint8(0);
    }
    await reader.readExact(skip + 2); // + BND.PORT
}

/** Fixed byte length of BND.ADDR per ATYP (domains: read length prefix first). */
function boundAddressByteLength(atyp: number): number | undefined {
    if (atyp === ATYP_IPV4) {
        return 4;
    }
    if (atyp === ATYP_DOMAIN) {
        return 0;
    }
    if (atyp === ATYP_IPV6) {
        return 16;
    }
    return undefined;
}

/** RFC 1928 §6 reply-code meanings, for error messages and `ProxyTunnelError.meaning`. */
export function socks5ReplyMeaning(code: number): string {
    switch (code) {
        case 0x01: return "general SOCKS server failure";
        case 0x02: return "connection not allowed by ruleset";
        case 0x03: return "network unreachable";
        case 0x04: return "host unreachable";
        case 0x05: return "connection refused";
        case 0x06: return "TTL expired";
        case 0x07: return "command not supported";
        case 0x08: return "address type not supported";
        default: return "unassigned reply code";
    }
}
