/**
 * HTTP CONNECT tunnel establishment (RFC 9110 §9.3.6).
 *
 * Uses a minimal internal codec — one request line pair and a status-line
 * parser — because importing `@browsercore/http1` would be an upward
 * dependency edge for twelve lines of protocol.
 *
 * Operates on an already-open duplex {@link Transport} and returns it
 * tunneled. HTTP/1.0 responses are tolerated; any 2xx establishes the
 * tunnel, 407 is an auth failure, everything else is a tunnel failure.
 */

import type { Transport } from "@browsercore/contracts";
import { ProxyAuthError, ProxyHandshakeError, ProxyTunnelError } from "./errors.js";
import { createTransportReader } from "./reader.js";
import { ConnectStatusLineSchema } from "./schemas.js";
import { tunnelTransport } from "./tunnel.js";
import type { ProxyCredentials, ProxyTarget } from "./types.js";
import { encodeBase64, utf8Decode, utf8Encode } from "./utils.js";

/**
 * Hard cap on the CONNECT response head. A proxy that streams bytes without
 * ever sending the `\r\n\r\n` terminator must not grow the read buffer
 * without bound.
 */
const MAX_RESPONSE_HEAD_BYTES = 64 * 1024;

/** The response-head terminator; module-level so it is encoded exactly once. */
const HEADER_TERMINATOR = utf8Encode("\r\n\r\n");

/** Parsed CONNECT response head — everything before the tunnel starts. */
interface ConnectResponseHead {
    readonly status: number;
    readonly reason: string;
    /** Header values keyed by lowercased name (lookup is case-insensitive). */
    readonly headers: Readonly<Record<string, string>>;
}

/**
 * Establish an HTTP CONNECT tunnel to `target` over an open transport.
 *
 * Sends `CONNECT host:port HTTP/1.1` with `Host:` and
 * `Proxy-Connection: keep-alive`, plus `Proxy-Authorization: Basic …` only
 * when credentials are configured. Reads the status line and headers up to
 * the empty line, then returns the transport tunneled.
 *
 * @param transport - Open transport to the HTTP proxy.
 * @param target - Destination to tunnel to.
 * @param credentials - Username/password sent as HTTP Basic auth.
 * @returns The same transport, now tunneled to the target. Bytes the peer
 *   sent past the response head (early target data) are preserved.
 * @throws {@link ProxyAuthError} the proxy answered 407 (the
 *   `Proxy-Authenticate` challenge is carried on the error).
 * @throws {@link ProxyTunnelError} the proxy answered a non-2xx status.
 * @throws {@link ProxyHandshakeError} the response head is malformed
 *   (unparseable status line, non-HTTP/1.x version) or exceeded the size cap.
 *
 * @since 0.1.0
 */
export async function establishHttpConnectTunnel(
    transport: Transport,
    target: ProxyTarget,
    credentials?: ProxyCredentials,
): Promise<Transport> {
    const reader = createTransportReader(transport);
    await transport.write(buildConnectRequest(target, credentials));
    const headBytes = await reader.readUntilDelimiter(HEADER_TERMINATOR, MAX_RESPONSE_HEAD_BYTES);
    const response = parseResponseHead(headBytes);
    assertTunnelEstablished(response);
    return tunnelTransport(transport, reader.remaining());
}

/** Build the exact CONNECT request bytes (the whole of the "codec" — see module doc). */
function buildConnectRequest(target: ProxyTarget, credentials?: ProxyCredentials): Uint8Array {
    const authority = `${target.host}:${target.port}`;
    const lines = [
        `CONNECT ${authority} HTTP/1.1`,
        `Host: ${authority}`,
        "Proxy-Connection: keep-alive",
    ];
    if (credentials !== undefined) {
        // Basic auth is the only scheme every proxy accepts without a challenge round-trip.
        const basic = encodeBase64(utf8Encode(`${credentials.username}:${credentials.password}`));
        lines.push(`Proxy-Authorization: Basic ${basic}`);
    }
    return utf8Encode(lines.join("\r\n") + "\r\n\r\n");
}

/**
 * Parse the response head bytes (terminator included) into a validated
 * {@link ConnectResponseHead}. The status line is Zod-validated — it is
 * untrusted peer data.
 */
function parseResponseHead(headBytes: Uint8Array): ConnectResponseHead {
    // readUntilDelimiter includes the terminator — strip it before splitting.
    const headText = utf8Decode(headBytes.subarray(0, headBytes.length - HEADER_TERMINATOR.length));
    const lines = headText.split("\r\n");
    const statusLine = lines[0] ?? "";
    const match = /^HTTP\/(\d)\.(\d) (\d{3})(?: (.*))?$/u.exec(statusLine);
    const candidate = match === null
        ? undefined
        : {
            version: `HTTP/${match[1]}.${match[2]}`,
            status: Math.trunc(Number(match[3] ?? "0")),
            reason: match[4] ?? "",
        };
    const validated = ConnectStatusLineSchema.safeParse(candidate);
    if (!validated.success) {
        throw new ProxyHandshakeError(
            `Malformed CONNECT status line: "${statusLine}"`,
            { statusLine },
        );
    }

    const headers: Record<string, string> = {};
    for (const line of lines.slice(1)) {
        const colonAt = line.indexOf(":");
        // Lines without a colon are tolerated (some proxies emit junk);
        // header semantics for CONNECT are advisory anyway.
        if (colonAt <= 0) {
            continue;
        }
        const name = line.slice(0, colonAt).trim().toLowerCase();
        const value = line.slice(colonAt + 1).trim();
        // First occurrence wins — repeated advisory headers are not additive.
        if (!(name in headers)) {
            headers[name] = value;
        }
    }
    return { status: validated.data.status, reason: validated.data.reason, headers };
}

/** Classify the response: 200 and any 2xx establish the tunnel; 407 is auth; the rest are tunnel failures. */
function assertTunnelEstablished(response: ConnectResponseHead): void {
    if (response.status === 200) {
        return;
    }
    if (response.status === 407) {
        const challenge = response.headers["proxy-authenticate"];
        throw new ProxyAuthError(
            `HTTP proxy rejected CONNECT credentials: 407 ${response.reason}`.trimEnd(),
            { scheme: "http", status: 407, challenge },
        );
    }
    if (response.status >= 200 && response.status < 300) {
        // Rare but legal: the RFC only requires "any 2xx" for an established tunnel.
        return;
    }
    throw new ProxyTunnelError(
        `HTTP proxy refused CONNECT: ${response.status} ${response.reason}`.trimEnd(),
        { scheme: "http", code: response.status, meaning: response.reason },
    );
}
