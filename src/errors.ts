/**
 * Typed errors for @browsercore/proxy.
 *
 * Errors are part of the API — every failure mode is an explicit type so callers
 * can match on `kind` instead of parsing messages (house style, mirrored from
 * @browsercore/transport's errors.ts).
 */

import type { ProxyScheme } from "./types.js";

/** Arbitrary structured metadata attached to a {@link ProxyError} (e.g. host, code, challenge). */
export type ProxyErrorDetails = Record<string, unknown>;

/**
 * Base class for every error raised by `@browsercore/proxy`.
 *
 * All proxy failures extend this class, which itself extends `Error` — so a
 * single `catch` on `ProxyError` (or `Error`) works, while `instanceof` against
 * a subclass narrows to a specific failure mode. Failures outside the four
 * subclasses below (e.g. a missing platform capability) are raised as the base
 * class itself.
 *
 * @example
 * ```ts
 * try {
 *     const tunneled = await connectViaProxy(proxy, target, platform);
 * } catch (e) {
 *     if (e instanceof ProxyAuthError) {
 *         // rotate credentials / try the next proxy...
 *     }
 *     throw e;
 * }
 * ```
 *
 * @since 0.1.0
 */
export class ProxyError extends Error {
    public readonly kind: string = "ProxyError";
    public readonly details: ProxyErrorDetails;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    public override readonly cause: Error | undefined;

    /**
     * @param message - Human-readable description of the failure.
     * @param details - Structured metadata about the error (e.g. `{ host, port }`).
     * @param options - Standard `Error` options; `cause` preserves the wrapped error.
     */
    constructor(
        message: string,
        details: ProxyErrorDetails = {},
        options?: { cause?: Error },
    ) {
        super(message, options);
        this.name = new.target.name;
        this.details = details;
        this.cause = options?.cause;
    }
}

/**
 * The proxy configuration itself is invalid.
 *
 * Raised by `parseProxyUrl` for unparseable URLs, unsupported schemes, and
 * out-of-range ports, and by the SOCKS5 handshake for credentials that cannot
 * be encoded on the wire (NUL bytes or fields ≥256 bytes — RFC 1929 has no
 * escaping and only a one-byte length prefix).
 *
 * @since 0.1.0
 */
export class ProxyConfigError extends ProxyError {
    public override readonly kind = "ProxyConfigError" as const;

    /**
     * @param message - Human-readable description of the invalid input.
     * @param details - Structured metadata (e.g. `{ url }` or `{ field, length }`).
     */
    constructor(message: string, details: ProxyErrorDetails = {}) {
        super(message, details);
    }
}

/**
 * The proxy rejected the offered credentials.
 *
 * Raised when a SOCKS5 proxy answers method negotiation with 0xFF ("no
 * acceptable methods"), when RFC 1929 username/password subnegotiation fails,
 * when a proxy demands authentication none was configured for, or when an
 * HTTP proxy answers CONNECT with 407.
 *
 * @since 0.1.0
 */
export class ProxyAuthError extends ProxyError {
    public override readonly kind = "ProxyAuthError" as const;
    /** Scheme whose authentication failed — failures differ per protocol. */
    public readonly scheme: ProxyScheme;
    /**
     * The `Proxy-Authenticate` challenge from an HTTP 407 response, when the
     * proxy sent one — tells the caller which scheme to retry with.
     */
    public readonly challenge: string | undefined;

    /**
     * @param message - Human-readable description of the rejection.
     * @param details - `scheme` is required; `challenge` (HTTP 407) and
     *   `status` (HTTP status code) are included when applicable.
     */
    constructor(
        message: string,
        details: {
            readonly scheme: ProxyScheme;
            readonly challenge?: string | undefined;
            readonly status?: number;
        },
    ) {
        super(message, details);
        this.scheme = details.scheme;
        this.challenge = details.challenge;
    }
}

/**
 * The proxy understood the request but refused or failed the tunnel.
 *
 * For SOCKS5 this carries the RFC 1928 reply code (1–8) and its meaning; for
 * HTTP CONNECT it carries the non-2xx status code and reason phrase. The
 * tunnel was NOT established — the transport is unusable afterwards.
 *
 * @since 0.1.0
 */
export class ProxyTunnelError extends ProxyError {
    public override readonly kind = "ProxyTunnelError" as const;
    /** Scheme that reported the failure. */
    public readonly scheme: ProxyScheme;
    /** SOCKS5 REP byte (1–8) or HTTP status code — whichever the scheme reports. */
    public readonly code: number | undefined;
    /** RFC 1928 meaning of the reply code, or the HTTP reason phrase. */
    public readonly meaning: string | undefined;

    /**
     * @param message - Human-readable description of the refusal.
     * @param details - `scheme` is required; `code` and `meaning` describe the refusal.
     */
    constructor(
        message: string,
        details: {
            readonly scheme: ProxyScheme;
            readonly code?: number | undefined;
            readonly meaning?: string | undefined;
        },
    ) {
        super(message, details);
        this.scheme = details.scheme;
        this.code = details.code;
        this.meaning = details.meaning;
    }
}

/**
 * The proxy peer produced bytes that do not match the protocol.
 *
 * Raised for wrong version bytes, unknown method/address-type selections,
 * truncated replies (the peer closed mid-message), and malformed HTTP status
 * lines. A handshake error always means the peer is broken or not a proxy —
 * it is never a credentials or target problem.
 *
 * @since 0.1.0
 */
export class ProxyHandshakeError extends ProxyError {
    public override readonly kind = "ProxyHandshakeError" as const;

    /**
     * @param message - Human-readable description of the malformed bytes.
     * @param details - Structured metadata (e.g. `{ version }`, `{ atyp }`).
     * @param options - `cause` preserves the underlying read/close error for
     *   truncated replies.
     */
    constructor(message: string, details: ProxyErrorDetails = {}, options?: { cause?: Error }) {
        super(message, details, options);
    }
}

/**
 * Narrow a caught error to a typed {@link ProxyError}.
 *
 * Returns the input unchanged if it is already a `ProxyError`. Otherwise wraps
 * it: an `Error` keeps its message as `cause`, and any other value is
 * stringified into a fresh `ProxyError`. This is the canonical way to convert
 * unknown `catch` values into the typed error hierarchy.
 *
 * @param e - The caught value from a `catch` clause.
 * @returns A typed {@link ProxyError}.
 *
 * @since 0.1.0
 */
export function ensureProxyError(e: unknown): ProxyError {
    if (e instanceof ProxyError) {
        return e;
    }
    if (e instanceof Error) {
        return new ProxyError(e.message, {}, { cause: e });
    }
    return new ProxyError(typeof e === "string" ? e : "unknown proxy error");
}
