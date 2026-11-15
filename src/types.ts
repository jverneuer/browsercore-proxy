/**
 * Domain types for @browsercore/proxy.
 *
 * This package owns NO knowledge of TLS, HTTP framing, or browser
 * fingerprints. It performs proxy handshakes (SOCKS5, HTTP CONNECT) over an
 * injected duplex {@link Transport} from `@browsercore/contracts` and returns
 * the same stream tunneled. Sockets and DNS are injected — this package
 * imports no `node:*` builtins.
 */

/**
 * Proxy schemes supported in v0.1.0.
 *
 * - `http` — HTTP CONNECT tunneling (RFC 9110 §9.3.6)
 * - `socks5` — SOCKS5 with client-side DNS: the hostname is resolved locally
 *   and the resolved IP is sent on the wire
 * - `socks5h` — SOCKS5 with remote DNS: the hostname is sent verbatim and the
 *   proxy resolves it (curl's `socks5h` semantics)
 */
export type ProxyScheme = "http" | "socks5" | "socks5h";

/**
 * A parsed, validated proxy endpoint.
 *
 * Produced by `parseProxyUrl` or hand-assembled by the caller. All fields are
 * readonly — configs are shared, never mutated.
 *
 * The `username`/`password` fields use an explicit `| undefined` so values
 * parsed from URLs (where "absent" and "empty" genuinely differ) stay
 * assignable under `exactOptionalPropertyTypes`.
 */
export interface ProxyConfig {
    /** Tunneling scheme. */
    readonly scheme: ProxyScheme;
    /** Proxy host (DNS name or IP literal). */
    readonly host: string;
    /** Proxy port, 1–65535. */
    readonly port: number;
    /** Proxy username, when the proxy requires authentication. */
    readonly username?: string | undefined;
    /** Proxy password, when the proxy requires authentication. */
    readonly password?: string | undefined;
}

/**
 * The destination requested through the proxy — what the client wants to
 * reach, not the proxy itself.
 */
export interface ProxyTarget {
    /** Target host (DNS name or IP literal). */
    readonly host: string;
    /** Target port, 1–65535. */
    readonly port: number;
}

/**
 * Credentials for proxy authentication.
 *
 * Used verbatim as RFC 1929 username/password (SOCKS5) or Basic auth
 * (HTTP CONNECT). Field length limits are enforced by the handshake, not
 * by this type — see `validateSocks5Credentials`.
 */
export interface ProxyCredentials {
    readonly username: string;
    readonly password: string;
}

/**
 * How the SOCKS5 CONNECT request encodes the target address (RFC 1928 ATYP).
 *
 * - `domain` — always `ATYP 0x03` (remote DNS), even for IP literals
 * - `ipv4` / `ipv6` — require an IP literal of that family
 * - `auto` — send IP literals as `0x01`/`0x04`, everything else as `0x03`
 *
 * `connectViaProxy` passes `domain` for `socks5h` (the proxy must resolve)
 * and relies on `auto` for `socks5` (the client already resolved).
 */
export type Socks5AddressMode = "domain" | "ipv4" | "ipv6" | "auto";

/** Options for {@link Socks5AddressMode} selection in `establishSocks5Tunnel`. */
export interface Socks5TunnelOptions {
    /**
     * Address-type mode for the CONNECT request.
     *
     * @defaultValue "auto"
     */
    readonly atyp?: Socks5AddressMode;
}
