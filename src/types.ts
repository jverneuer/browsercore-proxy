/**
 * Domain types for @browsercore/proxy.
 *
 * This package owns NO knowledge of TLS, HTTP framing, or browser
 * fingerprints. It performs proxy handshakes (SOCKS5, HTTP CONNECT) over an
 * injected duplex {@link Transport} from `@browsercore/contracts` and returns
 * the same stream tunneled. Sockets and DNS are injected — this package
 * imports no `node:*` builtins.
 */

// ---------------------------------------------------------------------------
// Canonical proxy config types — re-exported, no longer declared here.
//
// @browsercore/contracts 0.2.6 adopted this package's ProxyScheme /
// ProxyConfig / ProxyTarget / ProxyCredentials shapes verbatim as the
// canonical definitions (replaceability audit 2026-11-16, item #3 groundwork:
// one home per config-type family). The local declarations that used to live
// in this file are removed; the re-export below keeps every consumer of
// @browsercore/proxy on the exact same types as consumers of
// @browsercore/contracts — same names, same shapes, public API unchanged.
//
// The Zod schemas in schemas.ts stay proxy-local: validation is this
// package's job, and they validate external data INTO the canonical type.
// ---------------------------------------------------------------------------

export type {
    ProxyConfig,
    ProxyCredentials,
    ProxyScheme,
    ProxyTarget,
} from "@browsercore/contracts";

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
