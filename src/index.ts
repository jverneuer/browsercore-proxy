/**
 * @browsercore/proxy — public API surface.
 *
 * SOCKS5 and HTTP CONNECT proxy tunnels over any duplex Transport. Higher
 * layers compose exclusively through these exports.
 *
 * The package provides:
 * - {@link connectViaProxy} — dial a proxy via the injected Platform and tunnel
 * - {@link establishSocks5Tunnel} / {@link establishHttpConnectTunnel} —
 *   handshakes over an already-open Transport
 * - {@link parseProxyUrl} — Zod-validated `http://` / `socks5://` / `socks5h://` parsing
 * - A typed error hierarchy ({@link ProxyError} and subclasses) matched on `kind`
 *
 * This package imports only types from `@browsercore/contracts` — never
 * `node:net` or `node:dns` directly. Sockets and DNS are injected via the
 * Platform.
 *
 * @module
 */

export { connectViaProxy } from "./dial.js";
export { establishHttpConnectTunnel } from "./http-connect.js";
export { parseProxyUrl } from "./parse-url.js";
export { establishSocks5Tunnel, socks5ReplyMeaning, validateSocks5Credentials } from "./socks5.js";

export type {
    ProxyConfig,
    ProxyCredentials,
    ProxyScheme,
    ProxyTarget,
    Socks5AddressMode,
    Socks5TunnelOptions,
} from "./types.js";

export {
    ProxyAuthError,
    ProxyConfigError,
    ProxyError,
    ProxyHandshakeError,
    ProxyTunnelError,
    ensureProxyError,
} from "./errors.js";
export type { ProxyErrorDetails } from "./errors.js";

// Re-export the consumed contracts so callers need a single import — the
// Transport/Platform types this package's API speaks in.
export type { Platform, Transport } from "@browsercore/contracts";
