# @browsercore/proxy

[![npm version](https://img.shields.io/npm/v/@browsercore/proxy)](https://www.npmjs.com/package/@browsercore/proxy)
[![CI](https://img.shields.io/github/actions/workflow/status/jverneuer/browsercore-proxy/ci.yml?label=ci)](https://github.com/jverneuer/browsercore-proxy/actions/workflows/ci.yml)

@browsercore/proxy establishes tunneled connections through HTTP (CONNECT) and SOCKS5 proxies. It knows nothing about TLS, HTTP framing, or browser fingerprinting, it takes an open duplex `Transport` (from `@browsercore/contracts`), performs the proxy handshake on it, and hands the same stream back tunneled, ready for the next layer (e.g. `@browsercore/tls`).

This package contains **zero `node:*` imports** in `src/`. Sockets and DNS arrive injected through the `Platform` (from `@browsercore/contracts`); the handshakes themselves are pure byte exchanges over any `Transport`, so they are fully unit-testable against synthetic streams.

## Install

```bash
npm install @browsercore/proxy
```

## Quick usage

The high-level entry point dials the proxy itself via the injected `Platform` and returns the tunneled transport:

```ts
import { connectViaProxy, parseProxyUrl } from "@browsercore/proxy";
import type { Platform } from "@browsercore/contracts"; // assembled by browsersmith

const platform: Platform = buildNodePlatform(); // composition root of your app

// HTTP CONNECT proxy
const viaHttp = await connectViaProxy(
    parseProxyUrl("http://proxy.example.com:8080"),
    { host: "example.com", port: 443 },
    platform,
);

// SOCKS5 with client-side DNS (the hostname is resolved locally, the IP is sent)
const viaSocks5 = await connectViaProxy(
    parseProxyUrl("socks5://user:pass@proxy.example.com:1080"),
    { host: "example.com", port: 443 },
    platform,
);

// SOCKS5h with remote DNS (the hostname is sent as-is, the proxy resolves it)
const viaSocks5h = await connectViaProxy(
    parseProxyUrl("socks5h://proxy.example.com:1080"),
    { host: "example.com", port: 443 },
    platform,
);

// Every variant returns a Transport that now speaks directly to the target:
// hand it to @browsercore/tls and layer HTTP on top.
```

Already holding an open transport to the proxy (e.g. from a pool or a mock)? Use the handshake functions directly. They operate on the transport and return it tunneled:

```ts
import { establishHttpConnectTunnel, establishSocks5Tunnel } from "@browsercore/proxy";

const httpTunneled = await establishHttpConnectTunnel(
    proxyTransport,
    { host: "example.com", port: 443 },
    { username: "user", password: "pass" },
);

const socksTunneled = await establishSocks5Tunnel(
    proxyTransport,
    { host: "example.com", port: 443 },
    { username: "user", password: "pass" },
    { atyp: "domain" }, // force ATYP 0x03, remote DNS
);
```

## socks5 vs socks5h, or where DNS happens

The two SOCKS schemes differ only in **who resolves the target hostname**:

- `socks5`: the client resolves the hostname locally (via `platform.network.dns`) and sends the resulting IP literal (`ATYP 0x01`/`0x04`). The hostname never leaves the machine, but the client's resolver sees the lookup.
- `socks5h`: the hostname is sent verbatim (`ATYP 0x03`, never resolved locally) and the **proxy** performs DNS. This hides the target hostname from the local resolver and follows the proxy's view of the network.

`connectViaProxy` encodes this distinction: `socks5` requires `platform.network.dns` and resolves first; `socks5h` never touches DNS. IP-literal targets skip resolution under both schemes.

## Public API

| Export | Kind | Purpose |
| --- | --- | --- |
| `connectViaProxy()` | function | Dial the proxy via the injected `Platform` and establish the right tunnel per scheme |
| `establishSocks5Tunnel()` | function | RFC 1928/1929 handshake over an open `Transport` (method negotiation, user/pass auth, CONNECT) |
| `establishHttpConnectTunnel()` | function | HTTP CONNECT handshake over an open `Transport` (optional Basic auth) |
| `parseProxyUrl()` | function | Parse + Zod-validate `http://`, `socks5://`, `socks5h://` URLs into a `ProxyConfig` |
| `ProxyScheme` | type alias | `"http" \| "socks5" \| "socks5h"` |
| `ProxyConfig` | interface | Scheme, host, port, optional credentials (immutable) |
| `ProxyTarget` | interface | Destination host/port requested through the proxy |
| `ProxyCredentials` | interface | Username/password pair for SOCKS5 or Basic auth |
| `Socks5TunnelOptions` | interface | `atyp` override: `"domain" \| "ipv4" \| "ipv6" \| "auto"` (default `auto`) |
| `ProxyError` | class | Base typed error (`kind` + `details` + `cause`). Match on `kind`, not messages |
| `ProxyConfigError` | class | Invalid URL, unsupported scheme, or credentials that cannot be encoded on the wire |
| `ProxyAuthError` | class | SOCKS method 0xFF / RFC 1929 failure / HTTP 407 (carries `challenge`) |
| `ProxyTunnelError` | class | SOCKS reply codes 1–8 (RFC 1928 meanings) / HTTP CONNECT non-2xx (carries `code`, `meaning`) |
| `ProxyHandshakeError` | class | Malformed peer bytes, wrong versions, truncated replies |

## Package Dependencies

```
@browsercore/proxy
├── @browsercore/contracts   (Transport / Platform types, zod-validated boundaries)
└── zod                      (URL + response-head validation)

node:net / node:dns         (injected via Platform.network, never imported)
```

The HTTP CONNECT codec is internal on purpose: importing `@browsercore/http1` would be an upward dependency edge (http1 sits above transport in the layer graph) for what is a twelve-line request.

**Canonical config types (0.1.4).** `ProxyScheme`, `ProxyConfig`, `ProxyTarget`, and `ProxyCredentials` are no longer declared in this package. `@browsercore/contracts` 0.2.6 (`src/config.ts`) is their canonical home, and `@browsercore/proxy` re-exports the canonical definitions verbatim (the same rename-free adoption pattern `@browsercore/transport` 0.2.9 used for `Transport`). The public API is unchanged: same names, same shapes, now guaranteed drift-free against every other consumer of the config vocabulary. The Zod schemas in `src/schemas.ts` remain proxy-local, since validation is this package's job, and the schemas validate external data INTO the canonical type.

## Position in BrowserCore

```
Application
      │
 HTTP/3 / HTTP/2 / HTTP/1
      │
 TLS
      │
 @browsercore/proxy   ← this package (tunnels a Transport through a proxy)
      │
 @browsercore/transport
      │
     TCP
      │
     IP
```

## Limitations & future work

- **No `https` scheme proxy in v0.1.0.** Tunneling through a TLS-encrypted proxy would require an upward dependency on `@browsercore/tls`, which the layer graph forbids for this package. The planned path is an injected `wrapTls(transport) => Promise<TlsConnection>`-style hook supplied by the composition root, so the proxy layer stays runtime- and stack-agnostic. Until then, dial TLS proxies outside this package and pass the resulting transport to the handshake functions.
- **SOCKS5 only speaks CONNECT** (`CMD 0x01`); BIND and UDP ASSOCIATE are out of scope for a browser stack.
- **GSSAPI auth (method 0x01) is not offered**: the offered methods are `0x00` and `0x02` (when credentials are configured), per RFC 1928.
- **Handshake reads are bounded, not timed.** The CONNECT response head is capped at 64 KiB; wall-clock timeouts are the injected transport's concern (`readTimeoutMs` in `@browsercore/transport`).


## Contributing

Contributions are welcome: bug reports, reproductions, docs and code alike. Start with [CONTRIBUTING.md](CONTRIBUTING.md); the full guide lives in the [browsersmith repo](https://github.com/jverneuer/browsersmith/blob/main/CONTRIBUTING.md). First timer? Check the [`good first issue`](https://github.com/jverneuer/browsercore-proxy/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label. Security issues: [SECURITY.md](SECURITY.md), never a public issue.

## License

MIT
