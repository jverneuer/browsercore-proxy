/**
 * High-level proxy entry point: dial the proxy via the injected Platform,
 * dispatch to the right handshake per scheme, return the tunneled transport.
 *
 * This is the only module that touches the network — everything below it is
 * a pure byte exchange over an injected Transport.
 */

import type { Platform, Socket, Transport } from "@browsercore/contracts";
import { establishHttpConnectTunnel } from "./http-connect.js";
import { ProxyError } from "./errors.js";
import { createSocketTransport } from "./socket-transport.js";
import { establishSocks5Tunnel } from "./socks5.js";
import type { ProxyConfig, ProxyCredentials, ProxyTarget } from "./types.js";
import { assertNever, isIpLiteral } from "./utils.js";

/**
 * Connect to `target` through `proxy`, dialing the proxy itself over the
 * injected platform.
 *
 * Scheme dispatch:
 * - `http` — HTTP CONNECT tunnel; the target hostname is sent in the request
 *   line and resolved by the proxy
 * - `socks5` — local DNS: resolve `target.host` via `platform.network.dns`
 *   (skipped for IP literals), then SOCKS5 CONNECT with the resolved IP
 * - `socks5h` — remote DNS: SOCKS5 CONNECT with the hostname verbatim
 *   (`atyp: "domain"`, never resolved locally)
 *
 * @param proxy - Parsed/validated proxy endpoint (`parseProxyUrl` output).
 * @param target - Destination to reach through the proxy.
 * @param platform - Composition root with at least `network.tcp`
 *   (and `network.dns` for `socks5` with a hostname target).
 * @returns A transport tunneled to the target, ready for the next layer.
 * @throws {@link ProxyError} the platform lacks the required network
 *   capability, or DNS returned no addresses.
 * @throws one of the handshake errors — see `establishSocks5Tunnel` /
 *   `establishHttpConnectTunnel`.
 *
 * @since 0.1.0
 */
export async function connectViaProxy(
    proxy: ProxyConfig,
    target: ProxyTarget,
    platform: Platform,
): Promise<Transport> {
    // Dial first so an unreachable proxy fails before any protocol work —
    // and before credentials validation errors mask connectivity problems.
    const socket = dialProxy(proxy, platform);
    const transport = createSocketTransport(socket);
    const credentials = credentialsFromProxyConfig(proxy);
    switch (proxy.scheme) {
        case "http":
            return establishHttpConnectTunnel(transport, target, credentials);
        case "socks5":
            // Classic socks5: the client resolves DNS and sends an IP — the
            // hostname never leaves the machine.
            return establishSocks5Tunnel(transport, await resolveTargetLocally(target, platform), credentials);
        case "socks5h":
            // Remote DNS: always send the hostname (ATYP 0x03), never resolve.
            return establishSocks5Tunnel(transport, target, credentials, { atyp: "domain" });
        default:
            return assertNever(proxy.scheme);
    }
}

/** Dial `proxy.host:proxy.port` via the platform's injected TCP provider. */
function dialProxy(proxy: ProxyConfig, platform: Platform): Socket {
    const tcp = platform.network?.tcp;
    if (tcp === undefined) {
        throw new ProxyError(
            "Platform has no network.tcp — a TCP provider is required to dial a proxy",
            { missing: "platform.network.tcp" },
        );
    }
    return tcp.connect({ host: proxy.host, port: proxy.port });
}

/**
 * Resolve a socks5 target locally. IP literals pass through untouched;
 * hostnames go through the injected DNS resolver and the first address wins
 * (the SOCKS reply, not the client, decides reachability).
 */
async function resolveTargetLocally(target: ProxyTarget, platform: Platform): Promise<ProxyTarget> {
    if (isIpLiteral(target.host)) {
        return target;
    }
    const dns = platform.network?.dns;
    if (dns === undefined) {
        throw new ProxyError(
            "Platform has no network.dns — required for scheme socks5 (client-side DNS); use socks5h to resolve on the proxy instead",
            { missing: "platform.network.dns" },
        );
    }
    const addresses = await dns.lookup(target.host, 4);
    const first = addresses[0];
    if (first === undefined) {
        throw new ProxyError(`DNS returned no addresses for "${target.host}"`, { host: target.host });
    }
    return { ...target, host: first.address };
}

/** Extract handshake credentials from a proxy config; absent username means no auth. */
function credentialsFromProxyConfig(proxy: ProxyConfig): ProxyCredentials | undefined {
    if (proxy.username === undefined) {
        return undefined;
    }
    // Username-only configs are legal: RFC 1929 allows an empty password
    // (plen=0) and Basic auth treats "user:" as an empty password too.
    return { username: proxy.username, password: proxy.password ?? "" };
}
