/**
 * Proxy URL parsing — the configuration boundary.
 *
 * URLs are untrusted external input (Rule #12): `new URL()` provides loose
 * structural parsing, then every field is Zod-validated before it becomes a
 * {@link ProxyConfig}. Percent-encoded userinfo is decoded per component.
 */

import { ProxyConfigError } from "./errors.js";
import { ProxyUrlPartsSchema } from "./schemas.js";
import type { ProxyConfig, ProxyScheme } from "./types.js";

/**
 * Scheme default ports, applied when the URL omits one — mirrors curl's
 * `http://` / `socks5://` defaults so configs stay minimal.
 */
const DEFAULT_PROXY_PORTS: Readonly<Record<ProxyScheme, number>> = {
    http: 80,
    socks5: 1080,
    socks5h: 1080,
};

/**
 * Parse a proxy URL into a validated {@link ProxyConfig}.
 *
 * Accepts `http://`, `socks5://`, and `socks5h://` URLs with optional
 * `user:pass@` userinfo (percent-encoded characters are decoded). The scheme
 * is matched case-insensitively; a missing port falls back to the scheme
 * default (80 for http, 1080 for socks5/socks5h).
 *
 * @param url - The proxy URL, e.g. `"socks5h://user:p%40ss@proxy.example.com:1080"`.
 * @returns An immutable, validated proxy configuration.
 * @throws {@link ProxyConfigError} the URL is unparseable, the scheme is
 *   unsupported, the port is out of range, the host is empty, or the userinfo
 *   contains malformed percent-encoding.
 *
 * @example
 * ```ts
 * const proxy = parseProxyUrl("socks5://user:pass@10.0.0.1:1080");
 * // { scheme: "socks5", host: "10.0.0.1", port: 1080, username: "user", password: "pass" }
 * ```
 *
 * @since 0.1.0
 */
export function parseProxyUrl(url: string): ProxyConfig {
    return validateProxyUrlParts(extractProxyUrlParts(url), url);
}

/**
 * Structural extraction via the platform URL parser. Returns `unknown` —
 * the fields become trustworthy only after Zod validation.
 */
function extractProxyUrlParts(url: string): unknown {
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        throw new ProxyConfigError(`Invalid proxy URL: "${url}"`, { url });
    }
    const scheme = parsed.protocol.slice(0, -1).toLowerCase();
    if (!isProxyScheme(scheme)) {
        throw new ProxyConfigError(
            `Unsupported proxy scheme "${parsed.protocol}" — expected http, socks5, or socks5h`,
            { url, scheme: parsed.protocol },
        );
    }
    const port = parsed.port === "" ? DEFAULT_PROXY_PORTS[scheme] : Math.trunc(Number(parsed.port));
    return {
        scheme,
        // URL serializes IPv6 hosts with brackets ("[::1]") and preserves the
        // case of non-special-scheme hosts ("SOCKS5://Proxy.COM"); the wire
        // formats want a bare, normalized hostname.
        host: stripIpv6Brackets(parsed.hostname).toLowerCase(),
        port,
        username: parsed.username === "" ? undefined : percentDecode(parsed.username, url),
        password: parsed.password === "" ? undefined : percentDecode(parsed.password, url),
    };
}

/** Drop the "["…"]" wrapper URL parsing leaves on IPv6 hostnames. */
function stripIpv6Brackets(hostname: string): string {
    if (hostname.startsWith("[") && hostname.endsWith("]")) {
        return hostname.slice(1, -1);
    }
    return hostname;
}

/** Run the extracted parts through the boundary schema and assemble the config. */
function validateProxyUrlParts(parts: unknown, url: string): ProxyConfig {
    const result = ProxyUrlPartsSchema.safeParse(parts);
    if (!result.success) {
        const issues = result.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`);
        throw new ProxyConfigError(`Invalid proxy URL "${url}": ${issues.join("; ")}`, {
            url,
            issues,
        });
    }
    // Rebuild explicitly so absent userinfo stays absent — Zod preserves
    // undefined-valued keys, which would leak into callers' shallow compares.
    const { scheme, host, port, username, password } = result.data;
    if (username === undefined && password === undefined) {
        return { scheme, host, port };
    }
    return { scheme, host, port, username, password };
}

function isProxyScheme(value: string): value is ProxyScheme {
    return value === "http" || value === "socks5" || value === "socks5h";
}

/** Percent-decode one userinfo component; a lone "%" or bad escape is a typed error. */
function percentDecode(component: string, url: string): string {
    try {
        return decodeURIComponent(component);
    } catch {
        throw new ProxyConfigError(
            `Proxy URL contains malformed percent-encoding in userinfo: "${url}"`,
            { url },
        );
    }
}
