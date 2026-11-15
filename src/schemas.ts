/**
 * Zod schemas for @browsercore/proxy wire/config boundaries.
 *
 * Proxy URLs and CONNECT response heads are untrusted external data (Rule
 * #12): they are parsed loosely, then validated here before any field flows
 * into the domain types. Domain types live in `types.ts`; wire schemas in
 * this file (Rule #20).
 */

import { z } from "zod";

/**
 * Structured parts of a proxy URL, after `new URL()` extraction and before
 * conversion to a {@link ProxyConfig}.
 *
 * The scheme is constrained to the v0.1.0 set, the host must be non-empty,
 * and the port (explicit or scheme default) must be in 1–65535.
 */
export const ProxyUrlPartsSchema = z.object({
    scheme: z.enum(["http", "socks5", "socks5h"]),
    host: z.string().min(1),
    port: z.number().int().min(1).max(65535),
    username: z.string().optional(),
    password: z.string().optional(),
});

/** Validated proxy URL parts — structurally a `ProxyConfig` pending assembly. */
export type ProxyUrlParts = z.infer<typeof ProxyUrlPartsSchema>;

/**
 * The status line of an HTTP CONNECT response.
 *
 * CONNECT runs before any HTTP messaging, so proxies answer with a bare
 * status line; only `HTTP/1.0` and `HTTP/1.1` are accepted (an `HTTP/2`
 * status line means the peer is speaking a different protocol — h2 CONNECT
 * is a different mechanism entirely).
 */
export const ConnectStatusLineSchema = z.object({
    version: z.string().regex(/^HTTP\/1\.[01]$/u, "must be HTTP/1.0 or HTTP/1.1"),
    status: z.number().int().min(100).max(599),
    reason: z.string(),
});
