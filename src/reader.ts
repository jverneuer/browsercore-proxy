/**
 * Buffered byte reader over a pull-based Transport.
 *
 * `Transport.read()` delivers arbitrary chunks — chunk boundaries carry no
 * protocol meaning, so handshakes need exact-N-byte and read-until-delimiter
 * primitives that reassemble across chunks. Bytes consumed beyond the current
 * message stay buffered and are surfaced via {@link TransportReader.remaining}
 * so early tunnel data is never lost.
 */

import type { Transport } from "@browsercore/contracts";
import { ProxyHandshakeError } from "./errors.js";
import { concatBytes } from "./utils.js";

/** Reading primitives for proxy handshakes over one transport. */
export interface TransportReader {
    /** Resolve once exactly `count` bytes are available; consumes them. */
    readExact(count: number): Promise<Uint8Array>;
    /**
     * Resolve with the buffered bytes up to and including the first
     * occurrence of `delimiter`. Throws a {@link ProxyHandshakeError} if more
     * than `maxBytes` accumulate without a match — a proxy that never
     * terminates its response must not grow the buffer unbounded.
     */
    readUntilDelimiter(delimiter: Uint8Array, maxBytes: number): Promise<Uint8Array>;
    /** Bytes buffered past the last consumed message (early tunnel data). */
    remaining(): Uint8Array;
}

/**
 * Create a reader over an open transport. The reader holds exclusive pull
 * access for the duration of a handshake — concurrent `read()`s on the same
 * transport would race chunk ownership.
 */
export function createTransportReader(transport: Transport): TransportReader {
    // Annotated explicitly: chunks arriving from the transport widen the
    // buffer's backing type, and the local must accept every assignment.
    let buffered: Uint8Array = new Uint8Array(0);

    async function fill(): Promise<void> {
        let chunk: Uint8Array;
        try {
            chunk = await transport.read();
        } catch (e) {
            throw new ProxyHandshakeError(
                `Proxy peer stream failed mid-message: ${e instanceof Error ? e.message : String(e)}`,
                {},
                { cause: e instanceof Error ? e : new Error(String(e)) },
            );
        }
        buffered = concatBytes([buffered, chunk]);
    }

    function take(count: number): Uint8Array {
        const taken = buffered.slice(0, count);
        buffered = buffered.slice(count);
        return taken;
    }

    return {
        async readExact(count: number): Promise<Uint8Array> {
            while (buffered.length < count) {
                // oxlint-disable-next-line no-await-in-loop -- each read depends on accumulated bytes; ordering is inherent
                await fill();
            }
            return take(count);
        },

        async readUntilDelimiter(delimiter: Uint8Array, maxBytes: number): Promise<Uint8Array> {
            // Rescan only the unscanned tail — the delimiter may straddle a
            // chunk boundary, so the last delimiter.length-1 bytes are rechecked.
            let scanFrom = 0;
            for (;;) {
                const matchAt = indexOfSubsequence(buffered, delimiter, scanFrom);
                if (matchAt !== -1) {
                    return take(matchAt + delimiter.length);
                }
                scanFrom = Math.max(0, buffered.length - (delimiter.length - 1));
                if (buffered.length > maxBytes) {
                    throw new ProxyHandshakeError(
                        `Proxy response exceeded ${maxBytes} bytes without a terminator`,
                        { maxBytes },
                    );
                }
                // oxlint-disable-next-line no-await-in-loop -- each read depends on accumulated bytes; ordering is inherent
                await fill();
            }
        },

        remaining(): Uint8Array {
            return buffered;
        },
    };
}

/** First index ≥ `from` where `needle` occurs as a contiguous subsequence. */
function indexOfSubsequence(haystack: Uint8Array, needle: Uint8Array, from: number): number {
    let i = Math.max(0, from);
    while (i + needle.length <= haystack.length) {
        let matches = true;
        for (let j = 0; j < needle.length; j++) {
            if (haystack[i + j] !== needle[j]) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return i;
        }
        i += 1;
    }
    return -1;
}
