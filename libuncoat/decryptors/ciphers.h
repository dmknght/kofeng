#ifndef KUNCOAT_CIPHERS_H
#define KUNCOAT_CIPHERS_H

/*
 * decryptors/ciphers.h - the keyed ciphers of kuncoat_transform: KUNCOAT_ALGO_XOR_KEY,
 * XOR_COUNTER, XOR_ADD32, PLACEHOLDER_SUB, X86_SUB_CHAIN and RC4.
 *
 * The public entry is kuncoat_transform (transform.h), which checks the step once
 * and sends a cipher here. kuncoat_cipher is the part that does the work: it
 * trusts the step and the buffers, appends at out[*w] and returns why it stopped
 * (the contract is transform.h's). An algorithm that is not a cipher is
 * KUNCOAT_UNSUPPORTED.
 *
 * NOT HERE YET: XChaCha20 (to do, not the first priority; owner 2026-11-15). Measured
 * on a real APT set (four x64 DLLs: a service-DLL loader, an HTTPS backdoor and two
 * plug-ins, each statically linked with Crypto++): every interesting string is stored
 * as base64 text in .rdata and decrypted at run time by Crypto++ XChaCha20, and the
 * key and the nonce sit in the SAME .rdata as base64 text, next to the ciphertexts:
 *   key   = base64 of 32 bytes (44 chars ending '='), nonce = base64 of 24 bytes (32
 *   chars), ciphertext = base64 of the plaintext length, no tag (no Poly1305 here).
 * The cipher, exactly as it decrypted those strings (checked by decrypting them):
 *   subkey = HChaCha20(key, nonce[0..16))  - the 20-round ChaCha core on the constants
 *            "expand 32-byte k", the key and nonce[0..16), output words 0-3 and 12-15;
 *   stream = ChaCha20 (20 rounds, IETF layout) with that subkey, 96-bit nonce =
 *            four zero bytes || nonce[16..24), BLOCK COUNTER STARTING AT 1 (counter 0
 *            gives garbage for these strings);
 *   plain  = ciphertext XOR stream.
 * Recovered that way: the install path and export of the next stage, the event name
 * used as a single-instance mark, and the backdoor's C2 URL templates, cookie format
 * and User-Agent - i.e. the whole configuration that static analysis otherwise misses.
 * The constant "expand 32-byte k" does NOT appear as a string in these files (Crypto++
 * builds the state with immediates), so recognising the cipher is a code question.
 * Where it goes: KUNCOAT_ALGO_XCHACHA20 here (buffers in, bytes out; key, nonce and
 * the initial counter in the step), a ChaCha20 core shared by both forms. Finding the
 * key and nonce is NOT kuncoat's job: a routine (bases/) or the engine's string pass
 * pairs a 32-byte and a 24-byte base64 constant with the other base64 constants of the
 * same section and keeps a candidate only when the output is text. A third companion
 * file of the set (520 bytes, entropy 7.55) did not decrypt with any embedded key: its
 * key comes from somewhere else; do not assume every blob of a set shares one key.
 */

#include <stdint.h>

#include "../transform.h"

enum kuncoat_status kuncoat_cipher(const struct kuncoat_step *s,
				   const uint8_t *in, uint64_t n,
				   uint8_t *out, uint64_t cap, uint64_t *w);

#endif /* KUNCOAT_CIPHERS_H */
