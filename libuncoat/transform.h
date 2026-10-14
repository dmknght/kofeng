#ifndef KUNCOAT_TRANSFORM_H
#define KUNCOAT_TRANSFORM_H

/*
 * transform.h - ONE API for a byte-for-byte transform with a key, in
 * either direction: the ciphers a module can ask for and the text codings a
 * person can type.
 *
 * WHY ONE. The engine had two descriptors for the same job - a cipher over a
 * range (xor with a repeating key, a counter, RC4 ...) and a coding of text
 * (base64, hex, url, xor, add, caesar) - with two entry points, two ideas of what
 * "nothing came out" means, and xor written twice. A transform STEP says what to
 * run; kuncoat_transform runs it and says whether the answer is COMPLETE.
 *
 * NOTHING HERE KNOWS AN OBJECT. Bytes in, bytes out, a budget the caller passes,
 * and an output buffer the caller owns. The lib reads no engine state, writes no
 * global state, and is safe on any number of threads. What a person typed (a key
 * in hex, a coding's name) is not an algorithm and is not here.
 *
 * THE RESULT IS A STATUS PLUS A COUNT, never a bare count in which 0 means five
 * different things:
 *
 *   KUNCOAT_OK           the answer is complete; `*produced` bytes are all of it
 *   KUNCOAT_OVER_BUDGET  the output room (cap, or the step's max_out) ran out first;
 *                        `*produced` bytes are the real beginning, the rest was
 *                        not computed
 *   KUNCOAT_TRUNCATED    the input ended before the algorithm's own end (a cut
 *                        escape, an odd hex digit, a chain with no terminator)
 *   KUNCOAT_CORRUPT      the input is not what the algorithm reads (a character
 *                        outside the alphabet, a `%` that is not an escape, text
 *                        with no escape at all for the url coding)
 *   KUNCOAT_UNSUPPORTED  well-formed request this build cannot do: an unknown
 *                        algorithm, or a direction the algorithm has no inverse
 *                        for
 *   KUNCOAT_BAD_ARG      the step is not usable: null buffer, a keyed algorithm
 *                        with no key, a caesar shift of 0 mod 26
 *
 * `*produced` is set in EVERY case, and is the number of bytes written to `out`.
 * After a status other than OK those bytes are NOT the answer - a caller that
 * needs all of it tests for KUNCOAT_OK; a caller that can use a prefix
 * (KUNCOAT_OVER_BUDGET) says so by testing for that too.
 */

#include <stdint.h>

#include "status.h"

enum kuncoat_algo {
	KUNCOAT_ALGO_NONE = 0,

	/* ---- keyed ciphers over a range (the module ABI's kof_capsid_algo) ---- */

	/* out[i] = in[i] ^ key[i % key_len]. Its own inverse, so both directions run
	 * the same pass; a single typed byte is the same cipher with key_len 1. */
	KUNCOAT_ALGO_XOR_KEY = 1,
	/* out[i] = in[i] ^ (uint8_t)(k32 + i). Its own inverse. */
	KUNCOAT_ALGO_XOR_COUNTER = 2,
	/* A dword at a time with feedback: p = le32(in) ^ key, emit p, key += p. Starts
	 * from k32. Ends after the first plaintext dword that is zero (emitted). If it
	 * never appears the answer is TRUNCATED (input out) or OVER_BUDGET (room out).
	 * Decode only. */
	KUNCOAT_ALGO_XOR_ADD32 = 3,
	/* A template with placeholders: `in` is the template, k32 the placeholder byte,
	 * key/key_len the subtrahends in order. Output is the template's length.
	 * Decode only. */
	KUNCOAT_ALGO_PLACEHOLDER_SUB = 4,
	/* A chain of `sub eax, imm32` that pushes its result: the payload dwords in
	 * REVERSE order. `in` and `out` must not overlap. Decode only. OK when a
	 * terminator (any byte that is not part of the chain) was reached and every
	 * dword fits; exactly filling `cap` is complete. When the room is short the
	 * output is the BEGINNING of the payload (its first dwords), OVER_BUDGET. The
	 * chain running to the end of the input with no terminator is TRUNCATED. */
	KUNCOAT_ALGO_X86_SUB_CHAIN = 5,
	/* RC4 keyed by key/key_len (at least 1). Its own inverse. */
	KUNCOAT_ALGO_RC4 = 6,

	/* ---- codings of text, both directions ---- */

	/* base64. Decode skips '=', and the white space of a wrapped encoder; any other
	 * character is CORRUPT unless KUNCOAT_F_LAX, which skips it. Encode pads. */
	KUNCOAT_ALGO_B64 = 16,
	/* hex. Decode: pairs make a byte, ' ' '\n' '\r' '\t' ':' ',' between them are
	 * skipped, an odd digit is TRUNCATED. Encode: upper case, no separator. */
	KUNCOAT_ALGO_HEX,
	/* `%XX` and nothing else. Decode reads '+' as a space and needs at least one
	 * escape; a `%` that is not an escape is CORRUPT (or TRUNCATED when cut) unless
	 * KUNCOAT_F_LAX, which keeps it as the byte it is and does not need an escape.
	 * Encode escapes all but RFC 3986's unreserved set, '+' among them. */
	KUNCOAT_ALGO_URL,
	/* Decode: byte + (uint8_t)k32. Encode: byte - (uint8_t)k32. */
	KUNCOAT_ALGO_ADD,
	/* Letters shifted by k32 % 26 (decode shifts back); nothing else moves. A shift
	 * of 0 is BAD_ARG: it is not a coding. */
	KUNCOAT_ALGO_CAESAR,
	/* The bytes in reverse order. Its own inverse. `in` and `out` must not overlap. */
	KUNCOAT_ALGO_REVERSE
};

enum kuncoat_dir {
	KUNCOAT_DECODE = 0,     /* the form a sample wrote -> the bytes it means */
	KUNCOAT_ENCODE = 1      /* the bytes -> the form (what a rule is written against) */
};

/* Step flags. */
#define KUNCOAT_F_LAX 0x1u  /* B64 decode: skip a character outside the alphabet; URL decode: keep a stray `%` */

struct kuncoat_step {
	uint32_t        algo;           /* enum kuncoat_algo */
	uint32_t        dir;            /* enum kuncoat_dir */
	uint32_t        flags;          /* KUNCOAT_F_* */
	uint32_t        k32;            /* the numeric key, per algorithm */
	const uint8_t  *key;            /* the key bytes, or NULL */
	uint32_t        key_len;        /* length of `key` */
	/*
	 * THE MOST BYTES THIS STEP MAY PRODUCE, or 0 for as many as `cap` allows. The
	 * effective output cap is the smaller of the two. EVERY FIELD IS SET BY THE
	 * CALLER; name this one even when it is 0.
	 */
	uint64_t        max_out;
};

/*
 * Run `s` over `in[0..n)` into `out`, writing at most min(cap, s->max_out) bytes.
 * `*produced` (may be NULL) receives the bytes written, always.
 *
 * ALIASING. `out` may be `in` for the stream ciphers (XOR_KEY, XOR_COUNTER, RC4),
 * for PLACEHOLDER_SUB, and for B64 and HEX DECODE, which may also lie BEFORE `in`
 * because the write never overtakes the read - that is what lets the normaliser
 * decode a run where it sits. Every other algorithm needs a separate buffer.
 *
 * n == 0 is complete and empty: KUNCOAT_OK, produced 0.
 */
enum kuncoat_status kuncoat_transform(const struct kuncoat_step *s,
				      const uint8_t *in, uint64_t n,
				      uint8_t *out, uint64_t cap,
				      uint64_t *produced);

#endif /* KUNCOAT_TRANSFORM_H */
