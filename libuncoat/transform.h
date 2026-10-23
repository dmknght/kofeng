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
	 * skipped (KUNCOAT_F_STRICT: none is, it is CORRUPT), an odd digit is TRUNCATED. Encode: upper case, no separator. */
	KUNCOAT_ALGO_HEX,
	/* `%XX` and nothing else. Decode reads '+' as a space (KUNCOAT_F_RAW: keeps it) and needs at least one
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
	KUNCOAT_ALGO_REVERSE,
	/* `<s>xHH` repeated: a C or Python string escape, or the same shape written with a slash.
	 * `s` is the ONE separator byte, k32 (a backslash when k32 is 0; a letter, a digit or `x`
	 * is BAD_ARG). Decode needs every byte of the input to be part of a whole escape with that
	 * separator - the digits in either case, mixed within a run too - and anything else is
	 * CORRUPT, an escape cut short TRUNCATED. Encode: upper case digits. */
	KUNCOAT_ALGO_ESCAPE,

	/* ---- the string functions a script calls on a value, decode only ----
	 * What a script writes to hide a name is `str_replace("x", "", "ex" . "xec")`: the bytes it means
	 * are what the function gives. Each takes the subject as `in`, writes the answer to a separate
	 * `out`, and an answer longer than the room is OVER_BUDGET. An empty subject is OK and empty. */

	/* Every non-overlapping `search`, left to right, becomes `replace` (php's str_replace with two
	 * strings). key is search then replace, k32 the length of search (at least 1). KUNCOAT_F_FIRST: only
	 * the first one (javascript's replace, ruby's sub). KUNCOAT_F_ICASE: a letter of the search matches
	 * the same letter in either ASCII case (powershell's -replace); any other byte matches as it is. */
	KUNCOAT_ALGO_REPLACE = 32,
	/* Byte for byte: key is `from` then `to`, k32 the number of pairs (at least 1), key_len twice
	 * that. A byte listed twice takes the later pair, as php's strtr with two strings does. With
	 * KUNCOAT_F_RANGES the sets are tr's (k32 is the length of `from` as written, `to` the rest), and sets
	 * that do not come to as many bytes are BAD_ARG: tr pads the shorter, which no caller wants. */
	KUNCOAT_ALGO_TRANSLATE,
	/* A cut of the subject, as php's substr: k32 is the start (an int32, negative counts from the
	 * end), k32b the length (an int32, negative stops that many from the end) unless
	 * KUNCOAT_F_TOEND. A start past the end gives nothing. */
	KUNCOAT_ALGO_SLICE,
	/* ASCII letters only: k32 bit 0 upper case (clear: lower), bit 1 the first byte only. */
	KUNCOAT_ALGO_CASE,
	/* Space, \t \n \r NUL and \v off the ends: k32 bit 0 the left end, bit 1 the right. With a `key`, the bytes of the
	 * key are what is taken off instead (python's strip, javascript's trim, vbscript's Trim: each has its own set). */
	KUNCOAT_ALGO_TRIM,
	/* The subject written k32 times one after the other (python's s * n, perl's x, javascript's repeat, lua's string.rep).
	 * Nothing of the room is promised: an answer that does not fit is OVER_BUDGET, and 0 times is empty. */
	KUNCOAT_ALGO_REPEAT,
	/* The subject cut at every `key` (a separator of at least 1 byte), written as a LIST of strings (kofcore/kofstrlist.h): the pieces between, the empty ones too. KUNCOAT_F_ICASE: a
	 * letter of the separator matches either ASCII case. KUNCOAT_F_DROPTRAIL: the empty pieces at the END of the list are not written (ruby's split). Not found: one piece, the subject. */
	KUNCOAT_ALGO_SPLIT,
	/* A LIST of strings (the input, kofstrlist.h) written one after the other with `key` (any length, none when `key` is NULL) between them. A broken list is CORRUPT. */
	KUNCOAT_ALGO_JOIN,
	/* The subject without `key` at its front (the shell's ${x#p}, with a pattern that is plain text: the shortest and the longest match are the same), or as it is when it does not
	 * begin with it. A key of nothing is BAD_ARG. CUTTAIL: the same at the end (${x%p}). */
	KUNCOAT_ALGO_CUTHEAD,
	KUNCOAT_ALGO_CUTTAIL,
	/* The number of bytes of the subject, in decimal (the shell's ${#x}, tcl's string length). An empty subject is "0": the one op that answers something for nothing. */
	KUNCOAT_ALGO_LENGTH,
	/* The subject is a FORMAT, `key` the arguments as a list (kofstrlist.h): "%s" is the next argument and "%%" a percent sign, and any other "%" is CORRUPT, so is a backslash
	 * unless KUNCOAT_F_ESC (then \n, \t and \\ are what they say and any other is CORRUPT). The shell's printf runs the format again over the arguments left over
	 * (KUNCOAT_F_REUSE; with no argument or no "%s" it runs once, a missing argument being empty); without REUSE the arguments must be exactly the "%s"s (tcl's format). */
	KUNCOAT_ALGO_FORMAT,
	/* tcl's string map: `key` is the mapping as a tcl list (words by white space: k1 v1 k2 v2 ...; an element with a brace, a quote or a backslash, or an odd count, is CORRUPT). At each
	 * place the FIRST pair of the list whose key (never empty) is there is replaced by its value, and the scan goes on after the key. */
	KUNCOAT_ALGO_MAP
};

enum kuncoat_dir {
	KUNCOAT_DECODE = 0,     /* the form a sample wrote -> the bytes it means */
	KUNCOAT_ENCODE = 1      /* the bytes -> the form (what a rule is written against) */
};

/* Step flags. */
#define KUNCOAT_F_LAX 0x1u  /* B64 decode: skip a character outside the alphabet; URL decode: keep a stray `%` */
#define KUNCOAT_F_RAW 0x2u  /* URL decode: '+' stays a '+' (rawurldecode); without it '+' is a space (urldecode) */
#define KUNCOAT_F_STRICT 0x8u   /* HEX decode: nothing but pairs of digits - no separator is skipped (php's hex2bin) */
#define KUNCOAT_F_TOEND 0x4u    /* SLICE: to the end of the subject, k32b is not read */
#define KUNCOAT_F_FIRST 0x10u   /* REPLACE: the first match only */
#define KUNCOAT_F_ICASE 0x20u   /* REPLACE, SPLIT: ASCII letters of the search match in either case */
#define KUNCOAT_F_DROPTRAIL 0x40u /* SPLIT: the empty pieces at the end are dropped */
#define KUNCOAT_F_RANGES 0x80u    /* TRANSLATE: the two sets are written as tr writes them - "a-z" is the range, a "-" at either end is itself - and must come to as many bytes each */
#define KUNCOAT_F_WSLIST 0x100u   /* JOIN: the subject is a tcl list written as text (its elements the words between white space), not the list of kofstrlist.h */
#define KUNCOAT_F_REUSE 0x200u    /* FORMAT: the format is run again over the arguments left over */
#define KUNCOAT_F_ESC 0x400u      /* FORMAT: \n, \t and \\ in the format are what they say */

struct kuncoat_step {
	uint32_t        algo;           /* enum kuncoat_algo */
	uint32_t        dir;            /* enum kuncoat_dir */
	uint32_t        flags;          /* KUNCOAT_F_* */
	uint32_t        k32;            /* the numeric key, per algorithm */
	uint32_t        k32b;           /* a second number, for SLICE only */
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
 * for PLACEHOLDER_SUB, and for B64, HEX and ESCAPE DECODE, which may also lie BEFORE `in`
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
