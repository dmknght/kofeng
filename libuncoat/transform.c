/*
 * transform.c - kuncoat_transform: the one entry point over the decryptors
 * (decryptors/ciphers.c), the decoders (decoders/codings.c) and the string functions
 * (decoders/strfn.c). It checks the
 * step once and hands the work to the part that owns the algorithm. See
 * transform.h for the contract.
 */

#include <stddef.h>

#include "transform_private.h"
#include "decryptors/ciphers.h"
#include "decoders/codings.h"
#include "decoders/strfn.h"

/* Is `dir` one the algorithm has? The ciphers with feedback or a template have no
 * inverse here; the rest either have a pair or are their own inverse. */
static int has_dir(uint32_t algo, uint32_t dir)
{
	if (dir != KUNCOAT_DECODE && dir != KUNCOAT_ENCODE)
		return 0;
	switch (algo) {
	case KUNCOAT_ALGO_XOR_ADD32:
	case KUNCOAT_ALGO_PLACEHOLDER_SUB:
	case KUNCOAT_ALGO_X86_SUB_CHAIN:
	case KUNCOAT_ALGO_REPLACE: case KUNCOAT_ALGO_TRANSLATE: case KUNCOAT_ALGO_SLICE:
	case KUNCOAT_ALGO_CASE: case KUNCOAT_ALGO_TRIM: case KUNCOAT_ALGO_REPEAT: case KUNCOAT_ALGO_SPLIT: case KUNCOAT_ALGO_JOIN: case KUNCOAT_ALGO_CUTHEAD:
	case KUNCOAT_ALGO_CUTTAIL: case KUNCOAT_ALGO_LENGTH: case KUNCOAT_ALGO_FORMAT: case KUNCOAT_ALGO_MAP:
		return dir == KUNCOAT_DECODE;
	default:
		return 1;
	}
}


enum kuncoat_status kuncoat_transform(const struct kuncoat_step *s,
				      const uint8_t *in, uint64_t n,
				      uint8_t *out, uint64_t cap,
				      uint64_t *produced)
{
	uint64_t w = 0;
	kuncoat_st_t r;

	if (produced)
		*produced = 0;
	if (!s || !in || !out)
		return KUNCOAT_BAD_ARG;
	if (s->algo == KUNCOAT_ALGO_NONE || !has_dir(s->algo, s->dir))
		return KUNCOAT_UNSUPPORTED;
	switch (s->algo) {
	case KUNCOAT_ALGO_XOR_KEY: case KUNCOAT_ALGO_RC4:
		if (!s->key || !s->key_len)
			return KUNCOAT_BAD_ARG;
		break;
	case KUNCOAT_ALGO_PLACEHOLDER_SUB:
		if (!s->key)
			return KUNCOAT_BAD_ARG;
		break;
	case KUNCOAT_ALGO_CAESAR:
		if (!(s->k32 % 26u))
			return KUNCOAT_BAD_ARG;
		break;
	case KUNCOAT_ALGO_REPLACE:
		if (!s->key || !s->k32 || s->key_len < s->k32)
			return KUNCOAT_BAD_ARG;
		break;
	case KUNCOAT_ALGO_TRANSLATE:
		/* in 64 bits: `2u * k32` wraps at k32 = 2^31 and a key of no bytes passed (L10 of the lexer audit) */
		if (!s->key || !s->k32 || ((s->flags & KUNCOAT_F_RANGES) ? s->key_len <= s->k32 : (uint64_t)s->key_len != 2u * (uint64_t)s->k32))
			return KUNCOAT_BAD_ARG;
		break;
	case KUNCOAT_ALGO_CUTHEAD: case KUNCOAT_ALGO_CUTTAIL:
		if (!s->key || !s->key_len)
			return KUNCOAT_BAD_ARG;
		break;
	case KUNCOAT_ALGO_MAP:
		if (!s->key || !s->key_len)
			return KUNCOAT_BAD_ARG;
		break;
	case KUNCOAT_ALGO_SPLIT:
		if (!s->key || !s->key_len)
			return KUNCOAT_BAD_ARG;
		break;
	case KUNCOAT_ALGO_SLICE: case KUNCOAT_ALGO_CASE: case KUNCOAT_ALGO_TRIM: case KUNCOAT_ALGO_REPEAT: case KUNCOAT_ALGO_JOIN:
	case KUNCOAT_ALGO_LENGTH: case KUNCOAT_ALGO_FORMAT:
		break;
	case KUNCOAT_ALGO_XOR_COUNTER: case KUNCOAT_ALGO_XOR_ADD32:
	case KUNCOAT_ALGO_X86_SUB_CHAIN: case KUNCOAT_ALGO_B64:
	case KUNCOAT_ALGO_HEX: case KUNCOAT_ALGO_URL: case KUNCOAT_ALGO_ADD:
	case KUNCOAT_ALGO_REVERSE: case KUNCOAT_ALGO_ESCAPE:
		break;
	default:
		return KUNCOAT_UNSUPPORTED;
	}
	/* nothing to do, and that is all of it - but a split of nothing is ONE empty piece, the length of nothing is "0", a format of nothing with arguments is an error (tcl's), and the empty list of a join is "" */
	if (!n && s->algo != KUNCOAT_ALGO_SPLIT && s->algo != KUNCOAT_ALGO_LENGTH && s->algo != KUNCOAT_ALGO_FORMAT)
		return KUNCOAT_OK;
	if (s->max_out && cap > s->max_out)
		cap = s->max_out;
	if (!cap)
		return KUNCOAT_OVER_BUDGET;

	switch (s->algo) {
	case KUNCOAT_ALGO_XOR_KEY: case KUNCOAT_ALGO_XOR_COUNTER:
	case KUNCOAT_ALGO_XOR_ADD32: case KUNCOAT_ALGO_PLACEHOLDER_SUB:
	case KUNCOAT_ALGO_X86_SUB_CHAIN: case KUNCOAT_ALGO_RC4:
		r = kuncoat_cipher(s, in, n, out, cap, &w);
		break;
	case KUNCOAT_ALGO_REPLACE: case KUNCOAT_ALGO_TRANSLATE: case KUNCOAT_ALGO_SLICE:
	case KUNCOAT_ALGO_CASE: case KUNCOAT_ALGO_TRIM: case KUNCOAT_ALGO_REPEAT: case KUNCOAT_ALGO_SPLIT: case KUNCOAT_ALGO_JOIN: case KUNCOAT_ALGO_CUTHEAD:
	case KUNCOAT_ALGO_CUTTAIL: case KUNCOAT_ALGO_LENGTH: case KUNCOAT_ALGO_FORMAT: case KUNCOAT_ALGO_MAP:
		r = kuncoat_strfn(s, in, n, out, cap, &w);
		break;
	default:                                /* a text coding */
		r = kuncoat_coding(s, in, n, out, cap, &w);
		break;
	}
	if (produced)
		*produced = w;
	return r;
}
