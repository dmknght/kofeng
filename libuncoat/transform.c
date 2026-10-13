/*
 * transform.c - kuncoat_transform: the one entry point over the decryptors
 * (decryptors/ciphers.c) and the decoders (decoders/codings.c). It checks the
 * step once and hands the work to the part that owns the algorithm. See
 * transform.h for the contract.
 */

#include <stddef.h>

#include "transform_int.h"
#include "decryptors/ciphers.h"
#include "decoders/codings.h"

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
	case KUNCOAT_ALGO_XOR_COUNTER: case KUNCOAT_ALGO_XOR_ADD32:
	case KUNCOAT_ALGO_X86_SUB_CHAIN: case KUNCOAT_ALGO_B64:
	case KUNCOAT_ALGO_HEX: case KUNCOAT_ALGO_URL: case KUNCOAT_ALGO_ADD:
	case KUNCOAT_ALGO_REVERSE:
		break;
	default:
		return KUNCOAT_UNSUPPORTED;
	}
	if (!n)
		return KUNCOAT_OK;              /* nothing to do, and that is all of it */
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
	default:                                /* a text coding */
		r = kuncoat_coding(s, in, n, out, cap, &w);
		break;
	}
	if (produced)
		*produced = w;
	return r;
}
