/*
 * ciphers.c - the keyed ciphers behind kuncoat_transform: xor with a key, with a
 * counter, with feedback, a template with placeholders, a chain of `sub eax`, RC4.
 * See ciphers.h, and transform.h for the contract.
 *
 * Every routine below is a loop over bytes with a bound the caller gave, and
 * every one ends by saying WHY it stopped - the input ended, the room ended, or
 * the algorithm's own end was reached - because those are different answers and
 * a count alone cannot tell them apart.
 */

#include <stddef.h>

#include <kofcore.h>   /* kof_ld_le32 */

#include "ciphers.h"
#include "../transform_int.h"

static kuncoat_st_t xor_key(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
		    uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint64_t i;
	uint32_t k = 0;

	for (i = 0; i < n && *w < cap; i++) {
		out[(*w)++] = (uint8_t)(in[i] ^ s->key[k]);
		if (++k == s->key_len)
			k = 0;
	}
	return kuncoat_room_end(*w, n);
}

static kuncoat_st_t xor_counter(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
			uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint64_t i;

	for (i = 0; i < n && *w < cap; i++, (*w)++)
		out[*w] = (uint8_t)(in[i] ^ (uint8_t)(s->k32 + (uint32_t)i));
	return kuncoat_room_end(*w, n);
}

static kuncoat_st_t xor_add32(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
		      uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint32_t key = s->k32;
	uint64_t i;

	for (i = 0; i + 4u <= n && *w + 4u <= cap; i += 4u) {
		uint32_t pl = kof_ld_le32(in + i) ^ key;

		out[(*w)++] = (uint8_t)pl;
		out[(*w)++] = (uint8_t)(pl >> 8);
		out[(*w)++] = (uint8_t)(pl >> 16);
		out[(*w)++] = (uint8_t)(pl >> 24);
		if (!pl)
			return KUNCOAT_OK;      /* the stub's own end test */
		key += pl;
	}
	/* The end test never fired: the input ran out (a partial dword, or none
	 * left) or the room did. The two are told apart because only the second
	 * is cured by a bigger buffer. */
	return i + 4u > n ? KUNCOAT_TRUNCATED : KUNCOAT_OVER_BUDGET;
}

static kuncoat_st_t placeholder_sub(const struct kuncoat_step *s, const uint8_t *in,
			    uint64_t n, uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint64_t at = 0, i;
	uint32_t src;
	uint8_t mark = (uint8_t)s->k32;

	*w = n < cap ? n : cap;
	for (i = 0; i < *w; i++)
		out[i] = in[i];
	for (src = 0; src < s->key_len; src++) {
		while (at < *w && out[at] != mark)
			at++;
		if (at >= *w)
			break;          /* fewer placeholders than subtrahends */
		out[at] = (uint8_t)(mark - s->key[src]);
		at++;
	}
	return kuncoat_room_end(*w, n);
}

static kuncoat_st_t sub_chain(const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap,
		      uint64_t *w)
{
	uint32_t eax = 0, k, b, m = 0;
	uint64_t at = 0;
	int zeroed = 0, ended = 0, cut = 0;
	const uint64_t room = cap / 4u;

	/* The pushed dwords are written into the output as they come and reversed in
	 * place at the end, so nothing is held but the output: `room` dwords never
	 * overrun `cap`. `in` and `out` must not overlap. */
	if (!room)
		return KUNCOAT_OVER_BUDGET;
	while (at < n && m < room) {
		uint8_t op = in[at];

		if (op == 0x2du) {              /* sub eax, imm32 */
			if (at + 5u > n) {
				cut = 1;
				break;
			}
			eax -= kof_ld_le32(in + at + 1u);
			at += 5u;
		} else if (op == 0x25u) {       /* and eax, imm32 */
			if (at + 5u > n) {
				cut = 1;
				break;
			}
			eax &= kof_ld_le32(in + at + 1u);
			if (!eax)
				zeroed = 1;
			at += 5u;
		} else if (op == 0x50u) {       /* push eax */
			if (zeroed) {
				/* Written in order, reversed below. */
				for (b = 0; b < 4u; b++)
					out[4u * m + b] = (uint8_t)(eax >> (b * 8));
				m++;
			}
			at += 1u;
		} else if (op == 0x54u || op == 0x58u || op == 0x5cu) {
			at += 1u;               /* push esp / pop eax / pop esp */
		} else {
			ended = 1;              /* not part of the chain */
			break;
		}
	}
	/* The payload is built down the stack: the last push is its first dword. */
	for (k = 0; k < m / 2u; k++)
		for (b = 0; b < 4u; b++) {
			uint8_t t = out[4u * k + b];

			out[4u * k + b] = out[4u * (m - 1u - k) + b];
			out[4u * (m - 1u - k) + b] = t;
		}
	*w = (uint64_t)m * 4u;
	if (ended)
		return KUNCOAT_OK;
	if (!cut && at < n)
		return KUNCOAT_OVER_BUDGET;     /* the room filled with chain left */
	return KUNCOAT_TRUNCATED;               /* the data ended with the chain open */
}

static kuncoat_st_t rc4(const struct kuncoat_step *s, const uint8_t *in, uint64_t n,
		uint8_t *out, uint64_t cap, uint64_t *w)
{
	uint8_t st[256], t;
	uint32_t a, j = 0, x = 0;
	uint64_t i;

	for (a = 0; a < 256u; a++)
		st[a] = (uint8_t)a;
	for (a = 0; a < 256u; a++) {
		j = (j + st[a] + s->key[a % s->key_len]) & 0xffu;
		t = st[a];
		st[a] = st[j];
		st[j] = t;
	}
	j = 0;
	for (i = 0; i < n && *w < cap; i++) {
		x = (x + 1u) & 0xffu;
		j = (j + st[x]) & 0xffu;
		t = st[x];
		st[x] = st[j];
		st[j] = t;
		out[(*w)++] = (uint8_t)(in[i] ^ st[(uint8_t)(st[x] + st[j])]);
	}
	return kuncoat_room_end(*w, n);
}


enum kuncoat_status kuncoat_cipher(const struct kuncoat_step *s,
				   const uint8_t *in, uint64_t n,
				   uint8_t *out, uint64_t cap, uint64_t *w)
{
	switch (s->algo) {
	case KUNCOAT_ALGO_XOR_KEY:
		return xor_key(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_XOR_COUNTER:
		return xor_counter(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_XOR_ADD32:
		return xor_add32(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_PLACEHOLDER_SUB:
		return placeholder_sub(s, in, n, out, cap, w);
	case KUNCOAT_ALGO_X86_SUB_CHAIN:
		return sub_chain(in, n, out, cap, w);
	case KUNCOAT_ALGO_RC4:
		return rc4(s, in, n, out, cap, w);
	default:
		return KUNCOAT_UNSUPPORTED;
	}
}
