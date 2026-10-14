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
#include "../transform_private.h"

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

/* Walk the chain once. With `out` NULL it only counts the pushes; with `out` set
 * the push number j (in push order) is stored as dword `total - 1 - j` when that
 * dword is below `room`, so the dwords kept are the FIRST `room` of the payload
 * (the last pushes) and no more than `room` dwords are ever written. */
static uint32_t chain_walk(const uint8_t *in, uint64_t n, uint8_t *out, uint64_t room,
			   uint32_t total, int *ended, int *cut)
{
	uint32_t eax = 0, b, m = 0;
	uint64_t at = 0;
	int zeroed = 0;

	*ended = *cut = 0;
	while (at < n) {
		uint8_t op = in[at];

		if (op == 0x2du || op == 0x25u) {       /* sub / and eax, imm32 */
			if (at + 5u > n) {
				*cut = 1;
				break;
			}
			if (op == 0x2du) {
				eax -= kof_ld_le32(in + at + 1u);
			} else {
				eax &= kof_ld_le32(in + at + 1u);
				if (!eax)
					zeroed = 1;
			}
			at += 5u;
		} else if (op == 0x50u) {               /* push eax */
			if (zeroed) {
				uint64_t d = (uint64_t)total - 1u - m;

				if (out && d < room)
					for (b = 0; b < 4u; b++)
						out[4u * d + b] = (uint8_t)(eax >> (b * 8));
				m++;
			}
			at += 1u;
		} else if (op == 0x54u || op == 0x58u || op == 0x5cu) {
			at += 1u;               /* push esp / pop eax / pop esp */
		} else {
			*ended = 1;             /* not part of the chain */
			break;
		}
	}
	return m;
}

static kuncoat_st_t sub_chain(const uint8_t *in, uint64_t n, uint8_t *out, uint64_t cap,
		      uint64_t *w)
{
	int ended, cut;
	uint32_t total = chain_walk(in, n, NULL, 0, 0, &ended, &cut);
	const uint64_t room = cap / 4u;
	const uint64_t kept = total < room ? total : room;

	/* The payload is built down the stack: the last push is its first dword. The
	 * second walk stores each dword where it belongs, so what is kept when the room
	 * is short is the BEGINNING of the payload. `in` and `out` must not overlap. */
	if (kept)
		(void)chain_walk(in, n, out, room, total, &ended, &cut);
	*w = kept * 4u;
	if (!ended)
		return KUNCOAT_TRUNCATED;       /* the data ended with the chain open */
	return total > room ? KUNCOAT_OVER_BUDGET : KUNCOAT_OK;
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


static enum kuncoat_status cipher_run(const struct kuncoat_step *s,
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

/* Appends at out[*w]. The routines above count from the start of what they are
 * given, so "did the room cut the answer" compares what THIS call wrote with `n`,
 * not the absolute index: they get the tail of the buffer and a cap to match. */
enum kuncoat_status kuncoat_cipher(const struct kuncoat_step *s,
				   const uint8_t *in, uint64_t n,
				   uint8_t *out, uint64_t cap, uint64_t *w)
{
	const uint64_t w0 = *w;
	uint64_t mine = 0;
	enum kuncoat_status r = cipher_run(s, in, n, out + w0, cap > w0 ? cap - w0 : 0, &mine);

	*w = w0 + mine;
	return r;
}
