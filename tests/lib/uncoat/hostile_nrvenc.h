/*
 * hostile_nrvenc.h - encoders for aPLib and for NRV2B / NRV2D / NRV2E (at the three
 * bit-buffer widths UPX uses), for the tests of aplib.h and nrv2.h.
 *
 * Like hostile_lzenc.h they encode exactly the operations they are told and keep the
 * history the decoder will have produced, so a test can state the expected bytes and
 * can also state a sequence no real encoder writes (a distance past the output, the
 * reuse of a distance that was never set, a 2^24 distance prefix).
 *
 * NRV2B is written from the UCL format (the loop every UPX stub shares). NRV2D/E are
 * derived from the same loop; aPLib from its public description: a bit stream whose
 * tag bytes are fetched where the first bit after the last one is needed, with data
 * bytes (literals, the low offset byte) between them in the same stream.
 */

#ifndef HOSTILE_NRVENC_H
#define HOSTILE_NRVENC_H

#include <stdint.h>
#include <string.h>

/* ---- the shared bit-and-byte stream --------------------------------------------------- */

struct hv_tw {
	uint8_t  *out;
	size_t    cap, n;
	unsigned  width;          /* bits per tag word: 8, 16 or 32 */
	unsigned  left;           /* bits not yet used in the current tag word */
	size_t    wordpos;
	uint32_t  word;
	uint8_t  *hist;           /* what the decoder will have produced */
	size_t    hn, hcap;
	uint32_t  last;           /* the last distance (NRV2) or r0 (aPLib) */
	int       lwm;            /* aPLib's "last was match" */
	int       over;
};

static inline void hv_tw_init(struct hv_tw *w, uint8_t *out, size_t cap, unsigned width, uint8_t *hist,
			      size_t hcap)
{
	memset(w, 0, sizeof *w);
	w->out = out;
	w->cap = cap;
	w->width = width;
	w->hist = hist;
	w->hcap = hcap;
	w->last = 1;
}

static inline void hv_tw_byte(struct hv_tw *w, uint8_t b)
{
	if (w->n < w->cap)
		w->out[w->n] = b;
	else
		w->over = 1;
	w->n++;
}

static inline void hv_tw_store(struct hv_tw *w)
{
	unsigned i;

	for (i = 0; i < w->width / 8u; i++)
		if (w->wordpos + i < w->cap)
			w->out[w->wordpos + i] = (uint8_t)(w->word >> (8u * i));
}

static inline void hv_tw_bit(struct hv_tw *w, unsigned b)
{
	if (!w->left) {
		w->wordpos = w->n;
		w->n += w->width / 8u;
		w->left = w->width;
		w->word = 0;
	}
	w->left--;
	w->word |= (uint32_t)(b & 1u) << w->left;
	hv_tw_store(w);
}

static inline void hv_tw_hist(struct hv_tw *w, uint8_t b)
{
	if (w->hn < w->hcap)
		w->hist[w->hn] = b;
	w->hn++;
}

static inline void hv_tw_copy(struct hv_tw *w, uint32_t dist, unsigned len)
{
	unsigned k;

	for (k = 0; k < len; k++)
		hv_tw_hist(w, w->hn >= dist && w->hn - dist < w->hcap ? w->hist[w->hn - dist] : 0);
}

/* ---- NRV2 ------------------------------------------------------------------------------ */

enum { HV_NRV2B = 0, HV_NRV2D = 1, HV_NRV2E = 2 };

/* P as (bit, stop flag) pairs, NRV2B style: the bits below the leading one, a 1 on the last. */
static inline void hv_nrv_pairs(struct hv_tw *w, uint32_t v)
{
	int top = 31, i;

	while (!((v >> top) & 1u))
		top--;
	for (i = top - 1; i >= 0; i--) {
		hv_tw_bit(w, (v >> i) & 1u);
		hv_tw_bit(w, i == 0);
	}
}

/* NRV2D/E prefix: rounds of (b1, 0, b3) with a decrement, then (b1, 1). */
static inline void hv_nrv_prefix_de(struct hv_tw *w, uint32_t p)
{
	unsigned b1[40], b3[40], nr = 0, last = p & 1u;
	uint32_t v = p >> 1, u;
	int k;

	while (v != 1) {
		u = (v + 2u) / 4u;
		b1[nr] = (v - 4u * u + 2u) >> 1;
		b3[nr] = (v - 4u * u + 2u) & 1u;
		nr++;
		v = u;
	}
	for (k = (int)nr - 1; k >= 0; k--) {
		hv_tw_bit(w, b1[k]);
		hv_tw_bit(w, 0);
		hv_tw_bit(w, b3[k]);
	}
	hv_tw_bit(w, last);
	hv_tw_bit(w, 1);
}

static inline void hv_nrv_lit(struct hv_tw *w, uint8_t b)
{
	hv_tw_bit(w, 1);
	hv_tw_byte(w, b);
	hv_tw_hist(w, b);
}

/* The length part, after the offset (carry is NRV2D/E's bit carried out of the offset). */
static inline void hv_nrv_len(struct hv_tw *w, int variant, uint32_t dist, unsigned len, unsigned carry)
{
	if (variant == HV_NRV2B) {
		unsigned m = len - 1u - (dist > 0xd00u);

		if (m >= 1 && m <= 3) {
			hv_tw_bit(w, m >> 1);
			hv_tw_bit(w, m & 1u);
		} else {
			hv_tw_bit(w, 0);
			hv_tw_bit(w, 0);
			hv_nrv_pairs(w, m - 2u);
		}
	} else if (variant == HV_NRV2D) {
		unsigned base = len - (dist > 0x500u) - 1u;

		if (base >= 1 && base <= 3) {
			if (base >> 1 != carry)
				return;                 /* the caller chose the carry from the length */
			hv_tw_bit(w, base & 1u);
		} else {
			hv_tw_bit(w, 0);
			hv_nrv_pairs(w, base - 2u);
		}
	} else {
		unsigned base = len - (dist > 0x500u) - 2u;

		if (base <= 1) {
			hv_tw_bit(w, base);             /* carry is 1 */
		} else if (base <= 3) {
			hv_tw_bit(w, 1);
			hv_tw_bit(w, base - 2u);
		} else {
			hv_tw_bit(w, 0);
			hv_nrv_pairs(w, base - 2u);
		}
	}
}

/* The carry the length wants (D/E): D: base>>1 for 1..3 else 0; E: 1 for base 0..1 else 0. */
static inline unsigned hv_nrv_carry(int variant, uint32_t dist, unsigned len)
{
	if (variant == HV_NRV2D) {
		unsigned base = len - (dist > 0x500u) - 1u;

		return base >= 1 && base <= 3 ? base >> 1 : 0;
	}
	if (variant == HV_NRV2E) {
		unsigned base = len - (dist > 0x500u) - 2u;

		return base <= 1 ? 1u : 0u;
	}
	return 0;
}

/* A match of `len` bytes at `dist`; with prefix_override != 0 the prefix value is forced. */
static inline void hv_nrv_match(struct hv_tw *w, int variant, uint32_t dist, unsigned len)
{
	unsigned carry = hv_nrv_carry(variant, dist, len);
	uint32_t packed = variant == HV_NRV2B ? dist - 1u : 2u * dist - 1u - carry, p = 3u + (packed >> 8);

	hv_tw_bit(w, 0);
	if (variant == HV_NRV2B)
		hv_nrv_pairs(w, p);
	else
		hv_nrv_prefix_de(w, p);
	hv_tw_byte(w, (uint8_t)packed);
	hv_nrv_len(w, variant, dist, len, carry);
	w->last = dist;
	hv_tw_copy(w, dist, len);
}

/* The previous distance again. */
static inline void hv_nrv_rep(struct hv_tw *w, int variant, unsigned len)
{
	unsigned carry = hv_nrv_carry(variant, w->last, len);

	hv_tw_bit(w, 0);
	if (variant == HV_NRV2B) {
		hv_nrv_pairs(w, 2);
	} else {
		hv_nrv_prefix_de(w, 2);
		hv_tw_bit(w, carry);
	}
	hv_nrv_len(w, variant, w->last, len, carry);
	hv_tw_copy(w, w->last, len);
}

/* A match whose prefix and low byte are given as they are written (the lies). */
static inline void hv_nrv_match_raw(struct hv_tw *w, int variant, uint32_t prefix, uint8_t low,
				    unsigned len_bits_value)
{
	hv_tw_bit(w, 0);
	if (variant == HV_NRV2B)
		hv_nrv_pairs(w, prefix);
	else
		hv_nrv_prefix_de(w, prefix);
	hv_tw_byte(w, low);
	hv_tw_bit(w, (len_bits_value >> 1) & 1u);
	hv_tw_bit(w, len_bits_value & 1u);
}

static inline void hv_nrv_end(struct hv_tw *w, int variant)
{
	hv_tw_bit(w, 0);
	if (variant == HV_NRV2B)
		hv_nrv_pairs(w, 0x1000002u);
	else
		hv_nrv_prefix_de(w, 0x1000002u);
	hv_tw_byte(w, 0xFF);
}

/* ---- aPLib ------------------------------------------------------------------------------- */

static inline void hv_ap_gamma(struct hv_tw *w, uint32_t v)
{
	int top = 31, i;

	while (!((v >> top) & 1u))
		top--;
	for (i = top - 1; i >= 0; i--) {
		hv_tw_bit(w, (v >> i) & 1u);
		hv_tw_bit(w, i != 0);
	}
}

static inline void hv_ap_first(struct hv_tw *w, uint8_t b)
{
	w->last = 0;                    /* aPLib's r0 starts at 0: a rep before any match is refused */
	hv_tw_byte(w, b);
	hv_tw_hist(w, b);
}

static inline void hv_ap_lit(struct hv_tw *w, uint8_t b)
{
	hv_tw_bit(w, 0);
	hv_tw_byte(w, b);
	hv_tw_hist(w, b);
	w->lwm = 0;
}

/* The length adjustment the format gives a distance. */
static inline unsigned hv_ap_adj(uint32_t d)
{
	return (d >= 32000u ? 1u : 0u) + (d >= 1280u ? 1u : d < 128u ? 2u : 0u);
}

static inline void hv_ap_match(struct hv_tw *w, uint32_t dist, unsigned len)
{
	unsigned adj = w->lwm ? 2u : 3u;

	hv_tw_bit(w, 1);
	hv_tw_bit(w, 0);
	hv_ap_gamma(w, (dist >> 8) + adj);
	hv_tw_byte(w, (uint8_t)dist);
	hv_ap_gamma(w, len - hv_ap_adj(dist));
	w->last = dist;
	w->lwm = 1;
	hv_tw_copy(w, dist, len);
}

/* The previous offset again: only when the last item was not a match. */
static inline void hv_ap_rep(struct hv_tw *w, unsigned len)
{
	hv_tw_bit(w, 1);
	hv_tw_bit(w, 0);
	hv_ap_gamma(w, 2);
	hv_ap_gamma(w, len);
	w->lwm = 1;
	hv_tw_copy(w, w->last, len);
}

static inline void hv_ap_short(struct hv_tw *w, unsigned dist, unsigned len)
{
	hv_tw_bit(w, 1);
	hv_tw_bit(w, 1);
	hv_tw_bit(w, 0);
	hv_tw_byte(w, (uint8_t)((dist << 1) | (len - 2u)));
	w->last = dist;
	w->lwm = 1;
	hv_tw_copy(w, dist, len);
}

static inline void hv_ap_single(struct hv_tw *w, unsigned dist)
{
	unsigned i;

	hv_tw_bit(w, 1);
	hv_tw_bit(w, 1);
	hv_tw_bit(w, 1);
	for (i = 4; i-- > 0;)
		hv_tw_bit(w, (dist >> i) & 1u);
	if (dist)
		hv_tw_copy(w, dist, 1);
	else
		hv_tw_hist(w, 0);
	w->lwm = 0;
}

static inline void hv_ap_end(struct hv_tw *w)
{
	hv_tw_bit(w, 1);
	hv_tw_bit(w, 1);
	hv_tw_bit(w, 0);
	hv_tw_byte(w, 0);
}

#endif /* HOSTILE_NRVENC_H */
