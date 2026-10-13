/*
 * hostile_lzenc.h - an LZMA encoder small enough to read, for the tests of lzma.h.
 *
 * It encodes what it is TOLD: literal, match (length, distance), rep match (which
 * of the four, length), short rep, end marker. There is no search. That is the
 * point: a test states the exact sequence of operations and so can state the exact
 * bytes the decoder has to produce - and can state sequences no real encoder writes
 * (a distance past what was produced, a length past the room, the end marker in the
 * middle, 2^32-1 as a distance).
 *
 * The probability model is the format's, written here from the specification, not
 * read from the decoder. The encoder keeps its own history so matches are resolved
 * against what the decoder will have produced.
 */

#ifndef HOSTILE_LZENC_H
#define HOSTILE_LZENC_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct hv_lz {
	/* range encoder */
	uint8_t  *out;
	size_t    cap, n;
	uint64_t  low;
	uint32_t  range;
	uint8_t   cache;
	uint64_t  cache_size;
	int       over;
	/* model */
	unsigned  lc, lp, pb;
	unsigned  state;
	uint32_t  rep[4];                       /* 1-based distances, rep[0] is the last */
	uint16_t  is_match[12][16], is_rep[12], is_rep_g0[12], is_rep_g1[12], is_rep_g2[12];
	uint16_t  is_rep0_long[12][16];
	uint16_t  pos_slot[4][64], spec_pos[130], align[16];
	uint16_t  len_c[2][2 + 2 * 128 + 256];   /* [0] match, [1] rep: choice, choice2, low[16][8], mid[16][8], high[256] */
	uint16_t *lit;
	/* history: what the decoder will have produced */
	uint8_t  *hist;
	size_t    hn, hcap;
};

static inline void hv_lz_out(struct hv_lz *e, uint8_t b)
{
	if (e->n < e->cap)
		e->out[e->n] = b;
	else
		e->over = 1;
	e->n++;
}

static inline void hv_lz_shift(struct hv_lz *e)
{
	if ((uint32_t)e->low < 0xFF000000u || (e->low >> 32) != 0) {
		uint8_t carry = (uint8_t)(e->low >> 32), t = e->cache;

		do {
			hv_lz_out(e, (uint8_t)(t + carry));
			t = 0xFF;
		} while (--e->cache_size);
		e->cache = (uint8_t)(e->low >> 24);
	}
	e->cache_size++;
	e->low = (e->low & 0x00FFFFFFu) << 8;
}

static inline void hv_lz_rc_start(struct hv_lz *e, uint8_t *out, size_t cap)
{
	e->out = out; e->cap = cap; e->n = 0; e->over = 0;
	e->low = 0; e->range = 0xFFFFFFFFu; e->cache = 0; e->cache_size = 1;
}

/* Flush the range coder; returns the bytes written for this chunk/stream. */
static inline size_t hv_lz_rc_finish(struct hv_lz *e)
{
	unsigned i;

	for (i = 0; i < 5; i++)
		hv_lz_shift(e);
	return e->n;
}

static inline void hv_lz_bit(struct hv_lz *e, uint16_t *p, unsigned bit)
{
	uint32_t bound = (e->range >> 11) * *p;

	if (!bit) {
		e->range = bound;
		*p = (uint16_t)(*p + ((2048u - *p) >> 5));
	} else {
		e->low += bound;
		e->range -= bound;
		*p = (uint16_t)(*p - (*p >> 5));
	}
	while (e->range < (1u << 24)) {
		e->range <<= 8;
		hv_lz_shift(e);
	}
}

static inline void hv_lz_direct(struct hv_lz *e, uint32_t v, unsigned n)
{
	while (n--) {
		e->range >>= 1;
		if ((v >> n) & 1u)
			e->low += e->range;
		while (e->range < (1u << 24)) {
			e->range <<= 8;
			hv_lz_shift(e);
		}
	}
}

static inline void hv_lz_tree(struct hv_lz *e, uint16_t *probs, unsigned nbits, uint32_t sym)
{
	uint32_t m = 1;
	unsigned i;

	for (i = nbits; i-- > 0;) {
		unsigned b = (sym >> i) & 1u;

		hv_lz_bit(e, &probs[m], b);
		m = (m << 1) | b;
	}
}

static inline void hv_lz_tree_rev(struct hv_lz *e, uint16_t *probs, unsigned nbits, uint32_t sym)
{
	uint32_t m = 1;
	unsigned i;

	for (i = 0; i < nbits; i++) {
		unsigned b = (sym >> i) & 1u;

		hv_lz_bit(e, &probs[m], b);
		m = (m << 1) | b;
	}
}

/* Forget everything the model learned (a state reset); sets the properties. */
static inline int hv_lz_reset(struct hv_lz *e, unsigned lc, unsigned lp, unsigned pb)
{
	size_t nl = (size_t)0x300u << (lc + lp), i;
	uint16_t *np = realloc(e->lit, nl * sizeof *np);

	if (!np)
		return 0;
	e->lit = np;
	for (i = 0; i < nl; i++)
		e->lit[i] = 1024;
	e->lc = lc; e->lp = lp; e->pb = pb;
	e->state = 0;
	e->rep[0] = e->rep[1] = e->rep[2] = e->rep[3] = 1;
#define HV_LZ_FILL(a) do { size_t k_; uint16_t *q_ = (uint16_t *)(a); \
		for (k_ = 0; k_ < sizeof(a) / sizeof(uint16_t); k_++) q_[k_] = 1024; } while (0)
	HV_LZ_FILL(e->is_match); HV_LZ_FILL(e->is_rep); HV_LZ_FILL(e->is_rep_g0);
	HV_LZ_FILL(e->is_rep_g1); HV_LZ_FILL(e->is_rep_g2); HV_LZ_FILL(e->is_rep0_long);
	HV_LZ_FILL(e->pos_slot); HV_LZ_FILL(e->spec_pos); HV_LZ_FILL(e->align);
	HV_LZ_FILL(e->len_c);
#undef HV_LZ_FILL
	return 1;
}

/* A new encoder: model reset, history of `hcap` bytes, range coder writing to out. */
static inline int hv_lz_init(struct hv_lz *e, uint8_t *out, size_t cap, unsigned lc, unsigned lp,
			     unsigned pb, size_t hcap)
{
	memset(e, 0, sizeof *e);
	e->hist = malloc(hcap ? hcap : 1);
	e->hcap = hcap;
	if (!e->hist || !hv_lz_reset(e, lc, lp, pb))
		return 0;
	hv_lz_rc_start(e, out, cap);
	return 1;
}

static inline void hv_lz_free(struct hv_lz *e)
{
	free(e->lit);
	free(e->hist);
	e->lit = NULL;
	e->hist = NULL;
}

static inline void hv_lz_hist(struct hv_lz *e, uint8_t b)
{
	if (e->hn < e->hcap)
		e->hist[e->hn] = b;
	e->hn++;
}

static inline unsigned hv_lz_posstate(const struct hv_lz *e)
{
	return (unsigned)e->hn & ((1u << e->pb) - 1u);
}

static inline void hv_lz_len(struct hv_lz *e, int rep, unsigned len, unsigned ps)
{
	uint16_t *c = e->len_c[rep];
	uint16_t *low = c + 2, *mid = low + 128, *high = mid + 128;
	unsigned l = len - 2u;

	if (l < 8) {
		hv_lz_bit(e, &c[0], 0);
		hv_lz_tree(e, low + ps * 8u, 3, l);
	} else if (l < 16) {
		hv_lz_bit(e, &c[0], 1);
		hv_lz_bit(e, &c[1], 0);
		hv_lz_tree(e, mid + ps * 8u, 3, l - 8u);
	} else {
		hv_lz_bit(e, &c[0], 1);
		hv_lz_bit(e, &c[1], 1);
		hv_lz_tree(e, high, 8, l - 16u);
	}
}

/* One literal byte. */
static inline void hv_lz_lit(struct hv_lz *e, uint8_t byte)
{
	unsigned ps = hv_lz_posstate(e), i;
	uint32_t sym = 1;
	size_t at = e->hn;
	uint16_t *lit = e->lit + (size_t)0x300u *
		((((uint32_t)at & ((1u << e->lp) - 1u)) << e->lc) +
		 (at ? (uint32_t)(e->hist[at - 1] >> (8u - e->lc)) : 0u));

	hv_lz_bit(e, &e->is_match[e->state][ps], 0);
	i = 8;
	if (e->state >= 7) {
		uint32_t match = at >= e->rep[0] ? e->hist[at - e->rep[0]] : 0;

		do {
			unsigned mb = (match >> 7) & 1u, b = ((unsigned)byte >> (i - 1u)) & 1u;

			match <<= 1;
			i--;
			hv_lz_bit(e, &lit[((1u + mb) << 8) + sym], b);
			sym = (sym << 1) | b;
			if (mb != b) {
				while (i) {
					b = ((unsigned)byte >> (i - 1u)) & 1u;
					i--;
					hv_lz_bit(e, &lit[sym], b);
					sym = (sym << 1) | b;
				}
				break;
			}
		} while (i);
	} else {
		while (i) {
			unsigned b = ((unsigned)byte >> (i - 1u)) & 1u;

			i--;
			hv_lz_bit(e, &lit[sym], b);
			sym = (sym << 1) | b;
		}
	}
	hv_lz_hist(e, byte);
	e->state = e->state < 4 ? 0 : (e->state < 10 ? e->state - 3 : e->state - 6);
}

static inline void hv_lz_copy_hist(struct hv_lz *e, uint32_t dist, unsigned len)
{
	unsigned k;

	for (k = 0; k < len; k++)
		hv_lz_hist(e, e->hn >= dist && e->hn - dist < e->hcap ? e->hist[e->hn - dist] : 0);
}

/* A new match: length 2..273 and a distance 1..2^32 (dist - 1 == 0xFFFFFFFF is the end marker). */
static inline void hv_lz_match_raw(struct hv_lz *e, unsigned len, uint32_t dist0)
{
	unsigned ps = hv_lz_posstate(e), slot, ls;

	hv_lz_bit(e, &e->is_match[e->state][ps], 1);
	hv_lz_bit(e, &e->is_rep[e->state], 0);
	hv_lz_len(e, 0, len, ps);
	ls = len - 2u > 3u ? 3u : len - 2u;
	if (dist0 < 4) {
		slot = dist0;
	} else {
		unsigned nb = 31;

		while (!((dist0 >> nb) & 1u))
			nb--;
		slot = 2u * nb + ((dist0 >> (nb - 1u)) & 1u);
	}
	hv_lz_tree(e, e->pos_slot[ls], 6, slot);
	if (slot >= 4) {
		unsigned foot = (slot >> 1) - 1u;
		uint32_t base = (2u | (slot & 1u)) << foot, red = dist0 - base;

		if (slot < 14) {
			hv_lz_tree_rev(e, e->spec_pos + (base - slot), foot, red);   /* index base-slot+m: the decoder's, shifted by one */
		} else {
			hv_lz_direct(e, red >> 4, foot - 4u);
			hv_lz_tree_rev(e, e->align, 4, red & 15u);
		}
	}
	e->state = e->state < 7 ? 7 : 10;
	e->rep[3] = e->rep[2];
	e->rep[2] = e->rep[1];
	e->rep[1] = e->rep[0];
	e->rep[0] = dist0 + 1u;
}

static inline void hv_lz_match(struct hv_lz *e, unsigned len, uint32_t dist)
{
	hv_lz_match_raw(e, len, dist - 1u);
	hv_lz_copy_hist(e, dist, len);
}

/* The end marker: a match of length 2 with distance 0xFFFFFFFF. */
static inline void hv_lz_end_marker(struct hv_lz *e)
{
	hv_lz_match_raw(e, 2, 0xFFFFFFFFu);
}

/* A rep match: idx selects which of the last four distances, len >= 2. */
static inline void hv_lz_rep(struct hv_lz *e, unsigned idx, unsigned len)
{
	unsigned ps = hv_lz_posstate(e);
	uint32_t d = e->rep[idx];

	hv_lz_bit(e, &e->is_match[e->state][ps], 1);
	hv_lz_bit(e, &e->is_rep[e->state], 1);
	if (idx == 0) {
		hv_lz_bit(e, &e->is_rep_g0[e->state], 0);
		hv_lz_bit(e, &e->is_rep0_long[e->state][ps], 1);
	} else {
		hv_lz_bit(e, &e->is_rep_g0[e->state], 1);
		if (idx == 1) {
			hv_lz_bit(e, &e->is_rep_g1[e->state], 0);
		} else {
			hv_lz_bit(e, &e->is_rep_g1[e->state], 1);
			hv_lz_bit(e, &e->is_rep_g2[e->state], idx - 2u);
		}
		for (; idx > 0; idx--)
			e->rep[idx] = e->rep[idx - 1u];
		e->rep[0] = d;
	}
	hv_lz_len(e, 1, len, ps);
	e->state = e->state < 7 ? 8 : 11;
	hv_lz_copy_hist(e, d, len);
}

/* A one byte copy from the last distance. */
static inline void hv_lz_short(struct hv_lz *e)
{
	unsigned ps = hv_lz_posstate(e);

	hv_lz_bit(e, &e->is_match[e->state][ps], 1);
	hv_lz_bit(e, &e->is_rep[e->state], 1);
	hv_lz_bit(e, &e->is_rep_g0[e->state], 0);
	hv_lz_bit(e, &e->is_rep0_long[e->state][ps], 0);
	e->state = e->state < 7 ? 9 : 11;
	hv_lz_copy_hist(e, e->rep[0], 1);
}

/* ---- LZMA2 chunk framing (the container's own bytes) ------------------------------- */

/* An LZMA chunk header: reset 0 none, 1 state, 2 state + new props, 3 + dictionary. */
static inline size_t hv_lz2_head(uint8_t *o, size_t ulen, size_t clen, unsigned reset, unsigned props)
{
	size_t n = 0;

	o[n++] = (uint8_t)(0x80u | (reset << 5) | (((ulen - 1u) >> 16) & 0x1fu));
	o[n++] = (uint8_t)((ulen - 1u) >> 8);
	o[n++] = (uint8_t)(ulen - 1u);
	o[n++] = (uint8_t)((clen - 1u) >> 8);
	o[n++] = (uint8_t)(clen - 1u);
	if (reset >= 2)
		o[n++] = (uint8_t)props;
	return n;
}

/* An uncompressed chunk (control 1 resets the dictionary, 2 does not). */
static inline size_t hv_lz2_raw(uint8_t *o, const uint8_t *d, size_t n, int dict_reset)
{
	o[0] = dict_reset ? 1 : 2;
	o[1] = (uint8_t)((n - 1u) >> 8);
	o[2] = (uint8_t)(n - 1u);
	memcpy(o + 3, d, n);
	return n + 3u;
}

#endif /* HOSTILE_LZENC_H */
