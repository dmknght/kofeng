/*
 * hostile_rarenc.h - encoders for the LZ halves of RAR 3 and RAR 5, for the tests of rar3.h
 * and rar5.h (the PPMd half of RAR 3 has no encoder here: its model is Shkarin's and a
 * range coder over it is not something a test can state in a few lines).
 *
 * Both encoders use fixed, complete codes - one uniform code per table - and write the
 * tables through hv_rar_tables (hostile_lzhenc.h). They track the decoder's repeated
 * distances and last length, so a script of (literal | match | repeat | filter | ...) has an
 * exact expected output.
 */

#ifndef HOSTILE_RARENC_H
#define HOSTILE_RARENC_H

#include <stdint.h>
#include <string.h>

/* The literal alphabet of both encoders: 32..127, and 0xE8, 0xE9, 0, 1 (so a filter has something to find). */
static inline int hv_rar_is_lit(unsigned b)
{
	return (b >= 32 && b < 128) || b == 0xE8 || b == 0xE9 || b == 0 || b == 1;
}

/* The k-th literal of that alphabet (k < 100). */
static inline uint8_t hv_rar_lit(unsigned k)
{
	return k < 96 ? (uint8_t)(32 + k) : k == 96 ? 0xE8 : k == 97 ? 0xE9 : k == 98 ? 0 : 1;
}

/* ---- RAR 3 ------------------------------------------------------------------------------------ */

static const uint32_t HV_R3_LDEC[28] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96,
					 112, 128, 160, 192, 224 };
static const uint8_t HV_R3_LBITS[28] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5 };
static const uint32_t HV_R3_DDEC[16] = { 0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192 };
static const uint8_t HV_R3_DBITS[16] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6 };
static const uint32_t HV_R3_SDDEC[8] = { 0, 4, 8, 16, 32, 64, 128, 192 };
static const uint8_t HV_R3_SDBITS[8] = { 2, 2, 3, 4, 5, 6, 6, 6 };

struct hv_r3 {
	struct hv_bw w;
	uint8_t     *hist;
	size_t       hn, hcap;
	uint32_t     old[4];
	uint32_t     last_len, last_dist;
	uint8_t      lc[299], dc[60], lowc[17], rc[28];
	uint16_t     lcode[299], dcode[60], lowcode[17], rcode[28];
};

/* LD: 128 symbols of 7 bits: the 100 literals, 256, 258..262, 263..270, 271..284 (= 100 + 1 + 27).
 * DD: slots 0..15, 4 bits. LDD: 0..15, 4 bits. RD: 0..7, 3 bits. */
static inline void hv_r3_codes(struct hv_r3 *e)
{
	unsigned i;

	memset(e->lc, 0, sizeof e->lc); memset(e->dc, 0, sizeof e->dc);
	memset(e->lowc, 0, sizeof e->lowc); memset(e->rc, 0, sizeof e->rc);
	for (i = 0; i < 256; i++)
		if (hv_rar_is_lit(i))
			e->lc[i] = 7;
	e->lc[256] = 7;
	for (i = 258; i <= 284; i++)
		e->lc[i] = 7;
	for (i = 0; i < 16; i++)
		e->dc[i] = 4, e->lowc[i] = 4;
	for (i = 0; i < 8; i++)
		e->rc[i] = 3;
	hv_canon(e->lc, 299, e->lcode); hv_canon(e->dc, 60, e->dcode);
	hv_canon(e->lowc, 17, e->lowcode); hv_canon(e->rc, 28, e->rcode);
}

static inline void hv_r3_hist(struct hv_r3 *e, uint8_t b)
{
	if (e->hn < e->hcap)
		e->hist[e->hn] = b;
	e->hn++;
}

static inline void hv_r3_init(struct hv_r3 *e, uint8_t *out, size_t cap, uint8_t *hist, size_t hcap)
{
	uint8_t table[404];

	memset(e, 0, sizeof *e);
	hv_bw_init(&e->w, out, cap);
	e->hist = hist;
	e->hcap = hcap;
	hv_r3_codes(e);
	/* an LZ block, tables not kept: two zero bits, then the tables */
	hv_bw_msb(&e->w, 0, 2);
	memcpy(table, e->lc, 299);
	memcpy(table + 299, e->dc, 60);
	memcpy(table + 299 + 60, e->lowc, 17);
	memcpy(table + 299 + 60 + 17, e->rc, 28);
	hv_rar_tables(&e->w, table, 404);
}

static inline void hv_r3_lsym(struct hv_r3 *e, unsigned s)
{
	hv_bw_msb(&e->w, e->lcode[s], e->lc[s]);
}

static inline void hv_r3_lit(struct hv_r3 *e, uint8_t b)
{
	hv_r3_lsym(e, b);
	hv_r3_hist(e, b);
}

static inline void hv_r3_copy(struct hv_r3 *e, uint32_t dist, unsigned len)
{
	unsigned k;

	for (k = 0; k < len; k++)
		hv_r3_hist(e, e->hn >= dist && e->hn - dist < e->hcap ? e->hist[e->hn - dist] : 0);
}

static inline void hv_r3_push(struct hv_r3 *e, uint32_t d)
{
	e->old[3] = e->old[2]; e->old[2] = e->old[1]; e->old[1] = e->old[0]; e->old[0] = d;
}

/* A length as its slot and extra bits, with the offset added (3 for a match, 2 for a repeat). */
static inline int hv_r3_lenslot(unsigned len, unsigned base, unsigned maxslot, unsigned *slot, unsigned *ex,
				unsigned *exb)
{
	unsigned s;

	for (s = 0; s < maxslot; s++)
		if (len >= HV_R3_LDEC[s] + base && len < HV_R3_LDEC[s] + base + (1u << HV_R3_LBITS[s])) {
			*slot = s;
			*ex = len - HV_R3_LDEC[s] - base;
			*exb = HV_R3_LBITS[s];
			return 1;
		}
	return 0;
}

/* A new match: length 3..26, distance 1..256. */
static inline int hv_r3_match(struct hv_r3 *e, unsigned len, uint32_t dist)
{
	unsigned slot, ex, exb, dn;
	uint32_t d1 = dist - 1u;

	if (!hv_r3_lenslot(len, 3, 14, &slot, &ex, &exb))
		return 0;
	for (dn = 0; dn < 16; dn++)
		if (d1 >= HV_R3_DDEC[dn] && d1 < HV_R3_DDEC[dn] + (1u << HV_R3_DBITS[dn]))
			break;
	if (dn == 16)
		return 0;
	hv_r3_lsym(e, 271u + slot);
	hv_bw_msb(&e->w, ex, exb);
	hv_bw_msb(&e->w, e->dcode[dn], e->dc[dn]);
	{
		unsigned bits = HV_R3_DBITS[dn];
		uint32_t extra = d1 - HV_R3_DDEC[dn];

		if (bits) {
			if (dn > 9) {
				if (bits > 4)
					hv_bw_msb(&e->w, extra >> 4, bits - 4u);
				hv_bw_msb(&e->w, e->lowcode[extra & 15u], e->lowc[extra & 15u]);
			} else {
				hv_bw_msb(&e->w, extra, bits);
			}
		}
	}
	hv_r3_push(e, dist);
	e->last_len = len;
	e->last_dist = dist;
	hv_r3_copy(e, dist, len);
	return 1;
}

/* Repeat distance k (0..3), length 2..: through the repeat-length table. */
static inline int hv_r3_rep(struct hv_r3 *e, unsigned k, unsigned len)
{
	unsigned slot, ex, exb, j;
	uint32_t dist = e->old[k];

	if (!hv_r3_lenslot(len, 2, 8, &slot, &ex, &exb))
		return 0;
	hv_r3_lsym(e, 259u + k);
	for (j = k; j > 0; j--)
		e->old[j] = e->old[j - 1u];
	e->old[0] = dist;
	hv_bw_msb(&e->w, e->rcode[slot], e->rc[slot]);
	hv_bw_msb(&e->w, ex, exb);
	e->last_len = len;
	e->last_dist = dist;
	hv_r3_copy(e, dist, len);
	return 1;
}

static inline void hv_r3_repeat_last(struct hv_r3 *e)
{
	hv_r3_lsym(e, 258);
	if (e->last_len)
		hv_r3_copy(e, e->last_dist, e->last_len);
}

/* A two byte match at a short distance: 1..256. */
static inline int hv_r3_short(struct hv_r3 *e, uint32_t dist)
{
	unsigned k;
	uint32_t d1 = dist - 1u;

	for (k = 0; k < 8; k++)
		if (d1 >= HV_R3_SDDEC[k] && d1 < HV_R3_SDDEC[k] + (1u << HV_R3_SDBITS[k]))
			break;
	if (k == 8)
		return 0;
	hv_r3_lsym(e, 263u + k);
	hv_bw_msb(&e->w, d1 - HV_R3_SDDEC[k], HV_R3_SDBITS[k]);
	hv_r3_push(e, dist);
	e->last_len = 2;
	e->last_dist = dist;
	hv_r3_copy(e, dist, 2);
	return 1;
}

/* The end of the stream: symbol 256 and the two bits that say "no more tables". */
static inline size_t hv_r3_finish(struct hv_r3 *e)
{
	hv_r3_lsym(e, 256);
	hv_bw_msb(&e->w, 0, 2);
	hv_bw_align_msb(&e->w);
	return e->w.n;
}

/* ---- RAR 5 ------------------------------------------------------------------------------------ */

struct hv_r5 {
	struct hv_bw w;
	uint8_t     *hist;
	size_t       hn, hcap;
	uint32_t     old[4];
	uint32_t     last_len;
	uint8_t      lc[306], dc[64], lowc[16], rc[44];
	uint16_t     lcode[306], dcode[64], lowcode[16], rcode[44];
	/* the block under construction: its payload bits are collected first (the header holds their count) */
	uint8_t     *out;
	size_t       cap;
	uint8_t     *pay;
	size_t       pay_cap;
	struct hv_bw pw;
	int          started;
};

/* LD: 128 symbols of 7 bits: the 100 literals, 256, 257, 258..261, 262..283 (length slots 0..21).
 * DD: slots 0..31, 5 bits. LDD: 16 of 4 bits. RD: 0..7, 3 bits. */
static inline void hv_r5_codes(struct hv_r5 *e)
{
	unsigned i;

	memset(e->lc, 0, sizeof e->lc); memset(e->dc, 0, sizeof e->dc);
	memset(e->lowc, 0, sizeof e->lowc); memset(e->rc, 0, sizeof e->rc);
	for (i = 0; i < 256; i++)
		if (hv_rar_is_lit(i))
			e->lc[i] = 7;
	for (i = 256; i <= 283; i++)
		e->lc[i] = 7;                               /* 100 + 28 = 128 */
	for (i = 0; i < 32; i++)
		e->dc[i] = 5;
	for (i = 0; i < 16; i++)
		e->lowc[i] = 4;
	for (i = 0; i < 8; i++)
		e->rc[i] = 3;
	hv_canon(e->lc, 306, e->lcode); hv_canon(e->dc, 64, e->dcode);
	hv_canon(e->lowc, 16, e->lowcode); hv_canon(e->rc, 44, e->rcode);
}

static inline void hv_r5_hist(struct hv_r5 *e, uint8_t b)
{
	if (e->hn < e->hcap)
		e->hist[e->hn] = b;
	e->hn++;
}

/* Begin a block: the payload goes into `pay` until hv_r5_end_block writes header and payload. */
static inline void hv_r5_begin(struct hv_r5 *e, uint8_t *out, size_t cap, uint8_t *pay, size_t pay_cap,
			       uint8_t *hist, size_t hcap, int with_tables)
{
	uint8_t table[430];

	e->out = out;
	e->cap = cap;
	e->pay = pay;
	e->pay_cap = pay_cap;
	e->hist = hist;
	e->hcap = hcap;
	if (!e->started) {
		hv_bw_init(&e->w, out, cap);
		e->started = 1;
	}
	hv_bw_init(&e->pw, pay, pay_cap);
	hv_r5_codes(e);
	if (with_tables) {
		memcpy(table, e->lc, 306);
		memcpy(table + 306, e->dc, 64);
		memcpy(table + 306 + 64, e->lowc, 16);
		memcpy(table + 306 + 64 + 16, e->rc, 44);
		hv_rar_tables(&e->pw, table, 430);
	}
}

static inline void hv_r5_lsym(struct hv_r5 *e, unsigned s)
{
	hv_bw_msb(&e->pw, e->lcode[s], e->lc[s]);
}

static inline void hv_r5_lit(struct hv_r5 *e, uint8_t b)
{
	hv_r5_lsym(e, b);
	hv_r5_hist(e, b);
}

static inline void hv_r5_copy(struct hv_r5 *e, uint32_t dist, unsigned len)
{
	unsigned k;

	for (k = 0; k < len; k++)
		hv_r5_hist(e, e->hn >= dist && e->hn - dist < e->hcap ? e->hist[e->hn - dist] : 0);
}

/* A length (as the slot's base and extra bits, minus nothing: the caller has adjusted it). */
static inline int hv_r5_len(unsigned len, unsigned *slot, unsigned *ex, unsigned *exb)
{
	unsigned s;

	for (s = 0; s < 22; s++) {
		unsigned base, bits;

		if (s < 8) {
			base = 2u + s;
			bits = 0;
		} else {
			bits = s / 4u - 1u;
			base = 2u + ((4u | (s & 3u)) << bits);
		}
		if (len >= base && len < base + (1u << bits)) {
			*slot = s;
			*ex = len - base;
			*exb = bits;
			return 1;
		}
	}
	return 0;
}

/* A new match of `len` bytes at `dist`: the length coded is reduced by what the distance adds. */
static inline int hv_r5_match(struct hv_r5 *e, unsigned len, uint32_t dist)
{
	unsigned slot, ex, exb, dslot, nb, bits, coded = len, adj = 0;
	uint32_t d1 = dist - 1u, base, extra;

	if (dist > 0x100u) {
		adj++;
		if (dist > 0x2000u) {
			adj++;
			if (dist > 0x40000u)
				adj++;
		}
	}
	if (coded < adj + 2u)
		return 0;
	coded -= adj;
	if (!hv_r5_len(coded, &slot, &ex, &exb))
		return 0;
	if (d1 < 4) {
		dslot = d1;
		bits = 0;
		base = d1;
	} else {
		nb = 31;
		while (!((d1 >> nb) & 1u))
			nb--;
		dslot = 2u * nb + ((d1 >> (nb - 1u)) & 1u);
		bits = dslot / 2u - 1u;
		base = (2u | (dslot & 1u)) << bits;
	}
	if (dslot >= 32)
		return 0;
	extra = d1 - base;
	hv_r5_lsym(e, 262u + slot);
	hv_bw_msb(&e->pw, ex, exb);
	hv_bw_msb(&e->pw, e->dcode[dslot], e->dc[dslot]);
	if (bits) {
		if (bits >= 4) {
			if (bits > 4)
				hv_bw_msb(&e->pw, extra >> 4, bits - 4u);
			hv_bw_msb(&e->pw, e->lowcode[extra & 15u], e->lowc[extra & 15u]);
		} else {
			hv_bw_msb(&e->pw, extra, bits);
		}
	}
	e->old[3] = e->old[2]; e->old[2] = e->old[1]; e->old[1] = e->old[0]; e->old[0] = dist;
	e->last_len = coded + adj;                           /* the decoder stores the adjusted length */
	hv_r5_copy(e, dist, len);
	return 1;
}

/* Repeat distance k (0..3) with a length 2..9 through the repeat-length table. */
static inline int hv_r5_rep(struct hv_r5 *e, unsigned k, unsigned len)
{
	uint32_t dist = e->old[k];
	unsigned j;

	if (len < 2 || len > 9)
		return 0;
	hv_r5_lsym(e, 258u + k);
	for (j = k; j > 0; j--)
		e->old[j] = e->old[j - 1u];
	e->old[0] = dist;
	hv_bw_msb(&e->pw, e->rcode[len - 2u], e->rc[len - 2u]);
	e->last_len = len;
	hv_r5_copy(e, dist, len);
	return 1;
}

static inline void hv_r5_repeat_last(struct hv_r5 *e)
{
	hv_r5_lsym(e, 257);
	if (e->last_len)
		hv_r5_copy(e, e->old[0], e->last_len);
}

/* A filter: symbol 256, start and length as 1..4 byte fields, the type, delta's channel count. */
static inline void hv_r5_filter(struct hv_r5 *e, uint32_t start, uint32_t len, unsigned type, unsigned chan)
{
	unsigned i, nb;
	uint32_t v;

	hv_r5_lsym(e, 256);
	for (i = 0; i < 2; i++) {
		v = i ? len : start;
		nb = v < 256 ? 1u : v < 65536 ? 2u : v < (1u << 24) ? 3u : 4u;
		hv_bw_msb(&e->pw, nb - 1u, 2);
		while (nb--) {
			hv_bw_msb(&e->pw, v & 0xffu, 8);
			v >>= 8;
		}
	}
	hv_bw_msb(&e->pw, type, 3);
	if (type == 0)
		hv_bw_msb(&e->pw, chan - 1u, 5);
}

/* Close the block: header (flags, checksum, size) and the payload, byte aligned. */
static inline size_t hv_r5_end_block(struct hv_r5 *e, int with_tables, int last)
{
	size_t bits = e->pw.n * 8u + e->pw.nb, size, i;
	unsigned nbytes, flags, valid;
	uint32_t sz;

	hv_bw_align_msb(&e->pw);
	size = e->pw.n;
	valid = (unsigned)(bits - (size - 1u) * 8u);               /* bits used in the last byte, 1..8 */
	nbytes = size < 256 ? 1u : size < 65536 ? 2u : 3u;
	flags = (valid - 1u) | ((nbytes - 1u) << 3) | (last ? 0x40u : 0u) | (with_tables ? 0x80u : 0u);
	sz = (uint32_t)size;
	hv_bw_align_msb(&e->w);
	hv_bw_byte(&e->w, (uint8_t)flags);
	hv_bw_byte(&e->w, (uint8_t)(0x5au ^ flags ^ sz ^ (sz >> 8) ^ (sz >> 16)));
	for (i = 0; i < nbytes; i++)
		hv_bw_byte(&e->w, (uint8_t)(sz >> (8u * i)));
	for (i = 0; i < size; i++)
		hv_bw_byte(&e->w, e->pay[i]);
	hv_bw_init(&e->pw, e->pay, e->pay_cap);
	return e->w.n;
}

#endif /* HOSTILE_RARENC_H */
