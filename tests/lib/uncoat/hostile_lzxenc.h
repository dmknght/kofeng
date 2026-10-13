/*
 * hostile_lzxenc.h - an LZX encoder with fixed, complete Huffman trees, for the tests of
 * lzx.h.
 *
 * It writes the operations it is given. The trees never change: the main tree gives 128
 * literals (the byte values 0..127) and 128 match symbols (position slots 0..15, all
 * eight length headers) eight bits each, which is complete; the length tree gives its
 * first 128 symbols seven bits; the aligned-offset tree gives all eight symbols three
 * bits. That is enough for literals, matches at every slot below 16, repeated offsets,
 * the length tree, aligned and verbatim blocks, uncompressed blocks, several blocks
 * with their delta-coded trees, the E8 header and the 32 KB frame alignment.
 *
 * The bit order is the format's: bits MSB first inside 16-bit words, the words
 * little-endian.
 */

#ifndef HOSTILE_LZXENC_H
#define HOSTILE_LZXENC_H

#include <stdint.h>
#include <string.h>

struct hv_lx {
	uint8_t  *out;
	size_t    cap, n;
	uint32_t  acc;              /* bits waiting, MSB first */
	unsigned  nb;               /* how many (< 16) */
	uint8_t  *hist;
	size_t    hn, hcap;
	uint32_t  r[3];
	unsigned  window_bits;
	/* the lengths the decoder holds after the previous block (for the deltas) */
	uint8_t   main_prev[656], len_prev[249];
	unsigned  slots;
	int       over;
	uint32_t  base[51];
	uint8_t   extra[51];
	/* the block under construction */
	size_t    block_at;         /* history index where the block began */
};

static inline void hv_lx_word(struct hv_lx *e, uint16_t w)
{
	if (e->n + 1 < e->cap) {
		e->out[e->n] = (uint8_t)w;
		e->out[e->n + 1] = (uint8_t)(w >> 8);
	} else {
		e->over = 1;
	}
	e->n += 2;
}

/* `n` low bits of v, most significant first. */
static inline void hv_lx_bits(struct hv_lx *e, uint32_t v, unsigned n)
{
	while (n--) {
		e->acc = (e->acc << 1) | ((v >> n) & 1u);
		if (++e->nb == 16) {
			hv_lx_word(e, (uint16_t)e->acc);
			e->acc = 0;
			e->nb = 0;
		}
	}
}

static inline void hv_lx_align16(struct hv_lx *e)
{
	if (e->nb)
		hv_lx_bits(e, 0, 16u - e->nb);
}

static inline unsigned hv_lx_slots_for(unsigned bits)
{
	static const unsigned s[7] = { 30, 32, 34, 36, 38, 42, 50 };

	return s[bits - 15u];
}

static inline void hv_lx_init(struct hv_lx *e, uint8_t *out, size_t cap, uint8_t *hist, size_t hcap,
			      unsigned window_bits, uint32_t e8_size)
{
	unsigned i, j = 0;
	uint32_t at = 0;

	memset(e, 0, sizeof *e);
	e->out = out;
	e->cap = cap;
	e->hist = hist;
	e->hcap = hcap;
	e->window_bits = window_bits;
	e->slots = hv_lx_slots_for(window_bits);
	e->r[0] = e->r[1] = e->r[2] = 1;
	for (i = 0; i < 51; i += 2) {
		e->extra[i] = (uint8_t)j;
		if (i + 1 < 51)
			e->extra[i + 1] = (uint8_t)j;
		if (i != 0 && j < 17)
			j++;
	}
	for (i = 0; i < 51; i++) {
		e->base[i] = at;
		at += 1u << e->extra[i];
	}
	if (e8_size) {
		hv_lx_bits(e, 1, 1);
		hv_lx_bits(e, e8_size >> 16, 16);
		hv_lx_bits(e, e8_size & 0xffffu, 16);
	} else {
		hv_lx_bits(e, 0, 1);
	}
}

static inline void hv_lx_hist(struct hv_lx *e, uint8_t b)
{
	if (e->hn < e->hcap)
		e->hist[e->hn] = b;
	e->hn++;
}

/*
 * The pretree: five symbols, complete (3 x 1/4 + 2 x 1/8). 0 (keep), 9 (0 -> 8), 18 (a long
 * run of zeros) take two bits; 10 (0 -> 7) and 17 (a short run of zeros) three. Canonical
 * order: 0 = 00, 9 = 01, 18 = 10, 10 = 110, 17 = 111.
 */
static inline void hv_lx_pretree_head(struct hv_lx *e)
{
	unsigned i;

	for (i = 0; i < 20; i++)
		hv_lx_bits(e, (i == 0 || i == 9 || i == 18) ? 2u : (i == 10 || i == 17) ? 3u : 0u, 4);
}

static inline void hv_lx_pre_sym(struct hv_lx *e, unsigned sym)
{
	switch (sym) {
	case 0:  hv_lx_bits(e, 0, 2); break;
	case 9:  hv_lx_bits(e, 1, 2); break;
	case 18: hv_lx_bits(e, 2, 2); break;
	case 10: hv_lx_bits(e, 6, 3); break;
	default: hv_lx_bits(e, 7, 3); break;            /* 17 */
	}
}

/* Write the lengths first..last-1 as deltas against prev[]; target[] holds the new ones. */
static inline void hv_lx_lengths(struct hv_lx *e, uint8_t *prev, const uint8_t *target, unsigned first,
				 unsigned last)
{
	unsigned i = first;

	hv_lx_pretree_head(e);
	while (i < last) {
		unsigned run = 1, d;

		while (i + run < last && target[i + run] == 0 && prev[i + run] == 0)
			run++;
		d = (unsigned)(((int)prev[i] - (int)target[i] + 17) % 17);
		if (target[i] == 0 && prev[i] == 0 && run >= 20) {
			run = run > 51 ? 51 : run;
			hv_lx_pre_sym(e, 18);
			hv_lx_bits(e, run - 20u, 5);
		} else if (target[i] == 0 && prev[i] == 0 && run >= 4) {
			run = run > 19 ? 19 : run;
			hv_lx_pre_sym(e, 17);
			hv_lx_bits(e, run - 4u, 4);
		} else {
			hv_lx_pre_sym(e, d == 9 || d == 10 ? d : 0u);   /* the only deltas these trees need */
			run = 1;
		}
		for (; run; run--, i++)
			prev[i] = target[i];
	}
}

/* The tree lengths this encoder uses. */
static inline void hv_lx_trees(struct hv_lx *e, uint8_t *mainl, uint8_t *lenl)
{
	unsigned i;

	memset(mainl, 0, 656);
	memset(lenl, 0, 249);
	for (i = 0; i < 128; i++)
		mainl[i] = 8;                                   /* literals 0..127 */
	for (i = 0; i < 128; i++)
		mainl[256 + i] = 8;                             /* slots 0..15 */
	for (i = 0; i < 128; i++)
		lenl[i] = 7;
	(void)e;
}

/* An uncompressed block: type 3, a 24 bit size, align, R0..R2, the bytes, word padding. */
static inline void hv_lx_uncompressed(struct hv_lx *e, const uint8_t *d, size_t n, const uint32_t r[3])
{
	size_t i;

	hv_lx_bits(e, 3, 3);
	hv_lx_bits(e, (uint32_t)(n >> 8), 16);
	hv_lx_bits(e, (uint32_t)(n & 0xffu), 8);
	hv_lx_align16(e);
	for (i = 0; i < 3; i++) {
		hv_lx_word(e, (uint16_t)(r[i] & 0xffffu));
		hv_lx_word(e, (uint16_t)(r[i] >> 16));
	}
	for (i = 0; i < n; i++) {
		if (e->n < e->cap)
			e->out[e->n] = d[i];
		else
			e->over = 1;
		e->n++;
		hv_lx_hist(e, d[i]);
	}
	if (n & 1u) {
		if (e->n < e->cap)
			e->out[e->n] = 0;
		e->n++;
	}
	e->r[0] = r[0]; e->r[1] = r[1]; e->r[2] = r[2];
}

/* After a symbol: if it passed a multiple of 32768 the decoder aligned to a word there. */
static inline void hv_lx_frame(struct hv_lx *e, size_t before)
{
	if (e->hn / 32768u != before / 32768u)
		hv_lx_align16(e);
}

/*
 * One block, begun: type 1 verbatim or 2 aligned, the size, the trees. The caller then
 * writes symbols and the size must match what they total.
 */
static inline void hv_lx_block_begin(struct hv_lx *e, unsigned type, uint32_t size)
{
	uint8_t mainl[656], lenl[249];
	unsigned i;

	hv_lx_bits(e, type, 3);
	hv_lx_bits(e, size >> 8, 16);
	hv_lx_bits(e, size & 0xffu, 8);
	if (type == 2)
		for (i = 0; i < 8; i++)
			hv_lx_bits(e, 3, 3);
	hv_lx_trees(e, mainl, lenl);
	hv_lx_lengths(e, e->main_prev, mainl, 0, 256);
	hv_lx_lengths(e, e->main_prev, mainl, 256, 256u + e->slots * 8u);
	hv_lx_lengths(e, e->len_prev, lenl, 0, 249);
}

static inline void hv_lx_main(struct hv_lx *e, unsigned sym)
{
	/* literals 0..127 are ranks 0..127, match symbols 256..383 are ranks 128..255 */
	hv_lx_bits(e, sym < 128 ? sym : 128u + (sym - 256u), 8);
}

static inline void hv_lx_lit(struct hv_lx *e, uint8_t b)
{
	size_t before = e->hn;

	hv_lx_main(e, b & 0x7fu);
	hv_lx_hist(e, (uint8_t)(b & 0x7fu));
	hv_lx_frame(e, before);
}

/* A match: slot 0..15 and its extra bits written for `off`; the repeated-offset slots 0..2. */
static inline int hv_lx_match(struct hv_lx *e, unsigned aligned, uint32_t off, unsigned len)
{
	unsigned slot, hdr = len - 2u > 7u ? 7u : len - 2u, k, ex;
	size_t before = e->hn;
	uint32_t v;

	if (off == e->r[0]) {
		slot = 0;
	} else if (off == e->r[1]) {
		slot = 1;
	} else if (off == e->r[2]) {
		slot = 2;
	} else {
		for (slot = 3; slot < 16; slot++)
			if (off + 2u >= e->base[slot] && off + 2u < e->base[slot] + (1u << e->extra[slot]))
				break;
		if (slot == 16)
			return 0;
	}
	hv_lx_main(e, 256u + (slot << 3 | hdr));
	if (hdr == 7)
		hv_lx_bits(e, len - 9u, 7);                     /* the first 128 length symbols, 7 bits */
	if (slot == 0) {
		/* R0 stays */
	} else if (slot == 1) {
		e->r[1] = e->r[0]; e->r[0] = off;
	} else if (slot == 2) {
		e->r[2] = e->r[0]; e->r[0] = off;
	} else {
		ex = e->extra[slot];
		v = off + 2u - e->base[slot];
		if (slot != 3) {
			if (aligned && ex >= 3) {
				hv_lx_bits(e, v >> 3, ex - 3u);
				hv_lx_bits(e, v & 7u, 3);       /* the aligned tree: 3 bits for each of 8 */
			} else if (ex) {
				hv_lx_bits(e, v, ex);
			}
		}
		e->r[2] = e->r[1]; e->r[1] = e->r[0]; e->r[0] = off;
	}
	for (k = 0; k < len; k++)
		hv_lx_hist(e, e->hn >= off && e->hn - off < e->hcap ? e->hist[e->hn - off] : 0);
	hv_lx_frame(e, before);
	return 1;
}

static inline size_t hv_lx_finish(struct hv_lx *e)
{
	hv_lx_align16(e);
	return e->n;
}

#endif /* HOSTILE_LZXENC_H */
