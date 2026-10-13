/*
 * hostile_lzhenc.h - an encoder for the LHA / ARJ block-Huffman coding (lzhuf.h), for the
 * tests of kuncoat_lzhuf_decode.
 *
 * A block is a 16 bit code count, a PRETREE (nineteen lengths), the literal/length tree
 * written through the pretree, and the position tree. This encoder takes the symbol set
 * and the shape of the code from the caller: lengths come from hv_lh_lengths (a
 * "caterpillar" tree, depth 1, 2, ... then a balanced remainder, which is complete and
 * reaches deep codes) so a stream can use short codes, codes longer than the 8 and 12 bit
 * lookup tables, and every escape the length coding has. Bits are MSB first.
 */

#ifndef HOSTILE_LZHENC_H
#define HOSTILE_LZHENC_H

#include <stdint.h>
#include <string.h>

/* Complete lengths for `n` symbols: the first `d` get 1..d, the rest share a balanced
 * subtree below depth d. n >= d + 1. */
static inline void hv_lh_lengths(uint8_t *len, unsigned n, unsigned d)
{
	unsigned i, m = n - d, D = 0, shallow, deep;

	for (i = 0; i < d; i++)
		len[i] = (uint8_t)(i + 1u);
	while ((1u << D) < m)
		D++;
	shallow = (1u << D) - m;                    /* leaves one level up */
	deep = m - shallow;
	(void)deep;
	if (m == 1) {
		len[d] = (uint8_t)d;                /* the last leaf takes the slot at depth d */
		return;
	}
	for (i = 0; i < m; i++)
		len[d + i] = (uint8_t)(d + (i < shallow ? D - 1u : D));
}

/* A pretree length: 0..6 in three bits, longer as 111 and a unary tail. */
static inline void hv_lh_ptlen(struct hv_bw *w, unsigned l)
{
	if (l < 7) {
		hv_bw_msb(w, l, 3);
	} else {
		hv_bw_msb(w, 7, 3);
		while (l-- > 7)
			hv_bw_msb(w, 1, 1);
		hv_bw_msb(w, 0, 1);
	}
}

struct hv_lh {
	uint8_t  *out;
	size_t    cap;
	struct hv_bw w;
	uint8_t  *hist;
	size_t    hn, hcap;
	/* the code in use */
	uint8_t   cl[510];
	uint16_t  cc[510];
	uint8_t   pl[32];
	uint16_t  pc[32];
	unsigned  np, pbit;
	uint8_t   tl[19];
	uint16_t  tc[19];
	unsigned  nc;                /* entries of cl in use */
};

/* Write one block header for the code in `e` (cl[], pl[] filled by the caller) and size. */
static inline void hv_lh_block(struct hv_lh *e, uint32_t ncodes)
{
	unsigned i, last = 0, ntl = 0;
	struct hv_bw *w = &e->w;
	uint8_t seq[1100];
	unsigned seqn = 0, ex[1100], exb[1100];

	hv_bw_msb(w, ncodes, 16);
	/* the c_len entries as pretree symbols, zeros run-length coded */
	for (i = 0; i < 510; i++)
		if (e->cl[i])
			last = i + 1;
	e->nc = last;
	for (i = 0; i < last;) {
		if (!e->cl[i]) {
			unsigned r = 1;

			while (i + r < last && !e->cl[i + r])
				r++;
			if (r >= 20) {
				r = r > 531 ? 531 : r;
				seq[seqn] = 2; ex[seqn] = r - 20u; exb[seqn++] = 9;
			} else if (r >= 3) {
				r = r > 18 ? 18 : r;
				seq[seqn] = 1; ex[seqn] = r - 3u; exb[seqn++] = 4;
			} else {
				r = 1;
				seq[seqn] = 0; ex[seqn] = 0; exb[seqn++] = 0;
			}
			i += r;
		} else {
			seq[seqn] = (uint8_t)(e->cl[i] + 2u); ex[seqn] = 0; exb[seqn++] = 0;
			i++;
		}
	}
	/* the pretree: caterpillar over the symbols the sequence uses plus 0, 1, 2 */
	{
		uint8_t used[19];
		unsigned u = 0, d;

		memset(used, 0, sizeof used);
		used[0] = used[1] = used[2] = 1;
		for (i = 0; i < seqn; i++)
			used[seq[i]] = 1;
		for (i = 0; i < 19; i++)
			u += used[i];
		memset(e->tl, 0, sizeof e->tl);
		{
			uint8_t lens[19];

			d = u > 6 ? 4u : u - 1u;
			hv_lh_lengths(lens, u, d);
			for (i = 0, ntl = 0; i < 19; i++)
				if (used[i])
					e->tl[i] = lens[ntl++];
		}
	}
	hv_canon(e->tl, 19, e->tc);
	/* pretree lengths: n entries up to the last used one; after entry 2 a 2 bit skip count */
	{
		unsigned n = 19;

		while (n > 3 && !e->tl[n - 1])
			n--;
		hv_bw_msb(w, n, 5);
		for (i = 0; i < n;) {
			hv_lh_ptlen(w, e->tl[i]);
			i++;
			if (i == 3) {
				unsigned z = 0;

				while (z < 3 && i + z < n && !e->tl[i + z])
					z++;
				hv_bw_msb(w, z, 2);
				i += z;
			}
		}
	}
	hv_bw_msb(w, last, 9);
	for (i = 0; i < seqn; i++) {
		hv_bw_msb(w, e->tc[seq[i]], e->tl[seq[i]]);
		if (exb[i])
			hv_bw_msb(w, ex[i], exb[i]);
	}
	/* the position tree */
	{
		unsigned n = e->np;

		while (n > 1 && !e->pl[n - 1])
			n--;
		hv_bw_msb(w, n, e->pbit);
		for (i = 0; i < n; i++)
			hv_lh_ptlen(w, e->pl[i]);
	}
	hv_canon(e->cl, 510, e->cc);
	hv_canon(e->pl, e->np, e->pc);
}

static inline void hv_lh_hist(struct hv_lh *e, uint8_t b)
{
	if (e->hn < e->hcap)
		e->hist[e->hn] = b;
	e->hn++;
}

static inline void hv_lh_lit(struct hv_lh *e, uint8_t b)
{
	hv_bw_msb(&e->w, e->cc[b], e->cl[b]);
	hv_lh_hist(e, b);
}

/* A match of `len` (3..256) at `dist` (1..). */
static inline void hv_lh_match(struct hv_lh *e, unsigned len, uint32_t dist)
{
	unsigned c = 253u + len, sym, nb = 0, k;
	uint32_t d1 = dist - 1u;

	hv_bw_msb(&e->w, e->cc[c], e->cl[c]);
	if (d1 == 0) {
		sym = 0;
	} else {
		while ((d1 >> (nb + 1u)) != 0)
			nb++;
		sym = nb + 1u;
	}
	hv_bw_msb(&e->w, e->pc[sym], e->pl[sym]);
	if (d1)
		hv_bw_msb(&e->w, d1 - (1u << nb), nb);
	for (k = 0; k < len; k++)
		hv_lh_hist(e, e->hn >= dist && e->hn - dist < e->hcap ? e->hist[e->hn - dist] : 0);
}

static inline size_t hv_lh_finish(struct hv_lh *e)
{
	hv_bw_align_msb(&e->w);
	return e->w.n;
}

static inline void hv_lh_init(struct hv_lh *e, uint8_t *out, size_t cap, uint8_t *hist, size_t hcap, unsigned np,
			      unsigned pbit)
{
	memset(e, 0, sizeof *e);
	e->out = out;
	e->cap = cap;
	hv_bw_init(&e->w, out, cap);
	e->hist = hist;
	e->hcap = hcap;
	e->np = np;
	e->pbit = pbit;
}

/*
 * The table-coding both RAR formats share: twenty "length of a length" entries of four bits,
 * then the lengths of the real tables as symbols of that small code: 0..15 a length (RAR3:
 * a delta against the previous block's, so a first block's deltas ARE the lengths), 16 and
 * 17 repeat the previous 3..10 / 11..138 times, 18 and 19 write 3..10 / 11..138 zeros.
 * The small code is the caterpillar over the symbols the table uses plus 16..19.
 */
static inline void hv_rar_tables(struct hv_bw *w, const uint8_t *table, unsigned n)
{
	uint8_t seq[1200], used[20], bl[20], lens[20];
	unsigned ex[1200], exb[1200], seqn = 0, i, u = 0, k;
	uint16_t bc[20];

	for (i = 0; i < n;) {
		unsigned r = 1;

		while (i + r < n && table[i + r] == table[i])
			r++;
		if (table[i] == 0 && r >= 11) {
			r = r > 138 ? 138 : r;
			seq[seqn] = 19; ex[seqn] = r - 11u; exb[seqn++] = 7;
		} else if (table[i] == 0 && r >= 3) {
			r = r > 10 ? 10 : r;
			seq[seqn] = 18; ex[seqn] = r - 3u; exb[seqn++] = 3;
		} else if (i > 0 && table[i] == table[i - 1] && r >= 11) {
			r = r > 138 ? 138 : r;
			seq[seqn] = 17; ex[seqn] = r - 11u; exb[seqn++] = 7;
		} else if (i > 0 && table[i] == table[i - 1] && r >= 3) {
			r = r > 10 ? 10 : r;
			seq[seqn] = 16; ex[seqn] = r - 3u; exb[seqn++] = 3;
		} else {
			r = 1;
			seq[seqn] = table[i]; ex[seqn] = 0; exb[seqn++] = 0;
		}
		i += r;
	}
	memset(used, 0, sizeof used);
	for (i = 0; i < seqn; i++)
		used[seq[i]] = 1;
	used[16] = used[17] = used[18] = used[19] = 1;
	for (i = 0; i < 20; i++)
		u += used[i];
	hv_lh_lengths(lens, u, u > 6 ? 5u : u - 1u);
	memset(bl, 0, sizeof bl);
	for (i = 0, k = 0; i < 20; i++)
		if (used[i])
			bl[i] = lens[k++];
	hv_canon(bl, 20, bc);
	for (i = 0; i < 20; i++)
		hv_bw_msb(w, bl[i], 4);
	for (i = 0; i < seqn; i++) {
		hv_bw_msb(w, bc[seq[i]], bl[seq[i]]);
		if (exb[i])
			hv_bw_msb(w, ex[i], exb[i]);
	}
}

#endif /* HOSTILE_LZHENC_H */
