/*
 * hostile_aspenc.h - an ENCODER for the ASPack 2.x block coding of libuncoat/decompressors/aspack.c, written from the decoder's
 * own control flow (aspack.c, aspack.h) so that a plain text goes in one side and must come out of the other. Before this the
 * decoder had never been driven past its header by a stream whose answer was known (asp_run was run by no test).
 *
 * What the stream is, as the decoder reads it (most significant bit first):
 *   block header   1 bit (1: keep the previous block's code lengths, 0: start from zeros),
 *                  19 x 4 bits   code lengths of the alphabet that codes the lengths (alphabet 3),
 *                  757 lengths (721 + 28 + 8) coded with it: a symbol below 16 is a DELTA from the same position of the
 *                  previous block, mod 16; 16 repeats the previous output length 3..6 times (2 bits); 17 is 3..10 zeros (3 bits);
 *                  18 is 11..138 zeros (7 bits). Every alphabet must be a COMPLETE code (the codes fill the space exactly) and
 *                  no length is above 15 in practice (a code longer than 15 never fills it).
 *   symbols        alphabet 0, a canonical code with the SHORTEST codes numerically lowest:
 *                    < 256     a literal
 *                    256..719  a match: (sym - 256) >> 3 is the offset class, the low three bits are the length - 2 (7 means "9 or
 *                              more": an escape symbol of alphabet 1 follows, then extra bits)
 *                    720       rebuild the alphabets (a new block header) and go on
 *                  then the offset: the class gives a base (the cumulative 1 << width of the classes before it) and a width; use =
 *                  base + extra. use 0..2 names one of the three most recent offsets (and moves it to the front), use >= 3 is a new
 *                  distance of use - 2. When the offset alphabet (alphabet 2, eight symbols) is not the flat code (all eight
 *                  lengths 3) the low three bits of a wide offset are a symbol of it and the rest are raw.
 *   no end marker  the stream ends where the declared size is reached (the caller's out_cap).
 *
 * The includer has hostile_common.h (hv_rng32) and hostile_enc.h (hv_bw_msb) in scope first, and <decompressors/aspack_tab.h>
 * comes in here (the constant tables the format fixes: the decoder indexes the same ones).
 */
#ifndef HOSTILE_ASPENC_H
#define HOSTILE_ASPENC_H

#include <decompressors/aspack_tab.h>

#define HV_ASP_MAXV 60000u

struct hv_aspvec {
	uint8_t in[HV_ASP_MAXV];
	size_t  n;
	uint8_t want[HV_ASP_MAXV];
	size_t  wn;
};

/* The first code of each length of a canonical code, and the code of every symbol. */
static inline void hv_asp_codes(const uint8_t *len, unsigned n, uint32_t *code)
{
	unsigned cnt[18], i, l;
	uint32_t next[18];
	uint64_t sum = 0;

	memset(cnt, 0, sizeof cnt);
	for (i = 0; i < n; i++)
		cnt[len[i]]++;
	for (l = 1; l <= 15; l++) {
		next[l] = (uint32_t)(sum >> (24u - l));
		sum += (uint64_t)cnt[l] << (24u - l);
	}
	for (i = 0; i < n; i++)
		code[i] = len[i] ? next[len[i]]++ : 0;
}

/*
 * A random COMPLETE code over `nsyms` symbols that gives every symbol of `used` a length (and `extra` more at random), no length
 * above `maxlen`: start from two leaves of depth 1 and split a random leaf until there are enough. Returns 0 when it cannot.
 */
static inline int hv_asp_complete(uint8_t *len, unsigned nsyms, const uint8_t *used, unsigned extra, unsigned maxlen, uint64_t *rs)
{
	static uint16_t order[1024];
	static uint8_t mark[1024], depth[1024];
	unsigned k = 0, nu, nd, i, tries;

	memset(len, 0, nsyms);
	memset(mark, 0, nsyms);
	for (i = 0; i < nsyms; i++)
		if (used && used[i]) {
			mark[i] = 1;
			order[k++] = (uint16_t)i;
		}
	nu = k;
	for (tries = 0; tries < 8u * nsyms && k < nsyms && (k < nu + extra || k < 2); tries++) {
		i = hv_rng32(rs) % nsyms;
		if (!mark[i]) {
			mark[i] = 1;
			order[k++] = (uint16_t)i;
		}
	}
	if (k < 2)
		return 0;
	nd = 2;
	depth[0] = depth[1] = 1;
	for (tries = 0; nd < k && tries < 100000u; tries++) {
		unsigned j = hv_rng32(rs) % nd;

		if (depth[j] >= maxlen)
			continue;
		depth[j]++;
		depth[nd++] = depth[j];
	}
	if (nd < k)
		return 0;
	for (i = k; i > 1; i--) {                       /* shuffle which symbol gets which depth */
		unsigned j = hv_rng32(rs) % i;
		uint16_t t = order[i - 1];

		order[i - 1] = order[j];
		order[j] = t;
	}
	for (i = 0; i < k; i++)
		len[order[i]] = depth[i];
	return 1;
}

struct hv_asp {
	struct hv_bw w;
	uint8_t      prev[757];        /* the code lengths the previous block left */
	uint32_t     c0[721], c1[28], c2[8];
	uint8_t      l0[721], l1[28], l2[8];
	int          dict_ok;
	uint32_t     hist[4];
	uint64_t     rs;
};

/* One block header: the three alphabets' lengths, coded with a fresh alphabet 3 of 19 symbols. */
static inline void hv_asp_header(struct hv_asp *e, int carry)
{
	uint8_t a3len[19], all[757], used3[19];
	uint32_t a3code[19];
	unsigned c, i;
	uint8_t prevout = 0;

	memset(used3, 1, sizeof used3);
	(void)hv_asp_complete(a3len, 19, used3, 0, 15, &e->rs);
	hv_asp_codes(a3len, 19, a3code);
	hv_bw_msb(&e->w, carry ? 1u : 0u, 1);
	if (!carry)
		memset(e->prev, 0, sizeof e->prev);
	for (i = 0; i < 19; i++)
		hv_bw_msb(&e->w, a3len[i], 4);
	memcpy(all, e->l0, 721);
	memcpy(all + 721, e->l1, 28);
	memcpy(all + 749, e->l2, 8);
	for (c = 0; c < 757;) {
		unsigned z = 0, r = 0;

		while (c + z < 757 && all[c + z] == 0 && z < 138)
			z++;
		while (c + r < 757 && all[c + r] == prevout && r < 6)
			r++;
		if (z >= 11) {
			hv_bw_msb(&e->w, a3code[18], a3len[18]);
			hv_bw_msb(&e->w, z - 11u, 7);
			c += z;
			prevout = 0;
		} else if (z >= 3) {
			z = z > 10 ? 10 : z;
			hv_bw_msb(&e->w, a3code[17], a3len[17]);
			hv_bw_msb(&e->w, z - 3u, 3);
			c += z;
			prevout = 0;
		} else if (r >= 3) {
			hv_bw_msb(&e->w, a3code[16], a3len[16]);
			hv_bw_msb(&e->w, r - 3u, 2);
			c += r;
		} else {
			unsigned d = (unsigned)(all[c] - e->prev[c]) & 15u;

			hv_bw_msb(&e->w, a3code[d], a3len[d]);
			prevout = all[c];
			c++;
		}
	}
	memcpy(e->prev, all, sizeof all);
}

/* The alphabets of one segment: alphabet 0 covers `used0` (plus some at random), alphabet 1 every symbol, alphabet 2 flat or skewed. */
static inline void hv_asp_tables(struct hv_asp *e, const uint8_t *used0, int flat)
{
	static const uint8_t skew[8] = { 1, 2, 3, 4, 5, 6, 7, 7 };       /* complete, not all 3 */
	uint8_t all28[28];
	unsigned i;

	memset(all28, 1, sizeof all28);
	(void)hv_asp_complete(e->l0, 721, used0, 3u + hv_rng32(&e->rs) % 40u, 15, &e->rs);
	hv_asp_codes(e->l0, 721, e->c0);
	(void)hv_asp_complete(e->l1, 28, all28, 0, 15, &e->rs);
	hv_asp_codes(e->l1, 28, e->c1);
	for (i = 0; i < 8; i++)
		e->l2[i] = flat ? 3 : skew[i];
	hv_asp_codes(e->l2, 8, e->c2);
	e->dict_ok = !flat;
}

struct hv_asp_tok {
	unsigned kind;                 /* 0 literal, 1 match, 2 rebuild */
	unsigned sym0;                 /* alphabet 0 */
	unsigned esym, ebits;          /* alphabet 1 escape (esym 99: none), its extra bits */
	uint32_t eval;
	unsigned wbits;                /* raw offset bits */
	uint32_t wval;
	unsigned low;                  /* alphabet 2 symbol, 8: none */
};

static inline unsigned hv_asp_class(uint32_t use, uint32_t *extra, unsigned *width)
{
	uint32_t init = 0;
	unsigned cls;

	for (cls = 0; cls < KUNCOAT_ASPACK_OFF_N; cls++) {
		unsigned w = kuncoat_aspack_tab[KUNCOAT_ASPACK_OFF_BASE + cls];

		if (use < init + (1u << w)) {
			*extra = use - init;
			*width = w;
			return cls;
		}
		init += 1u << w;
	}
	*extra = 0;
	*width = 0;
	return KUNCOAT_ASPACK_OFF_N - 1u;
}

/* The match as tokens, tracking the three recent offsets as the decoder will; `dict_ok` says how the low three offset bits go. */
static inline void hv_asp_match_tok(struct hv_asp_tok *t, uint32_t hist[4], int dict_ok, uint32_t dist, unsigned len, int as_hist, unsigned hk)
{
	uint32_t use = as_hist ? hk : dist + 2u, extra;
	unsigned cls, width, lsym, e;
	uint32_t base[28];
	unsigned i;

	memset(t, 0, sizeof *t);
	t->kind = 1;
	cls = hv_asp_class(use, &extra, &width);
	if (!dict_ok || width < 3) {
		t->wbits = width;
		t->wval = extra;
		t->low = 8;
	} else {
		t->wbits = width - 3u;
		t->wval = extra >> 3;
		t->low = extra & 7u;
	}
	if (use < 3) {
		uint32_t c = hist[use];

		if (use) {
			hist[use] = hist[0];
			hist[0] = c;
		}
	} else {
		hist[2] = hist[1];
		hist[1] = hist[0];
		hist[0] = use - 3u;
	}
	t->esym = 99;
	if (len <= 8) {
		lsym = len - 2u;
	} else {
		lsym = 7;
		for (i = 0; i < 28; i++)
			base[i] = kuncoat_aspack_tab[i];
		for (e = 0; e < 28; e++)
			if (len - 9u >= base[e] && len - 9u < base[e] + (1u << kuncoat_aspack_tab[0x1cu + e]))
				break;
		t->esym = e;
		t->ebits = kuncoat_aspack_tab[0x1cu + e];
		t->eval = len - 9u - base[e];
	}
	t->sym0 = 256u + cls * 8u + lsym;
}

static inline void hv_asp_emit(struct hv_asp *e, const struct hv_asp_tok *t)
{
	hv_bw_msb(&e->w, e->c0[t->sym0], e->l0[t->sym0]);
	if (t->kind == 1) {
		if (t->esym != 99) {
			hv_bw_msb(&e->w, e->c1[t->esym], e->l1[t->esym]);
			hv_bw_msb(&e->w, t->eval, t->ebits);
		}
		hv_bw_msb(&e->w, t->wval, t->wbits);
		if (t->low != 8)
			hv_bw_msb(&e->w, e->c2[t->low], e->l2[t->low]);
	}
}

/*
 * A random valid ASPack stream of about `target` bytes in `nseg` segments (a rebuild between them, the second and later blocks
 * carrying the previous lengths or not at random), `flat` choosing the flat offset alphabet. The plain text is v->want and the
 * decoder must be called with out_cap == v->wn. Returns 0 when something did not fit.
 */
static inline int make_asp(struct hv_aspvec *v, uint64_t seed, size_t target, unsigned nseg, int flat)
{
	static struct hv_asp_tok tok[HV_ASP_MAXV];
	struct hv_asp e;
	uint32_t hist[4] = { 0, 0, 0, 0 };
	uint64_t rs = seed;
	size_t at = 0, nt = 0, seg_start = 0;
	unsigned seg, i;
	uint8_t used0[721];

	memset(&e, 0, sizeof e);
	e.rs = seed ^ 0x9e3779b97f4a7c15ull;
	hv_bw_init(&e.w, v->in, sizeof v->in);
	for (seg = 0; seg < nseg; seg++) {
		size_t until = target * (seg + 1u) / nseg;
		int seg_flat = seg ? (int)(hv_rng32(&rs) & 1u) : flat;

		seg_start = nt;
		while (at < until && nt < HV_ASP_MAXV - 4u) {
			uint32_t r = hv_rng32(&rs) % 100u;

			if (at < 4 || r < 45) {
				uint32_t pick = hv_rng32(&rs) % 5u, any = hv_rng32(&rs) % 256u;
				uint8_t b = (uint8_t)(pick ? (uint32_t)"abcdefgh"[hv_rng32(&rs) % 8u] : any);

				memset(&tok[nt], 0, sizeof tok[nt]);
				tok[nt].kind = 0;
				tok[nt].sym0 = b;
				v->want[at++] = b;
				nt++;
			} else {
				uint32_t k = hv_rng32(&rs) % 5u, span = k == 0 ? (uint32_t)at : k == 1 ? 40u : k == 2 ? 3000u : k == 3 ? 20000u : 8u, dist;
				uint32_t wide = hv_rng32(&rs) % 4u, lr = hv_rng32(&rs);                   /* sequenced: two draws in one expression are unordered in C */
				unsigned len = 2u + lr % (wide ? 9u : 263u);
				int as_hist = 0;
				unsigned hk = 0;
				size_t j;

				if (span > at)
					span = (uint32_t)at;
				dist = 1u + hv_rng32(&rs) % span;
				if (hv_rng32(&rs) % 4u == 0) {                  /* one of the three recent offsets, when it reaches back far enough */
					hk = hv_rng32(&rs) % 3u;
					if ((size_t)hist[hk] + 1u <= at) {
						as_hist = 1;
						dist = hist[hk] + 1u;
					}
				}
				hv_asp_match_tok(&tok[nt], hist, !seg_flat, dist, len, as_hist, hk);
				for (j = 0; j < len && at < HV_ASP_MAXV; j++, at++)
					v->want[at] = v->want[at - dist];
				nt++;
			}
		}
		/* tables for this segment: the symbols its tokens use, and 720 when a rebuild follows */
		memset(used0, 0, sizeof used0);
		for (i = (unsigned)seg_start; i < nt; i++)
			used0[tok[i].sym0] = 1;
		if (seg + 1u < nseg)
			used0[720] = 1;
		hv_asp_tables(&e, used0, seg_flat);
		hv_asp_header(&e, seg ? (int)(hv_rng32(&rs) & 1u) : 0);
		for (i = (unsigned)seg_start; i < nt; i++)
			hv_asp_emit(&e, &tok[i]);
		if (seg + 1u < nseg) {
			memset(&tok[nt], 0, sizeof tok[nt]);
			tok[nt].kind = 2;
			tok[nt].sym0 = 720;
			hv_asp_emit(&e, &tok[nt]);
			nt++;
		}
		/* the next segment's tables are chosen when its tokens are known: the header is written then, after the 720 above */
	}
	if (e.w.nb)
		hv_bw_msb(&e.w, 0, 8u - e.w.nb);
	v->n = e.w.n;
	v->wn = at;
	return !e.w.over && at <= HV_ASP_MAXV;
}

/*
 * The densest stream: one literal 'a', then `n_match` matches of length 264 at distance 1 (a use of 3, the first new distance). About 100
 * output bytes for each byte of input. The plain text is `wn` bytes of 'a' (v->want holds only the first HV_ASP_MAXV of them).
 */
static inline int make_asp_bomb(struct hv_aspvec *v, unsigned n_match)
{
	struct hv_asp e;
	struct hv_asp_tok lit, m;
	uint32_t hist[4] = { 0, 0, 0, 0 };
	uint8_t used0[721];
	unsigned i;
	size_t at = 0;

	memset(&e, 0, sizeof e);
	e.rs = 0x1234567u;
	hv_bw_init(&e.w, v->in, sizeof v->in);
	memset(&lit, 0, sizeof lit);
	lit.sym0 = 'a';
	hv_asp_match_tok(&m, hist, 0, 1, 264, 0, 0);
	memset(used0, 0, sizeof used0);
	used0[lit.sym0] = 1;
	used0[m.sym0] = 1;
	hv_asp_tables(&e, used0, 1);
	hv_asp_header(&e, 0);
	hv_asp_emit(&e, &lit);
	v->want[at++] = 'a';
	for (i = 0; i < n_match; i++) {
		hv_asp_emit(&e, &m);
		if (at + 264u <= HV_ASP_MAXV)
			memset(v->want + at, 'a', 264);
		at += 264;
	}
	if (e.w.nb)
		hv_bw_msb(&e.w, 0, 8u - e.w.nb);
	v->n = e.w.n;
	v->wn = at;
	return !e.w.over;
}

#endif /* HOSTILE_ASPENC_H */
