/*
 * hostile_lzvec.h - the script writers of the bit-stream LZ decoders: random VALID NRV2 / aPLib / LZMAT streams with the
 * bytes a decoder must give back. Written once and used by hostile_lzbit.c (the sweeps) and tests/fuzz/decomp (the seeds),
 * so that the format is spelled in one place. The includer has hostile_common.h (hv_rng32) and hostile_nrvenc.h
 * (the NRV2 and aPLib bit writers) in scope first.
 */
#ifndef HOSTILE_LZVEC_H
#define HOSTILE_LZVEC_H

/* ---- scripts ----------------------------------------------------------------------------- */

struct vec {
	uint8_t in[8000];
	size_t  n;
	uint8_t want[8000];
	size_t  wn;
};

/* A letter from `alpha` (8 of them), now and then a random byte; the draws are sequenced. */
static inline uint8_t rnd_byte(uint64_t *rs, const char *alpha)
{
	uint32_t pick = hv_rng32(rs) % 8u, odd = hv_rng32(rs) % 6u, any = hv_rng32(rs);

	return (uint8_t)(odd ? (uint32_t)alpha[pick] : any);
}

/* A length from a skewed distribution: mostly below `small`, sometimes up to `big`. */
static inline uint32_t rnd_len(uint64_t *rs, uint32_t small, uint32_t big)
{
	uint32_t wide = hv_rng32(rs) % 3u, v = hv_rng32(rs);

	return v % (wide ? small : big);
}

/* A random valid NRV2 script. */
static inline int make_nrv(struct vec *v, int variant, unsigned width, uint64_t seed, size_t target)
{
	struct hv_tw w;
	uint64_t rs = seed;
	int have_match = 0;

	hv_tw_init(&w, v->in, sizeof v->in, width, v->want, sizeof v->want);
	while (w.hn < target) {
		uint32_t r = hv_rng32(&rs) % 100u;

		if (w.hn < 3 || r < 50) {
			hv_nrv_lit(&w, rnd_byte(&rs, "abcdefgh"));
		} else if (r < 85 || !have_match) {
			uint32_t k = hv_rng32(&rs) % 4u;
			uint32_t span = k == 0 ? (uint32_t)w.hn : k == 1 ? 40u : k == 2 ? 600u : 4000u;
			uint32_t dist, minl, len;

			span = span > (uint32_t)w.hn ? (uint32_t)w.hn : span;
			dist = 1u + hv_rng32(&rs) % span;
			minl = variant == HV_NRV2B ? 2u + (dist > 0xd00u) : 2u + (dist > 0x500u);
			len = minl + rnd_len(&rs, 12u, 300u);
			hv_nrv_match(&w, variant, dist, len);
			have_match = 1;
		} else {
			uint32_t d = w.last, minl = variant == HV_NRV2B ? 2u + (d > 0xd00u) : 2u + (d > 0x500u);

			hv_nrv_rep(&w, variant, minl + hv_rng32(&rs) % 9u);
		}
	}
	hv_nrv_end(&w, variant);
	v->n = w.n;
	v->wn = w.hn;
	return !w.over;
}

static inline int make_ap(struct vec *v, uint64_t seed, size_t target)
{
	struct hv_tw w;
	uint64_t rs = seed;

	hv_tw_init(&w, v->in, sizeof v->in, 8, v->want, sizeof v->want);
	hv_ap_first(&w, 'S');
	while (w.hn < target) {
		uint32_t r = hv_rng32(&rs) % 100u, d;

		if (r < 40 || w.hn < 2) {
			hv_ap_lit(&w, rnd_byte(&rs, "hijklmno"));
		} else if (r < 70) {
			uint32_t k = hv_rng32(&rs) % 3u;
			uint32_t span = k == 0 ? (uint32_t)w.hn : k == 1 ? 100u : 2000u;

			span = span > (uint32_t)w.hn ? (uint32_t)w.hn : span;
			d = 1u + hv_rng32(&rs) % span;
			hv_ap_match(&w, d, 2u + hv_ap_adj(d) + rnd_len(&rs, 10u, 200u));
		} else if (r < 80 && !w.lwm && w.last >= 1 && w.last <= w.hn) {
			hv_ap_rep(&w, 2u + hv_rng32(&rs) % 9u);
		} else if (r < 90) {
			d = 1u + hv_rng32(&rs) % (w.hn < 127 ? (uint32_t)w.hn : 127u);
			hv_ap_short(&w, d, 2u + hv_rng32(&rs) % 2u);
		} else {
			d = hv_rng32(&rs) % (w.hn < 15 ? (uint32_t)w.hn + 1u : 16u);
			hv_ap_single(&w, d);
		}
	}
	hv_ap_end(&w);
	v->n = w.n;
	v->wn = w.hn;
	return !w.over;
}

/* ---- LZMAT: a nibble stream ------------------------------------------------------------------ */

struct nib {
	uint8_t *out;
	size_t   cap, n;           /* nibbles written */
	uint8_t *hist;
	size_t   hn, hcap;
	/* the group under construction */
	struct { int match; uint32_t dist, len; uint8_t lit; } g[8];
	unsigned ng;
	size_t   ctl_at;
};

static inline void nib_put(struct nib *e, unsigned v)
{
	if ((e->n >> 1) < e->cap) {
		if (e->n & 1u)
			e->out[e->n >> 1] = (uint8_t)(e->out[e->n >> 1] | (v << 4));
		else
			e->out[e->n >> 1] = (uint8_t)(v & 15u);
	}
	e->n++;
}

static inline void nib_val(struct nib *e, uint32_t v, unsigned nibbles)
{
	while (nibbles--) {
		nib_put(e, v & 15u);
		v >>= 4;
	}
}

static inline void lm_hist(struct nib *e, uint8_t b)
{
	if (e->hn < e->hcap)
		e->hist[e->hn] = b;
	e->hn++;
}

/* Write the distance forms the format has, by the output position at the time. */
static inline void lm_dist(struct nib *e, uint32_t dist, size_t pos)
{
	if (pos < 0x881u) {
		if (dist <= 0x80u)
			nib_val(e, (dist - 1u) << 1, 2);
		else
			nib_val(e, ((dist - 0x81u) << 1) | 1u, 3);
	} else if (dist <= 0x40u) {
		nib_val(e, (dist - 1u) << 2, 2);
	} else if (dist <= 0x440u) {
		nib_val(e, ((dist - 0x41u) << 2) | 1u, 3);
	} else if (dist < 0x4441u) {
		nib_val(e, ((dist - 0x441u) << 2) | 2u, 4);
	} else {
		uint32_t d = dist - 0x4441u;

		nib_val(e, ((d & 0x3fffu) << 2) | 3u, 4);
		nib_val(e, d >> 14, 1);
	}
}

static inline void lm_len(struct nib *e, uint32_t len)
{
	if (len < 18u) {
		nib_val(e, len - 3u, 1);
	} else if (len < 0x111u) {
		nib_val(e, 0xf, 1);
		nib_val(e, len - 0x12u, 2);
	} else {
		nib_val(e, 0xf, 1);
		nib_val(e, 0xff, 2);
		nib_val(e, len - 0x111u, 4);
	}
}

static inline void lm_flush(struct nib *e)
{
	unsigned i, ctl = 0;

	for (i = 0; i < e->ng; i++)
		if (e->g[i].match)
			ctl |= 0x80u >> i;
	nib_val(e, ctl, 2);
	for (i = 0; i < e->ng; i++) {
		if (!e->g[i].match) {
			nib_val(e, e->g[i].lit, 2);
			lm_hist(e, e->g[i].lit);
		} else {
			unsigned k;

			lm_dist(e, e->g[i].dist, e->hn);
			lm_len(e, e->g[i].len);
			for (k = 0; k < e->g[i].len; k++)
				lm_hist(e, e->hn >= e->g[i].dist && e->hn - e->g[i].dist < e->hcap ?
					e->hist[e->hn - e->g[i].dist] : 0);
		}
	}
	e->ng = 0;
}

static inline void lm_item(struct nib *e, int match, uint32_t dist, uint32_t len, uint8_t lit)
{
	e->g[e->ng].match = match;
	e->g[e->ng].dist = dist;
	e->g[e->ng].len = len;
	e->g[e->ng].lit = lit;
	e->ng++;
	if (e->ng == 8) {
		/* the history must be current before the next group's positions are chosen, so a
		 * group is encoded as soon as it is full */
		lm_flush(e);
	}
}

static int lm_odd __attribute__((unused));

/* A script that knows the position at the time each match is written: groups are encoded
 * in order, so `pos` for the distance form is the history length when its group begins and
 * grows within it; lm_flush recomputes it item by item exactly as the decoder will. */
static inline int make_lzmat(struct vec *v, uint64_t seed, size_t target)
{
	struct nib e;
	uint64_t rs = seed;
	size_t planned = 1;                 /* output bytes the script has promised so far */

	memset(&e, 0, sizeof e);
	e.out = v->in;
	e.cap = sizeof v->in;
	e.hist = v->want;
	e.hcap = sizeof v->want;
	nib_val(&e, 'L', 2);
	lm_hist(&e, 'L');
	while (planned < target) {
		uint32_t r = hv_rng32(&rs) % 100u;

		if (planned < 4 || r < 55) {
			lm_item(&e, 0, 0, 0, rnd_byte(&rs, "pqrstuvw"));
			planned++;
		} else {
			uint32_t k = hv_rng32(&rs) % 6u, lim, d, len, lk = hv_rng32(&rs) % 5u;

			lim = k == 0 ? 0x40u : k == 1 ? 0x80u : k == 2 ? 0x440u : k == 3 ? 0x880u : k == 4 ? 0x4440u : 0x7000u;
			if (lim > planned)
				lim = (uint32_t)planned;
			d = 1u + hv_rng32(&rs) % lim;
			len = lk < 3 ? 3u + hv_rng32(&rs) % 15u : lk == 3 ? 18u + hv_rng32(&rs) % 200u : 0x111u + hv_rng32(&rs) % 400u;
			lm_item(&e, 1, d, len, 0);
			planned += len;
		}
	}
	if (e.ng)
		lm_flush(&e);
	/* A stream must end on a byte: a half-byte tail is read by the decoder as one more
	 * literal (it has no end marker), so the caller asks again with the next seed. */
	lm_odd = (int)(e.n & 1u);
	if (lm_odd)
		nib_put(&e, 0);
	v->n = e.n >> 1;
	v->wn = e.hn;
	return (e.n >> 1) <= e.cap && e.hn <= e.hcap;
}

/* A script whose stream ends on a byte boundary: the first seed that does. */
static inline int make_lzmat_even(struct vec *v, uint64_t seed, size_t target)
{
	unsigned t;

	for (t = 0; t < 64; t++)
		if (make_lzmat(v, seed + t, target) && !lm_odd)
			return 1;
	return 0;
}

#endif /* HOSTILE_LZVEC_H */
