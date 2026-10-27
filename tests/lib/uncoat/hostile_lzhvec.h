/*
 * hostile_lzhvec.h - random VALID LHA/ARJ (LZHUF) streams for the four variants, a small and a deep code design, with the bytes a decoder must give back. Written once and used by hostile_lzhuf.c (the sweeps) and tests/fuzz/decomp (the seeds), so that the format is
 * spelled in one place. The includer has hostile_common.h and hostile_lzhenc.h in scope first.
 */
#ifndef HOSTILE_LZHVEC_H
#define HOSTILE_LZHVEC_H

static const struct { unsigned np, pbit, dict; } VAR[4] = {
	{ 17, 5, 26624 }, { 14, 4, 8192 }, { 16, 5, 32768 }, { 17, 5, 65536 }
};

struct vec {
	uint8_t in[200000];
	size_t  n;
	uint8_t want[180000];
	size_t  wn;
};

/* design 0: 40 literals, match lengths 3..18, positions 0..7. design 1: 60 literals,
 * lengths 3..34, every position the variant has. */
static inline void set_code(struct hv_lh *e, int design)
{
	uint8_t lens[256];
	unsigned nl = design ? 60u : 40u, nm = design ? 32u : 16u, np = design ? e->np : 8u, i, k = 0;

	memset(e->cl, 0, sizeof e->cl);
	memset(e->pl, 0, sizeof e->pl);
	hv_lh_lengths(lens, nl + nm, design ? 8u : 6u);
	for (i = 0; i < nl; i++)
		e->cl[32 + i] = lens[k++];
	for (i = 0; i < nm; i++)
		e->cl[256 + i] = lens[k++];
	hv_lh_lengths(lens, np, np > 6 ? 4u : np - 1u);
	for (i = 0; i < np; i++)
		e->pl[i] = lens[i];
}

static inline int make_lh(struct vec *v, unsigned var, int design, uint64_t seed, size_t target)
{
	struct hv_lh e;
	uint64_t rs = seed;
	size_t done = 0;
	static struct { int match; uint8_t lit; unsigned len; uint32_t dist; } ops[4000];

	hv_lh_init(&e, v->in, sizeof v->in, v->want, sizeof v->want, VAR[var].np, VAR[var].pbit);
	while (e.hn < target) {
		unsigned nops = 0;
		size_t blk_bytes = 0, hn = e.hn;

		while (nops < 3000 && blk_bytes < 6000) {
			uint32_t r = hv_rng32(&rs) % 100u;

			if (hn < 3 || r < 50) {
				uint32_t pick = hv_rng32(&rs) % 40u;

				ops[nops].match = 0;
				ops[nops].lit = (uint8_t)(32u + (design ? pick % 60u : pick));
				nops++;
				hn++;
				blk_bytes++;
			} else {
				uint32_t maxlen = design ? 34u : 18u, lenr = hv_rng32(&rs) % (maxlen - 2u);
				uint32_t maxd = design ? (uint32_t)(VAR[var].dict < 8192u ? VAR[var].dict : 8192u) : 128u;
				uint32_t span = hv_rng32(&rs) % 3u ? 40u : maxd, dist;

				if (span > hn)
					span = (uint32_t)hn;
				dist = 1u + hv_rng32(&rs) % span;
				ops[nops].match = 1;
				ops[nops].len = 3u + lenr;
				ops[nops].dist = dist;
				nops++;
				hn += 3u + lenr;
				blk_bytes += 3u + lenr;
			}
		}
		set_code(&e, design);
		hv_lh_block(&e, nops);
		{
			unsigned i;

			for (i = 0; i < nops; i++) {
				if (ops[i].match)
					hv_lh_match(&e, ops[i].len, ops[i].dist);
				else
					hv_lh_lit(&e, ops[i].lit);
			}
		}
		done = e.hn;
	}
	(void)done;
	v->n = hv_lh_finish(&e);
	v->wn = e.hn;
	return !e.w.over && e.hn <= sizeof v->want;
}


#endif /* HOSTILE_LZHVEC_H */
