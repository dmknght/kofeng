/*
 * hostile_rarvec.h - random VALID RAR3 and RAR5 streams (RAR5 with filters, independent restatements of the three filters included) with the bytes a decoder must give back. Written once and used by hostile_rar.c (the sweeps) and tests/fuzz/decomp (the seeds), so that the format is
 * spelled in one place. The includer has hostile_common.h, hostile_lzhenc.h and hostile_rarenc.h in scope first.
 */
#ifndef HOSTILE_RARVEC_H
#define HOSTILE_RARVEC_H

#define MAXV 60000u

struct vec {
	uint8_t in[MAXV];
	size_t  n;
	uint8_t want[MAXV];
	size_t  wn;
};

struct filt { uint64_t at; uint32_t len; unsigned type, chan; };

/* independent restatements of the three RAR5 filters */
static inline void ref_e8(uint8_t *d, uint32_t n, uint32_t file_off, int e9)
{
	uint32_t cur = 0;

	if (n < 5)
		return;
	while (cur < n - 4u) {
		uint8_t c = d[cur++];

		if (c == 0xE8 || (e9 && c == 0xE9)) {
			uint32_t off = (cur + file_off) % 0x1000000u;
			uint32_t addr = (uint32_t)d[cur] | (uint32_t)d[cur + 1] << 8 | (uint32_t)d[cur + 2] << 16 | (uint32_t)d[cur + 3] << 24;
			uint32_t nv = addr;
			int w = 0;

			if (addr < 0x1000000u) {
				nv = addr - off;
				w = 1;
			} else if ((addr & 0x80000000u) && !((addr + off) & 0x80000000u)) {
				nv = addr + 0x1000000u;
				w = 1;
			}
			if (w) {
				d[cur] = (uint8_t)nv; d[cur + 1] = (uint8_t)(nv >> 8);
				d[cur + 2] = (uint8_t)(nv >> 16); d[cur + 3] = (uint8_t)(nv >> 24);
			}
			cur += 4;
		}
	}
}

static inline void ref_delta(uint8_t *d, uint32_t n, unsigned chan)
{
	static uint8_t tmp[70000];
	uint32_t ch, src = 0, at;

	memcpy(tmp, d, n);
	for (ch = 0; ch < chan; ch++) {
		uint8_t prev = 0;

		for (at = ch; at < n; at += chan) {
			prev = (uint8_t)(prev - tmp[src++]);
			d[at] = prev;
		}
	}
}

static inline void ref_arm(uint8_t *d, uint32_t n, uint32_t file_off)
{
	uint32_t i;

	for (i = 0; i + 4 <= n; i += 4)
		if (d[i + 3] == 0xEB) {
			uint32_t off = (uint32_t)d[i] | (uint32_t)d[i + 1] << 8 | (uint32_t)d[i + 2] << 16;

			off -= (file_off + i) / 4u;
			d[i] = (uint8_t)off; d[i + 1] = (uint8_t)(off >> 8); d[i + 2] = (uint8_t)(off >> 16);
		}
}

static inline uint8_t rnd_lit(uint64_t *rs)
{
	uint32_t a = hv_rng32(rs) % 100u, b = hv_rng32(rs) % 3u, c = hv_rng32(rs) % 100u;

	return hv_rar_lit(b ? a % 96u : c);
}

/* A random RAR5 stream, two blocks (the second with no tables), optionally with filters. */
static inline int make_r5(struct vec *v, uint64_t seed, size_t target, int filters)
{
	struct hv_r5 e;
	static uint8_t pay[MAXV];
	uint64_t rs = seed;
	size_t half = target / 2, n;
	struct filt fl[6];
	unsigned nf = 0, blk, i;

	memset(&e, 0, sizeof e);
	for (blk = 0; blk < 2; blk++) {
		size_t until = blk ? target : half;

		hv_r5_begin(&e, v->in, sizeof v->in, pay, sizeof pay, v->want, sizeof v->want, blk == 0);
		while (e.hn < until) {
			uint32_t r = hv_rng32(&rs) % 100u;

			if (e.hn < 3 || r < 50) {
				hv_r5_lit(&e, rnd_lit(&rs));
			} else if (r < 70) {
				uint32_t k = hv_rng32(&rs) % 4u, span = k == 0 ? 60000u : k == 1 ? 200u : k == 2 ? 9000u : 40u, d;
				uint32_t len, adj;

				if (span > e.hn)
					span = (uint32_t)e.hn;
				d = 1u + hv_rng32(&rs) % span;
				adj = d > 0x40000u ? 3u : d > 0x2000u ? 2u : d > 0x100u ? 1u : 0u;
				len = adj + 2u + hv_rng32(&rs) % 40u;
				(void)hv_r5_match(&e, len, d);
			} else if (r < 80 && e.old[0] && e.old[0] <= e.hn && e.last_len) {
				hv_r5_repeat_last(&e);
			} else if (r < 92) {
				unsigned k = hv_rng32(&rs) % 4u;

				if (e.old[k] && e.old[k] <= e.hn)
					(void)hv_r5_rep(&e, k, 2u + hv_rng32(&rs) % 8u);
				else
					hv_r5_lit(&e, rnd_lit(&rs));
			} else if (filters && nf < 6 && e.hn > 400) {
				static const unsigned types[] = { 1, 2, 3, 0, 1, 0 };
				unsigned t = types[nf];
				uint32_t st = (uint32_t)(hv_rng32(&rs) % 3u);

				fl[nf].at = e.hn + st;
				fl[nf].len = 100u + hv_rng32(&rs) % 300u;
				fl[nf].type = t;
				fl[nf].chan = 1u + hv_rng32(&rs) % 4u;
				hv_r5_filter(&e, st, fl[nf].len, t, fl[nf].chan);
				nf++;
			} else {
				hv_r5_lit(&e, rnd_lit(&rs));
			}
		}
		n = hv_r5_end_block(&e, blk == 0, blk == 1);
		(void)n;
	}
	v->n = e.w.n;
	v->wn = e.hn;
	/* apply the filters to the expected bytes, in the order the decoder will */
	for (i = 0; i < nf; i++) {
		if (fl[i].at + fl[i].len > v->wn)
			continue;
		if (fl[i].type == 1 || fl[i].type == 2)
			ref_e8(v->want + fl[i].at, fl[i].len, (uint32_t)fl[i].at, fl[i].type == 2);
		else if (fl[i].type == 3)
			ref_arm(v->want + fl[i].at, fl[i].len, (uint32_t)fl[i].at);
		else
			ref_delta(v->want + fl[i].at, fl[i].len, fl[i].chan);
	}
	return !e.w.over && e.hn <= MAXV;
}

static inline int make_r3(struct vec *v, uint64_t seed, size_t target)
{
	struct hv_r3 e;
	uint64_t rs = seed;

	hv_r3_init(&e, v->in, sizeof v->in, v->want, sizeof v->want);
	while (e.hn < target) {
		uint32_t r = hv_rng32(&rs) % 100u;

		if (e.hn < 3 || r < 50) {
			hv_r3_lit(&e, rnd_lit(&rs));
		} else if (r < 70) {
			uint32_t d = 1u + hv_rng32(&rs) % (e.hn < 256 ? (uint32_t)e.hn : 256u), len = 3u + hv_rng32(&rs) % 24u;

			if (!hv_r3_match(&e, len, d))
				hv_r3_lit(&e, rnd_lit(&rs));
		} else if (r < 78 && e.last_len && e.last_dist <= e.hn) {
			hv_r3_repeat_last(&e);
		} else if (r < 90) {
			unsigned k = hv_rng32(&rs) % 4u;

			if (e.old[k] && e.old[k] <= e.hn) {
				if (!hv_r3_rep(&e, k, 2u + hv_rng32(&rs) % 8u))
					hv_r3_lit(&e, rnd_lit(&rs));
			} else {
				hv_r3_lit(&e, rnd_lit(&rs));
			}
		} else {
			uint32_t d = 1u + hv_rng32(&rs) % (e.hn < 256 ? (uint32_t)e.hn : 256u);

			if (!hv_r3_short(&e, d))
				hv_r3_lit(&e, rnd_lit(&rs));
		}
	}
	v->n = hv_r3_finish(&e);
	v->wn = e.hn;
	return !e.w.over && e.hn <= MAXV;
}


#endif /* HOSTILE_RARVEC_H */
