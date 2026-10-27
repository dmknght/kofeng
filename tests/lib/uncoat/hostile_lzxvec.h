/*
 * hostile_lzxvec.h - random VALID LZX streams (uncompressed, verbatim and aligned blocks) with the bytes a decoder must give back. Written once and used by hostile_lzx.c (the sweeps) and tests/fuzz/decomp (the seeds), so that the format is
 * spelled in one place. The includer has hostile_common.h and hostile_lzxenc.h in scope first.
 */
#ifndef HOSTILE_LZXVEC_H
#define HOSTILE_LZXVEC_H

struct vec {
	uint8_t in[90000];
	size_t  n;
	uint8_t want[90000];
	size_t  wn;
};

struct op { int kind; uint32_t off, len; uint8_t lit; };

/* A random valid block script totalling about `target` bytes of output. */
static inline size_t block_ops(struct op *ops, size_t max_ops, uint64_t *rs, size_t hn0, size_t target, size_t *total)
{
	size_t n = 0, hn = hn0, sum = 0;
	uint32_t r0 = 1;

	(void)r0;
	while (sum < target && n < max_ops) {
		uint32_t r = hv_rng32(rs) % 100u;

		if (hn < 4 || r < 55) {
			ops[n].kind = 0;
			uint32_t pick = hv_rng32(rs) % 4u, ix = hv_rng32(rs) % 12u, any = hv_rng32(rs) & 0x7fu;

			ops[n].lit = (uint8_t)(pick ? (uint32_t)"etaoinshrdlu"[ix] : any);
			n++;
			hn++;
			sum++;
		} else {
			uint32_t lim = hv_rng32(rs) % 3u == 0 ? 253u : 40u, wide = hv_rng32(rs) % 4u, len;
			uint32_t off;

			len = 2u + hv_rng32(rs) % (wide ? 7u : 135u);
			if (lim > hn)
				lim = (uint32_t)hn;
			off = 1u + hv_rng32(rs) % lim;
			ops[n].kind = 1;
			ops[n].off = off;
			ops[n].len = len;
			n++;
			hn += len;
			sum += len;
		}
	}
	*total = sum;
	return n;
}

static inline int emit_block(struct hv_lx *e, unsigned type, const struct op *ops, size_t nops, size_t total)
{
	size_t i;
	int ok = 1;

	hv_lx_block_begin(e, type, (uint32_t)total);
	for (i = 0; i < nops; i++) {
		if (ops[i].kind == 0)
			hv_lx_lit(e, ops[i].lit);
		else
			ok &= hv_lx_match(e, type == 2, ops[i].off, ops[i].len);
	}
	return ok;
}

/* uncompressed + verbatim + aligned (+ more), at `bits`, about `target` bytes in all. */
static inline int make_lzx(struct vec *v, unsigned bits, uint64_t seed, size_t target, uint32_t e8_size)
{
	struct hv_lx e;
	static struct op ops[30000];
	uint64_t rs = seed;
	size_t nops, total, i, done = 0;
	uint8_t raw[300];
	uint32_t r[3] = { 5, 7, 11 };
	int ok = 1;
	unsigned blk = 0;

	hv_lx_init(&e, v->in, sizeof v->in, v->want, sizeof v->want, bits, e8_size);
	for (i = 0; i < sizeof raw; i++)
		raw[i] = (uint8_t)hv_rng32(&rs);
	hv_lx_uncompressed(&e, raw, sizeof raw, r);
	done = sizeof raw;
	while (done < target) {
		size_t want_here = target - done > 7000 ? 7000 : target - done;

		nops = block_ops(ops, sizeof ops / sizeof ops[0], &rs, e.hn, want_here, &total);
		ok &= emit_block(&e, 1 + (blk++ & 1u), ops, nops, total);
		done += total;
		if (blk == 2) {                                   /* an odd-sized uncompressed block in the middle */
			uint32_t r2[3] = { 1, 2, 3 };

			hv_lx_uncompressed(&e, raw, 77, r2);
			done += 77;
		}
	}
	v->n = hv_lx_finish(&e);
	v->wn = e.hn;
	return ok && !e.over && e.hn <= sizeof v->want;
}


#endif /* HOSTILE_LZXVEC_H */
