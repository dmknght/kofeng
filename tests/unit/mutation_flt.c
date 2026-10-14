/*
 * mutation_flt - the block filter that follows the ledger (kofmutflt.h): the partitioned fuse filter, the rule that
 * sizes it, and the matcher holding it.
 *
 * WHAT IS PINNED, each a way the filter could be wrong while looking fine:
 *
 *   - NO FALSE REJECT. Every key that was added passes, at every stored width (8, 16), at every width the
 *     loader may keep (16, 8, 4, 2, 1), for sets of 0 to 2.5 million keys, uniform and crowded towards zero
 *     the way a block's smallest hashes are. A filter that rejected one member would lower a credit count.
 *   - THE FALSE-PASS RATE IS WHAT THE WIDTH SAYS: about 2^-w. A filter that passed everything would be
 *     correct and useless; one that is far above its width has a hash that does not spread.
 *   - TRUNCATION IS EXACT: a filter stored at 16 bits and kept at 8 answers like one built at 8.
 *   - A PARTITION THAT IS NOT RESIDENT PASSES every key (a cost, never a loss), and a partition with no keys
 *     passes none.
 *   - A DAMAGED REGION IS A REFUSAL, never an answer: a flipped byte (checksum), a short read, a table
 *     that says a part lies outside the region, a segment shape the arithmetic would overflow. A fuzzer
 *     flips bytes in the region and in the table (with the checksum recomputed, so the validation is what
 *     is on trial) and the open either fails or yields a filter that answers without leaving its arrays.
 *   - THE SIZE RULE has no flat figure: the ceiling follows the room, never exceeds a quarter of it, is
 *     the same for 1,000 and 1,000,000,000 hashes, and the ladder only ever goes down as the grant does.
 *   - THE MATCHER GIVES THE SAME CREDIT whatever the filter: a set whose filter is pre-built, kept at
 *     every width the ledger can leave it at (and with no filter at all), a set whose filter is a bloom filter, and
 *     a set that mixes the two over several packs, all credit every (object, block) the way a brute-force
 *     count over the same windows does.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include "../../libkofeng/kofcore/kofcore.h"

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint32_t rnd(uint32_t *s)
{
	*s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
	return *s;
}

static int t_mem_read(void *ctx, uint64_t off, void *buf, size_t n)
{
	memcpy(buf, (const uint8_t *)ctx + off, n);
	return 1;
}

/* kof_mflt_test as an unsigned 0 or 1, for the tallies below. */
static uint32_t ft(const struct kof_mflt *f, uint32_t v)
{
	return kof_mflt_test(f, v) ? 1u : 0u;
}

static int cmp32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

static uint32_t *keys_make(uint32_t n, int skew, uint32_t *seed, uint32_t *out_n)
{
	uint32_t *k = malloc((size_t)(n ? n : 1u) * 4u), i, m = 0;

	for (i = 0; i < n; i++) {
		uint32_t v = skew ? rnd(seed) % (1u << (8u + rnd(seed) % 20u)) : rnd(seed);

		k[i] = v * KOF_KIX_MULT;      /* what the matcher asks about: the multiplied key */
	}
	qsort(k, n, 4, cmp32);
	for (i = 0; i < n; i++)
		if (!m || k[i] != k[m - 1u])
			k[m++] = k[i];
	*out_n = m;
	return k;
}

static int has(const uint32_t *k, uint32_t n, uint32_t v)
{
	uint32_t lo = 0, hi = n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (k[mid] < v)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < n && k[lo] == v;
}

/* ---- the filter ------------------------------------------------------- */

static void t_filter(void)
{
	static const uint32_t sizes[] = { 0, 1, 2, 3, 7, 80, 1000, 50000, 300000 };
	uint32_t seed = 0x1234567u, si, skew, r, w;

	for (si = 0; si < sizeof sizes / sizeof sizes[0]; si++)
		for (skew = 0; skew < 2u; skew++) {
			uint32_t n, *k = keys_make(sizes[si], (int)skew, &seed, &n);

			for (r = 8; r <= 16; r += 8) {
				uint64_t len;
				uint32_t st = 0, nonmem = 0, q;
				uint8_t *reg = kof_mflt_build(k, n, r, &len, &st);

				CK(reg != NULL && st == 0);
				if (!reg)
					continue;
				for (w = r; w >= 1u; w >>= 1) {
					struct kof_mflt *f = kof_mflt_open_mem(reg, len, w, 0, NULL, 0);
					uint32_t i, pass = 0, bad = 0;
					struct kof_mflt_stat ss;

					CK(f != NULL);
					if (!f)
						continue;
					kof_mflt_stat(f, &ss);
					CK(ss.w == w && ss.n_key == n);
					for (i = 0; i < n; i++)
						bad += 1u - ft(f, k[i]);
					CK(bad == 0);                       /* no false reject, ever */
					nonmem = 0;
					for (q = 0; q < 200000u; q++) {
						uint32_t v = rnd(&seed);

						if (has(k, n, v))
							continue;
						nonmem++;
						pass += ft(f, v);
					}
					if (n >= 1000u && w >= 2u) {
						double rate = (double)pass / nonmem, want = 1.0 / (double)(1u << w);

						CK(rate < want * 1.6 + 0.002 && rate > want * 0.5);
					}
					if (n == 0)
						CK(pass == 0);             /* an empty set passes nothing */
					kof_mflt_close(f);
				}
				if (r == 16u && n >= 1000u) {
					/* truncation is exact: 16 kept at 8 answers like 8 built at 8 */
					uint64_t len8;
					uint8_t *reg8 = kof_mflt_build(k, n, 8, &len8, &st);
					struct kof_mflt *a = kof_mflt_open_mem(reg, len, 8, 0, NULL, 0);
					struct kof_mflt *b = kof_mflt_open_mem(reg8, len8, 8, 0, NULL, 0);
					uint32_t diff = 0;

					CK(a && b);
					for (q = 0; a && b && q < 100000u; q++) {
						uint32_t v = rnd(&seed);

						diff += ft(a, v) != ft(b, v);
					}
					CK(diff == 0);
					kof_mflt_close(a);
					kof_mflt_close(b);
					free(reg8);
				}
				free(reg);
			}
			free(k);
		}
	/* Unsorted and repeated keys are refused. */
	{
		uint32_t bad[3] = { 5, 3, 9 }, rep[3] = { 5, 5, 9 };
		uint32_t st = 0;
		uint64_t len;

		CK(kof_mflt_build(bad, 3, 8, &len, &st) == NULL && (st & KOF_MFLT_B_BAD_ARG));
		CK(kof_mflt_build(rep, 3, 8, &len, &st) == NULL && (st & KOF_MFLT_B_BAD_ARG));
		CK(kof_mflt_build(rep, 0, 12, &len, &st) == NULL && (st & KOF_MFLT_B_BAD_ARG));
	}
	printf("  filter: no false reject at 9 sizes x 2 shapes x 2 stored widths x every kept width; rates at their width: ok\n");
}

/* More than one partition: the keys are cut by their top bits, and partitions can be left out. */
static void t_partitions(void)
{
	uint32_t seed = 0xabcdef1u, n, *k = keys_make(2500000u, 0, &seed, &n), i, q;
	uint64_t len;
	uint32_t st = 0;
	uint8_t *reg = kof_mflt_build(k, n, 8, &len, &st);
	struct kof_mflt_io io;
	struct kof_mflt_info info;
	struct kof_mflt *f, *half;
	uint32_t pass_in = 0, pass_out = 0, tot_in = 0, tot_out = 0, bad = 0;
	char why[160];
	struct kof_mflt_stat ss;

	CK(reg != NULL);
	if (!reg)
		return;
	memset(&io, 0, sizeof io);
	io.read = t_mem_read;           /* a read callback over memory, as the loader's is over a pack file */
	io.ctx = reg;
	io.len = len;
	CK(kof_mflt_probe(&io, &info, why, sizeof why));
	CK(info.n_part == 2u && info.part_bits == 1u && info.n_key == n && info.r == 8u);
	CK(kof_mflt_bytes(&info, 8, 0) > kof_mflt_bytes(&info, 4, 0) && kof_mflt_bytes(&info, 4, 0) > kof_mflt_bytes(&info, 1, 0));
	f = kof_mflt_open(&io, 8, 0, kof_crc32(reg, len), why, sizeof why);
	half = kof_mflt_open(&io, 8, 1, kof_crc32(reg, len), why, sizeof why);
	CK(f && half);
	if (f && half) {
		kof_mflt_stat(half, &ss);
		CK(ss.n_res == 1u && ss.n_part == 2u);
		for (i = 0; i < n; i += 7u)
			bad += 2u - ft(f, k[i]) - ft(half, k[i]);
		CK(bad == 0);
		for (q = 0; q < 400000u; q++) {
			uint32_t v = rnd(&seed);

			if (has(k, n, v))
				continue;
			if (v >> 31) {            /* partition 1: not resident, passes everything */
				tot_out++;
				pass_out += ft(half, v);
			} else {                  /* partition 0: resident, rejects */
				tot_in++;
				pass_in += ft(half, v);
			}
		}
		CK(pass_out == tot_out);
		CK(pass_in * 100u < tot_in);
	}
	kof_mflt_close(f);
	kof_mflt_close(half);
	free(reg);
	free(k);
	printf("  partitions: 2.5 million keys in 2 parts, a part left out passes everything, the other rejects: ok\n");
}

/* ---- hostile regions ---------------------------------------------------- */

static void t_hostile(void)
{
	uint32_t seed = 0x5eed5u, n, *k = keys_make(3000u, 0, &seed, &n), it, opened = 0, refused = 0;
	uint64_t len;
	uint32_t st = 0;
	uint8_t *reg = kof_mflt_build(k, n, 8, &len, &st), *bad;
	char why[160];

	CK(reg != NULL);
	if (!reg)
		return;
	bad = malloc((size_t)len);
	/* a flipped byte: the checksum says no */
	memcpy(bad, reg, (size_t)len);
	bad[len / 2u] ^= 0x10u;
	{
		struct kof_mflt_io io = { t_mem_read, bad, len };

		CK(kof_mflt_open(&io, 8, 0, kof_crc32(reg, len), why, sizeof why) == NULL);
	}
	/* a short read: the region says more than the file has */
	{
		struct kof_mflt_io io = { t_mem_read, reg, len + 64u };

		CK(kof_mflt_probe(&io, NULL, why, sizeof why) == 0);
	}
	/* bytes flipped anywhere with the checksum RECOMPUTED, so the validation is what stands */
	for (it = 0; it < 4000u; it++) {
		struct kof_mflt_io io = { t_mem_read, bad, len };
		uint64_t at = it & 1u ? rnd(&seed) % 160u : rnd(&seed) % len;
		struct kof_mflt *f;

		memcpy(bad, reg, (size_t)len);
		bad[at] ^= (uint8_t)(1u << (rnd(&seed) % 8u));
		if (it % 5u == 0)
			bad[at] = (uint8_t)rnd(&seed);
		f = kof_mflt_open(&io, 8, 0, kof_crc32(bad, len), why, sizeof why);
		if (f) {
			uint32_t i;

			opened++;
			for (i = 0; i < 300u; i++)
				(void)kof_mflt_test(f, rnd(&seed));   /* leaves its arrays or ASAN says so */
			kof_mflt_close(f);
		} else {
			refused++;
		}
	}
	CK(refused > 100u);
	free(bad);
	free(reg);
	free(k);
	printf("  hostile region: flipped byte, short read, %u fuzzed regions (%u opened and answered in bounds, %u refused): ok\n", 4000u, opened, refused);
}

/* ---- the size rule ------------------------------------------------------ */

static void t_rule(void)
{
	uint64_t room, prev = 0, MiB = 1ull << 20;

	/* no flat figure: only the room matters */
	for (room = 0; room <= (1024ull << 20); room += 7 * MiB) {
		uint64_t c = kof_mflt_ceiling(room, 0, 0, 0);

		CK(c <= room / KOF_MFLT_SHARE_DEN);
		CK(c >= prev);
		prev = c;
	}
	CK(kof_mflt_ceiling(0, 0, 0, 0) == 0);
	CK(kof_mflt_ceiling(512 * MiB, 0, 8, 12 * MiB) == (512 * MiB - 96 * MiB) / 4);
	CK(kof_mflt_ceiling(512 * MiB, 0, 16, 12 * MiB) < kof_mflt_ceiling(512 * MiB, 0, 4, 12 * MiB));
	CK(kof_mflt_ceiling(64 * MiB, 0, 8, 12 * MiB) == (64 * MiB - 32 * MiB) / 4);   /* a small ledger's reserve stops at half */
	/* the hard maximum: a fifth of the cap, whatever the room, however few scanners; a huge cap does not grow it past that */
	CK(kof_mflt_ceiling(512 * MiB, 512 * MiB, 1, 12 * MiB) == 512 * MiB / KOF_MFLT_CAP_DEN);
	CK(kof_mflt_ceiling(8192 * MiB, 8192 * MiB, 8, 12 * MiB) == 8192 * MiB / KOF_MFLT_CAP_DEN);
	CK(kof_mflt_ceiling(480 * MiB, 512 * MiB, 8, 12 * MiB) == (480 * MiB - 96 * MiB) / 4);   /* the reference case (96 MiB) is under it */
	/* the ladder, through the bank that owns it: as the grant falls the width falls, then the partitions */
	{
		uint32_t seed = 0x77u, n, *k = keys_make(2500000u, 0, &seed, &n), pw = 99, pr = 99;
		uint64_t len;
		uint32_t st = 0;
		uint8_t *reg = kof_mflt_build(k, n, 8, &len, &st);
		struct kof_mflt_io io = { t_mem_read, reg, len };
		uint64_t g;

		CK(reg != NULL);
		for (g = 8u * MiB; reg && g > 0; g /= 2u) {
			struct kof_fbank *b = kof_fbank_new(1);

			CK(b && kof_fbank_add_xf(b, &io, kof_crc32(reg, len), n));
			CK(kof_fbank_open_xf(b, g));
			if (b->nfx) {
				CK(b->w <= pw && (b->w < pw || b->res <= pr));
				CK(b->fx_bytes <= g || g < 4096u);          /* what it holds is what was granted */
				pw = b->w;
				pr = b->res;
			} else {
				CK(!b->xf_ok);                              /* none fits: the bank says it is not covered */
			}
			kof_fbank_free(b);
		}
		CK(pw <= 2u || pr < 2u);                            /* the ladder did reach the bottom rungs */
		free(reg);
		free(k);
	}
	printf("  size rule: ceiling <= room/%u, monotone, no flat figure; ladder falls with the grant: ok\n", KOF_MFLT_SHARE_DEN);
}

/* ---- the matcher with every kind of filter ------------------------------ */

struct ref_pair { uint32_t hash, bs; };

static int ref_cmp(const void *a, const void *b)
{
	const struct ref_pair *x = a, *y = b;

	if (x->hash != y->hash)
		return x->hash < y->hash ? -1 : 1;
	return x->bs < y->bs ? -1 : x->bs > y->bs;
}

/* The brute-force count of block b over the windows of one object: the old matcher in a few lines. */
struct ref {
	struct ref_pair *pair;
	uint32_t n_pair, nb, *seen, *stamp, *pstamp, gen;
	const struct kof_mutation_block *blk;
};

static void ref_init(struct ref *r, const struct kof_mutation_block *b, uint32_t nb, const uint32_t *pool)
{
	uint32_t i, j, n = 0;

	memset(r, 0, sizeof *r);
	for (i = 0; i < nb; i++)
		n += b[i].n_hash;
	r->pair = malloc((size_t)(n ? n : 1u) * sizeof *r->pair);
	for (i = 0; i < nb; i++)
		for (j = 0; j < b[i].n_hash; j++) {
			r->pair[r->n_pair].hash = pool[b[i].first_hash + j];
			r->pair[r->n_pair++].bs = (i << 8) | j;
		}
	qsort(r->pair, r->n_pair, sizeof *r->pair, ref_cmp);
	r->nb = nb; r->blk = b; r->gen = 1;
	r->seen = calloc(nb ? nb : 1u, 4);
	r->stamp = calloc(nb ? nb : 1u, 4);
	r->pstamp = calloc(n ? n : 1u, 4);
}

static void ref_free(struct ref *r)
{
	free(r->pair); free(r->seen); free(r->stamp); free(r->pstamp);
}

static void ref_unit(struct ref *r, uint32_t mask, uint32_t norm, uint32_t side, const uint8_t *p, uint64_t n)
{
	struct kgenome_mtn_win w;

	if (!r->n_pair || !kgenome_mtn_win_begin(&w, p, n, norm))
		return;
	do {
		uint32_t h = kgenome_mtn_win_value(&w), lo = 0, hi = r->n_pair;

		if (kgenome_mtn_win_flat(&w))
			continue;
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (r->pair[mid].hash < h)
				lo = mid + 1u;
			else
				hi = mid;
		}
		for (; lo < r->n_pair && r->pair[lo].hash == h; lo++) {
			uint32_t b = r->pair[lo].bs >> 8;
			const struct kof_mutation_block *k = &r->blk[b];

			if (r->pstamp[lo] == r->gen || k->norm != norm || k->side != side || !(k->scan_mask & mask))
				continue;
			r->pstamp[lo] = r->gen;
			if (r->stamp[b] != r->gen) {
				r->stamp[b] = r->gen;
				r->seen[b] = 0;
			}
			r->seen[b]++;
		}
	} while (kgenome_mtn_win_next(&w));
}

static uint32_t ref_count(const struct ref *r, uint32_t b)
{
	return r->stamp[b] == r->gen ? r->seen[b] : 0u;
}

struct db {
	struct kof_mutation_block *b;
	uint32_t *pool, nb, np;
};

static void db_make(struct db *d, uint32_t nb, const uint32_t *src, uint32_t ns, uint32_t *seed)
{
	uint32_t i, j;

	d->nb = nb;
	d->b = calloc(nb, sizeof *d->b);
	d->pool = malloc((size_t)nb * 32u * 4u + 4u);
	d->np = 0;
	for (i = 0; i < nb; i++) {
		uint32_t n = 16u + rnd(seed) % 17u;

		d->b[i].first_hash = d->np;
		d->b[i].n_hash = n;
		d->b[i].scan_mask = 1u << (rnd(seed) % 3u);
		d->b[i].norm = (uint8_t)(rnd(seed) % 3u);
		d->b[i].side = (uint8_t)(rnd(seed) % 2u);
		for (j = 0; j < n; j++)
			d->pool[d->np++] = rnd(seed) % 4u ? src[rnd(seed) % ns] : rnd(seed);
	}
}

static void db_free(struct db *d)
{
	free(d->b);
	free(d->pool);
}

/* A pack as the loader hands it over: a trailer in memory (kof_kix_make + open_mem), with or without a pre-built filter. */
struct pack {
	uint8_t *reg;
	uint64_t reg_len;
	struct kof_mutation_src src;
};

static int pack_make(struct pack *p, const struct db *d, uint32_t base, int prebuilt, uint32_t r)
{
	struct kof_kix_build_in bi;
	struct kof_kix_build_res br;
	uint64_t len;
	uint8_t *img;
	struct kof_kix *k;
	char why[160];

	memset(p, 0, sizeof *p);
	memset(&bi, 0, sizeof bi);
	bi.blk = d->b; bi.n_blk = d->nb; bi.pool = d->pool; bi.n_pool = d->np;
	img = kof_kix_make(&bi, 0, 0, 0, &len, &br);
	if (!img)
		return 0;
	k = kof_kix_open_mem(img, len, d->b, d->nb, d->pool, d->np, why, sizeof why);
	if (!k)
		return 0;
	p->src.kix = k;
	p->src.base = base;
	p->src.n_blocks = d->nb;
	if (prebuilt) {
		uint32_t i, m = 0, st, *keys = malloc((size_t)d->np * 4u);

		for (i = 0; i < d->np; i++)
			keys[i] = d->pool[i] * KOF_KIX_MULT;
		qsort(keys, d->np, 4, cmp32);
		for (i = 0; i < d->np; i++)
			if (!m || keys[i] != keys[m - 1u])
				keys[m++] = keys[i];
		p->reg = kof_mflt_build(keys, m, r, &p->reg_len, &st);
		free(keys);
		if (!p->reg)
			return 0;
		p->src.xf.read = t_mem_read;
		p->src.xf.ctx = p->reg;
		p->src.xf.len = p->reg_len;
		p->src.xf_crc = kof_crc32(p->reg, p->reg_len);
	}
	return 1;
}

static void fill(uint8_t *p, uint64_t n, uint32_t *seed)
{
	uint64_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)rnd(seed);
}

/* One scan, counts compared against ref for every block of every db, for each set. */
static void compare(struct kof_mutation_set *set, const struct db *d, uint32_t n_db, const uint32_t *base,
		    const uint8_t *obj, uint64_t N, const char *what, uint32_t *seed)
{
	struct kof_mutation_ctx c, c2;
	struct ref r[2];
	uint32_t i, b, bad = 0, k;
	uint64_t credits = 0;

	CK(set != NULL);
	if (!set)
		return;
	for (i = 0; i < n_db; i++)
		ref_init(&r[i], d[i].b, d[i].nb, d[i].pool);
	CK(kof_mutation_ctx_init(&c, set) && kof_mutation_ctx_init(&c2, set));
	c2.chunk_max = 4096u;
	kof_mutation_begin(&c);
	kof_mutation_begin(&c2);
	for (k = 0; k < 18u; k++) {
		/* every (region, normalizer, side) once, over a piece of the object each */
		uint32_t mask = 1u << (k % 3u), norm = (k / 3u) % 3u, side = (k / 9u) % 2u;
		const uint8_t *p = obj + rnd(seed) % (N / 2u);
		uint64_t n = 2000u + rnd(seed) % (N / 2u - 2000u);

		for (i = 0; i < n_db; i++)
			ref_unit(&r[i], mask, norm, side, p, n);
		kof_mutation_unit(&c, mask, norm, side, p, n);
		kof_mutation_unit(&c2, mask, norm, side, p, n);
	}
	for (i = 0; i < n_db; i++)
		for (b = 0; b < d[i].nb; b++) {
			uint32_t x = ref_count(&r[i], b);

			credits += x;
			if (kof_mutation_matched(&c, base[i] + b) != x || kof_mutation_matched(&c2, base[i] + b) != x)
				bad++;
		}
	if (bad)
		printf("  %s: %u blocks differ\n", what, bad);
	CK(bad == 0);
	if (credits <= 200u) printf("  %s: only %llu credits\n", what, (unsigned long long)credits);
	CK(credits > 200u);                         /* the comparison saw real credit */
	for (i = 0; i < n_db; i++)
		ref_free(&r[i]);
	kof_mutation_ctx_done(&c);
	kof_mutation_ctx_done(&c2);
}

static void t_matcher(void)
{
	enum { N = 40000 };
	static uint8_t obj[N];
	static uint32_t vals[N];
	uint32_t seed = 0xC0FFEEu, ns = 0, i, g, r, st;
	struct db d[2];
	struct pack pk[2];
	struct kof_mutation_build_req rq;
	struct kof_mutation_build_res res;
	struct kof_mutation_set *set;
	uint32_t base[2];

	fill(obj, N, &seed);
	{
		struct kgenome_mtn_win w;

		if (kgenome_mtn_win_begin(&w, obj, N, 0))
			do {
				if (ns < N && !kgenome_mtn_win_flat(&w))
					vals[ns++] = kgenome_mtn_win_value(&w);
			} while (kgenome_mtn_win_next(&w));
	}
	db_make(&d[0], 400, vals, ns, &seed);
	db_make(&d[1], 250, vals, ns, &seed);
	base[0] = 0;
	base[1] = d[0].nb;

	/* One pack, pre-built filter, at every rung the ledger can leave it on. */
	for (r = 8; r <= 16; r += 8) {
		static const uint32_t rung[] = { 16, 8, 4, 2, 1, 0 };

		for (g = 0; g < 6u; g++) {
			uint32_t w = rung[g];
			struct kof_mflt_info info;
			struct kof_kix_info ki;
			uint64_t grant;
			char what[64];

			if (w > r)
				continue;
			CK(pack_make(&pk[0], &d[0], 0, 1, r));
			kof_kix_info(pk[0].src.kix, &ki);
			CK(kof_mflt_probe(&pk[0].src.xf, &info, NULL, 0));
			grant = w ? kof_mflt_bytes(&info, w, 0) : 0u;
			memset(&rq, 0, sizeof rq);
			rq.src = &pk[0].src; rq.n_src = 1; rq.res = &res;
			rq.max_bytes = ki.resident + grant;       /* the allowance leaves exactly this for the filter */
			set = kof_mutation_build_req(&rq);
			CK(set != NULL);
			if (set) {
				snprintf(what, sizeof what, "fuse r%u kept at %u", r, w);
				if (w) {
					CK(res.flt_w == w && (res.flt_kind & KOF_MTN_FLT_FUSE));
					CK(!!(res.status & KOF_MTN_B_FILTER_DEGRADED) == (w < KOF_MFLT_W_FLOOR));
					CK(!(res.status & KOF_MTN_B_NO_FILTER));
				} else {
					CK((res.status & KOF_MTN_B_NO_FILTER) && (res.status & KOF_MTN_B_FILTER_DEGRADED));
				}
				compare(set, &d[0], 1, base, obj, N, what, &seed);
				kof_mutation_set_free(set);
			}
			free(pk[0].reg);
		}
	}
	/* The control: a bloom filter (no pre-built one), alone. */
	CK(pack_make(&pk[0], &d[0], 0, 0, 0));
	memset(&rq, 0, sizeof rq);
	rq.src = &pk[0].src; rq.n_src = 1; rq.res = &res;
	set = kof_mutation_build_req(&rq);
	CK(set && (res.flt_kind & KOF_MTN_FLT_BLOOM) && !(res.flt_kind & KOF_MTN_FLT_FUSE));
	compare(set, &d[0], 1, base, obj, N, "bloom", &seed);
	kof_mutation_set_free(set);
	/* Two packs: bloom and pre-built, then both pre-built, then pre-built and one built in memory. */
	for (i = 0; i < 3u; i++) {
		struct kof_mutation_src s2[2];
		struct pack a, b;

		CK(pack_make(&a, &d[0], 0, i != 0u, 8));
		CK(pack_make(&b, &d[1], d[0].nb, i == 1u, 16));
		s2[0] = a.src;
		s2[1] = b.src;
		if (i == 2u) {
			kof_kix_close(s2[1].kix);                 /* the second as arrays, built in memory */
			memset(&s2[1], 0, sizeof s2[1]);
			s2[1].blocks = d[1].b; s2[1].n_blocks = d[1].nb;
			s2[1].pool = d[1].pool; s2[1].n_pool = d[1].np;
			s2[1].base = d[0].nb;
		}
		memset(&rq, 0, sizeof rq);
		rq.src = s2; rq.n_src = 2; rq.res = &res;
		set = kof_mutation_build_req(&rq);
		CK(set != NULL);
		st = res.status;
		(void)st;
		compare(set, d, 2, base, obj, N, i == 0 ? "bloom + pre-built" : i == 1 ? "two pre-built" : "pre-built + in memory", &seed);
		kof_mutation_set_free(set);
		free(a.reg);
		free(b.reg);
	}
	db_free(&d[0]);
	db_free(&d[1]);
	printf("  matcher: the same credit under a pre-built filter at every rung, none, a bloom filter and mixed packs: ok\n");
}

int main(void)
{
	t_filter();
	t_partitions();
	t_hostile();
	t_rule();
	t_matcher();
	if (fails) {
		printf("mutation_flt: %d failure(s)\n", fails);
		return 1;
	}
	printf("mutation_flt: ok\n");
	return 0;
}
