/*
 * fnprint_wdb_equal - the window stream credits what the shipped matcher credits.
 *
 * The matcher (kofmutation.c) is the reference: a sorted pair array, a bit filter, a stamp per pair.
 * The stream's database is another structure for the same question (sorted keys, a bucket index, a bit
 * per slot), so the only thing that makes it admissible is that it gives the same count for every block
 * on every object, and that no choice of filter or index width changes the count. Random databases with
 * the awkward shapes - shared hashes between blocks, a block that lists one hash twice, blocks on both
 * sides, a hot hash in many blocks - and random objects built from windows of the blocks' own sources.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/detectors/mutations/kofmutation.h"
#include <celllysis/fnprint.h>

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static uint64_t rs = 88172645463325252ull;
static uint32_t rnd(void)
{
	rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
	return (uint32_t)(rs >> 11);
}

#define NB 300u
#define OBJ 60000u

static void one(uint32_t trial, uint32_t fbits, uint32_t bbits)
{
	static uint8_t src[OBJ], obj[OBJ];
	static struct kof_mutation_block mb[NB];
	static struct kgenome_fnprint_wblock wb[NB];
	static uint32_t pool[NB * 32u];
	struct kof_mutation_set *set;
	struct kof_mutation_ctx kc;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_req rq;
	struct kgenome_fnprint_wpass_stat st;
	struct kof_range ext[2];
	uint32_t i, j, n = 0, bad = 0, hot = 0;

	for (i = 0; i < OBJ; i++)
		src[i] = (uint8_t)rnd();
	memcpy(obj, src, OBJ);
	for (i = 0; i < OBJ / 8u; i++)                         /* the object is the source, damaged */
		obj[rnd() % OBJ] = (uint8_t)rnd();
	/* blocks: 32 window values of the source taken at random places, so most of them are in the object */
	for (i = 0; i < NB; i++) {
		struct kgenome_mtn_win w;
		uint32_t at = rnd() % (OBJ - 2000u), k = 0;

		mb[i].first_hash = n; mb[i].n_hash = 32; mb[i].scan_mask = 1u; mb[i].norm = 0;
		mb[i].side = (uint8_t)(i % 7u == 0 ? KGENOME_MUTATION_SIDE_LIB : KGENOME_MUTATION_SIDE_USER);
		if (kgenome_mtn_win_begin(&w, src + at, 2000, 0))
			do {
				if (!kgenome_mtn_win_flat(&w) && (rnd() % 60u) == 0 && k < 32u)
					pool[n + k++] = kgenome_mtn_win_value(&w);
			} while (kgenome_mtn_win_next(&w) && k < 32u);
		while (k < 32u)
			pool[n + k++] = rnd();                       /* filled with values in no object */
		if (i % 11u == 0)
			pool[n + 31u] = pool[n];                      /* a hash listed twice */
		if (i % 13u == 0 && i)
			memcpy(pool + n, pool + mb[i - 1].first_hash, 16u * sizeof *pool);   /* shares half with the previous */
		if (i % 17u == 0)
			pool[n + 5u] = hot ? hot : (hot = pool[n + 5u]);     /* one hot hash in many blocks */
		n += 32;
	}
	set = kof_mutation_build(mb, NB, pool, n);
	CK(set != NULL);
	if (!set)
		return;
	CK(kof_mutation_ctx_init(&kc, set));
	for (i = 0; i < NB; i++) {
		wb[i].first = mb[i].first_hash; wb[i].n = 32; wb[i].side = mb[i].side; wb[i].tag = i % 5u;
	}
	memset(&o, 0, sizeof o);
	o.n_tag = 5; o.filter_bits_per_hash = fbits; o.bucket_bits = bbits;
	CK(kgenome_fnprint_wdb_build(&d, wb, NB, pool, n, &o));
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));

	/* two ranges, as the engine feeds two units, on each side */
	ext[0].off = 0; ext[0].len = OBJ / 2u;
	ext[1].off = OBJ / 2u; ext[1].len = OBJ / 2u;
	kof_mutation_begin(&kc);
	kof_mutation_any_region(&kc, 1);
	kof_mutation_unit(&kc, 1u, KGENOME_MUTATION_RAW, KGENOME_MUTATION_SIDE_USER, obj, ext[0].len);
	kof_mutation_unit(&kc, 1u, KGENOME_MUTATION_RAW, KGENOME_MUTATION_SIDE_USER, obj + ext[1].off, ext[1].len);
	kgenome_fnprint_wctx_begin(&c);
	memset(&rq, 0, sizeof rq);
	rq.p = obj; rq.n = OBJ; rq.ext = ext; rq.n_ext = 2; rq.c = &c; rq.stat = &st;
	kgenome_fnprint_wpass(&rq);
	for (i = 0; i < NB; i++) {
		uint32_t a = kof_mutation_matched(&kc, i), b = kgenome_fnprint_wctx_count(&c, i);

		if (a != b)
			bad++;
	}
	CK(bad == 0);
	/* the LIB side from the same bytes: a second object part fed as library on both */
	kof_mutation_begin(&kc);
	kof_mutation_any_region(&kc, 1);
	kof_mutation_unit(&kc, 1u, KGENOME_MUTATION_RAW, KGENOME_MUTATION_SIDE_LIB, obj, OBJ);
	kgenome_fnprint_wctx_begin(&c);
	for (j = 0, bad = 0; j < 1; j++) {
		struct kgenome_mtn_win w;

		if (kgenome_mtn_win_begin(&w, obj, OBJ, 0))
			do {
				if (!kgenome_mtn_win_flat(&w))
					kgenome_fnprint_wctx_credit(&c, kgenome_mtn_win_value(&w), KGENOME_MUTATION_SIDE_LIB);
			} while (kgenome_mtn_win_next(&w));
	}
	for (i = 0; i < NB; i++)
		if (kof_mutation_matched(&kc, i) != kgenome_fnprint_wctx_count(&c, i))
			bad++;
	CK(bad == 0);
	(void)trial;
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	kof_mutation_ctx_done(&kc);
	kof_mutation_set_free(set);
}

int main(void)
{
	uint32_t t;

	for (t = 0; t < 6; t++)
		one(t, 32u, 0);                    /* the default filter, bucket index from the count */
	one(10, 0xFFFFFFFFu, 0);                   /* no filter */
	one(11, 4u, 8);                            /* a small filter (many false passes) and a tiny index (long buckets) */
	one(12, 64u, 20);
	printf("fnprint_wdb_equal: %s\n", fails ? "FAIL" : "ok");
	return fails != 0;
}
