/*
 * kix_fix.h - the material of the block-index tests: random objects, blocks cut from their windows, and a pack that declares them (kix_load, api_kix_hostile).
 * Moved out of kix_load.c so that a second test builds the SAME packs; nothing changed.
 */

#ifndef KOFENG_TESTS_KIX_FIX_H
#define KOFENG_TESTS_KIX_FIX_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../libkofeng/kofcore/kofplatform.h"
#include "../../libkofeng/databases/dbloader.h"
#include "../../libkofeng/databases/pack/dbcore.h"
#include "../../libkofeng/databases/dbpacker.h"
#include "../../libkofeng/detectors/mutations/kofmutation.h"

static __attribute__((unused)) uint32_t rs = 0xfeed1234u;

static __attribute__((unused)) uint32_t rnd(void)
{
	rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5;
	return rs;
}

/* ---- material ------------------------------------------------------------------------- */

struct mat {
	struct kof_mutation_block *b;
	uint32_t *pool;
	uint32_t nb, np;
	uint8_t *obj;
	uint64_t n;
};

static __attribute__((unused)) void mat_free(struct mat *m)
{
	free(m->b); free(m->pool); free(m->obj);
	memset(m, 0, sizeof *m);
}

static __attribute__((unused)) uint32_t values(const uint8_t *p, uint64_t n, uint32_t *out, uint32_t max)
{
	struct kgenome_mtn_win w;
	uint32_t k = 0;

	if (!kgenome_mtn_win_begin(&w, p, n))
		return 0;
	do {
		if (k < max && !kgenome_mtn_win_flat(&w))
			out[k++] = kgenome_mtn_win_value(&w);
	} while (kgenome_mtn_win_next(&w));
	return k;
}

/* `nb` blocks of 32 hashes, a third of them cut from the windows of a random object (so that the object
 * credits them), the rest random; region 1 or 2, two sides, two normalizers. */
static __attribute__((unused)) void mat_make(struct mat *m, uint32_t nb, uint64_t n)
{
	uint32_t *src = malloc((size_t)n * 4u), ns, i, j;

	m->n = n;
	m->obj = malloc((size_t)n);
	for (i = 0; i < n; i++)
		m->obj[i] = (uint8_t)rnd();
	ns = values(m->obj, n, src, (uint32_t)n);
	m->nb = nb;
	m->b = calloc(nb ? nb : 1u, sizeof *m->b);
	m->pool = malloc((size_t)(nb ? nb : 1u) * 32u * 4u);
	m->np = 0;
	for (i = 0; i < nb; i++) {
		m->b[i].first_hash = m->np;
		m->b[i].n_hash = 32;
		m->b[i].scan_mask = 1u << (i % 2u);
		m->b[i].norm = 0;
		m->b[i].side = (uint8_t)((i / 2u) % 2u);
		for (j = 0; j < 32u; j++)
			m->pool[m->np++] = i % 3u == 0 ? src[rnd() % ns] : rnd();
	}
	free(src);
}

/* ---- packs --------------------------------------------------------------------------------- */

/* One module that declares the blocks, and a second with none (a pack with blocks is rarely only blocks). */
static __attribute__((unused)) uint8_t *build_pack(const struct mat *m, uint32_t first, uint32_t count, size_t *len)
{
	static const uint8_t code[] = { 0xc3 };
	struct kof_pw_mod mod[2];
	struct kof_mutation_block *b = calloc(count ? count : 1u, sizeof *b);
	uint32_t i, p0 = m->b[first].first_hash, np = 0;
	uint8_t *img;

	for (i = 0; i < count; i++) {
		b[i] = m->b[first + i];
		b[i].first_hash -= p0;          /* a module's block records index its own pool from zero */
		np += b[i].n_hash;
	}
	memset(mod, 0, sizeof mod);
	mod[0].code = code; mod[0].code_len = 1; mod[0].n_target = 1; mod[0].target[0] = KOF_FMT_UNKNOWN;
	mod[0].scan_mask = 1u;
	mod[0].blk = b; mod[0].n_blk = count; mod[0].pool = m->pool + p0; mod[0].n_pool = np;
	mod[1].code = code; mod[1].code_len = 1; mod[1].n_target = 1; mod[1].target[0] = KOF_FMT_UNKNOWN;
	mod[1].scan_mask = 1u;
	img = kof_pack_build(KOF_PACK_DETECT, mod, 2, len);
	free(b);
	return img;
}


/* The counts of every block after an object, by the engine's set, as an array. */
static __attribute__((unused)) uint32_t *counts_of(const struct kof_mutation_set *set, uint32_t nb, const uint8_t *obj, uint64_t n,
			   struct kof_mutation_stat *st, uint32_t chunk)
{
	struct kof_mutation_ctx c;
	uint32_t *out = calloc(nb ? nb : 1u, 4), b;
	uint64_t off;

	if (!out || !kof_mutation_ctx_init(&c, set))
		return out;
	c.chunk_max = chunk;
	kof_mutation_begin(&c);
	for (off = 0; off < n; off += 8192u) {
		kof_mutation_unit(&c, 1u, 0, obj + off, n - off < 8192u + 8u ? n - off : 8192u + 8u);
		kof_mutation_unit(&c, 2u, 1, obj + off, n - off < 8192u + 8u ? n - off : 8192u + 8u);
	}
	for (b = 0; b < nb; b++)
		out[b] = kof_mutation_matched(&c, b);
	if (st)
		kof_mutation_stat(&c, st);
	kof_mutation_ctx_done(&c);
	return out;
}

#endif /* KOFENG_TESTS_KIX_FIX_H */
