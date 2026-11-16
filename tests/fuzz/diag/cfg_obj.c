/*
 * diag/cfg_obj - the block layer (celllysis/cfg.h, kgenome_cfg_obj_build): the blocks of an object by recursive descent, over code the bytes spell.
 *
 * The first byte picks the architecture (x86-64, i386, ARM, AArch64, MIPS LE, MIPS BE); bytes 1..4 name up to four seeds (an offset each, the fifth
 * seed is 0); the whole input is one extent. No `held`: every instruction is decoded by the descent.
 *
 * Held:
 *   SHAPE        blocks in address order, inside the extent, not overlapping; their instruction counts add up to n_insn; n_fresh is n_insn (no trace)
 *   EDGES        every successor is a block or NONE; a fall-through successor starts where its block ends; a COND/JUMP block's taken successor exists
 *                only when the term allows it; a call names the block that holds it and lies inside it
 *   ENTRIES      one per distinct seed, address order; a seed with no block says why
 *   BUDGET       half the instructions as the work bound: OVER_BUDGET with no more instructions than the bound, or OK when the bound was enough
 *   DETERMINISM  a second build of the same bytes gives the same blocks
 */
#include "diag_seed.h"

#include <celllysis/cfg.h>

static int seg_at(void *priv, uint64_t off, struct kgenome_image_seg *out)
{
	(void)off;
	out->lo = 0;
	out->hi = *(const uint64_t *)priv;
	out->delta = 0x400000;
	return 1;
}

static uint64_t off_of_va(void *priv, uint64_t va)
{
	return va >= 0x400000u && va - 0x400000u < *(const uint64_t *)priv ? va - 0x400000u : KGENOME_BROKEN;
}

static void seeds(struct fz_corpus *c)
{
	static const uint8_t x64[] = { 0, 9, 0, 0, 0, 0x90, 0x0f, 0x85, 0x05, 0, 0, 0, 0x90, 0xe8, 0, 0, 0, 0, 0xe9, 0x01, 0, 0, 0, 0x90, 0xc3, 0xcc, 0xff, 0xe0 };
	static const uint8_t mips[] = { 4, 0, 0, 0, 0, 0x02, 0, 0x20, 0x14, 0, 0, 0, 0, 0x08, 0, 0xe0, 0x03, 0, 0, 0, 0 };
	static const uint8_t arm[] = { 2, 4, 0, 0, 0, 0x0f, 0xe0, 0xa0, 0xe1, 0x03, 0xf0, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1 };

	fz_corpus_add(c, "cfg_obj_x64", x64, sizeof x64);
	fz_corpus_add(c, "cfg_obj_mips", mips, sizeof mips);
	fz_corpus_add(c, "cfg_obj_arm", arm, sizeof arm);
}

static uint64_t digest(const struct kgenome_cfg_obj *g)
{
	uint64_t h = 1469598103934665603ull;
	uint32_t i;

	for (i = 0; i < g->n_b; i++)
		h = (h ^ (g->b[i].off * 31u + g->b[i].len + ((uint64_t)g->b[i].term << 40) + ((uint64_t)g->b[i].succ[0] << 20) + g->b[i].succ[1])) * 1099511628211ull;
	return h ^ g->n_insn ^ ((uint64_t)g->n_call << 32) ^ ((uint64_t)g->n_loose << 48);
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	const struct isa { unsigned arch; int be; } isa[6] = { { KGENOME_ARCH_X86_64, 0 }, { KGENOME_ARCH_X86, 0 }, { KGENOME_ARCH_ARM, 0 },
		{ KGENOME_ARCH_ARM64, 0 }, { KGENOME_ARCH_MIPS, 0 }, { KGENOME_ARCH_MIPS, 1 } };
	struct kgenome_cell_space sp;
	struct kgenome_cfg_obj_ext ext;
	struct kgenome_cfg_obj_seed sd[5];
	struct kgenome_cfg_obj_req rq;
	struct kgenome_cfg_obj g[2];
	uint64_t size;
	uint32_t i, sum = 0, pass;
	enum kgenome_status st;

	if (n < 8)
		return 0;
	size = n;
	memset(&sp, 0, sizeof sp);
	sp.base = in;
	sp.size = n;
	sp.arch = isa[in[0] % 6u].arch;
	sp.be = isa[in[0] % 6u].be;
	sp.priv = &size;
	sp.seg_at = seg_at;
	sp.off_of_va = off_of_va;
	sp.raw = 1;
	ext.off = 0;
	ext.len = n;
	for (i = 0; i < 4; i++) {
		sd[i].off = in[1u + i] % n;
		sd[i].src = 1u << i;
	}
	sd[4].off = 0;
	sd[4].src = 0x10u;
	memset(&rq, 0, sizeof rq);
	rq.sp = &sp;
	rq.ext = &ext;
	rq.n_ext = 1;
	rq.seed = sd;
	rq.n_seed = 5;
	for (pass = 0; pass < 2; pass++) {
		st = kgenome_cfg_obj_build(&rq, &g[pass]);
		FZ_CHECK(c, st == KGENOME_OK || st == KGENOME_NOMEM, "build: a status the call cannot give here");
	}
	FZ_CHECK(c, digest(&g[0]) == digest(&g[1]), "two builds of the same bytes differ");
	for (i = 0; i < g[0].n_b; i++) {
		const struct kgenome_cfg_obj_block *b = &g[0].b[i];

		sum += b->n_insn;
		FZ_CHECK(c, b->len && b->n_insn && b->off + b->len <= n, "a block outside the extent or empty");
		FZ_CHECK(c, !i || g[0].b[i - 1u].off + g[0].b[i - 1u].len <= b->off, "blocks overlap or are out of order");
		FZ_CHECK(c, (b->succ[0] == KGENOME_CFG_NONE || b->succ[0] < g[0].n_b) && (b->succ[1] == KGENOME_CFG_NONE || b->succ[1] < g[0].n_b), "a successor is no block");
		FZ_CHECK(c, b->succ[1] == KGENOME_CFG_NONE || g[0].b[b->succ[1]].off == b->off + b->len, "a fall-through successor is not the next byte");
		FZ_CHECK(c, b->succ[0] == KGENOME_CFG_NONE || b->term == KGENOME_CFG_OBJ_T_COND || b->term == KGENOME_CFG_OBJ_T_JUMP, "a taken edge from a block that does not branch");
		FZ_CHECK(c, b->call_first + b->n_call <= g[0].n_call, "a block's calls run past the list");
		FZ_CHECK(c, b->term != KGENOME_CFG_OBJ_T_STOP || b->stop != KGENOME_CFG_OBJ_W_NONE, "a stop without its reason");
		FZ_CHECK(c, kgenome_cfg_obj_block_at(&g[0], b->off) == i && kgenome_cfg_obj_block_at(&g[0], b->off + b->len - 1u) == i, "the lookup does not find the block");
	}
	FZ_CHECK(c, sum == g[0].n_insn && g[0].n_fresh == g[0].n_insn, "the blocks do not hold the instructions read");
	for (i = 0; i < g[0].n_call; i++)
		FZ_CHECK(c, g[0].call[i].blk < g[0].n_b && g[0].call[i].at >= g[0].b[g[0].call[i].blk].off &&
			    g[0].call[i].at < g[0].b[g[0].call[i].blk].off + g[0].b[g[0].call[i].blk].len, "a call outside its block");
	for (i = 0; i < g[0].n_e; i++) {
		FZ_CHECK(c, !i || g[0].e[i - 1u].off < g[0].e[i].off, "entries not distinct and in order");
		FZ_CHECK(c, (g[0].e[i].blk != KGENOME_CFG_NONE) == (g[0].e[i].why == KGENOME_CFG_OBJ_W_NONE), "an entry with no block and no reason");
	}
	FZ_CHECK(c, g[0].status != KGENOME_OK || g[0].n_e >= 1u, "no entry for the seeds");
	fz_digest(c, digest(&g[0]));
	if (g[0].status == KGENOME_OK && g[0].n_insn >= 2u) {
		struct kgenome_cfg_obj h;

		rq.max_insn = g[0].n_insn / 2u;
		st = kgenome_cfg_obj_build(&rq, &h);
		FZ_CHECK(c, (st == KGENOME_OVER_BUDGET || st == KGENOME_OK || st == KGENOME_NOMEM) && h.n_insn <= rq.max_insn, "the work bound did not hold");
		kgenome_cfg_obj_free(&h, NULL);
	}
	kgenome_cfg_obj_free(&g[0], NULL);
	kgenome_cfg_obj_free(&g[1], NULL);
	return 0;
}

FZ_ADAPTER(cfg_obj, .name = "kgenome/diag_cfg_obj",
	   .covers = "kgenome_cfg_obj_build kgenome_cfg_obj_free kgenome_cfg_obj_block_at",
	   .flags = 0, .backstop_s = 300, .steps_base = 100000u, .steps_per_byte = 64,
	   .shape = FZ_REQ, .seeds = seeds, .run = run);
