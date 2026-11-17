/*
 * diag/cfg - the control-flow graph of one function and the signatures over it (celllysis/cfg.h), over code the bytes spell.
 *
 * The first byte picks the architecture (x86-64, i386, ARM, AArch64, MIPS LE, MIPS BE); the rest is code, decoded
 * instruction by instruction with the lib's own decoder (an undecodable byte is skipped), the extent is the whole input.
 *
 * Held:
 *   GRAPH     the blocks tile the instructions (first = the sum of the n_insn before it, n_insn > 0, the sum is the count), every
 *             successor is a block or NONE, block 0 is reachable, out_deg counts the successors, reachable counts agree
 *   DETERMINISM  the graph and the signatures of a second build equal the first (the digest also takes the canonical hash)
 *   SIGN      a graph with a reachable block has a sketch of 1..32 ascending distinct keys; pct of a sketch with itself is 100; both
 *             policies and the callees' sketch (identities made from the instruction index, a third of them unresolved)
 *   ANCHOR    the anchor passes at exactly the number of reachable blocks and fails one above it
 *   VIEW      one entry per reachable block, successors inside the table, the canonical hash carried
 *   GRAPH     the view as a graph to look at (kgenome_cfg_gv_make, and the generic type: kgenome_gv_alloc, kgenome_gv_loops, kgenome_gv_box_line, kgenome_gv_free): a box
 *             row is NUL-ended, a loop link is a retreating edge, the head of a loop link is flagged, a graph of random edges (cycles, self loops, nodes nothing reaches)
 *             marked the same way twice
 */
#include "diag_seed.h"

#include <celllysis/cfg.h>

static uint64_t ids(void *u, uint32_t insn, const struct kgenome_cell_insn *in, uint8_t *kind)
{
	(void)u; (void)in; (void)kind;
	return insn % 3u ? (uint64_t)insn * 0x9e3779b97f4a7c15ull : 0u;
}

/* A graph the bytes spell: nodes, edges sorted by source, marked for loops; the rows of every box asked for. */
static void gview(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	const uint32_t nn = 1u + in[0] % 24u, ne = n > 48u ? 48u : (uint32_t)n;
	struct kgenome_gv gv;
	uint32_t i, k, heads = 0;
	uint64_t d1 = 0, d2 = 0;
	enum kgenome_status st1, st2;
	char buf[64];

	if (kgenome_gv_alloc(&gv, &(const struct kgenome_gv_size){ .n_node = nn, .n_edge = ne, .n_xline = in[3] % 5u, .n_note = in[3] % 5u, .n_aside = in[4] % 3u },
			     NULL, NULL) != KGENOME_OK)
		return;
	gv.id_prefix = 'N';
	for (i = 0; i < nn; i++) {
		gv.node[i].off = (uint64_t)in[i % n] << 8;
		gv.node[i].xtotal = in[(i + 2u) % n] % 7u;
		snprintf(gv.node[i].line[0], KGENOME_GV_LINE, "N%u", (unsigned)i);
		snprintf(gv.node[i].line[1], KGENOME_GV_LINE, "n=%u", (unsigned)in[(i + 1u) % n]);
	}
	for (i = 0; i < ne; i++) {
		gv.edge[i].from = i * nn / (ne ? ne : 1u);            /* non-decreasing: a node's edges are together */
		gv.edge[i].to = in[(i * 3u + 5u) % n] % nn;
		gv.edge[i].cond = (uint8_t)(in[i % n] % 3u);
	}
	for (i = 0; i < gv.n_xline; i++) {
		gv.xline[i].node = i % nn;
		snprintf(gv.xline[i].text, KGENOME_GV_LINE, "call %u", (unsigned)i);
	}
	st1 = kgenome_gv_loops(&gv, NULL, NULL);
	for (i = 0; i < ne; i++) {
		FZ_CHECK(c, gv.edge[i].loop <= KGENOME_GV_LOOP_RETREAT, "a loop value out of range");
		d1 = d1 * 31u + gv.edge[i].loop;
		if (gv.edge[i].loop == KGENOME_GV_LOOP_LINK) {
			FZ_CHECK(c, gv.node[gv.edge[i].to].flags & KGENOME_GV_NF_LOOP_HEAD, "the target of a loop link is not flagged as a head");
			heads++;
		}
	}
	st2 = kgenome_gv_loops(&gv, NULL, NULL);                    /* the same marks again: the result does not depend on what was there */
	for (i = 0; i < ne; i++)
		d2 = d2 * 31u + gv.edge[i].loop;
	/* A-D7: the marks are a function of the graph when both calls COMPUTED them. A call the harness's allocator refused (NOMEM) marks nothing and says so: the edges keep what they had (none), so a
	 * refused first call and a granted second one differ - the status is the answer, and the fuzz seed that hit it (3) was this, not a loop mark that moves. */
	if (st1 != KGENOME_NOMEM && st2 != KGENOME_NOMEM)
		FZ_CHECK(c, d1 == d2 && st1 == st2, "marking the loops twice gives different marks");
	for (i = 0; i < nn; i++)
		for (k = 0; k < 2u + KGENOME_GV_BOX_X + 2u; k++) {
			const char *t = kgenome_gv_box_line(&gv, i, k, buf, sizeof buf);

			if (!t)
				break;
			FZ_CHECK(c, strlen(t) < KGENOME_GV_LINE, "a box row is too long");
		}
	fz_digest(c, d1 ^ ((uint64_t)heads << 40));
	kgenome_gv_free(&gv, NULL);
}

static void seeds(struct fz_corpus *c)
{
	static const uint8_t x64[] = { 0, 0x90, 0x0f, 0x85, 0x05, 0, 0, 0, 0x90, 0xe8, 0, 0, 0, 0, 0xe9, 0x01, 0, 0, 0, 0x90, 0xc3, 0xcc, 0xff, 0xe0 };
	static const uint8_t a64[] = { 3, 0x1f, 0x20, 0x03, 0xd5, 0x41, 0x00, 0x00, 0x54, 0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6 };
	static const uint8_t mips[] = { 4, 0, 0, 0, 0, 0x02, 0, 0x20, 0x14, 0, 0, 0, 0, 0x08, 0, 0xe0, 0x03, 0, 0, 0, 0 };
	static const uint8_t arm[] = { 2, 0x00, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0x01, 0x00, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1 };

	fz_corpus_add(c, "cfg_x64", x64, sizeof x64);
	fz_corpus_add(c, "cfg_a64", a64, sizeof a64);
	fz_corpus_add(c, "cfg_mips", mips, sizeof mips);
	fz_corpus_add(c, "cfg_arm", arm, sizeof arm);
}

static int run(struct fz_ctx *c, const uint8_t *in, size_t n)
{
	struct kgenome_cell_insn *v;
	struct kgenome_cfg g[2];
	struct kgenome_cfg_sign s[2];
	const struct isa { unsigned arch; int be; } isa[6] = { { KGENOME_ARCH_X86_64, 0 }, { KGENOME_ARCH_X86, 0 }, { KGENOME_ARCH_ARM, 0 },
		{ KGENOME_ARCH_ARM64, 0 }, { KGENOME_ARCH_MIPS, 0 }, { KGENOME_ARCH_MIPS, 1 } };
	unsigned a, pass;
	uint32_t k = 0, pos = 1, i;

	if (n < 8)
		return 0;
	gview(c, in, n);
	a = in[0] % 6u;
	v = malloc((n + 1u) * sizeof *v);
	if (!v)
		return 0;
	while (pos < n && k < 4096u) {
		const uint32_t room = (uint32_t)(n - pos);
		const uint32_t l = kgenome_cell_decode(isa[a].arch, isa[a].be, in + pos, room > 16u ? 16u : room, 0x400000u + pos, &v[k]);

		fz_step(&c->steps, 1);
		if (!l) {
			pos++;
			continue;
		}
		v[k].at = pos;
		k++;
		pos += l;
	}
	for (pass = 0; pass < 2; pass++) {
		struct kgenome_cfg_req rq;
		struct kgenome_cfg_sign_req sq;
		struct kgenome_cfg_view_req vq;
		struct kgenome_cfg_view vw;
		struct kgenome_cfg_anchor_req ar;
		uint64_t *label = NULL;
		enum kgenome_status st;
		uint32_t sum = 0;

		memset(&rq, 0, sizeof rq);
		rq.in = v; rq.n_in = k; rq.arch = isa[a].arch; rq.be = isa[a].be; rq.va_lo = 0x400000u; rq.va_hi = 0x400000u + n;
		rq.bytes = in; rq.bytes_len = n; rq.flags = (in[0] & 0x80u) ? KGENOME_CFG_F_SPLIT_EXITS : 0u;
		rq.callee.id_of = ids;
		st = kgenome_cfg_build(&rq, &g[pass]);
		FZ_CHECK(c, st == KGENOME_OK || st == KGENOME_TRUNCATED || st == KGENOME_NOMEM || st == KGENOME_BAD_INPUT, "build: a status the call cannot give");
		if (st == KGENOME_NOMEM || st == KGENOME_BAD_INPUT) {
			FZ_CHECK(c, g[pass].b == NULL && g[pass].n_all == 0, "a refused build holds blocks");
			kgenome_cfg_free(&g[pass], NULL);
			continue;
		}
		for (i = 0; i < g[pass].n_all; i++) {
			const struct kgenome_cfg_block *b = &g[pass].b[i];

			FZ_CHECK(c, b->first == sum && b->n_insn > 0, "the blocks do not tile the instructions");
			sum += b->n_insn;
			FZ_CHECK(c, (b->succ[0] == KGENOME_CFG_NONE || b->succ[0] < g[pass].n_all) && (b->succ[1] == KGENOME_CFG_NONE || b->succ[1] < g[pass].n_all),
				 "a successor outside the table");
			FZ_CHECK(c, b->out_deg == (b->succ[0] != KGENOME_CFG_NONE) + (b->succ[1] != KGENOME_CFG_NONE), "out_deg is not the successor count");
		}
		FZ_CHECK(c, sum == k && (!k || g[pass].b[0].reach) && g[pass].n_blk <= g[pass].n_all, "the graph does not cover the instructions");
		label = malloc((g[pass].n_all + 1u) * sizeof *label);
		memset(&sq, 0, sizeof sq);
		sq.g = &g[pass]; sq.policy = KGENOME_CFG_P_BOTH; sq.rounds = (uint8_t)(in[0] >> 5 & 3u); sq.label = label;
		st = kgenome_cfg_sign(&sq, &s[pass]);
		if (st == KGENOME_OK && g[pass].n_blk) {
			uint32_t j;

			FZ_CHECK(c, s[pass].n_key >= 1 && s[pass].n_key <= KGENOME_CFG_KEYS, "a sketch of no keys for a graph with blocks");
			for (j = 1; j < s[pass].n_key; j++)
				FZ_CHECK(c, s[pass].key[j - 1u] < s[pass].key[j], "the sketch is not ascending and distinct");
			FZ_CHECK(c, kgenome_cfg_pct(&s[pass], &s[pass]) == 100u, "a sketch is not 100 percent like itself");
			{
				uint32_t hit, taken;

				kgenome_cfg_overlap(&s[pass], &s[pass], &hit, &taken);
				FZ_CHECK(c, hit == taken && taken >= 1u && taken <= KGENOME_CFG_KEYS && hit * 100u / taken == kgenome_cfg_pct(&s[pass], &s[pass]),
					 "the overlap of a sketch with itself is not all of it, or pct is not hit over taken");
			}
			{
				/* a pack's list, unsorted and repeating, becomes the ascending distinct bottom 32 of its values */
				uint32_t raw[64], q;
				struct kgenome_cfg_sign ks;

				for (q = 0; q < 64u; q++)
					raw[q] = s[pass].key[(q * 7u) % s[pass].n_key] ^ ((q & 8u) ? 0u : 0x80000000u);
				kgenome_cfg_keys_sign(&ks, raw, 64u);
				FZ_CHECK(c, ks.n_key >= 1u && ks.n_key <= KGENOME_CFG_KEYS, "the keys of a list are none or more than 32");
				for (q = 1; q < ks.n_key; q++)
					FZ_CHECK(c, ks.key[q - 1u] < ks.key[q], "the keys of a list are not ascending and distinct");
			}
			FZ_CHECK(c, kgenome_mutation_block_min(KGENOME_SCAN_ELF_CODE) == KGENOME_CFG_MIN_KEYS && kgenome_mutation_block_min(KGENOME_SCAN_ELF_DATA) == KGENOME_MUTATION_MIN_HASH,
				 "the minimum of a block: a function region may be a CFG block, every other region keeps the window minimum");
			FZ_CHECK(c, s[pass].n_ckey == 0 || kgenome_cfg_pct_callee(&s[pass], &s[pass]) == 100u, "the callee sketch is not 100 percent like itself");
		}
		memset(&ar, 0, sizeof ar);
		ar.min_blk = g[pass].n_blk ? g[pass].n_blk : 1u;
		FZ_CHECK(c, kgenome_cfg_anchor(&g[pass], &ar) == (g[pass].n_blk != 0), "the anchor does not pass at the exact block count");
		ar.min_blk = g[pass].n_blk + 1u;
		FZ_CHECK(c, !kgenome_cfg_anchor(&g[pass], &ar), "the anchor passes above the block count");
		if (label) {
			memset(&vq, 0, sizeof vq);
			vq.g = &g[pass]; vq.sign = &s[pass]; vq.label = label; vq.in = v;
			st = kgenome_cfg_view_make(&vq, &vw);
			if (vw.blk) {
				FZ_CHECK(c, vw.n_blk == g[pass].n_blk && vw.canon == s[pass].canon, "the view is not the graph's");
				for (i = 0; i < vw.n_blk; i++)
					FZ_CHECK(c, (vw.blk[i].succ[0] == KGENOME_CFG_NONE || vw.blk[i].succ[0] < vw.n_blk) &&
						    (vw.blk[i].succ[1] == KGENOME_CFG_NONE || vw.blk[i].succ[1] < vw.n_blk), "a view successor outside the table");
			}
			if (vw.blk || vw.n_blk == 0) {
				struct kgenome_cfg_gv_req gq;
				struct kgenome_gv gv;

				memset(&gq, 0, sizeof gq);
				gq.v = &vw;
				gq.n_note = in[2] % 3u;
				gq.n_xline = in[3] % 3u;
				(void)kgenome_cfg_gv_make(&gq, &gv);
				if (gv.n_node) {
					uint32_t q;

					FZ_CHECK(c, gv.n_node == vw.n_blk && gv.n_edge == vw.n_edge, "the graph to look at is not the view");
					for (q = 0; q < gv.n_edge; q++)
						FZ_CHECK(c, gv.edge[q].loop <= KGENOME_GV_LOOP_RETREAT && gv.edge[q].cond <= KGENOME_GV_COND_F, "an edge kind out of range");
				}
				kgenome_gv_free(&gv, NULL);
			}
			kgenome_cfg_view_free(&vw, NULL);
		}
		free(label);
		fz_digest(c, s[pass].canon ^ s[pass].ccanon ^ ((uint64_t)g[pass].n_all << 32) ^ g[pass].n_edge);
		if (pass == 1 && g[0].b && g[1].b)
			FZ_CHECK(c, s[0].canon == s[1].canon && s[0].n_key == s[1].n_key, "two builds of the same bytes differ");
		kgenome_cfg_free(&g[pass], NULL);
	}
	free(v);
	return 0;
}

FZ_ADAPTER(cfg, .name = "kgenome/diag_cfg",
	   .covers = "kgenome_cfg_build kgenome_cfg_free kgenome_cfg_sign kgenome_cfg_pct kgenome_cfg_pct_callee kgenome_cfg_overlap kgenome_cfg_keys_sign kgenome_mutation_block_min kgenome_cfg_anchor kgenome_cfg_view_make kgenome_cfg_view_free "
		 "kgenome_cfg_gv_make kgenome_gv_alloc kgenome_gv_free kgenome_gv_loops kgenome_gv_box_line",
	   .flags = 0, .backstop_s = 300, .steps_base = 100000u, .steps_per_byte = 64,
	   .shape = FZ_REQ, .seeds = seeds, .run = run);
