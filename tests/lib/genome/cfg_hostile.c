/*
 * genome / cfg_hostile - the cfg family against the inputs a hostile object makes, through <kgenome.h> alone.
 *
 *   SHAPES      a 200000-block function (ladder, all branches to the end, deep nesting, a self loop, all but the entry
 *               unreachable): linear in the blocks - the time at 4x the size is under 8x - and under a few seconds
 *   TINY        an empty array, one instruction, a function that falls off its end
 *   PREFIXES    every prefix of random programs (a truncated instruction array): the graph is consistent
 *   RANDOM      random instruction fields (any op, any flags, targets anywhere, addresses near the top of the space):
 *               the graph's invariants hold, no crash
 *   BUDGET      max_bytes from 1 up past what a call needs, for build, sign and view: below it OVER_BUDGET and nothing
 *               allocated, from it OK; never a crash and never a leak
 *   ALLOCATOR   the caller's allocator refusing the Nth allocation of build -> sign -> view for EVERY N: the status
 *               is NOMEM, every block the lib did get is given back
 *   THREADS     eight threads, one input, 200 rounds each: every output equals the single-threaded one
 */
#include "cfg_kit.h"

#include <pthread.h>

/* ---- consistency of any graph the lib returns ---- */
static int cfg_consistent(const struct kgenome_cfg *g, uint32_t n_in)
{
	uint32_t k, sum = 0, n_blk = 0, n_edge = 0, *indeg, *stk, sp = 0;
	uint8_t *reach;
	int ok = 1;

	if (!g->n_all)
		return g->b == NULL && g->n_blk == 0 && g->n_edge == 0;
	indeg = calloc(g->n_all, sizeof *indeg);
	stk = malloc((size_t)g->n_all * sizeof *stk);
	reach = calloc(g->n_all, 1);
	for (k = 0; k < g->n_all && ok; k++) {
		const struct kgenome_cfg_block *b = &g->b[k];
		unsigned e, out = 0;

		ok &= b->first == sum && b->n_insn > 0;
		sum += b->n_insn;
		for (e = 0; e < 2; e++) {
			if (b->succ[e] == KGENOME_CFG_NONE)
				continue;
			out++;
			ok &= b->succ[e] < g->n_all;
		}
		ok &= out == b->out_deg;
		switch (b->term) {
		case KGENOME_CFG_T_EXIT: ok &= out == 0; break;
		case KGENOME_CFG_T_JUMP: ok &= out == 1 && b->succ[1] == KGENOME_CFG_NONE; break;
		case KGENOME_CFG_T_COND: ok &= out >= 1 && b->succ[0] != KGENOME_CFG_NONE; break;
		case KGENOME_CFG_T_FALL: ok &= out <= 1 && b->succ[1] == KGENOME_CFG_NONE && (out == 0 ? k + 1u == g->n_all : b->succ[0] == k + 1u); break;
		default: ok = 0;
		}
	}
	ok &= sum == n_in;
	if (!ok) {
		free(indeg); free(stk); free(reach);
		return 0;
	}
	reach[0] = 1;
	stk[sp++] = 0;
	while (sp) {
		const struct kgenome_cfg_block *b = &g->b[stk[--sp]];
		unsigned e;

		for (e = 0; e < 2; e++) {
			const uint32_t s = b->succ[e];

			if (s == KGENOME_CFG_NONE)
				continue;
			indeg[s]++;
			n_edge++;
			if (!reach[s]) {
				reach[s] = 1;
				stk[sp++] = s;
			}
		}
	}
	for (k = 0; k < g->n_all; k++) {
		ok &= g->b[k].reach == reach[k] && g->b[k].in_deg == indeg[k];
		n_blk += reach[k];
	}
	ok &= n_blk == g->n_blk && n_edge == g->n_edge && g->b[0].reach == 1;
	free(indeg); free(stk); free(reach);
	return ok;
}

/* ---- synthetic instruction arrays (x86-flavoured fields, no bytes: the builder reads fields) ---- */
static void put(struct kgenome_cell_insn *in, uint32_t i, uint8_t op, uint64_t tgt_va)
{
	memset(&in[i], 0, sizeof in[i]);
	in[i].op = op;
	in[i].len = 1;
	in[i].at = i;
	in[i].at_va = 0x400000u + i;
	in[i].target_va = tgt_va;
	in[i].target = tgt_va;
}
#define VA(i) (0x400000u + (uint64_t)(i))

enum shape { SH_LADDER, SH_TO_END, SH_NESTED, SH_SELFLOOP, SH_JUNK, SH_FALLS, SH_RANDOM_JUMPS };

/* Blocks of two instructions: [nop][terminator]. */
static struct kgenome_cell_insn *shape_make(enum shape sh, uint32_t nb, uint32_t *n_in, struct crng *r)
{
	struct kgenome_cell_insn *in = calloc((size_t)nb * 2u + 1u, sizeof *in);
	uint32_t b;

	*n_in = nb * 2u;
	for (b = 0; b < nb; b++) {
		const uint32_t i = 2u * b;
		uint32_t t = 0;
		uint8_t op = KGENOME_CELL_JCC;

		put(in, i, KGENOME_CELL_NOP, KGENOME_BROKEN);
		switch (sh) {
		case SH_LADDER: t = b + 2u < nb ? b + 2u : nb - 1u; op = b + 1u == nb ? KGENOME_CELL_RET : KGENOME_CELL_JCC; break;
		case SH_TO_END: t = nb - 1u; op = b + 1u == nb ? KGENOME_CELL_RET : KGENOME_CELL_JCC; break;
		case SH_NESTED:                 /* the first half falls into the second; each block of the second branches back to its mirror */
			if (b < nb / 2u) { op = KGENOME_CELL_NOP; } else { t = nb - 1u - b; op = b + 1u == nb ? KGENOME_CELL_RET : KGENOME_CELL_JCC; }
			if (op == KGENOME_CELL_NOP) { put(in, i + 1u, KGENOME_CELL_NOP, KGENOME_BROKEN); continue; }
			break;
		case SH_SELFLOOP: t = b; op = KGENOME_CELL_JMP; break;
		case SH_JUNK: t = b ? b : 0; op = b == 0 ? KGENOME_CELL_RET : KGENOME_CELL_JMP; if (b) t = 1u + crng_below(r, nb - 1u); break;
		case SH_FALLS: op = KGENOME_CELL_NOP; break;
		case SH_RANDOM_JUMPS: t = crng_below(r, nb); op = crng_below(r, 3) == 0 ? KGENOME_CELL_JMP : KGENOME_CELL_JCC; if (b + 1u == nb) op = KGENOME_CELL_RET; break;
		}
		put(in, i + 1u, op, op == KGENOME_CELL_JCC || op == KGENOME_CELL_JMP ? VA(2u * t) : KGENOME_BROKEN);
	}
	return in;
}

static double run_shape(enum shape sh, uint32_t nb, int check, uint32_t *n_blk_out)
{
	struct crng rg;
	struct kgenome_cell_insn *in;
	uint32_t n_in;
	struct kgenome_cfg_req rq;
	struct kgenome_cfg g;
	struct kgenome_cfg_sign s;
	struct kgenome_cfg_sign_req sq;
	double t0, t1;

	crng_seed(&rg, 5);
	in = shape_make(sh, nb, &n_in, &rg);
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n_in; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x400000u; rq.va_hi = 0x400000u + n_in;
	t0 = now_ms();
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	memset(&sq, 0, sizeof sq);
	sq.g = &g;
	CK(kgenome_cfg_sign(&sq, &s) == KGENOME_OK);
	t1 = now_ms();
	if (check)
		CKM(cfg_consistent(&g, n_in), "shape %d, %u blocks: inconsistent", (int)sh, nb);
	if (n_blk_out)
		*n_blk_out = g.n_blk;
	kgenome_cfg_free(&g, NULL);
	free(in);
	return t1 - t0;
}

static void shapes(void)
{
	static const char *const name[] = { "ladder", "all-to-end", "nested", "self-loop", "junk", "falls", "random-jumps" };
	int sh;

	for (sh = SH_LADDER; sh <= SH_RANDOM_JUMPS; sh++) {
		uint32_t nb_small = 0, nb_big = 0;
		double t_small = 1e9, t_big = 1e9;
		int rep;

		for (rep = 0; rep < 3; rep++) {         /* the best of three: a scheduler hiccup is not a complexity class */
			double a = run_shape((enum shape)sh, 50000, 1, &nb_small), b = run_shape((enum shape)sh, 200000, rep == 0, &nb_big);

			if (a < t_small) t_small = a;
			if (b < t_big) t_big = b;
		}
		printf("  shape %-12s 50000 blocks %7.1f ms (%u reachable), 200000 blocks %7.1f ms (%u reachable), x%.1f\n", name[sh], t_small, nb_small, t_big, nb_big,
		       t_small > 0.01 ? t_big / t_small : 0.0);
		CKM(t_big < 5000.0, "%s: 200000 blocks took %.0f ms", name[sh], t_big);
		CKM(t_small < 0.5 || t_big < 8.0 * t_small, "%s: %.0f ms at 50000 and %.0f ms at 200000 is not linear", name[sh], t_small, t_big);
	}
	/* what each shape must hold: the reachable counts */
	{
		uint32_t n;

		run_shape(SH_JUNK, 200000, 0, &n);       CK(n == 1);                    /* all but the entry unreachable */
		run_shape(SH_SELFLOOP, 200000, 0, &n);   CK(n == 1);                    /* a jump to itself: block 0 only */
		run_shape(SH_LADDER, 200000, 0, &n);     CKM(n == 200000, "ladder reaches %u", n);
		run_shape(SH_TO_END, 200000, 0, &n);     CK(n == 200000);
		run_shape(SH_FALLS, 200000, 0, &n);      CKM(n == 1, "straight line is %u blocks", n);
	}
	/* in-degree past 16 bits is a count and not a wrap: every block of the all-to-end shape branches to the last */
	{
		uint32_t n_in;
		struct crng rg;
		struct kgenome_cell_insn *in;
		struct kgenome_cfg_req rq;
		struct kgenome_cfg g;

		crng_seed(&rg, 1);
		in = shape_make(SH_TO_END, 200000, &n_in, &rg);
		memset(&rq, 0, sizeof rq);
		rq.in = in; rq.n_in = n_in; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x400000u; rq.va_hi = 0x400000u + n_in;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		CK(g.b[g.n_all - 1u].in_deg == 200000u + 199999u - 199999u + 0u || g.b[g.n_all - 1u].in_deg >= 200000u);
		kgenome_cfg_free(&g, NULL);
		free(in);
	}
}

/* ---- tiny ---- */
static void tiny(void)
{
	struct kgenome_cell_insn in[2];
	struct kgenome_cfg_req rq;
	struct kgenome_cfg g;
	struct kgenome_cfg_sign s;
	struct kgenome_cfg_anchor_req ar = { .min_blk = 0 };

	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = 0x400000u; rq.va_hi = 0x400100u;
	rq.n_in = 0;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 0 && g.n_blk == 0 && g.b == NULL);
	CK(sign_of(&g, 0, &s) == KGENOME_OK && s.n_blk == 0 && s.n_key == 0 && s.canon == 0);
	CK(!kgenome_cfg_anchor(&g, &ar));
	CK(kgenome_cfg_pct(&s, &s) == 0);
	put(in, 0, KGENOME_CELL_RET, KGENOME_BROKEN);
	rq.n_in = 1;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 1 && g.n_blk == 1 && g.b[0].term == KGENOME_CFG_T_EXIT && g.b[0].in_deg == 0);
	CK(sign_of(&g, 0, &s) == KGENOME_OK && s.n_blk == 1 && s.n_key == 1);
	kgenome_cfg_free(&g, NULL);
	put(in, 0, KGENOME_CELL_NOP, KGENOME_BROKEN);
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_all == 1 && g.b[0].term == KGENOME_CFG_T_FALL && g.b[0].out_deg == 0);
	CK(sign_of(&g, 0, &s) == KGENOME_OK && s.n_blk == 1);
	kgenome_cfg_free(&g, NULL);
	put(in, 0, KGENOME_CELL_JMP, VA(0));              /* a one-instruction self loop */
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_blk == 1 && g.n_edge == 1 && g.b[0].succ[0] == 0 && g.b[0].in_deg == 1);
	CK(sign_of(&g, 0, &s) == KGENOME_OK && s.n_blk == 1);
	kgenome_cfg_free(&g, NULL);
	/* the extent is empty or inverted: every target is outside */
	rq.va_lo = 0x400100u; rq.va_hi = 0x400000u;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK && g.n_edge == 0 && g.b[0].term == KGENOME_CFG_T_EXIT);
	kgenome_cfg_free(&g, NULL);
	/* rounds past the limit */
	rq.va_lo = 0x400000u; rq.va_hi = 0x400100u;
	CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
	CK(sign_of(&g, KGENOME_CFG_ROUNDS_MAX, &s) == KGENOME_OK);
	CK(sign_of(&g, KGENOME_CFG_ROUNDS_MAX + 1u, &s) == KGENOME_BAD_INPUT && s.n_key == 0);
	kgenome_cfg_free(&g, NULL);
	{
		struct kgenome_cfg_sign_req sq;

		memset(&sq, 0, sizeof sq);
		CK(kgenome_cfg_sign(&sq, &s) == KGENOME_BAD_INPUT);
		CK(kgenome_cfg_sign(NULL, &s) == KGENOME_BAD_INPUT);
	}
}

/* ---- prefixes of random programs ---- */
static void prefixes(void)
{
	struct crng rg;
	unsigned ii, round;

	crng_seed(&rg, 99);
	for (ii = 0; ii < N_ISAS; ii++)
		for (round = 0; round < 60; round++) {
			struct prog p;
			struct blob x;
			struct kgenome_cell_insn *in = NULL;
			uint32_t n, k;

			prog_random(&ISAS[ii], &rg, 4u + crng_below(&rg, 40), &p);
			if (!blob_make(&ISAS[ii], &p, 0x1000, &x)) { prog_free(&p); continue; }
			n = blob_decode(&ISAS[ii], &x, &in);
			for (k = 0; k <= n; k++) {
				struct kgenome_cfg_req rq;
				struct kgenome_cfg g;
				struct kgenome_cfg_sign s;
				const enum kgenome_status st = (memset(&rq, 0, sizeof rq), rq.in = in, rq.n_in = k, rq.arch = ISAS[ii].arch, rq.be = ISAS[ii].be,
								rq.va_lo = x.va0, rq.va_hi = x.va0 + x.len, rq.bytes = x.b, rq.bytes_len = x.len,
								kgenome_cfg_build(&rq, &g));

				CKM(st == KGENOME_OK || st == KGENOME_TRUNCATED, "%s prefix %u/%u: status %d", ISAS[ii].name, k, n, (int)st);
				CKM(cfg_consistent(&g, k), "%s prefix %u/%u: inconsistent", ISAS[ii].name, k, n);
				CK(sign_of(&g, 0, &s) == st);
				kgenome_cfg_free(&g, NULL);
			}
			free(in);
			blob_free(&x);
			prog_free(&p);
		}
}

/* ---- random fields ---- */
static void random_fields(void)
{
	struct crng rg;
	unsigned round;

	crng_seed(&rg, 2024);
	for (round = 0; round < 20000; round++) {
		const uint32_t n = 1u + crng_below(&rg, 40);
		struct kgenome_cell_insn *in = calloc(n, sizeof *in);
		uint64_t va = crng_below(&rg, 4) == 0 ? UINT64_MAX - 200u : 0x1000u + crng_below(&rg, 1000);
		uint32_t i;
		struct kgenome_cfg_req rq;
		struct kgenome_cfg g;
		struct kgenome_cfg_sign s;
		const unsigned arch = ISAS[crng_below(&rg, N_ISAS)].arch;

		for (i = 0; i < n && va < UINT64_MAX - 20u; i++) {
			memset(&in[i], 0, sizeof in[i]);
			in[i].op = (uint8_t)(crng_below(&rg, 4) ? crng_below(&rg, KGENOME_CELL_OP_COUNT + 3u) : KGENOME_CELL_JCC);
			in[i].len = (uint8_t)(crng_below(&rg, 8));
			in[i].flags = (uint8_t)crng_next(&rg);
			in[i].cond = (uint8_t)crng_next(&rg);
			in[i].n_op = (uint8_t)crng_below(&rg, 5);
			in[i].at = crng_next(&rg) % 64u;
			in[i].at_va = va;
			in[i].target_va = crng_below(&rg, 5) == 0 ? KGENOME_BROKEN : crng_below(&rg, 5) == 0 ? crng_next(&rg) : va - 20u + crng_below(&rg, 60);
			va += 1u + crng_below(&rg, 3);
		}
		memset(&rq, 0, sizeof rq);
		rq.in = in; rq.n_in = i; rq.arch = arch; rq.be = (int)crng_below(&rg, 2);
		rq.va_lo = in[0].at_va - crng_below(&rg, 30); rq.va_hi = va + crng_below(&rg, 30);
		rq.bytes = (const uint8_t *)in; rq.bytes_len = crng_below(&rg, 2) ? n * sizeof *in : 7u;
		rq.flags = crng_below(&rg, 2) ? KGENOME_CFG_F_SPLIT_EXITS : 0u;
		(void)kgenome_cfg_build(&rq, &g);
		CKM(cfg_consistent(&g, rq.n_in), "random %u: inconsistent", round);
		(void)kgenome_cfg_sign(&(struct kgenome_cfg_sign_req){ .g = &g, .rounds = (uint8_t)crng_below(&rg, 4) }, &s);
		kgenome_cfg_free(&g, NULL);
		free(in);
	}
}

/* ---- budget and allocator ---- */
static void make_prog(struct prog *p, struct blob *x, struct kgenome_cell_insn **in, uint32_t *n)
{
	struct crng rg;

	crng_seed(&rg, 7);
	do {
		prog_free(p);
		prog_random(&ISAS[0], &rg, 30, p);
	} while (0);
	CK(blob_make(&ISAS[0], p, 0x1000, x));
	*n = blob_decode(&ISAS[0], x, in);
}

static void budget(void)
{
	struct prog p = { 0 };
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	uint32_t n;
	uint64_t b, first_ok_build = 0, first_ok_sign = 0, first_ok_view = 0;
	struct kgenome_cfg_req rq;
	struct kgenome_cfg g, full;
	struct kgenome_cfg_sign s;
	struct kgenome_cfg_sign_req sq;
	struct kgenome_cfg_view_req vq;
	struct kgenome_cfg_view v;
	uint64_t label[128];
	struct counting c = { 0 };
	struct kgenome_cfg_mem mem = COUNTING_MEM(&c);

	make_prog(&p, &x, &in, &n);
	memset(&rq, 0, sizeof rq);
	rq.in = in; rq.n_in = n; rq.arch = ISAS[0].arch; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len; rq.mem = mem;
	CK(kgenome_cfg_build(&rq, &full) == KGENOME_OK);
	CK(full.n_all < 128);
	for (b = 1; b < 4000; b++) {
		struct kgenome_budget bud;

		memset(&bud, 0, sizeof bud);
		bud.max_bytes = b;
		rq.budget = &bud;
		c.n_alloc = c.n_free = 0;
		{
			const enum kgenome_status st = kgenome_cfg_build(&rq, &g);

			if (st == KGENOME_OK) {
				if (!first_ok_build) first_ok_build = b;
				CKM(cfg_consistent(&g, n), "budget %llu: inconsistent", (unsigned long long)b);
			} else {
				CKM(st == KGENOME_OVER_BUDGET && g.b == NULL && g.n_all == 0, "budget %llu: status %d", (unsigned long long)b, (int)st);
				CKM(!first_ok_build, "budget %llu: refused after an OK at %llu (not monotone)", (unsigned long long)b, (unsigned long long)first_ok_build);
			}
			kgenome_cfg_free(&g, &mem);
			CKM(c.n_alloc == c.n_free, "budget %llu: %u allocations, %u released", (unsigned long long)b, c.n_alloc, c.n_free);
		}
	}
	{
		uint32_t calls = 0, q;
		uint64_t need;

		for (q = 0; q < n; q++)
			calls += in[q].op == KGENOME_CELL_CALL || in[q].op == KGENOME_CELL_SYSCALL;
		CK(calls > 0);
		need = (uint64_t)n * 9u + (uint64_t)full.n_all * sizeof(struct kgenome_cfg_block) + (uint64_t)calls * sizeof(struct kgenome_cfg_call);
		CKM(first_ok_build == need, "build needs %llu bytes (9 n_in + 32 n_all + 16 calls = %llu)", (unsigned long long)first_ok_build, (unsigned long long)need);
	}
	rq.budget = NULL;
	memset(&sq, 0, sizeof sq);
	sq.g = &full; sq.label = label; sq.mem = mem;
	for (b = 1; b < 8000; b++) {
		struct kgenome_budget bud;
		enum kgenome_status st;

		memset(&bud, 0, sizeof bud);
		bud.max_bytes = b;
		sq.budget = &bud;
		c.n_alloc = c.n_free = 0;
		st = kgenome_cfg_sign(&sq, &s);
		if (st == KGENOME_OK) {
			if (!first_ok_sign) first_ok_sign = b;
		} else {
			CKM(st == KGENOME_OVER_BUDGET && s.n_key == 0 && s.n_blk == 0 && s.canon == 0, "sign budget %llu: status %d", (unsigned long long)b, (int)st);
			CK(!first_ok_sign);
		}
		CKM(c.n_alloc == c.n_free, "sign budget %llu: %u allocations, %u released", (unsigned long long)b, c.n_alloc, c.n_free);
	}
	CK(first_ok_sign != 0);
	sq.budget = NULL;
	CK(kgenome_cfg_sign(&sq, &s) == KGENOME_OK);
	memset(&vq, 0, sizeof vq);
	vq.g = &full; vq.sign = &s; vq.label = label; vq.in = in; vq.mem = mem;
	for (b = 1; b < 8000; b++) {
		struct kgenome_budget bud;
		enum kgenome_status st;

		memset(&bud, 0, sizeof bud);
		bud.max_bytes = b;
		vq.budget = &bud;
		c.n_alloc = c.n_free = 0;
		st = kgenome_cfg_view_make(&vq, &v);
		if (st == KGENOME_OK) {
			if (!first_ok_view) first_ok_view = b;
		} else {
			CKM(st == KGENOME_OVER_BUDGET && v.blk == NULL && v.n_blk == 0, "view budget %llu: status %d", (unsigned long long)b, (int)st);
			CK(!first_ok_view);
		}
		kgenome_cfg_view_free(&v, &mem);
		CKM(c.n_alloc == c.n_free, "view budget %llu: %u allocations, %u released", (unsigned long long)b, c.n_alloc, c.n_free);
	}
	CK(first_ok_view != 0);
	/* no budget, a budget of 0 (= not set) and a huge one are all "no limit" */
	{
		struct kgenome_budget bud;

		memset(&bud, 0, sizeof bud);
		rq.budget = &bud;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		kgenome_cfg_free(&g, &mem);
		bud.max_bytes = UINT64_MAX;
		CK(kgenome_cfg_build(&rq, &g) == KGENOME_OK);
		kgenome_cfg_free(&g, &mem);
	}
	kgenome_cfg_free(&full, &mem);
	CKM(c.live == 0, "live bytes %lld at the end", (long long)c.live);
	free(in); blob_free(&x); prog_free(&p);
}

/* The allocator refuses the Nth allocation of the whole pipeline, for every N. */
static void allocator(void)
{
	struct prog p = { 0 };
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	uint32_t n, N, total = 0;
	int pass;

	make_prog(&p, &x, &in, &n);
	for (pass = 0; pass < 2; pass++) {
		for (N = 0; N <= 14; N++) {      /* N = 0: never refuse (counts the allocations of a whole run) */
			struct counting c = { 0 };
			struct kgenome_cfg_mem mem = COUNTING_MEM(&c);
			struct kgenome_cfg_req rq;
			struct kgenome_cfg g;
			struct kgenome_cfg_sign s;
			struct kgenome_cfg_sign_req sq;
			struct kgenome_cfg_view_req vq;
			struct kgenome_cfg_view v;
			uint64_t label[128];
			enum kgenome_status sb, ss, sv;

			c.fail_at = N;
			memset(&rq, 0, sizeof rq);
			rq.in = in; rq.n_in = n; rq.arch = ISAS[0].arch; rq.va_lo = x.va0; rq.va_hi = x.va0 + x.len; rq.mem = mem;
			sb = kgenome_cfg_build(&rq, &g);
			memset(&sq, 0, sizeof sq);
			sq.g = &g; sq.label = label; sq.mem = mem;
			ss = kgenome_cfg_sign(&sq, &s);
			memset(&vq, 0, sizeof vq);
			vq.g = &g; vq.sign = &s; vq.label = label; vq.in = in; vq.mem = mem;
			sv = kgenome_cfg_view_make(&vq, &v);
			if (N == 0) {
				CK(sb == KGENOME_OK && ss == KGENOME_OK && sv == KGENOME_OK);
				total = c.n_alloc;
				CKM(total == 6, "the pipeline makes %u allocations (build 3: temporary, blocks, calls; sign 1; view 2)", total);
			} else if (N <= total) {
				CKM(sb == KGENOME_NOMEM || ss == KGENOME_NOMEM || sv == KGENOME_NOMEM, "N=%u: no stage said NOMEM (%d %d %d)", N, (int)sb, (int)ss, (int)sv);
				CK(sb != KGENOME_OK || cfg_consistent(&g, n));
				CK(sb == KGENOME_NOMEM ? g.b == NULL : 1);
				if (ss == KGENOME_NOMEM)
					CK(s.n_key == 0);
				if (sv == KGENOME_NOMEM && sb == KGENOME_OK && ss == KGENOME_OK)
					CK(v.blk == NULL);      /* the view's own allocation failed: nothing of it is held */
			} else {
				CK(sb == KGENOME_OK && ss == KGENOME_OK && sv == KGENOME_OK);
			}
			kgenome_cfg_view_free(&v, &mem);
			kgenome_cfg_free(&g, &mem);
			CKM(c.n_alloc >= c.n_free && c.live == 0, "N=%u: %u allocations, %u released, %lld bytes live", N, c.n_alloc, c.n_free, (long long)c.live);
		}
	}
	free(in); blob_free(&x); prog_free(&p);
}

/* ---- threads ---- */
struct th {
	const struct kgenome_cell_insn *in;
	uint32_t n;
	struct kgenome_cfg_sign want;
	uint32_t want_view_succ0;
	int bad;
	pthread_barrier_t *go;
	uint64_t va0, len;
};

static void *th_main(void *arg)
{
	struct th *t = arg;
	unsigned round;

	pthread_barrier_wait(t->go);
	for (round = 0; round < 200; round++) {
		struct kgenome_cfg_req rq;
		struct kgenome_cfg g;
		struct kgenome_cfg_sign s;
		struct kgenome_cfg_sign_req sq;
		struct kgenome_cfg_view_req vq;
		struct kgenome_cfg_view v;
		uint64_t label[256];

		memset(&rq, 0, sizeof rq);
		rq.in = t->in; rq.n_in = t->n; rq.arch = KGENOME_ARCH_X86_64; rq.va_lo = t->va0; rq.va_hi = t->va0 + t->len;
		if (kgenome_cfg_build(&rq, &g) != KGENOME_OK) { t->bad++; continue; }
		memset(&sq, 0, sizeof sq);
		sq.g = &g; sq.label = label;
		if (kgenome_cfg_sign(&sq, &s) != KGENOME_OK || !sign_eq(&s, &t->want)) t->bad++;
		memset(&vq, 0, sizeof vq);
		vq.g = &g; vq.sign = &s; vq.label = label; vq.in = t->in;
		if (kgenome_cfg_view_make(&vq, &v) != KGENOME_OK || v.n_blk != g.n_blk || v.canon != t->want.canon) t->bad++;
		kgenome_cfg_view_free(&v, NULL);
		kgenome_cfg_free(&g, NULL);
	}
	return NULL;
}

static void threads(void)
{
	enum { NT = 8 };
	struct prog p = { 0 };
	struct blob x;
	struct kgenome_cell_insn *in = NULL;
	uint32_t n, i;
	struct th t[NT];
	pthread_t id[NT];
	pthread_barrier_t go;
	struct kgenome_cfg g;
	struct crng rg;

	crng_seed(&rg, 11);
	prog_random(&ISAS[0], &rg, 120, &p);
	CK(blob_make(&ISAS[0], &p, 0x1000, &x));
	CK(blob_cfg(&ISAS[0], &p, &x, &in, &g) == KGENOME_OK);
	n = x.n_insn;
	pthread_barrier_init(&go, NULL, NT);
	for (i = 0; i < NT; i++) {
		memset(&t[i], 0, sizeof t[i]);
		t[i].in = in; t[i].n = n; t[i].go = &go; t[i].va0 = x.va0; t[i].len = x.len;
		CK(sign_of(&g, 0, &t[i].want) == KGENOME_OK);
	}
	CK(g.n_all < 256);
	for (i = 0; i < NT; i++)
		pthread_create(&id[i], NULL, th_main, &t[i]);
	for (i = 0; i < NT; i++) {
		pthread_join(id[i], NULL);
		CKM(t[i].bad == 0, "thread %u: %d outputs differ from the single-threaded one", i, t[i].bad);
	}
	pthread_barrier_destroy(&go);
	kgenome_cfg_free(&g, NULL);
	free(in); blob_free(&x); prog_free(&p);
}

int main(void)
{
	shapes();
	tiny();
	prefixes();
	random_fields();
	budget();
	allocator();
	threads();
	if (fails)
		printf("cfg_hostile: %d FAILED\n", fails);
	else
		printf("cfg_hostile: ok\n");
	return fails != 0;
}
