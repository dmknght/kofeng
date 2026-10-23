/*
 * lineage_chain - WHICH STAGE RUNS ON WHICH CODE, and the obligations the chain leaves (diag_lineage_chain.c).
 *
 *   SELECTION = EAGER  Every generated program is scanned with the stages the class allows run on every function and block (the
 *                      eager reference, KGENOME_LINEAGE_S_EAGER) and with the chain's selection. The links must be the same:
 *                      the selection is a cost, not an answer. (Seeded code - blocks no walk from an entry reaches - is the
 *                      one place two seedings of it may differ, and only in MAY links, so a program with dead regions is held
 *                      to the MUST links being the same.)
 *   THE CHAIN          By hand, one program for each thing the selection claims: an obligation that travels across three stages
 *                      (a call's result stored in a heap field and read back), a stage that must NOT run (a global that is
 *                      only read; a call to a function that reaches no node), and the reasons that no stage discharges.
 *   THE UNRESOLVED SET Complete and exact against the oracle is checked by every campaign (lg_check_oblig); here the contents
 *                      of the record - node, role, partial, reason, function - are read.
 */
#include "lineage_check.h"

static struct lg_img g;
static struct lg_cg c;
static struct lg_prog p;

static int ex(int kind, int x, int a0, int a1, int n)
{
	return lg_ex(&p, kind, x, a0, a1, n);
}

static int api(int a, int a0, int a1)
{
	return lg_h_api(&p, a, a0, a1);
}

static void st(int blk, int kind, int x, int e, int a, int b)
{
	lg_h_st(&p, blk, kind, x, e, a, b);
}

/* ---- selection = eager ---- */

struct eqv {
	long files, same, only_dead_differs;
	long fns, runs, blocks, blocks_locs, blocks_summ, fns_locs, fns_summ;
	int without_mem;
};

/* Links as text, sorted: the comparison does not care which scan made them. */
static int links_equal(const struct lg_links *a, const struct lg_links *b, int must_only)
{
	int i = 0, j = 0;

	for (;;) {
		while (i < a->n && must_only && !a->v[i].must)
			i++;
		while (j < b->n && must_only && !b->v[j].must)
			j++;
		if (i >= a->n || j >= b->n)
			return i >= a->n && j >= b->n;
		if (memcmp(&a->v[i], &b->v[j], sizeof a->v[i]))
			return 0;
		i++;
		j++;
	}
}

static int eqv_one(void *user, const struct lg_prog *pr, const struct lg_cg *cg, const struct lg_img *im,
		   const struct lg_oracle *o, int target, int strip, uint64_t seed)
{
	static struct lg_links sel, eager;
	struct eqv *e = user;
	struct lg_scan a, b;
	struct kgenome_diag_lineage_stats stt;
	int fails = 0;

	(void)o;
	(void)cg;
	if (!lg_scan(&a, im, target, KGENOME_LINEAGE_S_ALL) ||
	    !lg_scan(&b, im, target, KGENOME_LINEAGE_S_ALL | KGENOME_LINEAGE_S_EAGER)) {
		printf("  seed %llu %s: no scan\n", (unsigned long long)seed, lg_target_name(target));
		return 1;
	}
	lg_actual(&sel, &a);
	lg_actual(&eager, &b);
	e->files++;
	if (links_equal(&sel, &eager, 0)) {
		e->same++;
	} else if (strip && links_equal(&sel, &eager, 1)) {
		e->only_dead_differs++;         /* a stripped twin's dead regions are seeded: MAY links may differ, MUST ones may not */
	} else {
		printf("  seed %llu %s%s: the selection holds %d links, the eager reference %d, and they differ\n", (unsigned long long)seed,
		       lg_target_name(target), strip ? " stripped" : "", sel.n, eager.n);
		fails++;
	}
	(void)kgenome_diag_lineage_stats_of(a.s, &stt);
	e->fns += (long)stt.fns;
	e->runs += (long)stt.runs;
	e->blocks += (long)stt.blocks;
	e->blocks_locs += (long)stt.blocks_stage[1];
	e->blocks_summ += (long)stt.blocks_stage[2];
	e->fns_locs += (long)stt.fns_stage[1];
	e->fns_summ += (long)stt.fns_stage[2];
	if (e->without_mem && stt.fns_stage[1]) {
		printf("  seed %llu %s: LOCS ran on %llu functions of a program with no global and no field\n", (unsigned long long)seed,
		       lg_target_name(target), (unsigned long long)stt.fns_stage[1]);
		fails++;
	}
	(void)pr;
	kgenome_diag_scan_free(a.s);
	kgenome_diag_scan_free(b.s);
	return fails;
}

static void t_equivalence(void)
{
	static const unsigned feat_mem = LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL | LG_F_REC | LG_F_MEM;
	const unsigned all = KGENOME_LINEAGE_S_ALL;
	struct eqv e;
	long programs = 0;
	int n = (int)(40 * hk_scale());

	memset(&e, 0, sizeof e);
	CK(lg_each(feat_mem, n, 31000, &all, &programs, eqv_one, &e) == 0);
	/* no memory in the program: LOCS has nothing to ask for, and the selection must not run it */
	e.without_mem = 1;
	CK(lg_each(LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL | LG_F_REC, n, 35000, &all, &programs, eqv_one, &e) == 0);
	/* with dead regions: the seeds */
	e.without_mem = 0;
	CK(lg_each(feat_mem | LG_F_DEAD, n, 39000, &all, &programs, eqv_one, &e) == 0);
	/* the selection reads less than the eager reference does, and some functions are read more than once */
	CK(e.runs > e.fns);
	CK(e.fns_locs > 0 && e.fns_locs < e.fns);
	CK(e.fns_summ > 0 && e.fns_summ < e.fns);
	CK(e.blocks_locs < e.blocks && e.blocks_summ < e.blocks);
	printf("lineage_chain: %ld scans, selection = eager in %ld (%ld differ in MAY links through dead regions only); %ld functions read "
	       "%ld times; LOCS on %ld of them and %ld of %ld blocks, SUMM on %ld and %ld blocks\n", e.files, e.same, e.only_dead_differs,
	       e.fns, e.runs, e.fns_locs, e.blocks_locs, e.blocks, e.fns_summ, e.blocks_summ);
}

/* ---- the chain, program by program ---- */

struct want {
	unsigned fns, runs;             /* functions solved, solves of them */
	unsigned fns_locs, fns_summ;    /* functions whose last run had the stage */
	unsigned links;                 /* links in the scan */
	unsigned oblig;                 /* inputs in the unresolved set */
	unsigned why;                   /* the reasons the first of them must carry (all of these bits), 0 when there is none */
	int      exact;                 /* ... and no others */
	int      strength;              /* the first link: 1 MUST, 2 MAY, 0 not checked */
	int      partial;               /* the first unresolved input: 1 some producers are known, 0 not checked */
	int      parent;                /* the first link's producer: the number of its call site + 1, 0 not checked */
};

/* What the next-stage count must say of the one unresolved input of the next check: 1 a stage the plan allows was not run, 2 it ran and
 * left the input, 3 the class switched it off, 4 none exists (a limit); 0 not checked. Reset by the check that reads it. */
static int g_next;

static void check(int target, unsigned stages, const struct want *w, const char *name)
{
	static struct lg_links got;
	struct kgenome_diag_lineage_stats stt;
	struct lg_scan sc;

	if (!lg_h_scan(&sc, &g, &c, &p, target, stages)) {
		printf("  %s %s: no scan\n", name, lg_target_name(target));
		CK(0);
		return;
	}
	lg_actual(&got, &sc);
	(void)kgenome_diag_lineage_stats_of(sc.s, &stt);
	if ((w->fns && (stt.fns != w->fns || stt.runs != w->runs || stt.fns_stage[1] != w->fns_locs || stt.fns_stage[2] != w->fns_summ)) ||
	    (unsigned)got.n != w->links || kgenome_diag_oblig_count(sc.s) != w->oblig) {
		printf("  %s %s: functions %llu (want %u) runs %llu (%u) with LOCS %llu (%u) with SUMM %llu (%u) links %d (%u) unresolved %u (%u)\n",
		       name, lg_target_name(target), (unsigned long long)stt.fns, w->fns, (unsigned long long)stt.runs, w->runs,
		       (unsigned long long)stt.fns_stage[1], w->fns_locs, (unsigned long long)stt.fns_stage[2], w->fns_summ, got.n, w->links,
		       kgenome_diag_oblig_count(sc.s), w->oblig);
		{
			uint32_t qq;

			for (qq = 0; qq < kgenome_diag_oblig_count(sc.s); qq++) {
				const struct kgenome_diag_oblig *ob = kgenome_diag_oblig_at(sc.s, qq);

				printf("    unresolved: role %u why %x partial %u\n", ob->role, ob->why, ob->partial);
			}
		}
		CK(0);
	}
	if (g_next) {
		const uint64_t *nx[4] = { &stt.next_missing, &stt.next_ran, &stt.next_off, &stt.next_none };
		int k;

		for (k = 0; k < 4; k++)
			if (*nx[k] != (k + 1 == g_next ? 1u : 0u)) {
				printf("  %s %s: next-stage counts %llu/%llu/%llu/%llu, wanted the one input in class %d\n", name, lg_target_name(target),
				       (unsigned long long)stt.next_missing, (unsigned long long)stt.next_ran, (unsigned long long)stt.next_off,
				       (unsigned long long)stt.next_none, g_next);
				CK(0);
				break;
			}
		g_next = 0;
	}
	if (w->parent && got.n && got.v[0].parent != (uint32_t)(g.code_off + c.site_off[w->parent - 1])) {
		printf("  %s %s: the first link's producer is at %x, wanted site %d (%x)\n", name, lg_target_name(target), got.v[0].parent,
		       w->parent - 1, (unsigned)(g.code_off + c.site_off[w->parent - 1]));
		CK(0);
	}
	if (w->strength && got.n && got.v[0].must != (w->strength == 1)) {
		printf("  %s %s: the first link is %s, wanted %s\n", name, lg_target_name(target), got.v[0].must ? "MUST" : "MAY",
		       w->strength == 1 ? "MUST" : "MAY");
		CK(0);
	}
	if (w->why) {
		const struct kgenome_diag_oblig *o = kgenome_diag_oblig_at(sc.s, 0);

		if (!o || (o->why & w->why) != w->why || (w->partial ? !o->partial : o->partial) || (w->exact && o->why != w->why)) {
			printf("  %s %s: the unresolved input carries reasons %x, wanted %x and no known producer\n", name, lg_target_name(target),
			       o ? o->why : 0u, w->why);
			CK(0);
		}
	}
	kgenome_diag_scan_free(sc.s);
}

static void t_chain(void)
{
	int target;

	for (target = LG_T_ELF64; target <= LG_T_PE32; target++) {
		int sock, sock1;

		/* 1. registers and frame alone: socket() then connect(it). Nothing asks for another stage. */
		lg_h_new(&p, 1, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, "regs");

		/* 2. a field of the object: the load is an obligation LOCS discharges, and nothing else is asked */
		lg_h_new(&p, 1, 1);
		st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_MALLOC, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_FSTORE, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_FIELD, 0, -1, -1, 0), -1), 0, 0);
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 1, 2, 1, 0, 1, 0, 0, 0, 0, 0, 0 }, "field");

		/* 3. a call's result: the return of a function that reaches a node is the obligation SUMM discharges. LOCS must not run. */
		lg_h_new(&p, 2, 0);
		st(p.fn[1].body, LG_S_RET, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 1, ex(LG_E_CALL, 1, -1, -1, 0), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 1, -1, -1, 0), -1), 0, 0);
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 2, 3, 0, 1, 1, 0, 0, 0, 0, 0, 0 }, "call");

		/* 4. both, one inside the other: a call's result stored in a field and read back. The obligation is W_MEM after the
		 * cheap stage, W_CALL after LOCS, and is gone after SUMM: three runs of that function, and the callee read once. */
		lg_h_new(&p, 2, 1);
		st(p.fn[1].body, LG_S_RET, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_MALLOC, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_FSTORE, 0, ex(LG_E_CALL, 1, -1, -1, 0), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_FIELD, 0, -1, -1, 0), -1), 0, 0);
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 2, 4, 1, 1, 1, 0, 0, 0, 0, 0, 0 }, "call in field");
		/* ... and with only one of the two stages the class allows, the input stays in the unresolved set and says why: without
		 * SUMM the call's result is what is unknown, without LOCS the cell is - and SUMM is not asked for, because what reaches the
		 * consumer is not a call's result but a load the cheap stage cannot follow */
		g_next = 3;       /* CALL: SUMM exists and the class does not run it */
		check(target, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS, &(struct want){ 2, 3, 1, 0, 0, 1, KGENOME_LINEAGE_W_CALL, 0, 0, 0, 0 },
		      "call in field, no SUMM");
		g_next = 3;       /* MEM: LOCS exists and the class does not run it */
		check(target, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SUMM, &(struct want){ 2, 2, 0, 0, 0, 1, KGENOME_LINEAGE_W_MEM, 0, 0, 0, 0 },
		      "call in field, no LOCS");

		/* 5. a stage that must NOT run: a global that is only read. LOCS can only follow a store the function made, and there is
		 * none - so the stage is not asked for and the limit is named for what it is: a cell this function never wrote (W_CELL). */
		lg_h_new(&p, 1, 0);
		p.ng = 1;
		p.g_owner[0] = 0;
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_GLOBAL, 0, -1, -1, 0), -1), 0, 0);
		g_next = 4;       /* CELL: a cell this function never wrote - no stage reads it */
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 1, 1, 0, 0, 0, 1, KGENOME_LINEAGE_W_CELL, 0, 0, 0, 0 }, "global read");
		/* ... and when the function does store to it, it is */
		lg_h_new(&p, 1, 0);
		p.ng = 1;
		p.g_owner[0] = 0;
		sock = api(LG_SOCKET, -1, -1);
		st(p.fn[0].body, LG_S_GSTORE, 0, sock, 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_GLOBAL, 0, -1, -1, 0), -1), 0, 0);
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 1, 2, 1, 0, 1, 0, 0, 0, 0, 0, 0 }, "global stored and read");

		/* 6. a call to a function that reaches no node: not read at first, and read after all when its result reaches a consumer
		 * (the caller's pending W_SKIP): here it returns a constant, so nothing is left unresolved. */
		lg_h_new(&p, 2, 0);
		st(p.fn[1].body, LG_S_RET, 0, ex(LG_E_CONST, 0, -1, -1, 0), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 1, ex(LG_E_CALL, 1, -1, -1, 0), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 1, -1, -1, 0), -1), 0, 0);
		/* read on demand: the caller (its first read is not counted: its links come from the second) and the callee; the constant it returns needs no SUMM run */
		check(target, KGENOME_LINEAGE_S_ALL | KGENOME_LINEAGE_S_DEMAND, &(struct want){ 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "call to a function with no node");
		/* ... and without the stage the callee stays unread and the result is the limit it is */
		g_next = 3;       /* SKIP: reading it on demand exists and the class does not run it */
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 1, 1, 0, 0, 0, 1, KGENOME_LINEAGE_W_SKIP, 1, 0, 0, 0 }, "call to a function with no node, no demand");

		/* 7. a call through a pointer: no stage reads it, and the reason is reported for whoever wants a dearer reading */
		lg_h_new(&p, 1, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 1, ex(LG_E_ICALL, 0, ex(LG_E_CONST, 0, -1, -1, 0), -1, 1), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 1, -1, -1, 0), -1), 0, 0);
		g_next = 4;       /* EXT: nothing reads a callee nobody names */
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 1, 1, 0, 0, 0, 1, KGENOME_LINEAGE_W_EXT, 0, 0, 0, 0 }, "call through a pointer");

		/* 8. a constant is resolved: no producer, nothing unknown, nothing in the set */
		lg_h_new(&p, 1, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_CONST, 0, -1, -1, 0), -1), 0, 0);
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "a constant");

		/* 8b. EVERY LIMIT HAS ITS OWN REASON, and an input stopped by one is reported with that one and no other. Each program is
		 * one limit; the stage set is the plan's (ALL) unless the limit is what a missing stage leaves. */
		{
			static const struct { const char *name; unsigned why; unsigned stages; } lim[] = {
				{ "entry",    KGENOME_LINEAGE_W_ENTRY,    KGENOME_LINEAGE_S_FLOW },
				{ "nocaller", KGENOME_LINEAGE_W_NOCALLER, KGENOME_LINEAGE_S_ALL },
				{ "computed", KGENOME_LINEAGE_W_COMPUTED, KGENOME_LINEAGE_S_ALL },
				{ "narrow",   KGENOME_LINEAGE_W_NARROW,   KGENOME_LINEAGE_S_ALL },
				{ "slot",     KGENOME_LINEAGE_W_SLOT,     KGENOME_LINEAGE_S_ALL },
				{ "clobber",  KGENOME_LINEAGE_W_CLOBBER,  KGENOME_LINEAGE_S_ALL },
				{ "status",   KGENOME_LINEAGE_W_STATUS,   KGENOME_LINEAGE_S_ALL },
				{ "addr",     KGENOME_LINEAGE_W_ADDR,     KGENOME_LINEAGE_S_ALL },
				{ "unreach",  KGENOME_LINEAGE_W_UNREACH,  KGENOME_LINEAGE_S_ALL },
			};
			unsigned li;

			for (li = 0; li < sizeof lim / sizeof lim[0]; li++) {
				int arg = -1, blk = p.fn[0].body;

				/* (a stale argument register is a stack word on a stack-argument target: another limit there) */
				if (!strcmp(lim[li].name, "clobber") && (target == LG_T_ELF32 || target == LG_T_PE32))
					continue;
				lg_h_new(&p, 1, !strcmp(lim[li].name, "addr"));
				blk = p.fn[0].body;
				if (!strcmp(lim[li].name, "entry") || !strcmp(lim[li].name, "nocaller")) {
					p.fn[0].nparams = 1;
					arg = ex(LG_E_PARAM, 0, -1, -1, 0);
				} else if (!strcmp(lim[li].name, "computed")) {
					arg = ex(LG_E_ARITH, 0, ex(LG_E_CONST, 0, -1, -1, 0), -1, 1);
				} else if (!strcmp(lim[li].name, "narrow")) {
					arg = ex(LG_E_BYTE, 0, ex(LG_E_CONST, 0, -1, -1, 0), -1, 1);
				} else if (!strcmp(lim[li].name, "slot")) {
					arg = ex(LG_E_VAR, 4, -1, -1, 0);               /* a local nothing wrote */
				} else if (!strcmp(lim[li].name, "clobber")) {
					arg = ex(LG_E_STALE, 0, -1, -1, 0);
				} else if (!strcmp(lim[li].name, "status")) {
					arg = api(LG_READ, ex(LG_E_CONST, 0, -1, -1, 0), ex(LG_E_CONST, 0, -1, -1, 0));
				} else if (!strcmp(lim[li].name, "addr")) {
					st(blk, LG_S_ASSIGN, 0, ex(LG_E_UNK, 0, -1, -1, 0), 0, 0);       /* the object is a pointer nothing names */
					arg = ex(LG_E_FIELD, 0, -1, -1, 0);
				} else {
					int dead = lg_newblk(&p);

					p.fn[0].dead = dead;
					p.fn[0].nparams = 1;
					st(dead, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_PARAM, 0, -1, -1, 0), -1), 0, 0);
					check(target, lim[li].stages, &(struct want){ 1, 1, 0, 0, 0, 1, lim[li].why, 1, 0, 0, 0 }, lim[li].name);
					continue;
				}
				st(blk, LG_S_EVAL, 0, api(LG_CONNECT, arg, -1), 0, 0);
				g_next = !strcmp(lim[li].name, "entry") ? 3 : 4;      /* entry: no SUMM in this stage set; the others: no stage reads them */
				check(target, lim[li].stages, &(struct want){ 1, 1, 0, 0, 0, 1, lim[li].why, 1, 0, 0, 0 }, lim[li].name);
			}
		}

		/* 8c. A CALL THE PROGRAM DOES NOT COME BACK FROM ends its block (a function of the object with no ret, no jump out, and a call).
		 * socket(); stop(); connect(it) - the connect is never reached, so no link and no state carried into whatever follows; the
		 * same program where stop() returns has the link. And in code no walk reaches, where a seed would carry the state across. */
		{
			int halts;

			for (halts = 0; halts < 2; halts++) {
				int blk, dead;

				lg_h_new(&p, 2, 0);
				p.fn[1].halts = halts;
				st(p.fn[1].body, LG_S_EVAL, 0, api(LG_SOCKET, -1, -1), 0, 0);
				st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
				st(p.fn[0].body, LG_S_EVAL, 0, ex(LG_E_CALL, 1, -1, -1, 0), 0, 0);
				st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
				check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 2, 2, 0, 0, halts ? 0u : 1u, halts ? 1u : 0u, halts ? KGENOME_LINEAGE_W_UNREACH : 0u, 1, 0, 0, 0 },
				      halts ? "stop() does not return" : "stop() returns");
				/* the same, in a region nothing reaches: a seed enters it at the socket */
				lg_h_new(&p, 2, 0);
				p.fn[1].halts = halts;
				st(p.fn[1].body, LG_S_EVAL, 0, api(LG_SOCKET, -1, -1), 0, 0);
				dead = lg_newblk(&p);
				blk = p.fn[0].body;
				p.fn[0].dead = dead;
				st(dead, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
				st(dead, LG_S_EVAL, 0, ex(LG_E_CALL, 1, -1, -1, 0), 0, 0);
				st(dead, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
				st(blk, LG_S_EVAL, 0, api(LG_SOCKET, -1, -1), 0, 0);
				{
					static struct lg_links got;
					struct lg_scan sc;

					if (lg_h_scan(&sc, &g, &c, &p, target, KGENOME_LINEAGE_S_ALL)) {
						lg_actual(&got, &sc);
						/* seeded: a MAY link when stop() returns, none when it does not */
						CK(got.n == (halts ? 0 : 1));
						kgenome_diag_scan_free(sc.s);
					} else {
						CK(0);
					}
				}
			}
		}

		/* 9. two producers on two paths: both known, so nothing is unresolved and the links are MAY */
		lg_h_new(&p, 1, 0);
		{
			int then = lg_newblk(&p), els = lg_newblk(&p);

			st(then, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
			sock1 = api(LG_SOCKET, -1, -1);
			st(els, LG_S_ASSIGN, 0, sock1, 0, 0);
			st(p.fn[0].body, LG_S_IF, 0, ex(LG_E_UNK, 0, -1, -1, 0), then, els);
			st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
		}
		check(target, KGENOME_LINEAGE_S_ALL, &(struct want){ 1, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0 }, "two paths");
	}
}

/*
 * THE CORNERS the random programs do not reach, one program each, with the link and the unresolved input they must give:
 * what a seeded caller does to its callee's link, the strength of a sink that took a parameter on some paths only, which
 * parameter a function returns, a tail jump that carries arguments, a seed that must not join the code the entry reached,
 * the reasons of a parameter nobody supplied, and the stack of a call whose callee pops what the code does not say.
 */
static void t_corners(void)
{
	int target;

	for (target = LG_T_ELF64; target <= LG_T_PE32; target++) {
		const unsigned all = KGENOME_LINEAGE_S_ALL;
		int then, els, dead;

		/* the callee takes the parameter, or a constant on one path: its sink is doubtful, and so is the link of a caller that passes
		 * a producer (MAY - not MUST - though every execution that reaches the consumer got it from that producer or a constant) */
		lg_h_new(&p, 2, 0);
		p.fn[1].nparams = 1;
		then = lg_newblk(&p);
		st(p.fn[1].body, LG_S_ASSIGN, 0, ex(LG_E_PARAM, 0, -1, -1, 0), 0, 0);
		st(then, LG_S_ASSIGN, 0, ex(LG_E_CONST, 0, -1, -1, 0), 0, 0);
		st(p.fn[1].body, LG_S_IF, 0, ex(LG_E_UNK, 0, -1, -1, 0), then, -1);
		st(p.fn[1].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, ex(LG_E_CALL, 1, ex(LG_E_VAR, 0, -1, -1, 0), -1, 1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0 }, "sink of a parameter that is a constant on a path");

		/* a function returns its SECOND parameter: the producer is the second argument's */
		lg_h_new(&p, 2, 0);
		p.fn[1].nparams = 2;
		st(p.fn[1].body, LG_S_RET, 0, ex(LG_E_PARAM, 1, -1, -1, 0), 0, 0);
		{
			const int a0 = api(LG_SOCKET, -1, -1), a1 = api(LG_MALLOC, -1, -1);

			st(p.fn[0].body, LG_S_ASSIGN, 0, ex(LG_E_CALL, 1, a0, a1, 2), 0, 0);
		}
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
		check(target, all | KGENOME_LINEAGE_S_DEMAND, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 2 }, "returns its second parameter");
		check(target, all, &(struct want){ 0, 0, 0, 0, 0, 1, KGENOME_LINEAGE_W_SKIP, 0, 0, 0, 0 }, "returns its second parameter, no demand");

		/* a tail jump that carries an argument: return f1(s) */
		lg_h_new(&p, 2, 0);
		p.fn[0].nparams = 1;
		p.fn[1].nparams = 1;
		st(p.fn[1].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_PARAM, 0, -1, -1, 0), -1), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_TAIL, 0, ex(LG_E_CALL, 1, ex(LG_E_VAR, 0, -1, -1, 0), -1, 1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 2 }, "tail jump with an argument");

		/* TAIL JUMPS between functions of the program (on i386 only where the function was given as many words as it passes on: then the
		 * jump keeps the arguments where they are, one word further up than a call's): what the last function returns is what
		 * the first one does, and a parameter passed on reaches the consumer two functions down */
		lg_h_new(&p, 3, 0);
		st(p.fn[2].body, LG_S_RET, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[1].body, LG_S_TAIL, 0, ex(LG_E_CALL, 2, -1, -1, 0), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, ex(LG_E_CALL, 1, -1, -1, 0), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1 }, "tail jump: what it returns");
		lg_h_new(&p, 3, 0);
		p.fn[1].nparams = 1;
		p.fn[2].nparams = 1;
		st(p.fn[2].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_PARAM, 0, -1, -1, 0), -1), 0, 0);
		st(p.fn[1].body, LG_S_TAIL, 0, ex(LG_E_CALL, 2, ex(LG_E_PARAM, 0, -1, -1, 0), -1, 1), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, ex(LG_E_CALL, 1, ex(LG_E_VAR, 0, -1, -1, 0), -1, 1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 2 }, "tail jump: a parameter passed on");

		/* a helper with no node that passes its parameter to a function with a sink: it is read (a callee has a summary a caller can
		 * use), and the link runs through both */
		lg_h_new(&p, 3, 0);
		p.fn[1].nparams = 1;
		p.fn[2].nparams = 1;
		st(p.fn[2].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_PARAM, 0, -1, -1, 0), -1), 0, 0);
		st(p.fn[1].body, LG_S_EVAL, 0, ex(LG_E_CALL, 2, ex(LG_E_PARAM, 0, -1, -1, 0), -1, 1), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, ex(LG_E_CALL, 1, ex(LG_E_VAR, 0, -1, -1, 0), -1, 1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 2 }, "a helper that passes a parameter to a sink");

		/* what a seeded region leaves unaccounted for asks for a stage like anything else: a call's result in a region no walk
		 * reached needs SUMM (the function is read again, with its seeds), a field of an object it made needs LOCS */
		lg_h_new(&p, 2, 0);
		st(p.fn[1].body, LG_S_RET, 0, api(LG_SOCKET, -1, -1), 0, 0);
		dead = lg_newblk(&p);
		p.fn[0].dead = dead;
		st(dead, LG_S_ASSIGN, 0, ex(LG_E_CALL, 1, -1, -1, 0), 0, 0);
		st(dead, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 1 }, "a seeded call's result needs SUMM");
		lg_h_new(&p, 1, 1);
		dead = lg_newblk(&p);
		p.fn[0].dead = dead;
		st(dead, LG_S_ASSIGN, 0, api(LG_MALLOC, -1, -1), 0, 0);
		st(dead, LG_S_FSTORE, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(dead, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_FIELD, 0, -1, -1, 0), -1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 2 }, "a seeded field needs LOCS");

		/* a region no walk reaches that ends in the epilogue the entry reached: the seed must not join into it, or what the region
		 * leaves in rax would be what the function returns */
		lg_h_new(&p, 2, 0);
		dead = lg_newblk(&p);
		p.fn[1].dead = dead;
		st(dead, LG_S_EVAL, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, ex(LG_E_CALL, 1, -1, -1, 0), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "a seed does not join the epilogue the entry reached");

		/* a caller in a region no walk reaches is a context of its callee: it passes a constant, so the link a reached caller makes is
		 * MAY with the seed and MUST without it */
		lg_h_new(&p, 2, 0);
		p.fn[1].nparams = 1;
		st(p.fn[1].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_PARAM, 0, -1, -1, 0), -1), 0, 0);
		st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(p.fn[0].body, LG_S_EVAL, 0, ex(LG_E_CALL, 1, ex(LG_E_VAR, 0, -1, -1, 0), -1, 1), 0, 0);
		dead = lg_newblk(&p);
		p.fn[0].dead = dead;
		st(dead, LG_S_EVAL, 0, ex(LG_E_CALL, 1, ex(LG_E_CONST, 0, -1, -1, 0), -1, 1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0 }, "a seeded caller is a context");
		check(target, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SUMM, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0 },
		      "without the seed the link is sure");

		/* a seeded caller with a producer: the link through it is MAY, whatever the callee's sink says */
		lg_h_new(&p, 2, 0);
		p.fn[1].nparams = 1;
		st(p.fn[1].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_PARAM, 0, -1, -1, 0), -1), 0, 0);
		dead = lg_newblk(&p);
		p.fn[0].dead = dead;
		st(dead, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(dead, LG_S_EVAL, 0, ex(LG_E_CALL, 1, ex(LG_E_VAR, 0, -1, -1, 0), -1, 1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0 }, "a link through a seeded call is MAY");

		/* a callee whose only caller is code no walk reached, with no seed: its parameter is a parameter nobody was seen to supply */
		lg_h_new(&p, 2, 0);
		p.fn[1].nparams = 1;
		st(p.fn[1].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_PARAM, 0, -1, -1, 0), -1), 0, 0);
		dead = lg_newblk(&p);
		p.fn[0].dead = dead;
		st(dead, LG_S_EVAL, 0, ex(LG_E_CALL, 1, ex(LG_E_CONST, 0, -1, -1, 0), -1, 1), 0, 0);
		g_next = 2;       /* ENTRY with SUMM on: the parameter machinery ran, no caller was seen to supply it */
		check(target, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SUMM, &(struct want){ 0, 0, 0, 0, 0, 1, KGENOME_LINEAGE_W_ENTRY, 1, 0, 0, 0 },
		      "a parameter whose callers were not seen");

		/* a producer on one path and a parameter nobody supplies on the other: the link is MAY and the input is partly known */
		lg_h_new(&p, 1, 0);
		p.fn[0].nparams = 1;
		then = lg_newblk(&p);
		els = lg_newblk(&p);
		st(then, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(els, LG_S_ASSIGN, 0, ex(LG_E_PARAM, 0, -1, -1, 0), 0, 0);
		st(p.fn[0].body, LG_S_IF, 0, ex(LG_E_UNK, 0, -1, -1, 0), then, els);
		st(p.fn[0].body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_VAR, 0, -1, -1, 0), -1), 0, 0);
		check(target, all, &(struct want){ 0, 0, 0, 0, 1, 1, KGENOME_LINEAGE_W_NOCALLER, 1, 2, 1, 1 }, "a producer or a parameter nobody supplies");

		/* the stack of a stdcall call that cannot be followed: a call through a pointer inside the arguments of another */
		if (target == LG_T_PE32) {
			lg_h_new(&p, 1, 0);
			st(p.fn[0].body, LG_S_ASSIGN, 0, api(LG_SOCKET, -1, -1), 0, 0);
			st(p.fn[0].body, LG_S_EVAL, 0,
			   api(LG_WRITE, ex(LG_E_VAR, 0, -1, -1, 0), ex(LG_E_ICALL, 0, ex(LG_E_CONST, 0, -1, -1, 0), -1, 1)), 0, 0);
			check(target, all, &(struct want){ 0, 0, 0, 0, 0, 2, KGENOME_LINEAGE_W_STACK, 0, 0, 0, 0 }, "pending pushes, a callee that pops an unknown count");
		}
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_chain();
	t_corners();
	t_equivalence();
	printf("lineage_chain: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
