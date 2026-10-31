/*
 * gview_data - the DATA of a graph to look at (celllysis/gview.h, gview_data.c, gview_loops.c, cfg_gv.c), through <kgenome.h> alone. The places are the viewer's and are
 * tested in tests/unit/kx_graph.c; what is held here is what the engine DECIDES about the graph:
 *
 *   KINDS     an edge has two independent properties, cond (none / T / F) and loop (none / loop link / retreating); a block's edges stand fall-through first and taken
 *             second; a loop link is a back edge whose target DOMINATES its source and its target is a loop head (flag, and `@` in the first row); an irreducible cycle is
 *             RETREAT with no head. The graphs: the six hand-built ones of the earlier drawing tests (a straight line, a diamond, a loop, a nested loop, a fan-out, a
 *             self-loop), the reachable part of attack_kill_all (the Mirai function whose picture the owner judged), a `while(1)` (an unconditional back edge), two loop
 *             links into one head, and an irreducible graph (two entries into a cycle).
 *   ORACLE    the loop marks of 600 random graphs of up to 12 nodes (fixed seeds) equal a brute-force oracle written here: dominator sets by the textbook fixed point over
 *             bit sets, retreating edges by a recursive walk. The mutant that swaps cond and loop, and the one that swaps T and F, are caught by the row they break.
 *   MEMORY    kgenome_gv_alloc and kgenome_gv_loops under an allocator that refuses the Nth call for every N and under a budget below what they need: a status, nothing held.
 *   BOUNDS    a graph past KGENOME_GV_DOM_MAX nodes: every retreating edge is RETREAT, no head is marked, the status is TRUNCATED (not computed is said, not guessed);
 *             200000 nodes with loops: marked within a time bound.
 *   BOX       kgenome_gv_box_line: the two rows, at most KGENOME_GV_BOX_X extra lines, then `+N more calls`; a node past the table is NULL.
 */
#include "cfg_kit.h"

#define NN KGENOME_CFG_NONE
struct g { uint8_t term; uint32_t s0, s1; };
struct spec { const char *name; const struct g *g; uint32_t n; uint32_t n_unr; };
static const struct g G_line[]={{0,1,NN},{0,2,NN},{3,NN,NN}};
static const struct g G_dia[]={{1,2,1},{0,3,NN},{0,3,NN},{3,NN,NN}};
static const struct g G_loop[]={{0,1,NN},{1,2,3},{2,1,NN},{3,NN,NN}};
static const struct g G_nest[]={{0,1,NN},{1,2,6},{0,3,NN},{1,4,5},{2,3,NN},{2,1,NN},{3,NN,NN}};
static const struct g G_fan[]={{1,1,2},{1,3,4},{1,5,6},{3,NN,NN},{3,NN,NN},{3,NN,NN},{3,NN,NN}};
static const struct g G_self[]={{0,1,NN},{1,1,2},{3,NN,NN}};
static const struct g G_kill[]={{2,2,NN},{1,4,2},{1,1,3},{1,2,4},{3,NN,NN}};              /* B0 jmp B2; B1 T B4 F B2; B2 T B1 F B3; B3 T B2 F B4; B4 ret */
static const struct g G_while[]={{0,1,NN},{0,2,NN},{2,1,NN}};                            /* B2 jmp B1: an unconditional loop link */
static const struct g G_two[]={{0,1,NN},{1,2,3},{1,1,4},{1,1,4},{3,NN,NN}};              /* B2 and B3 both go back to B1 */
static const struct g G_irr[]={{1,1,2},{0,2,NN},{1,1,3},{3,NN,NN}};                      /* B0 T B1 F B2; B1 -> B2; B2 T B1 F B3: B1 and B2 form a cycle with two entries */
static const struct spec SPEC[]={{"line",G_line,3,0},{"diamond",G_dia,4,0},{"loop",G_loop,4,0},{"nested",G_nest,7,0},{"fan",G_fan,7,0},{"self",G_self,3,0},
	{"kill",G_kill,5,0},{"while",G_while,3,0},{"two",G_two,5,0},{"irreducible",G_irr,4,0}};
#define N_SPEC (sizeof SPEC/sizeof SPEC[0])

static void build_spec(const struct spec *s, struct kgenome_cfg_view *v, struct kgenome_cfg_view_block *b, struct kgenome_cfg_view_unreach *u)
{
	uint32_t i;

	memset(v, 0, sizeof *v);
	memset(b, 0, 16 * sizeof *b);
	for (i = 0; i < s->n; i++) {
		b[i].off = 0x1000 + 0x10 * i; b[i].n_insn = 3 + i; b[i].term = s->g[i].term; b[i].succ[0] = s->g[i].s0; b[i].succ[1] = s->g[i].s1; b[i].label = 0xa0 + i;
		b[i].out_deg = (uint8_t)((s->g[i].s0 != NN) + (s->g[i].s1 != NN));
	}
	for (i = 0; i < s->n; i++) {
		if (s->g[i].s0 != NN) b[s->g[i].s0].in_deg++;
		if (s->g[i].s1 != NN) b[s->g[i].s1].in_deg++;
		v->n_edge += b[i].out_deg;
	}
	for (i = 0; i < s->n_unr; i++) { u[i].off = 0x2000 + 0x20 * i; u[i].n_insn = 2 + i; }
	v->n_blk = s->n; v->blk = b; v->n_unr = s->n_unr; v->unr = u; v->canon = 0x1122334455667788ull; v->n_key = 3; v->key[0] = 0x11; v->key[1] = 0x2222; v->key[2] = 0xdeadbeef;
}

/* ---- the oracle: dominators by bit sets, retreating edges by a recursive walk (n <= 32) ---- */

struct og { uint32_t n; uint32_t ne; uint32_t from[64], to[64]; };

static void o_walk(const struct og *g, uint32_t u, uint8_t *st, uint8_t *ret)
{
	uint32_t e;

	st[u] = 1;
	for (e = 0; e < g->ne; e++) {
		if (g->from[e] != u)
			continue;
		if (st[g->to[e]] == 1)
			ret[e] = 1;
		else if (!st[g->to[e]])
			o_walk(g, g->to[e], st, ret);
	}
	st[u] = 2;
}

/* want[e]: 0 none, 1 loop link, 2 retreat; head[v]. */
static void oracle(const struct og *g, uint32_t entry, uint8_t *want, uint8_t *head)
{
	uint32_t dom[32], full = g->n == 32 ? 0xffffffffu : (1u << g->n) - 1u, i, e, ch = 1;
	uint8_t st[32], ret[64];

	memset(st, 0, sizeof st);
	memset(ret, 0, sizeof ret);
	o_walk(g, entry, st, ret);
	for (i = 0; i < g->n; i++)
		dom[i] = i == entry ? 1u << entry : full;
	while (ch) {
		ch = 0;
		for (i = 0; i < g->n; i++) {
			uint32_t d = full, any = 0;

			if (i == entry || !st[i])
				continue;
			for (e = 0; e < g->ne; e++)
				if (g->to[e] == i && st[g->from[e]]) {
					d &= dom[g->from[e]];
					any = 1;
				}
			d = (any ? d : 0u) | (1u << i);
			if (d != dom[i]) {
				dom[i] = d;
				ch = 1;
			}
		}
	}
	memset(head, 0, g->n);
	for (e = 0; e < g->ne; e++) {
		want[e] = 0;
		if (!ret[e])
			continue;
		if (dom[g->from[e]] & (1u << g->to[e])) {
			want[e] = 1;
			head[g->to[e]] = 1;
		} else {
			want[e] = 2;
		}
	}
}

/* ---- a counting allocator ---- */

static unsigned long vt_live;
static unsigned vt_nth, vt_calls;

static void *vt_alloc(void *user, size_t n)
{
	(void)user;
	if (vt_nth && ++vt_calls == vt_nth)
		return NULL;
	vt_live++;
	return malloc(n);
}

static void vt_release(void *user, void *p, size_t n)
{
	(void)user; (void)n;
	if (p)
		vt_live--;
	free(p);
}

/* ---- the hand-built graphs ---- */

static const char *loop_name(unsigned l) { return l == 0 ? "none" : l == 1 ? "LOOP" : "RETREAT"; }

/* The graph of `s` through the filler, and the edges' cond and loop and the heads against the oracle that reads the same graph. */
static void fill_and_check(const struct spec *s, struct kgenome_gv *gv, struct kgenome_cfg_view *v, struct kgenome_cfg_view_block *b, struct kgenome_cfg_view_unreach *u)
{
	struct kgenome_cfg_gv_req rq;
	struct og og;
	uint8_t want[64], head[32];
	uint32_t e, i;

	build_spec(s, v, b, u);
	memset(&rq, 0, sizeof rq);
	rq.v = v;
	CKM(kgenome_cfg_gv_make(&rq, gv) <= KGENOME_TRUNCATED, "%s: no graph", s->name);
	CKM(gv->n_node == s->n && gv->n_edge == v->n_edge, "%s: nodes %u edges %u", s->name, gv->n_node, gv->n_edge);
	og.n = s->n;
	og.ne = gv->n_edge;
	for (e = 0; e < gv->n_edge; e++) {
		og.from[e] = gv->edge[e].from;
		og.to[e] = gv->edge[e].to;
	}
	oracle(&og, 0, want, head);
	for (e = 0; e < gv->n_edge; e++)
		CKM(gv->edge[e].loop == want[e], "%s: edge %u (B%u -> B%u) loop %s, the oracle says %s", s->name, e, gv->edge[e].from, gv->edge[e].to, loop_name(gv->edge[e].loop),
		    loop_name(want[e]));
	for (i = 0; i < gv->n_node; i++) {
		CKM(((gv->node[i].flags & KGENOME_GV_NF_LOOP_HEAD) != 0) == head[i], "%s: B%u head flag %u, the oracle says %u", s->name, i, gv->node[i].flags & 1u, head[i]);
		CKM((strstr(gv->node[i].line[0], " @ ") != NULL) == head[i], "%s: B%u first row '%s' vs head %u", s->name, i, gv->node[i].line[0], head[i]);
	}
}

static void hand_built(void)
{
	struct kgenome_cfg_view v;
	struct kgenome_cfg_view_block b[16];
	struct kgenome_cfg_view_unreach u[4];
	struct kgenome_gv gv;
	size_t k;
	uint32_t e, i;

	for (k = 0; k < N_SPEC; k++) {
		const struct spec *s = &SPEC[k];

		fill_and_check(s, &gv, &v, b, u);
		/* the edges of a node stand fall-through first, taken second: a COND block gives F then T, every other block gives cond none */
		for (i = 0; i < gv.n_node; i++) {
			uint32_t n = 0, first = 0xffffffffu;

			for (e = 0; e < gv.n_edge; e++) {
				if (gv.edge[e].from != i)
					continue;
				if (b[i].term == KGENOME_CFG_T_COND) {
					CKM(gv.edge[e].cond == (n ? KGENOME_GV_COND_T : KGENOME_GV_COND_F), "%s: B%u edge %u cond %u", s->name, i, n, gv.edge[e].cond);
					CKM(gv.edge[e].to == (n ? b[i].succ[0] : b[i].succ[1]), "%s: B%u edge %u goes to B%u", s->name, i, n, gv.edge[e].to);
				} else {
					CKM(gv.edge[e].cond == KGENOME_GV_COND_NONE, "%s: B%u is not a branch and its edge has cond %u", s->name, i, gv.edge[e].cond);
				}
				if (!n)
					first = e;
				n++;
			}
			CKM(n == b[i].out_deg, "%s: B%u has %u edges, the view says %u", s->name, i, n, b[i].out_deg);
			(void)first;
		}
		CKM(strstr(gv.head[0], "legend") == NULL, "%s: a legend line in the head", s->name);
		for (i = 0; i < gv.n_head; i++)
			CKM(strstr(gv.head[i], "letters") == NULL && strstr(gv.head[i], "legend") == NULL, "%s: head row %u is prose: %s", s->name, i, gv.head[i]);
		kgenome_gv_free(&gv, NULL);
	}
	/* the pictures the owner named */
	{
		uint32_t links = 0, retreat = 0, heads = 0;

		fill_and_check(&SPEC[6], &gv, &v, b, u);                  /* attack_kill_all: B1 F->B2 and B3 T->B2 are loop links, B2 is the head */
		for (e = 0; e < gv.n_edge; e++) {
			links += gv.edge[e].loop == KGENOME_GV_LOOP_LINK;
			retreat += gv.edge[e].loop == KGENOME_GV_LOOP_RETREAT;
		}
		for (i = 0; i < gv.n_node; i++)
			heads += (gv.node[i].flags & KGENOME_GV_NF_LOOP_HEAD) != 0;
		CKM(links == 2 && retreat == 0 && heads == 1 && (gv.node[2].flags & KGENOME_GV_NF_LOOP_HEAD), "kill: %u loop links, %u retreating, %u heads", links, retreat, heads);
		for (e = 0; e < gv.n_edge; e++)
			if (gv.edge[e].from == 1 && gv.edge[e].to == 2)
				CK(gv.edge[e].cond == KGENOME_GV_COND_F && gv.edge[e].loop == KGENOME_GV_LOOP_LINK);
			else if (gv.edge[e].from == 3 && gv.edge[e].to == 2)
				CK(gv.edge[e].cond == KGENOME_GV_COND_T && gv.edge[e].loop == KGENOME_GV_LOOP_LINK);
			else if (gv.edge[e].from == 0)
				CK(gv.edge[e].cond == KGENOME_GV_COND_NONE && gv.edge[e].loop == KGENOME_GV_LOOP_NONE);
			else
				CK(gv.edge[e].cond != KGENOME_GV_COND_NONE && gv.edge[e].loop == KGENOME_GV_LOOP_NONE);
		kgenome_gv_free(&gv, NULL);
		fill_and_check(&SPEC[7], &gv, &v, b, u);                  /* while(1): the back edge is a loop link with no cond */
		for (e = 0; e < gv.n_edge; e++)
			if (gv.edge[e].from == 2)
				CK(gv.edge[e].cond == KGENOME_GV_COND_NONE && gv.edge[e].loop == KGENOME_GV_LOOP_LINK);
		kgenome_gv_free(&gv, NULL);
		fill_and_check(&SPEC[5], &gv, &v, b, u);                  /* a self-loop: a loop link onto its own box, the head is that box */
		for (e = 0; e < gv.n_edge; e++)
			if (gv.edge[e].from == 1 && gv.edge[e].to == 1)
				CK(gv.edge[e].loop == KGENOME_GV_LOOP_LINK && (gv.node[1].flags & KGENOME_GV_NF_LOOP_HEAD));
		kgenome_gv_free(&gv, NULL);
		fill_and_check(&SPEC[8], &gv, &v, b, u);                  /* two loop links into one head */
		links = 0;
		for (e = 0; e < gv.n_edge; e++)
			links += gv.edge[e].loop == KGENOME_GV_LOOP_LINK && gv.edge[e].to == 1;
		CKM(links == 2 && (gv.node[1].flags & KGENOME_GV_NF_LOOP_HEAD), "two: %u loop links into B1", links);
		kgenome_gv_free(&gv, NULL);
		fill_and_check(&SPEC[3], &gv, &v, b, u);                  /* nested: two heads */
		heads = 0;
		for (i = 0; i < gv.n_node; i++)
			heads += (gv.node[i].flags & KGENOME_GV_NF_LOOP_HEAD) != 0;
		CKM(heads == 2, "nested: %u heads", heads);
		kgenome_gv_free(&gv, NULL);
		fill_and_check(&SPEC[9], &gv, &v, b, u);                  /* irreducible: a retreating edge that is no loop link, and no head */
		links = retreat = heads = 0;
		for (e = 0; e < gv.n_edge; e++) {
			links += gv.edge[e].loop == KGENOME_GV_LOOP_LINK;
			retreat += gv.edge[e].loop == KGENOME_GV_LOOP_RETREAT;
		}
		for (i = 0; i < gv.n_node; i++)
			heads += (gv.node[i].flags & KGENOME_GV_NF_LOOP_HEAD) != 0;
		CKM(links == 0 && retreat >= 1 && heads == 0, "irreducible: %u loop links, %u retreating, %u heads", links, retreat, heads);
		kgenome_gv_free(&gv, NULL);
	}
}

/* 600 random graphs against the oracle. */
static void random_graphs(void)
{
	struct crng r;
	unsigned t;

	crng_seed(&r, 20261031u);
	for (t = 0; t < 600; t++) {
		const uint32_t n = 1u + crng_below(&r, 12u);
		struct kgenome_gv gv;
		struct og og;
		uint8_t want[64], head[32];
		uint32_t e, i, ne = 0, pos = 0;

		for (i = 0; i < n; i++) {
			const uint32_t deg = crng_below(&r, 4u);

			for (e = 0; e < deg && ne < 60; e++) {
				og.from[ne] = i;
				og.to[ne] = crng_below(&r, n);
				ne++;
			}
		}
		og.n = n;
		og.ne = ne;
		if (kgenome_gv_alloc(&gv, &(const struct kgenome_gv_size){ .n_node = n, .n_edge = ne }, NULL, NULL) != KGENOME_OK) {
			CK(0);
			return;
		}
		for (e = 0; e < ne; e++) {
			gv.edge[e].from = og.from[e];
			gv.edge[e].to = og.to[e];
			gv.edge[e].cond = (uint8_t)crng_below(&r, 3u);
		}
		CK(kgenome_gv_loops(&gv, NULL, NULL) == KGENOME_OK);
		oracle(&og, 0, want, head);
		for (e = 0; e < ne; e++)
			CKM(gv.edge[e].loop == want[e], "graph %u edge %u (%u -> %u): loop %s, oracle %s", t, e, og.from[e], og.to[e], loop_name(gv.edge[e].loop), loop_name(want[e]));
		for (i = 0; i < n; i++)
			CKM(((gv.node[i].flags & KGENOME_GV_NF_LOOP_HEAD) != 0) == head[i], "graph %u node %u head %u, oracle %u", t, i, gv.node[i].flags & 1u, head[i]);
		/* marking again, after the edges were marked, gives the same marks (it does not depend on what was there) */
		for (e = 0; e < ne; e++)
			gv.edge[e].loop = (uint8_t)crng_below(&r, 3u);
		CK(kgenome_gv_loops(&gv, NULL, NULL) == KGENOME_OK);
		for (e = 0; e < ne; e++)
			pos += gv.edge[e].loop != want[e];
		CKM(pos == 0, "graph %u: marking twice differs in %u edges", t, pos);
		kgenome_gv_free(&gv, NULL);
	}
}

/* Allocator refusals and budgets. */
static void memory(void)
{
	struct kgenome_cfg_view v;
	struct kgenome_cfg_view_block b[16];
	struct kgenome_cfg_view_unreach u[4];
	struct kgenome_cfg_gv_req rq;
	struct kgenome_gv gv;
	struct kgenome_budget bud;
	unsigned n;
	uint64_t m, first_ok = 0;

	build_spec(&SPEC[6], &v, b, u);
	memset(&rq, 0, sizeof rq);
	memset(&bud, 0, sizeof bud);
	rq.v = &v;
	rq.mem.alloc = vt_alloc;
	rq.mem.release = vt_release;
	/* every Nth allocation refused: a status, the head still said, nothing held */
	for (n = 1; n <= 4; n++) {
		vt_calls = 0; vt_nth = n; vt_live = 0;
		(void)kgenome_cfg_gv_make(&rq, &gv);
		if (n == 1) {
			CKM(gv.status == KGENOME_NOMEM && gv.n_node == 0 && gv.n_head > 0, "allocation 1 refused: status %d nodes %u head %u", (int)gv.status, gv.n_node, gv.n_head);
		} else {
			/* the graph is made; the loop marking's own allocation refused leaves every edge with loop none and says NOMEM */
			CKM(gv.n_node == 5 && gv.n_edge == 7, "allocation %u refused: nodes %u", n, gv.n_node);
			if (n == 2) {
				uint32_t e;

				CKM(gv.status == KGENOME_NOMEM, "the marking refused: status %d", (int)gv.status);
				for (e = 0; e < gv.n_edge; e++)
					CK(gv.edge[e].loop == KGENOME_GV_LOOP_NONE);
			}
		}
		kgenome_gv_free(&gv, &rq.mem);
		CKM(vt_live == 0, "allocation %u refused: %lu left", n, vt_live);
	}
	vt_nth = 0; vt_live = 0;
	(void)kgenome_cfg_gv_make(&rq, &gv);
	CK(gv.status == KGENOME_OK);
	kgenome_gv_free(&gv, &rq.mem);
	CK(vt_live == 0);
	/* a budget: below what the graph needs it says OVER_BUDGET and holds nothing; above, the same graph every time */
	rq.mem.alloc = NULL;
	rq.mem.release = NULL;
	rq.budget = &bud;
	for (m = 1; m < 30000; m += (m < 200 ? 1 : 211)) {
		bud.max_bytes = m;
		(void)kgenome_cfg_gv_make(&rq, &gv);
		if (gv.n_node == 0) {
			CKM(gv.status >= KGENOME_OVER_BUDGET && !first_ok, "budget %llu: no graph after an answer, status %d", (unsigned long long)m, (int)gv.status);
		} else {
			if (!first_ok)
				first_ok = m;
			CKM(gv.n_node == 5 && gv.n_edge == 7, "budget %llu: nodes %u edges %u", (unsigned long long)m, gv.n_node, gv.n_edge);
		}
		kgenome_gv_free(&gv, NULL);
	}
	CK(first_ok > 0);
}

/* The box rows. */
static void box_rows(void)
{
	struct kgenome_gv gv;
	char buf[64];
	const char *t;
	uint32_t i;

	CK(kgenome_gv_alloc(&gv, &(const struct kgenome_gv_size){ .n_node = 3, .n_xline = 7 }, NULL, NULL) == KGENOME_OK);
	snprintf(gv.xnoun, sizeof gv.xnoun, "calls");
	for (i = 0; i < 3; i++) {
		snprintf(gv.node[i].line[0], KGENOME_GV_LINE, "N%u", i);
		snprintf(gv.node[i].line[1], KGENOME_GV_LINE, "row2 %u", i);
	}
	for (i = 0; i < 7; i++) {
		gv.xline[i].node = i < 5 ? 1u : 2u;
		snprintf(gv.xline[i].text, KGENOME_GV_LINE, "call %u", i);
	}
	gv.node[1].xtotal = 9;                  /* 5 held, 9 in all */
	gv.node[2].xtotal = 2;                  /* all held */
	CK(!strcmp(kgenome_gv_box_line(&gv, 0, 0, buf, sizeof buf), "N0") && !strcmp(kgenome_gv_box_line(&gv, 0, 1, buf, sizeof buf), "row2 0"));
	CK(kgenome_gv_box_line(&gv, 0, 2, buf, sizeof buf) == NULL);                       /* no extra lines, none said */
	for (i = 0; i < KGENOME_GV_BOX_X; i++) {
		t = kgenome_gv_box_line(&gv, 1, 2u + i, buf, sizeof buf);
		CKM(t && !strcmp(t, gv.xline[i].text), "extra %u: '%s'", i, t ? t : "(null)");
	}
	t = kgenome_gv_box_line(&gv, 1, 2u + KGENOME_GV_BOX_X, buf, sizeof buf);
	CKM(t && !strcmp(t, "+5 more calls"), "the row that counts: '%s'", t ? t : "(null)");                     /* 9 - 4 shown */
	CK(kgenome_gv_box_line(&gv, 1, 3u + KGENOME_GV_BOX_X, buf, sizeof buf) == NULL);
	CK(!strcmp(kgenome_gv_box_line(&gv, 2, 2, buf, sizeof buf), "call 5") && !strcmp(kgenome_gv_box_line(&gv, 2, 3, buf, sizeof buf), "call 6"));
	CK(kgenome_gv_box_line(&gv, 2, 4, buf, sizeof buf) == NULL);
	CK(kgenome_gv_box_line(&gv, 3, 0, buf, sizeof buf) == NULL && kgenome_gv_box_line(NULL, 0, 0, buf, sizeof buf) == NULL);
	/* a refusal of the allocator and a budget */
	{
		struct kgenome_budget bud = { .max_bytes = 8 };
		struct kgenome_gv g2;

		CK(kgenome_gv_alloc(&g2, &(const struct kgenome_gv_size){ .n_node = 3, .n_xline = 7 }, &bud, NULL) == KGENOME_OVER_BUDGET && g2.node == NULL);
		vt_calls = 0; vt_nth = 1; vt_live = 0;
		CK(kgenome_gv_alloc(&g2, &(const struct kgenome_gv_size){ .n_node = 3, .n_xline = 7 }, NULL, &(const struct kgenome_cfg_mem){ vt_alloc, vt_release, NULL }) == KGENOME_NOMEM);
		CK(vt_live == 0);
		vt_nth = 0;
	}
	kgenome_gv_free(&gv, NULL);
}

/* Past the dominator bound and a large graph in time. */
static void bounds(void)
{
	struct timespec t0, t1;
	struct kgenome_gv gv;
	const uint32_t NB = KGENOME_GV_DOM_MAX + 1u;
	uint32_t i, e, ret = 0;
	double ms;

	CK(kgenome_gv_alloc(&gv, &(const struct kgenome_gv_size){ .n_node = NB, .n_edge = NB }, NULL, NULL) == KGENOME_OK);
	for (i = 0; i < NB; i++) {          /* a chain whose last node goes back to the first: one retreating edge */
		gv.edge[i].from = i;
		gv.edge[i].to = i + 1u < NB ? i + 1u : 0u;
	}
	gv.n_edge = NB;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	CK(kgenome_gv_loops(&gv, NULL, NULL) == KGENOME_TRUNCATED);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	for (e = 0; e < gv.n_edge; e++)
		ret += gv.edge[e].loop == KGENOME_GV_LOOP_RETREAT;
	CKM(ret == 1 && gv.edge[NB - 1u].loop == KGENOME_GV_LOOP_RETREAT, "past the bound: %u retreating edges", ret);
	for (i = 0; i < NB; i++)
		CK(!(gv.node[i].flags & KGENOME_GV_NF_LOOP_HEAD));
	ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
	CKM(ms < 1500.0, "past the bound: %.0f ms", ms);
	kgenome_gv_free(&gv, NULL);
	/* 200000 nodes with a loop every seven: marked in full, within a time bound */
	{
		const uint32_t N2 = 200000u;
		uint32_t ne = 0, heads = 0;

		CK(kgenome_gv_alloc(&gv, &(const struct kgenome_gv_size){ .n_node = N2, .n_edge = 2u * N2 }, NULL, NULL) == KGENOME_OK);
		for (i = 0; i < N2; i++) {
			if (i + 1u < N2) {
				gv.edge[ne].from = i;
				gv.edge[ne++].to = i + 1u;
			}
			if (i % 7u == 6u) {
				gv.edge[ne].from = i;
				gv.edge[ne++].to = i - 6u;
			}
		}
		gv.n_edge = ne;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		CK(kgenome_gv_loops(&gv, NULL, NULL) == KGENOME_OK);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
		for (i = 0; i < N2; i++)
			heads += (gv.node[i].flags & KGENOME_GV_NF_LOOP_HEAD) != 0;
		for (e = 0; e < ne; e++)
			if (gv.edge[e].from % 7u == 6u && gv.edge[e].to + 6u == gv.edge[e].from)
				CK(gv.edge[e].loop == KGENOME_GV_LOOP_LINK);
		CKM(heads == N2 / 7u, "200000 nodes: %u heads, want %u", heads, N2 / 7u);
		CKM(ms < 1500.0, "200000 nodes marked in %.0f ms", ms);
		printf("  hostile: 200000 nodes marked in %.1f ms (%u heads)\n", ms, heads);
		kgenome_gv_free(&gv, NULL);
	}
}

int main(void)
{
	hand_built();
	random_graphs();
	memory();
	box_rows();
	bounds();
	if (fails) {
		printf("gview_data: %d failure(s)\n", fails);
		return 1;
	}
	printf("gview_data: ok\n");
	return 0;
}
