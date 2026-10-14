/*
 * fnprint_early_dx - the decision-complete interrupt: the outcome of every cluster is the same with
 * and without it.
 *
 * THE ORACLE is the full computation: the same stream of window values credited with nothing retired,
 * and the outcome read from the final counts (kgenome_fnprint_dx_full, which does not look at the state
 * machine). The interrupt run feeds the same stream in the same order, tells the context how many
 * windows are left after each one, and stops when the context says the consumers are decided. For every
 * cluster the state it ended in must be MET exactly when the full outcome is "held", and no cluster
 * may end undecided after the stream is exhausted (a finished pass decides everything).
 *
 * What may differ and is asserted: a block's count is at or under its full count (a lower bound: it was
 * dropped, or the stream was cut once everything was decided); when the stream was NOT cut, a block that
 * was never dropped has exactly its full count.
 */
#include "fnprint_early_kit.h"
#include "../../unit/known_miss.h"

#include <pthread.h>

static uint32_t g_dead_blocks;           /* blocks dropped over the whole differential run: the drop path is exercised */

struct run {
	uint32_t held[EK_MAXCL + EK_MAXDX];     /* outcome per cluster: 1 held, 0 not, 2 undecided */
	uint32_t fed, stopped;
	uint64_t lookups;
	uint32_t count[EK_MAXB];
	uint8_t  dead[EK_MAXB];
	uint32_t n_cl;
};

static uint32_t n_clusters(const struct ek_world *w)
{
	return w->own_clusters ? w->n_cl : w->n_dx;
}

static void run_full(const struct kgenome_fnprint_dxdb *x, struct kgenome_fnprint_wctx *c, const struct ek_world *w,
		     const struct ek_obj *o, struct run *r)
{
	uint32_t i, k;

	memset(r, 0, sizeof *r);
	kgenome_fnprint_wctx_begin(c);
	for (i = 0; i < o->n; i++)
		kgenome_fnprint_wctx_credit(c, o->v[i], o->side[i]);
	r->fed = o->n;
	r->n_cl = n_clusters(w);
	for (k = 0; k < r->n_cl; k++)
		r->held[k] = (uint32_t)kgenome_fnprint_dx_full(x, c, k);
	for (i = 0; i < w->n_blk; i++)
		r->count[i] = kgenome_fnprint_wctx_count(c, i);
	r->lookups = c->n_lookup;
}

/* `extra` windows are added to what is left: still an upper bound, so sound, and with enough of them dropping a decided diagnose's blocks pays and is done. */
static void run_early(struct kgenome_fnprint_wctx *c, const struct ek_world *w, const struct ek_obj *o, struct run *r, uint64_t extra)
{
	uint32_t i, k;

	memset(r, 0, sizeof *r);
	c->policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(c);
	r->n_cl = n_clusters(w);
	kgenome_fnprint_dx_remain(c, extra + o->n);
	for (i = 0; i < o->n && !c->stop; i++) {
		kgenome_fnprint_wctx_credit(c, o->v[i], o->side[i]);
		kgenome_fnprint_dx_remain(c, extra + o->n - i - 1u);
		r->fed++;
	}
	r->stopped = c->stop != 0;
	if (!c->stop)
		kgenome_fnprint_dx_remain(c, 0);
	for (k = 0; k < r->n_cl; k++) {
		enum kgenome_fnprint_dstate s = kgenome_fnprint_dx_cluster(c, k);

		r->held[k] = s == KGENOME_FNP_D_MET ? 1u : s == KGENOME_FNP_D_IMPOSSIBLE ? 0u : 2u;
	}
	for (i = 0; i < w->n_blk; i++) {
		r->count[i] = kgenome_fnprint_wctx_count(c, i);
		r->dead[i] = c->bdead ? c->bdead[i] : 0;
	}
	r->lookups = c->n_lookup;
	c->policy = KGENOME_FNP_RETIRE_NONE;
}

/* One world, several objects. Returns the number of differences. */
static uint32_t one_world(uint64_t seed, uint32_t hostile, uint32_t n_obj, uint64_t *fed_full, uint64_t *fed_early,
			  uint32_t *n_stopped, uint32_t *n_met, uint32_t *n_mid)
{
	struct ek_world *w = malloc(sizeof *w);
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_dxdesc desc;
	struct kgenome_fnprint_wctx cf, ce;
	struct hk_rng r = { seed * 77u + 5u };
	uint32_t bad = 0, t, k, b;

	ek_world(w, seed, hostile);
	ek_desc(w, &desc);
	if (!ek_build(&d, w, NULL) || !kgenome_fnprint_dxdb_build(&x, &d, &desc, NULL)) {
		CK(0 && "world builds");
		free(w);
		return 1;
	}
	CK(kgenome_fnprint_wctx_init(&cf, &d, NULL) && kgenome_fnprint_wctx_init(&ce, &d, NULL));
	CK(kgenome_fnprint_dx_attach(&ce, &x));
	for (t = 0; t < n_obj; t++) {
		struct ek_obj o;
		struct run f, e;

		ek_object(&o, w, &r);
		run_full(&x, &cf, w, &o, &f);
		run_early(&ce, w, &o, &e, (seed & 1u) ? 1000000u : 0u);
		for (k = 0; k < f.n_cl; k++) {
			bad += e.held[k] == 2u;                                   /* never undecided at the end */
			bad += e.held[k] != 2u && e.held[k] != f.held[k];         /* decided = the full outcome */
			if (e.held[k] == 2u || (e.held[k] != 2u && e.held[k] != f.held[k]))
				printf("    cluster %u: early %u full %u (stopped %u fed %u/%u)\n", k, e.held[k], f.held[k], e.stopped, e.fed, f.fed);
			*n_met += f.held[k];
		}
		for (b = 0; b < w->n_blk; b++) {
			g_dead_blocks += e.dead[b];
			bad += e.count[b] > f.count[b];                           /* a lower bound, never more */
			bad += !e.stopped && !e.dead[b] && e.count[b] != f.count[b];   /* never dropped, stream not cut: exact */
			if (e.count[b] > f.count[b] || (!e.stopped && !e.dead[b] && e.count[b] != f.count[b]))
				printf("    block %u: early %u full %u dead %u\n", b, e.count[b], f.count[b], e.dead[b]);
		}
		*fed_full += f.fed;
		*fed_early += e.fed;
		*n_stopped += e.stopped;
		*n_mid += e.fed < f.fed;
		ek_obj_free(&o);
	}
	kgenome_fnprint_wctx_done(&cf);
	kgenome_fnprint_wctx_done(&ce);
	kgenome_fnprint_dxdb_free(&x);
	kgenome_fnprint_wdb_free(&d);
	free(w);
	return bad;
}

static void t_differential(void)
{
	uint64_t seed, fed_full = 0, fed_early = 0;
	uint32_t bad = 0, n_stopped = 0, n_met = 0, objs = 0, hostile, n_mid = 0;

	for (hostile = 0; hostile < 3; hostile++)
		for (seed = 1; seed <= 180u * hk_scale(); seed++) {
			uint32_t b = one_world(seed + 1000u * hostile, hostile, 4, &fed_full, &fed_early, &n_stopped, &n_met, &n_mid);

			if (b)
				printf("  seed %llu hostile %u: %u differences\n", (unsigned long long)seed, hostile, b);
			bad += b;
			objs += 4;
		}
	CK(bad == 0);
	CK(n_met > 0 && g_dead_blocks > 0);                                   /* the generator reaches "held" often enough to mean something */
	CK(n_stopped > 0 && n_mid > 0);                  /* ... and the interrupt fires before the stream is exhausted */
	printf("  EARLY objects=%u clusters_held=%u stopped=%u(mid-stream %u) fed_full=%llu fed_early=%llu\n", objs, n_met, n_stopped, n_mid,
	       (unsigned long long)fed_full, (unsigned long long)fed_early);
}

/* ---- hand-built cases ------------------------------------------------------------------ */

/* Blocks of 32 distinct hashes: block b holds b*100+1 .. b*100+32. */
static void simple(struct kgenome_fnprint_wblock *blk, uint32_t *pool, uint32_t nb)
{
	uint32_t b, j;

	for (b = 0; b < nb; b++) {
		blk[b].first = b * 32u; blk[b].n = 32; blk[b].side = 0; blk[b].tag = 0;
		for (j = 0; j < 32; j++)
			pool[b * 32u + j] = b * 100u + 1u + j;
	}
}

static int mk(struct kgenome_fnprint_wdb *d, struct kgenome_fnprint_dxdb *x, const struct kgenome_fnprint_wblock *blk, uint32_t nb,
	      const uint32_t *pool, const struct kgenome_fnprint_dxdesc *desc, struct kgenome_fnprint_wctx *c)
{
	struct kgenome_fnprint_wdb_opts o;

	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	return kgenome_fnprint_wdb_build(d, blk, nb, pool, (uint64_t)nb * 32u, &o) && kgenome_fnprint_dxdb_build(x, d, desc, NULL) &&
	       kgenome_fnprint_wctx_init(c, d, NULL) && kgenome_fnprint_dx_attach(c, x);
}

static void credit_n(struct kgenome_fnprint_wctx *c, uint32_t b, uint32_t from, uint32_t n)
{
	uint32_t j;

	for (j = 0; j < n; j++)
		kgenome_fnprint_wctx_credit(c, b * 100u + 1u + from + j, 0);
}

/* 69 and 70 percent: 22 of 32 is 68.75 (not met), 23 is 71.9 (met, at the 23rd hash and not before). */
static void t_threshold(void)
{
	struct kgenome_fnprint_wblock blk[2];
	uint32_t pool[64], ref[1] = { 0 };
	struct kgenome_fnprint_dx dx = { 0, 1, 1, 70 };
	struct kgenome_fnprint_dxdesc desc = { &dx, 1, ref, 1, NULL, 0, NULL, 0 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_wctx c;

	simple(blk, pool, 2);
	CK(mk(&d, &x, blk, 2, pool, &desc, &c));
	c.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	credit_n(&c, 0, 0, 22);
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_UNDECIDED && !c.stop);
	kgenome_fnprint_dx_remain(&c, 5);                  /* 5 windows left: 22 + 5 >= 23, still possible */
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_UNDECIDED);
	kgenome_fnprint_dx_remain(&c, 0);                  /* nothing left: 22 of 32 cannot become 23 */
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_IMPOSSIBLE && c.stop);
	kgenome_fnprint_wctx_begin(&c);
	credit_n(&c, 0, 0, 22);
	CK(!c.stop);
	credit_n(&c, 0, 22, 1);
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_MET && c.stop);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 23u);
	kgenome_fnprint_wctx_begin(&c);                    /* the state is per object */
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_UNDECIDED && !c.stop);
	c.policy = 0;
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
}

/* A hit decides nothing: a diagnose that needs two blocks is not met by one, and the first block keeps growing. */
static void t_first_hit_is_not_a_decision(void)
{
	struct kgenome_fnprint_wblock blk[3];
	uint32_t pool[96], ref[3] = { 0, 1, 2 };
	struct kgenome_fnprint_dx dx = { 0, 3, 2, 70 };
	struct kgenome_fnprint_dxdesc desc = { &dx, 1, ref, 3, NULL, 0, NULL, 0 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_wctx c;

	simple(blk, pool, 3);
	CK(mk(&d, &x, blk, 3, pool, &desc, &c));
	c.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	kgenome_fnprint_dx_remain(&c, 1000000);             /* many windows to come: dropping a decided diagnose's blocks pays */
	credit_n(&c, 0, 0, 32);                             /* block 0 complete: one of the two blocks */
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_UNDECIDED && !c.stop);
	credit_n(&c, 1, 0, 30);                             /* block 1 at 30: still being credited after block 0 reached 70 */
	CK(kgenome_fnprint_wctx_count(&c, 1) == 23u);       /* grew to the threshold and no further: the diagnose was decided there */
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_MET && c.stop);
	/* the third block is not listed any more by a wanted diagnose: dropped, and its credit stays 0 */
	credit_n(&c, 2, 0, 32);
	CK(kgenome_fnprint_wctx_count(&c, 2) == 0u && c.n_skip_dead > 0);
	c.policy = 0;
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
}

/* With few windows left nothing is dropped: the credit of a decided diagnose keeps growing, and it is never more than the full count. */
static void t_no_drop_when_it_does_not_pay(void)
{
	struct kgenome_fnprint_wblock blk[2];
	uint32_t pool[64], ref[2] = { 0, 1 };
	struct kgenome_fnprint_dx dx = { 0, 2, 1, 70 };
	struct kgenome_fnprint_dxdesc desc = { &dx, 1, ref, 2, NULL, 0, NULL, 0 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_wctx c;

	simple(blk, pool, 2);
	CK(mk(&d, &x, blk, 2, pool, &desc, &c));
	c.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	kgenome_fnprint_dx_remain(&c, 100);                 /* 100 windows left, 64 pairs: a rebuild cannot pay */
	credit_n(&c, 0, 0, 23);
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_MET && c.stop);
	credit_n(&c, 1, 0, 32);                             /* the caller kept feeding: nothing was dropped, the count is the full one */
	CK(kgenome_fnprint_wctx_count(&c, 1) == 32u && c.n_bdead == 0);
	c.policy = 0;
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
}

/* A cluster of 2 of 3 members decided at three different times, and the member nobody needs any more is released. */
static void t_cluster_times(void)
{
	struct kgenome_fnprint_wblock blk[3];
	uint32_t pool[96], ref[3] = { 0, 1, 2 }, mem[3] = { 0, 1, 2 };
	struct kgenome_fnprint_dx dx[3] = { { 0, 1, 1, 70 }, { 1, 1, 1, 70 }, { 2, 1, 1, 70 } };
	struct kgenome_fnprint_cl cl = { 0, 3, 2 };
	struct kgenome_fnprint_dxdesc desc = { dx, 3, ref, 3, &cl, 1, mem, 3 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_wctx c;

	simple(blk, pool, 3);
	CK(mk(&d, &x, blk, 3, pool, &desc, &c));
	c.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	credit_n(&c, 1, 0, 32);
	CK(kgenome_fnprint_dx_state(&c, 1) == KGENOME_FNP_D_MET);
	CK(kgenome_fnprint_dx_cluster(&c, 0) == KGENOME_FNP_D_UNDECIDED && !c.stop && kgenome_fnprint_dx_open(&c) == 1u);
	kgenome_fnprint_dx_remain(&c, 20);                 /* member 0 and 2 can still be met by 20 windows? 23 needed: no */
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_IMPOSSIBLE && kgenome_fnprint_dx_state(&c, 2) == KGENOME_FNP_D_IMPOSSIBLE);
	CK(kgenome_fnprint_dx_cluster(&c, 0) == KGENOME_FNP_D_IMPOSSIBLE && c.stop);   /* 2 impossible of 3: 2 of 3 cannot hold */
	/* the same, with member 0 met later */
	kgenome_fnprint_wctx_begin(&c);
	credit_n(&c, 1, 0, 32);
	credit_n(&c, 2, 0, 5);                              /* 5 hashes of member 2: it is still alive */
	credit_n(&c, 0, 0, 32);
	CK(kgenome_fnprint_dx_cluster(&c, 0) == KGENOME_FNP_D_MET && c.stop);
	CK(kgenome_fnprint_dx_state(&c, 2) == KGENOME_FNP_D_RELEASED);     /* nobody reads it any more */
	CK(kgenome_fnprint_wctx_count(&c, 2) == 5u);                         /* frozen where it was */
	c.policy = 0;
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
}

/* A block listed by two diagnoses is dropped only when neither is wanted. */
static void t_shared_block(void)
{
	struct kgenome_fnprint_wblock blk[2];
	uint32_t pool[64], ref[3] = { 0, 0, 1 };
	struct kgenome_fnprint_dx dx[2] = { { 0, 1, 1, 70 }, { 1, 2, 2, 100 } };
	struct kgenome_fnprint_dxdesc desc = { dx, 2, ref, 3, NULL, 0, NULL, 0 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_wctx c;

	simple(blk, pool, 2);
	CK(mk(&d, &x, blk, 2, pool, &desc, &c));
	c.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	credit_n(&c, 0, 0, 23);                              /* diagnose 0 met at 70%; diagnose 1 needs block 0 at 100% */
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_MET && !c.stop);
	credit_n(&c, 0, 23, 9);                              /* block 0 is still credited: diagnose 1 wants it */
	CK(kgenome_fnprint_wctx_count(&c, 0) == 32u);
	c.policy = 0;
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
}

/* Initial states: nothing asked, more asked than listed, k of zero, k above n. */
static void t_trivial(void)
{
	struct kgenome_fnprint_wblock blk[1];
	uint32_t pool[32], ref[1] = { 0 }, mem[4] = { 0, 1, 2, 0 };
	struct kgenome_fnprint_dx dx[3] = { { 0, 1, 0, 70 }, { 0, 1, 2, 70 }, { 0, 1, 1, 70 } };
	struct kgenome_fnprint_cl cl[3] = { { 0, 1, 1 }, { 1, 1, 1 }, { 3, 1, 3 } };
	struct kgenome_fnprint_dxdesc desc = { dx, 3, ref, 1, cl, 3, mem, 4 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_wctx c;

	simple(blk, pool, 1);
	CK(mk(&d, &x, blk, 1, pool, &desc, &c));
	c.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_MET);          /* need 0 */
	CK(kgenome_fnprint_dx_state(&c, 1) == KGENOME_FNP_D_IMPOSSIBLE);   /* needs 2 of the 1 it lists */
	CK(kgenome_fnprint_dx_cluster(&c, 0) == KGENOME_FNP_D_MET);
	CK(kgenome_fnprint_dx_cluster(&c, 1) == KGENOME_FNP_D_IMPOSSIBLE);
	CK(kgenome_fnprint_dx_cluster(&c, 2) == KGENOME_FNP_D_IMPOSSIBLE); /* k 3 of 1 member */
	CK(c.stop && kgenome_fnprint_dx_open(&c) == 0u);                   /* decided before the first window: nothing to roll */
	c.policy = 0;
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
}

/*
 * Diagnoses that overlap in ref[] (50 diagnoses all pointing at the same three entries) and clusters that overlap in mem[]:
 * the index is sized by the listings, and every one of the 50 is decided by the same credit.
 */
static void t_overlapping_listings(void)
{
	enum { ND = 50 };
	struct kgenome_fnprint_wblock blk[3];
	uint32_t pool[96], ref[3] = { 0, 1, 2 }, mem[ND], d;
	struct kgenome_fnprint_dx dx[ND];
	struct kgenome_fnprint_cl cl[ND];
	struct kgenome_fnprint_dxdesc desc;
	struct kgenome_fnprint_wdb db;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_wctx c;

	simple(blk, pool, 3);
	for (d = 0; d < ND; d++) {
		dx[d].first = 0; dx[d].n = 3; dx[d].need = 1u + d % 3u; dx[d].pct = 70;     /* the same three blocks, needing 1, 2 or 3 of them */
		cl[d].first = 0; cl[d].n = ND; cl[d].k = ND;                               /* every cluster lists ALL fifty and wants all: the mem[] ranges overlap */
		mem[d] = d;
	}
	memset(&desc, 0, sizeof desc);
	desc.dx = dx; desc.n_dx = ND; desc.ref = ref; desc.n_ref = 3; desc.cl = cl; desc.n_cl = ND; desc.mem = mem; desc.n_mem = ND;
	{
		struct kgenome_fnprint_wdb_opts o;

		memset(&o, 0, sizeof o);
		o.n_tag = 1;
		CK(kgenome_fnprint_wdb_build(&db, blk, 3, pool, 96, &o) && kgenome_fnprint_dxdb_build(&x, &db, &desc, NULL));
	}
	CK(kgenome_fnprint_wctx_init(&c, &db, NULL) && kgenome_fnprint_dx_attach(&c, &x));
	c.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	credit_n(&c, 0, 0, 23);
	for (d = 0; d < ND; d++)                                                        /* need 1 is met by one block at 70% */
		CK(kgenome_fnprint_dx_state(&c, d) == (d % 3u == 0 ? KGENOME_FNP_D_MET : KGENOME_FNP_D_UNDECIDED));
	credit_n(&c, 1, 0, 23);
	for (d = 0; d < ND; d++)
		CK(kgenome_fnprint_dx_state(&c, d) == (d % 3u == 2 ? KGENOME_FNP_D_UNDECIDED : KGENOME_FNP_D_MET));
	CK(kgenome_fnprint_dx_open(&c) == ND && !c.stop);
	kgenome_fnprint_dx_remain(&c, 0);                                               /* the object ends: needing three blocks is impossible, so is every cluster */
	for (d = 0; d < ND; d++)
		CK(kgenome_fnprint_dx_cluster(&c, d) == KGENOME_FNP_D_IMPOSSIBLE);
	CK(kgenome_fnprint_dx_open(&c) == 0u && c.stop);
	c.policy = 0;
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&db);
}

/* Hostile: a block of 128 slots that all hold one value is credited 128 at once by one window; the bound must know. */
static void t_one_value_block(void)
{
	struct kgenome_fnprint_wblock blk[1];
	uint32_t pool[128], ref[1] = { 0 }, j;
	struct kgenome_fnprint_dx dx = { 0, 1, 1, 70 };
	struct kgenome_fnprint_dxdesc desc = { &dx, 1, ref, 1, NULL, 0, NULL, 0 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wdb_opts o;

	for (j = 0; j < 128; j++)
		pool[j] = 4242u;
	blk[0].first = 0; blk[0].n = 128; blk[0].side = 0; blk[0].tag = 0;
	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	CK(kgenome_fnprint_wdb_build(&d, blk, 1, pool, 128, &o) && kgenome_fnprint_dxdb_build(&x, &d, &desc, NULL));
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL) && kgenome_fnprint_dx_attach(&c, &x));
	c.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	kgenome_fnprint_dx_remain(&c, 1);                   /* one window left: it can credit all 128, so it is not IMPOSSIBLE */
	CK(kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_UNDECIDED && !c.stop);
	kgenome_fnprint_wctx_credit(&c, 4242u, 0);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 128u && kgenome_fnprint_dx_state(&c, 0) == KGENOME_FNP_D_MET);
	c.policy = 0;
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
}

/* The same value on the other side does not credit the block: the bound is about slots, the state machine reads counts. */
static void t_status_and_limits(void)
{
	struct ek_world *w = malloc(sizeof *w);
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_dxdesc desc, bad;
	struct kgenome_fnprint_wctx c;
	struct kgenome_ledger led;
	struct kgenome_fnprint_wpass_req rq;
	struct kgenome_fnprint_wpass_stat st;
	uint8_t buf[64] = { 0 };
	struct kof_range ext[2] = { { 0, 64 }, { 60, 100 } };
	uint32_t ref_bad[1] = { 9999 };
	struct kgenome_fnprint_dx dxbad = { 0, 1, 1, 70 };

	ek_world(w, 7, 0);
	ek_desc(w, &desc);
	CK(ek_build(&d, w, NULL));
	/* a description that points outside the database is refused */
	memset(&bad, 0, sizeof bad);
	bad.dx = &dxbad; bad.n_dx = 1; bad.ref = ref_bad; bad.n_ref = 1;
	CK(!kgenome_fnprint_dxdb_build(&x, &d, &bad, NULL) && x.status == KGENOME_BAD_INPUT);
	/* over the allowance: refused, the ledger is back to zero, and a context over it is refused too */
	kgenome_ledger_init(&led, 64);
	CK(!kgenome_fnprint_dxdb_build(&x, &d, &desc, &led) && x.status == KGENOME_OVER_BUDGET && led.used == 0);
	kgenome_ledger_init(&led, 0);
	CK(kgenome_fnprint_dxdb_build(&x, &d, &desc, &led) && led.used == x.bytes && x.bytes > 0);
	{
		struct kgenome_ledger l2;

		kgenome_ledger_init(&l2, 0);
		CK(kgenome_fnprint_wctx_init(&c, &d, &l2));
		l2.limit = l2.used + 8;
		CK(!kgenome_fnprint_dx_attach(&c, &x) && c.status == KGENOME_OVER_BUDGET && c.dxr == NULL);
		l2.limit = 0;
		CK(kgenome_fnprint_dx_attach(&c, &x) && c.dxr);
		kgenome_fnprint_wctx_done(&c);
		CK(l2.used == 0);                           /* everything given back, the state included */
	}
	kgenome_fnprint_dxdb_free(&x);
	CK(led.used == 0);
	/* the pass with the policy and no state is refused loudly; it does not run as NONE */
	CK(kgenome_fnprint_dxdb_build(&x, &d, &desc, NULL));
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	memset(&rq, 0, sizeof rq);
	rq.p = buf; rq.n = sizeof buf; rq.ext = ext; rq.n_ext = 1; rq.c = &c; rq.stat = &st; rq.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	kgenome_fnprint_wpass(&rq);
	CK(st.status == KGENOME_BAD_INPUT && st.n_win_rolled == 0);
	/* a range past the object is skipped and counted, with the policy on as with it off */
	CK(kgenome_fnprint_dx_attach(&c, &x));
	rq.ext = ext; rq.n_ext = 2;
	kgenome_fnprint_wctx_begin(&c);
	kgenome_fnprint_wpass(&rq);
	CK(st.status == KGENOME_OK && st.n_bad_ext == 1u);
	kgenome_fnprint_wctx_done(&c); kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
	free(w);
}

/* ---- threads: one read-only database and index, one context per thread ------------------- */

struct thr {
	const struct kgenome_fnprint_wdb *d;
	const struct kgenome_fnprint_dxdb *x;
	const struct ek_world *w;
	const struct ek_obj *o;
	uint32_t n_obj;
	struct run *out;
};

static void *thr_main(void *a)
{
	struct thr *t = a;
	struct kgenome_fnprint_wctx c;
	uint32_t i, round;

	kgenome_fnprint_wctx_init(&c, t->d, NULL);
	kgenome_fnprint_dx_attach(&c, t->x);
	for (round = 0; round < 3u; round++)
		for (i = 0; i < t->n_obj; i++)
			run_early(&c, t->w, &t->o[i], &t->out[i], 0);
	kgenome_fnprint_wctx_done(&c);
	return NULL;
}

static void t_threads(void)
{
	struct ek_world *w = malloc(sizeof *w);
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_dxdesc desc;
	struct kgenome_fnprint_wctx c;
	struct hk_rng r = { 99 };
	struct ek_obj o[6];
	struct run ref[6], got[4][6];
	struct thr t[4];
	pthread_t th[4];
	uint32_t i, k, bad = 0;

	ek_world(w, 321, 1);
	ek_desc(w, &desc);
	CK(ek_build(&d, w, NULL) && kgenome_fnprint_dxdb_build(&x, &d, &desc, NULL));
	for (i = 0; i < 6; i++)
		ek_object(&o[i], w, &r);
	kgenome_fnprint_wctx_init(&c, &d, NULL);
	kgenome_fnprint_dx_attach(&c, &x);
	for (i = 0; i < 6; i++)
		run_early(&c, w, &o[i], &ref[i], 0);
	for (k = 0; k < 4; k++) {
		t[k].d = &d; t[k].x = &x; t[k].w = w; t[k].o = o; t[k].n_obj = 6; t[k].out = got[k];
		pthread_create(&th[k], NULL, thr_main, &t[k]);
	}
	for (k = 0; k < 4; k++)
		pthread_join(th[k], NULL);
	for (k = 0; k < 4; k++)
		for (i = 0; i < 6; i++)
			bad += memcmp(ref[i].held, got[k][i].held, sizeof ref[i].held) || ref[i].fed != got[k][i].fed ||
			       memcmp(ref[i].count, got[k][i].count, sizeof ref[i].count);
	CK(bad == 0);
	kgenome_fnprint_wctx_done(&c);
	for (i = 0; i < 6; i++)
		ek_obj_free(&o[i]);
	kgenome_fnprint_dxdb_free(&x);
	kgenome_fnprint_wdb_free(&d);
	free(w);
}

int main(void)
{
	t_differential();
	t_threshold();
	t_first_hit_is_not_a_decision();
	t_no_drop_when_it_does_not_pay();
	t_cluster_times();
	t_shared_block();
	t_trivial();
	t_overlapping_listings();
	t_one_value_block();
	t_status_and_limits();
	t_threads();
	printf("fnprint_early_dx: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
