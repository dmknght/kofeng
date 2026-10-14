/*
 * fnprint_sel_hostile - the selection planner under hostile input, and the library policy.
 *
 *   - a database whose hottest key is held by thousands of blocks, and an object whose every probe hits it:
 *     the planner must not walk the run (bounded time), and a block of 128 hashes that are all one value
 *     must not break the order;
 *   - extents that are zero, past the end, overflowing, or end exactly on the last byte, on a buffer that
 *     is followed by a guard page: nothing is read outside, every extent is accounted for;
 *   - an allowance too small for the scratch: NOTHING is removed (the whole set comes back in order),
 *     the status says OVER_BUDGET, and the ledger returns to zero;
 *   - four threads planning and rolling over one read-only database agree;
 *   - the library policy removes library functions by their bytes, never adds credit, is not moved by a
 *     name, and has a limit that is a KNOWN-MISS: an author function built from library windows.
 */
#include "fnprint_sel_kit.h"
#include "../../unit/known_miss.h"

#include <pthread.h>
#include <time.h>

static double now(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static void t_hot_key(void)
{
	enum { NB = 4000, NFN = 4000 };
	struct kgenome_fnprint_wblock *blk = malloc(NB * sizeof *blk);
	uint32_t *pool = malloc((size_t)NB * 32u * sizeof *pool), i, hot;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_mtn_win w;
	uint8_t win[8] = { 0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f };
	struct sk_obj ob;
	struct kof_range *out = malloc(NFN * sizeof *out);
	struct kgenome_fnprint_sel_req rq;
	struct kgenome_fnprint_sel_stat ss;
	struct hk_rng g = { 17 };
	double t0, t1;

	CK(kgenome_mtn_win_begin(&w, win, 8, KGENOME_MUTATION_RAW));
	hot = kgenome_mtn_win_value(&w);
	for (i = 0; i < NB; i++) {
		uint32_t j;

		pool[i * 32u] = hot;                                    /* the hot key: held by every block */
		for (j = 1; j < 32u; j++)
			pool[i * 32u + j] = (uint32_t)(hk_next(&g) >> 40) | 0x1000u;
		blk[i].first = i * 32u; blk[i].n = 32; blk[i].side = 0; blk[i].tag = 0;
	}
	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	CK(kgenome_fnprint_wdb_build(&d, blk, NB, pool, (uint64_t)NB * 32u, &o));
	CK(d.max_run >= NB);
	memset(&ob, 0, sizeof ob);
	for (i = 0; i < NFN; i++) {                                     /* every function's two probe windows (k = 2: both ends) are the hot key */
		uint8_t f[64];
		uint32_t j;

		for (j = 0; j < sizeof f; j++)
			f[j] = (uint8_t)hk_next(&g);
		memcpy(f, win, 8);
		memcpy(f + sizeof f - 8u, win, 8);
		sk_add(&ob, f, sizeof f);
	}
	memset(&rq, 0, sizeof rq);
	rq.p = ob.p; rq.n = ob.n; rq.fn = ob.fn; rq.n_fn = ob.n_fn; rq.policy = KGENOME_FNP_SEL_ORDER | KGENOME_FNP_SEL_SAMPLE;
	rq.sample_k = 2; rq.db = &d; rq.out = out; rq.stat = &ss;
	t0 = now();
	kgenome_fnprint_sel_plan(&rq);
	t1 = now();
	CK(ss.status == KGENOME_OK && ss.n_out == NFN && ss.n_hit == NFN && ss.n_probe == 2u * NFN);
	CK(t1 - t0 < 1.0);                                              /* 8000 probes into a run of 4000: a bisection, not a walk */
	printf("  SEL-HOT probes=%llu run=%llu plan=%.4fs\n", (unsigned long long)ss.n_probe, (unsigned long long)d.max_run, t1 - t0);
	sk_obj_free(&ob);
	kgenome_fnprint_wdb_free(&d);
	free(blk); free(pool); free(out);
}

/* Functions that agree at both ends and in the middle and differ inside: the duplicate search is bounded, and nothing is removed. */
static void t_dup_adversary(void)
{
	enum { NFN = 4000, LEN = 4000 };
	struct sk_obj o;
	struct kof_range *out = malloc(NFN * sizeof *out);
	struct kgenome_fnprint_sel_stat ss;
	uint8_t tpl[LEN], f[LEN];
	struct hk_rng g = { 33 };
	uint32_t i, j;
	double t0, t1;

	for (j = 0; j < LEN; j++)
		tpl[j] = (uint8_t)hk_next(&g);
	memset(&o, 0, sizeof o);
	for (i = 0; i < NFN; i++) {
		memcpy(f, tpl, LEN);
		f[200u + hk_below(&g, 1500u)] ^= (uint8_t)(1u + i % 255u);   /* inside: not at the ends, not at the middle 16 */
		f[300u + hk_below(&g, 1500u)] ^= (uint8_t)(1u + (i / 255u) % 255u);
		sk_add(&o, f, LEN);
	}
	t0 = now();
	{
		struct kgenome_fnprint_sel_req rq;

		memset(&rq, 0, sizeof rq);
		rq.p = o.p; rq.n = o.n; rq.fn = o.fn; rq.n_fn = o.n_fn; rq.policy = KGENOME_FNP_SEL_DUP; rq.out = out; rq.stat = &ss;
		kgenome_fnprint_sel_plan(&rq);
	}
	t1 = now();
	CK(ss.status == KGENOME_OK && ss.n_out + ss.n_dup == NFN && ss.n_dup < 100u);   /* a few chance copies at most: they ARE equal */
	CK(ss.n_dup_cap > 3000u);                                       /* the bound fired, and says so */
	CK(ss.bytes_compared <= (uint64_t)NFN * 8u * LEN);              /* never more than 8 full compares per function */
	CK(t1 - t0 < 2.0);
	printf("  SEL-DUP-ADV functions=%d capped=%u compared=%llu bytes plan=%.4fs\n", NFN, ss.n_dup_cap, (unsigned long long)ss.bytes_compared, t1 - t0);
	sk_obj_free(&o);
	free(out);
}

static void t_one_value_block(void)
{
	struct kgenome_fnprint_wblock blk[2];
	uint32_t pool[256], j;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct sk_obj ob;
	struct kof_range out[8];
	struct kgenome_fnprint_sel_stat ss;
	struct hk_rng g = { 4 };

	for (j = 0; j < 256; j++)
		pool[j] = 0x777u;                                       /* 2 blocks x 128 slots, one value */
	blk[0].first = 0; blk[0].n = 128; blk[0].side = 0; blk[0].tag = 0;
	blk[1].first = 128; blk[1].n = 128; blk[1].side = 0; blk[1].tag = 0;
	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	CK(kgenome_fnprint_wdb_build(&d, blk, 2, pool, 256, &o));
	memset(&ob, 0, sizeof ob);
	for (j = 0; j < 6; j++)
		sk_add_random(&ob, &g, 100);
	{
		struct kgenome_fnprint_sel_req rq;

		memset(&rq, 0, sizeof rq);
		rq.p = ob.p; rq.n = ob.n; rq.fn = ob.fn; rq.n_fn = ob.n_fn; rq.policy = KGENOME_FNP_SEL_ORDER; rq.sample_k = 16; rq.db = &d;
		rq.out = out; rq.stat = &ss;
		kgenome_fnprint_sel_plan(&rq);
	}
	CK(ss.status == KGENOME_OK && ss.n_out == 6u && ss.n_hit == 0);
	sk_obj_free(&ob);
	kgenome_fnprint_wdb_free(&d);
}

static void t_extents(void)
{
	struct hk_gb gb;
	uint8_t src[256], *p;
	struct kof_range fn[10], out[10];
	struct kgenome_fnprint_sel_stat ss;
	struct kgenome_fnprint_sel_req rq;
	uint32_t i, pol;
	struct hk_rng g = { 6 };

	for (i = 0; i < sizeof src; i++)
		src[i] = (uint8_t)hk_next(&g);
	gb_init(&gb, sizeof src);
	p = gb_put(&gb, src, sizeof src);
	fn[0].off = 0;            fn[0].len = 256;                    /* the whole object: valid */
	fn[1].off = 256;          fn[1].len = 0;                      /* empty at the end: valid */
	fn[2].off = 257;          fn[2].len = 0;                      /* past the end */
	fn[3].off = 0;            fn[3].len = 257;                    /* one byte too long */
	fn[4].off = UINT64_MAX - 3u; fn[4].len = 8;                   /* off + len wraps */
	fn[5].off = 200;          fn[5].len = UINT64_MAX;             /* huge length */
	fn[6].off = 248;          fn[6].len = 8;                      /* ends on the last byte: valid */
	fn[7].off = 252;          fn[7].len = 8;                      /* four past the end */
	fn[8].off = 100;          fn[8].len = 100;
	fn[9].off = 100;          fn[9].len = 100;                    /* a copy */
	for (pol = 0; pol < 2; pol++) {
		memset(&rq, 0, sizeof rq);
		rq.p = p; rq.n = sizeof src; rq.fn = fn; rq.n_fn = 10; rq.out = out; rq.stat = &ss;
		rq.policy = pol ? KGENOME_FNP_SEL_FLAT | KGENOME_FNP_SEL_DUP | KGENOME_FNP_SEL_TINY | KGENOME_FNP_SEL_ORDER | KGENOME_FNP_SEL_SAMPLE : 0;
		rq.sample_k = 8;
		kgenome_fnprint_sel_plan(&rq);
		CK(ss.status == KGENOME_OK && ss.n_bad == 5u);
		CK(ss.n_in == ss.n_out + ss.n_flat + ss.n_dup + ss.n_tiny + ss.n_sample + ss.n_lib + ss.n_bad);
		if (!pol)
			CK(ss.n_out == 5u);
		else
			CK(ss.n_dup == 1u);                             /* the copy at 100 */
	}
	/* every length of the buffer: the planner reads only inside it */
	for (i = 0; i <= sizeof src; i++) {
		struct kof_range one = { 0, i };

		p = gb_put(&gb, src, i);
		memset(&rq, 0, sizeof rq);
		rq.p = p; rq.n = i; rq.fn = &one; rq.n_fn = 1; rq.out = out; rq.stat = &ss;
		rq.policy = KGENOME_FNP_SEL_FLAT | KGENOME_FNP_SEL_DUP | KGENOME_FNP_SEL_ORDER | KGENOME_FNP_SEL_SAMPLE;
		rq.sample_k = 4;
		kgenome_fnprint_sel_plan(&rq);
		CK(ss.status == KGENOME_OK);
	}
	gb_free(&gb);
}

static void t_ledger(void)
{
	struct sk_obj o;
	struct kof_range *out = malloc(2100 * sizeof *out), *ref = malloc(2100 * sizeof *ref);
	uint32_t *idx = malloc(2100 * sizeof *idx), i, lim, keep;
	struct kgenome_ledger led;
	struct kgenome_fnprint_sel_stat ss, s0;
	struct hk_rng g = { 8 };
	struct sk_db *db = malloc(sizeof *db);

	CK(sk_db_make(db, 5, NULL));
	memset(&o, 0, sizeof o);
	for (i = 0; i < 2000; i++) {
		if (i % 3 == 0)
			sk_add_fill(&o, 0x90, 64);                      /* flat: removable */
		else if (i % 3 == 1)
			sk_add(&o, db->body[1], 200);                   /* a copy: removable */
		else
			sk_add_random(&o, &g, 100);
	}
	sk_plan(db, &o, KGENOME_FNP_SEL_FLAT | KGENOME_FNP_SEL_DUP | KGENOME_FNP_SEL_ORDER, 8, 0, ref, NULL, NULL, &s0);
	CK(s0.status == KGENOME_OK && s0.n_out < 2000u);
	for (keep = 0; keep < 3; keep++) {
		lim = keep == 0 ? 100u : keep == 1 ? 60000u : 80000u;   /* no room for the duplicate table / room for it but not the order list */
		kgenome_ledger_init(&led, lim);
		sk_plan(db, &o, KGENOME_FNP_SEL_FLAT | KGENOME_FNP_SEL_DUP | KGENOME_FNP_SEL_ORDER, 8, 0, out, idx, &led, &ss);
		if (keep == 2) {
			CK(ss.status == KGENOME_OK && ss.n_out == s0.n_out);   /* the planner fits: the same answer */
		} else {
			CK(ss.status == KGENOME_OVER_BUDGET && ss.n_out == 2000u);      /* nothing removed, nothing lost */
			CK(ss.n_flat == 0 && ss.n_dup == 0);
			for (i = 0; i < 2000u; i++)
				if (idx[i] != i || out[i].off != o.fn[i].off || out[i].len != o.fn[i].len) {
					CK(0 && "the whole set comes back in order");
					break;
				}
		}
		CK(led.used == 0);                                      /* the scratch is given back */
	}
	sk_obj_free(&o);
	sk_db_free(db);
	free(db); free(out); free(ref); free(idx);
}

/* ---- threads ---------------------------------------------------------------------------- */

struct thr {
	const struct sk_db *db;
	const struct sk_obj *o;
	struct kof_range *out;
	uint32_t n_out, cnt[SK_NF];
};

static void *thr_main(void *a)
{
	struct thr *t = a;
	struct kgenome_fnprint_sel_stat ss;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_stat st;
	uint32_t round;

	kgenome_fnprint_wctx_init(&c, &t->db->d, NULL);
	for (round = 0; round < 3u; round++) {
		sk_plan(t->db, t->o, KGENOME_FNP_SEL_FLAT | KGENOME_FNP_SEL_DUP | KGENOME_FNP_SEL_ORDER, 8, 0, t->out, NULL, NULL, &ss);
		t->n_out = ss.n_out;
		sk_roll(t->db, &c, t->o, t->out, ss.n_out, t->cnt, &st);
	}
	kgenome_fnprint_wctx_done(&c);
	return NULL;
}

static void t_threads(void)
{
	struct sk_db *db = malloc(sizeof *db);
	struct sk_obj o;
	struct thr t[4];
	pthread_t th[4];
	struct hk_rng g = { 12 };
	uint32_t k, f, i;

	CK(sk_db_make(db, 99, NULL));
	memset(&o, 0, sizeof o);
	for (f = 0; f < SK_NF; f++)
		for (i = 0; i < 1u + f % 4u; i++)
			sk_add(&o, db->body[f], db->len[f]);
	for (i = 0; i < 50; i++)
		sk_add_random(&o, &g, 200);
	for (k = 0; k < 4; k++) {
		t[k].db = db; t[k].o = &o; t[k].out = malloc((o.n_fn + 1u) * sizeof *t[k].out);
		pthread_create(&th[k], NULL, thr_main, &t[k]);
	}
	for (k = 0; k < 4; k++)
		pthread_join(th[k], NULL);
	for (k = 1; k < 4; k++) {
		CK(t[k].n_out == t[0].n_out);
		CK(!memcmp(t[k].out, t[0].out, t[0].n_out * sizeof *t[0].out));
		CK(!memcmp(t[k].cnt, t[0].cnt, sizeof t[0].cnt));
	}
	for (k = 0; k < 4; k++)
		free(t[k].out);
	sk_obj_free(&o);
	sk_db_free(db);
	free(db);
}

/* ---- the library policy ------------------------------------------------------------------- */

static void t_lib(void)
{
	struct sk_db *db = malloc(sizeof *db);
	struct kgenome_fnprint_libtab tab;
	struct sk_obj o;
	uint8_t lib[SK_NF][600];
	uint32_t i, j, full[SK_NF], sel[SK_NF], bad = 0;
	struct hk_rng g = { 21 };
	struct kgenome_fnprint_req *unused = NULL;
	struct kof_range *out;
	struct kgenome_fnprint_sel_req rq;
	struct kgenome_fnprint_sel_stat ss;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_stat st;

	(void)unused;
	CK(sk_db_make(db, 31, NULL));
	CK(kgenome_fnprint_libtab_init(&tab, 0, NULL));
	for (i = 0; i < SK_NF; i++) {
		for (j = 0; j < 600; j++)
			lib[i][j] = (uint8_t)hk_next(&g);
		kgenome_fnprint_libtab_add(&tab, lib[i], 600);
	}
	memset(&o, 0, sizeof o);
	for (i = 0; i < SK_NF; i++) {
		sk_add(&o, lib[i], 600);                                /* library */
		sk_add(&o, db->body[i], db->len[i]);                    /* author: the bodies the blocks come from */
	}
	{
		uint8_t patched[600];

		memcpy(patched, lib[3], 600);
		for (j = 5; j < 600; j += 6)
			patched[j] ^= 0x5a;                             /* a library function patched every sixth byte */
		sk_add(&o, patched, 600);
	}
	out = malloc((o.n_fn + 1u) * sizeof *out);
	memset(&rq, 0, sizeof rq);
	rq.p = o.p; rq.n = o.n; rq.fn = o.fn; rq.n_fn = o.n_fn; rq.policy = KGENOME_FNP_SEL_LIB; rq.sample_k = 16; rq.lib = &tab; rq.out = out; rq.stat = &ss;
	kgenome_fnprint_sel_plan(&rq);
	CK(ss.status == KGENOME_OK && ss.n_lib == SK_NF && ss.n_out == SK_NF + 1u);   /* the 40 library copies go; the patched one stays */
	CK(kgenome_fnprint_wctx_init(&c, &db->d, NULL));
	sk_roll(db, &c, &o, o.fn, o.n_fn, full, &st);
	sk_roll(db, &c, &o, out, ss.n_out, sel, &st);
	for (i = 0; i < db->n_blk; i++)
		bad += full[i] != sel[i];
	CK(bad == 0);                                                   /* no author credit moved */
	kgenome_fnprint_wctx_done(&c);
	/* the limit: an author function that is mostly library windows, with the author's own tail */
	{
		struct sk_obj o2;
		uint8_t mix[1200];
		uint32_t b = 5, lost = 0;
		struct kgenome_fnprint_wctx c2;

		memcpy(mix, lib[1], 600);
		memcpy(mix + 600, lib[2], 600);
		memset(&o2, 0, sizeof o2);
		memcpy(mix + 1120, db->body[b], 80);                       /* the block's own windows, in the last 80 bytes: one probe of 16 lands there */
		sk_add(&o2, mix, sizeof mix);
		CK(kgenome_fnprint_wctx_init(&c2, &db->d, NULL));
		sk_roll(db, &c2, &o2, o2.fn, o2.n_fn, full, &st);
		rq.p = o2.p; rq.n = o2.n; rq.fn = o2.fn; rq.n_fn = o2.n_fn;
		kgenome_fnprint_sel_plan(&rq);
		sk_roll(db, &c2, &o2, out, ss.n_out, sel, &st);
		for (i = 0; i < db->n_blk; i++)
			lost += sel[i] < full[i];
		KM_CHECK(lost == 0, "a function of library windows with the author's own tail is removed whole by the library policy",
			 "LIB_SKIP_HIDES_AUTHOR_TAIL");
		kgenome_fnprint_wctx_done(&c2);
		sk_obj_free(&o2);
	}
	kgenome_fnprint_libtab_free(&tab);
	free(out);
	sk_obj_free(&o);
	sk_db_free(db);
	free(db);
}

int main(void)
{
	t_hot_key();
	t_dup_adversary();
	t_one_value_block();
	t_extents();
	t_ledger();
	t_threads();
	t_lib();
	printf("fnprint_sel_hostile: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
