/*
 * fnprint_pred - the prediction stage that does not decode: the known-library window table, the
 * byte statistics, the byte-level call-graph sketch, the window database and its context, and the
 * pass that rolls bytes through them.
 *
 * Every object is built in memory. The properties:
 *   - the library table recognises library windows and nothing else, grows under a ledger, and says
 *     (status, n_refused) when it cannot - a miss on an incomplete table is not "not library";
 *   - the database refuses what it cannot index, with a status, and never truncates;
 *   - a hot key is credited once per object, a slot at most once, a new object starts at zero;
 *   - retirement is OFF unless asked for, and when asked for it stops a tag's credit and nothing else;
 *   - the byte sketch finds the edges the bytes hold, its false edges on noise are rare, and the
 *     closure from main reaches what main reaches.
 */
#include "fnprint_kit.h"
#include "../../unit/known_miss.h"

static struct fk_var V0 = { 0x1000, 0x2000, 0x12345678u };

static uint32_t rnd_bytes(uint8_t *p, uint32_t n, uint64_t seed)
{
	struct hk_rng r = { seed | 1u };
	uint32_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)hk_next(&r);
	return n;
}

/* ---- the library table --------------------------------------------------------- */

static void t_libtab_basic(void)
{
	struct kgenome_fnprint_libtab t;
	struct kgenome_fnprint_libvote v;
	uint8_t lib[4096], other[4096];
	struct kgenome_mtn_win w;
	uint32_t hit = 0, n = 0;

	rnd_bytes(lib, sizeof lib, 11);
	rnd_bytes(other, sizeof other, 12);
	kgenome_fnprint_libtab_init(&t, 0, NULL);
	CK(!kgenome_fnprint_libtab_has(&t, 12345));              /* empty: nothing is library */
	kgenome_fnprint_libtab_add(&t, lib, sizeof lib);
	CK(t.n > 4000 && t.n <= sizeof lib && t.status == KGENOME_OK && t.n_refused == 0);
	kgenome_fnprint_libvote(&t, lib, sizeof lib, &v);
	CK(v.n_win > 4000 && v.n_hit == v.n_sampled && v.n_sampled == v.n_win);
	kgenome_fnprint_libvote(&t, other, sizeof other, &v);
	CK(v.n_hit * 100u < v.n_win);                            /* unrelated bytes: only coincidences */
	/* a window value 0 / flat windows are not content */
	{
		uint8_t flat[256];

		memset(flat, 0x90, sizeof flat);
		kgenome_fnprint_libtab_add(&t, flat, sizeof flat);
		kgenome_fnprint_libvote(&t, flat, sizeof flat, &v);
		CK(v.n_win == 0);
	}
	if (kgenome_mtn_win_begin(&w, lib, sizeof lib, 0))
		do { n++; hit += (uint32_t)kgenome_fnprint_libtab_has(&t, kgenome_mtn_win_value(&w)); } while (kgenome_mtn_win_next(&w));
	CK(n == hit);
	kgenome_fnprint_libtab_free(&t);
}

static void t_libtab_sampled(void)
{
	struct kgenome_fnprint_libtab full, s3;
	struct kgenome_fnprint_libvote v;
	uint8_t lib[65536];

	rnd_bytes(lib, sizeof lib, 21);
	kgenome_fnprint_libtab_init(&full, 0, NULL);
	kgenome_fnprint_libtab_init(&s3, 3, NULL);
	kgenome_fnprint_libtab_add(&full, lib, sizeof lib);
	kgenome_fnprint_libtab_add(&s3, lib, sizeof lib);
	CK(s3.n * 6u < full.n && s3.n * 10u > full.n / 2u);      /* about 1 in 8 */
	CK(s3.bytes < full.bytes);
	kgenome_fnprint_libvote(&s3, lib, sizeof lib, &v);
	CK(v.n_sampled > 0 && v.n_hit == v.n_sampled && v.n_sampled < v.n_win / 4u);
	kgenome_fnprint_libtab_free(&full);
	kgenome_fnprint_libtab_free(&s3);
}

static void t_libtab_ledger(void)
{
	struct kgenome_fnprint_libtab t;
	struct kgenome_ledger led;
	uint8_t lib[65536];

	rnd_bytes(lib, sizeof lib, 31);
	kgenome_ledger_init(&led, 64u * 1024u);                  /* room for 16K slots: not 64K windows */
	kgenome_fnprint_libtab_init(&t, 0, &led);
	kgenome_fnprint_libtab_add(&t, lib, sizeof lib);
	/* NO SILENT LIMIT: it says so, counts what did not fit, and what it holds is still true */
	CK(t.status == KGENOME_OVER_BUDGET && t.n_refused > 0);
	CK(t.n + t.n_refused >= 60000u);
	CK(led.used <= led.limit);
	CK(kgenome_fnprint_libtab_has(&t, 0) == 0);
	kgenome_fnprint_libtab_free(&t);
	CK(led.used == 0);                                       /* nothing leaked */
}

/* ---- byte statistics -------------------------------------------------------------- */

static void t_bstat(void)
{
	struct kgenome_fnprint_bstat s;
	uint8_t b[4096];
	struct fk_obj o;
	uint32_t i;

	memset(b, 0, sizeof b);
	kgenome_fnprint_bstat(b, sizeof b, &s);
	CK(kgenome_fnprint_bstat_is_data(&s));                   /* padding */
	for (i = 0; i < sizeof b; i++)
		b[i] = (uint8_t)('a' + i % 26u);
	kgenome_fnprint_bstat(b, sizeof b, &s);
	CK(kgenome_fnprint_bstat_is_data(&s));                   /* text */
	fk_init(&o);
	for (i = 0; i < 60; i++)
		fk_func(&o, 700 + i, 30, &V0);
	kgenome_fnprint_bstat(o.b, (uint32_t)(o.n < 4096 ? o.n : 4096), &s);
	CK(!kgenome_fnprint_bstat_is_data(&s));                  /* code */
	rnd_bytes(b, sizeof b, 5);
	kgenome_fnprint_bstat(b, sizeof b, &s);
	CK(!kgenome_fnprint_bstat_is_data(&s));                  /* noise / packed bytes: kept */
	/* the known blind spot of this prior: printable bytes are called data. A skip made on it is opt-in. */
	memset(b, 0, sizeof b);
	memcpy(b, "\x48\x31\xc0\x50\x48\xbb//bin/sh", 14);
	kgenome_fnprint_bstat(b, sizeof b, &s);
	CK(kgenome_fnprint_bstat_is_data(&s));                   /* a short stub in padding is invisible to it */
	fk_free(&o);
}

/* ---- the byte-level call graph ---------------------------------------------------- */

static void t_bsketch(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_bsketch g;
	uint64_t e, m, site[4], a, b, c, z, w;
	uint32_t ia, ib, ic, iw;

	fk_init(&o);
	z = fk_stub(&o, 1, site + 3);           /* z calls w, and nothing calls z: it lies before every start */
	w = fk_func(&o, 4, 40, &V0);
	e = fk_entry(&o, 0);
	m = fk_stub(&o, 2, site);
	a = fk_stub(&o, 1, site + 2);           /* a calls c */
	b = fk_func(&o, 1, 40, &V0);
	c = fk_func(&o, 2, 40, &V0);
	fk_call_to(&o, site[0], a);
	fk_call_to(&o, site[1], b);
	fk_call_to(&o, site[2], c);
	fk_call_to(&o, site[3], w);
	{ int32_t d = (int32_t)((int64_t)m - (int64_t)(e + 7)); memcpy(o.b + e + 3, &d, 4); }
	CK(kgenome_fnprint_bsketch_main(o.b, o.n, e, 0, 0, o.n) == m);
	CK(kgenome_fnprint_bsketch_main(o.b, o.n, o.n + 5, 0, 0, o.n) == KGENOME_BROKEN);
	kgenome_fnprint_bsketch_build(&g, o.b, 0, o.n, 0, m, NULL);
	ia = kgenome_fnprint_bsketch_find(&g, a);
	ib = kgenome_fnprint_bsketch_find(&g, b);
	ic = kgenome_fnprint_bsketch_find(&g, c);
	iw = kgenome_fnprint_bsketch_find(&g, w);
	CK(ia != UINT32_MAX && ib != UINT32_MAX && ic != UINT32_MAX && iw != UINT32_MAX);
	CK(g.reached[ia] && g.reached[ib] && g.reached[ic]);     /* what main reaches, one level and two */
	CK(!g.reached[iw]);                                      /* only an unreached caller names it: a prior, not a verdict */
	CK(kgenome_fnprint_bsketch_find(&g, z) == UINT32_MAX);   /* before the first start: in no stretch */
	CK(g.status == KGENOME_OK);
	kgenome_fnprint_bsketch_free(&g);
	fk_free(&o);
}

static void t_bsketch_noise(void)
{
	struct kgenome_fnprint_bsketch g;
	uint8_t *p = malloc(1u << 20);

	if (!p)
		return;
	rnd_bytes(p, 1u << 20, 77);
	kgenome_fnprint_bsketch_build(&g, p, 0, 1u << 20, 0, KGENOME_BROKEN, NULL);
	/* a random 32-bit displacement lands in a 1 MB text 1 time in 4096: false edges are rare */
	CK(g.n_edge < 64u);
	CK(g.scanned == 1u << 20);
	kgenome_fnprint_bsketch_free(&g);
	free(p);
}

static void t_bsketch_budget(void)
{
	struct kgenome_fnprint_bsketch g;
	struct kgenome_ledger led;
	uint8_t *p = malloc(1u << 16);
	uint32_t i;

	if (!p)
		return;
	memset(p, 0x90, 1u << 16);
	for (i = 0; i + 5 < (1u << 16); i += 5) {         /* a call every 5 bytes to the next */
		int32_t d = 0;

		p[i] = 0xe8;
		memcpy(p + i + 1, &d, 4);
	}
	kgenome_ledger_init(&led, 4096);
	kgenome_fnprint_bsketch_build(&g, p, 0, 1u << 16, 0, 0, &led);
	CK(g.status == KGENOME_OVER_BUDGET && g.n_edge == 0 && led.used == 0);   /* said so, kept nothing, leaked nothing */
	kgenome_fnprint_bsketch_free(&g);
	free(p);
}

/* ---- the database and its context ---------------------------------------------------- */

struct db {
	struct kgenome_fnprint_wblock blk[8];
	uint32_t pool[256];
	uint32_t n_blk, n_pool;
};

static void blk_add(struct db *d, const uint32_t *h, uint32_t n, uint32_t side, uint32_t tag)
{
	d->blk[d->n_blk].first = d->n_pool;
	d->blk[d->n_blk].n = n;
	d->blk[d->n_blk].side = side;
	d->blk[d->n_blk].tag = tag;
	memcpy(d->pool + d->n_pool, h, n * sizeof *h);
	d->n_pool += n;
	d->n_blk++;
}

static void t_wdb_validation(void)
{
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_wblock b[2];
	uint32_t pool[64], i;

	for (i = 0; i < 64; i++)
		pool[i] = 1000u + i;
	memset(&o, 0, sizeof o);
	o.n_tag = 2;
	b[0].first = 0; b[0].n = 32; b[0].side = 0; b[0].tag = 0;
	b[1] = b[0];
	b[1].first = 32;
	CK(kgenome_fnprint_wdb_build(&d, b, 2, pool, 64, &o) && d.n_pair == 64 && d.status == KGENOME_OK);
	CK(d.n_key == 64 && d.max_run == 1 && d.top == 1063u);
	kgenome_fnprint_wdb_free(&d);
	b[1].first = 40;                                         /* its hashes run past the pool */
	CK(!kgenome_fnprint_wdb_build(&d, b, 2, pool, 64, &o) && d.status == KGENOME_BAD_INPUT);
	b[1].first = 32; b[1].n = 0;                             /* an empty block */
	CK(!kgenome_fnprint_wdb_build(&d, b, 2, pool, 64, &o) && d.status == KGENOME_BAD_INPUT);
	b[1].n = 32; b[1].tag = 2;                               /* a tag that does not exist */
	CK(!kgenome_fnprint_wdb_build(&d, b, 2, pool, 64, &o) && d.status == KGENOME_BAD_INPUT);
	b[1].tag = 1; b[1].n = KGENOME_FNP_WDB_MAXN + 1u;
	CK(!kgenome_fnprint_wdb_build(&d, b, 2, pool, 64, &o) && d.status == KGENOME_BAD_INPUT);
	/* more blocks than the index word holds: refused as TRUNCATED, not cut to fit */
	CK(!kgenome_fnprint_wdb_build(&d, b, KGENOME_FNP_WDB_MAX_BLOCKS + 1u, pool, 64, &o) && d.status == KGENOME_TRUNCATED);
}

static void t_wdb_ledger(void)
{
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_wblock *b = calloc(1000, sizeof *b);
	uint32_t *pool = malloc(32000u * 4u), i;
	struct kgenome_ledger led;

	if (!b || !pool)
		return;
	for (i = 0; i < 32000u; i++)
		pool[i] = i * 2654435761u;
	for (i = 0; i < 1000u; i++) {
		b[i].first = i * 32u; b[i].n = 32; b[i].side = 0; b[i].tag = 0;
	}
	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	kgenome_ledger_init(&led, 100u * 1024u);                 /* 32000 pairs need 256 KB for the sort alone */
	o.led = &led;
	CK(!kgenome_fnprint_wdb_build(&d, b, 1000, pool, 32000, &o));
	CK(d.status == KGENOME_OVER_BUDGET && led.used == 0);    /* refused loudly and gave everything back */
	kgenome_ledger_init(&led, 8u << 20);
	CK(kgenome_fnprint_wdb_build(&d, b, 1000, pool, 32000, &o) && led.used == d.bytes && d.bytes > 32000u * 8u);
	kgenome_fnprint_wdb_free(&d);
	CK(led.used == 0);
	free(b); free(pool);
}

static void t_credit_semantics(void)
{
	struct db db = { 0 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_wctx c;
	uint32_t h0[16], h1[16], i;

	for (i = 0; i < 16; i++) {
		h0[i] = 0x10000u * (i + 1u);
		h1[i] = 0x10000u * (i + 1u) + (i < 8 ? 0u : 7u);        /* shares 8 hashes with block 0 */
	}
	blk_add(&db, h0, 16, KGENOME_MUTATION_SIDE_USER, 0);
	blk_add(&db, h1, 16, KGENOME_MUTATION_SIDE_USER, 1);
	blk_add(&db, h0, 16, KGENOME_MUTATION_SIDE_LIB, 0);      /* the same hashes on the other side */
	memset(&o, 0, sizeof o);
	o.n_tag = 2;
	CK(kgenome_fnprint_wdb_build(&d, db.blk, db.n_blk, db.pool, db.n_pool, &o));
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	kgenome_fnprint_wctx_begin(&c);
	for (i = 0; i < 100; i++)                                /* a hot window repeated 100 times is one hash */
		kgenome_fnprint_wctx_credit(&c, h0[0], KGENOME_MUTATION_SIDE_USER);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 1 && kgenome_fnprint_wctx_count(&c, 1) == 1);
	CK(kgenome_fnprint_wctx_count(&c, 2) == 0);              /* the LIB block is not credited from the USER side */
	CK(c.n_hot_repeat >= 99);
	for (i = 1; i < 16; i++)
		kgenome_fnprint_wctx_credit(&c, h0[i], KGENOME_MUTATION_SIDE_USER);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 16);
	CK(kgenome_fnprint_wctx_count(&c, 1) == 8);              /* only the shared half */
	kgenome_fnprint_wctx_credit(&c, h0[3], KGENOME_MUTATION_SIDE_LIB);
	CK(kgenome_fnprint_wctx_count(&c, 2) == 1);
	kgenome_fnprint_wctx_credit(&c, 0xdeadbeefu, KGENOME_MUTATION_SIDE_USER);   /* in no block */
	kgenome_fnprint_wctx_begin(&c);                           /* the next object starts from zero */
	CK(kgenome_fnprint_wctx_count(&c, 0) == 0 && kgenome_fnprint_wctx_count(&c, 2) == 0);
	kgenome_fnprint_wctx_credit(&c, h0[0], KGENOME_MUTATION_SIDE_USER);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 1);
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
}

static void t_retirement_is_opt_in(void)
{
	struct db db = { 0 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_wctx c;
	uint32_t h0[32], h1[32], i;

	for (i = 0; i < 32; i++) {
		h0[i] = 0x01000000u + i * 0x1000u;
		h1[i] = 0x02000000u + i * 0x1000u;
	}
	blk_add(&db, h0, 32, KGENOME_MUTATION_SIDE_USER, 0);
	blk_add(&db, h1, 32, KGENOME_MUTATION_SIDE_USER, 1);
	memset(&o, 0, sizeof o);
	o.n_tag = 2;
	CK(kgenome_fnprint_wdb_build(&d, db.blk, db.n_blk, db.pool, db.n_pool, &o));
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	kgenome_fnprint_wctx_begin(&c);
	CK(c.policy == KGENOME_FNP_RETIRE_NONE && c.n_dead == 0);   /* the default retires nothing */
	for (i = 0; i < 16; i++)
		kgenome_fnprint_wctx_credit(&c, h0[i], KGENOME_MUTATION_SIDE_USER);
	kgenome_fnprint_wctx_retire(&c, 0, 1);                       /* explicit */
	CK(c.n_dead == 1 && c.n_rebuild == 1);                       /* half the pairs dead: the filter was rebuilt */
	for (i = 16; i < 32; i++)
		kgenome_fnprint_wctx_credit(&c, h0[i], KGENOME_MUTATION_SIDE_USER);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 16);                 /* a retired tag's credit stops growing */
	for (i = 0; i < 32; i++)
		kgenome_fnprint_wctx_credit(&c, h1[i], KGENOME_MUTATION_SIDE_USER);
	CK(kgenome_fnprint_wctx_count(&c, 1) == 32);                 /* the other tag is unaffected */
	CK(c.n_skip_dead >= 16);
	kgenome_fnprint_wctx_begin(&c);                               /* retirement is per object */
	CK(c.n_dead == 0 && c.rfilter == NULL);
	for (i = 0; i < 32; i++)
		kgenome_fnprint_wctx_credit(&c, h0[i], KGENOME_MUTATION_SIDE_USER);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 32);
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
}

/* ---- the pass --------------------------------------------------------------------- */

static void t_wpass(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_libtab lib;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts op;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_stat st;
	struct kgenome_fnprint_wpass_req rq;
	struct kof_range ext;
	struct db db = { 0 };
	uint32_t sk[32], n, libfn_off, au_off, au_len, lib_len;

	fk_init(&o);
	libfn_off = (uint32_t)fk_func(&o, 900, 150, &V0);
	lib_len = (uint32_t)(o.n - libfn_off);
	au_off = (uint32_t)fk_func(&o, 901, 150, &V0);
	au_len = (uint32_t)(o.n - au_off);
	kgenome_fnprint_libtab_init(&lib, 0, NULL);
	kgenome_fnprint_libtab_add(&lib, o.b + libfn_off, lib_len);
	/* the block of the author's function: its windows that are not library */
	n = kgenome_fnprint_wsketch(o.b + au_off, au_len, &lib, sk, 32);
	CK(n == 32);
	blk_add(&db, sk, n, KGENOME_MUTATION_SIDE_USER, 0);
	/* the block of the LIBRARY function: its windows are library, so no USER block can hold them */
	n = kgenome_fnprint_wsketch(o.b + libfn_off, lib_len, &lib, sk, 32);
	CK(n == 0);
	n = kgenome_fnprint_wsketch(o.b + libfn_off, lib_len, NULL, sk, 32);
	CK(n == 32);
	blk_add(&db, sk, n, KGENOME_MUTATION_SIDE_USER, 1);
	memset(&op, 0, sizeof op);
	op.n_tag = 2;
	CK(kgenome_fnprint_wdb_build(&d, db.blk, db.n_blk, db.pool, db.n_pool, &op));
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	kgenome_fnprint_wctx_begin(&c);
	ext.off = 0; ext.len = o.n;
	memset(&rq, 0, sizeof rq);
	rq.p = o.b; rq.n = o.n; rq.ext = &ext; rq.n_ext = 1; rq.lib = &lib; rq.c = &c; rq.stat = &st;
	kgenome_fnprint_wpass(&rq);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 32);             /* the author's block: credited in full */
	CK(st.n_bad_ext == 0);
	{                                                         /* a range that runs past the bytes is skipped and counted, never read */
		struct kof_range bad[2] = { { 0, o.n }, { o.n - 4u, 64u } };

		kgenome_fnprint_wctx_begin(&c);
		rq.ext = bad; rq.n_ext = 2;
		kgenome_fnprint_wpass(&rq);
		CK(st.n_bad_ext == 1 && kgenome_fnprint_wctx_count(&c, 0) == 32);
		rq.ext = &ext; rq.n_ext = 1;
	}
	CK(kgenome_fnprint_wctx_count(&c, 1) == 0);              /* the library's windows are library by bytes: excluded */
	CK(st.n_lib > 0 && st.n_win == o.n - 7u && !st.stopped);
	/* without the table the same bytes credit both: the exclusion is the table's, not the pass's */
	kgenome_fnprint_wctx_begin(&c);
	rq.lib = NULL;
	kgenome_fnprint_wpass(&rq);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 32 && kgenome_fnprint_wctx_count(&c, 1) == 32);
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	kgenome_fnprint_libtab_free(&lib);
	fk_free(&o);
}

static void t_wpass_policy(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts op;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_stat st0, st1, st2;
	struct kgenome_fnprint_wpass_req rq;
	struct kof_range ext;
	struct db db = { 0 };
	uint32_t sk[32], n, a, la, b, lb;

	fk_init(&o);
	a = (uint32_t)fk_func(&o, 910, 100, &V0); la = (uint32_t)(o.n - a);
	fk_fill(&o, 0x90, 8000);                                 /* a lot of code behind it */
	b = (uint32_t)fk_func(&o, 911, 100, &V0); lb = (uint32_t)(o.n - b);
	n = kgenome_fnprint_wsketch(o.b + a, la, NULL, sk, 32);
	blk_add(&db, sk, n, KGENOME_MUTATION_SIDE_USER, 0);
	n = kgenome_fnprint_wsketch(o.b + b, lb, NULL, sk, 32);
	blk_add(&db, sk, n, KGENOME_MUTATION_SIDE_USER, 1);
	memset(&op, 0, sizeof op);
	op.n_tag = 2;
	CK(kgenome_fnprint_wdb_build(&d, db.blk, db.n_blk, db.pool, db.n_pool, &op));
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL));
	ext.off = 0; ext.len = o.n;
	memset(&rq, 0, sizeof rq);
	rq.p = o.b; rq.n = o.n; rq.ext = &ext; rq.n_ext = 1; rq.c = &c;
	/* the default: every tag keeps being evaluated */
	kgenome_fnprint_wctx_begin(&c);
	rq.stat = &st0;
	kgenome_fnprint_wpass(&rq);
	CK(kgenome_fnprint_wctx_count(&c, 0) == 32 && kgenome_fnprint_wctx_count(&c, 1) == 32 && !st0.stopped && c.n_dead == 0);
	/* the opt-in policy: the first tag decided stops the pass, and what it did not see is counted */
	kgenome_fnprint_wctx_begin(&c);
	rq.stat = &st1; rq.policy = KGENOME_FNP_RETIRE_STOP_FIRST; rq.decide_pct = 70;
	kgenome_fnprint_wpass(&rq);
	CK(st1.stopped && st1.n_stop_bytes > 8000 && kgenome_fnprint_wctx_count(&c, 1) < 4);   /* a window or two both functions share */
	/* retire each tag at its detection, stop when all are retired */
	kgenome_fnprint_wctx_begin(&c);
	rq.stat = &st2; rq.policy = KGENOME_FNP_RETIRE_TAG_STOP;
	kgenome_fnprint_wpass(&rq);
	CK(st2.n_decided == 2 && st2.stopped && c.n_dead == 2);
	CK(kgenome_fnprint_wctx_count(&c, 0) >= 23 && kgenome_fnprint_wctx_count(&c, 0) < 32);   /* credit stopped growing at the decision */
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_wdb_free(&d);
	fk_free(&o);
}

int main(void)
{
	t_libtab_basic();
	t_libtab_sampled();
	t_libtab_ledger();
	t_bstat();
	t_bsketch();
	t_bsketch_noise();
	t_bsketch_budget();
	t_wdb_validation();
	t_wdb_ledger();
	t_credit_semantics();
	t_retirement_is_opt_in();
	t_wpass();
	t_wpass_policy();
	printf("fnprint_pred: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
