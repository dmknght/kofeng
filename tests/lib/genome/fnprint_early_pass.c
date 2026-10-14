/*
 * fnprint_early_pass - the decision-complete interrupt through the REAL pass (kgenome_fnprint_wpass),
 * on bytes: blocks are the 32 smallest windows of random function bodies (the generator's own
 * kgenome_mutation_minhash), an object is some of those bodies, edited, among junk and copies, and the
 * ranges handed to the pass are its functions.
 *
 * Equality: for every cluster, the state the DX pass ends in is MET exactly when the counts of a pass that
 * retires nothing say "held". The pass reports what it rolled (n_win_rolled), what a stop left
 * (n_win_unvisited) and a range that does not fit (n_bad_ext): rolled + unvisited + what the stop cut
 * inside a range accounts for every window of every valid range.
 */
#include "fnprint_early_kit.h"
#include "../../unit/known_miss.h"

#define NF   24u
#define MAXL 1500u

struct ref {
	uint8_t  body[NF][MAXL];
	uint32_t len[NF];
	struct kgenome_fnprint_wblock blk[NF];
	uint32_t pool[NF * 32u];
	uint32_t n_blk;
	struct kgenome_fnprint_dx dx[NF / 3u];
	uint32_t ref[NF];
	struct kgenome_fnprint_cl cl[4];
	uint32_t mem[NF / 3u];
};

static void ref_make(struct ref *r, uint64_t seed)
{
	struct hk_rng g = { seed * 31u + 7u };
	uint32_t f, j, n = 0, d, k;

	memset(r, 0, sizeof *r);
	for (f = 0; f < NF; f++) {
		r->len[f] = 300u + hk_below(&g, MAXL - 300u);
		for (j = 0; j < r->len[f]; j++)
			r->body[f][j] = (uint8_t)hk_next(&g);
		n = kgenome_mutation_minhash(r->body[f], r->len[f], KGENOME_MUTATION_RAW, r->pool + r->n_blk * 32u);
		r->blk[r->n_blk].first = r->n_blk * 32u;
		r->blk[r->n_blk].n = n;
		r->blk[r->n_blk].side = KGENOME_MUTATION_SIDE_USER;
		r->blk[r->n_blk].tag = 0;
		r->ref[r->n_blk] = r->n_blk;
		r->n_blk++;
	}
	for (d = 0; d < NF / 3u; d++) {
		r->dx[d].first = d * 3u;
		r->dx[d].n = 3;
		r->dx[d].need = 1u + hk_below(&g, 3u);
		r->dx[d].pct = 70;
		r->mem[d] = d;
	}
	for (k = 0; k < 4u; k++) {
		r->cl[k].first = k * 2u;
		r->cl[k].n = 2;
		r->cl[k].k = 1u + hk_below(&g, 2u);
	}
}

struct subj {
	uint8_t *p;
	uint64_t n;
	struct kof_range *fn;
	uint32_t n_fn;
};

static void subj_make(struct subj *s, const struct ref *r, struct hk_rng *g)
{
	uint32_t f, copies, nj = 8u + hk_below(g, 40u), cap = 64u + nj, j;
	uint64_t at = 0;

	s->p = malloc(NF * MAXL * 3u + 40u * 700u + 4096u);
	s->fn = calloc(cap, sizeof *s->fn);
	s->n_fn = 0;
	for (f = 0; f < NF; f++) {
		uint32_t pick = hk_below(g, 100u);

		if (pick >= 45u)
			continue;                                             /* this function is not in the object */
		for (copies = 1u + (pick < 5u ? hk_below(g, 5u) : 0u); copies; copies--) {
			memcpy(s->p + at, r->body[f], r->len[f]);
			if (pick > 25u) {                                     /* edited: a few bytes changed */
				uint32_t e, ne = hk_below(g, 12u);

				for (e = 0; e < ne; e++)
					s->p[at + hk_below(g, r->len[f])] = (uint8_t)hk_next(g);
			}
			s->fn[s->n_fn].off = at;
			s->fn[s->n_fn++].len = r->len[f];
			at += r->len[f];
		}
	}
	for (j = 0; j < nj && s->n_fn + 1u < cap; j++) {              /* junk: random, padding, a repeat of the last */
		uint32_t kind = hk_below(g, 3u), len = 40u + hk_below(g, 600u), q;

		for (q = 0; q < len; q++)
			s->p[at + q] = kind == 1u ? 0x90 : kind == 2u && s->n_fn ? s->p[s->fn[s->n_fn - 1u].off + q % s->fn[s->n_fn - 1u].len]
			                                            : (uint8_t)hk_next(g);
		s->fn[s->n_fn].off = at;
		s->fn[s->n_fn++].len = len;
		at += len;
	}
	s->n = at;
}

static uint32_t one(uint64_t seed, uint64_t *rolled_full, uint64_t *rolled_dx)
{
	struct ref *r = malloc(sizeof *r);
	struct hk_rng g = { seed * 977u + 3u };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_dxdesc desc;
	struct kgenome_fnprint_wctx cf, ce;
	struct subj s;
	struct kgenome_fnprint_wpass_req rq;
	struct kgenome_fnprint_wpass_stat sf, se;
	uint32_t bad = 0, k, tot = 0, i;
	uint64_t total_win = 0;

	ref_make(r, seed);
	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	memset(&desc, 0, sizeof desc);
	desc.dx = r->dx; desc.n_dx = NF / 3u; desc.ref = r->ref; desc.n_ref = NF;
	if (seed & 1u) {
		desc.cl = r->cl; desc.n_cl = 4; desc.mem = r->mem; desc.n_mem = 8;
	}
	CK(kgenome_fnprint_wdb_build(&d, r->blk, r->n_blk, r->pool, (uint64_t)r->n_blk * 32u, &o));
	CK(kgenome_fnprint_dxdb_build(&x, &d, &desc, NULL));
	CK(kgenome_fnprint_wctx_init(&cf, &d, NULL) && kgenome_fnprint_wctx_init(&ce, &d, NULL) && kgenome_fnprint_dx_attach(&ce, &x));
	subj_make(&s, r, &g);
	for (i = 0; i < s.n_fn; i++)
		total_win += s.fn[i].len >= 8u ? s.fn[i].len - 7u : 0;
	memset(&rq, 0, sizeof rq);
	rq.p = s.p; rq.n = s.n; rq.ext = s.fn; rq.n_ext = s.n_fn;
	rq.c = &cf; rq.stat = &sf;
	kgenome_fnprint_wctx_begin(&cf);
	kgenome_fnprint_wpass(&rq);
	rq.c = &ce; rq.stat = &se; rq.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&ce);
	kgenome_fnprint_wpass(&rq);
	CK(sf.n_win_rolled == total_win && sf.n_win_unvisited == 0);
	CK(se.status == KGENOME_OK);
	/* the windows of every range are accounted for: rolled, cut inside the range the stop fell in, never started */
	CK(se.n_win_rolled + se.n_win_unvisited <= total_win);
	CK(!se.stopped ? se.n_win_rolled + se.n_win_unvisited == total_win : 1);
	CK(kgenome_fnprint_dx_open(&ce) == 0u);                          /* a finished pass decides every consumer */
	for (k = 0; k < (desc.cl ? desc.n_cl : desc.n_dx); k++) {
		int full = kgenome_fnprint_dx_full(&x, &cf, k);
		enum kgenome_fnprint_dstate st = kgenome_fnprint_dx_cluster(&ce, k);

		bad += st == KGENOME_FNP_D_UNDECIDED || (st == KGENOME_FNP_D_MET) != (full != 0);
		tot += full != 0;
	}
	*rolled_full += total_win;
	*rolled_dx += se.n_win_rolled;
	kgenome_fnprint_wctx_done(&cf); kgenome_fnprint_wctx_done(&ce);
	kgenome_fnprint_dxdb_free(&x); kgenome_fnprint_wdb_free(&d);
	free(s.p); free(s.fn); free(r);
	(void)tot;
	return bad;
}

/*
 * The limit of the interrupt, which no tuning removes: an object that matches NOTHING is decided only when
 * too few windows are left for any block to reach its percent (at most 128, the hashes of the largest
 * block). What is unread can hold anything; a sound bound cannot say otherwise. So the interrupt saves
 * work on objects that match and not on the ones that do not.
 */
static void t_clean_object(void)
{
	struct ref *r = malloc(sizeof *r);
	struct hk_rng g = { 424242 };
	struct kgenome_fnprint_wdb d;
	struct kgenome_fnprint_wdb_opts o;
	struct kgenome_fnprint_dxdb x;
	struct kgenome_fnprint_dxdesc desc;
	struct kgenome_fnprint_wctx c;
	struct kgenome_fnprint_wpass_req rq;
	struct kgenome_fnprint_wpass_stat st;
	struct kof_range fn[400];
	uint8_t *p = malloc(400u * 300u);
	uint64_t total = 0;
	uint32_t i, j;

	ref_make(r, 5);
	memset(&o, 0, sizeof o);
	o.n_tag = 1;
	memset(&desc, 0, sizeof desc);
	desc.dx = r->dx; desc.n_dx = NF / 3u; desc.ref = r->ref; desc.n_ref = NF;
	CK(kgenome_fnprint_wdb_build(&d, r->blk, r->n_blk, r->pool, (uint64_t)r->n_blk * 32u, &o));
	CK(kgenome_fnprint_dxdb_build(&x, &d, &desc, NULL));
	CK(kgenome_fnprint_wctx_init(&c, &d, NULL) && kgenome_fnprint_dx_attach(&c, &x));
	for (i = 0; i < 400u; i++) {
		fn[i].off = i * 300u;
		fn[i].len = 300;
		for (j = 0; j < 300u; j++)
			p[i * 300u + j] = (uint8_t)hk_next(&g);
		total += 293u;
	}
	memset(&rq, 0, sizeof rq);
	rq.p = p; rq.n = 400u * 300u; rq.ext = fn; rq.n_ext = 400; rq.c = &c; rq.stat = &st; rq.policy = KGENOME_FNP_RETIRE_DX;
	kgenome_fnprint_wctx_begin(&c);
	kgenome_fnprint_wpass(&rq);
	CK(kgenome_fnprint_dx_open(&c) == 0u);                           /* decided, by the bound, with at most 128 windows left */
	CK(st.n_win_rolled + 128u + 293u >= total);
	KM_CHECK(st.n_win_rolled * 2u < total, "an object that matches nothing is decided before it is exhausted",
		 "IMPOSSIBLE_NEEDS_THE_END_OF_THE_OBJECT");
	kgenome_fnprint_wctx_done(&c);
	kgenome_fnprint_dxdb_free(&x);
	kgenome_fnprint_wdb_free(&d);
	free(p); free(r);
}

int main(void)
{
	uint64_t seed, rf = 0, rd = 0;
	uint32_t bad = 0;

	for (seed = 1; seed <= 120u * hk_scale(); seed++)
		bad += one(seed, &rf, &rd);
	CK(bad == 0);
	CK(rd <= rf);
	t_clean_object();
	printf("  EARLY-PASS windows full=%llu dx=%llu (%.1f%%)\n", (unsigned long long)rf, (unsigned long long)rd, 100.0 * (double)rd / (double)rf);
	printf("fnprint_early_pass: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
