/*
 * fnprint_reliability - the same input gives the same output, and the answer does
 * not depend on how the function set was reached or what lies between functions.
 *
 *   - twice over the same object: identical records;
 *   - the function set in another ORDER: the same fingerprints for the same
 *     extents (a fingerprint is a function of bytes; only the relevance of an
 *     address-ordered rule may differ, and the walk says so in n_unsorted);
 *   - padding (zeros, int3, nops) BETWEEN functions: the same fingerprints;
 *   - the normalised view (zero runs collapsed) with the functions remapped by
 *     kgenome_funcs_remap: the same fingerprints;
 *   - a limit that fires says so: steps (OVER_BUDGET, the skipped count), the
 *     ledger (OVER_BUDGET, nothing grows), an unsorted set (TRUNCATED, counted);
 *   - separate instances on separate threads give the same answer.
 */
#include <pthread.h>

#include "fnprint_kit.h"

static struct fk_var V = { 0x321, 0x654, 0x11223344u };

static void build(struct fk_obj *o, uint32_t nf, uint32_t gap, uint8_t gapbyte)
{
	uint32_t i;

	fk_init(o);
	for (i = 0; i < nf; i++) {
		fk_func(o, 500 + i, 20 + (i % 15), &V);
		if (gap)
			fk_fill(o, gapbyte, gap);
	}
}

static uint32_t collect(const struct fk_obj *o, const struct kgenome_func_set *fs, struct kgenome_fnprint_set *s,
			enum kgenome_fnprint_link link)
{
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set own;

	fk_req(&rq, o, link, &st, &own);
	if (fs)
		rq.funcs = fs;
	kgenome_fnprint_collect(&rq, s);
	return s->n;
}

static int by_off(const void *a, const void *b)
{
	const struct kgenome_fnprint_fn *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

static void t_deterministic(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set a, b;
	uint32_t i;

	build(&o, 50, 7, 0xcc);
	collect(&o, NULL, &a, KGENOME_FNP_LINK_DYNAMIC);
	collect(&o, NULL, &b, KGENOME_FNP_LINK_DYNAMIC);
	CK(a.n == 50 && b.n == 50);
	for (i = 0; i < a.n && i < b.n; i++)
		CK(!memcmp(&a.fn[i], &b.fn[i], sizeof a.fn[i]));
	kgenome_fnprint_set_free(&a, NULL); kgenome_fnprint_set_free(&b, NULL);
	fk_free(&o);
}

static void t_discovery_order(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_set a, b;
	struct kgenome_func_set fs;
	struct kgenome_func *rev;
	uint32_t i;

	build(&o, 40, 5, 0xcc);
	collect(&o, NULL, &a, KGENOME_FNP_LINK_DYNAMIC);
	rev = malloc(o.nf * sizeof *rev);
	for (i = 0; i < o.nf; i++)
		rev[i] = o.v[o.nf - 1 - i];            /* descending: the order a hostile or buggy builder gives */
	fs.v = rev; fs.n = o.nf; fs.status = KGENOME_OK;
	collect(&o, &fs, &b, KGENOME_FNP_LINK_DYNAMIC);
	CK(b.n == a.n);
	CK(b.stat.n_unsorted > 0);                    /* it says the set was not in address order */
	CK(b.stat.status == KGENOME_TRUNCATED);       /* ...and that the answer may be partial for it */
	qsort(a.fn, a.n, sizeof *a.fn, by_off);
	qsort(b.fn, b.n, sizeof *b.fn, by_off);
	for (i = 0; i < a.n && i < b.n; i++) {
		CK(a.fn[i].off == b.fn[i].off);
		CK(a.fn[i].fp == b.fn[i].fp && a.fn[i].fw == b.fn[i].fw);
	}
	kgenome_fnprint_set_free(&a, NULL); kgenome_fnprint_set_free(&b, NULL);
	free(rev);
	fk_free(&o);
}

static void t_padding_between(void)
{
	struct fk_obj p, q;
	struct kgenome_fnprint_set a, b;
	uint32_t i;
	static const uint8_t pads[3] = { 0xcc, 0x90, 0x00 };
	uint32_t pi;

	build(&p, 30, 0, 0);
	collect(&p, NULL, &a, KGENOME_FNP_LINK_DYNAMIC);
	for (pi = 0; pi < 3; pi++) {
		build(&q, 30, 61, pads[pi]);
		collect(&q, NULL, &b, KGENOME_FNP_LINK_DYNAMIC);
		CK(a.n == b.n);
		for (i = 0; i < a.n && i < b.n; i++)
			CK(a.fn[i].fp == b.fn[i].fp);
		kgenome_fnprint_set_free(&b, NULL);
		fk_free(&q);
	}
	kgenome_fnprint_set_free(&a, NULL);
	fk_free(&p);
}

/* The normalised view: zero runs of 8 or more collapse to 2, the function set is remapped, the fingerprints are the same. */
static void t_view_collapse(void)
{
	struct fk_obj o, v;
	struct kgenome_fnprint_set a, b;
	struct kgenome_func_set vf;
	uint64_t i, j = 0;
	uint32_t k;

	build(&o, 30, 40, 0x00);                      /* 40 zero bytes after every function */
	fk_init(&v);
	for (i = 0; i < o.n;) {
		if (o.b[i] == 0) {
			uint64_t r = i;

			while (r < o.n && o.b[r] == 0)
				r++;
			fk_fill(&v, 0, r - i >= 8 ? 2 : r - i);
			i = r;
		} else {
			fk_raw(&v, o.b + i, 1);
			i++;
		}
	}
	(void)j;
	{
		struct kgenome_func_set pf = { o.v, o.nf, KGENOME_OK };

		memset(&vf, 0, sizeof vf);
		kgenome_funcs_remap(o.b, o.n, &pf, v.b, v.n, &vf);
	}
	CK(v.n < o.n);
	CK(vf.n == o.nf);
	collect(&o, NULL, &a, KGENOME_FNP_LINK_DYNAMIC);
	{
		struct kgenome_fnprint_req rq;
		struct kgenome_fnprint_stat st;
		struct kgenome_func_set own;

		fk_req(&rq, &v, KGENOME_FNP_LINK_DYNAMIC, &st, &own);
		rq.funcs = &vf;
		kgenome_fnprint_collect(&rq, &b);
	}
	CK(a.n == b.n);
	for (k = 0; k < a.n && k < b.n; k++)
		CK(a.fn[k].fp == b.fn[k].fp && a.fn[k].fw == b.fn[k].fw);
	kgenome_funcs_free(&vf);
	kgenome_fnprint_set_free(&a, NULL); kgenome_fnprint_set_free(&b, NULL);
	fk_free(&o); fk_free(&v);
}

static void t_step_budget_reports(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_budget bd;

	build(&o, 200, 0, 0);
	fk_req(&rq, &o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	kgenome_budget_default(&bd, o.n, 0);
	bd.max_steps = 500;                           /* a few functions' worth */
	rq.budget = &bd;
	kgenome_fnprint_walk(&rq);
	CK(st.status == KGENOME_OVER_BUDGET);
	CK(st.n_visited < 200 && st.n_skipped == st.n_funcs - st.n_visited);
	CK(st.n_skipped > 0);                         /* the rest is counted, not dropped */
	/* with the default budget it completes */
	rq.budget = NULL;
	kgenome_fnprint_walk(&rq);
	CK(st.status == KGENOME_OK && st.n_visited == 200 && st.n_skipped == 0);
	fk_free(&o);
}

static void t_ledger_refuses(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_ledger led;
	struct kgenome_fnprint_set s;

	build(&o, 600, 0, 0);
	fk_req(&rq, &o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	kgenome_ledger_init(&led, 16);                /* less than the walk's own scratch */
	rq.led = &led;
	kgenome_fnprint_walk(&rq);
	CK(st.status == KGENOME_OVER_BUDGET && st.n_visited == 0 && st.n_skipped == 600);
	CK(led.used == 0);
	/* the collecting variant stops at the allowance and says so; what it holds is charged and released */
	{
		struct kgenome_fnprint_req r2 = rq;

		kgenome_ledger_init(&led, 40000);
		r2.led = &led;
		kgenome_fnprint_collect(&r2, &s);
		CK(s.stat.status == KGENOME_OVER_BUDGET);
		CK(s.n < 600 && s.n > 0);
		CK(led.used == s.bytes);
		kgenome_fnprint_set_free(&s, &led);
		CK(led.used == 0);
	}
	fk_free(&o);
}

struct thr { const struct fk_obj *o; uint64_t sum; };

static void *worker(void *p)
{
	struct thr *t = p;
	struct kgenome_fnprint_set s;
	uint32_t i;

	collect(t->o, NULL, &s, KGENOME_FNP_LINK_DYNAMIC);
	for (i = 0; i < s.n; i++)
		t->sum = t->sum * 1000003u + s.fn[i].fp;
	kgenome_fnprint_set_free(&s, NULL);
	return NULL;
}

static void t_threads(void)
{
	struct fk_obj o;
	pthread_t th[4];
	struct thr t[4];
	int i;

	build(&o, 300, 3, 0xcc);
	for (i = 0; i < 4; i++) {
		t[i].o = &o; t[i].sum = 0;
		pthread_create(&th[i], NULL, worker, &t[i]);
	}
	for (i = 0; i < 4; i++)
		pthread_join(th[i], NULL);
	for (i = 1; i < 4; i++)
		CK(t[i].sum == t[0].sum && t[0].sum != 0);
	fk_free(&o);
}

int main(void)
{
	t_deterministic();
	t_discovery_order();
	t_padding_between();
	t_view_collapse();
	t_step_budget_reports();
	t_ledger_refuses();
	t_threads();
	printf("fnprint_reliability: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0;
}
