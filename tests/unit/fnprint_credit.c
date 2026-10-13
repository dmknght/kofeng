/*
 * fnprint_credit - the scan-time block credit: which bytes are hashed is decided
 * from the object's own functions at scan time and the units go to the existing
 * matcher (kof_mutation_unit) against a database of real blocks; the side a
 * block was stored with is not trusted.
 *
 *   (A) relevance-selected units: AUTHOR, AUTHOR+UNKNOWN, or every byte sided by
 *       the class the walk gave it (KGENOME_FNP_PICK_*);
 *   (B) diagnose-gated: only functions that hold a node the caller names.
 *
 * Built in memory: functions from fnprint_kit.h, the database from the
 * generator's own minhash. No corpus.
 */
#include "fnprint_db.h"
#include "known_miss.h"

static struct fk_var V = { 0x100, 0x200, 0x30405060u };

/*
 * "Not credited" is below this, not zero: functions built from one instruction template share windows (a
 * return followed by the next prologue, a prologue and its first instruction), and a block is the 32
 * smallest window hashes, a few of which are such windows. The same non-specific-feature effect the
 * corpus shows with real code, here in its smallest form.
 */
#define NOISE 25u

/* entry, author functions, `nw` wrappers (the frontier), library functions; main is the first author function. */
static uint64_t prog(struct fk_obj *o, uint32_t aseed, uint32_t na, uint32_t lseed, uint32_t nl, uint32_t nw,
		     uint64_t *main_at)
{
	uint64_t e, m, at[64], site[64];
	uint32_t i;

	fk_init(o);
	e = fk_entry(o, 0);
	m = fk_stub(o, na < 64 ? na : 64, site);       /* main: calls every author function, so the program reaches its code */
	for (i = 0; i < na && i < 64; i++)
		at[i] = fk_func(o, aseed + i, 40 + (i % 7), &V);
	for (i = 0; i < na && i < 64; i++)
		fk_call_to(o, site[i], at[i]);
	for (i = 0; i < nw; i++)
		fk_wrapper(o, 1 + i);
	for (i = 0; i < nl; i++)
		fk_func(o, lseed + i, 30 + (i % 9), &V);
	{
		int32_t d = (int32_t)((int64_t)m - (int64_t)(e + 7));

		memcpy(o->b + e + 3, &d, 4);
	}
	if (main_at)
		*main_at = m;
	return e;
}

static uint32_t pct_of(const struct fk_obj *o, uint64_t entry, enum kgenome_fnprint_link link, uint32_t pick,
		       const uint64_t *nodes, uint32_t nn, const struct fd_db *d, int blk, uint32_t *noside,
		       struct kgenome_fnprint_stat *stout)
{
	struct kof_mutation_ctx c, c2;
	struct kgenome_fnprint_stat st;
	uint32_t p;

	kof_mutation_ctx_init(&c, d->set);
	kof_mutation_ctx_init(&c2, d->set);
	kof_mutation_begin(&c);
	kof_mutation_begin(&c2);
	fd_credit(o, link, entry, pick, nodes, nn, &c, noside ? &c2 : NULL, &st);
	p = kof_mutation_pct(&c, (uint32_t)blk);
	if (noside)
		*noside = kof_mutation_pct(&c2, (uint32_t)blk);
	if (stout)
		*stout = st;
	kof_mutation_ctx_done(&c);
	kof_mutation_ctx_done(&c2);
	return p;
}

/*
 * The same function F is the author's in P1 and sits in the library block of P2. The block was stored
 * with a side; the scan decides the side of the bytes it holds from the object, so a block stored with the
 * wrong side still scores when the side is not required, and not when it is.
 */
static void t_side_decided_at_scan_time(void)
{
	struct fk_obj p1, p2;
	uint64_t e1, e2, f1, f2;
	struct fd_db d;
	int bu, bl;
	uint32_t ns;

	e1 = prog(&p1, 1000, 6, 5000, 20, 4, NULL);
	f1 = p1.v[4].off;                               /* the third author function (v[1] is main) */
	e2 = prog(&p2, 3000, 6, 5000, 20, 4, NULL);
	fk_func(&p2, 1000 + 2, 40 + 2, &V);                /* the same function (seed 1002), after the frontier */
	f2 = p2.v[p2.nf - 1].off;
	CK(memcmp(p1.b + f1, p2.b + f2, p1.v[4].len) == 0);

	memset(&d, 0, sizeof d);
	bu = fd_block(&d, p1.b, f1, p1.v[4].len, KGENOME_MUTATION_SIDE_USER);
	bl = fd_block(&d, p1.b, f1, p1.v[4].len, KGENOME_MUTATION_SIDE_LIB);
	fd_build(&d);
	CK(bu >= 0 && bl >= 0 && d.set);

	/* P1: F is author code - the USER block is credited fully, the LIB block (wrong side) not, unless the side is waived */
	CK(pct_of(&p1, e1, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_SIDED, NULL, 0, &d, bu, &ns, NULL) == 100);
	CK(ns == 100);
	CK(pct_of(&p1, e1, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_SIDED, NULL, 0, &d, bl, &ns, NULL) < NOISE);
	CK(ns == 100);                                       /* the side is what kept it out; without the side it is there */
	/* P2: the same bytes beyond the frontier are library: the sides swap, and A (author only) does not see them at all */
	CK(pct_of(&p2, e2, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_SIDED, NULL, 0, &d, bl, &ns, NULL) == 100);
	CK(pct_of(&p2, e2, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_SIDED, NULL, 0, &d, bu, &ns, NULL) < NOISE);
	CK(ns == 100);
	CK(pct_of(&p2, e2, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_AUTHOR, NULL, 0, &d, bu, NULL, NULL) < NOISE);
	fd_free(&d);
	fk_free(&p1); fk_free(&p2);
}

/*
 * More library functions than the old span lists hold (2048 spans, 16 for markers): there is no list here, so the
 * 2500th library function is credited on the LIB side like the first, and the author function among them on the
 * USER side.
 */
static void t_more_library_than_old_caps(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_stat st;
	struct fd_db d;
	uint64_t e, m, last;
	int bl, bm;
	uint32_t k;

	e = prog(&o, 1000, 5, 20000, 3000, 4, &m);
	last = o.v[o.nf - 1].off;
	memset(&d, 0, sizeof d);
	bl = fd_block(&d, o.b, last, o.v[o.nf - 1].len, KGENOME_MUTATION_SIDE_LIB);
	bm = fd_block(&d, o.b, m, o.v[1].len, KGENOME_MUTATION_SIDE_USER);
	fd_build(&d);
	CK(pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_SIDED, NULL, 0, &d, bl, NULL, &st) == 100);
	CK(st.n_lib >= 3000 && st.status == KGENOME_OK);
	CK(pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_SIDED, NULL, 0, &d, bm, NULL, NULL) == 100);
	/* and the second function of the 3000 stays library: no author block can be made of it */
	k = pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_AUTHOR, NULL, 0, &d, bl, NULL, NULL);
	CK(k == 0);
	fd_free(&d);
	fk_free(&o);
}

/* The normalised view: zero runs collapsed, functions remapped; the same blocks are credited the same. */
static void t_view_collapse_offsets(void)
{
	struct fk_obj o, v;
	struct kgenome_func_set pf, vf;
	struct fd_db d;
	uint64_t i, e = KGENOME_BROKEN;
	uint32_t k;
	int bk[3];

	fk_init(&o);
	for (k = 0; k < 12; k++) {
		fk_func(&o, 300 + k, 40, &V);
		fk_fill(&o, 0, 48);                        /* a zero run the view will collapse */
	}
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
	pf.v = o.v; pf.n = o.nf; pf.status = KGENOME_OK;
	memset(&vf, 0, sizeof vf);
	kgenome_funcs_remap(o.b, o.n, &pf, v.b, v.n, &vf);
	CK(vf.n == 12 && v.n < o.n);
	memset(&d, 0, sizeof d);
	for (k = 0; k < 3; k++)
		bk[k] = fd_block(&d, o.b, o.v[k * 4].off, o.v[k * 4].len, KGENOME_MUTATION_SIDE_USER);
	fd_build(&d);
	{
		/* the view carries its own offsets: units are taken from it by the walk over its function set */
		struct fk_obj vv = v;

		vv.v = vf.v; vv.nf = vf.n;
		for (k = 0; k < 3; k++) {
			CK(pct_of(&o, e, KGENOME_FNP_LINK_DYNAMIC, KGENOME_FNP_PICK_AUTHOR, NULL, 0, &d, bk[k], NULL, NULL) == 100);
			CK(pct_of(&vv, e, KGENOME_FNP_LINK_DYNAMIC, KGENOME_FNP_PICK_AUTHOR, NULL, 0, &d, bk[k], NULL, NULL) == 100);
		}
	}
	kgenome_funcs_free(&vf);
	fd_free(&d);
	fk_free(&o); fk_free(&v);
}

/* (B): with the object's nodes, only the functions that hold them; without the graph, nothing is selected and it is reported as nothing. */
static void t_diag_gated(void)
{
	struct fk_obj o;
	struct fd_db d;
	struct kgenome_fnprint_stat st;
	uint64_t e, m, node;
	int bx, by;

	e = prog(&o, 1000, 6, 5000, 10, 4, &m);
	memset(&d, 0, sizeof d);
	bx = fd_block(&d, o.b, o.v[2].off, o.v[2].len, KGENOME_MUTATION_SIDE_USER);   /* author function X */
	by = fd_block(&d, o.b, o.v[4].off, o.v[4].len, KGENOME_MUTATION_SIDE_USER);   /* author function Y */
	fd_build(&d);
	node = o.v[2].off + 7;                                                           /* a node inside X */
	CK(pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_DIAG, &node, 1, &d, bx, NULL, &st) == 100);
	CK(st.n_units == 1 && st.n_unit_funcs == 1);
	CK(pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_DIAG, &node, 1, &d, by, NULL, NULL) < NOISE);
	/* no graph for the object: nothing is selected, and the walk says no unit was made */
	CK(pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_DIAG, NULL, 0, &d, bx, NULL, &st) < NOISE);
	CK(st.n_units == 0);
	/* the same object without the gate: Y is credited (A) */
	CK(pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_AUTHOR, NULL, 0, &d, by, NULL, NULL) == 100);
	/* a node list that is not ascending is refused and no node is used */
	{
		uint64_t bad[2] = { o.v[4].off + 3, o.v[2].off + 3 };

		CK(pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_DIAG, bad, 2, &d, bx, NULL, &st) < NOISE);
		CK(st.status == KGENOME_BAD_INPUT && st.n_units == 0);
	}
	/* a node in a LIBRARY function (a wrapper's own syscall) selects nothing: its callers are the evidence */
	{
		uint64_t w = o.v[8].off + 2;           /* inside the first wrapper */

		CK(pct_of(&o, e, KGENOME_FNP_LINK_STATIC, KGENOME_FNP_PICK_DIAG, &w, 1, &d, bx, NULL, &st) < NOISE);
		CK(st.n_units == 0);
	}
	fd_free(&d);
	fk_free(&o);
}

/*
 * Dangerous: an adversary adds a node (a call to a diagnose wrapper) to functions that should not count. The
 * gate can only SELECT among the functions the walk calls author or unknown, so adding nodes never raises a
 * credit above the ungated one (B <= A2 for every block), and a node in library code selects nothing.
 * Junk functions in the object do not dilute a credit either: it is a containment of the block.
 */
static void t_adversary(void)
{
	struct fk_obj o;
	struct fd_db d;
	struct kof_mutation_ctx cb, ca;
	struct kgenome_fnprint_stat st;
	uint64_t e, m, nodes[64];
	uint32_t i, nn = 0;
	int b0, b1;

	e = prog(&o, 1000, 6, 5000, 30, 4, &m);
	for (i = 0; i < 400; i++)                                    /* junk after the library */
		fk_func(&o, 60000 + i, 12, &V);
	memset(&d, 0, sizeof d);
	b0 = fd_block(&d, o.b, o.v[3].off, o.v[3].len, KGENOME_MUTATION_SIDE_USER);
	b1 = fd_block(&d, o.b, o.v[o.nf - 1].off, o.v[o.nf - 1].len, KGENOME_MUTATION_SIDE_USER);   /* a junk function's block */
	fd_build(&d);
	for (i = 0; i < o.nf && nn < 64; i += 9)                      /* nodes sprinkled over every 9th function, library and junk included */
		nodes[nn++] = o.v[i].off + 4;
	kof_mutation_ctx_init(&ca, d.set);
	kof_mutation_ctx_init(&cb, d.set);
	kof_mutation_begin(&ca); kof_mutation_begin(&cb);
	fd_credit(&o, KGENOME_FNP_LINK_STATIC, e, KGENOME_FNP_PICK_AUTHOR | KGENOME_FNP_PICK_UNKNOWN, NULL, 0, &ca, NULL, &st);
	fd_credit(&o, KGENOME_FNP_LINK_STATIC, e, KGENOME_FNP_PICK_DIAG, nodes, nn, &cb, NULL, &st);
	CK(kof_mutation_pct(&cb, (uint32_t)b0) <= kof_mutation_pct(&ca, (uint32_t)b0));
	CK(kof_mutation_pct(&cb, (uint32_t)b1) <= kof_mutation_pct(&ca, (uint32_t)b1));
	CK(kof_mutation_pct(&ca, (uint32_t)b1) < NOISE);              /* junk placed after the frontier is library: not selected */
	CK(kof_mutation_pct(&ca, (uint32_t)b0) == 100);            /* and the real author block is not diluted by 400 of them */
	kof_mutation_ctx_done(&ca); kof_mutation_ctx_done(&cb);
	fd_free(&d);
	fk_free(&o);
}

int main(void)
{
	t_side_decided_at_scan_time();
	t_more_library_than_old_caps();
	t_view_collapse_offsets();
	t_diag_gated();
	t_adversary();
	printf("fnprint_credit: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
