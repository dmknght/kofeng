/*
 * lineage_edge - what the random programs cannot say, written out.
 *
 *   BASE       a field of the object is followed only when the base register holds ONE producer on every path: with two
 *              (an `if` that allocates in both arms) the field is unknown, whatever an execution would see.
 *   STACK      two paths that meet with the stack pointer in different places leave it unknown: a local read through it
 *              is not the slot either path means.
 *   PENDING    an i386 stdcall stack cannot be followed past a call through a pointer inside the arguments of another
 *              call: the engine loses the links it cannot place and invents none (programs with such calls, compared as
 *              "no link the oracle does not have").
 *   BUDGET     a scan whose step budget is spent writes no link of its own and says OVER_BUDGET.
 *   CONSUMER   (was a cap of 16, LG-11: it deleted producers) the 17th distinct producer at one consumer, in one function's own solve (kgenome_lineage_agg_add's own
 *              cap) and across TWO SEPARATE functions whose contributions are only combined at merge_loc (the object's
 *              table is not the function's): two callers of one helper, each under the per-solve cap of 16, whose union
 *              is not.
 *   AGG_RESIZE the aggregate table's own rehash, past 128 distinct (node,role) keys with its default capacity of 256:
 *              not reachable from a generated program (LG_MAXF holds no function with that many call sites), so it is
 *              called directly (kgenome_lineage_agg_add is the stage's own public entry, declared for exactly this).
 */
#include "lineage_check.h"

#include <phenotype/diag_lineage_private.h>

static struct lg_img g;
static struct lg_cg c;
static struct lg_prog p;

static int api(int a, int a0, int a1)
{
	return lg_h_api(&p, a, a0, a1);
}

static int ex(int kind, int x, int a0, int a1, int n)
{
	return lg_ex(&p, kind, x, a0, a1, n);
}

static void st(int blk, int kind, int x, int e, int a, int b)
{
	lg_h_st(&p, blk, kind, x, e, a, b);
}

static int scan_links(int target, unsigned stages, struct lg_links *got, enum kgenome_status *status)
{
	struct lg_scan sc;

	if (!lg_h_scan(&sc, &g, &c, &p, target, stages))
		return 0;
	lg_actual(got, &sc);
	if (status)
		*status = kgenome_diag_scan_status(sc.s);
	kgenome_diag_scan_free(sc.s);
	return 1;
}

static void t_base(void)
{
	static struct lg_links got;
	int target;

	for (target = LG_T_ELF64; target <= LG_T_PE32; target++) {
		int body, then, els, sock, m1, m2;

		memset(&p, 0, sizeof p);
		p.nf = 1;
		p.has_obj = 1;
		body = lg_newblk(&p);
		then = lg_newblk(&p);
		els = lg_newblk(&p);
		p.fn[0].body = body;
		p.fn[0].dead = -1;
		/* if (unknown) o = malloc() else o = malloc(); o.f0 = socket(); connect(o.f0) */
		m1 = api(LG_MALLOC, -1, -1);
		m2 = api(LG_MALLOC, -1, -1);
		st(then, LG_S_ASSIGN, 0, m1, 0, 0);
		st(els, LG_S_ASSIGN, 0, m2, 0, 0);
		st(body, LG_S_IF, 0, ex(LG_E_UNK, 0, -1, -1, 0), then, els);
		sock = api(LG_SOCKET, -1, -1);
		st(body, LG_S_FSTORE, 0, sock, 0, 0);
		st(body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_FIELD, 0, -1, -1, 0), -1), 0, 0);
		CK(scan_links(target, KGENOME_LINEAGE_S_ALL & ~(unsigned)KGENOME_LINEAGE_S_SEED, &got, NULL));
		CK(got.n == 0);                         /* the field is unknown: no link, in either direction */
		/* and with one allocation it is followed: the same program, the base fixed before the branch */
		memset(&p, 0, sizeof p);
		p.nf = 1;
		p.has_obj = 1;
		body = lg_newblk(&p);
		p.fn[0].body = body;
		p.fn[0].dead = -1;
		st(body, LG_S_ASSIGN, 0, api(LG_MALLOC, -1, -1), 0, 0);
		st(body, LG_S_FSTORE, 0, api(LG_SOCKET, -1, -1), 0, 0);
		st(body, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_FIELD, 0, -1, -1, 0), -1), 0, 0);
		CK(scan_links(target, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS, &got, NULL));
		CK(got.n == 1 && got.v[0].must);
	}
}

/* x86-64 code by hand: the stack pointer differs at a join, and a local is read through it afterwards. */
static void t_stack(void)
{
	static struct lg_links got;
	struct lg_rng r = { 3u };
	struct lg_scan sc;
	uint32_t at_connect;
	int l_join, ok;

	memset(&p, 0, sizeof p);
	p.nf = 1;
	p.fn[0].body = lg_newblk(&p);
	p.fn[0].dead = -1;
	CK(lg_codegen(&c, &p, &r, LG_T_ELF64));
	la_align(&c.a, 16);
	/* sub rsp, 0x40; mov rdi, 0x40..; call socket; mov [rsp+0x10], rax; call getpid; test; je L; push rax; L: mov rdi, [rsp+0x10]; call connect */
	la_spadj(&c.a, 1, 0x40);
	la_movi(&c.a, LA_DI, 0x40);
	la_call_sym(&c.a, LG_SYM_STUB(1));
	la_store(&c.a, LA_SP, 0x10, LA_AX);
	la_call_sym(&c.a, LG_SYM_STUB(LG_IMP_COND));
	la_test(&c.a, LA_AX);
	l_join = la_label(&c.a);
	la_jcc_label(&c.a, 4, l_join);
	la_push(&c.a, LA_AX);
	la_bind(&c.a, l_join);
	la_load(&c.a, LA_DI, LA_SP, 0x10);
	at_connect = c.a.n;
	la_call_sym(&c.a, LG_SYM_STUB(4));
	la_spadj(&c.a, 0, 0x40);
	la_ret(&c.a);
	ok = la_resolve_labels(&c.a);
	CK(ok);
	CK(lg_build(&g, &c, &r, 1));
	CK(lg_scan(&sc, &g, LG_T_ELF64, KGENOME_LINEAGE_S_FLOW));
	lg_actual(&got, &sc);
	/* on one path [rsp+0x10] is the socket, on the other it is eight bytes up: no link may say it is the socket */
	CK(got.n == 0);
	(void)at_connect;
	kgenome_diag_scan_free(sc.s);
}

static void t_pending(void)
{
	long programs = 0, links = 0, stripped = 0;
	int found = 0;

	lg_soft = 1;
	CK(lg_campaign(LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_DEEP | LG_F_TAIL, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SUMM,
		       (int)(120 * hk_scale()), 424242, &programs, &links, &stripped, &found) == 0);
	lg_soft = 0;
	printf("lineage_edge: %ld programs with calls through pointers inside arguments\n", programs);
}

static void t_budget(void)
{
	struct lg_rng r = { 11u };
	struct lg_scan sc;
	struct kgenome_diag_inputs in;
	struct kgenome_budget b;
	static struct lg_links got;
	int i, tried = 0;

	for (i = 0; i < 60 && tried < 6; i++) {
		unsigned run = KGENOME_DIAG_RUN_SYMBOL | KGENOME_DIAG_RUN_LINEAGE;
		uint32_t n_with, n_small;

		r.s = 1000u + (uint64_t)i * 977u;
		lg_generate(&p, &r, LG_F_CALL | LG_F_LOOP);
		if (p.bad || !lg_codegen(&c, &p, &r, LG_T_ELF64) || !lg_build(&g, &c, &r, 1))
			continue;
		memset(&sc, 0, sizeof sc);
		CK(kgenome_elf_image_parse(kof_buf_make(g.b, g.n), &sc.ei, &sc.obj));
		sc.obj.file_header = &sc.ei;
		memset(&in, 0, sizeof in);
		in.lineage_stages = KGENOME_LINEAGE_S_ALL;
		sc.s = kgenome_diag_scan_with_inputs(&sc.obj, g.b, g.n, run, &in);
		lg_actual(&got, &sc);
		n_with = (uint32_t)got.n;
		kgenome_diag_scan_free(sc.s);
		if (!n_with)
			continue;
		tried++;
		/* the same scan with a step budget of 3 instructions: the lineage stages cannot finish a function */
		memset(&b, 0, sizeof b);
		b.max_steps = 3;
		in.budget = &b;
		sc.s = kgenome_diag_scan_with_inputs(&sc.obj, g.b, g.n, run, &in);
		lg_actual(&got, &sc);
		n_small = (uint32_t)got.n;
		CK(n_small == 0u);
		CK(kgenome_diag_scan_status(sc.s) == KGENOME_OVER_BUDGET);
		kgenome_diag_scan_free(sc.s);
	}
	CK(tried >= 3);
}

/*
 * CONSUMER CAP, two ways - diag_lineage_solve.c's one token-set bound on a CONSUMER (as against
 * KGENOME_LINEAGE_B_VALUE, a producer's own value, lineage_state.c's t_values), read at the two places it
 * is checked: kgenome_lineage_agg_add's own cap, within one function's one solve, and merge_loc's, where the
 * OBJECT's table (glob) receives more than one function's contribution to the same (node, role).
 *
 * PART A (merge_loc). D(x) { connect(x); } is called from two OTHER functions, C1 and C2, each from ten
 * distinct call sites D(malloc()) - ten distinct producers, nowhere near agg_add's own cap of sixteen. SUMM
 * publishes D's summary once (a SINK: parameter 0 reaches its own connect()'s role); applying it at each of
 * C1's and C2's call sites writes the caller's producer into the CALLEE's node - so C1's merge_loc contributes
 * its ten to node D's key fresh (object table starts at 0), and C2's contributes ten more: 6 fit under the cap
 * of sixteen, the rest do not. Only merge_loc can see this: no one function ever holds more than ten.
 *
 * PART B (agg_add). The reverse shape: SEVENTEEN distinct tokens reaching one (node, role) within a SINGLE
 * solve - kgenome_lineage_agg_add is the stage's own public entry (diag_lineage_private.h), called directly on
 * a hand-built struct kgenome_lineage, exactly as lineage_state.c calls kgenome_lineage_val_add directly for
 * the per-VALUE cap. No codegen needed: the cap is a property of the aggregate table, not of what reaches it.
 */
static void t_consumer_cap(void)
{
	{
		static struct lg_links got;
		struct lg_scan sc;
		struct kgenome_diag_lineage_stats stt;
		int bD, bC1, bC2, k;

		memset(&p, 0, sizeof p);
		p.nf = 3;
		bD = lg_newblk(&p);
		bC1 = lg_newblk(&p);
		bC2 = lg_newblk(&p);
		p.fn[0].body = bD;
		p.fn[0].dead = -1;
		p.fn[0].nparams = 1;
		p.fn[1].body = bC1;
		p.fn[1].dead = -1;
		p.fn[1].nparams = 0;
		p.fn[2].body = bC2;
		p.fn[2].dead = -1;
		p.fn[2].nparams = 0;
		/* D(x) { connect(x); } */
		st(bD, LG_S_EVAL, 0, api(LG_CONNECT, ex(LG_E_PARAM, 0, -1, -1, 0), -1), 0, 0);
		/* C1, C2: ten calls each to D(malloc()), each malloc a distinct producer node */
		for (k = 0; k < 10; k++)
			st(bC1, LG_S_EVAL, 0, ex(LG_E_CALL, 0, api(LG_MALLOC, -1, -1), -1, 1), 0, 0);
		for (k = 0; k < 10; k++)
			st(bC2, LG_S_EVAL, 0, ex(LG_E_CALL, 0, api(LG_MALLOC, -1, -1), -1, 1), 0, 0);
		CK(lg_h_scan(&sc, &g, &c, &p, LG_T_ELF64, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SUMM));
		lg_actual(&got, &sc);
		CK(kgenome_diag_lineage_stats_of(sc.s, &stt));
		/* LG-11: the object's table holds all twenty, nothing is cut, and the connect has twenty inputs (four in its view) */
		CK(stt.bounded[KGENOME_LINEAGE_B_CONSUMER] == 0u);
		CK(kgenome_diag_scan_status(sc.s) == KGENOME_OK);
		{
			uint32_t q, n = kgenome_diag_scan_count(sc.s), best = 0;

			for (q = 0; q < n; q++)
				if (kgenome_diag_scan_at(sc.s, q)->cap == KGENOME_NUCLEO_NET_CONNECT && kgenome_diag_in_count(sc.s, q) > best)
					best = kgenome_diag_in_count(sc.s, q);
			CK(best == 20u);
		}
		kgenome_diag_scan_free(sc.s);
	}
	{
		struct lg_scan sc;
		struct kgenome_lineage L;
		struct kgenome_lineage_val v;
		uint32_t i;

		memset(&p, 0, sizeof p);
		lg_h_new(&p, 1, 0);
		lg_h_st(&p, p.fn[0].body, LG_S_EVAL, 0, lg_h_api(&p, LG_SOCKET, -1, -1), 0, 0);
		CK(lg_h_scan(&sc, &g, &c, &p, LG_T_ELF64, KGENOME_LINEAGE_S_ALL));
		memset(&L, 0, sizeof L);
		L.s = sc.s;
		L.ag = &L.loc;
		for (i = 0; i < KGENOME_LINEAGE_SET; i++) {
			memset(&v, 0, sizeof v);
			v.n = 1;
			v.t[0] = (uint16_t)(1000u + i);
			kgenome_lineage_agg_add(&L, 42u, 1u, &v, 0);
		}
		CK(L.st.bounded[KGENOME_LINEAGE_B_CONSUMER] == 0u);            /* sixteen distinct producers: exactly the cap, still fits */
		CK(kgenome_diag_scan_status(sc.s) == KGENOME_OK);
		memset(&v, 0, sizeof v);
		v.n = 1;
		v.t[0] = 9999u;
		kgenome_lineage_agg_add(&L, 42u, 1u, &v, 0);                   /* the seventeenth: kept (LG-11), in the table's pool */
		kgenome_lineage_agg_add(&L, 42u, 1u, &v, 0);                   /* (a repeat is one producer) */
		CK(L.st.bounded[KGENOME_LINEAGE_B_CONSUMER] == 0u);
		CK(kgenome_diag_scan_status(sc.s) == KGENOME_OK);
		{
			const struct kgenome_lineage_agg *a = kgenome_lineage_agg_get(&L.loc, ((42u + 1u) << 8) | 1u);
			uint16_t all[KGENOME_LINEAGE_SET + 1u];

			CK(a && a->n == KGENOME_LINEAGE_SET + 1u && !a->other);
			if (a && a->n == KGENOME_LINEAGE_SET + 1u) {
				kgenome_lineage_agg_toks(&L.loc, a, all);
				CK(all[KGENOME_LINEAGE_SET] == 9999u && all[0] == 1000u);
			}
		}
		free(L.loc.v);
		free(L.loc.x);
		kgenome_diag_scan_free(sc.s);
	}
}

/*
 * AGG_RESIZE. The aggregate table (diag_lineage_solve.c's agg_find) starts at capacity 0, resizes once to 256 on
 * its first key (an empty table: the rehash loop copies nothing), and resizes again to 512 once a 256-capacity
 * table holds 128 distinct keys (n*2 >= cap) - THAT second resize is the one with something to rehash. No
 * generated or hand-built program reaches 128 distinct (node, role) consumers in one function (LG_MAXF holds no
 * function with that many call sites: tests/lib/genome/lineage_ir.h), so this calls kgenome_lineage_agg_add
 * directly, the same way as the CONSUMER case above, pinning the exact boundary: 128 keys still fit in 256
 * (asserted before the 129th call), the 129th grows the table and rehashes what was there.
 */
static void t_agg_resize(void)
{
	struct lg_scan sc;
	struct kgenome_lineage L;
	struct kgenome_lineage_val v;
	uint32_t i;

	memset(&p, 0, sizeof p);
	lg_h_new(&p, 1, 0);
	lg_h_st(&p, p.fn[0].body, LG_S_EVAL, 0, lg_h_api(&p, LG_SOCKET, -1, -1), 0, 0);
	CK(lg_h_scan(&sc, &g, &c, &p, LG_T_ELF64, KGENOME_LINEAGE_S_ALL));
	memset(&L, 0, sizeof L);
	L.s = sc.s;
	L.ag = &L.loc;
	for (i = 0; i < 128u; i++) {
		memset(&v, 0, sizeof v);
		v.n = 1;
		v.t[0] = (uint16_t)i;
		kgenome_lineage_agg_add(&L, i, 0u, &v, 0);             /* 128 distinct (node, role) keys: node 0..127, role 0 */
	}
	CK(L.loc.n == 128u && L.loc.cap == 256u);
	memset(&v, 0, sizeof v);
	v.n = 1;
	v.t[0] = 1u;
	kgenome_lineage_agg_add(&L, 128u, 0u, &v, 0);                  /* the 129th distinct key: cap grows 256 -> 512, rehashing the 128 already there */
	CK(L.loc.n == 129u && L.loc.cap == 512u);
	free(L.loc.v);
	kgenome_diag_scan_free(sc.s);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_base();
	t_stack();
	t_pending();
	t_budget();
	t_consumer_cap();
	t_agg_resize();
	printf("lineage_edge: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
