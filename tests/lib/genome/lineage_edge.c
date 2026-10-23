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
 */
#include "lineage_check.h"

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

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_base();
	t_stack();
	t_pending();
	t_budget();
	printf("lineage_edge: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
