/*
 * lineage_state - the pieces of the stages that a whole program cannot reach alone, one at a time, on a state built by hand:
 *
 *   JOINS     two paths that meet with the stack pointer in different places leave it unknown; the same place keeps it; a
 *             path on which it is unknown makes it unknown. The words pushed since it last moved agree or are forgotten.
 *   CALLS     a callee that pops a count nobody knows leaves the stack pointer unknown when anything is pending, and not
 *             otherwise; a known count moves it by exactly that.
 *   VALUES    what a join of two unknowns says about WHY (the reasons add), that a value of more producers than it holds
 *             widens and says so on the scan, and the reasons the argument of a call gets.
 *   SITES     the node of an instruction: its first byte, or a byte inside it (a relocation's field), and nothing else.
 *
 * (The whole-program counterparts are lineage_flow/summ/seed/chain; these are the cases a generated program cannot make: an
 * unbalanced stack at a join needs code no compiler writes.)
 */
#include "lineage_check.h"

#include <phenotype/diag_lineage_private.h>

static const uint8_t clob64[9] = { 0, 1, 2, 6, 7, 8, 9, 10, 11 };
static const uint8_t clob32[3] = { 0, 1, 2 };

static struct lg_img g;
static struct lg_cg c;
static struct lg_prog p;
static struct lg_scan sc;

static void abi64(struct kgenome_lineage *L)
{
	memset(L, 0, sizeof *L);
	L->s = sc.s;
	L->plan = KGENOME_LINEAGE_S_ALL;
	L->run = L->act = KGENOME_LINEAGE_S_ALL;
	L->abi.wide = 1;
	L->abi.w = 8;
	L->abi.arg = kgenome_diag_sysv_arg;
	L->abi.n_arg = 6;
	L->abi.clob = clob64;
	L->abi.n_clob = (uint8_t)sizeof clob64;
	L->abi.stack_first = 6;
}

static void abi32(struct kgenome_lineage *L, int callee_pops)
{
	memset(L, 0, sizeof *L);
	L->s = sc.s;
	L->plan = KGENOME_LINEAGE_S_ALL;
	L->run = L->act = KGENOME_LINEAGE_S_ALL;
	L->abi.w = 4;
	L->abi.clob = clob32;
	L->abi.n_clob = (uint8_t)sizeof clob32;
	L->abi.callee_pops = (uint8_t)callee_pops;
}

static void t_joins(void)
{
	struct kgenome_lineage L;
	struct kgenome_lineage_state a, b;

	abi64(&L);
	kgenome_lineage_state_entry(&L, &a, 0);
	CK(kgenome_lineage_state_copy(&L, &b, &a));
	/* the same place on both paths: nothing changes, nothing is lost */
	CK(!kgenome_lineage_state_join(&L, &a, &b));
	CK(a.spok && a.sp == 0);
	/* different places: unknown, and the join says it changed */
	b.sp = -16;
	CK(kgenome_lineage_state_join(&L, &a, &b));
	CK(!a.spok);
	/* a path on which it is unknown */
	kgenome_lineage_state_free(&L, &a);
	kgenome_lineage_state_entry(&L, &a, 0);
	b.sp = 0;
	b.spok = 0;
	CK(kgenome_lineage_state_join(&L, &a, &b));
	CK(!a.spok);
	/* words pushed since the stack pointer moved: equal agree, unequal are forgotten (0 is where it stays) */
	kgenome_lineage_state_free(&L, &a);
	kgenome_lineage_state_entry(&L, &a, 0);
	b.spok = 1;
	a.pshs = 2;
	b.pshs = 2;
	CK(!kgenome_lineage_state_join(&L, &a, &b));
	CK(a.pshs == 2);
	b.pshs = 3;
	CK(kgenome_lineage_state_join(&L, &a, &b));
	CK(a.pshs == 0);
	kgenome_lineage_state_free(&L, &a);
	kgenome_lineage_state_free(&L, &b);
}

static void t_calls(void)
{
	struct kgenome_lineage L;
	struct kgenome_lineage_state s;

	abi32(&L, 1);
	/* a callee that pops a count nobody knows, with words pending: the stack pointer is unknown */
	kgenome_lineage_state_entry(&L, &s, 0);
	s.pshs = 2;
	kgenome_lineage_state_call(&L, &s, NULL, NULL, -1);
	CK(!s.spok);
	kgenome_lineage_state_free(&L, &s);
	/* ... with nothing pending it is kept */
	kgenome_lineage_state_entry(&L, &s, 0);
	kgenome_lineage_state_call(&L, &s, NULL, NULL, -1);
	CK(s.spok && s.sp == 0);
	kgenome_lineage_state_free(&L, &s);
	/* a known count moves it by that many words and settles what was pending */
	kgenome_lineage_state_entry(&L, &s, 0);
	s.sp = -12;
	s.pshs = 3;
	kgenome_lineage_state_call(&L, &s, NULL, NULL, 3);
	CK(s.spok && s.sp == 0 && s.pshs == 0);
	kgenome_lineage_state_free(&L, &s);
	/* a cdecl callee (its caller adds esp) is not asked to pop */
	abi32(&L, 0);
	kgenome_lineage_state_entry(&L, &s, 0);
	s.sp = -8;
	s.pshs = 2;
	kgenome_lineage_state_call(&L, &s, NULL, NULL, -1);
	CK(s.spok && s.sp == -8 && s.pshs == 0);
	kgenome_lineage_state_free(&L, &s);
}

static void t_values(void)
{
	struct kgenome_lineage L;
	struct kgenome_lineage_val a, b, d;
	uint32_t i;

	abi64(&L);
	/* two unknowns join to one that carries both reasons (and, being unknown on both sides, is not a change) */
	kgenome_lineage_val_unknown(&a, KGENOME_LINEAGE_W_ENTRY);
	kgenome_lineage_val_unknown(&b, KGENOME_LINEAGE_W_ADDR);
	CK(!kgenome_lineage_val_join(&L, &a, &b));          /* (a reason gained alone is not a change: no link depends on it) */
	CK(a.other && a.why == (KGENOME_LINEAGE_W_ENTRY | KGENOME_LINEAGE_W_ADDR));
	CK(!kgenome_lineage_val_join(&L, &a, &b));
	/* a producer and an unknown: the producer stays, the unknown's reason comes with `other` */
	memset(&d, 0, sizeof d);
	CK(kgenome_lineage_val_add(&L, &d, 3));
	CK(kgenome_lineage_val_join(&L, &d, &b));
	CK(d.n == 1 && d.t[0] == 3 && d.other && d.why == KGENOME_LINEAGE_W_ADDR);
	/* a constant joined with an unknown stays a constant's reason PLUS the unknown's: the input is not resolved */
	kgenome_lineage_val_unknown(&a, KGENOME_LINEAGE_W_CONST);
	CK(!kgenome_lineage_val_join(&L, &a, &b));
	CK(a.why == (KGENOME_LINEAGE_W_CONST | KGENOME_LINEAGE_W_ADDR));
	/* more producers than a value holds: it widens, says why, and the scan says it was cut */
	memset(&d, 0, sizeof d);
	for (i = 0; i < KGENOME_LINEAGE_SET; i++)
		CK(kgenome_lineage_val_add(&L, &d, 100u + i));
	CK(!d.other && d.n == KGENOME_LINEAGE_SET);
	CK(kgenome_diag_scan_status(sc.s) == KGENOME_OK);
	CK(kgenome_lineage_val_add(&L, &d, 999));
	CK(d.other && (d.why & KGENOME_LINEAGE_W_LIMIT) && d.n == KGENOME_LINEAGE_SET);
	CK(kgenome_diag_scan_status(sc.s) == KGENOME_TRUNCATED);
}

static void t_args(void)
{
	struct kgenome_lineage L;
	struct kgenome_lineage_state s;
	struct kgenome_lineage_val v;

	abi32(&L, 0);
	/* an i386 argument no push wrote: an argument the caller did not supply (ENTRY); with the stack pointer lost: STACK */
	kgenome_lineage_state_entry(&L, &s, 0);
	v = kgenome_lineage_arg(&L, &s, 0);
	CK(v.other && v.why == KGENOME_LINEAGE_W_ENTRY);
	s.spok = 0;
	v = kgenome_lineage_arg(&L, &s, 0);
	CK(v.other && v.why == KGENOME_LINEAGE_W_STACK);
	kgenome_lineage_state_free(&L, &s);
	/* an x86-64 register argument is what the register holds */
	abi64(&L);
	kgenome_lineage_state_entry(&L, &s, 0);
	CK(kgenome_lineage_val_add(&L, &s.r[kgenome_diag_sysv_arg[1]], 42));
	v = kgenome_lineage_arg(&L, &s, 1);
	CK(v.n == 1 && v.t[0] == 42);
	kgenome_lineage_state_free(&L, &s);
}

static void t_sites(void)
{
	struct kgenome_lineage L;
	struct kgenome_cell_insn in;
	static uint64_t at[3] = { 0x10, 0x20, 0x31 };
	static uint32_t node[3] = { 5, 6, 7 };
	uint32_t n = 99;

	memset(&L, 0, sizeof L);
	memset(&in, 0, sizeof in);
	L.site_at = at;
	L.site_node = node;
	L.n_site = 3;
	/* the instruction's first byte, a byte inside it, and nothing outside it */
	in.at = 0x10;
	in.len = 1;
	CK(kgenome_lineage_site_in(&L, &in, &n) && n == 5);
	in.at = 0x30;
	in.len = 4;
	CK(kgenome_lineage_site_in(&L, &in, &n) && n == 7);            /* a relocation's field, inside it */
	in.len = 1;
	CK(!kgenome_lineage_site_in(&L, &in, &n));                     /* ends before it */
	in.at = 0x11;
	in.len = 8;
	CK(!kgenome_lineage_site_in(&L, &in, &n));                     /* ends before the next */
	in.at = 0x32;
	in.len = 5;
	CK(!kgenome_lineage_site_in(&L, &in, &n));                     /* starts after the last */
	CK(kgenome_lineage_site_of(&L, 0x20, &n) && n == 6);          /* the exact lookup (a summary's site) */
	CK(!kgenome_lineage_site_of(&L, 0x21, &n));
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	lg_h_new(&p, 1, 0);
	lg_h_st(&p, p.fn[0].body, LG_S_EVAL, 0, lg_h_api(&p, LG_SOCKET, -1, -1), 0, 0);
	CK(lg_h_scan(&sc, &g, &c, &p, LG_T_ELF64, KGENOME_LINEAGE_S_ALL));
	t_joins();
	t_calls();
	t_values();
	t_args();
	t_sites();
	kgenome_diag_scan_free(sc.s);
	printf("lineage_state: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
