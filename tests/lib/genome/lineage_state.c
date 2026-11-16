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

static struct lg_img g;
static struct lg_cg c;
static struct lg_prog p;
static struct lg_scan sc;

/* The convention is the table's row (diag_lineage_arch.c), not a copy of it written here: a test that builds its own ABI tests its copy. */
static void abi_row(struct kgenome_lineage *L, unsigned arch, unsigned fmt)
{
	struct kgenome_obj o;

	memset(L, 0, sizeof *L);
	memset(&o, 0, sizeof o);
	o.arch = (uint8_t)arch;
	o.format = (uint8_t)fmt;
	L->s = sc.s;
	L->plan = KGENOME_LINEAGE_S_ALL;
	L->run = L->act = KGENOME_LINEAGE_S_ALL;
	CK(kgenome_lineage_arch_of(&o, &L->abi));
}

static void abi64(struct kgenome_lineage *L)
{
	abi_row(L, KGENOME_ARCH_X86_64, KGENOME_FMT_ELF);
	CK(L->abi.w == 8 && L->abi.n_arg == 6 && L->abi.stack_first == 6 && L->abi.sp == KGENOME_CELL_REG_SP && L->abi.n_sys_arg == 6);
}

/* i386: cdecl in an ELF, stdcall (the callee pops) in a PE */
static void abi32(struct kgenome_lineage *L, int callee_pops)
{
	abi_row(L, KGENOME_ARCH_X86, callee_pops ? KGENOME_FMT_PE : KGENOME_FMT_ELF);
	CK(L->abi.w == 4 && L->abi.n_arg == 0 && L->abi.callee_pops == (uint8_t)callee_pops);
}

/* THE ROWS: an architecture with no row is not read; the Windows x64 convention skips the shadow space. */
static void t_rows(void)
{
	struct kgenome_lineage L;
	struct kgenome_obj o;
	struct kgenome_lineage_abi a;

	abi_row(&L, KGENOME_ARCH_X86_64, KGENOME_FMT_PE);
	CK(L.abi.n_arg == 4 && L.abi.stack_first == 4 && L.abi.stack_off == 32 && !L.abi.callee_pops);
	memset(&o, 0, sizeof o);
	o.arch = KGENOME_ARCH_ARM;
	o.format = KGENOME_FMT_ELF;
	CK(!kgenome_lineage_arch_of(&o, &a));
	o.arch = KGENOME_ARCH_ARM64;
	CK(!kgenome_lineage_arch_of(&o, &a));
	CK(!kgenome_lineage_arch_of(NULL, &a));
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
	/* LG-12: A VALUE HOLDS EVERY PRODUCER THAT REACHES IT. Past the inline ones a token is a cell of the solve's pool; the seventeenth (and the
	 * hundredth) is kept, no bound fires, nothing is said cut - the bound of sixteen fired 69 times in 2 of 356 files and lost producers. */
	{
		const uint64_t b0 = L.st.bounded[KGENOME_LINEAGE_B_VALUE];
		struct kgenome_lineage_val e;
		uint16_t all[128];

		memset(&d, 0, sizeof d);
		for (i = 0; i < 100u; i++)
			CK(kgenome_lineage_val_add(&L, &d, 100u + i));
		CK(!kgenome_lineage_val_add(&L, &d, 150u));                     /* a repeat past the inline ones is one token */
		CK(!d.other && d.n == KGENOME_LINEAGE_VAL_INLINE && d.more);
		CK(kgenome_lineage_val_toks(&L, &d, all, 128u) == 100u);
		{
			uint32_t seen = 0;

			for (i = 0; i < 100u; i++)
				seen += all[i] >= 100u && all[i] < 200u;
			CK(seen == 100u);
		}
		CK(L.st.bounded[KGENOME_LINEAGE_B_VALUE] == b0);
		CK(kgenome_diag_scan_status(sc.s) == KGENOME_OK);
		/* a COPY shares the chain and does not change when the original gains a token (the chain is never written in place) */
		e = d;
		CK(kgenome_lineage_val_add(&L, &d, 999u));
		CK(kgenome_lineage_val_toks(&L, &d, all, 128u) == 101u && kgenome_lineage_val_toks(&L, &e, all, 128u) == 100u);
		/* a join brings the other's chain: e gains 999, and then is d's set */
		CK(kgenome_lineage_val_join(&L, &e, &d));
		CK(kgenome_lineage_val_toks(&L, &e, all, 128u) == 101u);
		CK(!kgenome_lineage_val_join(&L, &e, &d));
		/* statuses are tokens like any other, past the inline ones too */
		CK(kgenome_lineage_val_add(&L, &d, 7u | KGENOME_LINEAGE_STATUS) && !d.other);
		/* the one bound left is the ledger: with no room the next token widens the value (W_LIMIT) and the scan says it */
		{
			const uint64_t lim = sc.s->led.limit, used = sc.s->led.used;

			L.nvx = L.capvx;                /* the pool must grow for the next token */
			sc.s->led.limit = sc.s->led.used ? sc.s->led.used : 1u;
			sc.s->led.used = sc.s->led.limit;
			CK(kgenome_lineage_val_add(&L, &d, 4000u));
			CK(d.other && (d.why & KGENOME_LINEAGE_W_LIMIT) && L.st.bounded[KGENOME_LINEAGE_B_VALUE] == b0 + 1u);
			sc.s->led.limit = lim;
			sc.s->led.used = used;
		}
		free(L.vx);
		L.vx = NULL;
		L.nvx = L.capvx = 0;
	}
}

/* THE TABLE OF WHAT REACHES A CONSUMER: one probe for the insert and the lookup (diag_lineage_solve.c, agg_slot). Every key put in through
 * growth after growth is found by the lookup with what was added; a key never put in is not found. */
static void t_aggtab(void)
{
	struct kgenome_lineage L;
	struct kgenome_lineage_val v;
	uint32_t i, ok = 0;

	abi64(&L);
	L.ag = &L.glob;
	for (i = 0; i < 1500u; i++) {
		memset(&v, 0, sizeof v);
		v.n = 1;
		v.t[0] = (uint16_t)(i % 1000u + 1u);
		kgenome_lineage_agg_add(&L, i, (uint8_t)(1u + i % 3u), &v, 0);
	}
	CK(L.glob.n == 1500u && L.glob.cap >= 3000u);
	for (i = 0; i < 1500u; i++) {
		const struct kgenome_lineage_agg *a = kgenome_lineage_agg_get(&L.glob, ((i + 1u) << 8) | (1u + i % 3u));

		ok += a && a->n == 1u && a->t[0] == (uint16_t)(i % 1000u + 1u) && !a->other;
	}
	CK(ok == 1500u);
	CK(kgenome_lineage_agg_get(&L.glob, (1501u << 8) | 1u) == NULL);
	CK(kgenome_lineage_agg_get(&L.glob, (1u << 8) | 2u) == NULL);
	free(L.glob.v);
	kgenome_ledger_release(&sc.s->led, L.charged);
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
	t_rows();
	t_joins();
	t_calls();
	t_values();
	t_aggtab();
	t_args();
	t_sites();
	kgenome_diag_scan_free(sc.s);
	printf("lineage_state: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
