/*
 * api_emu - the emulator's public calls that no test named, each against the
 * contract in emu.h: what it returns, what it leaves alone, what a call with the
 * wrong argument does, and whether calling it twice says the same thing.
 *
 * The program every case runs (assembled by hand, offsets in the comments):
 *
 *    0  mov rdi, DATA                         ; 48 bf imm64
 *   10  mov rcx, 5
 *   17  loop: mov [rdi], rcx                  ; the stores the watch sees
 *   20        add rdi, 8
 *   24        call f
 *   29        dec rcx
 *   32        jnz loop
 *   34  hlt                                   ; an instruction the interpreter stops on
 *   35  f:  ret
 *
 * 33 instructions are retired before the hlt, five calls are made, and the
 * run ends UNSUPPORTED at 0x400022 (hlt is not implemented, by design: it is how
 * a stub is told to stop).
 */

#include <kgenome.h>

#include "hk.h"
#include "../../unit/known_miss.h"

#define CODE   0x400000ull
#define DATA   0x600000ull
#define STK    0x7ff00000ull

static const uint8_t prog[] = {
	0x48, 0xbf, 0, 0, 0x60, 0, 0, 0, 0, 0,
	0x48, 0xc7, 0xc1, 5, 0, 0, 0,
	0x48, 0x89, 0x0f,
	0x48, 0x83, 0xc7, 8,
	0xe8, 6, 0, 0, 0,
	0x48, 0xff, 0xc9,
	0x75, 0xef,
	0xf4,
	0xc3
};

static struct kgenome_emu *fresh(uint64_t budget, unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = budget;
	cfg.max_pages = 64;
	cfg.bits = bits;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	kgenome_emu_map(e, CODE, prog, sizeof prog, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA, NULL, 0, 0x2000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, STK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, CODE);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STK + 0x8000);
	return e;
}

/* ---- the machine's state accessors ------------------------------------------------------------ */

static void t_state(void)
{
	struct kgenome_emu *e = fresh(100000, 64);
	uint64_t tr[KGENOME_EMU_TRACE + 8], lc[2], ins = 99, rip = 99;
	uint32_t cnt = 99;
	unsigned n, i;
	enum kgenome_emu_stop st;

	CK(e != NULL);
	CK(kgenome_emu_rip(e) == CODE && kgenome_emu_get_rip(e) == CODE);
	CK(kgenome_emu_insn_count(e) == 0);
	CK(kgenome_emu_trace(e, tr, 8) == 0);               /* nothing executed yet */
	CK(kgenome_emu_win_event_count(e) == 0);
	CK(kgenome_emu_null_calls(e) == 0 && kgenome_emu_null_reads(e) == 0 && kgenome_emu_unhandled(e) == 0);
	CK(kgenome_emu_last_write(e) == 0);
	kgenome_emu_last_calls(e, lc);
	CK(lc[0] == 0 && lc[1] == 0);                       /* "0 when there were fewer" */

	kgenome_emu_itrace(e, 8);
	kgenome_emu_watch(e, DATA + 8);
	st = kgenome_emu_run(e);
	CK(st == KGENOME_EMU_STOP_UNSUPPORTED);
	CK(!strncmp(kgenome_emu_stop_detail(e), "HLT", 3));
	CK(kgenome_emu_insn_count(e) == 33);
	CK(kgenome_emu_rip(e) == CODE + 0x22 && kgenome_emu_get_rip(e) == CODE + 0x22);

	/* the rip ring: newest last, the last entry is where it stopped */
	n = kgenome_emu_trace(e, tr, KGENOME_EMU_TRACE + 8);
	CK(n == 33);
	CK(tr[0] == CODE && tr[n - 1u] == CODE + 0x22);
	CK(kgenome_emu_trace(e, tr, 3) == 3);
	CK(tr[0] == CODE + 0x1d && tr[1] == CODE + 0x20 && tr[2] == CODE + 0x22);
	CK(kgenome_emu_trace(e, tr, 0) == 0);

	/* the last two CALL instructions, newest first; the last transfer is the ret */
	kgenome_emu_last_calls(e, lc);
	CK(lc[0] == CODE + 0x18 && lc[1] == CODE + 0x18);
	CK(kgenome_emu_last_branch_at(e) == CODE + 0x23);

	/* the first hop needs a watch_exec range to be crossed; none was declared */
	kgenome_emu_first_hop(e, &ins, &rip);
	CK(ins == 0 && rip == 0);
	kgenome_emu_last_hop(e, &rip, &cnt);
	CK(cnt == 0);

	/* the instruction trace: the last 8, oldest first, with the registers BEFORE each ran */
	CK(kgenome_emu_itrace_count(e) == 8);
	for (i = 0; i < 8; i++) {
		uint64_t r = 0;
		const char *text = NULL;
		const uint64_t *gpr = NULL;

		CK(kgenome_emu_itrace_get(e, i, &r, &text, &gpr) == 1);
		CK(text && text[0] && gpr);
		if (i == 7)
			CK(r == CODE + 0x22 && !strncmp(text, "HLT", 3));
	}
	{
		uint64_t r = 77;
		const char *text = "x";
		const uint64_t *gpr = NULL;

		CK(kgenome_emu_itrace_get(e, 8, &r, &text, &gpr) == 0);
		CK(kgenome_emu_itrace_get(e, 0xffffffffu, &r, &text, &gpr) == 0);
		/* every out pointer is optional */
		CK(kgenome_emu_itrace_get(e, 0, NULL, NULL, NULL) == 1);
	}
	kgenome_emu_itrace(e, 0);                           /* 0 frees the ring */
	CK(kgenome_emu_itrace_count(e) == 0);

	/* the write watch: rip and value of the write that touched the byte */
	{
		uint64_t wr[4] = { 0 }, wv[4] = { 0 };
		CK(kgenome_emu_watch_hits(e, wr, wv, 4) == 1);
		CK(wr[0] == CODE + 0x11 && wv[0] == 4);
		CK(kgenome_emu_watch_hits(e, wr, wv, 0) == 0);
		CK(kgenome_emu_watch_hits(e, NULL, NULL, 0) == 0);
	}

	/* what the interpreter counted */
	{
		uint32_t ra = 9, ta = 9, v = 9;
		uint64_t len = 5;
		kgenome_emu_exc_counts(e, &ra, &ta, &v);
		CK(ra == 0 && ta == 0 && v == 0);
		CK(kgenome_emu_exc_scratch(e, &len) == 0);
		CK(kgenome_emu_exc_scratch(e, NULL) == 0);
	}
	CK(kgenome_emu_last_write(e) > 0);
	CK(kgenome_emu_idle_max(e) > 0);

	/* step runs the instruction it is standing on and says why it ended */
	CK(kgenome_emu_step(e) == KGENOME_EMU_STOP_UNSUPPORTED);
	CK(kgenome_emu_insn_count(e) <= 34);
	CK(kgenome_emu_stop_name(KGENOME_EMU_STOP_BUDGET) != NULL);
	{
		unsigned s;
		for (s = 0; s <= KGENOME_EMU_STOP_QUIET; s++)
			CK(kgenome_emu_stop_name((enum kgenome_emu_stop)s) && kgenome_emu_stop_name((enum kgenome_emu_stop)s)[0]);
	}
	kgenome_emu_free(e);
}

/* ---- budgets and the deadline ----------------------------------------------------------------- */

static void t_budgets(void)
{
	struct kgenome_emu *e;
	static const uint8_t spin[] = { 0xeb, 0xfe };
	double t0;
	struct kgenome_emu_cfg cfg;

	/* set_max_insn: the budget changes and a re-run is allowed to go on */
	e = fresh(10, 64);
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_BUDGET);
	CK(kgenome_emu_insn_count(e) == 10);
	kgenome_emu_set_max_insn(e, 20);
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_BUDGET);
	CK(kgenome_emu_insn_count(e) == 20);
	kgenome_emu_set_max_insn(e, 1000);
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_UNSUPPORTED);
	CK(kgenome_emu_insn_count(e) == 33);
	kgenome_emu_free(e);

	/* the icache is an acceleration: the same run, the same answers */
	{
		unsigned on;
		uint64_t insn[2], rcx[2];
		for (on = 0; on < 2; on++) {
			e = fresh(100000, 64);
			kgenome_emu_set_icache(e, (int)on);
			CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_UNSUPPORTED);
			insn[on] = kgenome_emu_insn_count(e);
			rcx[on] = kgenome_emu_get_reg(e, KGENOME_EMU_RCX);
			kgenome_emu_free(e);
		}
		CK(insn[0] == insn[1] && rcx[0] == rcx[1]);
	}

	/* the idle bound: a loop that touches no new page ends STALLED once it is reached */
	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = 50000000;
	cfg.max_pages = 16;
	e = kgenome_emu_new(&cfg);
	kgenome_emu_map(e, CODE, spin, sizeof spin, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_set_rip(e, CODE);
	kgenome_emu_set_idle(e, 5000);
	t0 = hk_now();
	{
		enum kgenome_emu_stop st = kgenome_emu_run(e);
		CK(st == KGENOME_EMU_STOP_STALLED || st == KGENOME_EMU_STOP_BUDGET);
		CK(kgenome_emu_insn_count(e) < 50000000u);
	}
	CK(hk_now() - t0 < 2.0);
	kgenome_emu_free(e);

	/* the deadline ends a spin that has an enormous instruction budget, in wall time */
	e = kgenome_emu_new(&cfg);
	kgenome_emu_map(e, CODE, spin, sizeof spin, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_set_rip(e, CODE);
	kgenome_emu_set_idle(e, UINT64_MAX);               /* lift the other bound */
	kgenome_emu_set_max_insn(e, UINT64_MAX);
	kgenome_emu_set_deadline(e, 60);
	t0 = hk_now();
	(void)kgenome_emu_run(e);
	{
		double dt = hk_now() - t0;
		CK(dt < 3.0);
		CK(kgenome_emu_insn_count(e) > 0);
	}
	kgenome_emu_free(e);
}

/* ---- the handover watches ----------------------------------------------------------------------- */

static void t_watches(void)
{
	struct kgenome_emu *e;
	static const uint8_t c3 = 0xc3;
	static const uint8_t nop = 0x90;

	/* watch_insn: PAUSE (STOP_INSN) on an instruction that begins with the bytes; a second run
	 * call carries on from the same place, and step executes the one it is standing on */
	e = fresh(1000, 64);
	kgenome_emu_watch_insn(e, &c3, 1);
	kgenome_emu_watch_insn_len(e, 1);
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_INSN);
	CK(kgenome_emu_rip(e) == CODE + 0x23);             /* the ret of f, paused ON it */
	CK(kgenome_emu_insn_count(e) == 5);
	{
		uint64_t rsp = kgenome_emu_get_reg(e, KGENOME_EMU_RSP);
		uint64_t ret = 0;
		CK(kgenome_emu_read(e, rsp, &ret, 8) == 1);
		CK(ret == CODE + 0x1d);                    /* [rsp] is the return address: what the module reads */
	}
	CK(kgenome_emu_step(e) == KGENOME_EMU_STOP_BUDGET);
	CK(kgenome_emu_rip(e) == CODE + 0x1d);
	/* an instruction of another length does not match: len 1 only */
	kgenome_emu_free(e);

	e = fresh(1000, 64);
	kgenome_emu_watch_insn(e, &nop, 1);                /* never executed */
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_UNSUPPORTED);
	kgenome_emu_free(e);

	/* the pattern table: at most KGENOME_EMU_INSN_WATCH patterns, 1..INSN_WATCH_LEN bytes;
	 * anything else is refused quietly and nothing is read past what was given */
	e = fresh(1000, 64);
	{
		uint8_t big[64];
		unsigned i;
		memset(big, 0x90, sizeof big);
		for (i = 0; i < KGENOME_EMU_INSN_WATCH + 4u; i++)
			kgenome_emu_watch_insn(e, big, 1 + i % KGENOME_EMU_INSN_WATCH_LEN);
		kgenome_emu_watch_insn(e, big, 0);
		kgenome_emu_watch_insn(e, big, 9);
		kgenome_emu_watch_insn(e, big, 0xffffffffu);
		kgenome_emu_watch_insn(e, NULL, 0);
		kgenome_emu_watch_insn_len(e, 0);
		kgenome_emu_watch_insn_len(e, 0xffffffffu);
		CK(kgenome_emu_run(e) != KGENOME_EMU_STOP_INSN);
	}
	kgenome_emu_free(e);

	/* watch_exec: only a fetch that crosses IN from outside ends the run */
	e = fresh(1000, 64);
	kgenome_emu_watch_exec(e, CODE + 0x23, CODE + 0x24);    /* f: entered by the call */
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_HANDOFF);
	CK(kgenome_emu_rip(e) == CODE + 0x23);
	kgenome_emu_free(e);
	e = fresh(1000, 64);
	kgenome_emu_watch_exec(e, CODE, CODE + 0x24);           /* it starts INSIDE the range */
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_UNSUPPORTED);
	kgenome_emu_free(e);
	e = fresh(1000, 64);
	{
		unsigned i;
		for (i = 0; i < KGENOME_EMU_EXEC_WATCH + 8u; i++)
			kgenome_emu_watch_exec(e, 0x1000u * (i + 1u), 0x1000u * (i + 1u) + 8u);
		kgenome_emu_watch_exec(e, 5, 5);                /* empty */
		kgenome_emu_watch_exec(e, 9, 3);                /* inverted */
		CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_UNSUPPORTED);
	}
	kgenome_emu_free(e);

	/* watch_write + write_seen */
	e = fresh(1000, 64);
	CK(kgenome_emu_write_seen(e) == 0);
	kgenome_emu_watch_write(e, DATA + 0x100, DATA + 0x200);  /* never written */
	(void)kgenome_emu_run(e);
	CK(kgenome_emu_write_seen(e) == 0);
	kgenome_emu_free(e);
	e = fresh(1000, 64);
	kgenome_emu_watch_write(e, DATA, DATA + 0x10);
	(void)kgenome_emu_run(e);
	CK(kgenome_emu_write_seen(e) == 1);
	kgenome_emu_free(e);

	/* the range setters are plain declarations: inverted or empty ranges are ignored */
	e = fresh(1000, 64);
	kgenome_emu_set_stub_range(e, CODE, CODE + 0x1000);
	kgenome_emu_set_stub_range(e, 10, 5);
	kgenome_emu_set_stack_range(e, STK, STK + 0x10000);
	kgenome_emu_set_stack_range(e, 0, 0);
	kgenome_emu_set_image_range(e, CODE, CODE + 0x1000);
	kgenome_emu_set_oep_watch(e, 1);
	kgenome_emu_hop_add(e, DATA, DATA + 0x1000, 0);
	kgenome_emu_hop_add(e, 5, 5, 0);
	kgenome_emu_hop_add(e, 9, 3, 1);
	{
		unsigned i;
		for (i = 0; i < KGENOME_EMU_EXEC_WATCH + 8u; i++)
			kgenome_emu_hop_add(e, 0x10000000ull + 0x1000u * i, 0x10000000ull + 0x1000u * i + 0x800u, (int)(i & 1u));
	}
	(void)kgenome_emu_run(e);
	CK(kgenome_emu_insn_count(e) <= 1000);
	kgenome_emu_free(e);

	/* watch: ONE address (a second call replaces it and forgets its hits); at most
	 * KGENOME_EMU_WATCH_MAX hits are kept, oldest first. mov rcx,40 ; L: mov [DATA],rcx ;
	 * dec rcx ; jnz L ; hlt */
	{
		static const uint8_t loop40[] = { 0x48, 0xc7, 0xc1, 40, 0, 0, 0,
			0x48, 0x89, 0x0c, 0x25, 0, 0, 0x60, 0,
			0x48, 0xff, 0xc9, 0x75, 0xf3, 0xf4 };
		uint64_t wr[64], wv[64];
		unsigned n;

		e = fresh(100000, 64);
		kgenome_emu_map(e, CODE, loop40, sizeof loop40, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
		kgenome_emu_watch(e, DATA);
		(void)kgenome_emu_run(e);
		n = kgenome_emu_watch_hits(e, wr, wv, 64);
		CK(n == KGENOME_EMU_WATCH_MAX);
		CK(wv[0] == 40 && wv[1] == 39);
		CK(kgenome_emu_watch_hits(e, wr, wv, 3) == 3);
		kgenome_emu_free(e);

		e = fresh(100000, 64);
		kgenome_emu_map(e, CODE, loop40, sizeof loop40, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
		kgenome_emu_watch(e, DATA);
		kgenome_emu_watch(e, DATA + 0x100);             /* replaces: DATA is no longer watched */
		(void)kgenome_emu_run(e);
		CK(kgenome_emu_watch_hits(e, wr, wv, 64) == 0);
		kgenome_emu_free(e);
	}
}

/* ---- fork -------------------------------------------------------------------------------------------- */

static void t_fork(void)
{
	struct kgenome_emu *e = fresh(1000, 64), *f, *g;
	uint8_t a = 0, b = 0;

	/* a copy of an emulator that has never run: independent, and the same program */
	f = kgenome_emu_fork(e);
	CK(f != NULL && f != e);
	CK(kgenome_emu_rip(f) == kgenome_emu_rip(e));
	CK(kgenome_emu_get_reg(f, KGENOME_EMU_RSP) == kgenome_emu_get_reg(e, KGENOME_EMU_RSP));
	CK(kgenome_emu_run(f) == KGENOME_EMU_STOP_UNSUPPORTED);
	CK(kgenome_emu_insn_count(e) == 0);                /* the original did not move */
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_UNSUPPORTED);
	CK(kgenome_emu_insn_count(e) == kgenome_emu_insn_count(f));
	/* writes to one are not seen by the other */
	g = kgenome_emu_fork(e);
	CK(g == NULL);                                     /* e has run: "NULL when it has" */
	kgenome_emu_free(e);
	kgenome_emu_free(f);

	e = fresh(1000, 64);
	f = kgenome_emu_fork(e);
	g = kgenome_emu_fork(e);
	a = 0x41;
	CK(kgenome_emu_write(f, DATA, &a, 1) == 1);
	CK(kgenome_emu_read(g, DATA, &b, 1) == 1 && b == 0);
	CK(kgenome_emu_read(e, DATA, &b, 1) == 1 && b == 0);
	CK(kgenome_emu_read(f, DATA, &b, 1) == 1 && b == 0x41);
	kgenome_emu_free(f);
	kgenome_emu_free(e);                               /* the copy outlives its source */
	CK(kgenome_emu_read(g, DATA, &b, 1) == 1 && b == 0);
	kgenome_emu_free(g);
}

/* ---- the Windows environment's tables ------------------------------------------------------------------ */

static void t_win_tables(void)
{
	unsigned n = kgenome_emu_win_api_count(), i, m, seen_mod[KGENOME_EMU_WIN_MOD_COUNT] = { 0 };
	struct kgenome_emu *e;

	CK(n > 100);
	CK(kgenome_emu_win_mod_count() == KGENOME_EMU_WIN_MOD_COUNT);
	for (i = 0; i < n; i++) {
		const char *nm = kgenome_emu_win_api_name(i);
		unsigned mod = kgenome_emu_win_api_mod(i);

		CK(nm && nm[0]);
		CK(mod < KGENOME_EMU_WIN_MOD_COUNT);
		CK(kgenome_emu_win_api_argc(i) <= 16u);
		CK(kgenome_emu_win_api_trap(i) == 0x57494e00u + i);     /* 'W','I','N', index */
		CK(kgenome_emu_win_api_slot(i) < n);
		if (mod < KGENOME_EMU_WIN_MOD_COUNT)
			seen_mod[mod]++;
	}
	CK(seen_mod[KGENOME_EMU_WIN_MOD_K32] > 20);
	/* a name is its own: two APIs may not share one inside a module */
	for (i = 0; i < n && i < 140; i++) {
		unsigned j;
		for (j = i + 1; j < n && j < 140; j++)
			if (kgenome_emu_win_api_mod(i) == kgenome_emu_win_api_mod(j) &&
			    !strcmp(kgenome_emu_win_api_name(i), kgenome_emu_win_api_name(j)))
				CK(0);
	}
	for (m = 0; m < KGENOME_EMU_WIN_MOD_COUNT; m++) {
		const char *nm = kgenome_emu_win_mod_name(m);
		unsigned bits;
		CK(nm && nm[0]);
		for (bits = 32; bits <= 64; bits += 32) {
			uint64_t b = kgenome_emu_win_mod_base(m, bits);
			CK(b != 0 && (b % KGENOME_EMU_PAGE) == 0);
			if (bits == 32)
				CK(b + KGENOME_EMU_WIN_MOD_SPAN <= 0x100000000ull);
		}
	}
	/* bases of two modules never overlap */
	for (m = 0; m + 1u < KGENOME_EMU_WIN_MOD_COUNT; m++) {
		uint64_t a = kgenome_emu_win_mod_base(m, 64), b = kgenome_emu_win_mod_base(m + 1u, 64);
		uint64_t lo = a < b ? a : b, hi = a < b ? b : a;
		CK(hi - lo >= KGENOME_EMU_WIN_MOD_SPAN);
	}
	/* past the end: nothing, never a stray pointer */
	CK(kgenome_emu_win_mod_name(KGENOME_EMU_WIN_MOD_COUNT) == NULL);
	CK(kgenome_emu_win_mod_name(~0u) == NULL);
	CK(kgenome_emu_win_api_name(n) == NULL);
	CK(kgenome_emu_win_api_name(~0u) == NULL);
	CK(kgenome_emu_win_api_argc(n) == 0 && kgenome_emu_win_api_argc(~0u) == 0);
	CK(kgenome_emu_win_api_mod(n) == 0 || kgenome_emu_win_api_mod(n) >= KGENOME_EMU_WIN_MOD_COUNT);
	CK(kgenome_emu_win_mod_base(KGENOME_EMU_WIN_MOD_COUNT, 64) == 0);
	CK(kgenome_emu_win_mod_base(~0u, 32) == 0);

	/* addr_of answers 0 until the module is placed, then the stub address; resolve never 0 for
	 * a plausible name */
	e = fresh(1000, 64);
	CK(kgenome_emu_win_addr_of(e, "VirtualAlloc") == 0);
	CK(kgenome_emu_win_addr_of(e, "") == 0);
	CK(kgenome_emu_win_addr_of(e, "NoSuchApiAnywhere") == 0);
	for (i = 0; i < n; i++)
		if (!strcmp(kgenome_emu_win_api_name(i), "VirtualAlloc"))
			break;
	CK(i < n);
	kgenome_emu_win_set_module(e, kgenome_emu_win_api_mod(i), 0x70000000ull);
	CK(kgenome_emu_win_addr_of(e, "VirtualAlloc") ==
	   0x70000000ull + KGENOME_EMU_WIN_STUB_RVA + (uint64_t)kgenome_emu_win_api_slot(i) * KGENOME_EMU_WIN_STUB);
	CK(kgenome_emu_win_addr_of(e, "virtualalloc") == kgenome_emu_win_addr_of(e, "VirtualAlloc"));
	CK(kgenome_emu_win_resolve(e, "VirtualAlloc") == kgenome_emu_win_addr_of(e, "VirtualAlloc"));
	CK(kgenome_emu_win_resolve(e, "DeleteFileW9") != 0);             /* a miss thunk, not 0 */
	kgenome_emu_win_set_module(e, KGENOME_EMU_WIN_MOD_COUNT, 0x1000);    /* out of range: ignored */
	kgenome_emu_win_set_module(e, ~0u, 0x1000);
	kgenome_emu_free(e);

	/* shim_api: 1 when the name is one of the APIs, 0 when not or the table is full;
	 * a later declaration of the same name replaces the earlier one */
	e = fresh(1000, 64);
	CK(kgenome_emu_shim_api(e, "NoSuchApiAnywhere", 1) == 0);
	CK(kgenome_emu_shim_api(e, "", 1) == 0);
	CK(kgenome_emu_shim_api(e, "GetVersion", 5) == 1);
	CK(kgenome_emu_shim_api(e, "GetVersion", 6) == 1);              /* replaces, takes no slot */
	{
		unsigned ok = 0;
		for (i = 0; i < n && ok < KGENOME_EMU_SHIM_MAX + 20u; i++)
			ok += (unsigned)(kgenome_emu_shim_api(e, kgenome_emu_win_api_name(i), 7) == 1);
		CK(ok <= KGENOME_EMU_SHIM_MAX + 1u);                    /* the table is bounded */
		CK(ok >= KGENOME_EMU_SHIM_MAX - 1u);
	}
	kgenome_emu_free(e);
}

/* a run of one API: the stub every module carries is `mov eax, trap ; syscall ; ret` */
static void t_win_events(void)
{
	static uint8_t code[] = { 0xb8, 0, 0, 0, 0, 0x0f, 0x05, 0xf4 };
	unsigned i, n = kgenome_emu_win_api_count(), getver = n;
	struct kgenome_emu *e;
	struct kgenome_emu_win_event ev;
	uint32_t trap;

	for (i = 0; i < n; i++)
		if (!strcmp(kgenome_emu_win_api_name(i), "GetVersion"))
			getver = i;
	CK(getver < n);
	trap = kgenome_emu_win_api_trap(getver);
	memcpy(code + 1, &trap, 4);
	e = fresh(1000, 64);
	/* the code is not at CODE here: map the stub itself */
	{
		struct kgenome_emu_cfg cfg = { 1000, 64, 0, 64 };
		kgenome_emu_free(e);
		e = kgenome_emu_new(&cfg);
		kgenome_emu_map(e, CODE, code, sizeof code, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
		kgenome_emu_map(e, STK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
		kgenome_emu_set_rip(e, CODE);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STK + 0x8000);
	}
	kgenome_emu_win_setup(e, 0x10000000ull);
	kgenome_emu_win_set_heap(e, STK);
	kgenome_emu_win_set_module(e, KGENOME_EMU_WIN_MOD_K32, 0x70000000ull);
	CK(kgenome_emu_shim_api(e, "GetVersion", 0x1234) == 1);
	(void)kgenome_emu_run(e);
	CK(kgenome_emu_win_event_count(e) == 1);
	memset(&ev, 0xaa, sizeof ev);
	CK(kgenome_emu_win_event_at(e, 0, &ev) == 1);
	CK(ev.api == getver && ev.count == 1 && ev.ret == 0x1234);
	CK(kgenome_emu_win_event_at(e, 1, &ev) == 0);
	CK(kgenome_emu_win_event_at(e, 0xffffffffu, &ev) == 0);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 0x1234);
	kgenome_emu_free(e);
}

/* ---- reads of the module image are counted only when asked ----------------------------------------------- */

static void t_mod_reads(void)
{
	/* mov rax, [BASE + 8] ; hlt   with BASE the kernel32 image the module placed */
	uint8_t code[] = { 0x48, 0xa1, 0, 0, 0, 0x70, 0, 0, 0, 0, 0xf4 };
	unsigned on;
	struct kgenome_emu *e;
	unsigned k;

	for (on = 0; on < 2; on++) {
		struct kgenome_emu_cfg cfg = { 1000, 64, 0, 64 };

		hk_w(code + 2, 0x70000008ull, 8, 0);
		e = kgenome_emu_new(&cfg);
		kgenome_emu_map(e, CODE, code, sizeof code, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
		kgenome_emu_map(e, 0x70000000ull, NULL, 0, 0x2000, KGENOME_EMU_R);
		kgenome_emu_set_rip(e, CODE);
		kgenome_emu_win_setup(e, 0x10000000ull);
		kgenome_emu_win_set_module(e, KGENOME_EMU_WIN_MOD_K32, 0x70000000ull);
		kgenome_emu_count_mod_reads(e, (int)on);
		(void)kgenome_emu_run(e);
		if (on)
			CK(kgenome_emu_mod_reads(e, KGENOME_EMU_WIN_MOD_K32) >= 1);
		else
			CK(kgenome_emu_mod_reads(e, KGENOME_EMU_WIN_MOD_K32) == 0);
		for (k = 1; k < KGENOME_EMU_WIN_MOD_COUNT; k++)
			CK(kgenome_emu_mod_reads(e, k) == 0);
		CK(kgenome_emu_mod_reads(e, KGENOME_EMU_WIN_MOD_COUNT) == 0);
		CK(kgenome_emu_mod_reads(e, ~0u) == 0);
		kgenome_emu_free(e);
	}
}

/* ---- syscall log, unknown syscalls, snapshots ---------------------------------------------------------------- */

static void t_syscalls_and_snapshots(void)
{
	/* getpid ; an unknown number ; a store into DATA ; mprotect(DATA, 0x1000, R|X) ; hlt */
	static const uint8_t code[] = {
		0xb8, 39, 0, 0, 0, 0x0f, 0x05,
		0xb8, 0x77, 0x77, 0, 0, 0x0f, 0x05,
		0xc6, 0x04, 0x25, 0, 0, 0x60, 0, 0x41,
		0x48, 0xc7, 0xc0, 10, 0, 0, 0,
		0x48, 0xbf, 0, 0, 0x60, 0, 0, 0, 0, 0,
		0x48, 0xc7, 0xc6, 0, 0x10, 0, 0,
		0x48, 0xc7, 0xc2, 5, 0, 0, 0,
		0x0f, 0x05,
		0xf4
	};
	unsigned i;
	struct kgenome_emu *e;
	struct kgenome_emu_syscall sl[KGENOME_EMU_SYSLOG + 4];
	uint32_t unk[KGENOME_EMU_UNKSYS + 4];
	uint32_t it = 0, snaps = 0;
	uint64_t va, len;
	const uint8_t *by;

	e = fresh(1000, 64);
	kgenome_emu_map(e, CODE, code, sizeof code, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	CK(kgenome_emu_syscall_log(e, sl, 4) == 0);
	(void)kgenome_emu_run(e);
	i = kgenome_emu_syscall_log(e, sl, KGENOME_EMU_SYSLOG + 4);
	CK(i >= 2 && i <= KGENOME_EMU_SYSLOG);
	CK(sl[0].nr == 39);                                 /* oldest first */
	CK(sl[1].nr == 0x7777 && (int64_t)sl[1].ret == -38);        /* ENOSYS */
	CK(kgenome_emu_syscall_log(e, sl, 0) == 0);
	CK(kgenome_emu_syscall_log(e, sl, 1) == 1);
	CK(kgenome_emu_syscall_log(e, NULL, 0) == 0);
	i = kgenome_emu_unknown_syscalls(e, unk, KGENOME_EMU_UNKSYS + 4);
	CK(i >= 1 && i <= KGENOME_EMU_UNKSYS);
	CK(unk[0] == 0x7777);
	CK(kgenome_emu_unknown_syscalls(e, unk, 0) == 0);
	CK(kgenome_emu_unknown_syscalls(e, NULL, 0) == 0);

	/* the mprotect(+X) over a page the run wrote is the snapshot */
	while (kgenome_emu_next_snapshot(e, &it, &va, &by, &len) && snaps < 64u) {
		snaps++;
		CK(by != NULL && len > 0);
	}
	CK(snaps >= 1);
	CK(kgenome_emu_next_snapshot(e, &it, &va, &by, &len) == 0);     /* the walk stays ended */
	kgenome_emu_snap_written(e);
	kgenome_emu_snap_written(e);                                    /* idempotent in effect */
	it = 0;
	snaps = 0;
	while (kgenome_emu_next_snapshot(e, &it, &va, &by, &len) && snaps < 1000u)
		snaps++;
	CK(snaps <= KGENOME_EMU_MAX_SNAP);
	kgenome_emu_free(e);
}

/* ---- map / read / write ----------------------------------------------------------------------------------------- */

static int write_cross_case(void *arg)
{
	struct kgenome_emu_cfg cfg = { 1000, 16, 0, 0 };
	struct kgenome_emu *e = kgenome_emu_new(&cfg);
	uint8_t z[16] = { 0 }, w[8], r[4] = { 0xff, 0xff, 0xff, 0xff };

	(void)arg;
	memset(w, 0x77, sizeof w);
	kgenome_emu_map(e, DATA, z, sizeof z, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	/* 8 bytes starting 4 before the end of the only page: the second half is unmapped */
	if (kgenome_emu_write(e, DATA + 0xffc, w, 8) != 0)
		return 2;
	/* a refused write is whole or nothing, like a refused read ("touches nothing then") */
	kgenome_emu_read(e, DATA + 0xffc, r, 4);
	kgenome_emu_free(e);
	return r[0] == 0 && r[1] == 0 && r[2] == 0 && r[3] == 0 ? 0 : 1;
}

static void t_memory_api(void)
{
	struct kgenome_emu_cfg cfg = { 1000, 64, 0, 0 };
	struct kgenome_emu *e = kgenome_emu_new(&cfg);
	uint8_t pat[16], buf[16], z[16] = { 0 };
	int sig = 0;
	unsigned i;

	for (i = 0; i < 16; i++)
		pat[i] = (uint8_t)(0x10 + i);
	CK(kgenome_emu_map(e, DATA, pat, 16, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W) == 1);
	/* the tail past n reads as zero */
	memset(buf, 0xee, sizeof buf);
	CK(kgenome_emu_read(e, DATA, buf, 16) == 1 && !memcmp(buf, pat, 16));
	CK(kgenome_emu_read(e, DATA + 16, buf, 16) == 1 && !memcmp(buf, z, 16));
	CK(kgenome_emu_read(e, DATA + 0x1000 - 16, buf, 16) == 1);
	/* refused reads touch nothing */
	memset(buf, 0xee, sizeof buf);
	CK(kgenome_emu_read(e, DATA + 0x1000 - 8, buf, 16) == 0);
	CK(buf[0] == 0xee && buf[7] == 0xee);
	CK(kgenome_emu_read(e, 0x500000, buf, 4) == 0);
	CK(kgenome_emu_read(e, UINT64_MAX - 2u, buf, 8) == 0);
	CK(kgenome_emu_read(e, UINT64_MAX, buf, 1) == 0);
	CK(kgenome_emu_read(e, DATA, buf, 0) == 1);
	CK(kgenome_emu_read(e, DATA, NULL, 4) == 0);
	CK(kgenome_emu_read(NULL, DATA, buf, 4) == 0);
	/* the null page answers zeros by design */
	memset(buf, 0xee, sizeof buf);
	CK(kgenome_emu_read(e, 0, buf, 8) == 1 && !memcmp(buf, z, 8));
	/* writes: into a mapped page, never wrapping, zero-length is vacuous */
	CK(kgenome_emu_write(e, DATA + 4, pat, 4) == 1);
	CK(kgenome_emu_read(e, DATA + 4, buf, 4) == 1 && !memcmp(buf, pat, 4));
	CK(kgenome_emu_write(e, UINT64_MAX - 2u, pat, 8) == 0);
	CK(kgenome_emu_write(e, 0x500000, pat, 4) == 0);
	CK(kgenome_emu_write(e, DATA, pat, 0) == 1);
	CK(kgenome_emu_write(e, 0, pat, 4) == 0);
	/* map: the refusals */
	CK(kgenome_emu_map(e, 0, pat, 16, 0x1000, KGENOME_EMU_R) == 0);              /* the null page */
	CK(kgenome_emu_map(e, 0x530000, NULL, 0, UINT64_MAX, KGENOME_EMU_R) == 0);     /* beyond max_pages */
	CK(kgenome_emu_map(e, UINT64_MAX - 0xfff, NULL, 0, 0x2000, KGENOME_EMU_R) == 0);   /* wraps */
	CK(kgenome_emu_map(e, 0xfffffffffffff000ull, NULL, 0, 0x1000, KGENOME_EMU_R) == 0 ||
	   kgenome_emu_map(e, 0xfffffffffffff000ull, NULL, 0, 0x1000, KGENOME_EMU_R) == 1);
	CK(kgenome_emu_map(NULL, DATA, pat, 16, 0x1000, KGENOME_EMU_R) == 0);
	kgenome_emu_free(e);

	/* a refused write is whole or nothing */
	{
		enum hk_result r = hk_isolated(write_cross_case, NULL, 10, &sig);
		KM_CHECK(r == HK_OK, "kgenome_emu_write that crosses into an unmapped page returns 0 "
			 "after writing the bytes before the hole",
			 "emu_api.c:475 kgenome_emu_write forwards to kgenome_emu_mem_wr with no per-page "
			 "pre-check (kgenome_emu_read has one, emu_api.c:441). Repro: map one page at 0x600000, "
			 "write 8 bytes at 0x600ffc: returns 0, bytes 0x600ffc..f are changed");
	}
}

/* ---- free and NULL ------------------------------------------------------------------------------------------------ */

static void t_null_free(void)
{
	kgenome_emu_free(NULL);
	CK(kgenome_emu_fork(NULL) == NULL);
	{
		struct kgenome_emu *e = kgenome_emu_new(NULL);          /* a NULL cfg takes every default */
		CK(e != NULL);
		kgenome_emu_free(e);
	}
	/* every struct/char accessor on a fresh emulator answers without running anything */
	{
		struct kgenome_emu *e = kgenome_emu_new(NULL);
		CK(kgenome_emu_stop_detail(e) != NULL && kgenome_emu_stop_detail(e)[0] == 0);
		CK(kgenome_emu_insn_count(e) == 0);
		kgenome_emu_free(e);
	}
	CK(kgenome_emu_win_event_count(NULL) == 0);
	CK(kgenome_emu_null_calls(NULL) == 0 && kgenome_emu_unhandled(NULL) == 0 && kgenome_emu_null_reads(NULL) == 0);
	CK(kgenome_emu_idle_max(NULL) == 0);
	CK(kgenome_emu_last_branch_at(NULL) == 0);
	CK(kgenome_emu_get_rip(NULL) == 0);
	CK(kgenome_emu_write_seen(NULL) == 0);
	CK(kgenome_emu_itrace_count(NULL) == 0);
	CK(kgenome_emu_itrace(NULL, 8) == 0);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	t_state();
	t_budgets();
	t_watches();
	t_fork();
	t_win_tables();
	t_win_events();
	t_mod_reads();
	t_syscalls_and_snapshots();
	t_memory_api();
	t_null_free();
	printf("api_emu: %d failure(s), %u known\n", hk_fails, km_known());
	return hk_fails != 0 || km_failed();
}
