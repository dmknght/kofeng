/*
 * hostile_emu - the emulator, run as a hostile guest would run it.
 *
 * The interpreter decodes and simulates; it calls no host system call and
 * jits nothing (emu.h), so what a hostile guest can attack is the HOST'S
 * OWN CODE: its integer arithmetic, its bounds on guest addresses, its tables
 * of mappings and snapshots, and its time. Each family below is one way of
 * pointing a guest at that code, and each asserts the same three things:
 *
 *   it ends        every run returns, within its instruction budget (an
 *                  infinite loop, a REP of 2^64, a stack that never fills are
 *                  all stopped by the budget or by a fault, never by the alarm)
 *   it stays small the pages and snapshots it owns stay under the cfg ceiling
 *   it says why    the stop reason is one of the documented ones; FAULT and
 *                  UNSUPPORTED are answers, not crashes
 *
 * THE FAMILIES
 *   programs     hand-written hostile code: divide by zero, the signed overflow
 *                of IDIV in all four widths, REP with a count of 2^64-1, a store
 *                that wraps the top of the address space, a push that never
 *                stops, self-modifying code, a jump to unmapped memory, #UD
 *   random code  fixed-seed random byte streams (biased to prefixes, escapes,
 *                x87, SSE, string ops, syscall) with random registers, 64- and
 *                32-bit; the seed of the run in progress is kept in shared
 *                memory so a crash names it
 *   syscalls     every number 0..511 and a handful of hostile ones, with
 *                hostile argument sets (unmapped pointers, 2^63 lengths, -1)
 *   windows APIs every function of the Windows environment, called with hostile
 *                arguments through its own stub
 *   API misuse   the public calls with values no honest caller passes
 *
 * Each family is a forked child (hk_isolated): a crash is the family's result.
 */

#include <kgenome.h>
#include <genotype/x86/x86.h>

#include "hk.h"
#include "../../unit/known_miss.h"

#define CODE_VA   0x400000ull
#define DATA_VA   0x600000ull
#define STACK_VA  0x7ff00000ull
#define DATA_LEN  0x10000ull
#define STACK_LEN 0x10000ull

/* a crash names the seed it died on */
static volatile uint64_t *shared_seed;

struct run_res {
	enum kgenome_emu_stop stop;
	uint64_t insn;
	double secs;
	uint64_t rip;
};

/* Build an emulator over `code`, run it, report. `setup` may prime registers. */
typedef void (*setup_fn)(struct kgenome_emu *e, void *arg);

static struct kgenome_emu *mk(const uint8_t *code, size_t n, uint64_t budget, uint64_t pages,
			      unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = budget;
	cfg.max_pages = pages;
	cfg.bits = bits;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	kgenome_emu_map(e, CODE_VA, code, n, 0x2000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA_VA, NULL, 0, DATA_LEN, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, STACK_VA, NULL, 0, STACK_LEN, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, CODE_VA);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK_VA + STACK_LEN / 2u);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSI, DATA_VA);
	kgenome_emu_set_reg(e, KGENOME_EMU_RDI, DATA_VA + DATA_LEN / 2u);
	return e;
}

static struct run_res run_code(const uint8_t *code, size_t n, uint64_t budget, unsigned bits,
			       setup_fn setup, void *arg)
{
	struct run_res r;
	struct kgenome_emu *e = mk(code, n, budget, 256, bits);
	double t0 = hk_now();

	memset(&r, 0, sizeof r);
	r.stop = KGENOME_EMU_STOP_QUIET;
	if (!e)
		return r;
	if (setup)
		setup(e, arg);
	r.stop = kgenome_emu_run(e);
	r.secs = hk_now() - t0;
	r.insn = kgenome_emu_insn_count(e);
	r.rip = kgenome_emu_get_rip(e);
	kgenome_emu_free(e);
	return r;
}

static int stop_known(enum kgenome_emu_stop s)
{
	return s >= KGENOME_EMU_STOP_BUDGET && s <= KGENOME_EMU_STOP_QUIET;
}

/* ---- 1: hand-written hostile programs ------------------------------------------------- */

struct prog {
	const char *name;
	const uint8_t *code;
	size_t n;
	uint64_t budget;
	int must_end_by;                        /* an enum kgenome_emu_stop, or -1: any */
	int may_be_budget;
};

#define P(nm, ...) static const uint8_t nm[] = { __VA_ARGS__ }

P(p_div0,      0x31, 0xc9, 0xb8, 1, 0, 0, 0, 0x31, 0xd2, 0xf7, 0xf1, 0xf4);
P(p_div0_64,   0x48, 0x31, 0xc9, 0x48, 0xf7, 0xf1, 0xf4);
P(p_div0_8,    0x30, 0xc9, 0xf6, 0xf1, 0xf4);
P(p_idiv64,    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x48, 0x99, 0x48, 0xc7, 0xc1, 0xff, 0xff,
		0xff, 0xff, 0x48, 0xf7, 0xf9, 0xf4);
P(p_idiv32,    0xb8, 0, 0, 0, 0x80, 0x99, 0xb9, 0xff, 0xff, 0xff, 0xff, 0xf7, 0xf9, 0xf4);
P(p_idiv16,    0x66, 0xb8, 0, 0x80, 0x66, 0x99, 0x66, 0xb9, 0xff, 0xff, 0x66, 0xf7, 0xf9, 0xf4);
P(p_idiv8,     0x66, 0xb8, 0, 0x80, 0xb1, 0xff, 0xf6, 0xf9, 0xf4);
P(p_div128,    0x48, 0xc7, 0xc2, 1, 0, 0, 0, 0x31, 0xc0, 0xb9, 1, 0, 0, 0, 0x48, 0xf7, 0xf1, 0xf4);
P(p_imul_ovf,  0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x48, 0xf7, 0xe8, 0x48, 0x0f, 0xaf, 0xc0, 0xf4);
P(p_rep_movs,  0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, 0xf3, 0xa4, 0xf4);
P(p_rep_stos,  0x48, 0x31, 0xc9, 0x48, 0xff, 0xc9, 0xf3, 0x48, 0xab, 0xf4);
P(p_rep_backwards, 0xfd, 0x48, 0x31, 0xc9, 0x48, 0xff, 0xc9, 0xf3, 0xa4, 0xf4);
P(p_rep_cmps,  0x48, 0x31, 0xc9, 0x48, 0xff, 0xc9, 0xf3, 0xa6, 0xf4);
P(p_rep_scas,  0x48, 0x31, 0xc9, 0x48, 0xff, 0xc9, 0x31, 0xc0, 0xf2, 0xae, 0xf4);
P(p_jmp_self,  0xeb, 0xfe);
P(p_push_loop, 0x50, 0xeb, 0xfd);
P(p_call_loop, 0xe8, 0xfb, 0xff, 0xff, 0xff);
P(p_jmp_unmap, 0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0, 0xff, 0xe0);
P(p_jmp_top,   0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0);
P(p_ret0,      0xc3);
P(p_ud2,       0x0f, 0x0b);
P(p_ffff,      0xff, 0xff, 0xff);
P(p_store_top, 0x48, 0xbf, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x89, 0x07, 0xf4);
P(p_load_top,  0x48, 0xbf, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x07, 0xf4);
P(p_store_page_end, 0x48, 0xbf, 0xfd, 0xff, 0x60, 0, 0, 0, 0, 0, 0x48, 0xc7, 0x07, 1, 2, 3, 4, 0xf4);
P(p_smc_self,  0xc6, 0x05, 0xf9, 0xff, 0xff, 0xff, 0x90, 0xf4, 0xeb, 0xfe);
P(p_smc_ahead, 0xc6, 0x05, 0x01, 0, 0, 0, 0xcc, 0x90, 0xeb, 0xfe);
P(p_cpuid_loop, 0x0f, 0xa2, 0xeb, 0xfc);
P(p_rdtsc_loop, 0x0f, 0x31, 0xeb, 0xfc);
P(p_xsave_unmapped, 0x48, 0xbf, 0, 0, 0, 0, 0xf0, 0xff, 0, 0, 0x0f, 0xae, 0x27, 0xf4);
P(p_movaps_unaligned, 0x0f, 0x28, 0x46, 0x01, 0xf4);
P(p_shift_big, 0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, 0x48, 0xd3, 0xe0, 0x48, 0xd3, 0xf8, 0x48, 0x0f, 0xa5, 0xc8, 0x48, 0x0f, 0xad, 0xc8, 0xf4);
P(p_bsf0,      0x31, 0xc0, 0x48, 0x0f, 0xbc, 0xc0, 0x48, 0x0f, 0xbd, 0xc0, 0xf3, 0x48, 0x0f, 0xbc, 0xc0, 0xf4);
P(p_cmpxchg16b, 0x48, 0x0f, 0xc7, 0x0e, 0xf4);
P(p_enter_big, 0xc8, 0xff, 0xff, 0x1f, 0xf4);
P(p_loopn,     0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff, 0xe2, 0xfe, 0xf4);
P(p_x87_stack, 0xd9, 0xe8, 0xeb, 0xfc);
P(p_fxsave_self, 0x0f, 0xae, 0x06, 0xf4);
P(p_syscall_loop, 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0x7f, 0x0f, 0x05, 0xeb, 0xf7);
P(p_int_loop,  0xcd, 0x80, 0xeb, 0xfc);
P(p_int3,      0xcc, 0xcc, 0xcc);
P(p_far_call,  0x9a, 0, 0, 0, 0, 0, 0);
P(p_lock_ud,   0xf0, 0x90);
P(p_xlat_big,  0x48, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff, 0xd7, 0xf4);
P(p_pushf_pop, 0x9c, 0x9d, 0x9c, 0x58, 0x0d, 0, 1, 0, 0, 0x50, 0x9d, 0xeb, 0xf1);

static const struct prog progs[] = {
	{ "div by zero 32",          p_div0,      sizeof p_div0,      1000, -1, 0 },
	{ "div by zero 64",          p_div0_64,   sizeof p_div0_64,   1000, -1, 0 },
	{ "div by zero 8",           p_div0_8,    sizeof p_div0_8,    1000, -1, 0 },
	{ "idiv 64 INT_MIN/-1",      p_idiv64,    sizeof p_idiv64,    1000, -1, 0 },
	{ "idiv 32 INT_MIN/-1",      p_idiv32,    sizeof p_idiv32,    1000, -1, 0 },
	{ "idiv 16 INT_MIN/-1",      p_idiv16,    sizeof p_idiv16,    1000, -1, 0 },
	{ "idiv 8  INT_MIN/-1",      p_idiv8,     sizeof p_idiv8,     1000, -1, 0 },
	{ "div 128/64 overflow",     p_div128,    sizeof p_div128,    1000, -1, 0 },
	{ "imul overflow",           p_imul_ovf,  sizeof p_imul_ovf,  1000, -1, 0 },
	{ "rep movsb rcx=2^32-1",    p_rep_movs,  sizeof p_rep_movs,  3000000, -1, 1 },
	{ "rep stosq rcx=2^64-1",    p_rep_stos,  sizeof p_rep_stos,  3000000, -1, 1 },
	{ "rep movsb backwards",     p_rep_backwards, sizeof p_rep_backwards, 3000000, -1, 1 },
	{ "rep cmpsb rcx=2^64-1",    p_rep_cmps,  sizeof p_rep_cmps,  3000000, -1, 1 },
	{ "repne scasb rcx=2^64-1",  p_rep_scas,  sizeof p_rep_scas,  3000000, -1, 1 },
	{ "jmp $",                   p_jmp_self,  sizeof p_jmp_self,  200000, KGENOME_EMU_STOP_BUDGET, 1 },
	{ "push forever",            p_push_loop, sizeof p_push_loop, 200000, KGENOME_EMU_STOP_FAULT, 0 },
	{ "call forever (recursion)", p_call_loop, sizeof p_call_loop, 200000, KGENOME_EMU_STOP_FAULT, 0 },
	{ "jump to unmapped",        p_jmp_unmap, sizeof p_jmp_unmap, 1000, KGENOME_EMU_STOP_FAULT, 0 },
	{ "jump to the top of memory", p_jmp_top, sizeof p_jmp_top,   1000, KGENOME_EMU_STOP_FAULT, 0 },
	{ "ret to zero",             p_ret0,      sizeof p_ret0,      1000, KGENOME_EMU_STOP_FAULT, 0 },
	{ "ud2",                     p_ud2,       sizeof p_ud2,       1000, -1, 0 },
	{ "ff ff ff",                p_ffff,      sizeof p_ffff,      1000, -1, 0 },
	{ "store across the top of memory", p_store_top, sizeof p_store_top, 1000, KGENOME_EMU_STOP_FAULT, 0 },
	{ "load across the top of memory",  p_load_top,  sizeof p_load_top,  1000, KGENOME_EMU_STOP_FAULT, 0 },
	{ "store across the end of the mapping", p_store_page_end, sizeof p_store_page_end, 1000, -1, 0 },
	{ "self modifying: behind itself", p_smc_self, sizeof p_smc_self, 1000, -1, 0 },
	{ "self modifying: ahead of itself", p_smc_ahead, sizeof p_smc_ahead, 1000, -1, 1 },
	{ "cpuid loop",              p_cpuid_loop, sizeof p_cpuid_loop, 100000, -1, 1 },
	{ "rdtsc loop",              p_rdtsc_loop, sizeof p_rdtsc_loop, 100000, -1, 1 },
	{ "xsave to unmapped",       p_xsave_unmapped, sizeof p_xsave_unmapped, 1000, -1, 0 },
	{ "movaps unaligned",        p_movaps_unaligned, sizeof p_movaps_unaligned, 1000, -1, 0 },
	{ "shift counts > width",    p_shift_big, sizeof p_shift_big, 1000, -1, 0 },
	{ "bsf/bsr/tzcnt of zero",   p_bsf0,      sizeof p_bsf0,      1000, -1, 0 },
	{ "cmpxchg16b unaligned",    p_cmpxchg16b, sizeof p_cmpxchg16b, 1000, -1, 0 },
	{ "enter with 0x1fffff",     p_enter_big, sizeof p_enter_big, 1000, -1, 0 },
	{ "loop with rcx=2^64-1",    p_loopn,     sizeof p_loopn,     100000, -1, 1 },
	{ "x87 stack overflow",      p_x87_stack, sizeof p_x87_stack, 100000, -1, 1 },
	{ "fxsave over its own code", p_fxsave_self, sizeof p_fxsave_self, 1000, -1, 0 },
	{ "syscall(0x7fffffff) loop", p_syscall_loop, sizeof p_syscall_loop, 100000, -1, 1 },
	{ "int 0x80 loop",           p_int_loop,  sizeof p_int_loop,  100000, -1, 1 },
	{ "int3 x3",                 p_int3,      sizeof p_int3,      1000, -1, 0 },
	{ "far call",                p_far_call,  sizeof p_far_call,  1000, -1, 0 },
	{ "lock nop (#UD)",          p_lock_ud,   sizeof p_lock_ud,   1000, -1, 0 },
	{ "xlat with rbx=2^64-1",    p_xlat_big,  sizeof p_xlat_big,  1000, -1, 0 },
	{ "pushf/popf flag games",   p_pushf_pop, sizeof p_pushf_pop, 100000, -1, 1 },
};

static int fam_programs(void *arg)
{
	unsigned i, bits;

	(void)arg;
	for (bits = 64; bits >= 32; bits -= 32) {
		for (i = 0; i < sizeof progs / sizeof progs[0]; i++) {
			const struct prog *p = &progs[i];
			struct run_res r;

			/* KNOWN UNDEFINED BEHAVIOUR (UBSAN only): emu_interp.c:2003 multiplies two int64_t for a
			 * one-operand IMUL, so INT64_MIN * INT64_MIN overflows; in a plain build it wraps */
			if (hk_ubsan() && p->code == p_imul_ovf)
				continue;
			r = run_code(p->code, p->n, p->budget, bits, NULL, NULL);

			if (!stop_known(r.stop)) {
				printf("  FAIL %s (%u-bit): unknown stop %d\n", p->name, bits, (int)r.stop);
				hk_fails++;
			}
			/* the budget is a bound on instructions; a REP iteration counts as one */
			if (r.insn > p->budget) {
				printf("  FAIL %s (%u-bit): %llu insn > budget %llu\n", p->name, bits,
				       (unsigned long long)r.insn, (unsigned long long)p->budget);
				hk_fails++;
			}
			if (r.secs > 1.5) {
				printf("  FAIL %s (%u-bit): took %.2fs\n", p->name, bits, r.secs);
				hk_fails++;
			}
			if (p->must_end_by >= 0 && (int)r.stop != p->must_end_by && bits == 64) {
				printf("  FAIL %s: stopped with %s, expected %s\n", p->name,
				       kgenome_emu_stop_name(r.stop),
				       kgenome_emu_stop_name((enum kgenome_emu_stop)p->must_end_by));
				hk_fails++;
			}
			if (!p->may_be_budget && r.stop == KGENOME_EMU_STOP_BUDGET && bits == 64) {
				printf("  FAIL %s: ran to its budget\n", p->name);
				hk_fails++;
			}
		}
	}
	return hk_fails != 0;
}

/* ---- 2: random code ---------------------------------------------------------------------------- */

static const uint8_t hot[] = {
	0x0f, 0x0f, 0x38, 0x3a, 0x66, 0x67, 0xf2, 0xf3, 0xf0, 0x2e, 0x64, 0x65, 0x40, 0x48, 0x4c,
	0xc4, 0xc5, 0x62, 0xd8, 0xd9, 0xdb, 0xdd, 0xdf, 0xa4, 0xa5, 0xaa, 0xab, 0xa6, 0xa7, 0xae,
	0xaf, 0xac, 0xad, 0x0f, 0x05, 0xcd, 0x80, 0x0f, 0xa2, 0x0f, 0x31, 0x0f, 0xae, 0x0f, 0xc7,
	0x0f, 0xb0, 0x0f, 0xb1, 0x0f, 0xc8, 0xf6, 0xf7, 0xff, 0xfe, 0x8f, 0x8d, 0x89, 0x8b, 0x88,
	0x8a, 0xc6, 0xc7, 0xe8, 0xe9, 0xeb, 0x74, 0x75, 0xc3, 0xc2, 0x50, 0x58, 0x9c, 0x9d, 0xe2,
	0xe3, 0x0f, 0x1f, 0x0f, 0x18, 0x0f, 0xa3, 0x0f, 0xab, 0x0f, 0xba, 0x0f, 0xbc, 0x0f, 0xbd,
	0x0f, 0x10, 0x0f, 0x11, 0x0f, 0x28, 0x0f, 0x29, 0x0f, 0x6f, 0x0f, 0x7f, 0x0f, 0xd6, 0x00,
	0x00, 0x00, 0xff, 0xff, 0x80, 0x01, 0x03, 0x05, 0x07
};

struct rnd_arg { uint64_t seed0; unsigned runs; unsigned bits; };

static int fam_random_code(void *arg)
{
	const struct rnd_arg *ra = (const struct rnd_arg *)arg;
	struct hk_rng r;
	unsigned it, k;
	double t0 = hk_now();

	for (it = 0; it < ra->runs * hk_scale(); it++) {
		uint8_t code[256];
		struct kgenome_emu *e;
		enum kgenome_emu_stop st;
		uint64_t budget;
		unsigned reg;

		r.s = (ra->seed0 + it) * 0x9e3779b97f4a7c15ull | 1u;
		budget = 4000 + hk_below(&r, 20000);
		if (shared_seed)
			*shared_seed = ra->seed0 + it;
		/* every other run is a sequence of DECODABLE instructions (a candidate is kept when
		 * the lib's own decoder accepts it), so the interpreter's handlers are reached and
		 * not just its decode-refusal path */
		if (it & 1u) {
			for (k = 0; k + 16u <= sizeof code;) {
				uint8_t cand[16];
				struct kgenome_x86_insn in;
				unsigned j, tries;

				for (tries = 0; tries < 8; tries++) {
					for (j = 0; j < 16; j++)
						cand[j] = hk_below(&r, 3) ? hot[hk_below(&r, sizeof hot)] : (uint8_t)hk_next(&r);
					if (kgenome_x86_decode(&in, cand, 16, (int)ra->bits) == KGENOME_OK)
						break;
				}
				if (tries == 8) {
					code[k++] = 0x90;
					continue;
				}
				memcpy(code + k, cand, in.len);
				k += in.len;
			}
			while (k < sizeof code)
				code[k++] = 0x90;
		} else {
			for (k = 0; k < sizeof code; k++)
				code[k] = hk_below(&r, 3) ? hot[hk_below(&r, sizeof hot)] : (uint8_t)hk_next(&r);
		}
		if (hk_ubsan()) {
			/* the same known UB as above: a decoded IMUL is replaced by NOPs, see emu_interp.c:2003 */
			unsigned at = 0;
			while (at < sizeof code) {
				struct kgenome_x86_insn di;
				unsigned l = 1;

				if (kgenome_x86_decode(&di, code + at, sizeof code - at, (int)ra->bits) == KGENOME_OK) {
					l = di.len ? di.len : 1u;
					if (di.id == KGENOME_X86_I_IMUL)
						memset(code + at, 0x90, l);
				}
				at += l;
			}
		}
		e = mk(code, sizeof code, budget, 64, ra->bits);
		if (!e)
			return 2;
		for (reg = 0; reg < KGENOME_EMU_NGPR; reg++) {
			uint64_t v;
			switch (hk_below(&r, 6)) {
			case 0: v = 0; break;
			case 1: v = UINT64_MAX; break;
			case 2: v = DATA_VA + hk_below(&r, (uint32_t)DATA_LEN); break;
			case 3: v = 0x8000000000000000ull; break;
			case 4: v = hk_next(&r); break;
			default: v = hk_below(&r, 300); break;
			}
			if (reg != KGENOME_EMU_RSP)
				kgenome_emu_set_reg(e, reg, v);
		}
		st = kgenome_emu_run(e);
		if (!stop_known(st) || kgenome_emu_insn_count(e) > budget) {
			printf("  FAIL random run seed %llu: stop %d insn %llu budget %llu\n",
			       (unsigned long long)(ra->seed0 + it), (int)st,
			       (unsigned long long)kgenome_emu_insn_count(e), (unsigned long long)budget);
			hk_fails++;
		}
		/* what the run wrote is walkable and sane */
		{
			uint32_t iter = 0, runs = 0;
			uint64_t va, len;
			const uint8_t *by;
			while (kgenome_emu_next_written(e, &iter, &va, &by, &len) && runs++ < 4096u)
				if (!by || !len)
					hk_fails++;
		}
		kgenome_emu_free(e);
	}
	return hk_fails != 0 || hk_now() - t0 > 20.0 * hk_scale();
}

/* ---- 3: syscalls ---------------------------------------------------------------------------------- */

struct sys_arg { unsigned bits; unsigned pat; };

static void sys_setup(struct kgenome_emu *e, void *a)
{
	const struct sys_arg *s = (const struct sys_arg *)a;
	static const uint64_t ptr[] = { 0, DATA_VA, DATA_VA + 0x8000, 0xdead0000ull, UINT64_MAX,
		UINT64_MAX - 7u, DATA_VA + DATA_LEN - 1u, 0x7fffffffffffffffull };
	static const uint64_t len[] = { 0, 1, 0x1000, 0xffffffffu, 0x7fffffffffffffffull,
		0x8000000000000000ull, UINT64_MAX, 0x100000000ull };
	unsigned k;
	static const uint8_t selfbytes[512] = { 0x7f, 'E', 'L', 'F' };

	kgenome_emu_set_self(e, selfbytes, sizeof selfbytes);
	for (k = 0; k < 6; k++) {
		static const unsigned regs[6] = { KGENOME_EMU_RDI, KGENOME_EMU_RSI, KGENOME_EMU_RDX,
			KGENOME_EMU_R10, KGENOME_EMU_R8, KGENOME_EMU_R9 };
		uint64_t v = (k & 1u) ? len[(s->pat + k) % 8u] : ptr[(s->pat + k * 3u) % 8u];
		if (s->bits == 32)
			v &= 0xffffffffu;
		kgenome_emu_set_reg(e, regs[k], v);
	}
	/* 32-bit: ebx ecx edx esi edi ebp are the six arguments */
	if (s->bits == 32) {
		kgenome_emu_set_reg(e, KGENOME_EMU_RBX, ptr[s->pat % 8u] & 0xffffffffu);
		kgenome_emu_set_reg(e, KGENOME_EMU_RCX, len[(s->pat + 1u) % 8u] & 0xffffffffu);
	}
}

static int fam_syscalls(void *arg)
{
	/* mov eax, imm32 ; syscall|int 0x80 ; hlt */
	static uint8_t code64[] = { 0xb8, 0, 0, 0, 0, 0x0f, 0x05, 0xf4 };
	static uint8_t code32[] = { 0xb8, 0, 0, 0, 0, 0xcd, 0x80, 0xf4 };
	static const uint32_t extra[] = { 512, 1000, 0x3fffffffu, 0x7fffffffu, 0x80000000u,
		0xffffffffu, 0x40000000u, 0x4000003bu };
	unsigned bits, nr, pat, which;
	double t0 = hk_now();

	(void)arg;
	for (bits = 64; bits >= 32; bits -= 32) {
		for (which = 0; which < 512u + sizeof extra / sizeof extra[0]; which++) {
			nr = which < 512u ? which : extra[which - 512u];
			for (pat = 0; pat < (nr < 512u ? 8u : 2u); pat++) {
				struct sys_arg sa = { bits, pat };
				uint8_t *c = bits == 64 ? code64 : code32;
				struct run_res r;

				memcpy(c + 1, &nr, 4);
				if (shared_seed)
					*shared_seed = (uint64_t)bits << 40 | (uint64_t)nr << 8 | pat;
				r = run_code(c, 8, 20000, bits, sys_setup, &sa);
				if (!stop_known(r.stop) || r.insn > 20000u || r.secs > 1.0) {
					printf("  FAIL syscall %u pattern %u (%u-bit): stop %d insn %llu %.2fs\n",
					       nr, pat, bits, (int)r.stop, (unsigned long long)r.insn, r.secs);
					hk_fails++;
				}
			}
		}
	}
	return hk_fails != 0 || hk_now() - t0 > 20.0 * hk_scale();
}

/* ---- 4: the Windows environment ---------------------------------------------------------------------- */

struct win_arg { unsigned bits; unsigned pat; };

static int fam_windows(void *arg)
{
	const struct win_arg *wa = (const struct win_arg *)arg;
	static const uint64_t vals[] = { 0, 1, UINT64_MAX, 0x7fffffffffffffffull, 0x8000000000000000ull,
		0xdead0000ull, DATA_VA, DATA_VA + DATA_LEN - 1u, 0xffffffffu, 0x100000000ull, 0x1000 };
	unsigned i, n = kgenome_emu_win_api_count(), stops[16] = { 0 }, events = 0;
	double t0 = hk_now();

	for (i = 0; i < n; i++) {
		unsigned pat;
		for (pat = 0; pat < 6; pat++) {
			/* the stub the loader writes into every module: mov eax, trap ; syscall|int 0x80 ; hlt */
			uint8_t code[8];
			uint32_t trap = kgenome_emu_win_api_trap(i);
			struct kgenome_emu *e;
			unsigned k;
			struct kgenome_emu_win_event ev;
			enum kgenome_emu_stop st;

			code[0] = 0xb8;
			memcpy(code + 1, &trap, 4);
			code[5] = wa->bits == 64 ? 0x0f : 0xcd;
			code[6] = wa->bits == 64 ? 0x05 : 0x80;
			code[7] = 0xf4;
			e = mk(code, sizeof code, 20000, 128, wa->bits);
			if (!e)
				return 2;
			if (shared_seed)
				*shared_seed = (uint64_t)i << 8 | pat;
			kgenome_emu_win_setup(e, 0x10000000ull);
			kgenome_emu_win_set_heap(e, DATA_VA);
			if (wa->bits == 64) {
				kgenome_emu_set_reg(e, KGENOME_EMU_RCX, vals[(pat + 0u) % 11u]);
				kgenome_emu_set_reg(e, KGENOME_EMU_RDX, vals[(pat + 3u) % 11u]);
				kgenome_emu_set_reg(e, KGENOME_EMU_R8, vals[(pat + 5u) % 11u]);
				kgenome_emu_set_reg(e, KGENOME_EMU_R9, vals[(pat + 7u) % 11u]);
			}
			/* the stack arguments, whichever convention: eleven hostile words */
			for (k = 0; k < 12; k++) {
				uint64_t w = vals[(pat + k * 2u) % 11u];
				if (wa->bits == 32)
					w &= 0xffffffffu;
				kgenome_emu_write(e, STACK_VA + STACK_LEN / 2u + 8u * (k + 1u), &w, 8);
			}
			st = kgenome_emu_run(e);
			if (!stop_known(st) || kgenome_emu_insn_count(e) > 20000u) {
				printf("  FAIL %s pattern %u: stop %d\n", kgenome_emu_win_api_name(i), pat, (int)st);
				hk_fails++;
			}
			stops[(unsigned)st & 15u]++;
			events += kgenome_emu_win_event_count(e);
			/* the log stays walkable */
			for (k = 0; k < kgenome_emu_win_event_count(e) && k < 64u; k++)
				if (!kgenome_emu_win_event_at(e, k, &ev))
					hk_fails++;
			kgenome_emu_free(e);
		}
	}
	printf("  windows %u-bit: %u APIs; stops budget %u exit %u handoff %u fault %u unsupported %u decode %u; %u calls logged\n",
	       wa->bits, n, stops[0], stops[1], stops[2], stops[3], stops[4], stops[5], events);
	CK(events > n);
	return hk_fails != 0 || hk_now() - t0 > 20.0 * hk_scale();
}

/* ---- one-operand 64-bit IMUL: RDX:RAX is the 128-bit product ------------------------------------------------ */

static int km_imul64(void *arg)
{
	/* imul rbx ; hlt  with rax = 2^62, rbx = 4: the product is 2^64, rdx:rax = 1:0 */
	static const uint8_t code[] = { 0x48, 0xf7, 0xeb, 0xf4 };
	struct kgenome_emu *e = mk(code, sizeof code, 100, 16, 64);
	uint64_t hi, lo;
	int rc;

	(void)arg;
	if (hk_ubsan())
		return 0;                       /* the same instruction is the UB site; see the gate in fam_programs */
	kgenome_emu_set_reg(e, KGENOME_EMU_RAX, 1ull << 62);
	kgenome_emu_set_reg(e, KGENOME_EMU_RBX, 4);
	(void)kgenome_emu_run(e);
	lo = kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
	hi = kgenome_emu_get_reg(e, KGENOME_EMU_RDX);
	rc = lo == 0 && hi == 1 ? 0 : 1;
	kgenome_emu_free(e);
	return rc;
}

/* ---- 5: the public calls with values no honest caller passes -------------------------------------------- */

static struct kgenome_emu *plain(void)
{
	static const uint8_t code[] = { 0x90, 0xf4 };
	struct kgenome_emu_cfg c = { 1000, 16, 0, 0 };
	struct kgenome_emu *e = kgenome_emu_new(&c);

	if (!e)
		return NULL;
	kgenome_emu_map(e, CODE_VA, code, sizeof code, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA_VA, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, CODE_VA);
	return e;
}

/* The configuration calls with hostile numbers: nothing may crash and the emulator must
 * still run afterwards. */
static int fam_misuse_values(void *arg)
{
	static const uint64_t cfgs[] = { 0, 1, 2, 3, 0xffff, 1u << 22, (1u << 22) + 1u, UINT64_MAX };
	static const unsigned bitsv[] = { 0, 7, 32, 64, 0xffffffffu };
	struct kgenome_emu *e;
	unsigned i, j, k;
	uint64_t u[8];
	uint8_t buf[16];

	(void)arg;
	/* the cfg: every pair of ceilings, every width (a page ceiling is a table of 2 * pages entries, so the
	 * largest is taken once, below) */
	for (i = 0; i < 5; i++) {
		for (j = 0; j < sizeof bitsv / sizeof bitsv[0]; j++) {
			struct kgenome_emu_cfg c;
			static const uint8_t code[] = { 0x90, 0x90, 0xf4 };

			memset(&c, 0, sizeof c);
			c.max_insn = cfgs[(i + j) % (sizeof cfgs / sizeof cfgs[0])];
			c.max_pages = cfgs[i];
			c.bits = bitsv[j];
			e = kgenome_emu_new(&c);
			if (!e)
				continue;
			kgenome_emu_map(e, CODE_VA, code, sizeof code, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
			kgenome_emu_set_rip(e, CODE_VA);
			(void)kgenome_emu_run(e);
			kgenome_emu_free(e);
		}
	}
	{
		struct kgenome_emu_cfg c = { UINT64_MAX, UINT64_MAX, 0, 64 };       /* clamped to 2^22 pages */

		e = kgenome_emu_new(&c);
		kgenome_emu_free(e);
	}
	e = plain();
	CK(e != NULL);
	/* registers and segment bases: an index past the file is ignored or answers 0, never indexes */
	for (k = 0; k < 40; k++) {
		static const unsigned idx[] = { 16, 17, 31, 32, 64, 255, 256, 0x7fffffffu, 0x80000000u, 0xffffffffu };
		unsigned x = idx[k % 10u];
		kgenome_emu_set_reg(e, x, 0x1122334455667788ull);
		(void)kgenome_emu_get_reg(e, x);
		kgenome_emu_set_seg_base(e, x, 0x1000);
		(void)kgenome_emu_mod_reads(e, x);
		kgenome_emu_win_set_module(e, x, 0x1000);
		(void)kgenome_emu_win_mod_name(x);
		(void)kgenome_emu_win_mod_base(x, x);
		(void)kgenome_emu_win_api_name(x);
		(void)kgenome_emu_win_api_mod(x);
		(void)kgenome_emu_win_api_slot(x);
		(void)kgenome_emu_win_api_argc(x);
		(void)kgenome_emu_win_event_at(e, x, (struct kgenome_emu_win_event *)u);
		(void)kgenome_emu_itrace_get(e, x, &u[0], NULL, NULL);
	}
	/* a register index past the file reads as 0 and never aliases a real register */
	kgenome_emu_set_reg(e, KGENOME_EMU_RAX, 0x55);
	for (k = 16; k < 24; k++) {
		kgenome_emu_set_reg(e, k, 0x1122334455667788ull);
		CK(kgenome_emu_get_reg(e, k) == 0);
		CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 0x55);
	}
	/* sizes that are 32-bit unsigned: no wrap in `n` arithmetic */
	CK(kgenome_emu_read(e, DATA_VA, u, 0xffffffffu) == 0);
	CK(kgenome_emu_read(e, DATA_VA, u, 0x80000000u) == 0);
	CK(kgenome_emu_read(e, 0xfffffffffffff000ull, u, 0xffffffffu) == 0);
	/* (a write of 2^32-1 bytes from a 16-byte buffer is the caller lying about the buffer: not asked) */
	CK(kgenome_emu_write(e, UINT64_MAX, buf, 1) == 0);
	CK(kgenome_emu_read(e, UINT64_MAX, buf, 1) == 0);
	CK(kgenome_emu_read(e, UINT64_MAX - 0xfffu, buf, 0x1001u) == 0);
	/* the rings: a request for 2^32-1 entries is clamped, and 0 turns them off */
	(void)kgenome_emu_itrace(e, 0xffffffffu);
	kgenome_emu_itrace_at(e, UINT64_MAX);
	kgenome_emu_itrace_until(e, UINT64_MAX);
	kgenome_emu_itrace_on_null(e, -1);
	CK(kgenome_emu_itrace_count(e) <= KGENOME_EMU_ITRACE_MAX);
	kgenome_emu_itrace(e, 0);
	kgenome_emu_itrace(e, 0);
	CK(kgenome_emu_itrace_count(e) == 0);
	/* the ledgers: a huge n only ever returns what there is */
	CK(kgenome_emu_syscall_log(e, (struct kgenome_emu_syscall *)u, 0) == 0);
	CK(kgenome_emu_unknown_syscalls(e, (uint32_t *)u, 0) == 0);
	CK(kgenome_emu_trace(e, u, 0) == 0);
	CK(kgenome_emu_watch_hits(e, u, u + 4, 0) == 0);
	/* watch/shim names: empty, very long, with an embedded high bit */
	{
		char name[400];
		memset(name, 'A', sizeof name - 1u);
		name[sizeof name - 1u] = 0;
		CK(kgenome_emu_shim_api(e, name, 1) == 0);
		CK(kgenome_emu_win_addr_of(e, name) == 0);
		(void)kgenome_emu_win_resolve(e, name);
		name[0] = (char)0xff;
		name[1] = 0;
		CK(kgenome_emu_shim_api(e, name, 1) == 0);
		CK(kgenome_emu_win_addr_of(e, "") == 0);
	}
	/* map: refusals leave the emulator able to run */
	CK(kgenome_emu_map(e, 0, buf, 16, 0x1000, 7) == 0);
	CK(kgenome_emu_map(e, 0x20000000ull, NULL, 0, UINT64_MAX, 7) == 0);
	CK(kgenome_emu_map(e, UINT64_MAX - 0x1000u, NULL, 0, 0x4000, 7) == 0);
	CK(kgenome_emu_map(e, 0x30000000ull, NULL, 0, 0, 7) <= 1);
	CK(kgenome_emu_map(e, 0x31000000ull, buf, 16, 8, 7) <= 1);       /* n > memsz */
	CK(kgenome_emu_map(e, 0x32000000ull, buf, UINT64_MAX, 0x1000, 7) == 0);
	CK(kgenome_emu_map(e, 0x33000000ull, NULL, 16, 0x1000, 7) <= 1); /* NULL src, n > 0 */
	CK(kgenome_emu_run(e) != KGENOME_EMU_STOP_QUIET);
	kgenome_emu_free(e);
	return hk_fails != 0;
}

/* a reservation loop of ONE-page maps: the table of mappings is bounded by KGENOME_EMU_MAX_VMA
 * and the pages by cfg.max_pages, and a refusal is the answer past either */
static int fam_misuse_map_flood(void *arg)
{
	struct kgenome_emu_cfg c = { 1000, 8192, 0, 0 };
	struct kgenome_emu *e = kgenome_emu_new(&c);
	unsigned i, ok = 0;

	(void)arg;
	for (i = 0; i < 20000; i++)
		ok += (unsigned)(kgenome_emu_map(e, 0x10000000ull + 0x2000ull * i, NULL, 0, 0x1000, 7) == 1);
	CK(ok >= 1);
	CK(ok <= 8192u);
	{
		uint8_t b = 1;
		/* and what was mapped still works */
		CK(kgenome_emu_write(e, 0x10000000ull, &b, 1) == 1);
	}
	kgenome_emu_free(e);
	return hk_fails != 0;
}

/* ---- 6: NULL handles and NULL parameters, one forked child each --------------------------------------------- */

#define NT(name, expr) static int name(void *a) { \
	struct kgenome_emu *e = plain(); \
	uint64_t u64[4] = { 0 }; uint32_t u32[4] = { 0 }; uint8_t b[64] = { 0 }; \
	const char *cp = NULL; const uint64_t *gp = NULL; \
	(void)a; (void)e; (void)u64; (void)u32; (void)b; (void)cp; (void)gp; \
	(void)(expr); return 0; }

NT(h_set_self,   kgenome_emu_set_self(NULL, NULL, 0))
NT(h_seg_base,   kgenome_emu_set_seg_base(NULL, 4, 0))
NT(h_win_module, kgenome_emu_win_set_module(NULL, 0, 0))
NT(h_win_heap,   kgenome_emu_win_set_heap(NULL, 0))
NT(h_count_mod,  kgenome_emu_count_mod_reads(NULL, 1))
NT(h_mod_reads,  kgenome_emu_mod_reads(NULL, 0))
NT(h_first_hop,  kgenome_emu_first_hop(NULL, u64, u64 + 1))
NT(h_last_hop,   kgenome_emu_last_hop(NULL, u64, u32))
NT(h_win_setup,  kgenome_emu_win_setup(NULL, 0x400000))
NT(h_last_calls, kgenome_emu_last_calls(NULL, u64))
NT(h_set_rip,    kgenome_emu_set_rip(NULL, 0))
NT(h_set_reg,    kgenome_emu_set_reg(NULL, 0, 0))
NT(h_get_reg,    kgenome_emu_get_reg(NULL, 0))
NT(h_rip,        kgenome_emu_rip(NULL))
NT(h_run,        kgenome_emu_run(NULL))
NT(h_last_write, kgenome_emu_last_write(NULL))
NT(h_icache,     kgenome_emu_set_icache(NULL, 1))
NT(h_snap_w,     kgenome_emu_snap_written(NULL))
NT(h_insn_count, kgenome_emu_insn_count(NULL))
NT(h_exc_counts, kgenome_emu_exc_counts(NULL, u32, u32 + 1, u32 + 2))
NT(h_exc_scratch, kgenome_emu_exc_scratch(NULL, u64))
NT(h_trace,      kgenome_emu_trace(NULL, u64, 4))
NT(h_write,      kgenome_emu_write(NULL, 0x1000, b, 4))
NT(h_watch,      kgenome_emu_watch(NULL, 0x1000))
NT(h_watch_hits, kgenome_emu_watch_hits(NULL, u64, u64 + 1, 1))
NT(h_unknown,    kgenome_emu_unknown_syscalls(NULL, u32, 1))
NT(h_sysl,       kgenome_emu_syscall_log(NULL, (struct kgenome_emu_syscall *)b, 0))
NT(h_next_snap,  kgenome_emu_next_snapshot(NULL, u32, u64, (const uint8_t **)&cp, u64 + 1))
NT(h_next_wr,    kgenome_emu_next_written(NULL, u32, u64, (const uint8_t **)&cp, u64 + 1))

NT(p_win_addr,   kgenome_emu_win_addr_of(e, NULL))
NT(p_win_res,    kgenome_emu_win_resolve(e, NULL))
NT(p_write_src,  kgenome_emu_write(e, DATA_VA, NULL, 3))
NT(p_last_calls, kgenome_emu_last_calls(e, NULL))
NT(p_next_snap,  kgenome_emu_next_snapshot(e, NULL, u64, (const uint8_t **)&cp, u64 + 1))
NT(p_next_wr,    kgenome_emu_next_written(e, NULL, u64, (const uint8_t **)&cp, u64 + 1))

/* the calls that DO guard a NULL handle keep answering "nothing" */
NT(g_free,       kgenome_emu_free(NULL))
NT(g_fork,       kgenome_emu_fork(NULL))
NT(g_map,        kgenome_emu_map(NULL, 0x1000, NULL, 0, 0x1000, 6))
NT(g_itrace,     kgenome_emu_itrace(NULL, 5))
NT(g_itget,      kgenome_emu_itrace_get(NULL, 0, u64, &cp, &gp))
NT(g_event_cnt,  kgenome_emu_win_event_count(NULL))
NT(g_event_at,   kgenome_emu_win_event_at(NULL, 0, (struct kgenome_emu_win_event *)b))
NT(g_read,       kgenome_emu_read(NULL, 0x1000, b, 4))
NT(g_step,       kgenome_emu_step(NULL))
NT(g_shim,       kgenome_emu_shim_api(NULL, "x", 1))
NT(g_hop,        kgenome_emu_hop_add(NULL, 0, 1, 0))
NT(g_deadline,   kgenome_emu_set_deadline(NULL, 1))

struct nulltest { const char *name; hk_case_fn fn; };

#define NTE(x) { #x + 2, x }

static const struct nulltest handle_null[] = {
	NTE(h_set_self), NTE(h_seg_base), NTE(h_win_module), NTE(h_win_heap), NTE(h_count_mod),
	NTE(h_mod_reads), NTE(h_first_hop), NTE(h_last_hop), NTE(h_win_setup), NTE(h_last_calls),
	NTE(h_set_rip), NTE(h_set_reg), NTE(h_get_reg), NTE(h_rip), NTE(h_run), NTE(h_last_write),
	NTE(h_icache), NTE(h_snap_w), NTE(h_insn_count), NTE(h_exc_counts), NTE(h_exc_scratch),
	NTE(h_trace), NTE(h_write), NTE(h_watch), NTE(h_watch_hits), NTE(h_unknown), NTE(h_sysl),
	NTE(h_next_snap), NTE(h_next_wr)
};
static const struct nulltest param_null[] = {
	NTE(p_win_addr), NTE(p_win_res), NTE(p_write_src), NTE(p_last_calls), NTE(p_next_snap),
	NTE(p_next_wr)
};
static const struct nulltest guarded[] = {
	NTE(g_free), NTE(g_fork), NTE(g_map), NTE(g_itrace), NTE(g_itget), NTE(g_event_cnt),
	NTE(g_event_at), NTE(g_read), NTE(g_step), NTE(g_shim), NTE(g_hop), NTE(g_deadline)
};

static unsigned null_sweep(const struct nulltest *t, unsigned n, char *names, size_t cap)
{
	unsigned i, bad_n = 0;
	size_t at = 0;

	for (i = 0; i < n; i++) {
		int sig = 0;
		enum hk_result r = hk_isolated(t[i].fn, NULL, 5, &sig);

		if (r != HK_OK) {
			bad_n++;
			at += (size_t)snprintf(names + at, cap - at < at ? 0 : cap - at, "%s%s", at ? " " : "", t[i].name);
		}
	}
	return bad_n;
}

static void known_null_cases(void)
{
	char names[2048];
	unsigned n;

	/* the calls that guard a NULL handle today must keep guarding it */
	n = null_sweep(guarded, sizeof guarded / sizeof guarded[0], names, sizeof names);
	if (n) {
		printf("  FAIL a NULL-guarded emulator call crashed: %s\n", names);
		hk_fails++;
	}
	n = null_sweep(handle_null, sizeof handle_null / sizeof handle_null[0], names, sizeof names);
	if (n)
		printf("  (crash on a NULL emulator handle: %s)\n", names);
	KM_CHECK(n == 0, "29 public emulator calls dereference a NULL handle while 34 sibling calls guard it",
		 "emu_api.c and friends: no `if (!e)` in set_self set_seg_base win_set_module win_set_heap "
		 "count_mod_reads mod_reads first_hop last_hop win_setup last_calls set_rip set_reg get_reg rip "
		 "run last_write set_icache snap_written insn_count exc_counts exc_scratch trace write watch "
		 "watch_hits unknown_syscalls syscall_log next_snapshot next_written; kgenome_emu_new returns "
		 "NULL on OOM (emu_api.c:25), so an unchecked result crashes in the first of them. "
		 "Repro: kgenome_emu_run(NULL)");
	n = null_sweep(param_null, sizeof param_null / sizeof param_null[0], names, sizeof names);
	if (n)
		printf("  (crash on a NULL parameter: %s)\n", names);
	KM_CHECK(n == 0, "6 public emulator calls dereference a NULL in/out parameter their siblings accept",
		 "kgenome_emu_win_addr_of / win_resolve (name NULL -> strcmp, emu_win.c:415), "
		 "kgenome_emu_write (src NULL, n > 0), kgenome_emu_last_calls (out NULL), "
		 "kgenome_emu_next_snapshot / next_written (it NULL); kgenome_emu_read(dst NULL) and "
		 "kgenome_emu_itrace_get(NULL outs) are guarded. Repro: kgenome_emu_last_calls(e, NULL)");
}

/* ---- the driver ---------------------------------------------------------------------------------------- */

struct fam { const char *name; hk_case_fn fn; void *arg; unsigned secs; };

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	static struct rnd_arg r64a = { 1000, 10000, 64 }, r64b = { 90000000, 10000, 64 },
			      r32a = { 50000000, 10000, 32 };
	static struct win_arg w64 = { 64, 0 }, w32 = { 32, 0 };
	static struct fam fams[] = {
		{ "hostile programs", fam_programs, NULL, 60 },
		{ "random code, 64-bit, seeds 1000+", fam_random_code, &r64a, 120 },
		{ "random code, 64-bit, seeds 900000+", fam_random_code, &r64b, 120 },
		{ "random code, 32-bit, seeds 500000+", fam_random_code, &r32a, 120 },
		{ "syscalls, every number, hostile args", fam_syscalls, NULL, 120 },
		{ "windows API, 64-bit", fam_windows, &w64, 120 },
		{ "windows API, 32-bit", fam_windows, &w32, 120 },
		{ "hostile values to every setter", fam_misuse_values, NULL, 60 },
		{ "mapping flood", fam_misuse_map_flood, NULL, 60 },
	};
	unsigned i;

	shared_seed = (volatile uint64_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
						MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared_seed == (volatile uint64_t *)MAP_FAILED)
		shared_seed = NULL;
	for (i = 0; i < sizeof fams / sizeof fams[0]; i++) {
		int sig = 0;
		double t0 = hk_now();
		enum hk_result r;

		if (shared_seed)
			*shared_seed = 0;
		r = hk_isolated(fams[i].fn, fams[i].arg, fams[i].secs, &sig);
		printf("  %-40s %s (%.2fs)\n", fams[i].name,
		       r == HK_OK ? "ok" : r == HK_FAILED ? "FAILED" :
		       r == HK_HUNG ? "HUNG" : "CRASHED", hk_now() - t0);
		if (r != HK_OK) {
			printf("  FAIL %s: result %d signal %d (last seed/case %#llx)\n", fams[i].name,
			       (int)r, sig, shared_seed ? (unsigned long long)*shared_seed : 0ull);
			hk_fails++;
		}
	}
	if (!hk_ubsan()) {
		int sig = 0;
		KM_CHECK(hk_isolated(km_imul64, NULL, 10, &sig) == HK_OK,
			 "the interpreter's one-operand 64-bit IMUL leaves RDX as the sign of the product, not its high half",
			 "emu_interp.c:2008-2009 `(uint64_t)((x < 0) != (y < 0) ? -1 : 0)` for sz == 8 (and :2003 `x * y` is a "
			 "signed overflow). Repro: rax = 2^62, rbx = 4, `imul rbx` -> rdx:rax = 0:0, the CPU's is 1:0; "
			 "rax = rbx = 2^40 -> rdx 0, the CPU's is 0x10000. MUL and the 32-bit IMUL are right");
	}
	known_null_cases();
	printf("hostile_emu: %d failure(s)\n", hk_fails);
	return hk_fails != 0 || km_failed();
}
