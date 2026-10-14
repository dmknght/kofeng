/*
 * cov_emu_int - the interpreter's integer instructions that are not plain ALU, against the host CPU.
 *
 * Shifts and rotates (RCL/RCR/SHLD/SHRD with the counts the hardware masks), MUL/IMUL, DIV/IDIV,
 * the bit tests (BT/BTS/BTR/BTC), BSF/BSR/TZCNT/LZCNT/POPCNT, CMPXCHG/XADD and the string
 * instructions (REP/REPE/REPNE, both directions). Each is run on the host and in the interpreter
 * (cov_native.h) with random and edge inputs and the registers, the flags the architecture
 * DEFINES and the memory written are compared. What the manual calls undefined is masked beside
 * the instruction.
 *
 * Every defect an earlier version of this file pinned as a KM_CHECK is fixed (shift count zero and
 * the 32 bit zero-extension, OF after a shift by one, IMUL's CF/OF, the byte divide, BT with a
 * memory operand and a register offset, TZCNT/LZCNT flags, the 64 bit carry, CMOVcc, DAA/DAS flags)
 * and is a hard check here. Where it refuses an instruction on purpose
 * (a quotient that does not fit, a zero divisor) the fault is asserted: the registers are untouched and the stop is
 * reported, never a wrong quotient.
 *
 * The last group needs no host: the BCD adjusts exist only in 32 bit mode, so they are checked
 * against the algorithm of the manual, and the clock, CPUID, XGETBV and MXCSR instructions
 * against what the interpreter documents it answers.
 *
 * Skipped, visibly, where the host is not an x86-64 Linux machine.
 */

#include "cov_native.h"

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

/* ---- a tiny encoder: [mandatory] [66] [REX.W] [0F] opcode modrm [imm] ---------------------- */

struct ib {
	uint8_t  b[16];
	unsigned n;
};

static void build(struct ib *x, unsigned size, unsigned mand, unsigned opc, unsigned modrm,
		  unsigned immn, uint32_t imm)
{
	unsigned i;

	x->n = 0;
	if (mand)
		x->b[x->n++] = (uint8_t)mand;
	if (size == 2)
		x->b[x->n++] = 0x66;
	if (size == 8)
		x->b[x->n++] = 0x48;
	if (opc > 0xffu)
		x->b[x->n++] = (uint8_t)(opc >> 8);
	x->b[x->n++] = (uint8_t)opc;
	x->b[x->n++] = (uint8_t)modrm;
	for (i = 0; i < immn; i++)
		x->b[x->n++] = (uint8_t)(imm >> (8 * i));
}

static const unsigned SZ[4] = { 1, 2, 4, 8 };

static uint64_t szmask(unsigned size)
{
	return size >= 8 ? ~0ull : ((1ull << (size * 8u)) - 1ull);
}

/* Three tallies: `st` for what must equal the CPU, `kz` and `ko` for the shapes with a known defect
 * (each reported with its own check so a failure names the shape). */
static struct cn_stat st, kz, ko;

/* What each known defect cost over the whole run: the shapes tried and how many differed. One check
 * per defect at the end (km_report), so the summary names each defect once. */
struct agg { unsigned cases, diffs; };
static struct agg a_zext, a_of, a_imul, a_div8, a_bt, a_tzcnt, a_lzcnt, a_carry, a_cmov;

static void acc(struct agg *a, const struct cn_stat *t)
{
	a->cases += t->cases;
	a->diffs += t->diffs;
}

/* an operand of `size` bytes in RAX with garbage above it, so a write that must zero-extend (or must
 * leave the upper bytes alone) is visible */
static uint64_t junk(unsigned size)
{
	uint64_t m = szmask(size);

	return (cn_edge(size) & m) | (cn_rng() & ~m);
}

static void begin(void)
{
	memset(&st, 0, sizeof st);
	memset(&kz, 0, sizeof kz);
	memset(&ko, 0, sizeof ko);
}

static void goto_(struct cn_stat *t, const char *name, const struct ib *x, const struct cn_io *in,
		  uint64_t mask, int buf)
{
	(void)cn_case(t, name, x->b, x->n, in, mask, 64, 0, buf);
}

static void go(const char *name, const struct ib *x, const struct cn_io *in, uint64_t mask, int buf)
{
	goto_(&st, name, x, in, mask, buf);
}

/* ---- shifts and rotates ----------------------------------------------------------------- */

/* the flags a shift/rotate defines, from the masked count (see the header of the file) */
static uint64_t shift_mask(unsigned ext, unsigned size, unsigned count)
{
	unsigned w = size * 8u;
	unsigned cnt = count & (size == 8 ? 63u : 31u);
	uint64_t m;

	if (!cnt)
		return CN_FL_ARITH;                       /* a zero count changes no flag */
	if (ext == 0 || ext == 1) {                       /* ROL ROR: CF, and OF for a count of one */
		m = CN_FL_CF | CN_FL_SF | CN_FL_ZF | CN_FL_PF | CN_FL_AF;
		return cnt == 1 ? m | CN_FL_OF : m;
	}
	if (ext == 2 || ext == 3) {                       /* RCL RCR */
		m = CN_FL_CF | CN_FL_SF | CN_FL_ZF | CN_FL_PF | CN_FL_AF;
		return cnt == 1 ? m | CN_FL_OF : m;
	}
	m = CN_FL_SF | CN_FL_ZF | CN_FL_PF;               /* SHL SHR SAR */
	if (cnt <= w)
		m |= CN_FL_CF;
	if (cnt == 1)
		m |= CN_FL_OF;
	return m;
}

static void t_shifts(void)
{
	static const struct { unsigned ext; const char *nm; } op[] = {
		{ 0, "rol" }, { 1, "ror" }, { 2, "rcl" }, { 3, "rcr" },
		{ 4, "shl" }, { 5, "shr" }, { 7, "sar" }
	};
	unsigned o, z, i;

	for (o = 0; o < 7; o++) {
		begin();
		for (z = 0; z < 4; z++)
			for (i = 0; i < 90; i++) {
				struct cn_io in;
				struct ib x;
				unsigned size = SZ[z];
				unsigned cnt = (unsigned)(cn_rng() % 72u);
				char nm[40];

				cn_input(&in, 0);
				cn_put(&in, CN_O_RAX, junk(size));
				if (i & 1) {
					/* shift by cl */
					cn_put(&in, CN_O_RCX, cnt);
					build(&x, size, 0, size == 1 ? 0xd2u : 0xd3u, 0xc0u | (op[o].ext << 3), 0, 0);
				} else {
					cnt &= 63u;
					build(&x, size, 0, size == 1 ? 0xc0u : 0xc1u, 0xc0u | (op[o].ext << 3), 1, cnt);
				}
				snprintf(nm, sizeof nm, "%s/%u", op[o].nm, size * 8u);
				{
					unsigned mc = cnt & (size == 8 ? 63u : 31u);
					uint64_t fm = shift_mask(op[o].ext, size, cnt);
					int plain = op[o].ext >= 4;   /* SHL SHR SAR */

					if (size == 4 && mc == 0) {
						goto_(&kz, nm, &x, &in, fm, 0);        /* the 32 bit destination is zero-extended */
					} else if (plain && mc == 1 && op[o].ext != 7) {
						goto_(&st, nm, &x, &in, fm & ~CN_FL_OF, 0);
						goto_(&ko, nm, &x, &in, CN_FL_OF, 0);
					} else {
						go(nm, &x, &in, fm, 0);
					}
				}
			}
		cn_print(op[o].nm, &st);
		CK(st.native_ok == st.cases, "the host ran %s", op[o].nm);
		CK(st.unsupported == 0, "%s: the interpreter carries it", op[o].nm);
		CK(st.diffs == 0, "%s: registers and defined flags equal the CPU's (%u differ)", op[o].nm, st.diffs);
		CK(kz.cases > 0, "%s: the count-masks-to-zero shape was generated", op[o].nm);
		acc(&a_zext, &kz);
		if (op[o].ext == 4 || op[o].ext == 5) {
			CK(ko.cases > 0, "%s: the count-of-one shape was generated", op[o].nm);
			acc(&a_of, &ko);
		}
	}
}

static void t_dshift(void)
{
	static const char *nm[2] = { "shld", "shrd" };
	unsigned d, z, i;

	for (d = 0; d < 2; d++) {
		begin();
		for (z = 1; z < 4; z++)
			for (i = 0; i < 120; i++) {
				struct cn_io in;
				struct ib x;
				unsigned size = SZ[z];
				unsigned maxc = size * 8u - 1u;
				unsigned cnt = (unsigned)(cn_rng() % (maxc + 1u));
				uint64_t mk;

				cn_input(&in, 0);
				cn_put(&in, CN_O_RAX, junk(size));
				cn_put(&in, CN_O_RDX, cn_edge(size));
				mk = cnt ? (CN_FL_CF | CN_FL_SF | CN_FL_ZF | CN_FL_PF) | (cnt == 1 ? CN_FL_OF : 0)
					 : CN_FL_ARITH;
				if (i & 1) {
					cn_put(&in, CN_O_RCX, cnt);
					/* shld rax, rdx, cl */
					build(&x, size, 0, d ? 0x0fadu : 0x0fa5u, 0xd0, 0, 0);
				} else {
					build(&x, size, 0, d ? 0x0facu : 0x0fa4u, 0xd0, 1, cnt);
				}
				if (size == 4 && cnt == 0)
					goto_(&kz, nm[d], &x, &in, mk, 0);
				else
					go(nm[d], &x, &in, mk, 0);
			}
		cn_print(nm[d], &st);
		CK(st.unsupported == 0, "%s is carried", nm[d]);
		CK(st.diffs == 0, "%s equals the CPU (%u differ)", nm[d], st.diffs);
		CK(kz.cases > 0, "%s: a zero count on 32 bits was generated", nm[d]);
		acc(&a_zext, &kz);
	}
}

/* ---- multiply and divide ---------------------------------------------------------------- */

static void t_mul(void)
{
	unsigned z, i, which;
	static const char *nm[3] = { "mul", "imul1", "imul2/3" };

	for (which = 0; which < 3; which++) {
		begin();
		for (z = 0; z < 4; z++)
			for (i = 0; i < 100; i++) {
				struct cn_io in;
				struct ib x;
				unsigned size = SZ[z];

				cn_input(&in, 0);
				cn_put(&in, CN_O_RAX, junk(size));
				cn_put(&in, CN_O_RCX, cn_edge(size));
				if (which == 0) {
					build(&x, size, 0, size == 1 ? 0xf6u : 0xf7u, 0xe1, 0, 0);   /* mul cl.. */
				} else if (which == 1) {
					build(&x, size, 0, size == 1 ? 0xf6u : 0xf7u, 0xe9, 0, 0);   /* imul */
				} else {
					if (size == 1)
						continue;
					if (i & 1)
						build(&x, size, 0, 0x0fafu, 0xc1, 0, 0);            /* imul rax, rcx */
					else if (i & 2)
						build(&x, size, 0, 0x69u, 0xc1, size == 2 ? 2 : 4, (uint32_t)cn_rng());
					else
						build(&x, size, 0, 0x6bu, 0xc1, 1, (uint32_t)cn_rng());
				}
				/* CF and OF are defined; SF ZF AF PF are not. IMUL's flags are checked apart from its result. */
				if (which == 0) {
					go(nm[which], &x, &in, CN_FL_CF | CN_FL_OF, 0);
				} else {
					go(nm[which], &x, &in, 0, 0);
					goto_(&ko, nm[which], &x, &in, CN_FL_CF | CN_FL_OF, 0);
				}
			}
		cn_print(nm[which], &st);
		CK(st.unsupported == 0, "%s is carried", nm[which]);
		CK(st.diffs == 0, "%s result equals the CPU (%u differ)", nm[which], st.diffs);
		if (which)
			acc(&a_imul, &ko);
	}
}

/* A divisor, a quotient and a remainder that fit, composed into the dividend the instruction reads. */
static int mk_div(unsigned size, int sgn, uint64_t *lo, uint64_t *hi, uint64_t *dv)
{
	unsigned bits = size * 8u;
	uint64_t m = szmask(size);

	if (!sgn) {
		uint64_t d = cn_edge(size) & m, q, r;
		unsigned __int128 n;

		if (!d)
			d = 1;
		q = cn_edge(size) & m;
		if (size == 8 && d > 1)
			q %= (UINT64_MAX / d);          /* keeps q*d+r inside 64 bits: the carried shape */
		r = cn_rng() % d;
		n = (unsigned __int128)q * d + r;
		if (size == 1) {
			*lo = (uint64_t)n & 0xffffu;
			*hi = 0;
		} else {
			*lo = (uint64_t)n & m;
			*hi = size == 8 ? 0 : (uint64_t)(n >> bits) & m;
		}
		*dv = d;
		return 1;
	} else {
		__int128 lim = (__int128)1 << (bits - 1), sd, sq, sr, n;
		uint64_t x = cn_edge(size) & m, y = cn_edge(size) & m;

		sd = (__int128)(int64_t)((x ^ (uint64_t)lim) - (uint64_t)lim);
		if (size == 8)
			sd = (__int128)(int64_t)x;
		if (sd == 0)
			sd = 1;
		sq = (__int128)(int64_t)((y ^ (uint64_t)lim) - (uint64_t)lim);
		if (size == 8)
			sq = (__int128)(int64_t)y;
		if (size == 8) {
			/* the carried shape: hi = 0 and a non-negative dividend */
			if (sd < 0)
				sd = -sd;
			if (sd == 0 || sd > INT64_MAX)
				sd = 1;
			if (sq < 0)
				sq = -(sq + 1);
			sq %= (__int128)(INT64_MAX / (int64_t)sd);
			sr = (__int128)(cn_rng() % (uint64_t)sd);
		} else {
			__int128 ad = sd < 0 ? -sd : sd;

			sr = (__int128)(cn_rng() % (uint64_t)ad);
			if ((sq < 0) != (sd < 0) && sq != 0)
				sr = -sr;
			if (sq == 0)
				sr = sr < 0 ? -sr : sr;
		}
		n = sq * sd + sr;
		if (size == 8 && n < 0)
			return 0;
		if (size == 1) {
			*lo = (uint64_t)n & 0xffffu;
			*hi = 0;
		} else {
			*lo = (uint64_t)n & m;
			*hi = size == 8 ? 0 : (uint64_t)(n >> bits) & m;
		}
		*dv = (uint64_t)sd & m;
		return 1;
	}
}

static void t_div(void)
{
	unsigned z, i, sgn;

	for (sgn = 0; sgn < 2; sgn++) {
		begin();
		for (z = 0; z < 4; z++)
			for (i = 0; i < 120; i++) {
				struct cn_io in;
				struct ib x;
				unsigned size = SZ[z];
				uint64_t lo, hi, d;

				cn_input(&in, 0);
				if (!mk_div(size, (int)sgn, &lo, &hi, &d))
					continue;
				cn_put(&in, CN_O_RAX, lo);
				cn_put(&in, CN_O_RDX, hi);
				cn_put(&in, CN_O_RCX, d);
				build(&x, size, 0, size == 1 ? 0xf6u : 0xf7u, sgn ? 0xf9u : 0xf1u, 0, 0);
				if (size == 1)
					goto_(&kz, sgn ? "idiv/8" : "div/8", &x, &in, 0, 0);
				else
					go(sgn ? "idiv" : "div", &x, &in, 0, 0);
			}
		cn_print(sgn ? "idiv" : "div", &st);
		CK(st.cases > 200, "division: %u case(s) were generated", st.cases);
		CK(st.unsupported == 0, "division is carried for the shapes that fit (%u refused)", st.unsupported);
		CK(st.diffs == 0, "quotient and remainder equal the CPU's (%u differ)", st.diffs);
		CK(kz.cases > 50, "8 bit division: %u case(s) were generated", kz.cases);
		acc(&a_div8, &kz);
	}
}

/*
 * THE DIVIDES THAT FAULT, AND THE 128 BIT DIVIDEND. A zero divisor and a quotient that does not fit are #DE:
 * the host raises SIGFPE for them (cov_native.h catches it) and the interpreter must end the run with a FAULT
 * stop that names the divide - not UNSUPPORTED, which says "an instruction this build lacks". A dividend with
 * RDX != 0 is not a refusal either: it is the 128 by 64 divide, compared with the CPU's. Every operand is an
 * edge value (0, 1, all ones, the sign bit, a single bit) so the two outcomes are both common; the sweep is
 * the host's answer for each, and a case where the host did not trap compares the registers as usual.
 */
static void t_div_faults(void)
{
	struct cn_io in;
	struct cn_stat f;
	struct ib x;
	unsigned z, i, sgn, trapped = 0, ran = 0;

	memset(&f, 0, sizeof f);
	for (sgn = 0; sgn < 2; sgn++)
		for (z = 0; z < 4; z++)
			for (i = 0; i < 600; i++) {
				unsigned size = SZ[z];

				cn_input(&in, 0);
				cn_put(&in, CN_O_RAX, cn_edge(size) & szmask(size));
				cn_put(&in, CN_O_RDX, size == 1 ? 0 : cn_edge(size) & szmask(size));
				cn_put(&in, CN_O_RCX, cn_edge(size) & szmask(size));
				build(&x, size, 0, size == 1 ? 0xf6u : 0xf7u, sgn ? 0xf9u : 0xf1u, 0, 0);
				if (size == 1)
					cn_put(&in, CN_O_RAX, cn_rng() & 0xffffu);
				(void)cn_case(&f, sgn ? "idiv" : "div", x.b, x.n, &in, 0, 64, 0, 0);
				trapped += (unsigned)cn_trapped;
				ran++;
			}
	cn_print("div/idiv incl. #DE", &f);
	CK(trapped > 200 && trapped < ran, "both outcomes were met (%u of %u cases trap)", trapped, ran);
	CK(f.unsupported == 0, "no divide is an unsupported instruction (%u)", f.unsupported);
	CK(f.diffs == 0, "quotient, remainder and #DE equal the CPU's (%u of %u differ)", f.diffs, f.cases);
}

/* The named cases: nothing is written when the divide faults, and the stop says which fault it was. */
static void t_div_named(void)
{
	struct cn_io in, out;
	struct ib x;
	struct cn_emu r;

	cn_input(&in, 0);
	cn_put(&in, CN_O_RAX, 100);
	cn_put(&in, CN_O_RDX, 0);
	cn_put(&in, CN_O_RCX, 0);
	build(&x, 8, 0, 0xf7u, 0xf1u, 0, 0);
	CK(cn_emulate(x.b, x.n, &in, &out, 64, &r), "emulator available");
	CK(!r.done && r.stop == KGENOME_EMU_STOP_FAULT && !strncmp(r.detail, "divzero", 7),
	   "div by zero: a fault, not an unsupported instruction (%s: %s)", kgenome_emu_stop_name(r.stop), r.detail);
	CK(cn_get(&out, 48) == 0, "div by zero: the output block is not written (rax out = %#llx)",
	   (unsigned long long)cn_get(&out, 48));
	/* RDX:RAX = 2^64 + 100 divided by 3 fits: 6148914691236517238 (0x5555555555555576) remainder 2 */
	cn_put(&in, CN_O_RDX, 1);
	cn_put(&in, CN_O_RCX, 3);
	CK(cn_emulate(x.b, x.n, &in, &out, 64, &r) && r.done, "a 128 bit dividend runs (%s)", r.detail);
	CK(cn_get(&out, 48) == 0x5555555555555576ull && cn_get(&out, 64) == 2u,
	   "128/64 divide: quotient %#llx remainder %llu", (unsigned long long)cn_get(&out, 48),
	   (unsigned long long)cn_get(&out, 64));
	/* the quotient does not fit: RDX >= the divisor */
	cn_put(&in, CN_O_RDX, 3);
	CK(cn_emulate(x.b, x.n, &in, &out, 64, &r), "emulator available");
	CK(!r.done && r.stop == KGENOME_EMU_STOP_FAULT && !strncmp(r.detail, "divovf", 6),
	   "quotient overflow: a fault that says so (%s: %s)", kgenome_emu_stop_name(r.stop), r.detail);
	/* signed: RDX:RAX = -100 divided by 3 = -33 remainder -1 */
	cn_put(&in, CN_O_RDX, ~0ull);
	cn_put(&in, CN_O_RAX, (uint64_t)-100);
	build(&x, 8, 0, 0xf7u, 0xf9u, 0, 0);
	CK(cn_emulate(x.b, x.n, &in, &out, 64, &r) && r.done, "a negative 64 bit idiv runs (%s)", r.detail);
	CK(cn_get(&out, 48) == (uint64_t)-33 && cn_get(&out, 64) == (uint64_t)-1, "idiv -100 / 3 = %lld r %lld",
	   (long long)cn_get(&out, 48), (long long)cn_get(&out, 64));
	/* INT64_MIN / -1 */
	cn_put(&in, CN_O_RAX, 0x8000000000000000ull);
	cn_put(&in, CN_O_RCX, ~0ull);
	CK(cn_emulate(x.b, x.n, &in, &out, 64, &r), "emulator available");
	CK(!r.done && r.stop == KGENOME_EMU_STOP_FAULT && !strncmp(r.detail, "divovf", 6),
	   "INT64_MIN / -1 overflows (%s: %s)", kgenome_emu_stop_name(r.stop), r.detail);
}

/* ---- bit tests and scans ----------------------------------------------------------------- */

static void t_bt(void)
{
	static const struct { unsigned reg, ext; const char *nm; } op[] = {
		{ 0x0fa3, 4, "bt" }, { 0x0fab, 5, "bts" }, { 0x0fb3, 6, "btr" }, { 0x0fbb, 7, "btc" }
	};
	unsigned o, z, i, form;

	for (form = 0; form < 4; form++) {
		for (o = 0; o < 4; o++) {
			begin();
			for (z = 1; z < 4; z++)
				for (i = 0; i < 60; i++) {
					struct cn_io in;
					struct ib x;
					unsigned size = SZ[z];
					char nm[48];

					cn_input(&in, 0);
					cn_fill_buf(&in, 0);
					cn_put(&in, CN_O_RAX, cn_edge(size));
					cn_put(&in, CN_O_RCX, cn_rng() % 64u);
					if (form == 0)         /* bt rax, rcx */
						build(&x, size, 0, op[o].reg, 0xc8, 0, 0);
					else if (form == 1)    /* bt rax, imm8 */
						build(&x, size, 0, 0x0fbau, 0xc0u | (op[o].ext << 3), 1, (uint32_t)(cn_rng() & 0xffu));
					else if (form == 2) {  /* bt [rsi], imm8 */
						cn_put(&in, CN_O_RSI, CN_O_BUF + 64u);
						build(&x, size, 0, 0x0fbau, 0x06u | (op[o].ext << 3), 1, (uint32_t)(cn_rng() & 0xffu));
					} else {               /* bt [rsi], rcx: the bit string form, offset past the operand */
						cn_put(&in, CN_O_RSI, CN_O_BUF + 512u);
						cn_put(&in, CN_O_RCX, cn_rng() % 1024u);
						build(&x, size, 0, op[o].reg, 0x0eu, 0, 0);
					}
					snprintf(nm, sizeof nm, "%s/%u form %u", op[o].nm, size * 8u, form);
					go(nm, &x, &in, CN_FL_CF, form >= 2);
				}
			cn_print(op[o].nm, &st);
			CK(st.unsupported == 0, "%s form %u is carried", op[o].nm, form);
			if (form == 3)
				acc(&a_bt, &st);
			else
				CK(st.diffs == 0, "%s form %u equals the CPU (%u differ)", op[o].nm, form, st.diffs);
		}
	}
}

static void t_scan(void)
{
	static const struct { unsigned pfx, opc; const char *nm; uint64_t mask; } op[] = {
		{ 0,    0x0fbc, "bsf",    CN_FL_ZF },
		{ 0,    0x0fbd, "bsr",    CN_FL_ZF },
		{ 0xf3, 0x0fbc, "tzcnt",  CN_FL_ZF | CN_FL_CF },
		{ 0xf3, 0x0fbd, "lzcnt",  CN_FL_ZF | CN_FL_CF },
		{ 0xf3, 0x0fb8, "popcnt", CN_FL_ARITH }
	};
	unsigned o, z, i;

	for (o = 0; o < 5; o++) {
		begin();
		for (z = 1; z < 4; z++)
			for (i = 0; i < 100; i++) {
				struct cn_io in;
				struct ib x;
				unsigned size = SZ[z];
				uint64_t src = cn_edge(size) & szmask(size);
				char nm[48];

				/* BSF/BSR leave the destination alone for a zero source on some CPUs and not on
				 * others (the manual calls it undefined): a zero source is checked apart below */
				if (!src && o < 2)
					src = 1;
				cn_input(&in, 0);
				cn_put(&in, CN_O_RAX, cn_rng());
				cn_put(&in, CN_O_RCX, src);
				if (i & 1) {
					cn_put(&in, CN_O_RSI, CN_O_BUF);
					memcpy(in.raw + CN_O_BUF, &src, 8);
					build(&x, size, op[o].pfx, op[o].opc, 0x06, 0, 0);
				} else {
					build(&x, size, op[o].pfx, op[o].opc, 0xc1, 0, 0);
				}
				snprintf(nm, sizeof nm, "%s/%u", op[o].nm, size * 8u);
				go(nm, &x, &in, op[o].mask, 0);
			}
		cn_print(op[o].nm, &st);
		CK(st.unsupported == 0, "%s is carried", op[o].nm);
		if (o == 2 || o == 3)
			acc(o == 2 ? &a_tzcnt : &a_lzcnt, &st);
		else
			CK(st.diffs == 0, "%s equals the CPU (%u differ)", op[o].nm, st.diffs);
	}
	/* a zero source: ZF is set, and the destination of a 64 and of a 16 bit BSF/BSR is not touched */
	for (o = 0; o < 2; o++) {
		unsigned z2;

		for (z2 = 1; z2 < 4; z2 += 2) {
			struct cn_io in, out;
			struct ib x;
			struct cn_emu r;
			unsigned size = SZ[z2 == 1 ? 1 : 3];

			cn_input(&in, 0);
			cn_put(&in, CN_O_RAX, 0x1122334455667788ull);
			cn_put(&in, CN_O_RCX, 0);
			build(&x, size, op[o].pfx, op[o].opc, 0xc1, 0, 0);
			CK(cn_emulate(x.b, x.n, &in, &out, 64, &r) && r.done, "%s of zero runs", op[o].nm);
			CK(cn_get(&out, 88) & CN_FL_ZF, "%s of zero sets ZF", op[o].nm);
			CK(cn_get(&out, 48) == 0x1122334455667788ull, "%s/%u of zero leaves the destination (%#llx)",
			   op[o].nm, size * 8u, (unsigned long long)cn_get(&out, 48));
		}
	}
}

/* ---- compare-exchange, exchange-add ------------------------------------------------------- */

static void t_atomic(void)
{
	unsigned which, z, i, mem;

	for (which = 0; which < 2; which++)
		for (mem = 0; mem < 2; mem++) {
			begin();
			for (z = 0; z < 4; z++)
				for (i = 0; i < 90; i++) {
					struct cn_io in;
					struct ib x;
					unsigned size = SZ[z];
					unsigned opc = which == 0 ? (size == 1 ? 0x0fb0u : 0x0fb1u)
								  : (size == 1 ? 0x0fc0u : 0x0fc1u);
					uint64_t v = cn_edge(size);

					cn_input(&in, 0);
					cn_fill_buf(&in, 0);
					cn_put(&in, CN_O_RAX, (i & 1) ? v : cn_edge(size));   /* half the time equal */
					cn_put(&in, CN_O_RDX, v);
					cn_put(&in, CN_O_RCX, cn_edge(size));
					if (mem) {
						memcpy(in.raw + CN_O_BUF + 32, &v, 8);
						cn_put(&in, CN_O_RSI, CN_O_BUF + 32u);
						build(&x, size, 0, opc, 0x0e, 0, 0);       /* op [rsi], rcx */
					} else {
						build(&x, size, 0, opc, 0xca, 0, 0);       /* op rdx, rcx */
					}
					if (which && size == 8)
						goto_(&ko, "xadd/64", &x, &in, CN_FL_ARITH, (int)mem);
					else
						go(which ? "xadd" : "cmpxchg", &x, &in, CN_FL_ARITH, (int)mem);
				}
			cn_print(which ? (mem ? "xadd [m]" : "xadd") : (mem ? "cmpxchg [m]" : "cmpxchg"), &st);
			CK(st.unsupported == 0, "carried");
			CK(st.diffs == 0, "equals the CPU (%u differ)", st.diffs);
			if (which) {
				CK(ko.cases > 0, "xadd/64 generated");
				acc(&a_carry, &ko);
			}
		}
}

/* ---- string instructions ------------------------------------------------------------------ */

static void t_string(void)
{
	static const struct { unsigned opc8, opc; const char *nm; int cmp; } op[] = {
		{ 0xa4, 0xa5, "movs", 0 }, { 0xaa, 0xab, "stos", 0 }, { 0xac, 0xad, "lods", 0 },
		{ 0xae, 0xaf, "scas", 1 }, { 0xa6, 0xa7, "cmps", 1 }
	};
	static const unsigned pfx[3] = { 0, 0xf3, 0xf2 };
	unsigned o, p, z, i;

	for (o = 0; o < 5; o++) {
		begin();
		for (p = 0; p < 3; p++)
			for (z = 0; z < 4; z++)
				for (i = 0; i < 40; i++) {
					struct cn_io in;
					struct ib x;
					unsigned size = SZ[z];
					unsigned df = i & 1;
					unsigned cnt = (unsigned)(cn_rng() % 40u);
					unsigned span = 40u * size;     /* the room the pointers need either way */
					char nm[48];

					cn_input(&in, (int)df);
					cn_fill_buf(&in, 2);            /* two symbols: equal and unequal come up */
					cn_put(&in, CN_O_RAX, cn_rng() % 2u);
					cn_put(&in, CN_O_RCX, cnt);
					cn_put(&in, CN_O_RSI, CN_O_BUF + 400u + (df ? span : 0));
					cn_put(&in, CN_O_RDI, CN_O_BUF + 1200u + (df ? span : 0));
					x.n = 0;
					if (pfx[p])
						x.b[x.n++] = (uint8_t)pfx[p];
					if (size == 2)
						x.b[x.n++] = 0x66;
					if (size == 8)
						x.b[x.n++] = 0x48;
					x.b[x.n++] = (uint8_t)(size == 1 ? op[o].opc8 : op[o].opc);
					snprintf(nm, sizeof nm, "%s/%u pfx %02x df %u", op[o].nm, size * 8u, pfx[p], df);
					/* a plain MOVS/STOS/LODS changes no flag; SCAS/CMPS set all six */
					go(nm, &x, &in, CN_FL_ARITH, 1);
				}
		cn_print(op[o].nm, &st);
		CK(st.unsupported == 0, "%s is carried", op[o].nm);
		CK(st.diffs == 0, "%s: pointers, count, flags and memory equal the CPU's (%u differ)", op[o].nm, st.diffs);
	}
}

/* ---- the plain ALU and the single-byte family, for the flag helpers every other check leans on ---- */

static void t_alu(void)
{
	static const struct { unsigned opc; const char *nm; uint64_t mask; } two[] = {
		{ 0x01, "add", CN_FL_ARITH },  { 0x09, "or",  CN_FL_ARITH & ~CN_FL_AF },
		{ 0x11, "adc", CN_FL_ARITH },  { 0x19, "sbb", CN_FL_ARITH },
		{ 0x21, "and", CN_FL_ARITH & ~CN_FL_AF }, { 0x29, "sub", CN_FL_ARITH },
		{ 0x31, "xor", CN_FL_ARITH & ~CN_FL_AF }, { 0x39, "cmp", CN_FL_ARITH },
		{ 0x85, "test", CN_FL_ARITH & ~CN_FL_AF }
	};
	static const struct { unsigned opc, ext; const char *nm; uint64_t mask; } one[] = {
		{ 0xf7, 3, "neg", CN_FL_ARITH }, { 0xf7, 2, "not", CN_FL_ARITH },
		{ 0xff, 0, "inc", CN_FL_ARITH }, { 0xff, 1, "dec", CN_FL_ARITH }
	};
	unsigned o, z, i;

	for (o = 0; o < 9; o++) {
		begin();
		for (z = 0; z < 4; z++)
			for (i = 0; i < 80; i++) {
				struct cn_io in;
				struct ib x;
				unsigned size = SZ[z];
				uint64_t v = cn_edge(size);

				cn_input(&in, 0);
				cn_put(&in, CN_O_RAX, (v & szmask(size)) | (cn_rng() & ~szmask(size)));
				cn_put(&in, CN_O_RCX, (i & 3) == 0 ? v : cn_edge(size));
				build(&x, size, 0, size == 1 ? two[o].opc - 1u : two[o].opc, 0xc8, 0, 0);
				if (size == 8 && (o == 0 || o == 2))
					goto_(&ko, "add/64", &x, &in, two[o].mask, 0);
				else
					go(two[o].nm, &x, &in, two[o].mask, 0);
			}
		cn_print(two[o].nm, &st);
		CK(st.unsupported == 0, "%s is carried", two[o].nm);
		CK(st.diffs == 0, "%s equals the CPU (%u differ)", two[o].nm, st.diffs);
		if (o == 0 || o == 2)
			acc(&a_carry, &ko);
	}
	for (o = 0; o < 4; o++) {
		begin();
		for (z = 0; z < 4; z++)
			for (i = 0; i < 80; i++) {
				struct cn_io in;
				struct ib x;
				unsigned size = SZ[z];
				unsigned opc = one[o].opc == 0xf7 ? (size == 1 ? 0xf6u : 0xf7u) : (size == 1 ? 0xfeu : 0xffu);

				cn_input(&in, 0);
				cn_put(&in, CN_O_RAX, junk(size));
				build(&x, size, 0, opc, 0xc0u | (one[o].ext << 3), 0, 0);
				go(one[o].nm, &x, &in, one[o].mask, 0);
			}
		cn_print(one[o].nm, &st);
		CK(st.unsupported == 0, "%s is carried", one[o].nm);
		CK(st.diffs == 0, "%s equals the CPU (%u differ)", one[o].nm, st.diffs);
	}
}

static void t_misc(void)
{
	static const struct { uint8_t b[8]; unsigned n; const char *nm; } c[] = {
		{ { 0x48, 0x0f, 0xc8 }, 3, "bswap rax" }, { { 0x0f, 0xc8 }, 2, "bswap eax" },
		{ { 0x0f, 0xb6, 0xc1 }, 3, "movzx eax,cl" }, { { 0x0f, 0xb7, 0xc1 }, 3, "movzx eax,cx" },
		{ { 0x0f, 0xbe, 0xc1 }, 3, "movsx eax,cl" }, { { 0x0f, 0xbf, 0xc1 }, 3, "movsx eax,cx" },
		{ { 0x48, 0x0f, 0xb6, 0xc1 }, 4, "movzx rax,cl" }, { { 0x48, 0x0f, 0xb7, 0xc1 }, 4, "movzx rax,cx" },
		{ { 0x48, 0x0f, 0xbe, 0xc1 }, 4, "movsx rax,cl" }, { { 0x48, 0x0f, 0xbf, 0xc1 }, 4, "movsx rax,cx" },
		{ { 0x48, 0x63, 0xc1 }, 3, "movsxd rax,ecx" }, { { 0x66, 0x0f, 0xb6, 0xc1 }, 4, "movzx ax,cl" },
		{ { 0x66, 0x0f, 0xbe, 0xc1 }, 4, "movsx ax,cl" },
		{ { 0x98 }, 1, "cwde" }, { { 0x48, 0x98 }, 2, "cdqe" }, { { 0x66, 0x98 }, 2, "cbw" },
		{ { 0x99 }, 1, "cdq" }, { { 0x48, 0x99 }, 2, "cqo" }, { { 0x66, 0x99 }, 2, "cwd" },
		{ { 0x48, 0x91 }, 2, "xchg rax,rcx" }, { { 0x87, 0xca }, 2, "xchg edx,ecx" },
		{ { 0x86, 0xca }, 2, "xchg dl,cl" }, { { 0x66, 0x87, 0xca }, 3, "xchg dx,cx" },
		{ { 0x9f }, 1, "lahf" }, { { 0x9e }, 1, "sahf" },
		{ { 0xf5 }, 1, "cmc" }, { { 0xf9 }, 1, "stc" }, { { 0xf8 }, 1, "clc" },
		{ { 0x48, 0x8d, 0x44, 0x91, 0x10 }, 5, "lea rax,[rcx+rdx*4+16]" },
		{ { 0x8d, 0x04, 0x51 }, 3, "lea eax,[rcx+rdx*2]" },
		{ { 0x66, 0x8d, 0x44, 0x91, 0x10 }, 5, "lea ax,[rcx+rdx*4+16]" },
		{ { 0x0f, 0x44, 0xc1 }, 3, "cmove eax,ecx" }, { { 0x48, 0x0f, 0x4c, 0xc1 }, 4, "cmovl rax,rcx" },
		{ { 0x66, 0x0f, 0x47, 0xc1 }, 4, "cmova ax,cx" }, { { 0x0f, 0x48, 0xc1 }, 3, "cmovs eax,ecx" },
		{ { 0x0f, 0x92, 0xc0 }, 3, "setb al" }, { { 0x0f, 0x9f, 0xc0 }, 3, "setg al" },
		{ { 0x0f, 0x9a, 0xc0 }, 3, "setp al" }, { { 0x0f, 0x90, 0xc0 }, 3, "seto al" },
		{ { 0x48, 0x0f, 0xaf, 0xc2 }, 4, "imul rax,rdx" },
		{ { 0x48, 0xf7, 0xe2 }, 3, "mul rdx" },
		{ { 0x48, 0x0f, 0xa3, 0xc8 }, 4, "bt rax,rcx" }
	};
	unsigned o, i;

	begin();
	for (o = 0; o < sizeof c / sizeof c[0]; o++) {
		for (i = 0; i < 60; i++) {
			struct cn_io in;
			uint64_t mask = CN_FL_ARITH;
			uint8_t code[8];

			cn_input(&in, 0);
			cn_put(&in, CN_O_RAX, cn_edge(8));
			cn_put(&in, CN_O_RCX, cn_edge(8));
			cn_put(&in, CN_O_RDX, cn_edge(8));
			memcpy(code, c[o].b, c[o].n);
			/* flag-defining ones among these: IMUL and MUL (CF OF), BT (CF), CMC STC CLC and
			 * SAHF are all defined; the rest leave every flag alone */
			if (!strncmp(c[o].nm, "imul", 4) || !strncmp(c[o].nm, "mul", 3))
				mask = CN_FL_CF | CN_FL_OF;
			else if (!strncmp(c[o].nm, "bt", 2))
				mask = CN_FL_CF;
			if (!strncmp(c[o].nm, "imul", 4))
				mask = 0;           /* IMUL's flags are checked in t_mul */
			(void)cn_case(!strncmp(c[o].nm, "cmov", 4) && strstr(c[o].nm, "eax,ecx") ? &ko : &st,
				      c[o].nm, code, c[o].n, &in, mask, 64, 0, 0);
		}
	}
	cn_print("single-byte family", &st);
	CK(st.unsupported == 0, "all carried (%u refused)", st.unsupported);
	CK(st.diffs == 0, "equal the CPU (%u differ)", st.diffs);
	CK(ko.cases > 0, "the 32 bit CMOVcc shapes were generated");
	acc(&a_cmov, &ko);
}

/* ---- the instructions with no host reference ------------------------------------------------ */

/* The BCD adjusts, as the manual writes them. */
static void bcd_ref(unsigned op, uint32_t eax, uint32_t fl, uint32_t *oeax, uint32_t *ofl, uint32_t *defined)
{
	unsigned al = eax & 0xff, ah = (eax >> 8) & 0xff;
	int af = (fl & CN_FL_AF) != 0, cf = (fl & CN_FL_CF) != 0, ncf = 0, naf = 0;
	unsigned oal = al;

	*defined = CN_FL_CF | CN_FL_AF;
	switch (op) {
	case 0: /* aaa */
	case 1: /* aas */
		if ((al & 15u) > 9u || af) {
			if (op == 0) { al = (al + 6u) & 0xff; ah = (ah + 1u) & 0xff; }
			else         { al = (al - 6u) & 0xff; ah = (ah - 1u) & 0xff; }
			ncf = naf = 1;
		}
		al &= 15u;
		break;
	default: { /* daa, das */
		int sub = op == 3;

		if ((al & 15u) > 9u || af) {
			al = sub ? (al - 6u) & 0xff : (al + 6u) & 0xff;
			naf = 1;
			ncf = cf || (sub && oal < 6u) || (!sub && oal + 6u > 0xff);
		} else {
			ncf = 0;
		}
		if (oal > 0x99u || cf) {
			al = sub ? (al - 0x60u) & 0xff : (al + 0x60u) & 0xff;
			ncf = 1;
		}
		/* SF ZF PF are set from the result */
		*defined |= CN_FL_SF | CN_FL_ZF | CN_FL_PF;
		break;
	}
	}
	*oeax = (eax & ~0xffffu) | (ah << 8) | al;
	if (op >= 2)
		*oeax = (eax & ~0xffu) | al;
	*ofl = (ncf ? CN_FL_CF : 0) | (naf ? CN_FL_AF : 0);
	if (op >= 2) {
		unsigned p = (unsigned)__builtin_popcount(al) & 1u;

		*ofl |= (al == 0 ? CN_FL_ZF : 0) | ((al & 0x80u) ? CN_FL_SF : 0) | (p ? 0 : CN_FL_PF);
	}
}

static void t_bcd(void)
{
	static const struct { uint8_t b; const char *nm; } op[4] = {
		{ 0x37, "aaa" }, { 0x3f, "aas" }, { 0x27, "daa" }, { 0x2f, "das" }
	};
	unsigned o, i, flag_miss = 0, reg_miss = 0, n = 0;

	for (o = 0; o < 4; o++) {
		for (i = 0; i < 4096; i++) {
			struct kgenome_emu_cfg cfg;
			struct kgenome_emu *e;
			uint8_t code[16];
			uint32_t eax = (uint32_t)(cn_rng() & 0xffffu) | (i < 512 ? (i & 0xffu) : 0u);
			uint32_t fl = (uint32_t)(cn_rng() & (CN_FL_CF | CN_FL_AF));
			uint32_t want_eax, want_fl, def, got_eax, got_fl;
			unsigned k = 0;

			memset(&cfg, 0, sizeof cfg);
			cfg.bits = 32;
			cfg.max_insn = 100;
			e = kgenome_emu_new(&cfg);
			if (!e) {
				CK(0, "emulator");
				return;
			}
			code[k++] = 0x68;                       /* push imm32 */
			fl |= 2u;
			memcpy(code + k, &fl, 4);
			k += 4;
			code[k++] = 0x9d;                       /* popfd */
			code[k++] = op[o].b;
			code[k++] = 0x9c;                       /* pushfd */
			code[k++] = 0x5a;                       /* pop edx */
			code[k++] = 0xf4;                       /* hlt */
			kgenome_emu_map(e, CN_CODE, code, k, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
			kgenome_emu_map(e, CN_STACK, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
			kgenome_emu_set_rip(e, CN_CODE);
			kgenome_emu_set_reg(e, KGENOME_EMU_RSP, CN_STACK + 0x800);
			kgenome_emu_set_reg(e, KGENOME_EMU_RAX, eax);
			(void)kgenome_emu_run(e);
			if (kgenome_emu_get_rip(e) != CN_CODE + k - 1u) {
				CK(0, "%s: the interpreter stopped (%s)", op[o].nm, kgenome_emu_stop_detail(e));
				kgenome_emu_free(e);
				return;
			}
			got_eax = (uint32_t)kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
			got_fl = (uint32_t)kgenome_emu_get_reg(e, KGENOME_EMU_RDX);
			kgenome_emu_free(e);
			bcd_ref(o, eax, fl, &want_eax, &want_fl, &def);
			n++;
			if ((got_eax & 0xffffu) != (want_eax & 0xffffu))
				reg_miss++;
			if ((got_fl & def) != (want_fl & def))
				flag_miss++;
		}
	}
	CK(reg_miss == 0, "BCD adjusts: AX equals the manual's algorithm in all %u case(s) (%u differ)", n, reg_miss);
	CK(flag_miss == 0, "DAA/DAS set SF, ZF and PF from AL, CF and AF as the manual's algorithm (%u differ)", flag_miss);
}

static void t_environment(void)
{
	struct cn_io in, out;
	struct cn_emu r;
	struct ib x;
	uint64_t t1, t2;
	static const uint8_t rdtsc2[] = { 0x0f, 0x31, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0x49, 0x89, 0xc2,
					  0x0f, 0x31, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0x48, 0x89, 0xc1,
					  0x4c, 0x89, 0xd0 };

	/* RDTSC twice: it only moves forward, and reproducibly */
	cn_input(&in, 0);
	CK(cn_emulate_fresh(rdtsc2, sizeof rdtsc2, &in, &out, 64, &r) && r.done, "rdtsc runs (%s)", r.detail);
	t1 = cn_get(&out, 48);          /* the first read, put back in rax */
	t2 = cn_get(&out, 56);          /* the second */
	CK(t2 > t1 && t1 != 0, "the clock is monotone: %#llx then %#llx", (unsigned long long)t1, (unsigned long long)t2);
	{
		struct cn_io out2;
		struct cn_emu r2;

		CK(cn_emulate_fresh(rdtsc2, sizeof rdtsc2, &in, &out2, 64, &r2) && r2.done, "rdtsc runs again");
		CK(cn_get(&out2, 48) == t1 && cn_get(&out2, 56) == t2, "two fresh runs read the same clock (a run is reproducible)");
	}
	/* XGETBV: x87 and SSE state, nothing wider */
	{
		static const uint8_t xg[] = { 0x31, 0xc9, 0x0f, 0x01, 0xd0 };

		CK(cn_emulate(xg, sizeof xg, &in, &out, 64, &r) && r.done, "xgetbv runs");
		CK(cn_get(&out, 48) == 3 && cn_get(&out, 64) == 0, "XCR0 = 3 (rax %#llx rdx %#llx)",
		   (unsigned long long)cn_get(&out, 48), (unsigned long long)cn_get(&out, 64));
	}
	/* CPUID leaf 0 names an Intel CPU with one more leaf; leaf 1 has SSE2 and no AVX; other leaves are zero */
	{
		static const uint8_t cp[] = { 0x0f, 0xa2, 0x41, 0x89, 0x99, 0x00, 0x04, 0x00, 0x00 };   /* cpuid; mov [r9+0x400], ebx */
		unsigned leaf;

		for (leaf = 0; leaf < 4; leaf++) {
			cn_input(&in, 0);
			cn_put(&in, CN_O_RAX, leaf);
			CK(cn_emulate(cp, sizeof cp, &in, &out, 64, &r) && r.done, "cpuid %u runs", leaf);
			if (leaf == 0)
				CK(cn_get(&out, 48) == 1 && !memcmp(out.raw + CN_O_BUF, "Genu", 4) &&
				   cn_get(&out, 64) == 0x49656e69ull && cn_get(&out, 56) == 0x6c65746eull,
				   "cpuid 0: one more leaf, vendor GenuineIntel (%#llx)", (unsigned long long)cn_get(&out, 48));
			if (leaf == 1)
				CK((cn_get(&out, 64) & (1u << 26)) && !(cn_get(&out, 56) & (1u << 28)),
				   "cpuid 1: SSE2 present, AVX absent (edx %#llx ecx %#llx)",
				   (unsigned long long)cn_get(&out, 64), (unsigned long long)cn_get(&out, 56));
			if (leaf >= 2)
				CK(cn_get(&out, 48) == 0 && cn_get(&out, 56) == 0 && cn_get(&out, 64) == 0,
				   "cpuid %u: all zero", leaf);
		}
	}
	/* LDMXCSR / STMXCSR: what was written is read back */
	{
		static const uint8_t mx[] = { 0x0f, 0xae, 0x16, 0x0f, 0xae, 0x5e, 0x08 };  /* ldmxcsr [rsi]; stmxcsr [rsi+8] */
		uint32_t v = 0x1fa0u;

		cn_input(&in, 0);
		memcpy(in.raw + CN_O_BUF, &v, 4);
		cn_put(&in, CN_O_RSI, CN_O_BUF);
		CK(cn_emulate(mx, sizeof mx, &in, &out, 64, &r) && r.done, "ldmxcsr/stmxcsr run (%s)", r.detail);
		{
			uint32_t g;

			memcpy(&g, out.raw + CN_O_BUF + 8, 4);
			CK(g == v, "mxcsr reads back what was loaded (%#x)", g);
		}
	}
	(void)x;
}

static void km_report(void)
{
	CK(a_zext.cases > 20 && a_of.cases > 20 && a_imul.cases > 100 && a_div8.cases > 100 && a_bt.cases > 100 &&
	   a_tzcnt.cases > 50 && a_lzcnt.cases > 50 && a_carry.cases > 100 && a_cmov.cases > 10,
	   "every defect shape was generated (%u %u %u %u %u %u %u %u %u)", a_zext.cases, a_of.cases, a_imul.cases,
	   a_div8.cases, a_bt.cases, a_tzcnt.cases, a_lzcnt.cases, a_carry.cases, a_cmov.cases);
	CK(a_zext.diffs == 0, "a 32 bit shift, rotate, SHLD or SHRD whose count masks to zero still zero-extends the destination into the register (%u differ)", a_zext.diffs);
	CK(a_of.diffs == 0, "SHL and SHR by one set OF (%u differ)", a_of.diffs);
	CK(a_imul.diffs == 0, "IMUL (one, two and three operand forms) sets CF and OF when the signed product does not fit (%u differ)", a_imul.diffs);
	CK(a_div8.diffs == 0, "8 bit DIV/IDIV divide AX and leave the quotient in AL and the remainder in AH (%u differ)", a_div8.diffs);
	CK(a_bt.diffs == 0, "BT/BTS/BTR/BTC with a memory operand and a register offset address the bit string past the operand (%u differ)", a_bt.diffs);
	CK(a_tzcnt.diffs == 0, "TZCNT sets ZF when its result is zero and CF when its source is zero (%u differ)", a_tzcnt.diffs);
	CK(a_lzcnt.diffs == 0, "LZCNT sets ZF when its result is zero (the top bit is set) and CF when its source is zero (%u differ)", a_lzcnt.diffs);
	CK(a_carry.diffs == 0, "a 64 bit ADD, ADC or XADD sets CF on carry (%u differ)", a_carry.diffs);
	CK(a_cmov.diffs == 0, "a 32 bit CMOVcc whose condition is false still zero-extends the destination (%u differ)", a_cmov.diffs);
}

/* the re-armed machine answers exactly as a fresh one: the premise of running tens of thousands of cases on one */
static void t_machine_reuse(void)
{
	static const uint8_t ops[][4] = { { 0x48, 0x01, 0xc8 }, { 0x48, 0xd3, 0xe0 }, { 0x48, 0xf7, 0xe1 }, { 0xf3, 0xa4 },
					  { 0x48, 0x0f, 0xaf, 0xc1 }, { 0x0f, 0x28, 0xc1 } };
	static const unsigned len[] = { 3, 3, 3, 2, 4, 3 };
	unsigned i, bad = 0, nonfinal = 0;

	for (i = 0; i < 600; i++) {
		struct cn_io in, a, b;
		struct cn_emu ra, rb;
		unsigned k = i % 6u;

		cn_input(&in, (int)(i & 1u));
		cn_fill_buf(&in, 2);
		cn_put(&in, CN_O_RSI, CN_O_BUF + 400u);
		cn_put(&in, CN_O_RDI, CN_O_BUF + 1200u);
		cn_put(&in, CN_O_RCX, i % 50u);
		if (!cn_emulate(ops[k], len[k], &in, &a, 64, &ra) || !cn_emulate_fresh(ops[k], len[k], &in, &b, 64, &rb)) {
			CK(0, "emulator available");
			return;
		}
		bad += memcmp(a.raw, b.raw, CN_IO) != 0 || ra.done != rb.done || ra.stop != rb.stop;
		nonfinal += !ra.done;
	}
	CK(bad == 0, "a re-armed machine and a fresh one gave the same answer in all 600 cases (%u differ)", bad);
	CK(nonfinal == 0, "every case ran to the frame's end");
}

int main(void)
{
	cn_rng_state = 0x4b4f464e41544956ull;
	if (!CN_HOST) {
		printf("cov_emu_int: SKIPPED (the host is not x86-64 Linux, so there is no reference to run)\n");
		return 0;
	}
	t_machine_reuse();
	t_shifts();
	t_dshift();
	t_mul();
	t_div();
	t_div_faults();
	t_div_named();
	t_bt();
	t_scan();
	t_atomic();
	t_string();
	t_alu();
	t_misc();
	t_bcd();
	t_environment();
	km_report();
	if (fails) {
		printf("cov_emu_int: FAILED (%d)\n", fails);
		return 1;
	}
	printf("cov_emu_int: ok\n");
	return 0;
}
