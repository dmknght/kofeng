/*
 * emu_x87.c - the x87 stack and the 80-bit format.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"

/* ---- the x87 stack ---------------------------------------------------------
 *
 * See `st` in struct kgenome_emu for what is modelled and what is not.
 */


/*
 * The 80-bit extended format, which is the one x87 stores to memory when a
 * guest asks for `tbyte ptr`. Sign and a 15-bit exponent in the top two bytes,
 * and a 64-bit mantissa WITH ITS LEADING ONE WRITTEN OUT - unlike every other
 * IEEE format, where that bit is implied. So the value is simply
 * mantissa * 2^(exponent - 16383 - 63), and no bit has to be put back.
 */
static double f80_rd(const uint8_t *b)
{
	uint64_t m = kof_ld_le64(b);
	unsigned e16 = kof_ld_le16(b + 8);
	int ex = (int)(e16 & 0x7fffu), sign = (int)(e16 >> 15);
	double v;

	if (ex == 0x7fff) {
		/* Infinity when only the explicit leading one is set, and a NaN
		 * otherwise. Both are values a guest can store and reload. */
		v = (m << 1) ? (double)NAN : (double)INFINITY;
		return sign ? -v : v;
	}
	if (!ex && !m)
		return sign ? -0.0 : 0.0;
	v = ldexp((double)m, ex - 16383 - 63);
	return sign ? -v : v;
}

static void f80_wr(uint8_t *b, double v)
{
	unsigned e16 = 0;
	uint64_t m = 0;
	int sign = 0, ex;

	if (signbit(v)) {
		sign = 1;
		v = -v;
	}
	if (isnan(v)) {
		e16 = 0x7fffu;
		m = 0xc000000000000000ull;
	} else if (isinf(v)) {
		e16 = 0x7fffu;
		m = 0x8000000000000000ull;
	} else if (v != 0.0) {
		double f = frexp(v, &ex);       /* v = f * 2^ex, 0.5 <= f < 1 */

		m = (uint64_t)ldexp(f, 64);     /* so 2^63 <= m < 2^64 */
		e16 = (unsigned)(ex - 1 + 16383) & 0x7fffu;
	}
	{
		unsigned i;

		for (i = 0; i < 8u; i++)
			b[i] = (uint8_t)(m >> (8u * i));
	}
	e16 |= (unsigned)sign << 15;
	b[8] = (uint8_t)e16;
	b[9] = (uint8_t)(e16 >> 8);
}

/*
 * The pointers a NON-CONTROL x87 instruction leaves behind (Intel SDM Vol. 1 8.1.8): FIP, the address
 * of the instruction, and FOP, its 11 bit opcode - the low three bits of the escape byte (D8..DF) and
 * the byte after it, which is the ModRM. FNSTENV and FXSAVE report both. The control instructions
 * (FNINIT, FNCLEX, FLDCW, FNSTCW, FNSTSW, FNSTENV, FXSAVE) leave them as they were, and FNINIT clears them.
 */
static void fpu_note(struct kgenome_emu *e, const struct kgenome_emu_insn *ixp)
{
	unsigned k;

	e->fpu_rip = e->rip;
	for (k = 0; k + 1u < ixp->h.len && k < sizeof ixp->h.code; k++)
		if (ixp->h.code[k] >= 0xd8u && ixp->h.code[k] <= 0xdfu) {
			e->fop = (uint16_t)(((ixp->h.code[k] & 7u) << 8) | ixp->h.code[k + 1u]);
			return;
		}
}

/* The rounding the control word's RC field (bits 10-11) selects: nearest even, down, up, toward zero. */
static double fp_round(const struct kgenome_emu *e, double v)
{
	switch ((e->fcw >> 10) & 3u) {
	case 1:  return floor(v);
	case 2:  return ceil(v);
	case 3:  return trunc(v);
	default: return nearbyint(v);
	}
}

static double st_get(const struct kgenome_emu *e, unsigned i)
{
	return e->st[(e->st_top + i) & 7u];
}

static void st_set(struct kgenome_emu *e, unsigned i, double v)
{
	unsigned k = (e->st_top + i) & 7u;

	e->st[k] = v;
	e->st_tag[k] = 1;
}

static void st_push(struct kgenome_emu *e, double v)
{
	e->st_top = (uint8_t)((e->st_top - 1u) & 7u);
	e->st[e->st_top] = v;
	e->st_tag[e->st_top] = 1;
}

static void st_pop(struct kgenome_emu *e)
{
	e->st_tag[e->st_top] = 0;
	e->st_top = (uint8_t)((e->st_top + 1u) & 7u);
}

/*
 * One x87 source operand as a double. `is_int` picks how a MEMORY operand is
 * read - the instruction says which, not the operand: FILD's m32 and FLD's m32
 * are the same four bytes and mean different numbers.
 */
static int fp_rd(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		 int is_int, double *out)
{
	uint64_t ea;
	uint8_t b[10];
	unsigned n = op->size;

	if (op->type == KGENOME_X86_OP_REG) {
		if (op->rtype != KGENOME_X86_REG_FPU)
			return 0;
		*out = st_get(e, op->reg);
		return 1;
	}
	if (op->type != KGENOME_X86_OP_MEM || !kgenome_emu_ea_of(e, ix, op, &ea))
		return 0;
	if (n != 2u && n != 4u && n != 8u && n != 10u)
		return 0;
	if (!kgenome_emu_mem_rd(e, ea, b, n))
		return 0;
	e->fpu_dp = ea;                    /* FDP: the operand's address, reported by FNSTENV/FXSAVE */
	if (is_int) {
		int64_t v = 0;
		unsigned i;

		for (i = 0; i < n; i++)
			v |= (int64_t)((uint64_t)b[i] << (8u * i));
		/* Sign extended from its own width, because that is what the
		 * integer formats are - m16int, m32int, m64int. */
		if (n < 8u && (b[n - 1u] & 0x80u))
			v |= (int64_t)(~(uint64_t)0 << (8u * n));
		*out = (double)v;
		return 1;
	}
	if (n == 4u) {
		uint32_t u = kof_ld_le32(b);
		float f;

		memcpy(&f, &u, 4);
		*out = (double)f;
		return 1;
	}
	if (n == 8u) {
		double d;

		memcpy(&d, b, 8);
		*out = d;
		return 1;
	}
	if (n == 10u) {
		*out = f80_rd(b);
		return 1;
	}
	return 0;
}

/* And one destination. Same rule about `is_int`. */
static int fp_wr(struct kgenome_emu *e, const struct kgenome_emu_insn *ix, const struct kgenome_x86_op *op,
		 int is_int, double v)
{
	uint64_t ea;
	uint8_t b[10];
	unsigned n = op->size, i;

	if (op->type == KGENOME_X86_OP_REG) {
		if (op->rtype != KGENOME_X86_REG_FPU)
			return 0;
		st_set(e, op->reg, v);
		return 1;
	}
	if (op->type != KGENOME_X86_OP_MEM || !kgenome_emu_ea_of(e, ix, op, &ea))
		return 0;
	if (is_int) {
		int64_t q;

		double lim;

		if (n != 2u && n != 4u && n != 8u)
			return 0;
		e->fpu_dp = ea;
		/*
		 * OUT OF RANGE IS THE "INTEGER INDEFINITE" (Intel SDM Vol. 1 4.8.4.1, FIST/FISTP/FISTTP):
		 * a NaN, an infinity or a value that does not fit the destination's width is stored as the
		 * most negative integer OF THAT WIDTH - 0x8000, 0x80000000, 0x8000000000000000 - and not
		 * as the low part of a 64 bit result, which is 0 for the two narrower ones.
		 */
		lim = ldexp(1.0, (int)(8u * n) - 1);
		if (!(v >= -lim) || !(v < lim))
			q = (int64_t)((uint64_t)1 << (8u * n - 1u));
		else
			q = (int64_t)v;
		for (i = 0; i < n; i++)
			b[i] = (uint8_t)((uint64_t)q >> (8u * i));
		return kgenome_emu_mem_wr(e, ea, b, n);
	}
	if (n == 4u) {
		float f = (float)v;
		uint32_t u;

		memcpy(&u, &f, 4);
		for (i = 0; i < 4u; i++)
			b[i] = (uint8_t)(u >> (8u * i));
		return kgenome_emu_mem_wr(e, ea, b, 4u);
	}
	if (n == 8u) {
		memcpy(b, &v, 8);
		return kgenome_emu_mem_wr(e, ea, b, 8u);
	}
	if (n == 10u) {
		f80_wr(b, v);
		return kgenome_emu_mem_wr(e, ea, b, 10u);
	}
	return 0;
}

/* The three condition codes a compare leaves in the status word. */
static void fp_cmp_cc(struct kgenome_emu *e, double a, double b)
{
	e->fsw &= (uint16_t)~(KGENOME_EMU_FSW_C0 | KGENOME_EMU_FSW_C2 | KGENOME_EMU_FSW_C3);
	if (isnan(a) || isnan(b))
		e->fsw |= (uint16_t)(KGENOME_EMU_FSW_C0 | KGENOME_EMU_FSW_C2 | KGENOME_EMU_FSW_C3);
	else if (a < b)
		e->fsw |= KGENOME_EMU_FSW_C0;
	else if (a == b)
		e->fsw |= KGENOME_EMU_FSW_C3;
}

/*
 * FXCH
 */
static inline int x87_fxch(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	double t;
	unsigned i = 1u;

	fpu_note(e, ixp);
	if (ixp->n > 1u &&
	    ixp->op[1].type == KGENOME_X86_OP_REG &&
	    ixp->op[1].rtype == KGENOME_X86_REG_FPU)
		i = ixp->op[1].reg;
	t = st_get(e, 0);
	st_set(e, 0, st_get(e, i));
	st_set(e, i, t);
	return KGENOME_EMU_RUN_OK;
}

/*
 * FST, FSTP and the integer stores: write st0 to an operand, optionally popping
 */
static inline int x87_fst(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	int is_int = ixp->h.id != KGENOME_X86_I_FST &&
		     ixp->h.id != KGENOME_X86_I_FSTP;
	double v = st_get(e, 0);

	fpu_note(e, ixp);
	/* FISTTP truncates toward zero whatever the rounding mode says; FIST and FISTP follow the control
	 * word's RC field (FLDCW sets it; a guest starts in round to nearest). */
	if (ixp->h.id == KGENOME_X86_I_FISTTP)
		v = trunc(v);
	else if (is_int)
		v = fp_round(e, v);
	if (!ixp->n ||
	    !fp_wr(e, ixp, &ixp->op[0], is_int, v))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (ixp->h.id != KGENOME_X86_I_FST &&
	    ixp->h.id != KGENOME_X86_I_FIST)
		st_pop(e);
	return KGENOME_EMU_RUN_OK;
}

/*
 * the arithmetic, as one function: operator, reversed forms, integer memory side, pop
 */
static inline int x87_arith(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	double fa, fb, fr;
	int is_int = 0, rev = 0, pop = 0;

	fpu_note(e, ixp);
	switch (ixp->h.id) {
	case KGENOME_X86_I_FIADD: case KGENOME_X86_I_FIMUL:
	case KGENOME_X86_I_FISUB: case KGENOME_X86_I_FISUBR:
	case KGENOME_X86_I_FIDIV: case KGENOME_X86_I_FIDIVR:
		is_int = 1;
		break;
	default:
		break;
	}
	switch (ixp->h.id) {
	case KGENOME_X86_I_FSUBR: case KGENOME_X86_I_FSUBRP: case KGENOME_X86_I_FISUBR:
	case KGENOME_X86_I_FDIVR: case KGENOME_X86_I_FDIVRP: case KGENOME_X86_I_FIDIVR:
		rev = 1;
		break;
	default:
		break;
	}
	switch (ixp->h.id) {
	case KGENOME_X86_I_FADDP: case KGENOME_X86_I_FMULP:
	case KGENOME_X86_I_FSUBP: case KGENOME_X86_I_FSUBRP:
	case KGENOME_X86_I_FDIVP: case KGENOME_X86_I_FDIVRP:
		pop = 1;
		break;
	default:
		break;
	}
	if (ixp->n < 2u ||
	    !fp_rd(e, ixp, &ixp->op[0], 0, &fa) ||
	    !fp_rd(e, ixp, &ixp->op[1], is_int, &fb))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (rev) {
		double t = fa;

		fa = fb;
		fb = t;
	}
	switch (ixp->h.id) {
	case KGENOME_X86_I_FADD: case KGENOME_X86_I_FADDP: case KGENOME_X86_I_FIADD:
		fr = fa + fb; break;
	case KGENOME_X86_I_FMUL: case KGENOME_X86_I_FMULP: case KGENOME_X86_I_FIMUL:
		fr = fa * fb; break;
	case KGENOME_X86_I_FSUB: case KGENOME_X86_I_FSUBP: case KGENOME_X86_I_FISUB:
	case KGENOME_X86_I_FSUBR: case KGENOME_X86_I_FSUBRP: case KGENOME_X86_I_FISUBR:
		fr = fa - fb; break;
	default:
		/*
		 * DIVIDING BY ZERO IS A VALUE, NOT A FAULT.
		 * Unmasked it would raise #DE; a guest that has
		 * not unmasked it - which is every guest here,
		 * since nothing writes the control word - gets
		 * an infinity and carries on, and so does this.
		 */
		fr = fa / fb; break;
	}
	if (!fp_wr(e, ixp, &ixp->op[0], 0, fr))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (pop)
		st_pop(e);
	return KGENOME_EMU_RUN_OK;
}

/*
 * the FCOM group: the answer lands in the status word
 */
static inline int x87_compare(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	double fa = st_get(e, 0), fb = 0.0;
	int is_int = ixp->h.id == KGENOME_X86_I_FICOM ||
		     ixp->h.id == KGENOME_X86_I_FICOMP;

	fpu_note(e, ixp);
	if (ixp->h.id == KGENOME_X86_I_FCOMPP || ixp->h.id == KGENOME_X86_I_FUCOMPP) {
		/* SDM: FCOMPP and FUCOMPP compare ST0 with ST1, which the encoding does not name, and pop twice. */
		fb = st_get(e, 1);
	} else if (ixp->h.id != KGENOME_X86_I_FTST) {
		if (ixp->n < 2u ||
		    !fp_rd(e, ixp, &ixp->op[1], is_int, &fb))
			return KGENOME_EMU_RUN_UNSUPPORTED;
	}
	fp_cmp_cc(e, fa, fb);
	switch (ixp->h.id) {
	case KGENOME_X86_I_FCOMP: case KGENOME_X86_I_FUCOMP:
	case KGENOME_X86_I_FICOMP:
		st_pop(e);
		break;
	case KGENOME_X86_I_FCOMPP: case KGENOME_X86_I_FUCOMPP:
		st_pop(e);
		st_pop(e);
		break;
	default:
		break;
	}
	return KGENOME_EMU_RUN_OK;
}

/*
 * the FCOMI group: the answer lands in EFLAGS
 */
static inline int x87_fcomi(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	double fa = st_get(e, 0), fb;

	fpu_note(e, ixp);
	if (ixp->n < 2u ||
	    !fp_rd(e, ixp, &ixp->op[1], 0, &fb))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	e->flags &= ~(uint64_t)(KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF);
	if (isnan(fa) || isnan(fb))
		e->flags |= KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF;
	else if (fa < fb)
		e->flags |= KGENOME_EMU_FL_CF;
	else if (fa == fb)
		e->flags |= KGENOME_EMU_FL_ZF;
	if (ixp->h.id == KGENOME_X86_I_FCOMIP ||
	    ixp->h.id == KGENOME_X86_I_FUCOMIP)
		st_pop(e);
	return KGENOME_EMU_RUN_OK;
}

/*
 * FXAM: classify st0 into C3/C2/C0
 */
static inline int x87_fxam(struct kgenome_emu *e, const struct kgenome_emu_insn *ixp)
{
	double v = st_get(e, 0);

	fpu_note(e, ixp);
	e->fsw &= (uint16_t)~(KGENOME_EMU_FSW_C0 | KGENOME_EMU_FSW_C1 | KGENOME_EMU_FSW_C2 | KGENOME_EMU_FSW_C3);
	if (signbit(v))
		e->fsw |= KGENOME_EMU_FSW_C1;
	if (!e->st_tag[e->st_top])
		e->fsw |= (uint16_t)(KGENOME_EMU_FSW_C3 | KGENOME_EMU_FSW_C0);  /* empty */
	else if (isnan(v))
		e->fsw |= KGENOME_EMU_FSW_C0;
	else if (isinf(v))
		e->fsw |= (uint16_t)(KGENOME_EMU_FSW_C2 | KGENOME_EMU_FSW_C0);
	else if (v == 0.0)
		e->fsw |= KGENOME_EMU_FSW_C3;
	else
		e->fsw |= KGENOME_EMU_FSW_C2;                       /* normal */
	return KGENOME_EMU_RUN_OK;
}

/*
 * the conditional moves
 */
static inline int x87_fcmov(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	int cf = (e->flags & KGENOME_EMU_FL_CF) != 0;
	int zf = (e->flags & KGENOME_EMU_FL_ZF) != 0;
	int pf = (e->flags & KGENOME_EMU_FL_PF) != 0;
	int take;
	double v;

	fpu_note(e, ixp);
	switch (ixp->h.id) {
	case KGENOME_X86_I_FCMOVB:   take = cf; break;
	case KGENOME_X86_I_FCMOVE:   take = zf; break;
	case KGENOME_X86_I_FCMOVBE:  take = cf || zf; break;
	case KGENOME_X86_I_FCMOVU:   take = pf; break;
	case KGENOME_X86_I_FCMOVNB:  take = !cf; break;
	case KGENOME_X86_I_FCMOVNE:  take = !zf; break;
	case KGENOME_X86_I_FCMOVNBE: take = !cf && !zf; break;
	default:              take = !pf; break;
	}
	if (!take)
		return KGENOME_EMU_RUN_OK;
	if (ixp->n < 2u ||
	    !fp_rd(e, ixp, &ixp->op[1], 0, &v))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	st_set(e, 0, v);
	return KGENOME_EMU_RUN_OK;
}

/*
 * The tag word (Intel SDM Vol. 1 8.1.7): two bits per PHYSICAL register - 00 valid, 01 zero, 10 special
 * (NaN, infinity), 11 empty. Every finite double is a normal number in the 80 bit format, so a double
 * denormal is valid.
 */
static unsigned tag_word(const struct kgenome_emu *e)
{
	unsigned k, w = 0;

	for (k = 0; k < 8u; k++) {
		unsigned t = 3u;

		if (e->st_tag[k] >= 2u)
			t = e->st_tag[k] - 2u;                  /* the tag a restore loaded */
		else if (e->st_tag[k])
			t = (isnan(e->st[k]) || isinf(e->st[k])) ? 2u : (e->st[k] == 0.0 ? 1u : 0u);
		w |= t << (2u * k);
	}
	return w;
}

static uint16_t sw_with_top(const struct kgenome_emu *e)
{
	return (uint16_t)(e->fsw | (uint16_t)((e->st_top & 7u) << 11));
}

/*
 * FNSTENV: the environment block, whose FIP a GetPC reads. 32 bit protected mode format, 28 bytes
 * (also what 64-bit mode writes without an operand-size prefix): FCW @0, FSW @4, FTW @8, FIP @12,
 * FCS (bits 0-15) and FOP (bits 16-26) @16, FDP @20, FDS @24. FCS and FDS are written as zero: a
 * flat-model process has no use for them and CPUs that deprecate them (CPUID.7.0:EBX[13]) store zero.
 * FNSTENV is a control instruction and leaves FIP and FOP alone.
 */
static inline int x87_fnstenv(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t env[28];
	/* The operand's effective address. Named apart from
	 * `at`, the instruction address the handover test
	 * reads - see where that is declared. */
	uint64_t ea;

	memset(env, 0, sizeof env);
	kof_st_le16(env, e->fcw);
	kof_st_le16(env + 4, sw_with_top(e));
	kof_st_le16(env + 8, (uint16_t)tag_word(e));
	kof_st_le32(env + 12, (uint32_t)e->fpu_rip);
	kof_st_le32(env + 16, (uint32_t)(e->fop & 0x7ffu) << 16);
	kof_st_le32(env + 20, (uint32_t)e->fpu_dp);
	if (ixp->op[0].type != KGENOME_X86_OP_MEM ||
	    !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (!kgenome_emu_mem_wr(e, ea, env, sizeof env))
		return KGENOME_EMU_RUN_FAULT;
	return KGENOME_EMU_RUN_OK;
}

/*
 * FXSAVE and FXSAVE64 (SDM Vol. 2): the 512 byte save area.
 *
 *   @0 FCW  @2 FSW (TOP in bits 11-13)  @4 FTW, ABRIDGED: one bit per physical register, 1 = not empty
 *   @6 FOP  @8 FIP  (FXSAVE: 32 bits, FCS @12;  FXSAVE64: 64 bits)  @16 FDP (FDS @20, or 64 bits)
 *   @24 MXCSR  @28 MXCSR_MASK  @32 ST0..ST7 (80 bit, 16 bytes each, in STACK order)  @160 XMM0..XMM15
 *
 * FCS and FDS are zero (see FNSTENV), XMM8-15 are saved only in 64-bit mode, and the rest of the area is
 * zero. FXSAVE is not a control instruction in the x87 sense and does not update FIP.
 */
static inline int x87_fxsave(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t area[512];
	uint64_t ea;         /* see FNSTENV above */
	unsigned k, ftw = 0;

	memset(area, 0, sizeof area);
	for (k = 0; k < 8u; k++)
		if (e->st_tag[k])
			ftw |= 1u << k;
	kof_st_le16(area, e->fcw);
	kof_st_le16(area + 2, sw_with_top(e));
	area[4] = (uint8_t)ftw;
	kof_st_le16(area + 6, e->fop & 0x7ffu);
	if (ixp->h.id == KGENOME_X86_I_FXSAVE64) {
		kof_st_le64(area + 8, e->fpu_rip);
		kof_st_le64(area + 16, e->fpu_dp);
	} else {
		kof_st_le32(area + 8, (uint32_t)e->fpu_rip);
		kof_st_le32(area + 16, (uint32_t)e->fpu_dp);
	}
	kof_st_le32(area + 24, e->mxcsr);
	kof_st_le32(area + 28, 0xffffu);
	for (k = 0; k < 8u; k++)
		f80_wr(area + 32u + 16u * k, e->st[(e->st_top + k) & 7u]);
	for (k = 0; k < (e->bits == 32 ? 8u : 16u); k++)
		memcpy(area + 160u + 16u * k, e->xmm[k], 16);
	if (ixp->op[0].type != KGENOME_X86_OP_MEM ||
	    !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (!kgenome_emu_mem_wr(e, ea, area, sizeof area))
		return KGENOME_EMU_RUN_FAULT;
	return KGENOME_EMU_RUN_OK;
}

/* FNINIT (SDM): control word 037FH, status and tags cleared, FIP, FDP and FOP zero. FNSAVE ends with it. */
static void x87_init(struct kgenome_emu *e)
{
	unsigned q;

	for (q = 0; q < 8u; q++) {
		e->st[q] = 0.0;
		e->st_tag[q] = 0;
	}
	e->st_top = 0;
	e->fsw = 0;
	e->fcw = 0x037fu;
	e->fpu_rip = e->fpu_dp = 0;
	e->fop = 0;
}

/* The 16 bit environment (a 66 prefix on FLDENV, FNSAVE, FRSTOR) is the one format this does not carry. */
static int x87_wide_env(const struct kgenome_emu_insn *ixp)
{
	return !(ixp->h.osz & 1u);
}

/*
 * The status/control/tag state, loaded from the 28 byte environment FNSTENV writes (x87_fnstenv has the
 * layout): control word, status word with TOP, the tag word (11b = empty, anything else a register in use), FIP,
 * FOP and FDP. FLDENV does exactly this and nothing else; FRSTOR follows it with the eight registers.
 */
static void x87_env_load(struct kgenome_emu *e, const uint8_t *env)
{
	const unsigned sw = kof_ld_le16(env + 4), tw = kof_ld_le16(env + 8);
	unsigned k;

	e->fcw = kof_ld_le16(env);
	e->st_top = (uint8_t)((sw >> 11) & 7u);
	e->fsw = (uint16_t)(sw & ~0x3800u);
	for (k = 0; k < 8u; k++)
		e->st_tag[k] = (uint8_t)(((tw >> (2u * k)) & 3u) == 3u ? 0u : 2u + ((tw >> (2u * k)) & 3u));
	e->fpu_rip = kof_ld_le32(env + 12);
	e->fop = (uint16_t)((kof_ld_le32(env + 16) >> 16) & 0x7ffu);
	e->fpu_dp = kof_ld_le32(env + 20);
}

static inline int x87_fldenv(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t env[28];
	uint64_t ea;

	if (!x87_wide_env(ixp) || ixp->op[0].type != KGENOME_X86_OP_MEM ||
	    !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (!kgenome_emu_mem_rd(e, ea, env, sizeof env))
		return KGENOME_EMU_RUN_FAULT;
	x87_env_load(e, env);
	return KGENOME_EMU_RUN_OK;
}

/* FRSTOR: the environment, then the eight registers (80 bit, in stack order from ST0). */
static inline int x87_frstor(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t img[108];
	uint64_t ea;
	unsigned k;

	if (!x87_wide_env(ixp) || ixp->op[0].type != KGENOME_X86_OP_MEM ||
	    !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (!kgenome_emu_mem_rd(e, ea, img, sizeof img))
		return KGENOME_EMU_RUN_FAULT;
	x87_env_load(e, img);
	for (k = 0; k < 8u; k++)
		e->st[(e->st_top + k) & 7u] = f80_rd(img + 28u + 10u * k);
	return KGENOME_EMU_RUN_OK;
}

/* FNSAVE: the environment and the eight registers, then FNINIT. */
static inline int x87_fnsave(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t img[108];
	uint64_t ea;
	unsigned k;

	if (!x87_wide_env(ixp) || ixp->op[0].type != KGENOME_X86_OP_MEM ||
	    !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memset(img, 0, sizeof img);
	kof_st_le16(img, e->fcw);
	kof_st_le16(img + 4, sw_with_top(e));
	kof_st_le16(img + 8, (uint16_t)tag_word(e));
	kof_st_le32(img + 12, (uint32_t)e->fpu_rip);
	kof_st_le32(img + 16, (uint32_t)(e->fop & 0x7ffu) << 16);
	kof_st_le32(img + 20, (uint32_t)e->fpu_dp);
	for (k = 0; k < 8u; k++)
		f80_wr(img + 28u + 10u * k, e->st[(e->st_top + k) & 7u]);
	if (!kgenome_emu_mem_wr(e, ea, img, sizeof img))
		return KGENOME_EMU_RUN_FAULT;
	x87_init(e);
	return KGENOME_EMU_RUN_OK;
}

/*
 * FXRSTOR and FXRSTOR64: the inverse of x87_fxsave, field for field. The abridged tag word has one bit a physical
 * register (1 = in use); MXCSR keeps its architectural 16 bits (a reserved bit would be #GP on the CPU - not
 * raised here); the xmm registers 8-15 are loaded in 64-bit mode only.
 */
static inline int x87_fxrstor(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t area[512];
	uint64_t ea;
	unsigned k, sw;

	if (ixp->op[0].type != KGENOME_X86_OP_MEM || !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (!kgenome_emu_mem_rd(e, ea, area, sizeof area))
		return KGENOME_EMU_RUN_FAULT;
	sw = kof_ld_le16(area + 2);
	e->fcw = kof_ld_le16(area);
	e->st_top = (uint8_t)((sw >> 11) & 7u);
	e->fsw = (uint16_t)(sw & ~0x3800u);
	for (k = 0; k < 8u; k++)
		e->st_tag[k] = (uint8_t)(((unsigned)area[4] >> k) & 1u);
	e->fop = (uint16_t)(kof_ld_le16(area + 6) & 0x7ffu);
	if (ixp->h.id == KGENOME_X86_I_FXRSTOR64) {
		e->fpu_rip = kof_ld_le64(area + 8);
		e->fpu_dp = kof_ld_le64(area + 16);
	} else {
		e->fpu_rip = kof_ld_le32(area + 8);
		e->fpu_dp = kof_ld_le32(area + 16);
	}
	e->mxcsr = kof_ld_le32(area + 24) & 0xffffu;
	for (k = 0; k < 8u; k++)
		e->st[(e->st_top + k) & 7u] = f80_rd(area + 32u + 16u * k);
	for (k = 0; k < (e->bits == 32 ? 8u : 16u); k++)
		memcpy(e->xmm[k], area + 160u + 16u * k, 16);
	return KGENOME_EMU_RUN_OK;
}

/*
 * FBLD and FBSTP: the 80 bit packed decimal, 18 digits in nine bytes (low digit first, two to a byte) and a sign in
 * bit 7 of the tenth. The register is a double here (see `st`), so a value of 2^53 or more is rounded on the way in -
 * an 18 digit number that does not fit 53 bits is the one case the format is wider than the register. FBSTP rounds as
 * RC says, pops, and stores the "packed decimal indefinite" (FF FF C0 00 ...) for a NaN, an infinity or a value of
 * 10^18 or more.
 */
static inline int x87_fbld(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t b[10];
	uint64_t ea, n = 0;
	unsigned k;
	double v;

	if (ixp->op[1].type != KGENOME_X86_OP_MEM || !kgenome_emu_ea_of(e, ixp, &ixp->op[1], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (!kgenome_emu_mem_rd(e, ea, b, sizeof b))
		return KGENOME_EMU_RUN_FAULT;
	for (k = 9; k-- > 0;)
		n = n * 100u + (uint64_t)(b[k] >> 4) * 10u + (b[k] & 15u);
	v = (double)n;
	st_push(e, (b[9] & 0x80u) ? -v : v);
	return KGENOME_EMU_RUN_OK;
}

static inline int x87_fbstp(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t b[10];
	uint64_t ea, n;
	unsigned k;
	double v = fp_round(e, st_get(e, 0));

	if (ixp->op[0].type != KGENOME_X86_OP_MEM || !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memset(b, 0, sizeof b);
	if (isnan(v) || isinf(v) || fabs(v) >= 1e18) {
		b[7] = 0xc0u;
		b[8] = 0xffu;
		b[9] = 0xffu;
	} else {
		n = (uint64_t)fabs(v);
		for (k = 0; k < 9u; k++, n /= 100u)
			b[k] = (uint8_t)(((n / 10u) % 10u) << 4 | (n % 10u));
		b[9] = signbit(v) ? 0x80u : 0u;
	}
	if (!kgenome_emu_mem_wr(e, ea, b, sizeof b))
		return KGENOME_EMU_RUN_FAULT;
	st_pop(e);
	return KGENOME_EMU_RUN_OK;
}

/*
 * THE TRANSCENDENTALS AND THE REMAINDERS: F2XM1, FSIN, FCOS, FSINCOS, FPTAN, FPATAN, FSCALE, FXTRACT, FPREM, FPREM1.
 *
 * The registers here are doubles (see `st`), and the host's long double - the 80 bit format itself on an x86 host - does
 * the work, so that the answer is the extended one rounded once to the register's width. The architecture's own limits are
 * kept: FSIN, FCOS, FSINCOS and FPTAN take |x| < 2^63 and leave the operand alone with C2 = 1 for anything larger (a
 * reduction the instruction does not do); the remainders say with C2 = 0 that the reduction is complete, and hand back the
 * low three bits of the quotient in C0 (Q2), C3 (Q1) and C1 (Q0). Operands the host's functions answer with a NaN
 * (a negative or infinite argument of a logarithm, 0 * infinity) give the x87's real indefinite - a NaN with the sign set.
 * Tolerance, stated once: a result within one unit in the last place of a double; FSCALE, FXTRACT and the remainders are exact.
 *
 * WHERE THE CPU DIFFERS FROM THIS, and the interpreter is the more accurate: the trigonometric instructions reduce the
 * argument by multiples of pi/2 with a 66 bit approximation of pi, so a large argument, or one close to a multiple of
 * pi/2 (fsin of the double nearest pi is 1.2246063538223773e-16 on the CPU, 1.2246467991473532e-16 here, which is the
 * sine of that double), comes back with an error far above one unit in the last place. A guest whose control flow depends
 * on those digits is not one an unpacker meets; the differential test keeps to the arguments the CPU reduces accurately.
 */
static void c_bits(struct kgenome_emu *e, unsigned c0, unsigned c1, unsigned c2, unsigned c3)
{
	e->fsw &= (uint16_t)~(KGENOME_EMU_FSW_C0 | KGENOME_EMU_FSW_C1 | KGENOME_EMU_FSW_C2 | KGENOME_EMU_FSW_C3);
	if (c0)
		e->fsw |= KGENOME_EMU_FSW_C0;
	if (c1)
		e->fsw |= KGENOME_EMU_FSW_C1;
	if (c2)
		e->fsw |= KGENOME_EMU_FSW_C2;
	if (c3)
		e->fsw |= KGENOME_EMU_FSW_C3;
}

static double indefinite(void)
{
	return -NAN;
}

static inline int x87_trans(struct kgenome_emu *e, const struct kgenome_emu_insn *ixp)
{
	const double x = st_get(e, 0), y = st_get(e, 1);
	long double r;
	double d;

	fpu_note(e, ixp);
	switch (ixp->h.id) {
	case KGENOME_X86_I_FSIN: case KGENOME_X86_I_FCOS: case KGENOME_X86_I_FSINCOS: case KGENOME_X86_I_FPTAN:
		if (!isinf(x) && !isnan(x) && fabs(x) >= 9223372036854775808.0) {   /* out of range: the operand stays, C2 = 1 */
			c_bits(e, 0, 0, 1, 0);
			return KGENOME_EMU_RUN_OK;
		}
		c_bits(e, 0, 0, 0, 0);
		if (isinf(x) || isnan(x))
			d = isnan(x) ? x : indefinite();
		else if (ixp->h.id == KGENOME_X86_I_FCOS)
			d = (double)cosl((long double)x);
		else if (ixp->h.id == KGENOME_X86_I_FPTAN)
			d = (double)tanl((long double)x);
		else
			d = (double)sinl((long double)x);
		if (ixp->h.id == KGENOME_X86_I_FSINCOS) {
			const double c = (isinf(x) || isnan(x)) ? d : (double)cosl((long double)x);

			st_set(e, 0, d);
			st_push(e, c);
		} else if (ixp->h.id == KGENOME_X86_I_FPTAN) {
			st_set(e, 0, d);
			st_push(e, (isinf(x) || isnan(x)) ? d : 1.0);      /* the invalid operation pushes its indefinite, not the 1.0 */
		} else {
			st_set(e, 0, d);
		}
		return KGENOME_EMU_RUN_OK;
	case KGENOME_X86_I_FPATAN:
		if (isnan(x) || isnan(y))
			d = isnan(y) ? y : x;
		else
			d = (double)atan2l((long double)y, (long double)x);
		st_pop(e);
		st_set(e, 0, d);
		return KGENOME_EMU_RUN_OK;
	case KGENOME_X86_I_F2XM1:
		if (isnan(x))
			d = x;
		else if (isinf(x))
			d = x > 0 ? x : -1.0;
		else
			d = (double)expm1l((long double)x * 0.693147180559945309417232121458176568L);
		st_set(e, 0, d);
		return KGENOME_EMU_RUN_OK;
	case KGENOME_X86_I_FSCALE:
		if (isnan(x) || isnan(y)) {
			d = isnan(x) ? x : y;
		} else if (isinf(y)) {
			d = (y < 0 && isinf(x)) ? indefinite() : (y < 0 ? (signbit(x) ? -0.0 : 0.0) : (x == 0.0 ? indefinite() : x * HUGE_VAL));
		} else {
			const double t = trunc(y);
			const int n = t > 100000.0 ? 100000 : t < -100000.0 ? -100000 : (int)t;

			d = (double)ldexpl((long double)x, n);
		}
		st_set(e, 0, d);
		return KGENOME_EMU_RUN_OK;
	case KGENOME_X86_I_FXTRACT: {
		double sig, ex;

		if (isnan(x)) {
			sig = ex = x;
		} else if (isinf(x)) {
			sig = x;
			ex = HUGE_VAL;
		} else if (x == 0.0) {
			sig = x;
			ex = -HUGE_VAL;
		} else {
			int n;

			sig = frexp(x, &n) * 2.0;                      /* [1, 2) with the sign of x */
			ex = (double)(n - 1);
		}
		st_set(e, 0, ex);
		st_push(e, sig);
		return KGENOME_EMU_RUN_OK;
	}
	default: {                                              /* FPREM, FPREM1 */
		long double q;
		int64_t qi;

		if (isnan(x) || isnan(y)) {
			d = isnan(x) ? x : y;
			c_bits(e, 0, 0, 0, 0);
		} else if (isinf(x) || y == 0.0) {
			d = indefinite();
			c_bits(e, 0, 0, 0, 0);
		} else if (isinf(y)) {
			d = x;                                          /* a finite dividend of an infinite divisor is itself */
			c_bits(e, 0, 0, 0, 0);
		} else {
			if (ixp->h.id == KGENOME_X86_I_FPREM) {
				r = fmodl((long double)x, (long double)y);
				q = truncl((long double)x / (long double)y);
			} else {
				r = remainderl((long double)x, (long double)y);
				q = nearbyintl((long double)x / (long double)y);
			}
			qi = (int64_t)fabsl(q);
			d = (double)r;
			c_bits(e, (unsigned)((qi >> 2) & 1), (unsigned)(qi & 1), 0, (unsigned)((qi >> 1) & 1));
		}
		st_set(e, 0, d);
		return KGENOME_EMU_RUN_OK;
	}
	}
}

/*
 * Execute the x87 instructions; see the comment on its first case.
 *
 * One arm of the dispatch in kgenome_emu_run, moved out so that the loop stays
 * readable and the instructions nobody runs often are not in it. Returns
 * KGENOME_EMU_RUN_NOT_MINE for an id that is not one of its own; the loop then asks the next.
 */
int kgenome_emu_run_x87(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	switch (ixp->h.id) {
	/*
	 * ---- x87 ------------------------------------------------------
	 *
	 * WHAT THIS USED TO BE, because the shape is still visible. Only
	 * the instructions a GetPC sequence picks from were carried, and
	 * they were carried as NO-OPS that set `fpu_rip` and nothing
	 * else: a 32-bit shellcode encoder cannot say `lea eax, [rip]`,
	 * so it executes any x87 instruction and then FNSTENV, whose
	 * twelfth byte onward holds that instruction's address.
	 *
	 *     dd c3              ffree  st(3)      <- a marker, nothing else
	 *     d9 74 24 f4        fnstenv [esp-0xc]
	 *     5a                 pop    edx        <- edx = &ffree
	 *
	 * Those encoders never read a value, so no value was kept, and
	 * everything that COMPUTES was left to the unsupported path on
	 * purpose - running on with a wrong st0 and not saying so is the
	 * one failure an interpreter must not have.
	 *
	 * NOW THE VALUES ARE KEPT - see `st` in struct kgenome_emu - so the
	 * distinction is gone and these are executed for real. The GetPC
	 * sequences are unaffected: `fpu_rip` is still set by every one
	 * of them, and computing FFREE correctly is a superset of
	 * ignoring it.
	 *
	 * WHAT IS STILL ABSENT is the transcendental set - FSIN, FCOS,
	 * FPTAN, FYL2X and the rest - which keeps reaching the
	 * unsupported path. Not because they are hard, but because
	 * nothing measured has executed one, and an instruction nobody
	 * has met is an instruction whose implementation nobody can
	 * check.
	 */
	case KGENOME_X86_I_FNOP:
		fpu_note(e, ixp);
		break;

	case KGENOME_X86_I_FFREE:
	case KGENOME_X86_I_FFREEP:
		fpu_note(e, ixp);
		if (ixp->n &&
		    ixp->op[0].type == KGENOME_X86_OP_REG &&
		    ixp->op[0].rtype == KGENOME_X86_REG_FPU)
			e->st_tag[(e->st_top +
				   ixp->op[0].reg) & 7u] = 0;
		if (ixp->h.id == KGENOME_X86_I_FFREEP)
			st_pop(e);
		break;

	case KGENOME_X86_I_FDECSTP:
		fpu_note(e, ixp);
		e->st_top = (uint8_t)((e->st_top - 1u) & 7u);
		break;
	case KGENOME_X86_I_FINCSTP:
		fpu_note(e, ixp);
		e->st_top = (uint8_t)((e->st_top + 1u) & 7u);
		break;

	case KGENOME_X86_I_FXCH:
		return x87_fxch(e, ixp);

	/*
	 * The constants. FLDZ and FLD1 were already here as no-ops and
	 * now push what they name; the other five never were, and they
	 * are the same instruction with a different number.
	 */
	case KGENOME_X86_I_FLDZ:   fpu_note(e, ixp); st_push(e, 0.0); break;
	case KGENOME_X86_I_FLD1:   fpu_note(e, ixp); st_push(e, 1.0); break;
	case KGENOME_X86_I_FLDPI:  fpu_note(e, ixp);
		st_push(e, 3.14159265358979323846); break;
	case KGENOME_X86_I_FLDL2E: fpu_note(e, ixp);
		st_push(e, 1.44269504088896340736); break;
	case KGENOME_X86_I_FLDL2T: fpu_note(e, ixp);
		st_push(e, 3.32192809488736234787); break;
	case KGENOME_X86_I_FLDLG2: fpu_note(e, ixp);
		st_push(e, 0.30102999566398119521); break;
	case KGENOME_X86_I_FLDLN2: fpu_note(e, ixp);
		st_push(e, 0.69314718055994530942); break;

	case KGENOME_X86_I_FABS: fpu_note(e, ixp);
		st_set(e, 0, fabs(st_get(e, 0))); break;
	case KGENOME_X86_I_FCHS: fpu_note(e, ixp);
		st_set(e, 0, -st_get(e, 0)); break;
	case KGENOME_X86_I_FSQRT: fpu_note(e, ixp);
		st_set(e, 0, sqrt(st_get(e, 0))); break;
	case KGENOME_X86_I_FRNDINT: fpu_note(e, ixp);
		st_set(e, 0, fp_round(e, st_get(e, 0))); break;

	/*
	 * FLD and FILD PUSH; they do not write their first operand.
	 * the decoder names st0 as that operand because that is where the
	 * result ends up, but the register underneath it is a different
	 * one after the push - so the source is read first and the push
	 * is the whole of the write.
	 */
	case KGENOME_X86_I_FLD:
	case KGENOME_X86_I_FILD: {
		double v;

		fpu_note(e, ixp);
		if (ixp->n < 2u ||
		    !fp_rd(e, ixp, &ixp->op[1],
			   ixp->h.id == KGENOME_X86_I_FILD, &v))
			goto unsupported;
		st_push(e, v);
		break;
	}

	case KGENOME_X86_I_FST:
	case KGENOME_X86_I_FSTP:
	case KGENOME_X86_I_FIST:
	case KGENOME_X86_I_FISTP:
	case KGENOME_X86_I_FISTTP:
		return x87_fst(e, ixp);

	/*
	 * THE ARITHMETIC, AS ONE CASE, because the only things that
	 * differ between twenty-odd mnemonics are the operator, whether
	 * the operands are swapped, whether the memory side is an
	 * integer, and whether the stack is popped afterwards. Writing
	 * them out separately is twenty chances to get one wrong.
	 *
	 * THE REVERSED FORMS ARE NOT A DETAIL. `FSUB` computes
	 * dst - src and `FSUBR` computes src - dst; a guest that divides
	 * with FDIVR and gets FDIV's answer has every later value wrong
	 * and nothing says so.
	 */
	case KGENOME_X86_I_FADD: case KGENOME_X86_I_FADDP: case KGENOME_X86_I_FIADD:
	case KGENOME_X86_I_FMUL: case KGENOME_X86_I_FMULP: case KGENOME_X86_I_FIMUL:
	case KGENOME_X86_I_FSUB: case KGENOME_X86_I_FSUBP: case KGENOME_X86_I_FISUB:
	case KGENOME_X86_I_FSUBR: case KGENOME_X86_I_FSUBRP: case KGENOME_X86_I_FISUBR:
	case KGENOME_X86_I_FDIV: case KGENOME_X86_I_FDIVP: case KGENOME_X86_I_FIDIV:
	case KGENOME_X86_I_FDIVR: case KGENOME_X86_I_FDIVRP: case KGENOME_X86_I_FIDIVR:
		return x87_arith(e, ixp);

	/*
	 * THE COMPARES, which used to be here for their address alone.
	 * Two families: the FCOM group leaves its answer in the status
	 * word's condition codes, where a guest reads it with FNSTSW and
	 * branches on AH; the FCOMI group puts it straight in EFLAGS.
	 */
	case KGENOME_X86_I_FCOM:  case KGENOME_X86_I_FCOMP:  case KGENOME_X86_I_FCOMPP:
	case KGENOME_X86_I_FUCOM: case KGENOME_X86_I_FUCOMP: case KGENOME_X86_I_FUCOMPP:
	case KGENOME_X86_I_FICOM: case KGENOME_X86_I_FICOMP:
	case KGENOME_X86_I_FTST:
		return x87_compare(e, ixp);

	case KGENOME_X86_I_FCOMI: case KGENOME_X86_I_FCOMIP:
	case KGENOME_X86_I_FUCOMI: case KGENOME_X86_I_FUCOMIP:
		return x87_fcomi(e, ixp);

	/*
	 * FXAM classifies st0 into C3/C2/C0. It was a no-op here and a
	 * GetPC does not read it, but a guest that branches on "is this
	 * zero" does, and the classification is three comparisons.
	 */
	case KGENOME_X86_I_FXAM:
		return x87_fxam(e, ixp);

	/*
	 * The status word, which is how a guest reads a compare it made
	 * with the FCOM family: `fnstsw ax` then `sahf` or `test ah`.
	 * TOP sits in bits 11..13 and is part of what is reported.
	 */
	case KGENOME_X86_I_FNSTSW: {
		uint64_t v = (uint64_t)(e->fsw |
				(uint16_t)((e->st_top & 7u) << 11));

		/* a control instruction: FIP and FOP stay as they were */
		if (!ixp->n ||
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], v))
			goto unsupported;
		break;
	}

	/*
	 * The conditional moves. They were no-ops and the condition was
	 * never looked at; now the value moves when EFLAGS says it
	 * should, which is what a guest that used one is expecting.
	 */
	case KGENOME_X86_I_FCMOVB:  case KGENOME_X86_I_FCMOVBE: case KGENOME_X86_I_FCMOVE:
	case KGENOME_X86_I_FCMOVNB: case KGENOME_X86_I_FCMOVNBE: case KGENOME_X86_I_FCMOVNE:
	case KGENOME_X86_I_FCMOVU:  case KGENOME_X86_I_FCMOVNU:
		return x87_fcmov(e, ixp);

	/*
	 * The control-word and state instructions that a guest issues to
	 * put the FPU in a known state. Nothing here reads the control
	 * word - rounding is always to nearest and every exception is
	 * masked - so these are accepted and only FINIT has an effect
	 * that anything can observe.
	 */
	case KGENOME_X86_I_FLDCW:
	case KGENOME_X86_I_FNSTCW:
	case KGENOME_X86_I_FNCLEX:
		/* control instructions: FIP and FOP stay as they were (SDM Vol. 1 8.1.8) */
		if (ixp->h.id == KGENOME_X86_I_FNSTCW && ixp->n &&
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], e->fcw))
			goto unsupported;
		if (ixp->h.id == KGENOME_X86_I_FLDCW) {
			uint64_t cw;

			if (!ixp->n || !kgenome_emu_op_rd(e, ixp, &ixp->op[0], &cw))
				goto unsupported;
			e->fcw = (uint16_t)cw;        /* RC is honoured by FIST/FRNDINT; the masks change nothing here */
		}
		if (ixp->h.id == KGENOME_X86_I_FNCLEX)
			e->fsw = 0;
		break;

	case KGENOME_X86_I_FNINIT:
		x87_init(e);
		break;

	/*
	 * The environment block (see x87_fnstenv for the layout). FIP at offset 12 is what a GetPC
	 * reads; the control word, status word with TOP, tag word, FOP and FDP are kept and reported
	 * too, so a guest that saves and compares them sees a machine and not zeros.
	 *
	 * FNSTENV does not check for pending exceptions, which is why the
	 * encoders use it rather than FSTENV, and why nothing is checked
	 * here either.
	 */
	case KGENOME_X86_I_FNSTENV:
		return x87_fnstenv(e, ixp);

	/*
	 * FXSAVE - THE OTHER GetPC, and the reason it is here.
	 *
	 * It saves the whole x87/SSE state, 512 bytes of it, and one
	 * field is the address of the last x87 instruction - the same
	 * value FNSTENV reports and the same use a stub makes of it.
	 * x64/zutto_dekiru opens with `fxsave [r8]` and died on its
	 * fifth instruction without it.
	 *
	 * The layout differs between the two forms and the difference
	 * matters, because a stub reads one exact offset (see x87_fxsave):
	 *
	 *   FXSAVE64   FIP is 64 bits at offset 8
	 *   FXSAVE     FIP is 32 bits at offset 8, its selector at 12
	 *
	 * The control word, status word, abridged tag word, FOP, FDP, MXCSR, the register stack
	 * (80 bit, stack order) and the xmm registers are all written; before this was
	 * fixed the area was zero but for FIP, so a stub that saved the state and
	 * compared or restored it read a machine with no registers.
	 */
	case KGENOME_X86_I_FXSAVE:
	case KGENOME_X86_I_FXSAVE64:
		return x87_fxsave(e, ixp);

	/* The inverses of the two saves, FRSTOR/FNSAVE for the 108 byte image, and the decimal and logarithm ops. */
	case KGENOME_X86_I_FXRSTOR:
	case KGENOME_X86_I_FXRSTOR64:
		return x87_fxrstor(e, ixp);
	case KGENOME_X86_I_FLDENV:
		return x87_fldenv(e, ixp);
	case KGENOME_X86_I_FRSTOR:
		return x87_frstor(e, ixp);
	case KGENOME_X86_I_FNSAVE:
		return x87_fnsave(e, ixp);
	case KGENOME_X86_I_FBLD:
		fpu_note(e, ixp);
		return x87_fbld(e, ixp);
	case KGENOME_X86_I_FBSTP:
		fpu_note(e, ixp);
		return x87_fbstp(e, ixp);

	/*
	 * FYL2X and FYL2XP1: st1 * log2(st0) (or log2(st0 + 1)), stored in st1 and popped. The host's log2 and log1p
	 * give the double; the 80 bit result of the real instruction rounds once more, so the differential allows one
	 * unit in the last place of a double here and nowhere else. A negative st0 is the invalid operation: the real
	 * indefinite, which for the x87 is a QNaN with the sign set.
	 */
	case KGENOME_X86_I_FSIN: case KGENOME_X86_I_FCOS: case KGENOME_X86_I_FSINCOS: case KGENOME_X86_I_FPTAN:
	case KGENOME_X86_I_FPATAN: case KGENOME_X86_I_F2XM1: case KGENOME_X86_I_FSCALE: case KGENOME_X86_I_FXTRACT:
	case KGENOME_X86_I_FPREM: case KGENOME_X86_I_FPREM1:
		return x87_trans(e, ixp);

	case KGENOME_X86_I_FYL2X:
	case KGENOME_X86_I_FYL2XP1: {
		const double x = st_get(e, 0), y = st_get(e, 1);
		double r;

		fpu_note(e, ixp);
		if (x != x || y != y)
			r = x != x ? x : y;
		else if (ixp->h.id == KGENOME_X86_I_FYL2X ? x < 0.0 : x < -1.0)
			r = -NAN;
		else
			r = y * (ixp->h.id == KGENOME_X86_I_FYL2X ? log2(x) : log1p(x) / 0.69314718055994530942);
		st_pop(e);
		st_set(e, 0, r);
		break;
	}
	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
	return KGENOME_EMU_RUN_OK;

unsupported:
	return KGENOME_EMU_RUN_UNSUPPORTED;
}
