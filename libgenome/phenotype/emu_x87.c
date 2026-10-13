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

		if (n != 2u && n != 4u && n != 8u)
			return 0;
		/*
		 * OUT OF RANGE IS THE "INDEFINITE" VALUE, which is what the
		 * hardware stores rather than wrapping: the most negative
		 * integer of the destination's width. A guest that stores a
		 * huge float into a word gets that on a real CPU too.
		 */
		if (!(v >= -9.2233720368547758e18) || !(v <= 9.2233720368547758e18))
			q = (int64_t)0x8000000000000000ull;
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

	e->fpu_rip = e->rip;
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

	e->fpu_rip = e->rip;
	/* FISTTP truncates toward zero whatever the rounding
	 * mode says; the others follow it, and this rounds to
	 * nearest, which is the mode a guest starts in. */
	if (ixp->h.id == KGENOME_X86_I_FISTTP)
		v = trunc(v);
	else if (is_int)
		v = nearbyint(v);
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

	e->fpu_rip = e->rip;
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

	e->fpu_rip = e->rip;
	if (ixp->h.id != KGENOME_X86_I_FTST) {
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

	e->fpu_rip = e->rip;
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
static inline int x87_fxam(struct kgenome_emu *e)
{
	double v = st_get(e, 0);

	e->fpu_rip = e->rip;
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

	e->fpu_rip = e->rip;
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
 * FNSTENV: the environment block, whose FIP a GetPC reads
 */
static inline int x87_fnstenv(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t env[28];
	/* The operand's effective address. Named apart from
	 * `at`, the instruction address the handover test
	 * reads - see where that is declared. */
	uint64_t ea;

	memset(env, 0, sizeof env);
	env[12] = (uint8_t)(e->fpu_rip);
	env[13] = (uint8_t)(e->fpu_rip >> 8);
	env[14] = (uint8_t)(e->fpu_rip >> 16);
	env[15] = (uint8_t)(e->fpu_rip >> 24);
	if (ixp->op[0].type != KGENOME_X86_OP_MEM ||
	    !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (!kgenome_emu_mem_wr(e, ea, env, sizeof env))
		return KGENOME_EMU_RUN_FAULT;
	return KGENOME_EMU_RUN_OK;
}

/*
 * FXSAVE and FXSAVE64: the save area, whose FIP a GetPC reads
 */
static inline int x87_fxsave(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t area[512];
	uint64_t ea;         /* see FNSTENV above */

	memset(area, 0, sizeof area);
	if (ixp->h.id == KGENOME_X86_I_FXSAVE64) {
		unsigned k;

		for (k = 0; k < 8u; k++)
			area[8 + k] = (uint8_t)(e->fpu_rip >>
						(k * 8));
	} else {
		area[8]  = (uint8_t)(e->fpu_rip);
		area[9]  = (uint8_t)(e->fpu_rip >> 8);
		area[10] = (uint8_t)(e->fpu_rip >> 16);
		area[11] = (uint8_t)(e->fpu_rip >> 24);
	}
	if (ixp->op[0].type != KGENOME_X86_OP_MEM ||
	    !kgenome_emu_ea_of(e, ixp, &ixp->op[0], &ea))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (!kgenome_emu_mem_wr(e, ea, area, sizeof area))
		return KGENOME_EMU_RUN_FAULT;
	return KGENOME_EMU_RUN_OK;
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
		e->fpu_rip = e->rip;
		break;

	case KGENOME_X86_I_FFREE:
	case KGENOME_X86_I_FFREEP:
		e->fpu_rip = e->rip;
		if (ixp->n &&
		    ixp->op[0].type == KGENOME_X86_OP_REG &&
		    ixp->op[0].rtype == KGENOME_X86_REG_FPU)
			e->st_tag[(e->st_top +
				   ixp->op[0].reg) & 7u] = 0;
		if (ixp->h.id == KGENOME_X86_I_FFREEP)
			st_pop(e);
		break;

	case KGENOME_X86_I_FDECSTP:
		e->fpu_rip = e->rip;
		e->st_top = (uint8_t)((e->st_top - 1u) & 7u);
		break;
	case KGENOME_X86_I_FINCSTP:
		e->fpu_rip = e->rip;
		e->st_top = (uint8_t)((e->st_top + 1u) & 7u);
		break;

	case KGENOME_X86_I_FXCH:
		return x87_fxch(e, ixp);

	/*
	 * The constants. FLDZ and FLD1 were already here as no-ops and
	 * now push what they name; the other five never were, and they
	 * are the same instruction with a different number.
	 */
	case KGENOME_X86_I_FLDZ:   e->fpu_rip = e->rip; st_push(e, 0.0); break;
	case KGENOME_X86_I_FLD1:   e->fpu_rip = e->rip; st_push(e, 1.0); break;
	case KGENOME_X86_I_FLDPI:  e->fpu_rip = e->rip;
		st_push(e, 3.14159265358979323846); break;
	case KGENOME_X86_I_FLDL2E: e->fpu_rip = e->rip;
		st_push(e, 1.44269504088896340736); break;
	case KGENOME_X86_I_FLDL2T: e->fpu_rip = e->rip;
		st_push(e, 3.32192809488736234787); break;
	case KGENOME_X86_I_FLDLG2: e->fpu_rip = e->rip;
		st_push(e, 0.30102999566398119521); break;
	case KGENOME_X86_I_FLDLN2: e->fpu_rip = e->rip;
		st_push(e, 0.69314718055994530942); break;

	case KGENOME_X86_I_FABS: e->fpu_rip = e->rip;
		st_set(e, 0, fabs(st_get(e, 0))); break;
	case KGENOME_X86_I_FCHS: e->fpu_rip = e->rip;
		st_set(e, 0, -st_get(e, 0)); break;
	case KGENOME_X86_I_FSQRT: e->fpu_rip = e->rip;
		st_set(e, 0, sqrt(st_get(e, 0))); break;
	case KGENOME_X86_I_FRNDINT: e->fpu_rip = e->rip;
		st_set(e, 0, nearbyint(st_get(e, 0))); break;

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

		e->fpu_rip = e->rip;
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
		return x87_fxam(e);

	/*
	 * The status word, which is how a guest reads a compare it made
	 * with the FCOM family: `fnstsw ax` then `sahf` or `test ah`.
	 * TOP sits in bits 11..13 and is part of what is reported.
	 */
	case KGENOME_X86_I_FNSTSW: {
		uint64_t v = (uint64_t)(e->fsw |
				(uint16_t)((e->st_top & 7u) << 11));

		e->fpu_rip = e->rip;
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
		e->fpu_rip = e->rip;
		if (ixp->h.id == KGENOME_X86_I_FNSTCW && ixp->n &&
		    !kgenome_emu_op_wr(e, ixp, &ixp->op[0], 0x037fu))
			goto unsupported;
		if (ixp->h.id == KGENOME_X86_I_FNCLEX)
			e->fsw = 0;
		break;

	case KGENOME_X86_I_FNINIT: {
		unsigned q;

		e->fpu_rip = e->rip;
		for (q = 0; q < 8u; q++) {
			e->st[q] = 0.0;
			e->st_tag[q] = 0;
		}
		e->st_top = 0;
		e->fsw = 0;
		break;
	}

	/*
	 * The environment block, and the one field in it that matters.
	 *
	 * 28 bytes in 32 bit protected mode, and the address of the last
	 * non-control x87 instruction sits at offset 12. Everything else is
	 * written as zero: a control word, a status word and tag bits that
	 * nothing here maintains, and inventing values for them would be
	 * three more numbers a reader could mistake for real state.
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
	 * matters, because a stub reads one exact offset:
	 *
	 *   FXSAVE64   FIP is 64 bits at offset 8
	 *   FXSAVE     FIP is 32 bits at offset 8, its selector at 12
	 *
	 * Everything else is written as zero. A run that needed the
	 * control word or a live xmm register out of this block would
	 * be doing arithmetic on the FPU, which nothing this interprets
	 * does - and a wrong answer there would be visible, not silent,
	 * because the stub would fetch from the wrong address.
	 */
	case KGENOME_X86_I_FXSAVE:
	case KGENOME_X86_I_FXSAVE64:
		return x87_fxsave(e, ixp);
	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
	return KGENOME_EMU_RUN_OK;

unsupported:
	return KGENOME_EMU_RUN_UNSUPPORTED;
}
