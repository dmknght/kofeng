/*
 * emu_vec_fp.c - packed and scalar SSE floating point, the conversions, and the arithmetic they share.
 * Part of the interpreter; see emu_interp.c, emu_vec.c and emu_private.h.
 *
 * THE ARITHMETIC IS THE HOST'S, THE ANSWERS THE HOST LEAVES TO ITS CPU ARE DECIDED HERE (Intel SDM Vol. 1
 * 4.8.3 Table 4-7, 11.5.2):
 *   - a NaN operand gives that operand quieted (the FIRST source operand if both are NaN), payload kept;
 *   - an invalid operation (inf - inf, 0 / 0, 0 * inf, sqrt of a negative) gives the "real indefinite" QNaN,
 *     whose sign bit is SET (0xFFF8000000000000, 0xFFC00000);
 *   - MIN and MAX are not arithmetic: dest = (dest < src) ? dest : src (MAX: >), so a NaN in either operand, or two
 *     zeros, return the SOURCE operand untouched (a signalling NaN stays signalling);
 *   - an integer conversion of a NaN or of a value that does not fit gives the INTEGER INDEFINITE, the most
 *     negative integer of the destination's width.
 * The rounding is MXCSR.RC (bits 13-14: nearest even, down, up, toward zero), which the host's own FP unit is
 * switched to for the one operation when it is not "nearest" (fenv, no system call). A single precision operation
 * is done in float, so it rounds once.
 *
 * NOT MODELLED, AND SAID SO HERE: the sticky exception flags of MXCSR (IE DE ZE OE UE PE) are never set, a
 * guest cannot unmask an exception (so none is delivered), and DAZ / FTZ are not applied. A guest that tests them
 * - a Go runtime's arithmetic self-check does not - sees them clear. diff_sse_x87.c compares everything else with
 * the CPU: NaNs of every kind, infinities, zeros of both signs, denormals, the rounding ties and every RC.
 * RCPPS, RSQRTPS (and the SS forms) are refused: the architecture gives an approximation whose last bits differ
 * between a vendor's cores, so there is no answer to be right about.
 */
#define _POSIX_C_SOURCE 200809L

#include <fenv.h>

#include "emu_private.h"

/* ---- one lane --------------------------------------------------------------------------------- */

static int rc_enter(unsigned rc)
{
	static const int m[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
	const int old = fegetround();

	if (rc)
		fesetround(m[rc & 3u]);
	return old;
}

static void rc_leave(unsigned rc, int old)
{
	if (rc)
		fesetround(old);
}

static double dop(unsigned op, double u, double v, unsigned rc)
{
	volatile double vu = u, vv = v, w;
	const int old = rc_enter(rc);

	switch (op) {
	case KGENOME_EMU_FP_ADD: w = vu + vv; break;
	case KGENOME_EMU_FP_SUB: w = vu - vv; break;
	case KGENOME_EMU_FP_MUL: w = vu * vv; break;
	case KGENOME_EMU_FP_DIV: w = vu / vv; break;
	default:                 w = sqrt(vv); break;
	}
	rc_leave(rc, old);
	return w;
}

static float fop(unsigned op, float u, float v, unsigned rc)
{
	volatile float vu = u, vv = v, w;
	const int old = rc_enter(rc);

	switch (op) {
	case KGENOME_EMU_FP_ADD: w = vu + vv; break;
	case KGENOME_EMU_FP_SUB: w = vu - vv; break;
	case KGENOME_EMU_FP_MUL: w = vu * vv; break;
	case KGENOME_EMU_FP_DIV: w = vu / vv; break;
	default:                 w = sqrtf(vv); break;
	}
	rc_leave(rc, old);
	return w;
}

uint64_t kgenome_emu_fpd(unsigned op, uint64_t ub, uint64_t vb, unsigned rc)
{
	double u, v, w;
	uint64_t r;

	memcpy(&u, &ub, 8);
	memcpy(&v, &vb, 8);
	if (op == KGENOME_EMU_FP_MIN)
		return u < v ? ub : vb;
	if (op == KGENOME_EMU_FP_MAX)
		return u > v ? ub : vb;
	if (op == KGENOME_EMU_FP_SQRT) {            /* the source alone: the destination is not an operand */
		if (v != v)
			return vb | 0x0008000000000000ull;
	} else {
		if (u != u)
			return ub | 0x0008000000000000ull;
		if (v != v)
			return vb | 0x0008000000000000ull;
	}
	w = dop(op, u, v, rc);
	if (w != w)
		return 0xfff8000000000000ull;
	memcpy(&r, &w, 8);
	return r;
}

uint32_t kgenome_emu_fps(unsigned op, uint32_t ub, uint32_t vb, unsigned rc)
{
	float u, v, w;
	uint32_t r;

	memcpy(&u, &ub, 4);
	memcpy(&v, &vb, 4);
	if (op == KGENOME_EMU_FP_MIN)
		return u < v ? ub : vb;
	if (op == KGENOME_EMU_FP_MAX)
		return u > v ? ub : vb;
	if (op == KGENOME_EMU_FP_SQRT) {
		if (v != v)
			return vb | 0x00400000u;
	} else {
		if (u != u)
			return ub | 0x00400000u;
		if (v != v)
			return vb | 0x00400000u;
	}
	w = fop(op, u, v, rc);
	if (w != w)
		return 0xffc00000u;
	memcpy(&r, &w, 4);
	return r;
}

/* float -> double and double -> float of a NaN: quiet, sign kept, the payload widened or cut to the new fraction. */
uint64_t kgenome_emu_f2d(uint32_t b)
{
	float f;
	double d;
	uint64_t r;

	memcpy(&f, &b, 4);
	if (f != f)
		return ((uint64_t)(b >> 31) << 63) | 0x7ff8000000000000ull | ((uint64_t)(b & 0x007fffffu) << 29);
	d = f;
	memcpy(&r, &d, 8);
	return r;
}

uint32_t kgenome_emu_d2f(uint64_t b, unsigned rc)
{
	double d;
	float f;
	uint32_t r;
	volatile double vd;
	int old;

	memcpy(&d, &b, 8);
	if (d != d)
		return ((uint32_t)(b >> 63) << 31) | 0x7fc00000u | (uint32_t)((b >> 29) & 0x003fffffu);
	vd = d;
	old = rc_enter(rc);
	f = (float)vd;
	rc_leave(rc, old);
	memcpy(&r, &f, 4);
	return r;
}

/* An integer converted to float or double, rounded by RC. */
uint32_t kgenome_emu_i2f(int64_t n, unsigned rc)
{
	volatile int64_t vn = n;
	const int old = rc_enter(rc);
	float f = (float)vn;
	uint32_t r;

	rc_leave(rc, old);
	memcpy(&r, &f, 4);
	return r;
}

uint64_t kgenome_emu_i2d(int64_t n, unsigned rc)
{
	volatile int64_t vn = n;
	const int old = rc_enter(rc);
	double d = (double)vn;
	uint64_t r;

	rc_leave(rc, old);
	memcpy(&r, &d, 8);
	return r;
}

/*
 * A double (a float is exact in one) to a signed integer of `w` bits: rounded as RC says, or toward zero for the
 * truncating forms; a NaN or an out-of-range value is the integer indefinite.
 */
uint64_t kgenome_emu_f2i(double d, unsigned w, int trunc_to_zero, unsigned rc)
{
	double t;
	volatile double vd = d;
	int old;

	if (d != d)
		return (uint64_t)1 << (w - 1u);
	if (trunc_to_zero) {
		t = trunc(d);
	} else {
		old = rc_enter(rc);
		t = nearbyint(vd);
		rc_leave(rc, old);
	}
	if (!(t >= -ldexp(1.0, (int)w - 1)) || !(t < ldexp(1.0, (int)w - 1)))
		return (uint64_t)1 << (w - 1u);
	return (uint64_t)(int64_t)t;
}

/* ---- packed arithmetic -------------------------------------------------------------------------- */

/*
 * The whole destination register, for a form whose operand is only a lane of it: a scalar compare or round, and
 * CVTPI2PS, replace one part and keep the rest, so the rest has to be read - the decoder sizes the operand at the
 * lane, and reading it through kgenome_emu_vec_rd would hand back zeros above it.
 */
static int dst_rd(const struct kgenome_emu *e, const struct kgenome_emu_insn *ixp, uint8_t *x)
{
	const struct kgenome_x86_op *d = &ixp->op[0];

	if (d->type != KGENOME_X86_OP_REG || d->rtype != KGENOME_X86_REG_SSE || d->reg >= 16u)
		return 0;
	memcpy(x, e->xmm[d->reg], 16);
	return 1;
}

static int dst_wr(struct kgenome_emu *e, const struct kgenome_emu_insn *ixp, const uint8_t *q)
{
	const struct kgenome_x86_op *d = &ixp->op[0];

	if (d->type != KGENOME_X86_OP_REG || d->rtype != KGENOME_X86_REG_SSE || d->reg >= 16u)
		return 0;
	memcpy(e->xmm[d->reg], q, 16);
	return 1;
}

static unsigned mx_rc(const struct kgenome_emu *e)
{
	return (e->mxcsr >> 13) & 3u;
}

/* the operation an id performs, and whether it is the double or the single form, packed or scalar */
static int fp_class(unsigned id, unsigned *op, int *dbl)
{
	switch (id) {
	case KGENOME_X86_I_ADDPS: *op = KGENOME_EMU_FP_ADD; *dbl = 0; return 1;
	case KGENOME_X86_I_ADDPD: *op = KGENOME_EMU_FP_ADD; *dbl = 1; return 1;
	case KGENOME_X86_I_SUBPS: *op = KGENOME_EMU_FP_SUB; *dbl = 0; return 1;
	case KGENOME_X86_I_SUBPD: *op = KGENOME_EMU_FP_SUB; *dbl = 1; return 1;
	case KGENOME_X86_I_MULPS: *op = KGENOME_EMU_FP_MUL; *dbl = 0; return 1;
	case KGENOME_X86_I_MULPD: *op = KGENOME_EMU_FP_MUL; *dbl = 1; return 1;
	case KGENOME_X86_I_DIVPS: *op = KGENOME_EMU_FP_DIV; *dbl = 0; return 1;
	case KGENOME_X86_I_DIVPD: *op = KGENOME_EMU_FP_DIV; *dbl = 1; return 1;
	case KGENOME_X86_I_MINPS: *op = KGENOME_EMU_FP_MIN; *dbl = 0; return 1;
	case KGENOME_X86_I_MINPD: *op = KGENOME_EMU_FP_MIN; *dbl = 1; return 1;
	case KGENOME_X86_I_MAXPS: *op = KGENOME_EMU_FP_MAX; *dbl = 0; return 1;
	case KGENOME_X86_I_MAXPD: *op = KGENOME_EMU_FP_MAX; *dbl = 1; return 1;
	case KGENOME_X86_I_SQRTPS: *op = KGENOME_EMU_FP_SQRT; *dbl = 0; return 1;
	case KGENOME_X86_I_SQRTPD: *op = KGENOME_EMU_FP_SQRT; *dbl = 1; return 1;
	default:
		return 0;
	}
}

static int fp_packed(struct kgenome_emu *e, struct kgenome_emu_insn *ixp, unsigned op, int dbl)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, k;
	const unsigned rc = mx_rc(e);

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < (dbl ? 2u : 4u); k++) {
		if (dbl) {
			uint64_t a, b, r;

			memcpy(&a, x + k * 8u, 8);
			memcpy(&b, y + k * 8u, 8);
			r = kgenome_emu_fpd(op, a, b, rc);
			memcpy(q + k * 8u, &r, 8);
		} else {
			uint32_t a, b, r;

			memcpy(&a, x + k * 4u, 4);
			memcpy(&b, y + k * 4u, 4);
			r = kgenome_emu_fps(op, a, b, rc);
			memcpy(q + k * 4u, &r, 4);
		}
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* ---- compares ----------------------------------------------------------------------------------- */

/* CMPPS/PD/SS/SD: the predicate (EQ LT LE UNORD NEQ NLT NLE ORD) of two values, all ones or zero. */
static int cmp_pred(unsigned pred, double u, double v)
{
	const int un = u != u || v != v;

	switch (pred & 7u) {
	case 0: return !un && u == v;
	case 1: return !un && u < v;
	case 2: return !un && u <= v;
	case 3: return un;
	case 4: return un || u != v;
	case 5: return un || !(u < v);
	case 6: return un || !(u <= v);
	default: return !un;
	}
}

static int fp_cmp(struct kgenome_emu *e, struct kgenome_emu_insn *ixp, int dbl, int scalar)
{
	uint8_t x[16], y[16];
	unsigned nx, ny, k, n = scalar ? 1u : (dbl ? 2u : 4u);
	uint64_t pred;

	if (!dst_rd(e, ixp, x) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &pred))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	(void)nx;
	for (k = 0; k < n; k++) {
		int t;

		if (dbl) {
			double u, v;

			memcpy(&u, x + k * 8u, 8);
			memcpy(&v, y + k * 8u, 8);
			t = cmp_pred((unsigned)pred, u, v);
			memset(x + k * 8u, t ? 0xff : 0, 8);
		} else {
			float u, v;

			memcpy(&u, x + k * 4u, 4);
			memcpy(&v, y + k * 4u, 4);
			t = cmp_pred((unsigned)pred, (double)u, (double)v);
			memset(x + k * 4u, t ? 0xff : 0, 4);
		}
	}
	return dst_wr(e, ixp, x) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* ---- shuffles, horizontal ops, blends ---------------------------------------------------------- */

static int fp_shuffle(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, k;
	uint64_t sel = 0;
	const unsigned id = ixp->h.id;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if ((id == KGENOME_X86_I_SHUFPS || id == KGENOME_X86_I_SHUFPD) &&
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memset(q, 0, 16);
	switch (id) {
	case KGENOME_X86_I_UNPCKLPS:
		memcpy(q, x, 4); memcpy(q + 4, y, 4); memcpy(q + 8, x + 4, 4); memcpy(q + 12, y + 4, 4);
		break;
	case KGENOME_X86_I_UNPCKHPS:
		memcpy(q, x + 8, 4); memcpy(q + 4, y + 8, 4); memcpy(q + 8, x + 12, 4); memcpy(q + 12, y + 12, 4);
		break;
	case KGENOME_X86_I_UNPCKLPD:
		memcpy(q, x, 8); memcpy(q + 8, y, 8);
		break;
	case KGENOME_X86_I_UNPCKHPD:
		memcpy(q, x + 8, 8); memcpy(q + 8, y + 8, 8);
		break;
	case KGENOME_X86_I_SHUFPS:
		/* the two low results come from the destination, the two high ones from the source */
		for (k = 0; k < 4u; k++)
			memcpy(q + k * 4u, (k < 2u ? x : y) + ((sel >> (k * 2u)) & 3u) * 4u, 4);
		break;
	case KGENOME_X86_I_SHUFPD:
		memcpy(q, x + ((sel & 1u) ? 8 : 0), 8);
		memcpy(q + 8, y + ((sel & 2u) ? 8 : 0), 8);
		break;
	case KGENOME_X86_I_MOVSHDUP:
		memcpy(q, y + 4, 4); memcpy(q + 4, y + 4, 4); memcpy(q + 8, y + 12, 4); memcpy(q + 12, y + 12, 4);
		break;
	case KGENOME_X86_I_MOVSLDUP:
		memcpy(q, y, 4); memcpy(q + 4, y, 4); memcpy(q + 8, y + 8, 4); memcpy(q + 12, y + 8, 4);
		break;
	default:                                    /* MOVDDUP: the low double of the source twice */
		memcpy(q, y, 8); memcpy(q + 8, y, 8);
		break;
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* HADDPS/PD HSUBPS/PD: pairs of the destination, then pairs of the source. ADDSUBPS/PD: even lanes subtract. */
static int fp_horiz(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, k;
	const unsigned id = ixp->h.id, rc = mx_rc(e);
	const int dbl = id == KGENOME_X86_I_HADDPD || id == KGENOME_X86_I_HSUBPD || id == KGENOME_X86_I_ADDSUBPD;
	const int sub = id == KGENOME_X86_I_HSUBPS || id == KGENOME_X86_I_HSUBPD;
	const int addsub = id == KGENOME_X86_I_ADDSUBPS || id == KGENOME_X86_I_ADDSUBPD;
	const unsigned lw = dbl ? 8u : 4u, n = 16u / lw;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < n; k++) {
		const unsigned opn = addsub ? ((k & 1u) ? KGENOME_EMU_FP_ADD : KGENOME_EMU_FP_SUB)
					    : (sub ? KGENOME_EMU_FP_SUB : KGENOME_EMU_FP_ADD);
		const uint8_t *a, *b;

		if (addsub) {
			a = x + k * lw;
			b = y + k * lw;
		} else {
			const uint8_t *s = k < n / 2u ? x : y;
			const unsigned j = (k % (n / 2u)) * 2u;

			a = s + j * lw;
			b = s + (j + 1u) * lw;
		}
		if (dbl) {
			uint64_t u, v, r;

			memcpy(&u, a, 8);
			memcpy(&v, b, 8);
			r = kgenome_emu_fpd(opn, u, v, rc);
			memcpy(q + k * 8u, &r, 8);
		} else {
			uint32_t u, v, r;

			memcpy(&u, a, 4);
			memcpy(&v, b, 4);
			r = kgenome_emu_fps(opn, u, v, rc);
			memcpy(q + k * 4u, &r, 4);
		}
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* BLENDPS/PD (an immediate, a bit a lane), BLENDVPS/PD (the sign bit of a lane of xmm0) */
static int fp_blend(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16];
	unsigned nx, ny, k;
	const unsigned id = ixp->h.id;
	const int dbl = id == KGENOME_X86_I_BLENDPD || id == KGENOME_X86_I_BLENDVPD;
	const unsigned lw = dbl ? 8u : 4u;
	uint64_t sel = 0;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if ((id == KGENOME_X86_I_BLENDPS || id == KGENOME_X86_I_BLENDPD) &&
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < 16u / lw; k++) {
		const int take = (id == KGENOME_X86_I_BLENDPS || id == KGENOME_X86_I_BLENDPD)
				 ? (int)((sel >> k) & 1u) : (int)(e->xmm[0][k * lw + lw - 1u] >> 7);

		if (take)
			memcpy(x + k * lw, y + k * lw, lw);
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* MOVMSKPS/PD: the sign bits of the lanes, in the low bits of a general register. */
static int fp_movmsk(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16];
	unsigned ny, k;
	uint64_t m = 0;
	const int dbl = ixp->h.id == KGENOME_X86_I_MOVMSKPD;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < (dbl ? 2u : 4u); k++)
		m |= (uint64_t)(y[k * (dbl ? 8u : 4u) + (dbl ? 7u : 3u)] >> 7) << k;
	return kgenome_emu_op_wr(e, ixp, &ixp->op[0], m) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/*
 * ROUNDPS/PD/SS/SD (SSE4.1): imm bits 1-0 the rounding (nearest even, down, up, truncate), bit 2 says use MXCSR.RC
 * instead, bit 3 only suppresses the precision exception (nothing here). A NaN is quieted.
 */
static int fp_round(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16];
	unsigned nx, ny, k;
	uint64_t imm;
	const unsigned id = ixp->h.id;
	const int dbl = id == KGENOME_X86_I_ROUNDPD || id == KGENOME_X86_I_ROUNDSD;
	const int scalar = id == KGENOME_X86_I_ROUNDSS || id == KGENOME_X86_I_ROUNDSD;
	unsigned mode;

	if (!dst_rd(e, ixp, x) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &imm))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	(void)nx;
	mode = (imm & 4u) ? mx_rc(e) : (unsigned)(imm & 3u);
	for (k = 0; k < (scalar ? 1u : (dbl ? 2u : 4u)); k++) {
		if (dbl) {
			double d, r;
			uint64_t b;

			memcpy(&d, y + k * 8u, 8);
			memcpy(&b, y + k * 8u, 8);
			if (d != d) {
				b |= 0x0008000000000000ull;
				memcpy(x + k * 8u, &b, 8);
				continue;
			}
			r = mode == 1 ? floor(d) : mode == 2 ? ceil(d) : mode == 3 ? trunc(d) : nearbyint(d);
			if (r == 0.0)
				r = copysign(0.0, d);       /* the sign of a zero result is the operand's */
			memcpy(x + k * 8u, &r, 8);
		} else {
			float d, r;
			uint32_t b;

			memcpy(&d, y + k * 4u, 4);
			memcpy(&b, y + k * 4u, 4);
			if (d != d) {
				b |= 0x00400000u;
				memcpy(x + k * 4u, &b, 4);
				continue;
			}
			r = mode == 1 ? floorf(d) : mode == 2 ? ceilf(d) : mode == 3 ? truncf(d) : nearbyintf(d);
			if (r == 0.0f)
				r = copysignf(0.0f, d);
			memcpy(x + k * 4u, &r, 4);
		}
	}
	return dst_wr(e, ixp, x) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/*
 * INSERTPS: one float of the source (a register's lane selected by imm bits 7-6; a memory operand is the float itself) into the
 * destination lane imm bits 5-4 names, then every destination lane whose bit is set in imm bits 3-0 zeroed.
 * EXTRACTPS: the float in lane (imm & 3) of the source, to a general register (zero extended) or to memory.
 */
static int fp_insertps(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16];
	unsigned nx, ny, k;
	uint64_t imm;
	const int from_mem = ixp->op[1].type == KGENOME_X86_OP_MEM;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &imm))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memcpy(x + ((imm >> 4) & 3u) * 4u, y + (from_mem ? 0u : (unsigned)((imm >> 6) & 3u) * 4u), 4);
	for (k = 0; k < 4u; k++)
		if ((imm >> k) & 1u)
			memset(x + k * 4u, 0, 4);
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

static int fp_extractps(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16];
	unsigned ny;
	uint64_t imm, v = 0;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) || !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &imm))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memcpy(&v, y + (imm & 3u) * 4u, 4);
	return kgenome_emu_op_wr(e, ixp, &ixp->op[0], v) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/*
 * DPPS and DPPD: a masked dot product. The high immediate bits choose which products are formed (the rest are zero), the low
 * ones which result lanes receive the sum (the rest are zero). The sum is added the way the instruction's pseudo-code does:
 * DPPS (p0 + p1) + (p2 + p3), each product and each add rounded, with the NaN rules of the lane arithmetic.
 */
static int fp_dpp(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16] = { 0 };
	unsigned nx, ny, k;
	uint64_t imm;
	const unsigned rc = mx_rc(e);

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &imm))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	/*
	 * A NaN in an operand that takes part is REFUSED, not guessed at: which NaN comes out of the sum depends on the order the
	 * core adds in and on which operands it has already quieted, and the CPUs this was compared with give a different payload
	 * than the lane rules of the multiplies and adds do (a quiet NaN with its own payload where this gives the default one).
	 * An honest stop beats a plausible wrong NaN; every other operand - infinities and zeros included - is the CPU's answer.
	 */
	for (k = 0; k < (ixp->h.id == KGENOME_X86_I_DPPS ? 4u : 2u); k++) {
		if (!((imm >> (4u + k)) & 1u))
			continue;
		if (ixp->h.id == KGENOME_X86_I_DPPS) {
			float fa, fb;

			memcpy(&fa, x + k * 4u, 4);
			memcpy(&fb, y + k * 4u, 4);
			if (fa != fa || fb != fb)
				return KGENOME_EMU_RUN_UNSUPPORTED;
		} else {
			double da, db;

			memcpy(&da, x + k * 8u, 8);
			memcpy(&db, y + k * 8u, 8);
			if (da != da || db != db)
				return KGENOME_EMU_RUN_UNSUPPORTED;
		}
	}
	if (ixp->h.id == KGENOME_X86_I_DPPS) {
		uint32_t p[4], s, a, b;

		for (k = 0; k < 4u; k++) {
			memcpy(&a, x + k * 4u, 4);
			memcpy(&b, y + k * 4u, 4);
			p[k] = ((imm >> (4u + k)) & 1u) ? kgenome_emu_fps(KGENOME_EMU_FP_MUL, a, b, rc) : 0u;
		}
		s = kgenome_emu_fps(KGENOME_EMU_FP_ADD, kgenome_emu_fps(KGENOME_EMU_FP_ADD, p[0], p[1], rc),
				    kgenome_emu_fps(KGENOME_EMU_FP_ADD, p[2], p[3], rc), rc);
		for (k = 0; k < 4u; k++)
			if ((imm >> k) & 1u)
				memcpy(q + k * 4u, &s, 4);
	} else {
		uint64_t p[2], s, a, b;

		for (k = 0; k < 2u; k++) {
			memcpy(&a, x + k * 8u, 8);
			memcpy(&b, y + k * 8u, 8);
			p[k] = ((imm >> (4u + k)) & 1u) ? kgenome_emu_fpd(KGENOME_EMU_FP_MUL, a, b, rc) : 0u;
		}
		s = kgenome_emu_fpd(KGENOME_EMU_FP_ADD, p[0], p[1], rc);
		for (k = 0; k < 2u; k++)
			if ((imm >> k) & 1u)
				memcpy(q + k * 8u, &s, 8);
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* ---- conversions ------------------------------------------------------------------------------- */

static int fp_cvt(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, k, w = 16;
	const unsigned id = ixp->h.id, rc = mx_rc(e);

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	memset(q, 0, 16);
	switch (id) {
	case KGENOME_X86_I_CVTDQ2PS:
		for (k = 0; k < 4u; k++) {
			int32_t n;
			uint32_t r;

			memcpy(&n, y + k * 4u, 4);
			r = kgenome_emu_i2f(n, rc);
			memcpy(q + k * 4u, &r, 4);
		}
		break;
	case KGENOME_X86_I_CVTDQ2PD:
		for (k = 0; k < 2u; k++) {
			int32_t n;
			uint64_t r;

			memcpy(&n, y + k * 4u, 4);
			r = kgenome_emu_i2d(n, rc);
			memcpy(q + k * 8u, &r, 8);
		}
		break;
	case KGENOME_X86_I_CVTPS2DQ: case KGENOME_X86_I_CVTTPS2DQ:
		for (k = 0; k < 4u; k++) {
			float f;
			uint32_t r;

			memcpy(&f, y + k * 4u, 4);
			r = (uint32_t)kgenome_emu_f2i((double)f, 32, id == KGENOME_X86_I_CVTTPS2DQ, rc);
			memcpy(q + k * 4u, &r, 4);
		}
		break;
	case KGENOME_X86_I_CVTPD2DQ: case KGENOME_X86_I_CVTTPD2DQ:
		for (k = 0; k < 2u; k++) {
			double d;
			uint32_t r;

			memcpy(&d, y + k * 8u, 8);
			r = (uint32_t)kgenome_emu_f2i(d, 32, id == KGENOME_X86_I_CVTTPD2DQ, rc);
			memcpy(q + k * 4u, &r, 4);
		}
		break;
	case KGENOME_X86_I_CVTPS2PD:
		for (k = 0; k < 2u; k++) {
			uint32_t b;
			uint64_t r;

			memcpy(&b, y + k * 4u, 4);
			r = kgenome_emu_f2d(b);
			memcpy(q + k * 8u, &r, 8);
		}
		break;
	case KGENOME_X86_I_CVTPD2PS:
		for (k = 0; k < 2u; k++) {
			uint64_t b;
			uint32_t r;

			memcpy(&b, y + k * 8u, 8);
			r = kgenome_emu_d2f(b, rc);
			memcpy(q + k * 4u, &r, 4);
		}
		break;
	case KGENOME_X86_I_CVTPI2PS: case KGENOME_X86_I_CVTPI2PD: {
		/* two int32 of an MMX register or m64: to the low two floats (the upper half of the destination is
		 * kept) or to two doubles */
		const int dbl = id == KGENOME_X86_I_CVTPI2PD;

		if (!dst_rd(e, ixp, x))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		(void)nx;
		memcpy(q, x, 16);
		for (k = 0; k < 2u; k++) {
			int32_t n;

			memcpy(&n, y + k * 4u, 4);
			if (dbl) {
				const uint64_t r = kgenome_emu_i2d(n, rc);

				memcpy(q + k * 8u, &r, 8);
			} else {
				const uint32_t r = kgenome_emu_i2f(n, rc);

				memcpy(q + k * 4u, &r, 4);
			}
		}
		return dst_wr(e, ixp, q) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
	}
	case KGENOME_X86_I_CVTPS2PI: case KGENOME_X86_I_CVTTPS2PI:
		w = 8;
		for (k = 0; k < 2u; k++) {
			float f;
			uint32_t r;

			memcpy(&f, y + k * 4u, 4);
			r = (uint32_t)kgenome_emu_f2i((double)f, 32, id == KGENOME_X86_I_CVTTPS2PI, rc);
			memcpy(q + k * 4u, &r, 4);
		}
		break;
	case KGENOME_X86_I_CVTPD2PI: case KGENOME_X86_I_CVTTPD2PI:
		w = 8;
		for (k = 0; k < 2u; k++) {
			double d;
			uint32_t r;

			memcpy(&d, y + k * 8u, 8);
			r = (uint32_t)kgenome_emu_f2i(d, 32, id == KGENOME_X86_I_CVTTPD2PI, rc);
			memcpy(q + k * 4u, &r, 4);
		}
		break;
	default: {                                  /* CVTSD2SI, CVTSS2SI: one value to a general register */
		const unsigned bits = ixp->op[0].size == 8 ? 64u : 32u;
		double d;

		if (id == KGENOME_X86_I_CVTSD2SI) {
			memcpy(&d, y, 8);
		} else {
			float f;

			memcpy(&f, y, 4);
			d = f;
		}
		return kgenome_emu_op_wr(e, ixp, &ixp->op[0], kgenome_emu_f2i(d, bits, 0, rc)) ? KGENOME_EMU_RUN_OK
											       : KGENOME_EMU_RUN_UNSUPPORTED;
	}
	}
	return kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, w) ? KGENOME_EMU_RUN_OK : KGENOME_EMU_RUN_UNSUPPORTED;
}

/* ---- the entry -------------------------------------------------------------------------------- */

int kgenome_emu_run_vec_fp(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	unsigned op;
	int dbl;

	if (fp_class(ixp->h.id, &op, &dbl))
		return fp_packed(e, ixp, op, dbl);
	switch (ixp->h.id) {
	case KGENOME_X86_I_CMPPS: return fp_cmp(e, ixp, 0, 0);
	case KGENOME_X86_I_CMPPD: return fp_cmp(e, ixp, 1, 0);
	case KGENOME_X86_I_CMPSS: return fp_cmp(e, ixp, 0, 1);
	case KGENOME_X86_I_CMPSD: return fp_cmp(e, ixp, 1, 1);
	case KGENOME_X86_I_UNPCKLPS: case KGENOME_X86_I_UNPCKHPS: case KGENOME_X86_I_UNPCKLPD:
	case KGENOME_X86_I_UNPCKHPD: case KGENOME_X86_I_SHUFPS: case KGENOME_X86_I_SHUFPD:
	case KGENOME_X86_I_MOVSHDUP: case KGENOME_X86_I_MOVSLDUP: case KGENOME_X86_I_MOVDDUP:
		return fp_shuffle(e, ixp);
	case KGENOME_X86_I_HADDPS: case KGENOME_X86_I_HADDPD: case KGENOME_X86_I_HSUBPS:
	case KGENOME_X86_I_HSUBPD: case KGENOME_X86_I_ADDSUBPS: case KGENOME_X86_I_ADDSUBPD:
		return fp_horiz(e, ixp);
	case KGENOME_X86_I_BLENDPS: case KGENOME_X86_I_BLENDPD: case KGENOME_X86_I_BLENDVPS:
	case KGENOME_X86_I_BLENDVPD:
		return fp_blend(e, ixp);
	case KGENOME_X86_I_MOVMSKPS: case KGENOME_X86_I_MOVMSKPD:
		return fp_movmsk(e, ixp);
	case KGENOME_X86_I_ROUNDPS: case KGENOME_X86_I_ROUNDPD: case KGENOME_X86_I_ROUNDSS:
	case KGENOME_X86_I_ROUNDSD:
		return fp_round(e, ixp);
	case KGENOME_X86_I_INSERTPS:
		return fp_insertps(e, ixp);
	case KGENOME_X86_I_EXTRACTPS:
		return fp_extractps(e, ixp);
	case KGENOME_X86_I_DPPS: case KGENOME_X86_I_DPPD:
		return fp_dpp(e, ixp);
	case KGENOME_X86_I_CVTDQ2PS: case KGENOME_X86_I_CVTDQ2PD: case KGENOME_X86_I_CVTPS2DQ:
	case KGENOME_X86_I_CVTTPS2DQ: case KGENOME_X86_I_CVTPD2DQ: case KGENOME_X86_I_CVTTPD2DQ:
	case KGENOME_X86_I_CVTPS2PD: case KGENOME_X86_I_CVTPD2PS: case KGENOME_X86_I_CVTPI2PS:
	case KGENOME_X86_I_CVTPI2PD: case KGENOME_X86_I_CVTPS2PI: case KGENOME_X86_I_CVTTPS2PI:
	case KGENOME_X86_I_CVTPD2PI: case KGENOME_X86_I_CVTTPD2PI: case KGENOME_X86_I_CVTSD2SI:
	case KGENOME_X86_I_CVTSS2SI:
		return fp_cvt(e, ixp);
	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
}
