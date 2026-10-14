/*
 * emu_vec.c - the SSE subset of the interpreter.
 * Part of the interpreter; see emu_interp.c and emu_private.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "emu_private.h"


/*
 * the bitwise operators and PCMPEQB/PSUBB over a whole register
 */
static inline int vec_xorps(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16];
	unsigned nx, ny, k;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
	    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < 16; k++)
		switch (ixp->h.id) {
		case KGENOME_X86_I_XORPS: case KGENOME_X86_I_XORPD:
		case KGENOME_X86_I_PXOR:    x[k] ^= y[k]; break;
		case KGENOME_X86_I_POR:  case KGENOME_X86_I_ORPS:
		case KGENOME_X86_I_ORPD:    x[k] |= y[k]; break;
		case KGENOME_X86_I_PAND: case KGENOME_X86_I_ANDPS:
		case KGENOME_X86_I_ANDPD:   x[k] &= y[k]; break;
		case KGENOME_X86_I_PANDN: case KGENOME_X86_I_ANDNPS:
		case KGENOME_X86_I_ANDNPD:  x[k] = (uint8_t)(~x[k] & y[k]); break;
		case KGENOME_X86_I_PSUBB:   x[k] = (uint8_t)(x[k] - y[k]); break;
		default:             x[k] = x[k] == y[k] ? 0xffu : 0u; break;
		}
	if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, nx))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/*
 * scalar double and single arithmetic: the result replaces the LOW lane of the destination register and
 * the lane above it is left alone (SDM: ADDSD "bits 127:64 of the destination are unchanged"; the single
 * forms leave bits 127:32). The lane arithmetic - NaNs, the indefinite, MIN and MAX, the rounding MXCSR asks
 * for - is the packed instructions' too, and lives with them in emu_vec_fp.c: one answer for one lane.
 */
static inline int vec_addsd(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16];
	unsigned ny, op, rc = (e->mxcsr >> 13) & 3u;
	uint8_t *d = kgenome_emu_xmm_of(e, &ixp->op[0]);
	int dbl = 1;

	switch (ixp->h.id) {
	case KGENOME_X86_I_ADDSD: op = KGENOME_EMU_FP_ADD; break;
	case KGENOME_X86_I_SUBSD: op = KGENOME_EMU_FP_SUB; break;
	case KGENOME_X86_I_MULSD: op = KGENOME_EMU_FP_MUL; break;
	case KGENOME_X86_I_DIVSD: op = KGENOME_EMU_FP_DIV; break;
	case KGENOME_X86_I_MINSD: op = KGENOME_EMU_FP_MIN; break;
	case KGENOME_X86_I_MAXSD: op = KGENOME_EMU_FP_MAX; break;
	case KGENOME_X86_I_SQRTSD: op = KGENOME_EMU_FP_SQRT; break;
	default:
		dbl = 0;
		switch (ixp->h.id) {
		case KGENOME_X86_I_ADDSS: op = KGENOME_EMU_FP_ADD; break;
		case KGENOME_X86_I_SUBSS: op = KGENOME_EMU_FP_SUB; break;
		case KGENOME_X86_I_MULSS: op = KGENOME_EMU_FP_MUL; break;
		case KGENOME_X86_I_DIVSS: op = KGENOME_EMU_FP_DIV; break;
		case KGENOME_X86_I_MINSS: op = KGENOME_EMU_FP_MIN; break;
		case KGENOME_X86_I_MAXSS: op = KGENOME_EMU_FP_MAX; break;
		default:                  op = KGENOME_EMU_FP_SQRT; break;
		}
	}
	if (!d || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (dbl) {
		uint64_t ub, vb, rb;

		memcpy(&ub, d, 8);
		memcpy(&vb, y, 8);
		rb = kgenome_emu_fpd(op, ub, vb, rc);
		memcpy(d, &rb, 8);
	} else {
		uint32_t ub, vb, rb;

		memcpy(&ub, d, 4);
		memcpy(&vb, y, 4);
		rb = kgenome_emu_fps(op, ub, vb, rc);
		memcpy(d, &rb, 4);
	}
	return KGENOME_EMU_RUN_OK;
}

/*
 * scalar compares into EFLAGS
 */
static inline int vec_ucomisd(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16];
	unsigned nx, ny;
	int dbl = ixp->h.id == KGENOME_X86_I_UCOMISD ||
		  ixp->h.id == KGENOME_X86_I_COMISD;
	double u, v;
	float fu, fv;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
	    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (dbl) { memcpy(&u, x, 8); memcpy(&v, y, 8); }
	else     { memcpy(&fu, x, 4); memcpy(&fv, y, 4); u = fu; v = fv; }
	e->flags &= ~(uint64_t)(KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF |
				KGENOME_EMU_FL_SF | KGENOME_EMU_FL_AF);
	if (u != u || v != v)          /* unordered */
		e->flags |= KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF;
	else if (u < v)                e->flags |= KGENOME_EMU_FL_CF;
	else if (u == v)               e->flags |= KGENOME_EMU_FL_ZF;
	return KGENOME_EMU_RUN_OK;
}

/*
 * int/double/single conversions into a register. Each writes the low lane of the destination only: the
 * rest of the register is unchanged (SDM CVTSI2SD, CVTSI2SS, CVTSD2SS, CVTSS2SD). A NaN converts to a
 * QUIET NaN with the sign kept and the payload cut or widened to the new format's fraction.
 */
static inline int vec_cvtsi2sd(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16];
	unsigned ny, rc = (e->mxcsr >> 13) & 3u;
	uint8_t *dst = kgenome_emu_xmm_of(e, &ixp->op[0]);

	if (!dst)
		return KGENOME_EMU_RUN_UNSUPPORTED;
	switch (ixp->h.id) {
	case KGENOME_X86_I_CVTSI2SD: case KGENOME_X86_I_CVTSI2SS: {
		uint64_t a = 0;
		int64_t n;

		if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		n = (int64_t)kgenome_emu_sext(a, ixp->op[1].size ? ixp->op[1].size : 8u);
		if (ixp->h.id == KGENOME_X86_I_CVTSI2SS) {
			const uint32_t f = kgenome_emu_i2f(n, rc);        /* one rounding, not int -> double -> float */

			memcpy(dst, &f, 4);
		} else {
			const uint64_t d = kgenome_emu_i2d(n, rc);

			memcpy(dst, &d, 8);
		}
		break;
	}
	case KGENOME_X86_I_CVTSS2SD: {
		uint32_t b;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		memcpy(&b, y, 4);
		{
			const uint64_t q = kgenome_emu_f2d(b);

			memcpy(dst, &q, 8);
		}
		break;
	}
	default: {                                 /* CVTSD2SS */
		uint64_t b;
		uint32_t r;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		memcpy(&b, y, 8);
		r = kgenome_emu_d2f(b, rc);
		memcpy(dst, &r, 4);
		break;
	}
	}
	return KGENOME_EMU_RUN_OK;
}

/*
 * truncating conversion to an integer register (SDM CVTTSD2SI, CVTTSS2SI): rounds toward zero, and a NaN
 * or a value that does not fit the 32 or 64 bit destination gives the INTEGER INDEFINITE, the most
 * negative integer of the destination's width (0x80000000, 0x8000000000000000).
 */
static inline int vec_cvttsd2si(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16];
	unsigned ny, w = ixp->op[0].size == 8 ? 64u : 32u;
	double d;
	float f;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (ixp->h.id == KGENOME_X86_I_CVTTSD2SI)
		memcpy(&d, y, 8);
	else { memcpy(&f, y, 4); d = f; }
	if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], kgenome_emu_f2i(d, w, 1, 0)))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/*
 * the moves that touch HALF a register or merge into one (SDM):
 *   MOVSS/MOVSD  xmm, xmm     replace the low 32/64 bits, keep the rest (from memory they zero the rest)
 *   MOVLHPS      xmm, xmm     high 64 bits of the destination = low 64 bits of the source, low kept
 *   MOVHLPS      xmm, xmm     low 64 bits of the destination = high 64 bits of the source, high kept
 *   MOVLPS/MOVLPD xmm, m64    low 64 bits loaded, high kept;  m64, xmm  stores the low 64 bits
 * The decoder names 0F 12 by its ModRM mod field: MOVHLPS for a register source, MOVLPS for memory, as
 * the manual does (the reference decoder named both MOVHLPS; tools/genotype/oracle_fix.h puts that
 * right where the table is made), so MOVHLPS here always has two registers.
 */
static inline int vec_halfmove(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t *d = kgenome_emu_xmm_of(e, &ixp->op[0]);
	uint8_t *s = kgenome_emu_xmm_of(e, &ixp->op[1]);
	uint8_t v[16];
	unsigned n;

	switch (ixp->h.id) {
	case KGENOME_X86_I_MOVSS: case KGENOME_X86_I_MOVSD:
		if (!d || !s)
			return KGENOME_EMU_RUN_NOT_MINE;       /* a load or a store: the generic move */
		memcpy(d, s, ixp->h.id == KGENOME_X86_I_MOVSS ? 4u : 8u);
		return KGENOME_EMU_RUN_OK;
	case KGENOME_X86_I_MOVLHPS:
		if (!d || !s)
			return KGENOME_EMU_RUN_UNSUPPORTED;
		memcpy(d + 8, s, 8);
		return KGENOME_EMU_RUN_OK;
	case KGENOME_X86_I_MOVHLPS:
		if (!d || !s)
			return KGENOME_EMU_RUN_UNSUPPORTED;
		memcpy(d, s + 8, 8);
		return KGENOME_EMU_RUN_OK;
	default:                                   /* MOVLPS, MOVLPD */
		if (d) {                               /* load */
			if (ixp->op[1].type != KGENOME_X86_OP_MEM ||
			    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], v, &n))
				return KGENOME_EMU_RUN_UNSUPPORTED;
			memcpy(d, v, 8);
			return KGENOME_EMU_RUN_OK;
		}
		if (!s || !kgenome_emu_vec_wr(e, ixp, &ixp->op[0], s, 8))   /* store the low half */
			return KGENOME_EMU_RUN_UNSUPPORTED;
		return KGENOME_EMU_RUN_OK;
	}
}

/*
 * the high half moves
 */
static inline int vec_movhps(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16];
	unsigned nx, ny;

	if (ixp->op[0].type == KGENOME_X86_OP_MEM) {
		/* store: the HIGH 64 bits of the register go to memory (the decoder sizes the register operand at 8,
		 * so reading it through the operand would give the low half) */
		uint8_t *sx = kgenome_emu_xmm_of(e, &ixp->op[1]);

		(void)y; (void)ny;
		if (!sx || !kgenome_emu_vec_wr(e, ixp, &ixp->op[0], sx + 8, 8))
			return KGENOME_EMU_RUN_UNSUPPORTED;
	} else {
		/* load: the high 64 bits are replaced, the low 64 bits stay */
		uint8_t *d = kgenome_emu_xmm_of(e, &ixp->op[0]);

		(void)x; (void)nx;
		if (!d || !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			return KGENOME_EMU_RUN_UNSUPPORTED;
		memcpy(d + 8, y, 8);
	}
	return KGENOME_EMU_RUN_OK;
}

/*
 * insert one word
 */
static inline int vec_pinsrw(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16];
	unsigned nx;
	uint64_t v, sel;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &v) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	/* an MMX register has four words, an xmm one eight */
	sel &= ixp->op[0].rtype == KGENOME_X86_REG_MMX ? 3u : 7u;
	x[sel * 2u]      = (uint8_t)v;
	x[sel * 2u + 1u] = (uint8_t)(v >> 8);
	if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, ixp->op[0].rtype == KGENOME_X86_REG_MMX ? 8u : 16u))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/*
 * extract one word
 */
static inline int vec_pextrw(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16];
	unsigned ny;
	uint64_t sel;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	sel &= ixp->op[1].rtype == KGENOME_X86_REG_MMX ? 3u : 7u;
	if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0],
		   (uint64_t)y[sel * 2u] |
		   ((uint64_t)y[sel * 2u + 1u] << 8)))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/*
 * byte sign mask
 */
static inline int vec_pmovmskb(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16];
	unsigned ny, k;
	uint64_t m = 0;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < 16; k++)
		m |= (uint64_t)(y[k] >> 7) << k;
	if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], m))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/*
 * whole-register byte shifts
 */
static inline int vec_pslldq(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], q[16] = { 0 };
	unsigned nx, k;
	uint64_t sh;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &sh))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	if (sh < 16)
		for (k = 0; k < 16u - sh; k++) {
			if (ixp->h.id == KGENOME_X86_I_PSLLDQ)
				q[k + sh] = x[k];
			else
				q[k] = x[k + sh];
		}
	if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/*
 * interleave the low bytes
 */
static inline int vec_punpcklbw(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t x[16], y[16], q[16];
	unsigned nx, ny, k;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
	    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < 8; k++) {
		q[k * 2u]      = x[k];
		q[k * 2u + 1u] = y[k];
	}
	if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/*
 * shuffle dwords
 */
static inline int vec_pshufd(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint8_t y[16], q[16];
	unsigned ny, k;
	uint64_t sel;

	if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
	    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	for (k = 0; k < 4; k++)
		memcpy(q + k * 4u, y + ((sel >> (k * 2u)) & 3u) * 4u, 4);
	if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16))
		return KGENOME_EMU_RUN_UNSUPPORTED;
	return KGENOME_EMU_RUN_OK;
}

/*
 * Execute the SSE subset; see the comment on its first case.
 *
 * One arm of the dispatch in kgenome_emu_run, moved out so that the loop stays
 * readable and the instructions nobody runs often are not in it. Returns
 * KGENOME_EMU_RUN_NOT_MINE for an id that is not one of its own; the loop then asks the next.
 */
int kgenome_emu_run_vec(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	switch (ixp->h.id) {
	/*
	 * The SSE a runtime uses to move and compare bytes. The vector
	 * arithmetic is NOT here and is no longer absent: the packed integer
	 * set is emu_vec_int.c, the packed floating point set and the
	 * conversions emu_vec_fp.c, each reached from the default arm below,
	 * and every instruction in them is compared with the host CPU
	 * (tests/lib/genome/diff_vec_packed.c). What is left out is listed,
	 * with the reason, in tests/lib/genome/diff_decode_cover.c.
	 */
	case KGENOME_X86_I_MOVUPS: case KGENOME_X86_I_MOVAPS:
	case KGENOME_X86_I_MOVUPD: case KGENOME_X86_I_MOVAPD:
	case KGENOME_X86_I_MOVDQU: case KGENOME_X86_I_MOVDQA:
	case KGENOME_X86_I_MOVSS:  case KGENOME_X86_I_MOVSD:
	case KGENOME_X86_I_MOVD:   case KGENOME_X86_I_MOVQ:
	/* The non-temporal stores and loads are plain ones here (there is no cache to bypass), LDDQU is an
	 * unaligned load, and MOVQ2DQ / MOVDQ2Q move the low quadword between an MMX and an xmm register. */
	case KGENOME_X86_I_MOVNTDQ: case KGENOME_X86_I_MOVNTDQA: case KGENOME_X86_I_MOVNTPS:
	case KGENOME_X86_I_MOVNTPD: case KGENOME_X86_I_MOVNTQ:  case KGENOME_X86_I_MOVNTI:
	case KGENOME_X86_I_MOVNTSD: case KGENOME_X86_I_MOVNTSS:
	case KGENOME_X86_I_LDDQU:   case KGENOME_X86_I_MOVQ2DQ: case KGENOME_X86_I_MOVDQ2Q:
	/* The half-register loads and stores a memcpy is built from. */
	case KGENOME_X86_I_MOVLPS: case KGENOME_X86_I_MOVLPD:
	case KGENOME_X86_I_MOVHLPS: case KGENOME_X86_I_MOVLHPS: {
		uint8_t v[16];
		unsigned n;

		if (ixp->h.id == KGENOME_X86_I_MOVSS || ixp->h.id == KGENOME_X86_I_MOVSD ||
		    ixp->h.id == KGENOME_X86_I_MOVLPS || ixp->h.id == KGENOME_X86_I_MOVLPD ||
		    ixp->h.id == KGENOME_X86_I_MOVHLPS || ixp->h.id == KGENOME_X86_I_MOVLHPS) {
			int rc = vec_halfmove(e, ixp);

			if (rc != KGENOME_EMU_RUN_NOT_MINE)
				return rc;
		}
		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], v, &n) ||
		    !kgenome_emu_vec_wr(e, ixp, &ixp->op[0], v, n))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_XORPS: case KGENOME_X86_I_XORPD: case KGENOME_X86_I_PXOR:
	case KGENOME_X86_I_POR:   case KGENOME_X86_I_PAND:  case KGENOME_X86_I_PANDN:
	case KGENOME_X86_I_ORPS:  case KGENOME_X86_I_ORPD:
	case KGENOME_X86_I_ANDPS: case KGENOME_X86_I_ANDPD:
	case KGENOME_X86_I_ANDNPS: case KGENOME_X86_I_ANDNPD:
	case KGENOME_X86_I_PCMPEQB: case KGENOME_X86_I_PSUBB:
		return vec_xorps(e, ixp);

	/*
	 * SCALAR DOUBLE AND SINGLE, WHICH IS NOT OPTIONAL EITHER.
	 *
	 * No packer needs floating point to unpack, but a Go runtime
	 * checks its own arithmetic before running anything and traps
	 * when the answers are wrong - so a Go-built packer never
	 * reaches its payload without these. The host is IEEE754 and
	 * so is the guest, so the host's own double does the work.
	 */
	case KGENOME_X86_I_ADDSD: case KGENOME_X86_I_SUBSD: case KGENOME_X86_I_MULSD:
	case KGENOME_X86_I_DIVSD: case KGENOME_X86_I_MAXSD: case KGENOME_X86_I_MINSD:
	case KGENOME_X86_I_SQRTSD:
	case KGENOME_X86_I_ADDSS: case KGENOME_X86_I_SUBSS: case KGENOME_X86_I_MULSS:
	case KGENOME_X86_I_DIVSS: case KGENOME_X86_I_MINSS: case KGENOME_X86_I_MAXSS:
	case KGENOME_X86_I_SQRTSS:
		return vec_addsd(e, ixp);

	case KGENOME_X86_I_UCOMISD: case KGENOME_X86_I_COMISD:
	case KGENOME_X86_I_UCOMISS: case KGENOME_X86_I_COMISS:
		return vec_ucomisd(e, ixp);

	case KGENOME_X86_I_CVTSI2SD: case KGENOME_X86_I_CVTSI2SS:
	case KGENOME_X86_I_CVTSD2SS: case KGENOME_X86_I_CVTSS2SD:
		return vec_cvtsi2sd(e, ixp);

	case KGENOME_X86_I_CVTTSD2SI: case KGENOME_X86_I_CVTTSS2SI:
		return vec_cvttsd2si(e, ixp);

	/*
	 * The high half, and the one-word insert and extract. Present
	 * because real samples stopped on them: a UPX payload's own
	 * startup used MOVHPS and another used PINSRW, and one
	 * unimplemented opcode ends a run that had otherwise reached
	 * its payload.
	 */
	case KGENOME_X86_I_MOVHPS: case KGENOME_X86_I_MOVHPD:
		return vec_movhps(e, ixp);

	case KGENOME_X86_I_PINSRW:
		return vec_pinsrw(e, ixp);

	case KGENOME_X86_I_PEXTRW:
		return vec_pextrw(e, ixp);

	case KGENOME_X86_I_PMOVMSKB:
		return vec_pmovmskb(e, ixp);

	case KGENOME_X86_I_PSLLDQ: case KGENOME_X86_I_PSRLDQ:
		return vec_pslldq(e, ixp);

	case KGENOME_X86_I_PUNPCKLBW:
		return vec_punpcklbw(e, ixp);

	case KGENOME_X86_I_PSHUFD:
		return vec_pshufd(e, ixp);
	default:
		return kgenome_emu_run_vec_int(e, ixp);
	}
	return KGENOME_EMU_RUN_OK;

unsupported:
	return KGENOME_EMU_RUN_UNSUPPORTED;
}
