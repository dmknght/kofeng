/*
 * kofemu_vec.c - the SSE subset of the interpreter.
 * Part of the interpreter; see kofemu.c and kofemu_int.h.
 */
#define _POSIX_C_SOURCE 199309L

#include "kofemu_int.h"


/*
 * Execute the SSE subset; see the comment on its first case.
 *
 * One arm of the dispatch in kgenome_emu_run, moved out so that the loop stays
 * readable and the instructions nobody runs often are not in it. Returns
 * KGENOME_EMU_RUN_NOT_MINE for an id that is not one of its own; the loop then asks the next.
 */
int kgenome_emu_run_vec(struct kgenome_emu *e, struct kgenome_emu_insn *ixp)
{
	uint64_t a = 0;

	switch (ixp->h.id) {
	/*
	 * The SSE a runtime uses to move and compare bytes. Vector
	 * arithmetic is deliberately absent: nothing that unpacks a
	 * payload needs it, and guessing at it would produce wrong
	 * bytes instead of an honest stop.
	 */
	case KGENOME_X86_I_MOVUPS: case KGENOME_X86_I_MOVAPS:
	case KGENOME_X86_I_MOVUPD: case KGENOME_X86_I_MOVAPD:
	case KGENOME_X86_I_MOVDQU: case KGENOME_X86_I_MOVDQA:
	case KGENOME_X86_I_MOVSS:  case KGENOME_X86_I_MOVSD:
	case KGENOME_X86_I_MOVD:   case KGENOME_X86_I_MOVQ:
	/* The half-register loads and stores a memcpy is built from. */
	case KGENOME_X86_I_MOVLPS: case KGENOME_X86_I_MOVLPD: {
		uint8_t v[16];
		unsigned n;

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
	case KGENOME_X86_I_PCMPEQB: case KGENOME_X86_I_PSUBB: {
		uint8_t x[16], y[16];
		unsigned nx, ny, k;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
		    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			goto unsupported;
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
			goto unsupported;
		break;
	}

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
	case KGENOME_X86_I_DIVSS: {
		uint8_t x[16], y[16];
		unsigned nx, ny;
		int dbl = ixp->h.id == KGENOME_X86_I_ADDSD ||
			  ixp->h.id == KGENOME_X86_I_SUBSD ||
			  ixp->h.id == KGENOME_X86_I_MULSD ||
			  ixp->h.id == KGENOME_X86_I_DIVSD ||
			  ixp->h.id == KGENOME_X86_I_MAXSD ||
			  ixp->h.id == KGENOME_X86_I_MINSD ||
			  ixp->h.id == KGENOME_X86_I_SQRTSD;
		double u, v, w;
		float  fu, fv, fw;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
		    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			goto unsupported;
		if (dbl) { memcpy(&u, x, 8); memcpy(&v, y, 8); }
		else     { memcpy(&fu, x, 4); memcpy(&fv, y, 4); u = fu; v = fv; }
		switch (ixp->h.id) {
		case KGENOME_X86_I_ADDSD: case KGENOME_X86_I_ADDSS: w = u + v; break;
		case KGENOME_X86_I_SUBSD: case KGENOME_X86_I_SUBSS: w = u - v; break;
		case KGENOME_X86_I_MULSD: case KGENOME_X86_I_MULSS: w = u * v; break;
		case KGENOME_X86_I_DIVSD: case KGENOME_X86_I_DIVSS: w = u / v; break;
		case KGENOME_X86_I_MAXSD: w = v > u ? v : u; break;
		case KGENOME_X86_I_MINSD: w = v < u ? v : u; break;
		default:           w = v >= 0 ? sqrt(v) : (v - v) / (v - v); break;
		}
		if (dbl) { memcpy(x, &w, 8); }
		else     { fw = (float)w; memcpy(x, &fw, 4); }
		if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, nx))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_UCOMISD: case KGENOME_X86_I_COMISD:
	case KGENOME_X86_I_UCOMISS: case KGENOME_X86_I_COMISS: {
		uint8_t x[16], y[16];
		unsigned nx, ny;
		int dbl = ixp->h.id == KGENOME_X86_I_UCOMISD ||
			  ixp->h.id == KGENOME_X86_I_COMISD;
		double u, v;
		float fu, fv;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
		    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			goto unsupported;
		if (dbl) { memcpy(&u, x, 8); memcpy(&v, y, 8); }
		else     { memcpy(&fu, x, 4); memcpy(&fv, y, 4); u = fu; v = fv; }
		e->flags &= ~(uint64_t)(KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF | KGENOME_EMU_FL_OF |
					KGENOME_EMU_FL_SF | KGENOME_EMU_FL_AF);
		if (u != u || v != v)          /* unordered */
			e->flags |= KGENOME_EMU_FL_ZF | KGENOME_EMU_FL_PF | KGENOME_EMU_FL_CF;
		else if (u < v)                e->flags |= KGENOME_EMU_FL_CF;
		else if (u == v)               e->flags |= KGENOME_EMU_FL_ZF;
		break;
	}

	case KGENOME_X86_I_CVTSI2SD: case KGENOME_X86_I_CVTSI2SS:
	case KGENOME_X86_I_CVTSD2SS: case KGENOME_X86_I_CVTSS2SD: {
		uint8_t x[16] = { 0 }, y[16];
		unsigned ny;
		double d;
		float f;

		if (ixp->h.id == KGENOME_X86_I_CVTSI2SD ||
		    ixp->h.id == KGENOME_X86_I_CVTSI2SS) {
			if (!kgenome_emu_op_rd(e, ixp, &ixp->op[1], &a))
				goto unsupported;
			d = (double)(int64_t)kgenome_emu_sext(a,
				ixp->op[1].size ? ixp->op[1].size : 8u);
		} else {
			if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
				goto unsupported;
			if (ixp->h.id == KGENOME_X86_I_CVTSS2SD) {
				memcpy(&f, y, 4); d = f;
			} else {
				memcpy(&d, y, 8);
			}
		}
		if (ixp->h.id == KGENOME_X86_I_CVTSI2SS ||
		    ixp->h.id == KGENOME_X86_I_CVTSD2SS) {
			f = (float)d; memcpy(x, &f, 4);
		} else {
			memcpy(x, &d, 8);
		}
		if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, 16))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_CVTTSD2SI: case KGENOME_X86_I_CVTTSS2SI: {
		uint8_t y[16];
		unsigned ny;
		double d;
		float f;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			goto unsupported;
		if (ixp->h.id == KGENOME_X86_I_CVTTSD2SI)
			memcpy(&d, y, 8);
		else { memcpy(&f, y, 4); d = f; }
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], (uint64_t)(int64_t)d))
			goto unsupported;
		break;
	}

	/*
	 * The high half, and the one-word insert and extract. Present
	 * because real samples stopped on them: a UPX payload's own
	 * startup used MOVHPS and another used PINSRW, and one
	 * unimplemented opcode ends a run that had otherwise reached
	 * its payload.
	 */
	case KGENOME_X86_I_MOVHPS: case KGENOME_X86_I_MOVHPD: {
		uint8_t x[16], y[16];
		unsigned nx, ny;

		if (ixp->op[0].type == KGENOME_X86_OP_MEM) {
			/* store: the high half goes to memory */
			if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
				goto unsupported;
			if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], y + 8, 8))
				goto unsupported;
		} else {
			if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
			    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
				goto unsupported;
			memcpy(x + 8, y, 8);
			if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, 16))
				goto unsupported;
		}
		break;
	}

	case KGENOME_X86_I_PINSRW: {
		uint8_t x[16];
		unsigned nx;
		uint64_t v, sel;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &v) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
			goto unsupported;
		x[(sel & 7u) * 2u]      = (uint8_t)v;
		x[(sel & 7u) * 2u + 1u] = (uint8_t)(v >> 8);
		if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], x, 16))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_PEXTRW: {
		uint8_t y[16];
		unsigned ny;
		uint64_t sel;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
			goto unsupported;
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0],
			   (uint64_t)y[(sel & 7u) * 2u] |
			   ((uint64_t)y[(sel & 7u) * 2u + 1u] << 8)))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_PMOVMSKB: {
		uint8_t y[16];
		unsigned ny, k;
		uint64_t m = 0;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			goto unsupported;
		for (k = 0; k < 16; k++)
			m |= (uint64_t)(y[k] >> 7) << k;
		if (!kgenome_emu_op_wr(e, ixp, &ixp->op[0], m))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_PSLLDQ: case KGENOME_X86_I_PSRLDQ: {
		uint8_t x[16], q[16] = { 0 };
		unsigned nx, k;
		uint64_t sh;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[1], &sh))
			goto unsupported;
		if (sh < 16)
			for (k = 0; k < 16u - sh; k++) {
				if (ixp->h.id == KGENOME_X86_I_PSLLDQ)
					q[k + sh] = x[k];
				else
					q[k] = x[k + sh];
			}
		if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_PUNPCKLBW: {
		uint8_t x[16], y[16], q[16];
		unsigned nx, ny, k;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[0], x, &nx) ||
		    !kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny))
			goto unsupported;
		for (k = 0; k < 8; k++) {
			q[k * 2u]      = x[k];
			q[k * 2u + 1u] = y[k];
		}
		if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16))
			goto unsupported;
		break;
	}

	case KGENOME_X86_I_PSHUFD: {
		uint8_t y[16], q[16];
		unsigned ny, k;
		uint64_t sel;

		if (!kgenome_emu_vec_rd(e, ixp, &ixp->op[1], y, &ny) ||
		    !kgenome_emu_op_rd(e, ixp, &ixp->op[2], &sel))
			goto unsupported;
		for (k = 0; k < 4; k++)
			memcpy(q + k * 4u, y + ((sel >> (k * 2u)) & 3u) * 4u, 4);
		if (!kgenome_emu_vec_wr(e, ixp, &ixp->op[0], q, 16))
			goto unsupported;
		break;
	}
	default:
		return KGENOME_EMU_RUN_NOT_MINE;
	}
	return KGENOME_EMU_RUN_OK;

unsupported:
	return KGENOME_EMU_RUN_UNSUPPORTED;
}
