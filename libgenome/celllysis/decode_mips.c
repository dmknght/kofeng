/*
 * decode_mips.c - MIPS32 and MIPS64 into celllysis's one instruction form.
 *
 * DISPATCH BY TABLE, NOT BY CHAIN - which is the decoder's method and the one
 * measurable thing a hand-written decoder can take from it. It indexes a
 * table by the opcode byte and walks a chain of tables from there, so the
 * cost of recognising an instruction does not depend on where it sits in
 * the author's list of cases. The sweep this replaces asked `else if` ten
 * times in a row and answered the eleventh case slowest.
 *
 * MIPS makes that easy: the primary opcode is the top six bits, so the
 * table is sixty-four entries and the lookup is one index. SPECIAL (op 0)
 * and REGIMM (op 1) are second-level tables on the function field, exactly
 * the chain the decoder walks.
 *
 * WHAT IT DOES NOT DO. It recognises the instructions the sweep asks
 * about - what loads a constant, what calls, what returns, what writes a
 * register - and reports everything else as KGENOME_CELL_OTHER with a correct
 * write mask. That is the contract in decode.h, and a decoder that named
 * all four hundred MIPS instructions would be carrying three hundred and
 * ninety the engine never asks about.
 */
#include <string.h>

/* KGENOME_BROKEN - the sentinel cell.h names for a target there is not. */
#include <celllysis/cell.h>
#include "decode.h"

/* The six-bit primary opcode. */
#define MIPS_SPECIAL 0x00u
#define MIPS_REGIMM  0x01u
#define MIPS_J       0x02u
#define MIPS_JAL     0x03u
#define MIPS_ADDI    0x08u
#define MIPS_ADDIU   0x09u
#define MIPS_ORI     0x0du
#define MIPS_LUI     0x0fu
#define MIPS_COP1    0x11u

/* COP1's own `rs` sub-opcode that means "branch coprocessor 1" (BC1F/BC1T/BC1FL/BC1TL); every other `rs` is an FP
 * arithmetic/move/compare instruction this decoder does not model (see the COP1 branch below). */
#define MIPS_COP1_BC 0x08u

/*
 * CS-4 (fixed): a MIPS branch's `cond` names exactly which comparison it is, ten values that fit the walk's
 * packed trace record (diag_wrapper_walk.c: a segment's trace gives up the day `cond` needs more than 4 bits -
 * measured, trace_arch.c: 2026-11-05, 4-23 instructions of 4075 fell out of the trace on the first MIPS random
 * run once `cond` carried the raw opcode/rt field, a value up to 35). The "likely" bit (CL-3's
 * KGENOME_CELL_F_ANNUL) and the write of `ra` are kept in `flags`/`wmask` instead of widening `cond` further -
 * neither needs its own `cond` value once it has a flag bit, and a flag the trace already packs separately costs
 * it nothing.
 */
#define MIPS_COND_BLTZ   0u
#define MIPS_COND_BGEZ   1u
#define MIPS_COND_BLTZAL 2u
#define MIPS_COND_BGEZAL 3u
#define MIPS_COND_BEQ    4u             /* == the primary opcode of beq/beql (0x04), kept equal on purpose */
#define MIPS_COND_BNE    5u
#define MIPS_COND_BLEZ   6u
#define MIPS_COND_BGTZ   7u
#define MIPS_COND_BC1F   8u
#define MIPS_COND_BC1T   9u

/*
 * WHAT EACH PRIMARY OPCODE IS, as one row per opcode - see the note above.
 * `cls` is the class when the opcode alone decides it; the two that need a
 * second look are marked and handled below.
 */
struct mrow {
	uint8_t cls;            /* enum kgenome_cell_op_class */
	uint8_t form;           /* 0 none, 1 I-type, 2 J-type, 3 branch */
};

#define MF_NONE 0u
#define MF_I    1u
#define MF_J    2u
#define MF_B    3u

/*
 * CL-3 (fixed, 2026-11-05): g_prim now has rows for the branch-likely opcodes 0x14-0x17 (beql, bnel, blezl,
 * bgtzl: same shape as their non-likely counterparts at 0x04-0x07) and for COP1's branch sub-opcode
 * (0x11 with rs == MIPS_COP1_BC: bc1f/bc1t/bc1fl/bc1tl, handled below as a second special-case block
 * alongside MIPS_SPECIAL, since "is this a branch" depends on `rs` and not on the opcode alone). Every
 * branch-likely form sets KGENOME_CELL_F_ANNUL (cell.h); cfg_build.c gives its delay slot a block of its
 * own, reached only on the taken edge.
 */
static const struct mrow g_prim[64] = {
	[MIPS_SPECIAL] = { KGENOME_CELL_OTHER, MF_NONE },
	[MIPS_REGIMM]  = { KGENOME_CELL_JCC,   MF_B    },
	[MIPS_J]       = { KGENOME_CELL_JMP,   MF_J    },
	[MIPS_JAL]     = { KGENOME_CELL_CALL,  MF_J    },
	[0x04]         = { KGENOME_CELL_JCC,   MF_B    },   /* beq  */
	[0x05]         = { KGENOME_CELL_JCC,   MF_B    },   /* bne  */
	[0x06]         = { KGENOME_CELL_JCC,   MF_B    },   /* blez */
	[0x07]         = { KGENOME_CELL_JCC,   MF_B    },   /* bgtz */
	[0x14]         = { KGENOME_CELL_JCC,   MF_B    },   /* beql  (CL-3) */
	[0x15]         = { KGENOME_CELL_JCC,   MF_B    },   /* bnel  (CL-3) */
	[0x16]         = { KGENOME_CELL_JCC,   MF_B    },   /* blezl (CL-3) */
	[0x17]         = { KGENOME_CELL_JCC,   MF_B    },   /* bgtzl (CL-3) */
	[MIPS_ADDI]    = { KGENOME_CELL_ADD,   MF_I    },
	[MIPS_ADDIU]   = { KGENOME_CELL_ADD,   MF_I    },
	[0x0a]         = { KGENOME_CELL_CMP,   MF_I    },   /* slti  */
	[0x0b]         = { KGENOME_CELL_CMP,   MF_I    },   /* sltiu */
	[0x0c]         = { KGENOME_CELL_AND,   MF_I    },
	[MIPS_ORI]     = { KGENOME_CELL_OR,    MF_I    },
	[0x0e]         = { KGENOME_CELL_XOR,   MF_I    },
	[MIPS_LUI]     = { KGENOME_CELL_MOV,   MF_I    },
	[0x20]         = { KGENOME_CELL_MOV,   MF_I    },   /* lb  */
	[0x21]         = { KGENOME_CELL_MOV,   MF_I    },   /* lh  */
	[0x23]         = { KGENOME_CELL_MOV,   MF_I    },   /* lw  */
	[0x24]         = { KGENOME_CELL_MOVZX, MF_I    },   /* lbu */
	[0x25]         = { KGENOME_CELL_MOVZX, MF_I    },   /* lhu */
	[0x28]         = { KGENOME_CELL_MOV,   MF_NONE },   /* sb - writes memory */
	[0x29]         = { KGENOME_CELL_MOV,   MF_NONE },   /* sh */
	[0x2b]         = { KGENOME_CELL_MOV,   MF_NONE },   /* sw */
};

/* SPECIAL, on the six-bit function field. */
static const uint8_t g_special[64] = {
	[0x08] = KGENOME_CELL_JMP,      /* jr   */
	[0x09] = KGENOME_CELL_CALL,     /* jalr */
	[0x0c] = KGENOME_CELL_SYSCALL,
	[0x0d] = KGENOME_CELL_INT,      /* break */
	[0x20] = KGENOME_CELL_ADD, [0x21] = KGENOME_CELL_ADD,
	[0x22] = KGENOME_CELL_SUB, [0x23] = KGENOME_CELL_SUB,
	[0x24] = KGENOME_CELL_AND, [0x25] = KGENOME_CELL_OR,
	[0x26] = KGENOME_CELL_XOR, [0x27] = KGENOME_CELL_NOT,
	[0x00] = KGENOME_CELL_SHL, [0x02] = KGENOME_CELL_SHR, [0x03] = KGENOME_CELL_SAR,
	[0x2a] = KGENOME_CELL_CMP, [0x2b] = KGENOME_CELL_CMP,
};

uint32_t kgenome_cell_decode_mips(const uint8_t *p, uint32_t n, uint64_t va,
			 int be, struct kgenome_cell_insn *out)
{
	uint32_t x, op, rs, rt, rd, fn;
	const struct mrow *m;

	if (!p || n < 4u || !out)
		return 0;
	x = be ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
		  (uint32_t)p[2] << 8 | p[3])
	       : ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
		  (uint32_t)p[1] << 8 | p[0]);

	memset(out, 0, sizeof *out);
	out->len = 4u;
	out->at = va;
	out->at_va = va;
	/*
	 * KGENOME_BROKEN AND NOT (uint64_t)-1, WHICH IS A DIFFERENT NUMBER -
	 * see the same correction in decode_x86.c, where it was measured.
	 * cell.h says "no target" is KGENOME_BROKEN; a decoder that writes
	 * UINT64_MAX makes every reader's test for it true.
	 */
	out->target = KGENOME_BROKEN;
	out->target_va = KGENOME_BROKEN;
	out->o[0].reg = out->o[0].index = out->o[0].seg = KGENOME_CELL_REG_NONE;
	out->o[1].reg = out->o[1].index = out->o[1].seg = KGENOME_CELL_REG_NONE;
	out->o[2].reg = out->o[2].index = out->o[2].seg = KGENOME_CELL_REG_NONE;

	op = x >> 26;
	rs = (x >> 21) & 31u;
	rt = (x >> 16) & 31u;
	rd = (x >> 11) & 31u;
	fn = x & 63u;
	m = &g_prim[op];

	if (op == MIPS_SPECIAL) {
		out->op = g_special[fn];
		if (!out->op)
			out->op = KGENOME_CELL_OTHER;
		if (out->op == KGENOME_CELL_JMP || out->op == KGENOME_CELL_CALL) {
			/* jr/jalr: through a register - see KGENOME_CELL_F_INDIRECT. */
			out->flags |= KGENOME_CELL_F_INDIRECT;
			out->n_op = 1u;
			out->o[0].kind = KGENOME_CELL_O_REG;
			out->o[0].reg = (uint8_t)rs;
			out->o[0].flags = KGENOME_CELL_OF_READ;
			if (out->op == KGENOME_CELL_CALL)
				out->wmask |= 1ull << 31;   /* ra */
		} else if (out->op != KGENOME_CELL_SYSCALL && out->op != KGENOME_CELL_INT) {
			out->n_op = 3u;
			out->o[0].kind = KGENOME_CELL_O_REG;
			out->o[0].reg = (uint8_t)rd;
			out->o[0].flags = KGENOME_CELL_OF_WRITE;
			out->o[1].kind = KGENOME_CELL_O_REG;
			out->o[1].reg = (uint8_t)rs;
			out->o[1].flags = KGENOME_CELL_OF_READ;
			out->o[2].kind = KGENOME_CELL_O_REG;
			out->o[2].reg = (uint8_t)rt;
			out->o[2].flags = KGENOME_CELL_OF_READ;
			if (rd)
				out->wmask |= 1ull << rd;
		}
		return 4u;
	}

	if (op == MIPS_COP1) {
		/*
		 * CL-3 (fixed): BC1F/BC1T/BC1FL/BC1TL (rs == MIPS_COP1_BC) are the only COP1
		 * encoding that transfers control; this engine does not model FP VALUES, so every
		 * other `rs` (the arithmetic/move/compare opcodes) decodes as KGENOME_CELL_OTHER
		 * with the correct 4-byte length and no operands - exactly what an unlisted g_prim
		 * row already gave every other COP1 instruction, now said explicitly rather than by
		 * omission.
		 */
		if (rs == MIPS_COP1_BC) {
			out->op = KGENOME_CELL_JCC;
			out->target_va = va + 4u +
					 (uint64_t)((int64_t)(int16_t)(x & 0xffffu) * 4);
			out->target = out->target_va;
			out->n_op = 1u;
			out->o[0].kind = KGENOME_CELL_O_REL;
			/*
			 * `rt` (bits 20-16) packs a 3-bit FP condition-code number (cc, bits 20-18 -
			 * which of several FP flags this tests; MIPS IV+, almost always 0) ahead of
			 * `nd` (bit 17, CL-3's annul-on-not-taken "likely" bit) and `tf` (bit 16,
			 * branch-on-true vs branch-on-false). cond names only tf (BC1F/BC1T); cc selects
			 * WHICH flag, not a fact about control flow, and this decoder does not track FP
			 * flag values to resolve it - an honest limit, not a 4th GPR operand pretending
			 * to read one.
			 */
			out->cond = (uint8_t)(MIPS_COND_BC1F + (rt & 0x01u));
			if (rt & 0x02u)
				out->flags |= KGENOME_CELL_F_ANNUL;    /* bc1fl/bc1tl */
		} else {
			out->op = KGENOME_CELL_OTHER;
		}
		return 4u;
	}

	out->op = m->cls ? m->cls : KGENOME_CELL_OTHER;
	switch (m->form) {
	case MF_J:
		/* The target keeps the top four bits of the delay slot. */
		out->target_va = ((va + 4u) & 0xfffffffff0000000ull) |
				 ((uint64_t)(x & 0x03ffffffu) << 2);
		out->target = out->target_va;
		out->n_op = 1u;
		out->o[0].kind = KGENOME_CELL_O_REL;
		if (out->op == KGENOME_CELL_CALL)
			out->wmask |= 1ull << 31;       /* ra */
		break;
	case MF_B:
		/*
		 * CS-4 (fixed): a MIPS branch now carries its compared registers (o[1], o[2]) and a
		 * `cond` that says exactly which comparison this is, so a consumer (cfg_isa.c) reads
		 * the decoded instruction instead of re-fetching the word. The "likely" bit (CL-3) and
		 * the write of `ra` are kept out of `cond` and in `flags`/`wmask` - see MIPS_COND_* above.
		 */
		out->target_va = va + 4u +
				 (uint64_t)((int64_t)(int16_t)(x & 0xffffu) * 4);
		out->target = out->target_va;
		out->o[0].kind = KGENOME_CELL_O_REL;
		if (op == MIPS_REGIMM) {
			const unsigned al = (rt & 0x10u) != 0;

			out->cond = (uint8_t)((rt & 0x01u) | (al << 1));       /* 0 bltz, 1 bgez, 2 bltzal, 3 bgezal */
			if (rt & 0x02u)
				out->flags |= KGENOME_CELL_F_ANNUL;    /* bltzl/bgezl/-all (CL-3) */
			if (al)
				out->wmask |= 1ull << 31;              /* bltzal/bgezal/-l: writes ra */
			out->n_op = 2u;
			out->o[1].kind = KGENOME_CELL_O_REG;
			out->o[1].reg = (uint8_t)rs;
			out->o[1].flags = KGENOME_CELL_OF_READ;
		} else {
			/* beq/bne/blez/bgtz and their likely forms: blez/bgtz always have rt == 0
			 * ($zero) in the encoding, so filling o[2] from rt already says "compared
			 * against zero" without a special case. op & 7 is MIPS_COND_BEQ..BGTZ for
			 * both a plain branch (0x04-0x07) and its likely form (0x14-0x17: bit 4 set),
			 * which is exactly the bit CL-3 reads into KGENOME_CELL_F_ANNUL below. */
			out->cond = (uint8_t)(op & 0x07u);
			if (op & 0x10u)
				out->flags |= KGENOME_CELL_F_ANNUL;    /* beql/bnel/blezl/bgtzl (CL-3) */
			out->n_op = 3u;
			out->o[1].kind = KGENOME_CELL_O_REG;
			out->o[1].reg = (uint8_t)rs;
			out->o[1].flags = KGENOME_CELL_OF_READ;
			out->o[2].kind = KGENOME_CELL_O_REG;
			out->o[2].reg = (uint8_t)rt;
			out->o[2].flags = KGENOME_CELL_OF_READ;
		}
		break;
	case MF_I:
		out->n_op = 3u;
		out->o[0].kind = KGENOME_CELL_O_REG;
		out->o[0].reg = (uint8_t)rt;
		out->o[0].flags = KGENOME_CELL_OF_WRITE;
		out->o[1].kind = KGENOME_CELL_O_REG;
		out->o[1].reg = (uint8_t)rs;
		out->o[1].flags = KGENOME_CELL_OF_READ;
		out->o[2].kind = KGENOME_CELL_O_IMM;
		/*
		 * `lui` is the top half and the rest are signed - the two
		 * halves of how MIPS writes a 32-bit constant at all.
		 */
		out->o[2].imm = op == MIPS_LUI
				? (uint64_t)(x & 0xffffu) << 16
				: (op == MIPS_ORI || op == 0x0cu ||
				   op == 0x0eu)
				  ? (x & 0xffffu)
				  : (uint64_t)(int64_t)(int16_t)(x & 0xffffu);
		if (rt)
			out->wmask |= 1ull << rt;
		break;
	default:
		break;
	}
	return 4u;
}
