/*
 * decode_mips.c - MIPS32 and MIPS64 into the engine's one instruction form.
 *
 * DISPATCH BY TABLE, NOT BY CHAIN - which is bddisasm's method and the one
 * measurable thing a hand-written decoder can take from it. It indexes a
 * table by the opcode byte and walks a chain of tables from there, so the
 * cost of recognising an instruction does not depend on where it sits in
 * the author's list of cases. The sweep this replaces asked `else if` ten
 * times in a row and answered the eleventh case slowest.
 *
 * MIPS makes that easy: the primary opcode is the top six bits, so the
 * table is sixty-four entries and the lookup is one index. SPECIAL (op 0)
 * and REGIMM (op 1) are second-level tables on the function field, exactly
 * the chain bddisasm walks.
 *
 * WHAT IT DOES NOT DO. It recognises the instructions the sweep asks
 * about - what loads a constant, what calls, what returns, what writes a
 * register - and reports everything else as KDIS_OTHER with a correct
 * write mask. That is the contract in decode.h, and a decoder that named
 * all four hundred MIPS instructions would be carrying three hundred and
 * ninety the engine never asks about.
 */
#include <string.h>

/* KOF_BROKEN - the sentinel kdis.h names for a target there is not. */
#include "kofmod/kofsig.h"
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

/*
 * WHAT EACH PRIMARY OPCODE IS, as one row per opcode - see the note above.
 * `cls` is the class when the opcode alone decides it; the two that need a
 * second look are marked and handled below.
 */
struct mrow {
	uint8_t cls;            /* enum kdis_op_class */
	uint8_t form;           /* 0 none, 1 I-type, 2 J-type, 3 branch */
};

#define MF_NONE 0u
#define MF_I    1u
#define MF_J    2u
#define MF_B    3u

static const struct mrow g_prim[64] = {
	[MIPS_SPECIAL] = { KDIS_OTHER, MF_NONE },
	[MIPS_REGIMM]  = { KDIS_JCC,   MF_B    },
	[MIPS_J]       = { KDIS_JMP,   MF_J    },
	[MIPS_JAL]     = { KDIS_CALL,  MF_J    },
	[0x04]         = { KDIS_JCC,   MF_B    },   /* beq  */
	[0x05]         = { KDIS_JCC,   MF_B    },   /* bne  */
	[0x06]         = { KDIS_JCC,   MF_B    },   /* blez */
	[0x07]         = { KDIS_JCC,   MF_B    },   /* bgtz */
	[MIPS_ADDI]    = { KDIS_ADD,   MF_I    },
	[MIPS_ADDIU]   = { KDIS_ADD,   MF_I    },
	[0x0a]         = { KDIS_CMP,   MF_I    },   /* slti  */
	[0x0b]         = { KDIS_CMP,   MF_I    },   /* sltiu */
	[0x0c]         = { KDIS_AND,   MF_I    },
	[MIPS_ORI]     = { KDIS_OR,    MF_I    },
	[0x0e]         = { KDIS_XOR,   MF_I    },
	[MIPS_LUI]     = { KDIS_MOV,   MF_I    },
	[0x20]         = { KDIS_MOV,   MF_I    },   /* lb  */
	[0x21]         = { KDIS_MOV,   MF_I    },   /* lh  */
	[0x23]         = { KDIS_MOV,   MF_I    },   /* lw  */
	[0x24]         = { KDIS_MOVZX, MF_I    },   /* lbu */
	[0x25]         = { KDIS_MOVZX, MF_I    },   /* lhu */
	[0x28]         = { KDIS_MOV,   MF_NONE },   /* sb - writes memory */
	[0x29]         = { KDIS_MOV,   MF_NONE },   /* sh */
	[0x2b]         = { KDIS_MOV,   MF_NONE },   /* sw */
};

/* SPECIAL, on the six-bit function field. */
static const uint8_t g_special[64] = {
	[0x08] = KDIS_JMP,      /* jr   */
	[0x09] = KDIS_CALL,     /* jalr */
	[0x0c] = KDIS_SYSCALL,
	[0x0d] = KDIS_INT,      /* break */
	[0x20] = KDIS_ADD, [0x21] = KDIS_ADD,
	[0x22] = KDIS_SUB, [0x23] = KDIS_SUB,
	[0x24] = KDIS_AND, [0x25] = KDIS_OR,
	[0x26] = KDIS_XOR, [0x27] = KDIS_NOT,
	[0x00] = KDIS_SHL, [0x02] = KDIS_SHR, [0x03] = KDIS_SAR,
	[0x2a] = KDIS_CMP, [0x2b] = KDIS_CMP,
};

uint32_t kof_decode_mips(const uint8_t *p, uint32_t n, uint64_t va,
			 int be, struct kdis_insn *out)
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
	 * KOF_BROKEN AND NOT (uint64_t)-1, WHICH IS A DIFFERENT NUMBER -
	 * see the same correction in decode_x86.c, where it was measured.
	 * kdis.h says "no target" is KOF_BROKEN; a decoder that writes
	 * UINT64_MAX makes every reader's test for it true.
	 */
	out->target = KOF_BROKEN;
	out->target_va = KOF_BROKEN;
	out->o[0].reg = out->o[0].index = out->o[0].seg = KDIS_REG_NONE;
	out->o[1].reg = out->o[1].index = out->o[1].seg = KDIS_REG_NONE;
	out->o[2].reg = out->o[2].index = out->o[2].seg = KDIS_REG_NONE;

	op = x >> 26;
	rs = (x >> 21) & 31u;
	rt = (x >> 16) & 31u;
	rd = (x >> 11) & 31u;
	fn = x & 63u;
	m = &g_prim[op];

	if (op == MIPS_SPECIAL) {
		out->op = g_special[fn];
		if (!out->op)
			out->op = KDIS_OTHER;
		if (out->op == KDIS_JMP || out->op == KDIS_CALL) {
			/* jr/jalr: through a register - see KDIS_F_INDIRECT. */
			out->flags |= KDIS_F_INDIRECT;
			out->n_op = 1u;
			out->o[0].kind = KDIS_O_REG;
			out->o[0].reg = (uint8_t)rs;
			out->o[0].flags = KDIS_OF_READ;
			if (out->op == KDIS_CALL)
				out->wmask |= 1ull << 31;   /* ra */
		} else if (out->op != KDIS_SYSCALL && out->op != KDIS_INT) {
			out->n_op = 3u;
			out->o[0].kind = KDIS_O_REG;
			out->o[0].reg = (uint8_t)rd;
			out->o[0].flags = KDIS_OF_WRITE;
			out->o[1].kind = KDIS_O_REG;
			out->o[1].reg = (uint8_t)rs;
			out->o[1].flags = KDIS_OF_READ;
			out->o[2].kind = KDIS_O_REG;
			out->o[2].reg = (uint8_t)rt;
			out->o[2].flags = KDIS_OF_READ;
			if (rd)
				out->wmask |= 1ull << rd;
		}
		return 4u;
	}

	out->op = m->cls ? m->cls : KDIS_OTHER;
	switch (m->form) {
	case MF_J:
		/* The target keeps the top four bits of the delay slot. */
		out->target_va = ((va + 4u) & 0xfffffffff0000000ull) |
				 ((uint64_t)(x & 0x03ffffffu) << 2);
		out->target = out->target_va;
		out->n_op = 1u;
		out->o[0].kind = KDIS_O_REL;
		if (out->op == KDIS_CALL)
			out->wmask |= 1ull << 31;       /* ra */
		break;
	case MF_B:
		out->target_va = va + 4u +
				 (uint64_t)((int64_t)(int16_t)(x & 0xffffu) * 4);
		out->target = out->target_va;
		out->n_op = 1u;
		out->o[0].kind = KDIS_O_REL;
		break;
	case MF_I:
		out->n_op = 3u;
		out->o[0].kind = KDIS_O_REG;
		out->o[0].reg = (uint8_t)rt;
		out->o[0].flags = KDIS_OF_WRITE;
		out->o[1].kind = KDIS_O_REG;
		out->o[1].reg = (uint8_t)rs;
		out->o[1].flags = KDIS_OF_READ;
		out->o[2].kind = KDIS_O_IMM;
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
