/*
 * decode_x86.c - x86 and x86-64 into celllysis's one instruction form.
 *
 * The decoding itself is genotype's (libgenome/genotype/x86); this is the
 * translation, and it is the ONLY place in the engine that reads one of its
 * instructions. Everything downstream reads struct cell_insn, so a decoder
 * that renames an instruction class is applied here and nowhere else - see
 * decode.h for why that mattered enough to write this.
 *
 * ONLY WHAT THE SWEEP READS IS BUILT. genotype finds the instruction first and
 * builds operands when asked; the sweep asks for the explicit ones (at most
 * three are kept) and takes the registers an instruction writes WITHOUT naming
 * them from a mask the decoder keeps per opcode, so the stack pointer a push
 * moves or the rdx a mul fills is never built as an operand at all. MEASURED
 * over 44.7 M instructions, building every operand was 15 of the 41 ns.
 */
#include <stddef.h>
#include <string.h>

/* KOF_BROKEN - the sentinel cell.h names for a target there is not. */
#include "kofmod/cell.h"
#include "decode.h"
#include <x86/x86.h>

/* ---- THE CLASS ---------------------------------------------------------- */
/*
 * the decoder names roughly sixteen hundred instructions and the sweep asks
 * about thirty-eight of them. The rest are not "unknown": they are
 * instructions whose CLASS is all anyone downstream needs, and CELL_OTHER
 * with a correct wmask is a complete answer for them.
 *
 * THE ANSWER IS LOOKED UP, NOT SEARCHED, and there is one statement of it: this
 * table, indexed by the decoder's id, holding the class and the two flags that
 * are a property of the id as well (a far branch, an indirect one). It was a
 * sixty-case switch filled into a table on first use - a flag tested on every
 * instruction - with two more switches (is_far, is_indirect) asked of every
 * instruction; MEASURED over 9.2 M instructions that was 15 of the ~700
 * instructions executed per decode. The table is constant, so there is nothing
 * to initialise and nothing two threads could race on, and an id the table does
 * not name is CELL_OTHER with no flag because zero is what the designated
 * initialisers leave.
 */
struct xcls {
	uint8_t op;
	uint8_t flags;                  /* CELL_F_FAR, CELL_F_INDIRECT */
};

static const struct xcls g_cls[GT_X86_I__COUNT] = {
	[GT_X86_I_NOP]      = { CELL_NOP, 0 },
	[GT_X86_I_MOV]      = { CELL_MOV, 0 },
	[GT_X86_I_MOVZX]    = { CELL_MOVZX, 0 },
	[GT_X86_I_MOVSX]    = { CELL_MOVSX, 0 },
	[GT_X86_I_MOVSXD]   = { CELL_MOVSX, 0 },
	[GT_X86_I_LEA]      = { CELL_LEA, 0 },
	[GT_X86_I_XCHG]     = { CELL_XCHG, 0 },
	[GT_X86_I_PUSH]     = { CELL_PUSH, 0 },
	[GT_X86_I_POP]      = { CELL_POP, 0 },
	[GT_X86_I_ADD]      = { CELL_ADD, 0 },
	[GT_X86_I_SUB]      = { CELL_SUB, 0 },
	[GT_X86_I_ADC]      = { CELL_ADC, 0 },
	[GT_X86_I_SBB]      = { CELL_SBB, 0 },
	[GT_X86_I_AND]      = { CELL_AND, 0 },
	[GT_X86_I_OR]       = { CELL_OR, 0 },
	[GT_X86_I_XOR]      = { CELL_XOR, 0 },
	[GT_X86_I_NOT]      = { CELL_NOT, 0 },
	[GT_X86_I_NEG]      = { CELL_NEG, 0 },
	[GT_X86_I_INC]      = { CELL_INC, 0 },
	[GT_X86_I_DEC]      = { CELL_DEC, 0 },
	[GT_X86_I_CMP]      = { CELL_CMP, 0 },
	[GT_X86_I_TEST]     = { CELL_TEST, 0 },
	[GT_X86_I_SHL]      = { CELL_SHL, 0 },
	[GT_X86_I_SHR]      = { CELL_SHR, 0 },
	[GT_X86_I_SAR]      = { CELL_SAR, 0 },
	[GT_X86_I_ROL]      = { CELL_ROL, 0 },
	[GT_X86_I_ROR]      = { CELL_ROR, 0 },
	[GT_X86_I_RCL]      = { CELL_RCL, 0 },
	[GT_X86_I_RCR]      = { CELL_RCR, 0 },
	[GT_X86_I_MUL]      = { CELL_MUL, 0 },
	[GT_X86_I_IMUL]     = { CELL_IMUL, 0 },
	[GT_X86_I_DIV]      = { CELL_DIV, 0 },
	[GT_X86_I_IDIV]     = { CELL_IDIV, 0 },
	[GT_X86_I_CALLNR]   = { CELL_CALL, 0 },
	[GT_X86_I_CALLNI]   = { CELL_CALL, CELL_F_INDIRECT },
	[GT_X86_I_CALLFI]   = { CELL_CALL, CELL_F_FAR | CELL_F_INDIRECT },
	[GT_X86_I_CALLFD]   = { CELL_CALL, CELL_F_FAR },
	[GT_X86_I_JMPNR]    = { CELL_JMP, 0 },
	[GT_X86_I_JMPNI]    = { CELL_JMP, CELL_F_INDIRECT },
	[GT_X86_I_JMPFI]    = { CELL_JMP, CELL_F_FAR | CELL_F_INDIRECT },
	[GT_X86_I_JMPFD]    = { CELL_JMP, CELL_F_FAR },
	[GT_X86_I_Jcc]      = { CELL_JCC, 0 },
	[GT_X86_I_LOOP]     = { CELL_LOOP, 0 },
	[GT_X86_I_LOOPNZ]   = { CELL_LOOP, 0 },
	[GT_X86_I_LOOPZ]    = { CELL_LOOP, 0 },
	[GT_X86_I_RETN]     = { CELL_RET, 0 },
	[GT_X86_I_RETF]     = { CELL_RET, CELL_F_FAR },
	[GT_X86_I_INT]      = { CELL_INT, 0 },
	[GT_X86_I_INT1]     = { CELL_INT, 0 },
	[GT_X86_I_INT3]     = { CELL_INT, 0 },
	[GT_X86_I_INTO]     = { CELL_INT, 0 },
	[GT_X86_I_SYSCALL]  = { CELL_SYSCALL, 0 },
	[GT_X86_I_SYSENTER] = { CELL_SYSCALL, 0 },
	[GT_X86_I_CMOVcc]   = { CELL_CMOV, 0 },
	[GT_X86_I_SETcc]    = { CELL_SETCC, 0 },
	[GT_X86_I_CBW]      = { CELL_WIDEN, 0 },
	[GT_X86_I_CWDE]     = { CELL_WIDEN, 0 },
	[GT_X86_I_CDQE]     = { CELL_WIDEN, 0 },
	[GT_X86_I_CWD]      = { CELL_WIDEN, 0 },
	[GT_X86_I_CDQ]      = { CELL_WIDEN, 0 },
	[GT_X86_I_CQO]      = { CELL_WIDEN, 0 },
	/*
	 * WHICH special register, in `cond` - the field is the condition
	 * code of a JCC and a MOV has none, so it is free here. A module
	 * writing cr0 is a rootkit turning write protection off; one
	 * touching a debug register is doing something else entirely, and
	 * the class alone cannot tell them apart.
	 */
	[GT_X86_I_MOV_CR]   = { CELL_MOV_SPECIAL, 0 },
	[GT_X86_I_MOV_DR]   = { CELL_MOV_SPECIAL, 0 },
	[GT_X86_I_MOV_TR]   = { CELL_MOV_SPECIAL, 0 },
	[GT_X86_I_IRET]     = { CELL_IRET, 0 },
	[GT_X86_I_UD0]      = { CELL_UD, 0 },
	[GT_X86_I_UD1]      = { CELL_UD, 0 },
	[GT_X86_I_UD2]      = { CELL_UD, 0 },
	[GT_X86_I_MOVS]     = { CELL_STRING, 0 },
	[GT_X86_I_STOS]     = { CELL_STRING, 0 },
	[GT_X86_I_LODS]     = { CELL_STRING, 0 },
	[GT_X86_I_SCAS]     = { CELL_STRING, 0 },
	[GT_X86_I_CMPS]     = { CELL_STRING, 0 }
};

/*
 * THE DECODER'S SWEEP VIEW IS THIS FORM, not a look-alike: genotype fills
 * struct gt_x86_sop with the numbers of cell_operand and the adapter copies the
 * three operands as they stand. The asserts are what makes that agreement a fact
 * and not a coincidence.
 */
_Static_assert(sizeof(struct gt_x86_sop) == sizeof(struct cell_operand), "operand size");
_Static_assert(offsetof(struct gt_x86_sop, kind) == offsetof(struct cell_operand, kind) &&
	       offsetof(struct gt_x86_sop, reg) == offsetof(struct cell_operand, reg) &&
	       offsetof(struct gt_x86_sop, index) == offsetof(struct cell_operand, index) &&
	       offsetof(struct gt_x86_sop, scale) == offsetof(struct cell_operand, scale) &&
	       offsetof(struct gt_x86_sop, size) == offsetof(struct cell_operand, size) &&
	       offsetof(struct gt_x86_sop, flags) == offsetof(struct cell_operand, flags) &&
	       offsetof(struct gt_x86_sop, seg) == offsetof(struct cell_operand, seg) &&
	       offsetof(struct gt_x86_sop, disp) == offsetof(struct cell_operand, disp) &&
	       offsetof(struct gt_x86_sop, imm) == offsetof(struct cell_operand, imm),
	       "operand layout");
_Static_assert(GT_X86_SK_NONE == CELL_O_NONE && GT_X86_SK_REG == CELL_O_REG &&
	       GT_X86_SK_MEM == CELL_O_MEM && GT_X86_SK_IMM == CELL_O_IMM &&
	       GT_X86_SK_REL == CELL_O_REL, "operand kinds");
_Static_assert(GT_X86_SF_WRITE == CELL_OF_WRITE && GT_X86_SF_READ == CELL_OF_READ &&
	       GT_X86_SF_RIPREL == CELL_OF_RIPREL && GT_X86_SF_HIGH8 == CELL_OF_HIGH8 &&
	       GT_X86_SREG_NONE == CELL_REG_NONE, "operand flags");

uint32_t cell_decode_x86(const uint8_t *p, uint32_t n, uint64_t va,
			unsigned bits, struct cell_insn *out)
{
	struct gt_x86_sweep x;
	const struct xcls *c;
	unsigned op, k;

	if (!p || !n || !out)
		return 0;
	if (gt_x86_sweep(&x, p, n, bits == 32 ? 32 : 64) != GT_OK)
		return 0;

	/*
	 * EVERY FIELD WRITTEN, NOT ZEROED THEN WRITTEN.
	 *
	 * This cleared the whole structure first, which is a hundred and
	 * twenty bytes per instruction on a path that runs tens of
	 * millions of times - MEASURED on one 7 MB object, the
	 * translation cost 38% on top of the decode itself, and the clear
	 * was most of it. Every field is written once, and the operands the
	 * instruction does not have arrive from genotype marked absent, so
	 * nothing is written twice and nothing is left stale.
	 */
	c = x.id < (unsigned)GT_X86_I__COUNT ? &g_cls[x.id] : &g_cls[0];
	op = c->op;
	/* The x87 test needs the category, which the table cannot hold. */
	if (op == CELL_OTHER && x.cat == GT_X86_C_X87_ALU)
		op = CELL_FPU;
	out->op = (uint8_t)op;
	out->len = x.len;
	out->n_op = x.n;
	out->flags = (uint8_t)(c->flags | (x.rep ? CELL_F_REP : 0u));
	out->cond = x.cond;
	if (op == CELL_MOV_SPECIAL)
		out->cond = x.id == GT_X86_I_MOV_CR ? CELL_SR_CR
			  : x.id == GT_X86_I_MOV_DR ? CELL_SR_DR
						    : CELL_SR_TR;
	/* The registers it writes: the ones it names and the ones it does not - see
	 * cell_insn.wmask. The decoder reports both, so the consumer need not care which. */
	out->wmask = x.wmask;
	out->at_va = va;
	out->at = va;
	/*
	 * KOF_BROKEN AND NOT (uint64_t)-1, WHICH IS A DIFFERENT NUMBER.
	 *
	 * cell.h says "no target" is KOF_BROKEN, and KOF_BROKEN is
	 * UINT64_MAX - 1. Writing UINT64_MAX here meant every reader's
	 * `target_va != KOF_BROKEN` was true for EVERY instruction, branch
	 * or not. MEASURED: kof_cell_next then called kof_pz_addr_to_off -
	 * a linear walk of the segment table - 1,327,512 times over a 12 MB
	 * subset where only 273,617 instructions have a relative target,
	 * and that one wasted call was 6.2% of the whole scan.
	 *
	 * It did not produce a wrong answer, which is why it survived: the
	 * walk found no segment holding UINT64_MAX and returned KOF_BROKEN,
	 * so `target` came out right by the long way round. `target_va` did
	 * not - it kept UINT64_MAX, and a reader testing IT against
	 * KOF_BROKEN still sees a target that is not there.
	 */
	out->target = KOF_BROKEN;
	out->target_va = KOF_BROKEN;
	memcpy(out->o, x.op, sizeof out->o);
	for (k = 0; k < x.n; k++) {
		if (x.op[k].kind == CELL_O_REL) {
			out->target_va = va + x.len +
					 (uint64_t)(int64_t)(int32_t)x.op[k].imm;
			out->target = out->target_va;
		}
	}
	return x.len;
}
