/*
 * decode_x86.c - x86 and x86-64 into celllysis's one instruction form.
 *
 * The decoding itself is genotype's (libgenome/genotype/x86); this is the
 * translation, and it is the ONLY place in the engine that reads one of its
 * instructions. Everything downstream reads struct kgenome_cell_insn, so a decoder
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

/* KGENOME_BROKEN - the sentinel cell.h names for a target there is not. */
#include <celllysis/cell.h>
#include "decode.h"
#include <genotype/x86/x86.h>

/* ---- THE CLASS ---------------------------------------------------------- */
/*
 * the decoder names roughly sixteen hundred instructions and the sweep asks
 * about thirty-eight of them. The rest are not "unknown": they are
 * instructions whose CLASS is all anyone downstream needs, and KGENOME_CELL_OTHER
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
 * not name is KGENOME_CELL_OTHER with no flag because zero is what the designated
 * initialisers leave.
 */
struct xcls {
	uint8_t op;
	uint8_t flags;                  /* KGENOME_CELL_F_FAR, KGENOME_CELL_F_INDIRECT */
};

static const struct xcls g_cls[KGENOME_X86_I__COUNT] = {
	[KGENOME_X86_I_NOP]      = { KGENOME_CELL_NOP, 0 },
	[KGENOME_X86_I_MOV]      = { KGENOME_CELL_MOV, 0 },
	[KGENOME_X86_I_MOVZX]    = { KGENOME_CELL_MOVZX, 0 },
	[KGENOME_X86_I_MOVSX]    = { KGENOME_CELL_MOVSX, 0 },
	[KGENOME_X86_I_MOVSXD]   = { KGENOME_CELL_MOVSX, 0 },
	[KGENOME_X86_I_LEA]      = { KGENOME_CELL_LEA, 0 },
	[KGENOME_X86_I_XCHG]     = { KGENOME_CELL_XCHG, 0 },
	[KGENOME_X86_I_PUSH]     = { KGENOME_CELL_PUSH, 0 },
	[KGENOME_X86_I_POP]      = { KGENOME_CELL_POP, 0 },
	[KGENOME_X86_I_ADD]      = { KGENOME_CELL_ADD, 0 },
	[KGENOME_X86_I_SUB]      = { KGENOME_CELL_SUB, 0 },
	[KGENOME_X86_I_ADC]      = { KGENOME_CELL_ADC, 0 },
	[KGENOME_X86_I_SBB]      = { KGENOME_CELL_SBB, 0 },
	[KGENOME_X86_I_AND]      = { KGENOME_CELL_AND, 0 },
	[KGENOME_X86_I_OR]       = { KGENOME_CELL_OR, 0 },
	[KGENOME_X86_I_XOR]      = { KGENOME_CELL_XOR, 0 },
	[KGENOME_X86_I_NOT]      = { KGENOME_CELL_NOT, 0 },
	[KGENOME_X86_I_NEG]      = { KGENOME_CELL_NEG, 0 },
	[KGENOME_X86_I_INC]      = { KGENOME_CELL_INC, 0 },
	[KGENOME_X86_I_DEC]      = { KGENOME_CELL_DEC, 0 },
	[KGENOME_X86_I_CMP]      = { KGENOME_CELL_CMP, 0 },
	[KGENOME_X86_I_TEST]     = { KGENOME_CELL_TEST, 0 },
	[KGENOME_X86_I_SHL]      = { KGENOME_CELL_SHL, 0 },
	[KGENOME_X86_I_SHR]      = { KGENOME_CELL_SHR, 0 },
	[KGENOME_X86_I_SAR]      = { KGENOME_CELL_SAR, 0 },
	[KGENOME_X86_I_ROL]      = { KGENOME_CELL_ROL, 0 },
	[KGENOME_X86_I_ROR]      = { KGENOME_CELL_ROR, 0 },
	[KGENOME_X86_I_RCL]      = { KGENOME_CELL_RCL, 0 },
	[KGENOME_X86_I_RCR]      = { KGENOME_CELL_RCR, 0 },
	[KGENOME_X86_I_MUL]      = { KGENOME_CELL_MUL, 0 },
	[KGENOME_X86_I_IMUL]     = { KGENOME_CELL_IMUL, 0 },
	[KGENOME_X86_I_DIV]      = { KGENOME_CELL_DIV, 0 },
	[KGENOME_X86_I_IDIV]     = { KGENOME_CELL_IDIV, 0 },
	[KGENOME_X86_I_CALLNR]   = { KGENOME_CELL_CALL, 0 },
	[KGENOME_X86_I_CALLNI]   = { KGENOME_CELL_CALL, KGENOME_CELL_F_INDIRECT },
	[KGENOME_X86_I_CALLFI]   = { KGENOME_CELL_CALL, KGENOME_CELL_F_FAR | KGENOME_CELL_F_INDIRECT },
	[KGENOME_X86_I_CALLFD]   = { KGENOME_CELL_CALL, KGENOME_CELL_F_FAR },
	[KGENOME_X86_I_JMPNR]    = { KGENOME_CELL_JMP, 0 },
	[KGENOME_X86_I_JMPNI]    = { KGENOME_CELL_JMP, KGENOME_CELL_F_INDIRECT },
	[KGENOME_X86_I_JMPFI]    = { KGENOME_CELL_JMP, KGENOME_CELL_F_FAR | KGENOME_CELL_F_INDIRECT },
	[KGENOME_X86_I_JMPFD]    = { KGENOME_CELL_JMP, KGENOME_CELL_F_FAR },
	[KGENOME_X86_I_Jcc]      = { KGENOME_CELL_JCC, 0 },
	[KGENOME_X86_I_LOOP]     = { KGENOME_CELL_LOOP, 0 },
	[KGENOME_X86_I_LOOPNZ]   = { KGENOME_CELL_LOOP, 0 },
	[KGENOME_X86_I_LOOPZ]    = { KGENOME_CELL_LOOP, 0 },
	[KGENOME_X86_I_RETN]     = { KGENOME_CELL_RET, 0 },
	[KGENOME_X86_I_RETF]     = { KGENOME_CELL_RET, KGENOME_CELL_F_FAR },
	[KGENOME_X86_I_INT]      = { KGENOME_CELL_INT, 0 },
	[KGENOME_X86_I_INT1]     = { KGENOME_CELL_INT, 0 },
	[KGENOME_X86_I_INT3]     = { KGENOME_CELL_INT, 0 },
	[KGENOME_X86_I_INTO]     = { KGENOME_CELL_INT, 0 },
	[KGENOME_X86_I_SYSCALL]  = { KGENOME_CELL_SYSCALL, 0 },
	[KGENOME_X86_I_SYSENTER] = { KGENOME_CELL_SYSCALL, 0 },
	[KGENOME_X86_I_CMOVcc]   = { KGENOME_CELL_CMOV, 0 },
	[KGENOME_X86_I_SETcc]    = { KGENOME_CELL_SETCC, 0 },
	[KGENOME_X86_I_CBW]      = { KGENOME_CELL_WIDEN, 0 },
	[KGENOME_X86_I_CWDE]     = { KGENOME_CELL_WIDEN, 0 },
	[KGENOME_X86_I_CDQE]     = { KGENOME_CELL_WIDEN, 0 },
	[KGENOME_X86_I_CWD]      = { KGENOME_CELL_WIDEN, 0 },
	[KGENOME_X86_I_CDQ]      = { KGENOME_CELL_WIDEN, 0 },
	[KGENOME_X86_I_CQO]      = { KGENOME_CELL_WIDEN, 0 },
	/*
	 * WHICH special register, in `cond` - the field is the condition
	 * code of a JCC and a MOV has none, so it is free here. A module
	 * writing cr0 is a rootkit turning write protection off; one
	 * touching a debug register is doing something else entirely, and
	 * the class alone cannot tell them apart.
	 */
	[KGENOME_X86_I_MOV_CR]   = { KGENOME_CELL_MOV_SPECIAL, 0 },
	[KGENOME_X86_I_MOV_DR]   = { KGENOME_CELL_MOV_SPECIAL, 0 },
	[KGENOME_X86_I_MOV_TR]   = { KGENOME_CELL_MOV_SPECIAL, 0 },
	[KGENOME_X86_I_IRET]     = { KGENOME_CELL_IRET, 0 },
	[KGENOME_X86_I_UD0]      = { KGENOME_CELL_UD, 0 },
	[KGENOME_X86_I_UD1]      = { KGENOME_CELL_UD, 0 },
	[KGENOME_X86_I_UD2]      = { KGENOME_CELL_UD, 0 },
	[KGENOME_X86_I_MOVS]     = { KGENOME_CELL_STRING, 0 },
	[KGENOME_X86_I_STOS]     = { KGENOME_CELL_STRING, 0 },
	[KGENOME_X86_I_LODS]     = { KGENOME_CELL_STRING, 0 },
	[KGENOME_X86_I_SCAS]     = { KGENOME_CELL_STRING, 0 },
	[KGENOME_X86_I_CMPS]     = { KGENOME_CELL_STRING, 0 }
};

/*
 * THE DECODER'S SWEEP VIEW IS THIS FORM, not a look-alike: genotype fills
 * struct kgenome_x86_sop with the numbers of kgenome_cell_operand and the adapter copies the
 * three operands as they stand. The asserts are what makes that agreement a fact
 * and not a coincidence.
 */
_Static_assert(sizeof(struct kgenome_x86_sop) == sizeof(struct kgenome_cell_operand), "operand size");
_Static_assert(offsetof(struct kgenome_x86_sop, kind) == offsetof(struct kgenome_cell_operand, kind) &&
	       offsetof(struct kgenome_x86_sop, reg) == offsetof(struct kgenome_cell_operand, reg) &&
	       offsetof(struct kgenome_x86_sop, index) == offsetof(struct kgenome_cell_operand, index) &&
	       offsetof(struct kgenome_x86_sop, scale) == offsetof(struct kgenome_cell_operand, scale) &&
	       offsetof(struct kgenome_x86_sop, size) == offsetof(struct kgenome_cell_operand, size) &&
	       offsetof(struct kgenome_x86_sop, flags) == offsetof(struct kgenome_cell_operand, flags) &&
	       offsetof(struct kgenome_x86_sop, seg) == offsetof(struct kgenome_cell_operand, seg) &&
	       offsetof(struct kgenome_x86_sop, disp) == offsetof(struct kgenome_cell_operand, disp) &&
	       offsetof(struct kgenome_x86_sop, imm) == offsetof(struct kgenome_cell_operand, imm),
	       "operand layout");
_Static_assert(KGENOME_X86_SK_NONE == KGENOME_CELL_O_NONE && KGENOME_X86_SK_REG == KGENOME_CELL_O_REG &&
	       KGENOME_X86_SK_MEM == KGENOME_CELL_O_MEM && KGENOME_X86_SK_IMM == KGENOME_CELL_O_IMM &&
	       KGENOME_X86_SK_REL == KGENOME_CELL_O_REL, "operand kinds");
_Static_assert(KGENOME_X86_SF_WRITE == KGENOME_CELL_OF_WRITE && KGENOME_X86_SF_READ == KGENOME_CELL_OF_READ &&
	       KGENOME_X86_SF_RIPREL == KGENOME_CELL_OF_RIPREL && KGENOME_X86_SF_HIGH8 == KGENOME_CELL_OF_HIGH8 &&
	       KGENOME_X86_SREG_NONE == KGENOME_CELL_REG_NONE, "operand flags");

uint32_t kgenome_cell_decode_x86(const uint8_t *p, uint32_t n, uint64_t va,
			unsigned bits, struct kgenome_cell_insn *out)
{
	struct kgenome_x86_sweep x;
	const struct xcls *c;
	unsigned op, k;

	if (!p || !n || !out)
		return 0;
	if (kgenome_x86_sweep(&x, p, n, bits == 32 ? 32 : 64) != KGENOME_OK)
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
	c = x.id < (unsigned)KGENOME_X86_I__COUNT ? &g_cls[x.id] : &g_cls[0];
	op = c->op;
	/* The x87 test needs the category, which the table cannot hold. */
	if (op == KGENOME_CELL_OTHER && x.cat == KGENOME_X86_C_X87_ALU)
		op = KGENOME_CELL_FPU;
	out->op = (uint8_t)op;
	out->len = x.len;
	out->n_op = x.n;
	out->flags = (uint8_t)(c->flags | (x.rep ? KGENOME_CELL_F_REP : 0u));
	out->cond = x.cond;
	if (op == KGENOME_CELL_MOV_SPECIAL)
		out->cond = x.id == KGENOME_X86_I_MOV_CR ? KGENOME_CELL_SR_CR
			  : x.id == KGENOME_X86_I_MOV_DR ? KGENOME_CELL_SR_DR
						    : KGENOME_CELL_SR_TR;
	/* The registers it writes: the ones it names and the ones it does not - see
	 * kgenome_cell_insn.wmask. The decoder reports both, so the consumer need not care which. */
	out->wmask = x.wmask;
	out->at_va = va;
	out->at = va;
	/*
	 * KGENOME_BROKEN AND NOT (uint64_t)-1, WHICH IS A DIFFERENT NUMBER.
	 *
	 * cell.h says "no target" is KGENOME_BROKEN, and KGENOME_BROKEN is
	 * UINT64_MAX - 1. Writing UINT64_MAX here meant every reader's
	 * `target_va != KGENOME_BROKEN` was true for EVERY instruction, branch
	 * or not. MEASURED: kgenome_cell_next then called kgenome_image_addr_to_off -
	 * a linear walk of the segment table - 1,327,512 times over a 12 MB
	 * subset where only 273,617 instructions have a relative target,
	 * and that one wasted call was 6.2% of the whole scan.
	 *
	 * It did not produce a wrong answer, which is why it survived: the
	 * walk found no segment holding UINT64_MAX and returned KGENOME_BROKEN,
	 * so `target` came out right by the long way round. `target_va` did
	 * not - it kept UINT64_MAX, and a reader testing IT against
	 * KGENOME_BROKEN still sees a target that is not there.
	 */
	out->target = KGENOME_BROKEN;
	out->target_va = KGENOME_BROKEN;
	memcpy(out->o, x.op, sizeof out->o);
	for (k = 0; k < x.n; k++) {
		if (x.op[k].kind == KGENOME_CELL_O_REL) {
			out->target_va = va + x.len +
					 (uint64_t)(int64_t)(int32_t)x.op[k].imm;
			out->target = out->target_va;
		}
	}
	return x.len;
}
