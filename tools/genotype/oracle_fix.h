/*
 * oracle_fix - what the reference decoder names WRONG, put right in one place.
 *
 * The generated tables are measured from the reference (x86_gen.c asks it what every encoding
 * is), so a mistake of the reference is copied into the table unless it is corrected between
 * the question and the record. x86_gen.c and x86_diff.c both read the reference through this
 * function, so the table and the differential that checks it agree on the corrected answer.
 *
 * Each entry below was found by running every encoding the decoder accepts through GNU objdump
 * (tests/lib/genome/cov_x86_forms.c) and reading the instruction NAMES that disagree beyond
 * spelling. The Intel and AMD manuals decide:
 *
 *   0F 12 /r with a MEMORY operand is MOVLPS (the load of the low half); only the register form
 *   (mod = 11b) is MOVHLPS. The reference gives both forms the name MOVHLPS. The EVEX/VEX
 *   forms and 0F 16 (MOVHPS memory / MOVLHPS register) it names correctly. The emulator used
 *   to read a MOVHLPS with a memory source as the load it is.
 *
 *   XOP VPSHLW (opcode 95) and VPSHLD (96) with XOP.W = 1 - the operand-swapped form - the
 *   reference names VPSHLB. Opcodes 94 and 97 and every XOP.W = 0 form are right.
 *
 * The identity changes; nothing else about the record does.
 */
#ifndef KOFENG_TOOLS_ORACLE_FIX_H
#define KOFENG_TOOLS_ORACLE_FIX_H

#include "bddisasm.h"

static inline unsigned oracle_fix_id(const INSTRUX *ix)
{
	unsigned id = (unsigned)ix->Instruction;

	if (id == ND_INS_MOVHLPS && ix->HasModRm && ix->ModRm.mod != 3)
		return ND_INS_MOVLPS;
	if (id == ND_INS_VPSHLB && ix->HasXop && ix->Xop.w) {
		if (ix->PrimaryOpCode == 0x95)
			return ND_INS_VPSHLW;
		if (ix->PrimaryOpCode == 0x96)
			return ND_INS_VPSHLD;
	}
	return id;
}

#endif
