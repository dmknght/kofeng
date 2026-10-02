/*
 * kdis_walk - decoding code without running it, which is what a rule against a
 * polymorphic decryptor has to be written on. See kofmod/kdis.h.
 *
 * WHAT IS ASSERTED, and each is something such a rule depends on:
 *
 *   THE LENGTHS, because a walk that mis-sizes one instruction reads rubbish
 *   from the next byte onward - and reads it without complaining.
 *
 *   THE CLASS AND THE OPERAND KINDS, because that is the whole vocabulary: a
 *   rule says "an XOR whose destination is memory", not "31 1C 8E".
 *
 *   A RELATIVE BRANCH RESOLVED BACK TO AN OFFSET, because stepping over a
 *   generator's junk means following its jumps, and a target left as an
 *   address is a target the cursor cannot be moved to.
 *
 *   AN INDIRECT BRANCH LEFT UNRESOLVED, which is the same assertion from the
 *   other side: `jmp eax` has a target and this is not the thing that knows
 *   it.
 *
 *   THE CONSTANT MAP, INCLUDING WHERE IT GIVES UP. `mov eax, [esi]` must make
 *   eax unknown. A map that guessed there would hand a rule a number that is
 *   not in the program, and the rule would have no way to tell.
 *
 * The instruction run below is not invented: it is the shape the four Sality
 * bodies open with - call/pop to find yourself, subtract a constant, junk, a
 * memory XOR, a jump onward.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/pe.h"
#include "../../libkofeng/analyzers/parsers/binaries/disasm/kdis.h"

static int failures;

static void fail(const char *what)
{
	printf("  FAIL %s\n", what);
	failures++;
}

#define CODE_OFF  0x400u
#define CODE_RVA  0x1000u
#define BASE      0x400000u

int main(void)
{
	static const uint8_t code[] = {
		0xE8,0x00,0x00,0x00,0x00,        /* call $+5           5 */
		0x5D,                            /* pop ebp            1 */
		0x81,0xED,0x05,0x10,0x40,0x00,   /* sub ebp,0x401005   6 */
		0xBF,0x0C,0x02,0x00,0x00,        /* mov edi,0x20c      5 */
		0x81,0xC7,0x00,0x01,0x00,0x00,   /* add edi,0x100      6 */
		0x8B,0x06,                       /* mov eax,[esi]      2 */
		0x31,0x1C,0x8E,                  /* xor [esi+ecx*4],ebx 3 */
		0xEB,0x02,                       /* jmp +2             2 */
		0x90,0x90,                       /* nop nop  (skipped)   */
		0xFF,0xE0,                       /* jmp eax            2 */
		0xC3                             /* ret                1 */
	};
	static const struct { uint8_t op; uint8_t len; } want[] = {
		{ KDIS_CALL, 5 }, { KDIS_POP, 1 }, { KDIS_SUB, 6 },
		{ KDIS_MOV, 5 },  { KDIS_ADD, 6 }, { KDIS_MOV, 2 },
		{ KDIS_XOR, 3 },  { KDIS_JMP, 2 }
	};
	uint8_t buf[0x800];
	struct kof_pe_info pe;
	struct kof_obj_ctx ctx;
	struct kof_kdis k;
	struct kdis_insn in;
	uint64_t v;
	unsigned i;

	memset(buf, 0x90, sizeof buf);
	memcpy(buf + CODE_OFF, code, sizeof code);

	/* Just enough of a PE for offsets and addresses to translate. */
	memset(&pe, 0, sizeof pe);
	pe.valid = 1;
	pe.image_base = BASE;
	pe.sec_count = 1;
	pe.sec[0].file_off = CODE_OFF;
	pe.sec[0].file_size = sizeof buf - CODE_OFF;
	pe.sec[0].mem_rva = CODE_RVA;
	pe.sec[0].mem_size = pe.sec[0].file_size;

	memset(&ctx, 0, sizeof ctx);
	ctx.format = KOF_FMT_PE;
	ctx.arch = KOF_ARCH_X86;
	ctx.file_header = &pe;
	ctx.obj_size = sizeof buf;

	memset(&k, 0, sizeof k);
	if (!kof_kdis_seek(&k, CODE_OFF, 0))
		fail("seek");

	for (i = 0; i < sizeof want / sizeof want[0]; i++) {
		if (!kof_kdis_next(&k, &ctx, buf, sizeof buf, &in)) {
			fail("the walk stopped early");
			break;
		}
		if (in.op != want[i].op || in.len != want[i].len) {
			printf("  FAIL insn %u: class %u len %u, want %u/%u\n",
			       i, in.op, in.len, want[i].op, want[i].len);
			failures++;
		}
		switch (i) {
		case 0:
			/* call $+5 lands on the byte after itself, and the
			 * offset is what the cursor would be moved to. */
			if (in.target != CODE_OFF + 5u)
				fail("call $+5 did not resolve to the next offset");
			if (in.target_va != BASE + CODE_RVA + 5u)
				fail("call $+5 did not resolve its address");
			break;
		case 2:
			if (in.n_op != 2u || in.o[0].kind != KDIS_O_REG ||
			    in.o[0].reg != KDIS_REG_BP ||
			    in.o[1].kind != KDIS_O_IMM ||
			    in.o[1].imm != 0x401005u)
				fail("sub ebp, 0x401005 came apart wrongly");
			break;
		case 4:
			/* mov edi,0x20c then add edi,0x100 - the whole point
			 * of the map is that the second is still known. */
			if (!kof_kdis_reg(&k, KDIS_REG_DI, &v) || v != 0x30cu)
				fail("edi was not tracked through the add");
			break;
		case 5:
			if (kof_kdis_reg(&k, KDIS_REG_AX, &v))
				fail("eax was claimed known after a load from memory");
			break;
		case 6:
			if (in.o[0].kind != KDIS_O_MEM ||
			    in.o[0].reg != KDIS_REG_SI ||
			    in.o[0].index != KDIS_REG_CX ||
			    in.o[0].scale != 4u ||
			    in.o[1].kind != KDIS_O_REG ||
			    in.o[1].reg != KDIS_REG_BX)
				fail("xor [esi+ecx*4], ebx came apart wrongly");
			break;
		case 7:
			if (in.target != CODE_OFF + 32u)
				fail("jmp +2 did not resolve past the junk");
			break;
		default:
			break;
		}
	}

	/*
	 * FOLLOWING THE BRANCH, WITH THE MAP KEPT. This is the move a rule
	 * makes to step over a generator's junk, and edi has to survive it -
	 * that is what `keep` is for.
	 */
	if (!kof_kdis_seek(&k, CODE_OFF + 32u, 1))
		fail("seek to the branch target");
	if (!kof_kdis_reg(&k, KDIS_REG_DI, &v) || v != 0x30cu)
		fail("the constant map was lost across a kept seek");
	if (!kof_kdis_next(&k, &ctx, buf, sizeof buf, &in) || in.op != KDIS_JMP)
		fail("the instruction at the branch target is not the jmp");
	else if (in.target != KOF_BROKEN)
		fail("jmp eax was given a target it cannot have");
	if (!kof_kdis_next(&k, &ctx, buf, sizeof buf, &in) || in.op != KDIS_RET)
		fail("ret");

	/* And a seek that does NOT keep clears it. */
	if (!kof_kdis_seek(&k, CODE_OFF, 0))
		fail("reseek");
	if (kof_kdis_reg(&k, KDIS_REG_DI, &v))
		fail("a fresh walk started with a register already known");

	printf("kdis walk: lengths, classes, operands, a resolved branch, an"
	       " unresolved one, the constant map - %s\n",
	       failures ? "FAILED" : "ok");
	return failures != 0;
}
