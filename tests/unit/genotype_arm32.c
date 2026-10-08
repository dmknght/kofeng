/*
 * genotype_arm32 - the ARM state and Thumb state decode tables, against what the
 * instruction set says.
 *
 * The encodings below are real instructions from the Mirai ARM binaries in the
 * corpus where it has one (the file and address are in the decode_arm32 test, which
 * checks the same words through the engine's form) and are written from the ARM
 * ARM where it has none - all of Thumb state, the corpus having no Thumb code. Each
 * says what it IS, and the check is the NAME genotype gives it, its length and
 * the fields read out of it. They need nothing but this tree.
 *
 * Two things about the tables themselves are checked at the end: that no row is
 * shadowed by an earlier one, and that the lists derived from them fit their pools.
 *
 * The other checks live elsewhere because they need more than this tree:
 * tools/celllysis/arm32_equiv.c decodes every word against the decoder this one
 * replaced, and tools/celllysis/arm32_diff.c against Capstone.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../libgenome/genotype/arm32/arm32.h"
#include "../../libgenome/genotype/arm32/thumb.h"
#include "../../libgenome/genotype/arm32/arm32_int.h"

static int failures;
static int checks;

static void ok(const char *what, int cond)
{
	checks++;
	if (!cond) {
		printf("  FAIL %s\n", what);
		failures++;
	}
}

/* ---- ARM state ------------------------------------------------------------ */

struct acase {
	const char *what;
	uint32_t w;
	unsigned id;
	unsigned cond;          /* the condition field as encoded */
	enum gt_status st;
};

#define AOK GT_OK

static const struct acase A[] = {
	{ "mov r7,#1  (a syscall number)", 0xe3a07001, GT_ARM32_I_MOV_IMM, 14, AOK },
	{ "mov r7,#0x80000000  (the rotation)", 0xe3a07102, GT_ARM32_I_MOV_IMM, 14, AOK },
	{ "ldr r7,[pc,#0xb4]  (a literal)", 0xe59f70b4, GT_ARM32_I_LDR_IMM, 14, AOK },
	{ "svc 0  (EABI)", 0xef000000, GT_ARM32_I_SVC, 14, AOK },
	{ "svc 0x900037  (OABI: the number is in the instruction)", 0xef900037, GT_ARM32_I_SVC, 14, AOK },
	{ "bl 0x139c0", 0xeb002dfe, GT_ARM32_I_BL, 14, AOK },
	{ "bx lr  (a return)", 0xe12fff1e, GT_ARM32_I_BX, 14, AOK },
	{ "bxne r3", 0x112fff13, GT_ARM32_I_BX, 1, AOK },
	{ "push {r4,r5,r6,r7,lr}  (stmdb sp!)", 0xe92d40f0, GT_ARM32_I_PUSH, 14, AOK },
	{ "str r2,[sp,#-4]!  (a one-register push)", 0xe52d2004, GT_ARM32_I_PUSH_1, 14, AOK },
	{ "pop {r4,r5,pc}  (ldmia sp!)", 0xe8bd8030, GT_ARM32_I_POP, 14, AOK },
	{ "ldr pc,[sp],#4  (pop {pc})", 0xe49df004, GT_ARM32_I_POP_1, 14, AOK },
	{ "ldm r0,{r0,r1}  (not sp: not a pop)", 0xe8900003, GT_ARM32_I_LDM, 14, AOK },
	{ "bne 0x8120", 0x1a000006, GT_ARM32_I_B, 1, AOK },
	{ "add r0,r0,#1", 0xe2800001, GT_ARM32_I_ADD_IMM, 14, AOK },
	{ "add r0,r1,r2", 0xe0810002, GT_ARM32_I_ADD_REG, 14, AOK },
	{ "eor r3,r3,r3", 0xe0233003, GT_ARM32_I_EOR_REG, 14, AOK },
	{ "mvn r0,#0", 0xe3e00000, GT_ARM32_I_MVN_IMM, 14, AOK },
	{ "lsl r3,sb,#2  (mov with a shifted operand)", 0xe1a03109, GT_ARM32_I_MOV_REG, 14, AOK },
	{ "mov r0,r1,lsl r2  (the amount in a register)", 0xe1a00211, GT_ARM32_I_MOV_RSR, 14, AOK },
	{ "cmp r3,#0", 0xe3530000, GT_ARM32_I_CMP_IMM, 14, AOK },
	{ "ldrb r3,[r4]", 0xe5d43000, GT_ARM32_I_LDRB_IMM, 14, AOK },
	{ "orr r3,r3,r0,lsr #8", 0xe1833420, GT_ARM32_I_ORR_REG, 14, AOK },
	{ "movw r0,#0x1234", 0xe3010234, GT_ARM32_I_MOVW, 14, AOK },
	{ "movt r0,#0xabcd", 0xe34a0bcd, GT_ARM32_I_MOVT, 14, AOK },
	{ "blx 0x8008  (the unconditional space)", 0xfa000000, GT_ARM32_I_BLX_IMM, 15, AOK },
	{ "udf #0  (permanently undefined: an instruction)", 0xe7f000f0, GT_ARM32_I_UDF, 14, AOK },
	{ "mul r0,r1,r2", 0xe0000291, GT_ARM32_I_MUL, 14, AOK },
	{ "ldrh r1,[r2,#6]", 0xe1d210b6, GT_ARM32_I_LDRH_IMM, 14, AOK },
	{ "strd r2,r3,[sp]", 0xe1cd20f0, GT_ARM32_I_STRD_IMM, 14, AOK },
	{ "bkpt #1", 0xe1200071, GT_ARM32_I_BKPT, 14, AOK },
	{ "clz r0,r1", 0xe16f0f11, GT_ARM32_I_CLZ, 14, AOK },
	{ "uxtb r0,r1", 0xe6ef0071, GT_ARM32_I_UXTB, 14, AOK },
	{ "uxtab r0,r2,r1  (Rn is not pc: the add form)", 0xe6e20071, GT_ARM32_I_UXTAB, 14, AOK },
	{ "sdiv r0,r1,r2", 0xe710f211, GT_ARM32_I_SDIV, 14, AOK },
	{ "mrc p15,0,r0,c13,c0,3  (the thread pointer)", 0xee1d0f70, GT_ARM32_I_MRC, 14, AOK },
	{ "dmb ish", 0xf57ff05b, GT_ARM32_I_DMB, 15, AOK },
	{ "unallocated: the 0111 multiply slot", 0xe0700090, GT_ARM32_I_INVALID, 14, GT_INVALID },
	{ "unallocated: strd with P=0 W=1", 0xe0e020f0, GT_ARM32_I_INVALID, 14, GT_INVALID },
	{ "unallocated: the unconditional space, bits 27:25 = 000, not cps", 0xf0000000, GT_ARM32_I_INVALID, 15, GT_INVALID },
};

static void arm32_curated(void)
{
	size_t i;

	for (i = 0; i < sizeof A / sizeof A[0]; i++) {
		const struct acase *c = &A[i];
		struct gt_arm32_insn in;
		enum gt_status st = gt_arm32_decode(&in, c->w);
		char buf[160];

		snprintf(buf, sizeof buf, "arm32 %08x %s: id %u (want %u)", (unsigned)c->w, c->what,
			 (unsigned)in.id, c->id);
		ok(buf, in.id == c->id);
		ok("  status", st == c->st);
		ok("  length 4", in.len == 4u);
		ok("  condition as encoded", in.cond == c->cond);
		ok("  the word is kept", in.w == c->w);
	}
}

/* The fields, read out of the words above. */
static void arm32_fields(void)
{
	struct gt_arm32_insn in;

	gt_arm32_decode(&in, 0xe3a07102);              /* mov r7,#0x80000000 */
	ok("mov: rd 7", gt_arm32_r12(in) == 7u);
	ok("mov: imm8 2 rotated right by 2 * 1 is 0x80000000", gt_arm32_modimm(in) == 0x80000000u);
	ok("mov: S clear", gt_arm32_s(in) == 0u);

	gt_arm32_decode(&in, 0xe59f70b4);              /* ldr r7,[pc,#0xb4] */
	ok("ldr literal: base pc", gt_arm32_r16(in) == 15u);
	ok("ldr literal: rt 7", gt_arm32_r12(in) == 7u);
	ok("ldr literal: offset 0xb4", gt_arm32_imm12(in) == 0xb4u);
	ok("ldr literal: pre-indexed, added, no write-back",
	   gt_arm32_p(in) == 1u && gt_arm32_u(in) == 1u && gt_arm32_wb(in) == 0u);
	ok("ldr literal: a load of a word", gt_arm32_s(in) == 1u && gt_arm32_b(in) == 0u);

	gt_arm32_decode(&in, 0xe49df004);              /* ldr pc,[sp],#4 */
	ok("pop one: post-indexed", gt_arm32_p(in) == 0u);
	ok("pop one: rt is pc", gt_arm32_r12(in) == 15u);

	gt_arm32_decode(&in, 0xeb002dfe);              /* bl */
	ok("bl: offset is the signed 24 bits times 4", gt_arm32_branch_off(in) == 0x2dfe * 4);
	gt_arm32_decode(&in, 0xeafffffe);              /* b . */
	ok("b to itself: offset -8 from pc+8 is -8 + 8", gt_arm32_branch_off(in) == -8);
	gt_arm32_decode(&in, 0xfb000000);              /* blx, H set */
	ok("blx: the H bit is the halfword", gt_arm32_h(in) == 1u);

	gt_arm32_decode(&in, 0xe92d40f0);
	ok("push: list r4-r7, lr", gt_arm32_list(in) == 0x40f0u);

	gt_arm32_decode(&in, 0xef900037);
	ok("svc: the 24-bit immediate", gt_arm32_imm24(in) == 0x900037u);

	gt_arm32_decode(&in, 0xe1833420);              /* orr r3,r3,r0,lsr #8 */
	ok("orr: shift type lsr", gt_arm32_shift_type(in) == 1u);
	ok("orr: shift amount 8", gt_arm32_shift_imm(in) == 8u);
	ok("orr: rm 0, rn 3, rd 3",
	   gt_arm32_r0(in) == 0u && gt_arm32_r16(in) == 3u && gt_arm32_r12(in) == 3u);

	gt_arm32_decode(&in, 0xe1a00211);              /* mov r0,r1,lsl r2 */
	ok("rsr: amount register is bits 11:8", gt_arm32_r8(in) == 2u);

	gt_arm32_decode(&in, 0xe3010234);              /* movw r0,#0x1234 */
	ok("movw: imm4:imm12", gt_arm32_imm16(in) == 0x1234u);

	gt_arm32_decode(&in, 0xe1d210b6);              /* ldrh r1,[r2,#6] */
	ok("ldrh: offset is split across 11:8 and 3:0", gt_arm32_imm8_split(in) == 6u);

	gt_arm32_decode(&in, 0xe6ef0471);              /* uxtb r0,r1,ror #8 */
	ok("uxtb: the rotation is in bytes", gt_arm32_rot(in) == 1u);

	gt_arm32_decode(&in, 0xe1200071);
	ok("bkpt: the 16 bits split across 19:8 and 3:0", gt_arm32_imm16_split(in) == 1u);
}

/* ---- Thumb state ---------------------------------------------------------- */

struct tcase {
	const char *what;
	uint16_t hw0, hw1;      /* hw1 is ignored when the instruction is 16 bits */
	unsigned id;
	unsigned len;
	enum gt_status st;
};

static const struct tcase T[] = {
	{ "movs r7,#0x37", 0x2737, 0, GT_THUMB_I_MOVS_IMM8, 2, GT_OK },
	{ "svc 0", 0xdf00, 0, GT_THUMB_I_SVC, 2, GT_OK },
	{ "push {r4,lr}", 0xb510, 0, GT_THUMB_I_PUSH, 2, GT_OK },
	{ "pop {r4,pc}", 0xbd10, 0, GT_THUMB_I_POP, 2, GT_OK },
	{ "bx lr", 0x4770, 0, GT_THUMB_I_BX, 2, GT_OK },
	{ "blx r3", 0x4798, 0, GT_THUMB_I_BLX_REG, 2, GT_OK },
	{ "ldr r7,[pc,#0x40]", 0x4f10, 0, GT_THUMB_I_LDR_LIT, 2, GT_OK },
	{ "bne to itself", 0xd1fe, 0, GT_THUMB_I_BCOND, 2, GT_OK },
	{ "cbz r0", 0xb100, 0, GT_THUMB_I_CBZ, 2, GT_OK },
	{ "add sp,#8", 0xb002, 0, GT_THUMB_I_ADD_SP_IMM7, 2, GT_OK },
	{ "adds r0,#1", 0x3001, 0, GT_THUMB_I_ADDS_IMM8, 2, GT_OK },
	{ "adds r0,r1,r2", 0x1888, 0, GT_THUMB_I_ADDS_REG, 2, GT_OK },
	{ "negs r0,r1", 0x4248, 0, GT_THUMB_I_RSBS_IMM0, 2, GT_OK },
	{ "cmp r0,#0", 0x2800, 0, GT_THUMB_I_CMP_IMM8, 2, GT_OK },
	{ "lsls r0,r0,#2", 0x0080, 0, GT_THUMB_I_LSL_IMM, 2, GT_OK },
	{ "movs r0,r1  (lsl #0)", 0x0008, 0, GT_THUMB_I_MOVS_REG, 2, GT_OK },
	{ "mov r0,r1  (any registers)", 0x4608, 0, GT_THUMB_I_MOV_REG_HI, 2, GT_OK },
	{ "muls r0,r1,r0", 0x4348, 0, GT_THUMB_I_MULS, 2, GT_OK },
	{ "it eq", 0xbf08, 0, GT_THUMB_I_IT, 2, GT_OK },
	{ "nop", 0xbf00, 0, GT_THUMB_I_HINT, 2, GT_OK },
	{ "udf #0", 0xde00, 0, GT_THUMB_I_UDF, 2, GT_OK },
	{ "unallocated: 1011 1000", 0xb800, 0, GT_THUMB_I_INVALID, 2, GT_INVALID },
	{ "bl 0x8008 from 0x8000", 0xf000, 0xf802, GT_THUMB_I_BL, 4, GT_OK },
	{ "bl backwards", 0xf7ff, 0xfffe, GT_THUMB_I_BL, 4, GT_OK },
	{ "pop.w {r4,r5,pc}", 0xe8bd, 0x8030, GT_THUMB_I_POP_W, 4, GT_OK },
	{ "push.w {r4-r8,lr}", 0xe92d, 0x41f0, GT_THUMB_I_PUSH_W, 4, GT_OK },
	{ "ldr r7,[sp],#4  (pop {r7})", 0xf85d, 0x7b04, GT_THUMB_I_POP_REG_W, 4, GT_OK },
	{ "str r7,[sp,#-4]!  (push {r7})", 0xf84d, 0x7d04, GT_THUMB_I_PUSH_REG_W, 4, GT_OK },
	{ "ldr.w ip,[pc,#12]", 0xf8df, 0xc00c, GT_THUMB_I_LDR_LIT_W, 4, GT_OK },
	{ "mov.w r0,#1", 0xf04f, 0x0001, GT_THUMB_I_MOV_IMM_W, 4, GT_OK },
	{ "movw r0,#0x1234", 0xf241, 0x2034, GT_THUMB_I_MOVW, 4, GT_OK },
	{ "tbb [r0,r1]", 0xe8d0, 0xf001, GT_THUMB_I_TBB, 4, GT_OK },
	{ "add.w r0,r1,r2,lsl #3", 0xeb01, 0x00c2, GT_THUMB_I_ADD_REG_W, 4, GT_OK },
	{ "cmp.w r1,#4  (the compare is an add with Rd = pc and S)", 0xf1b1, 0x0f04, GT_THUMB_I_CMP_IMM_W, 4, GT_OK },
	{ "sdiv r0,r1,r2", 0xfb91, 0xf0f2, GT_THUMB_I_SDIV, 4, GT_OK },
	{ "mul r0,r1,r2", 0xfb01, 0xf002, GT_THUMB_I_MUL_W, 4, GT_OK },
	{ "uxtb.w r0,r1", 0xfa5f, 0xf081, GT_THUMB_I_UXTB_W, 4, GT_OK },
	{ "b.w", 0xf000, 0x9000, GT_THUMB_I_B_W, 4, GT_OK },
	{ "udf.w #0", 0xf7f0, 0xa000, GT_THUMB_I_UDF_W, 4, GT_OK },
	{ "unallocated: a store with pc as the base", 0xf84f, 0x0000, GT_THUMB_I_INVALID, 4, GT_INVALID },
};

static void thumb_curated(void)
{
	size_t i;

	for (i = 0; i < sizeof T / sizeof T[0]; i++) {
		const struct tcase *c = &T[i];
		struct gt_thumb_insn in;
		enum gt_status st;
		char buf[160];

		ok("the length comes from the first halfword", gt_thumb_len(c->hw0) == c->len);
		st = gt_thumb_decode(&in, c->hw0, c->hw1);
		snprintf(buf, sizeof buf, "thumb %04x %s: id %u (want %u)", c->hw0, c->what,
			 (unsigned)in.id, c->id);
		ok(buf, in.id == c->id);
		ok("  status", st == c->st);
		ok("  length", in.len == c->len);
		ok("  the halfwords are kept", in.w == ((uint32_t)c->hw0 << 16 | (c->len == 4u ? c->hw1 : 0u)));
	}
}

static void thumb_fields(void)
{
	struct gt_thumb_insn in;

	gt_thumb_decode(&in, 0x2737, 0);               /* movs r7,#0x37 */
	ok("movs: rd 7, imm8 0x37", gt_thumb_n_r8(in) == 7u && gt_thumb_n_imm8(in) == 0x37u);

	gt_thumb_decode(&in, 0xb510, 0);               /* push {r4,lr} */
	ok("push: list r4, and the lr bit", gt_thumb_n_list(in) == 0x10u && gt_thumb_n_bit(in, 8) == 1u);

	gt_thumb_decode(&in, 0x4770, 0);               /* bx lr */
	ok("bx: rm lr", gt_thumb_n_hi_rm(in) == 14u);

	gt_thumb_decode(&in, 0x4f10, 0);               /* ldr r7,[pc,#0x40] */
	ok("ldr literal: rt 7, imm8 0x10 (a word offset)", gt_thumb_n_r8(in) == 7u && gt_thumb_n_imm8(in) == 0x10u);

	gt_thumb_decode(&in, 0x1888, 0);               /* adds r0,r1,r2 */
	ok("adds: rd 0, rn 1, rm 2",
	   gt_thumb_n_r0(in) == 0u && gt_thumb_n_r3(in) == 1u && gt_thumb_n_r6(in) == 2u);

	gt_thumb_decode(&in, 0xd1fe, 0);               /* bne . */
	ok("b<cond>: cond ne, offset -4 bytes", gt_thumb_n_cond(in) == 1u && gt_thumb_n_bcond_off(in) == -4);

	gt_thumb_decode(&in, 0xb100, 0);               /* cbz r0, +0 */
	ok("cbz: rn 0, offset 0", gt_thumb_n_r0(in) == 0u && gt_thumb_n_cbz_off(in) == 0u);

	gt_thumb_decode(&in, 0xb002, 0);
	ok("add sp: imm7 2 (times 4 is 8)", gt_thumb_n_imm7(in) == 2u);

	gt_thumb_decode(&in, 0xf000, 0xf802);          /* bl +4 */
	ok("bl: offset 4", gt_thumb_w_b_off(in) == 4);
	gt_thumb_decode(&in, 0xf7ff, 0xfffe);          /* bl -4 */
	ok("bl: offset -4", gt_thumb_w_b_off(in) == -4);

	gt_thumb_decode(&in, 0xf04f, 0x0001);          /* mov.w r0,#1 */
	ok("mov.w: rd 0, the modified immediate is 1", gt_thumb_w_rd(in) == 0u && gt_thumb_w_modimm(in) == 1u);
	gt_thumb_decode(&in, 0xf04f, 0x12ff);          /* imm3 = 1, imm8 = 0xff: 0x00ff00ff */
	ok("mov.w: the replicated-halfword immediate",
	   gt_thumb_w_imm12(in) == 0x1ffu && gt_thumb_w_modimm(in) == 0x00ff00ffu);

	gt_thumb_decode(&in, 0xf241, 0x2034);          /* movw r0,#0x1234 */
	ok("movw: imm4:i:imm3:imm8", gt_thumb_w_imm16(in) == 0x1234u);

	gt_thumb_decode(&in, 0xe8bd, 0x8030);          /* pop.w */
	ok("pop.w: base sp, list r4 r5 pc", gt_thumb_w_rn(in) == 13u && gt_thumb_w_list(in) == 0x8030u);

	gt_thumb_decode(&in, 0xf8df, 0xc00c);          /* ldr.w ip,[pc,#12] */
	ok("ldr.w literal: rt 12, offset 12, added",
	   gt_thumb_w_rt(in) == 12u && gt_thumb_w_ls_imm12(in) == 12u && gt_thumb_w_bit0(in, 7) == 1u);

	gt_thumb_decode(&in, 0xeb01, 0x00c2);          /* add.w r0,r1,r2,lsl #3 */
	ok("add.w: rn 1, rd 0, rm 2, lsl #3",
	   gt_thumb_w_rn(in) == 1u && gt_thumb_w_rd(in) == 0u && gt_thumb_w_rm(in) == 2u &&
	   gt_thumb_w_shift_type(in) == 0u && gt_thumb_w_shift_imm(in) == 3u);

	gt_thumb_decode(&in, 0xe8d0, 0xf001);          /* tbb [r0,r1] */
	ok("tbb: base 0, index 1", gt_thumb_w_rn(in) == 0u && gt_thumb_w_rm(in) == 1u);
}

/* ---- the tables themselves -------------------------------------------------- */

/*
 * Every answer is a name this enum has, and the length is the first halfword's:
 * over every ARM state word that a million-odd hash walks, every Thumb first
 * halfword with a spread of second ones.
 */
static void tables(void)
{
	struct gt_arm32_stats st;

	uint32_t i;
	int bad_arm = 0, bad_thumb = 0, bad_len = 0;

	for (i = 0; i < 1u << 20; i++) {
		struct gt_arm32_insn in;
		uint32_t w = i * 2654435761u ^ (i << 12);

		gt_arm32_decode(&in, w);
		if (in.id >= GT_ARM32_I_COUNT || in.len != 4u)
			bad_arm++;
	}
	/*
	 * THE ROWS ARE A PRIORITY LIST, written by hand, and a row put after the
	 * general one it is cut out of is never reached - silently. The index builder
	 * counts the rows no key reaches. The pools are fixed storage: the check is
	 * that the rows still fit with room to spare.
	 */
	gt_arm32_stats(&st);
	ok("no ARM state row is shadowed by an earlier one", st.shadowed_arm32 == 0u);
	ok("no Thumb state row is shadowed by an earlier one", st.shadowed_thumb == 0u);
	ok("the ARM state lists fit their pool with room to spare", st.lists_arm32 * 2u < st.cap_arm32);
	ok("the Thumb state lists fit their pool with room to spare", st.lists_thumb * 2u < st.cap_thumb);
	ok("every ARM state word decodes to a known name", !bad_arm);
	for (i = 0; i < 65536u; i++) {
		uint32_t k;

		for (k = 0; k < 64u; k++) {
			struct gt_thumb_insn in;
			uint32_t h1 = (k * 2654435761u) >> 16;

			gt_thumb_decode(&in, i, h1);
			if (in.id >= GT_THUMB_I_COUNT)
				bad_thumb++;
			if (in.len != gt_thumb_len(i))
				bad_len++;
		}
	}
	ok("every Thumb halfword pair decodes to a known name", !bad_thumb);
	ok("the length is always what the first halfword says", !bad_len);
}

int main(void)
{
	printf("genotype arm32:\n");
	arm32_curated();
	arm32_fields();
	thumb_curated();
	thumb_fields();
	tables();
	printf("genotype arm32: %d checks, %s\n", checks, failures ? "FAILED" : "ok");
	return failures ? 1 : 0;
}
