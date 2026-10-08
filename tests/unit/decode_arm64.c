/*
 * decode_arm64 - the AArch64 decoder, against what the instruction set says.
 *
 * Every encoding below was assembled by hand from the A64 encoding diagrams
 * (the field layout is written beside it) or is the well-known compiler
 * output for that instruction, and says what it IS. Nothing here is a
 * transcript of another decoder's answer: the second check - a differential
 * run over random, systematic and real code against a reference decoder - lives
 * in tools/celllysis/arm64_diff.c, needs that reference, and cannot catch a bug
 * both decoders share. This can.
 *
 * What is asserted for each: the class, every register written (wmask - the
 * thing the constant map forgets), the branch target, and the operands where
 * a consumer reads them by value.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include <celllysis/celllysis.h>

static int failures;

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		failures++;
}

#define BIT(r) (1ull << (r))
#define NOTGT KOF_BROKEN

static uint32_t dec(uint32_t w, uint64_t va, struct cell_insn *k)
{
	uint8_t b[4] = { (uint8_t)w, (uint8_t)(w >> 8), (uint8_t)(w >> 16),
			 (uint8_t)(w >> 24) };

	return cell_decode_arm64(b, 4, va, k);
}

struct tc {
	const char *what;
	uint32_t w;
	uint64_t va;
	unsigned op;
	uint64_t wmask;
	unsigned n_op;
	uint64_t target;
};

/*
 * class, written registers, operand count and target for each. Fields in the
 * comments are from the encoding diagrams: sf op S, imm, Rn, Rd, ...
 */
static const struct tc C[] = {
	/* movz: sf=1 opc=10 100101 hw=00 imm16=198 Rd=8 */
	{ "mov x8,#198 (movz)", 0xd28018c8u, 0x400000, CELL_MOV, BIT(8), 2, NOTGT },
	/* movz w0: sf=0 opc=10 hw=00 imm16=1 */
	{ "mov w0,#1 (movz w)", 0x52800020u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	/* movn x0,#0: the value is ~0 */
	{ "mov x0,#-1 (movn)", 0x92800000u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	{ "mov w0,#-1 (movn w)", 0x12800000u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	/* movk x0,#0x1234,lsl #16: keeps 48 bits, so it is no MOV */
	{ "movk x0,#0x1234,lsl #16", 0xf2a24680u, 0x400000, CELL_OTHER, BIT(0), 3, NOTGT },
	/* svc: 11010100 000 imm16=0 000 01 */
	{ "svc #0", 0xd4000001u, 0x400000, CELL_SYSCALL, 0, 1, NOTGT },
	{ "brk #0x3e8", 0xd4207d00u, 0x400000, CELL_INT, 0, 1, NOTGT },
	/* bl: 1 00101 imm26=0x10 -> +0x40 */
	{ "bl .+0x40", 0x94000010u, 0x400000, CELL_CALL, BIT(30), 1, 0x400040 },
	/* b: 0 00101 imm26=-2 -> -8 */
	{ "b .-8", 0x17fffffeu, 0x400000, CELL_JMP, 0, 1, 0x3ffff8 },
	/* b.cond: 01010100 imm19=2 0 cond */
	{ "b.eq .+8", 0x54000040u, 0x400000, CELL_JCC, 0, 1, 0x400008 },
	{ "b.ne .+8", 0x54000041u, 0x400000, CELL_JCC, 0, 1, 0x400008 },
	/* cbz x0,.+0x10: sf=1 011010 op=0 imm19=4 Rt=0 */
	{ "cbz x0,.+0x10", 0xb4000080u, 0x400000, CELL_JCC, 0, 2, 0x400010 },
	{ "cbnz w1,.-4", 0x35ffffe1u, 0x400000, CELL_JCC, 0, 2, 0x3ffffc },
	/* tbz x3,#35,.+0x20: b5=1 011011 op=0 b40=3 imm14=8 Rt=3 */
	{ "tbz x3,#35,.+0x20", 0xb6180103u, 0x400000, CELL_JCC, 0, 3, 0x400020 },
	/* the three branches through a register: 1101011 opc 11111 000000 Rn 00000 */
	{ "ret", 0xd65f03c0u, 0x400000, CELL_RET, 0, 1, NOTGT },
	{ "blr x3", 0xd63f0060u, 0x400000, CELL_CALL, BIT(30), 1, NOTGT },
	{ "br x16", 0xd61f0200u, 0x400000, CELL_JMP, 0, 1, NOTGT },
	{ "eret", 0xd69f03e0u, 0x400000, CELL_IRET, 0, 0, NOTGT },
	/* adrp x0,#0x412000 from 0x400abc: immlo=2 immhi=4 -> 0x12 pages */
	{ "adrp x0,0x412000", 0xd0000080u, 0x400abc, CELL_LEA, BIT(0), 2, NOTGT },
	/* adr x1,.+0x10: immlo=0 immhi=4 */
	{ "adr x1,.+0x10", 0x10000081u, 0x400000, CELL_LEA, BIT(1), 2, NOTGT },
	/* add x0,x0,#0x7a8: sf=1 op=0 S=0 100010 sh=0 imm12=0x7a8 Rn=0 Rd=0 */
	{ "add x0,x0,#0x7a8", 0x911ea000u, 0x400000, CELL_ADD, BIT(0), 2, NOTGT },
	{ "add x0,x1,x2", 0x8b020020u, 0x400000, CELL_ADD, BIT(0), 3, NOTGT },
	{ "sub sp,sp,#32", 0xd10083ffu, 0x400000, CELL_SUB, BIT(31), 2, NOTGT },
	{ "eor x0,x0,x1", 0xca010000u, 0x400000, CELL_XOR, BIT(0), 2, NOTGT },
	{ "mov x0,x1 (orr x0,xzr,x1)", 0xaa0103e0u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	{ "mov x29,sp (add x29,sp,#0)", 0x910003fdu, 0x400000, CELL_MOV, BIT(29), 2, NOTGT },
	/* subs xzr,x0,#5 is cmp; ands xzr,x1,#1 is tst: neither writes a register */
	{ "cmp x0,#5", 0xf100141fu, 0x400000, CELL_CMP, 0, 2, NOTGT },
	{ "tst x1,#1", 0xf240003fu, 0x400000, CELL_TEST, 0, 2, NOTGT },
	/* the shifts, as the bitfield moves the assembler writes them */
	{ "lsl x0,x1,#4 (ubfm #60,#59)", 0xd37cec20u, 0x400000, CELL_SHL, BIT(0), 3, NOTGT },
	{ "lsr x0,x0,#3 (ubfm #3,#63)", 0xd343fc00u, 0x400000, CELL_SHR, BIT(0), 2, NOTGT },
	{ "asr w0,w0,#31 (sbfm #31,#31)", 0x131f7c00u, 0x400000, CELL_SAR, BIT(0), 2, NOTGT },
	/* madd with Ra=xzr: sf=1 00 11011 000 Rm=2 0 11111 Rn=1 Rd=0 */
	{ "mul x0,x1,x2", 0x9b027c20u, 0x400000, CELL_MUL, BIT(0), 3, NOTGT },
	/* loads and stores */
	{ "ldr x0,[x1,#8]", 0xf9400420u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	{ "ldrb w0,[x1,#1]", 0x39400420u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	{ "str x0,[sp,#8]", 0xf90007e0u, 0x400000, CELL_MOV, 0, 2, NOTGT },
	{ "str xzr,[x0]", 0xf900001fu, 0x400000, CELL_MOV, 0, 2, NOTGT },
	{ "ldr x0,[x1],#8 (post-index)", 0xf8408420u, 0x400000, CELL_MOV, BIT(0) | BIT(1), 3, NOTGT },
	{ "ldr x0,[x1,#8]! (pre-index)", 0xf8408c20u, 0x400000, CELL_MOV, BIT(0) | BIT(1), 2, NOTGT },
	{ "ldr w0,[x1,x2,lsl #2]", 0xb8627820u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	{ "ldr x0,[pc,#0x20] (literal)", 0x58000100u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	{ "ldxr x0,[x1]", 0xc85f7c20u, 0x400000, CELL_MOV, BIT(0), 2, NOTGT },
	/* stxr w2,x0,[x1]: the status goes to w2 */
	{ "stxr w2,x0,[x1]", 0xc8027c20u, 0x400000, CELL_OTHER, BIT(2), 3, NOTGT },
	/* the pairs: PUSH/POP are not invented, the frame forms are OTHER */
	{ "stp x29,x30,[sp,#-16]!", 0xa9bf7bfdu, 0x400000, CELL_OTHER, BIT(31), 3, NOTGT },
	{ "ldp x29,x30,[sp],#16", 0xa8c17bfdu, 0x400000, CELL_OTHER,
	  BIT(29) | BIT(30) | BIT(31), 3, NOTGT },
	{ "ldp x0,x1,[x2,#16]", 0xa9410440u, 0x400000, CELL_OTHER, BIT(0) | BIT(1), 3, NOTGT },
	/* LSE: ldadd x1,x2,[x3] returns the old value in x2 */
	{ "ldadd x1,x2,[x3]", 0xf8210062u, 0x400000, CELL_OTHER, BIT(2), 3, NOTGT },
	/* vector and floating point: OTHER, and the general register they write */
	{ "fmov x0,d0", 0x9e660000u, 0x400000, CELL_OTHER, BIT(0), 1, NOTGT },
	{ "fcvtzs x0,d0", 0x9e780000u, 0x400000, CELL_OTHER, BIT(0), 1, NOTGT },
	{ "umov w0,v0.b[0]", 0x0e013c00u, 0x400000, CELL_OTHER, BIT(0), 1, NOTGT },
	{ "fmov d0,x0 (writes no general register)", 0x9e670000u, 0x400000, CELL_OTHER, 0, 0, NOTGT },
	{ "cntb x0 (sve)", 0x0420e3e0u, 0x400000, CELL_OTHER, BIT(0), 1, NOTGT },
	/* hints, barriers, system */
	{ "nop", 0xd503201fu, 0x400000, CELL_NOP, 0, 0, NOTGT },
	{ "yield (a hint is a nop)", 0xd503203fu, 0x400000, CELL_NOP, 0, 0, NOTGT },
	{ "paciasp (rewrites lr)", 0xd503233fu, 0x400000, CELL_OTHER, BIT(30), 0, NOTGT },
	{ "dmb ish", 0xd5033bbfu, 0x400000, CELL_OTHER, 0, 0, NOTGT },
	{ "dc zva,x0 (sys #3,c7,c4,#1)", 0xd50b7420u, 0x400000, CELL_OTHER, 0, 0, NOTGT },
	{ "mrs x0,tpidr_el0", 0xd53bd040u, 0x400000, CELL_PRIV, BIT(0), 2, NOTGT },
	{ "msr tpidr_el0,x0", 0xd51bd040u, 0x400000, CELL_PRIV, 0, 2, NOTGT },
	/* udf #0x1234: the top sixteen bits are zero, and it is defined to fault */
	{ "udf #0x1234", 0x00001234u, 0x400000, CELL_UD, 0, 0, NOTGT },
	/* bit 31 clear in the reserved group with a non-zero upper half */
	{ "unallocated (reserved group, upper bits set)", 0x20000000u, 0x400000, CELL_UD, 0, 0, NOTGT },
};

static void table(void)
{
	size_t i;

	printf("class, written registers, operand count, target:\n");
	for (i = 0; i < sizeof C / sizeof *C; i++) {
		struct cell_insn k;
		char what[128];
		int good;

		good = dec(C[i].w, C[i].va, &k) == 4u && k.len == 4u &&
		       k.op == C[i].op && k.wmask == C[i].wmask &&
		       k.n_op == C[i].n_op && k.target_va == C[i].target &&
		       k.at_va == C[i].va;
		snprintf(what, sizeof what, "%08x %s", C[i].w, C[i].what);
		ok(what, good);
		if (!good)
			printf("       got op=%u wmask=%llx n_op=%u target=%llx; want op=%u wmask=%llx n_op=%u target=%llx\n",
			       k.op, (unsigned long long)k.wmask, k.n_op,
			       (unsigned long long)k.target_va, C[i].op,
			       (unsigned long long)C[i].wmask, C[i].n_op,
			       (unsigned long long)C[i].target);
	}
}

/* ---- operand values ------------------------------------------------------ */

static void movs(void)
{
	struct cell_insn k;

	printf("movz, movn, movk operands:\n");
	dec(0xd28018c8u, 0x400000, &k);
	ok("movz x8,#198: dest x8, 8 bytes, written",
	   k.o[0].kind == CELL_O_REG && k.o[0].reg == 8 && k.o[0].size == 8 &&
	   (k.o[0].flags & CELL_OF_WRITE));
	ok("movz x8,#198: the immediate is 198", k.o[1].kind == CELL_O_IMM && k.o[1].imm == 198);
	dec(0x52800020u, 0x400000, &k);
	ok("mov w0,#1: a w write is size 4", k.o[0].size == 4 && k.o[1].imm == 1);
	dec(0xd2a00020u, 0x400000, &k);      /* movz x0,#1,lsl #16 */
	ok("movz x0,#1,lsl #16 is 0x10000", k.op == CELL_MOV && k.o[1].imm == 0x10000);
	dec(0x92800000u, 0x400000, &k);
	ok("movn x0,#0 is all ones", k.o[1].imm == ~0ull);
	dec(0x12800000u, 0x400000, &k);
	ok("movn w0,#0 is 0xffffffff, not 64 ones", k.o[1].imm == 0xffffffffull && k.o[0].size == 4);
	dec(0x92a00020u, 0x400000, &k);      /* movn x0,#1,lsl #16 */
	ok("movn x0,#1,lsl #16 is ~0x10000", k.o[1].imm == ~0x10000ull);
	dec(0xf2a24680u, 0x400000, &k);
	ok("movk: the bits to OR in are 0x12340000", k.o[1].imm == 0x12340000ull);
	ok("movk: the bits it replaces are 0xffff0000", k.o[2].imm == 0xffff0000ull);
	ok("movk: x0 is read and written", k.o[0].flags == (CELL_OF_READ | CELL_OF_WRITE));
	dec(0xd280001fu, 0x400000, &k);      /* movz xzr,#0: writes the zero register */
	ok("movz xzr writes nothing: a nop", k.op == CELL_NOP && k.wmask == 0);
	dec(0x320003e0u, 0x400000, &k);      /* orr w0,wzr,#1 (mov w0,#1) */
	ok("orr w0,wzr,#1 is a move of the constant 1",
	   k.op == CELL_MOV && k.o[1].kind == CELL_O_IMM && k.o[1].imm == 1 && k.o[0].size == 4);
	dec(0xb200c3e0u, 0x400000, &k);      /* orr x0,xzr,#0x0101010101010101 */
	ok("orr x0,xzr,#imm is the decoded bitmask",
	   k.op == CELL_MOV && k.o[1].imm == 0x0101010101010101ull);
}

static void addresses(void)
{
	struct cell_insn k;
	uint64_t v;

	printf("adrp, adr, literal loads:\n");
	dec(0xd0000080u, 0x400abc, &k);
	ok("adrp resolves to the absolute page address (low 12 bits of pc dropped)",
	   k.o[1].kind == CELL_O_IMM && k.o[1].imm == 0x412000);
	v = k.o[1].imm;
	dec(0x911ea000u, 0x400ac0, &k);
	ok("adrp + add x0,x0,#0x7a8 folds to 0x4127a8", k.op == CELL_ADD && v + k.o[1].imm == 0x4127a8);
	dec(0x10000081u, 0x400000, &k);
	ok("adr x1,.+0x10 resolves to va+0x10", k.o[1].imm == 0x400010);
	dec(0xf0ffffe0u, 0x401234, &k);      /* adrp x0,.-1 page: immlo=3 immhi=all ones */
	ok("adrp backwards from 0x401234 by one page is 0x400000", k.o[1].imm == 0x400000);
	dec(0x58000100u, 0x400000, &k);
	ok("ldr literal: a MEM operand with no base, relative to the instruction",
	   k.o[1].kind == CELL_O_MEM && (k.o[1].flags & CELL_OF_RIPREL) &&
	   k.o[1].reg == CELL_REG_NONE && k.o[1].size == 8);
	ok("ldr literal: address = at_va + disp = 0x400020", k.at_va + (uint64_t)k.o[1].disp == 0x400020);
	dec(0x18ffffe1u, 0x400100, &k);      /* ldr w1,.-4 */
	ok("ldr w literal, backwards: address = at_va - 4",
	   k.at_va + (uint64_t)k.o[1].disp == 0x4000fc && k.o[1].size == 4 && k.o[0].size == 4);
	dec(0x98000040u, 0x400000, &k);      /* ldrsw x0,.+8 */
	ok("ldrsw literal: reads 4 bytes into x0", k.o[1].size == 4 && k.o[0].size == 8 && k.o[0].reg == 0);
}

static void memory(void)
{
	struct cell_insn k;

	printf("memory operands:\n");
	dec(0xf9400420u, 0x400000, &k);
	ok("ldr x0,[x1,#8]: base x1, disp 8, 8 bytes",
	   k.o[1].kind == CELL_O_MEM && k.o[1].reg == 1 && k.o[1].disp == 8 && k.o[1].size == 8);
	dec(0xf94007e0u, 0x400000, &k);      /* ldr x0,[sp,#8] */
	ok("ldr x0,[sp,#8]: the base is register 31 meaning sp", k.o[1].reg == 31 && k.o[1].disp == 8);
	dec(0xf9400c20u, 0x400000, &k);      /* ldr x0,[x1,#24]: imm12=3 scaled by 8 */
	ok("an unsigned offset is scaled by the access size", k.o[1].disp == 24);
	dec(0xf8408c20u, 0x400000, &k);
	ok("pre-index: the address already includes the increment", k.o[1].disp == 8);
	dec(0xf8408420u, 0x400000, &k);
	ok("post-index: the access is [x1], and the increment is carried", k.o[1].disp == 0 &&
	   k.n_op == 3 && k.o[2].kind == CELL_O_IMM && k.o[2].imm == 8);
	dec(0xf85f8020u, 0x400000, &k);      /* ldur x0,[x1,#-8] */
	ok("ldur takes a signed unscaled offset", k.o[1].disp == -8);
	dec(0xb8627820u, 0x400000, &k);
	ok("register offset: base x1, index x2, scale 4",
	   k.o[1].reg == 1 && k.o[1].index == 2 && k.o[1].scale == 4 && k.o[1].size == 4);
	dec(0xf90007e0u, 0x400000, &k);      /* str x0,[sp,#8] */
	ok("a store writes memory: o[0] is the MEM operand, written, o[1] the value",
	   k.o[0].kind == CELL_O_MEM && (k.o[0].flags & CELL_OF_WRITE) &&
	   k.o[1].kind == CELL_O_REG && k.o[1].reg == 0 && k.wmask == 0);
	dec(0xf900001fu, 0x400000, &k);
	ok("a store of xzr stores the constant 0", k.o[1].kind == CELL_O_IMM && k.o[1].imm == 0);
	dec(0x39400420u, 0x400000, &k);
	ok("ldrb w0,[x1,#1]: a byte read into a 4-byte register",
	   k.o[0].size == 4 && k.o[1].size == 1 && k.o[1].disp == 1);
	dec(0xb9800020u, 0x400000, &k);      /* ldrsw x0,[x1] */
	ok("ldrsw x0,[x1]: 4 bytes into an 8-byte register", k.op == CELL_MOV && k.o[0].size == 8 && k.o[1].size == 4);
	dec(0xf940001fu, 0x400000, &k);      /* ldr xzr,[x0]: loads and discards */
	ok("a load into xzr writes no register and is no MOV", k.op == CELL_OTHER && k.wmask == 0);
	dec(0xa9bf7bfdu, 0x400000, &k);
	ok("stp pre-index: the frame push is the OTHER form with sp written",
	   k.op == CELL_OTHER && k.wmask == BIT(31) &&
	   k.o[2].kind == CELL_O_MEM && k.o[2].reg == 31 && k.o[2].disp == -16 && k.o[2].size == 16);
	ok("stp: the stored registers are x29 and x30",
	   k.o[0].reg == 29 && k.o[1].reg == 30 && (k.o[0].flags & CELL_OF_READ));
	dec(0xa8c17bfdu, 0x400000, &k);
	ok("ldp post-index: x29, x30 and the base sp are all written", k.wmask == (BIT(29) | BIT(30) | BIT(31)));
	ok("ldp: the loaded registers are x29 and x30",
	   k.o[0].reg == 29 && k.o[1].reg == 30 && (k.o[0].flags & CELL_OF_WRITE));
	dec(0xa940045fu, 0x400000, &k);      /* ldp xzr,x1,[x2] */
	ok("ldp xzr,x1,[x2]: only x1 is written; the discarded half names no register",
	   k.wmask == BIT(1) && k.o[0].kind == CELL_O_REG && k.o[0].reg == CELL_REG_NONE);
	dec(0xa9400fe0u, 0x400000, &k);      /* ldp x0,x3,[sp] */
	ok("ldp x0,x3,[sp] writes x0 and x3 and not sp", k.wmask == (BIT(0) | BIT(3)));
}

static void branches(void)
{
	struct cell_insn k;

	printf("branch operands:\n");
	dec(0x54000040u, 0x400000, &k);
	ok("b.eq: condition code 0", k.cond == 0);
	ok("b.eq: o[0] is the relative operand", k.o[0].kind == CELL_O_REL);
	dec(0x5400004bu, 0x400000, &k);      /* b.lt: cond=11 */
	ok("b.lt: condition code 11", k.op == CELL_JCC && k.cond == 11);
	dec(0xb4000080u, 0x400000, &k);
	ok("cbz carries the tested register in o[1] and cond 0",
	   k.o[1].kind == CELL_O_REG && k.o[1].reg == 0 && k.o[1].size == 8 && k.cond == 0);
	dec(0x35ffffe1u, 0x400000, &k);
	ok("cbnz w1: size 4 and cond 1", k.o[1].reg == 1 && k.o[1].size == 4 && k.cond == 1);
	dec(0xb6180103u, 0x400000, &k);
	ok("tbz carries the register and the bit number 35",
	   k.o[1].reg == 3 && k.o[2].kind == CELL_O_IMM && k.o[2].imm == 35);
	dec(0xd63f0060u, 0x400000, &k);
	ok("blr x3 is indirect and has no target", (k.flags & CELL_F_INDIRECT) && k.target_va == NOTGT &&
	   k.target == NOTGT && k.o[0].kind == CELL_O_REG && k.o[0].reg == 3);
	dec(0xd65f03c0u, 0x400000, &k);
	ok("ret reads x30", k.o[0].reg == 30 && (k.flags & CELL_F_INDIRECT));
	dec(0xd65f0020u, 0x400000, &k);      /* ret x1 */
	ok("ret x1 reads x1", k.op == CELL_RET && k.o[0].reg == 1);
	dec(0xd61f0200u, 0x400000, &k);
	ok("br x16 is an indirect jump through x16", k.op == CELL_JMP && (k.flags & CELL_F_INDIRECT) && k.o[0].reg == 16);
	dec(0x94000010u, 0xfffffffffffffff0ull, &k);
	ok("bl past the top of the address space wraps to 0x30", k.target_va == 0x30);
	dec(0xd4000001u, 0x400000, &k);
	ok("svc #0 carries its immediate", k.n_op == 1 && k.o[0].kind == CELL_O_IMM && k.o[0].imm == 0);
	dec(0xd4001c01u, 0x400000, &k);      /* svc #0xe0 */
	ok("svc #0xe0 carries 0xe0", k.op == CELL_SYSCALL && k.o[0].imm == 0xe0);
	ok("svc writes no register", k.wmask == 0);
}

static void alu(void)
{
	struct cell_insn k;

	printf("ALU operand forms:\n");
	dec(0x911ea000u, 0x400000, &k);
	ok("add x0,x0,#0x7a8: two operands, the destination also read",
	   k.n_op == 2 && k.o[0].reg == 0 && k.o[0].flags == (CELL_OF_READ | CELL_OF_WRITE) &&
	   k.o[1].kind == CELL_O_IMM && k.o[1].imm == 0x7a8);
	dec(0x91000420u, 0x400000, &k);      /* add x0,x1,#1 */
	ok("add x0,x1,#1: the three-operand form, since x0 is not a source",
	   k.n_op == 3 && k.o[0].reg == 0 && k.o[1].reg == 1 && k.o[2].imm == 1);
	dec(0x91400400u, 0x400000, &k);      /* add x0,x0,#1,lsl #12 */
	ok("add imm with lsl #12 is shifted in the immediate", k.o[1].imm == 0x1000);
	dec(0x8b021020u, 0x400000, &k);      /* add x0,x1,x2,lsl #4 */
	ok("add with a shifted register is no ADD: its operands could not say so",
	   k.op == CELL_OTHER && k.wmask == BIT(0));
	dec(0x8b22c020u, 0x400000, &k);      /* add x0,x1,w2,sxtw */
	ok("add with an extended register is OTHER", k.op == CELL_OTHER && k.wmask == BIT(0));
	dec(0x8b206020u, 0x400000, &k);      /* add x0,x1,x0,uxtx */
	ok("add xd,xn,xm,uxtx (no shift) is the plain 64-bit add", k.op == CELL_ADD && k.n_op == 3);
	dec(0xcb0003e0u, 0x400000, &k);      /* neg x0,x0: sub x0,xzr,x0 */
	ok("neg x0,x0 is NEG on one operand", k.op == CELL_NEG && k.n_op == 1 && k.o[0].reg == 0);
	dec(0xaa2003e0u, 0x400000, &k);      /* mvn x0,x0 */
	ok("mvn x0,x0 is NOT", k.op == CELL_NOT && k.n_op == 1);
	dec(0x8a2100a0u, 0x400000, &k);      /* bic x0,x5,x1 */
	ok("bic has no class: OTHER with x0 written", k.op == CELL_OTHER && k.wmask == BIT(0));
	dec(0x9100001fu, 0x400000, &k);      /* add sp,x0,#0 */
	ok("add sp,x0,#0 is a move into sp", k.op == CELL_MOV && k.wmask == BIT(31));
	dec(0x9100041fu, 0x400000, &k);      /* add sp,x0,#1 */
	ok("add sp,x0,#1 writes sp (register 31 is sp in this slot)", k.op == CELL_ADD && k.wmask == BIT(31));
	dec(0x8b00001fu, 0x400000, &k);      /* add xzr,x0,x0 */
	ok("add xzr,... writes the zero register: nothing", k.op == CELL_NOP && k.wmask == 0);
	dec(0xab00001fu, 0x400000, &k);      /* adds xzr,x0,x0: cmn */
	ok("cmn writes nothing and is no CMP", k.op == CELL_OTHER && k.wmask == 0);
	dec(0xeb01001fu, 0x400000, &k);      /* cmp x0,x1 */
	ok("cmp x0,x1 compares the two registers",
	   k.op == CELL_CMP && k.n_op == 2 && k.o[0].reg == 0 && k.o[1].reg == 1 && k.wmask == 0);
	dec(0xeb1f001fu, 0x400000, &k);      /* cmp x0,xzr */
	ok("cmp x0,xzr compares with the constant 0", k.o[1].kind == CELL_O_IMM && k.o[1].imm == 0);
	dec(0xf2400400u, 0x400000, &k);      /* ands x0,x0,#3 */
	ok("ands x0,x0,#3 writes x0: AND with the mask 3", k.op == CELL_AND && k.o[1].imm == 3 && k.wmask == BIT(0));
	dec(0x92400800u, 0x400000, &k);      /* and x0,x0,#7 */
	ok("and x0,x0,#7", k.op == CELL_AND && k.o[1].imm == 7);
	dec(0x92401c00u, 0x400000, &k);      /* and x0,x0,#0xff */
	ok("and x0,x0,#0xff", k.op == CELL_AND && k.o[1].imm == 0xff);
	dec(0xd2400000u, 0x400000, &k);      /* eor x0,x0,#1 */
	ok("eor x0,x0,#1", k.op == CELL_XOR && k.o[1].imm == 1);
	dec(0x9ac12020u, 0x400000, &k);      /* lsl x0,x1,x1 (lslv) */
	ok("lslv is SHL with a register amount", k.op == CELL_SHL && k.o[2].kind == CELL_O_REG);
	dec(0x9ac20c20u, 0x400000, &k);      /* sdiv x0,x1,x2 */
	ok("sdiv", k.op == CELL_IDIV && k.wmask == BIT(0));
	dec(0x9ac20820u, 0x400000, &k);      /* udiv x0,x1,x2 */
	ok("udiv", k.op == CELL_DIV);
	dec(0x9bc27c20u, 0x400000, &k);      /* umulh x0,x1,x2 */
	ok("umulh is MUL", k.op == CELL_MUL && k.wmask == BIT(0));
	dec(0x9b0a0c20u, 0x400000, &k);      /* madd x0,x1,x10,x3: a real multiply-add */
	ok("madd with a non-zero addend is OTHER", k.op == CELL_OTHER && k.wmask == BIT(0));
	dec(0xd3401c20u, 0x400000, &k);      /* uxtb-like: ubfx x0,x1,#0,#8 */
	ok("ubfx is OTHER", k.op == CELL_OTHER && k.wmask == BIT(0));
	dec(0x53001c20u, 0x400000, &k);      /* uxtb w0,w1 */
	ok("uxtb w0,w1 is MOVZX from 1 byte", k.op == CELL_MOVZX && k.o[1].size == 1 && k.o[0].size == 4);
	dec(0x93407c20u, 0x400000, &k);      /* sxtw x0,w1 */
	ok("sxtw x0,w1 is MOVSX from 4 bytes", k.op == CELL_MOVSX && k.o[1].size == 4 && k.o[0].size == 8);
	dec(0x9a820020u, 0x400000, &k);      /* csel x0,x1,x2,eq */
	ok("csel is OTHER with x0 written", k.op == CELL_OTHER && k.wmask == BIT(0) && k.cond == 0);
	dec(0x9a9f17e0u, 0x400000, &k);      /* cset x0,eq: csinc x0,xzr,xzr,ne */
	ok("cset x0,eq writes x0", k.wmask == BIT(0));
	dec(0xba400000u, 0x400000, &k);      /* ccmn x0,x0,#0,eq */
	ok("ccmn writes nothing", k.op == CELL_OTHER && k.wmask == 0);
	dec(0xda8003e0u, 0x400000, &k);      /* csinv x0,xzr,x0,eq */
	ok("csinv writes x0", k.wmask == BIT(0));
	dec(0xdac01020u, 0x400000, &k);      /* clz x0,x1 */
	ok("clz writes x0", k.op == CELL_OTHER && k.wmask == BIT(0));
	dec(0xdac00c20u, 0x400000, &k);      /* rev x0,x1 */
	ok("rev writes x0", k.wmask == BIT(0));
	dec(0x93c18c20u, 0x400000, &k);      /* extr x0,x1,x1,#35 = ror x0,x1,#35 */
	ok("extr with equal sources is ror", k.op == CELL_ROR && k.o[2].imm == 35);
	dec(0x9a000020u, 0x400000, &k);      /* adc x0,x1,x0 */
	ok("adc is ADC", k.op == CELL_ADC && k.wmask == BIT(0));
	dec(0xda000020u, 0x400000, &k);
	ok("sbc is SBB", k.op == CELL_SBB);
}

static void system(void)
{
	struct cell_insn k;

	printf("system, hints, and unallocated words:\n");
	dec(0xd53bd040u, 0x400000, &k);
	ok("mrs x0,tpidr_el0: o[1] is the 15-bit register id 0x5e82 (o0 op1 CRn CRm op2)",
	   k.o[0].reg == 0 && k.o[1].imm == 0x5e82);
	dec(0xd53b4200u, 0x400000, &k);      /* mrs x0,nzcv */
	ok("mrs x0,nzcv writes x0", k.wmask == BIT(0));
	dec(0xd53bd05fu, 0x400000, &k);      /* mrs xzr,tpidr_el0 */
	ok("mrs xzr writes no register and names none", k.wmask == 0 && k.o[0].reg == CELL_REG_NONE);
	dec(0xd503201fu, 0x400000, &k);
	ok("nop has no operands", k.op == CELL_NOP && k.n_op == 0);
	dec(0xd50320ffu, 0x400000, &k);      /* hint #7 = xpaclri */
	ok("xpaclri strips lr: OTHER writing x30", k.op == CELL_OTHER && k.wmask == BIT(30));
	dec(0xd503211fu, 0x400000, &k);      /* hint #8 = pacia1716 */
	ok("pacia1716 rewrites x17", k.wmask == BIT(17));
	dec(0xd5033fdfu, 0x400000, &k);
	ok("isb is OTHER and writes nothing", k.op == CELL_OTHER && k.wmask == 0);
	dec(0xd5033f5fu, 0x400000, &k);      /* clrex */
	ok("clrex is OTHER", k.op == CELL_OTHER);
	dec(0xd50b7a20u, 0x400000, &k);      /* dc cvac,x0 -- sys #3,c7,c10,#1 */
	ok("dc is OTHER and writes nothing", k.op == CELL_OTHER && k.wmask == 0);
	dec(0x00000000u, 0x400000, &k);
	ok("udf #0 is UD", k.op == CELL_UD && k.len == 4);
	dec(0x00010000u, 0x400000, &k);
	ok("zero in bits 31..25 with bit 16 set is not udf: still UD", k.op == CELL_UD && k.wmask == 0);
	dec(0x02000000u, 0x400000, &k);      /* bits 28..25 = 0001: an unallocated top-level group */
	ok("top-level group 0001 is UD, nothing written", k.op == CELL_UD && k.wmask == 0);
	dec(0x06000000u, 0x400000, &k);      /* bits 28..25 = 0011 */
	ok("top-level group 0011 is UD, nothing written", k.op == CELL_UD && k.wmask == 0);
	dec(0x1e202800u, 0x400000, &k);      /* fadd s0,s0,s0 */
	ok("fadd s0,s0,s0 is OTHER and writes no general register", k.op == CELL_OTHER && k.wmask == 0);
	dec(0x1e200000u, 0x400000, &k);      /* fcvtns w0,s0 */
	ok("fcvtns w0,s0 writes w0", k.wmask == BIT(0) && k.o[0].size == 4);
	dec(0x0e013c00u, 0x400000, &k);
	ok("umov w0,v0.b[0]: x0 written as a 4-byte register", k.o[0].reg == 0 && k.o[0].size == 4);
	dec(0x4e083c00u, 0x400000, &k);      /* umov x0,v0.d[0] */
	ok("umov x0,v0.d[0]: an 8-byte register", k.wmask == BIT(0) && k.o[0].size == 8);
	dec(0x0e033c00u, 0x400000, &k);      /* umov w0,v0.b[1]: imm5=00011, the low set bit says byte */
	ok("umov with imm5 low bit set reads a byte", k.wmask == BIT(0));
	dec(0x4e043c00u, 0x400000, &k);      /* imm5=00100 is a word element, which needs Q=0 */
	ok("umov with Q=1 and a word element is unallocated", k.op == CELL_UD && k.wmask == 0);
	dec(0x9e790000u, 0x400000, &k);      /* fcvtzu x0,d0 */
	ok("fcvtzu x0,d0 writes x0", k.wmask == BIT(0));
	dec(0x9e620000u, 0x400000, &k);      /* scvtf d0,x0: reads x0, writes d0 */
	ok("scvtf d0,x0 writes no general register", k.wmask == 0);
	dec(0x9e780400u, 0x400000, &k);      /* the conversion pattern with 15:10 non-zero */
	ok("a word that only resembles the conversion is not read as one", k.wmask == 0);
	dec(0x1e7e0000u, 0x400000, &k);      /* fjcvtzs w0,d0 */
	ok("fjcvtzs w0,d0 writes w0", k.wmask == BIT(0));
}

static void sve(void)
{
	struct cell_insn k;

	printf("SVE general-register writers:\n");
	dec(0x0420e3e0u, 0x400000, &k);
	ok("cntb x0", k.wmask == BIT(0) && k.o[0].reg == 0);
	dec(0x04bf5000u, 0x400000, &k);
	ok("rdvl x0,#0", k.wmask == BIT(0));
	dec(0x04205020u, 0x400000, &k);      /* addvl x0,x0,#1: Rn=0, imm6=1 */
	ok("addvl x0,x0,#1", k.wmask == BIT(0));
	dec(0x0420501fu, 0x400000, &k);      /* addvl sp,x0,#0 */
	ok("addvl with rd 31 writes sp", k.wmask == BIT(31));
	dec(0x0420e3ffu, 0x400000, &k);      /* cntb xzr */
	ok("cntb xzr writes nothing", k.wmask == 0);
	dec(0x0520a000u, 0x400000, &k);      /* lasta w0,p0,z0.b */
	ok("lasta w0 writes x0", k.wmask == BIT(0));
	dec(0x04200000u, 0x400000, &k);      /* some vector SVE word: add z0.b,z0.b,z0.b */
	ok("a vector SVE word writes no general register", k.wmask == 0 && k.op == CELL_OTHER);
}

static void lengths(void)
{
	struct cell_insn k;
	static const uint8_t b[8] = { 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5 };

	printf("lengths:\n");
	ok("fewer than four bytes is 0", cell_decode_arm64(b, 3, 0, &k) == 0);
	ok("no bytes is 0", cell_decode_arm64(b, 0, 0, &k) == 0);
	ok("a null pointer is 0", cell_decode_arm64(NULL, 4, 0, &k) == 0);
	ok("four bytes is 4", cell_decode_arm64(b, 4, 0, &k) == 4);
	ok("more than four bytes still decodes one instruction of 4", cell_decode_arm64(b, 8, 0, &k) == 4 && k.len == 4);
	ok("at and at_va are the address given", (cell_decode_arm64(b, 4, 0x1234, &k), k.at == 0x1234 && k.at_va == 0x1234));
}

int main(void)
{
	printf("decode arm64:\n");
	table();
	movs();
	addresses();
	memory();
	branches();
	alu();
	system();
	sve();
	lengths();
	printf("decode arm64: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
