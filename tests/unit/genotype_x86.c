/*
 * genotype_x86 - the x86 decoder, against what the instruction set says.
 *
 * The encodings below are written from the manuals and from the behaviour the
 * anti-disassembly literature describes, and say what each of them IS. They need
 * nothing but this tree.
 *
 * The other check - random encodings compared with a reference decoder - lives
 * in tools/genotype/x86_diff.c, because it needs that reference and the reference
 * is not part of this tree. See `make genotype-x86-diff`.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../libgenome/genotype/x86/x86.h"

static int failures;

static void ok(const char *what, int cond)
{
	printf("  %s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		failures++;
}

/* ---- curated encodings ---------------------------------------------------- */

struct curated {
	int mode;
	const char *what;
	uint8_t b[16];
	size_t n;               /* bytes given                                     */
	enum gt_status st;
	unsigned len;           /* when GT_OK                                      */
	unsigned id;            /* when GT_OK; 0 = not checked                     */
};

static const struct curated C[] = {
	{ 64, "mov rax,[rip+0x2fdd]", { 0x48, 0x8b, 0x05, 0xdd, 0x2f, 0, 0 }, 7, GT_OK, 7, GT_X86_I_MOV },
	{ 64, "call rel32", { 0xe8, 1, 0, 0, 0 }, 5, GT_OK, 5, GT_X86_I_CALLNR },
	{ 64, "syscall", { 0x0f, 0x05 }, 2, GT_OK, 2, GT_X86_I_SYSCALL },
	{ 64, "ud2", { 0x0f, 0x0b }, 2, GT_OK, 2, GT_X86_I_UD2 },
	{ 32, "int 0x80", { 0xcd, 0x80 }, 2, GT_OK, 2, GT_X86_I_INT },
	{ 32, "push imm32", { 0x68, 1, 2, 3, 4 }, 5, GT_OK, 5, GT_X86_I_PUSH },
	{ 64, "xchg r8, rax (REX.B turns the nop into an exchange)", { 0x49, 0x90 }, 2, GT_OK, 2, GT_X86_I_XCHG },
	{ 64, "pause (F3 90)", { 0xf3, 0x90 }, 2, GT_OK, 2, GT_X86_I_PAUSE },
	{ 64, "66 90 is a two-byte nop", { 0x66, 0x90 }, 2, GT_OK, 2, GT_X86_I_NOP },
	/*
	 * THE ENCODINGS FROM THE ANTI-DISASSEMBLY CHAPTER. The first is the NOP with a
	 * REP prefix and a disp32 that Sality uses: eight bytes, not the seven the
	 * printed bytes show (the book is one byte short). The others are the moves to
	 * and from CR0 and DR0 with a mod field that is not 11b - which the CPU reads as
	 * if it were, and which some disassemblers give a displacement.
	 */
	{ 32, "rep nop [eax+disp32] (Sality)", { 0xf3, 0x0f, 0x1f, 0x90, 0x90, 0x90, 0x90, 0x90 }, 8, GT_OK, 8, 0 },
	{ 32, "mov eax,cr0 written 0f 20 00", { 0x0f, 0x20, 0x00 }, 3, GT_OK, 3, GT_X86_I_MOV_CR },
	{ 32, "mov eax,cr0 written 0f 20 40", { 0x0f, 0x20, 0x40 }, 3, GT_OK, 3, GT_X86_I_MOV_CR },
	{ 32, "mov eax,cr0 written 0f 20 80", { 0x0f, 0x20, 0x80 }, 3, GT_OK, 3, GT_X86_I_MOV_CR },
	{ 32, "mov eax,dr0 written 0f 21 00", { 0x0f, 0x21, 0x00 }, 3, GT_OK, 3, GT_X86_I_MOV_DR },
	{ 32, "mov eax,dr0 written 0f 21 40", { 0x0f, 0x21, 0x40 }, 3, GT_OK, 3, GT_X86_I_MOV_DR },
	{ 32, "mov eax,dr0 written 0f 21 80", { 0x0f, 0x21, 0x80 }, 3, GT_OK, 3, GT_X86_I_MOV_DR },
	{ 64, "vzeroupper", { 0xc5, 0xf8, 0x77 }, 3, GT_OK, 3, GT_X86_I_VZEROUPPER },
	{ 64, "vaddps zmm0,zmm0,zmm1 (EVEX)", { 0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc1 }, 6, GT_OK, 6, GT_X86_I_VADDPS },
	{ 64, "lock add [rax],eax", { 0xf0, 0x01, 0x00 }, 3, GT_OK, 3, GT_X86_I_ADD },
	{ 64, "lock mov is not an instruction", { 0xf0, 0x89, 0x00 }, 3, GT_INVALID, 0, 0 },
	{ 64, "lock on a register form is not an instruction", { 0xf0, 0x01, 0xc0 }, 3, GT_INVALID, 0, 0 },
	{ 64, "a REX that is not last is not a REX", { 0x48, 0x66, 0x90 }, 3, GT_OK, 3, 0 },
	{ 64, "cut off in the ModRM", { 0x48, 0x8b }, 2, GT_TRUNCATED, 0, 0 },
	{ 64, "cut off in the displacement", { 0x8b, 0x80, 1, 2 }, 4, GT_TRUNCATED, 0, 0 },
	{ 64, "cut off after a VEX prefix", { 0xc5, 0xf8 }, 2, GT_TRUNCATED, 0, 0 },
	{ 64, "nothing at all", { 0 }, 0, GT_TRUNCATED, 0, 0 },
	/* Sixteen bytes of prefix and an opcode: past the limit of 15. */
	{ 64, "more than 15 bytes", { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90 }, 16, GT_INVALID, 0, 0 },
	{ 64, "0x0f 0x0f (3DNow!) is reported, not guessed at", { 0x0f, 0x0f, 0xc0, 0x9e }, 4, GT_INVALID, 0, 0 },
};

static void curated(void)
{
	size_t i;

	printf("curated encodings:\n");
	for (i = 0; i < sizeof C / sizeof C[0]; i++) {
		const struct curated *c = &C[i];
		struct gt_x86_insn x;
		enum gt_status st = gt_x86_decode(&x, c->b, c->n, c->mode);
		int good = st == c->st;

		if (good && st == GT_OK)
			good = x.len == c->len && (!c->id || x.id == c->id);
		ok(c->what, good);
	}
}

/* A memory operand with a RIP-relative base: the one operand worth checking
 * by value, because it is what the code sweep resolves to an address. */
static void rip_relative(void)
{
	static const uint8_t b[] = { 0x48, 0x8b, 0x05, 0xdd, 0x2f, 0, 0 };
	struct gt_x86_insn x;
	struct gt_x86_op o;

	printf("operand values:\n");
	ok("decodes", gt_x86_decode(&x, b, sizeof b, 64) == GT_OK);
	ok("two operands", gt_x86_nops(&x) == 2);
	gt_x86_operand(&x, 1, &o);
	ok("the second is memory", o.type == GT_X86_OP_MEM);
	ok("addressed from RIP", (o.mf & GT_X86_M_RIPREL) != 0);
	ok("with the displacement the bytes hold", (o.mf & GT_X86_M_DISP) && o.v == 0x2fdd);
	gt_x86_operand(&x, 0, &o);
	ok("the first is rax", o.type == GT_X86_OP_REG && o.reg == 0 && o.rsize == 8);
}

int main(void)
{
	printf("genotype x86:\n");
	curated();
	rip_relative();
	printf("genotype x86: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
