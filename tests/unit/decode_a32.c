/*
 * decode_a32 - the ARM decoders (A32 and Thumb), on encodings with a known meaning.
 *
 * Every A32 encoding below is a real instruction from the Mirai ARM binaries
 * in the corpus (file and address in the comment), taken out of .text and
 * written down with what it IS. Where the corpus has no instance - movw/movt
 * (no ARMv7-only builds), blx immediate, udf, and ALL of Thumb (the corpus
 * has no Thumb code: scanning every halfword of every .text for `svc` found
 * only data that reads as it) - the encoding is written from the ARM ARM and
 * says so. Each was also read by an independent disassembler when it was
 * chosen; that is how the "what it is" column was checked, and nothing here
 * links it.
 *
 * WHAT IS CHECKED is what a consumer of struct cell_insn reads: class,
 * length, condition, flags, the written-register mask, the branch target and
 * the operands, in the convention decode_arm.h documents. tools/genotype/
 * arm_diff.c is the other half - random encodings against the oracle.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "kofmod/kofsig.h"
#include <celllysis/celllysis.h>
#include "../../libgenome/celllysis/decode_arm.h"

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

#define R(n)   (1ull << (n))
#define SP 13
#define LR 14
#define PC 15

/* What one operand should be. `val` is the immediate, the displacement or the list. */
struct opx {
	uint8_t  kind;
	uint8_t  reg;
	uint8_t  fl;            /* flags that must be set (RIPREL) */
	int64_t  val;
	uint8_t  check_val;     /* 1: compare val; 2 + k: a REG shifted by kind k */
};

#define NO          { CELL_O_NONE, 0xff, 0, 0, 0 }
#define RG(r)       { CELL_O_REG, (r), 0, 0, 0 }
#define IM(v)       { CELL_O_IMM, 0xff, 0, (int64_t)(v), 1 }
#define RL          { CELL_O_REL, 0xff, 0, 0, 0 }
#define SH(r, k, a) { CELL_O_REG, (r), 0, (int64_t)(a), 2 + (k) }   /* a shifted source */
#define ME(b, d)    { CELL_O_MEM, (b), 0, (int64_t)(d), 1 }
#define LIT(d)      { CELL_O_MEM, PC, CELL_OF_RIPREL, (int64_t)(d), 1 }
#define LIST(v)     { CELL_O_NONE, 0xff, 0, (int64_t)(v), 1 }

struct tc {
	const char *what;
	int         thumb;
	int         be;
	uint32_t    w;          /* A32 word, or Thumb halfword 1 << 16 | halfword 2 */
	unsigned    nb;         /* Thumb: 2 or 4 bytes given */
	uint64_t    va;
	unsigned    op;
	unsigned    len;
	unsigned    n_op;
	unsigned    cond;
	unsigned    flags;
	uint64_t    wmask;
	uint64_t    target;     /* KOF_BROKEN when there is none */
	struct opx  o[3];
};

#define B KOF_BROKEN
#define AL 0xe

static const struct tc C[] = {
	/* ---- A32, from the Mirai ARM binaries ------------------------------ */
	{ "skid.arm7.1 @8634  mov r7,#1  (a syscall number)", 0, 0, 0xe3a07001, 4, 0x8634,
	  CELL_MOV, 4, 2, AL, 0, R(7), B, { RG(7), IM(1) } },
	{ "skid.arm7.1 @10068  mov r7,#0xdd", 0, 0, 0xe3a070dd, 4, 0x10068,
	  CELL_MOV, 4, 2, AL, 0, R(7), B, { RG(7), IM(0xdd) } },
	{ "skid.arm7.1 @fc88  mov r7,#0x80000000  (the rotation: imm8 2 ror 2)", 0, 0, 0xe3a07102, 4, 0xfc88,
	  CELL_MOV, 4, 2, AL, 0, R(7), B, { RG(7), IM(0x80000000u) } },
	{ "skid.arm7.1 @cd08  ldr r7,[pc,#0xb4]  (literal at cd08+8+0xb4)", 0, 0, 0xe59f70b4, 4, 0xcd08,
	  CELL_MOV, 4, 2, AL, 0, R(7), B, { RG(7), LIT(8 + 0xb4) } },
	{ "skid.arm7.1 @1006c  svc 0  (EABI: the number is in r7)", 0, 0, 0xef000000, 4, 0x1006c,
	  CELL_SYSCALL, 4, 1, AL, 0, 0, B, { IM(0) } },
	{ "Demon.arm4 @c2f8  svc 0x900037  (OABI: the number is in the instruction)", 0, 0, 0xef900037, 4, 0xc2f8,
	  CELL_SYSCALL, 4, 1, AL, 0, 0, B, { IM(0x900037) } },
	{ "Demon.arm4 @c384  svc 0x900001  (OABI exit)", 0, 0, 0xef900001, 4, 0xc384,
	  CELL_SYSCALL, 4, 1, AL, 0, 0, B, { IM(0x900001) } },
	{ "skid.arm7.1 @81c0  bl 0x139c0", 0, 0, 0xeb002dfe, 4, 0x81c0,
	  CELL_CALL, 4, 1, AL, 0, R(LR) | R(PC), 0x139c0, { RL } },
	{ "skid.arm7.1 @8124  bx lr  (a return)", 0, 0, 0xe12fff1e, 4, 0x8124,
	  CELL_RET, 4, 1, AL, CELL_F_INDIRECT, R(PC), B, { RG(LR) } },
	{ "skid.arm7.1 @8114  bxne r3  (conditional: the class stays, cond says ne)", 0, 0, 0x112fff13, 4, 0x8114,
	  CELL_JMP, 4, 1, 1, CELL_F_INDIRECT, R(PC), B, { RG(3) } },
	{ "skid.arm7.1 @85c4  push {r4,r5,r6,r7,lr}", 0, 0, 0xe92d40f0, 4, 0x85c4,
	  CELL_PUSH, 4, 0, AL, 0, R(SP), B, { LIST(0x40f0) } },
	{ "skid.arm7.1 @81a4  str r2,[sp,#-4]!  (a one-register push)", 0, 0, 0xe52d2004, 4, 0x81a4,
	  CELL_PUSH, 4, 1, AL, 0, R(SP), B, { RG(2) } },
	{ "arm5.13 @8e34  pop {r4,r5,pc}  (a return that restores)", 0, 0, 0xe8bd8030, 4, 0x8e34,
	  CELL_RET, 4, 0, AL, CELL_F_INDIRECT, R(4) | R(5) | R(SP) | R(PC), B, { LIST(0x8030) } },
	{ "arm5.13 @8e4c  pop {pc}  (ldr pc,[sp],#4)", 0, 0, 0xe49df004, 4, 0x8e4c,
	  CELL_RET, 4, 0, AL, CELL_F_INDIRECT, R(SP) | R(PC), B, { LIST(0x8000) } },
	{ "skid.arm7.1 @10240  ldmia sp!,{r7}  (a one-register pop)", 0, 0, 0xe8bd0080, 4, 0x10240,
	  CELL_POP, 4, 1, AL, 0, R(7) | R(SP), B, { RG(7) } },
	{ "skid.arm7.1 @8b24  ldm r0,{r0,r1}  (not sp: not a pop)", 0, 0, 0xe8900003, 4, 0x8b24,
	  CELL_OTHER, 4, 2, AL, 0, R(0) | R(1), B, { RG(0), IM(3) } },
	{ "skid.arm7.1 @8100  bne 0x8120", 0, 0, 0x1a000006, 4, 0x8100,
	  CELL_JCC, 4, 1, 1, 0, R(PC), 0x8120, { RL } },
	{ "arm5.13 @8df4  beq 0x8e18", 0, 0, 0x0a000007, 4, 0x8df4,
	  CELL_JCC, 4, 1, 0, 0, R(PC), 0x8e18, { RL } },
	{ "arm5.13 @8e14  bne backwards, 0x8df8", 0, 0, 0x1afffff7, 4, 0x8e14,
	  CELL_JCC, 4, 1, 1, 0, R(PC), 0x8df8, { RL } },
	{ "skid.arm7.1 @8290  add r0,r0,#1  (rd == rn: two operands, r0 += 1)", 0, 0, 0xe2800001, 4, 0x8290,
	  CELL_ADD, 4, 2, AL, 0, R(0), B, { RG(0), IM(1) } },
	{ "skid.arm7.1 @8140  sub sp,sp,#4", 0, 0, 0xe24dd004, 4, 0x8140,
	  CELL_SUB, 4, 2, AL, 0, R(SP), B, { RG(SP), IM(4) } },
	{ "add r0,r1,#1  (rd != rn: three operands)", 0, 0, 0xe2810001, 4, 0x8000,
	  CELL_ADD, 4, 3, AL, 0, R(0), B, { RG(0), RG(1), IM(1) } },
	{ "add r0,r1,r2", 0, 0, 0xe0810002, 4, 0x8000,
	  CELL_ADD, 4, 3, AL, 0, R(0), B, { RG(0), RG(1), RG(2) } },
	{ "eor r3,r3,r3  (a register against itself)", 0, 0, 0xe0233003, 4, 0x8000,
	  CELL_XOR, 4, 2, AL, 0, R(3), B, { RG(3), RG(3) } },
	{ "mvn r0,#0  (a constant: MOV of 0xffffffff)", 0, 0, 0xe3e00000, 4, 0x8000,
	  CELL_MOV, 4, 2, AL, 0, R(0), B, { RG(0), IM(0xffffffffu) } },
	{ "mvn r0,r1  (not r0 = ~r0: OTHER, so the map is not told it knows)", 0, 0, 0xe1e00001, 4, 0x8000,
	  CELL_OTHER, 4, 2, AL, 0, R(0), B, { RG(0), RG(1) } },
	{ "mvn r0,r0", 0, 0, 0xe1e00000, 4, 0x8000,
	  CELL_NOT, 4, 2, AL, 0, R(0), B, { RG(0), RG(0) } },
	{ "rsb r0,r0,#0  (negate)", 0, 0, 0xe2600000, 4, 0x8000,
	  CELL_NEG, 4, 2, AL, 0, R(0), B, { RG(0), RG(0) } },
	{ "skid.arm7.1 @8330  lsl r3,sb,#2  (mov with a shifted operand IS a shift)", 0, 0, 0xe1a03109, 4, 0x8330,
	  CELL_SHL, 4, 3, AL, 0, R(3), B, { RG(3), RG(9), IM(2) } },
	{ "skid.arm7.1 @80fc  cmp r3,#0  (writes no register)", 0, 0, 0xe3530000, 4, 0x80fc,
	  CELL_CMP, 4, 2, AL, 0, 0, B, { RG(3), IM(0) } },
	{ "skid.arm7.1 @80f8  ldrb r3,[r4]", 0, 0, 0xe5d43000, 4, 0x80f8,
	  CELL_MOVZX, 4, 2, AL, 0, R(3), B, { RG(3), ME(4, 0) } },
	{ "skid.arm7.1 @826c  ldrb r3,[ip,#4]", 0, 0, 0xe5dc3004, 4, 0x826c,
	  CELL_MOVZX, 4, 2, AL, 0, R(3), B, { RG(3), ME(12, 4) } },
	{ "skid.arm7.1 @11a24  mov r0,r0  (the nop)", 0, 0, 0xe1a00000, 4, 0x11a24,
	  CELL_NOP, 4, 2, AL, 0, R(0), B, { RG(0), RG(0) } },
	{ "skid.arm7.1 @b988  mov r7,r0  (a register: o1 is a REG)", 0, 0, 0xe1a07000, 4, 0xb988,
	  CELL_MOV, 4, 2, AL, 0, R(7), B, { RG(7), RG(0) } },
	{ "skid.arm7.1 @82fc  orr r3,r3,r0,lsr #8  (a shifted source: three operands, the shift on o2)", 0, 0, 0xe1833420, 4, 0x82fc,
	  CELL_OR, 4, 3, AL, 0, R(3), B, { RG(3), RG(3), SH(0, ARM_SH_LSR, 8) } },
	/* ---- A32, written from the ARM ARM: nothing like it in the corpus ---- */
	{ "movw r0,#0x1234", 0, 0, 0xe3010234, 4, 0x8000,
	  CELL_MOV, 4, 2, AL, 0, R(0), B, { RG(0), IM(0x1234) } },
	{ "movt r0,#0xabcd  (an OR of the high half, exact after a movw)", 0, 0, 0xe34a0bcd, 4, 0x8000,
	  CELL_OR, 4, 2, AL, 0, R(0), B, { RG(0), IM(0xabcd0000u) } },
	{ "blx 0x8008  (to Thumb: bit 0 of the target is clear)", 0, 0, 0xfa000000, 4, 0x8000,
	  CELL_CALL, 4, 1, AL, 0, R(LR) | R(PC), 0x8008, { RL } },
	{ "blx 0x800a  (the H bit is the halfword)", 0, 0, 0xfb000000, 4, 0x8000,
	  CELL_CALL, 4, 1, AL, 0, R(LR) | R(PC), 0x800a, { RL } },
	{ "udf #0  (permanently undefined)", 0, 0, 0xe7f000f0, 4, 0x8000,
	  CELL_UD, 4, 0, AL, 0, 0, B, { NO } },
	{ "svc 0, big-endian bytes", 0, 1, 0xef000000, 4, 0x8000,
	  CELL_SYSCALL, 4, 1, AL, 0, 0, B, { IM(0) } },
	/* ---- Thumb, written from the ARM ARM ---------------------------------- */
	{ "movs r7,#0x37", 1, 0, 0x2737, 2, 0x8000,
	  CELL_MOV, 2, 2, AL, 0, R(7), B, { RG(7), IM(0x37) } },
	{ "svc 0", 1, 0, 0xdf00, 2, 0x8000,
	  CELL_SYSCALL, 2, 1, AL, 0, 0, B, { IM(0) } },
	{ "svc 0, big-endian bytes", 1, 1, 0xdf00, 2, 0x8000,
	  CELL_SYSCALL, 2, 1, AL, 0, 0, B, { IM(0) } },
	{ "push {r4,lr}", 1, 0, 0xb510, 2, 0x8000,
	  CELL_PUSH, 2, 0, AL, 0, R(SP), B, { LIST(R(4) | R(LR)) } },
	{ "pop {r4,pc}", 1, 0, 0xbd10, 2, 0x8000,
	  CELL_RET, 2, 0, AL, CELL_F_INDIRECT, R(4) | R(SP) | R(PC), B, { LIST(R(4) | R(PC)) } },
	{ "bx lr", 1, 0, 0x4770, 2, 0x8000,
	  CELL_RET, 2, 1, AL, CELL_F_INDIRECT, R(PC), B, { RG(LR) } },
	{ "blx r3", 1, 0, 0x4798, 2, 0x8000,
	  CELL_CALL, 2, 1, AL, CELL_F_INDIRECT, R(LR) | R(PC), B, { RG(3) } },
	{ "ldr r7,[pc,#0x40] at a 4-aligned address: the base is the address + 4", 1, 0, 0x4f10, 2, 0x8000,
	  CELL_MOV, 2, 2, AL, 0, R(7), B, { RG(7), LIT(4 + 0x40) } },
	{ "ldr r7,[pc,#0x40] at 2 mod 4: Align(pc,4) is 2 bytes on", 1, 0, 0x4f10, 2, 0x8002,
	  CELL_MOV, 2, 2, AL, 0, R(7), B, { RG(7), LIT(2 + 0x40) } },
	{ "bl 0x8008  (the 32-bit pair, one instruction)", 1, 0, 0xf000f802, 4, 0x8000,
	  CELL_CALL, 4, 1, AL, 0, R(LR) | R(PC), 0x8008, { RL } },
	{ "bl 0x8000 from 0x8000+4: a negative offset", 1, 0, 0xf7fffffe, 4, 0x8004,
	  CELL_CALL, 4, 1, AL, 0, R(LR) | R(PC), 0x8004, { RL } },
	{ "bne to itself", 1, 0, 0xd1fe, 2, 0x8000,
	  CELL_JCC, 2, 1, 1, 0, R(PC), 0x8000, { RL } },
	{ "cbz r0 (taken: eq)", 1, 0, 0xb100, 2, 0x8000,
	  CELL_JCC, 2, 2, 0, 0, R(PC), 0x8004, { RL, RG(0) } },
	{ "add sp,#8", 1, 0, 0xb002, 2, 0x8000,
	  CELL_ADD, 2, 2, AL, 0, R(SP), B, { RG(SP), IM(8) } },
	{ "adds r0,#1", 1, 0, 0x3001, 2, 0x8000,
	  CELL_ADD, 2, 2, AL, 0, R(0), B, { RG(0), IM(1) } },
	{ "adds r0,r1,r2", 1, 0, 0x1888, 2, 0x8000,
	  CELL_ADD, 2, 3, AL, 0, R(0), B, { RG(0), RG(1), RG(2) } },
	{ "negs r0,r1  (rd != rm: not a map-computable negate)", 1, 0, 0x4248, 2, 0x8000,
	  CELL_OTHER, 2, 2, AL, 0, R(0), B, { RG(0), RG(1) } },
	{ "cmp r0,#0", 1, 0, 0x2800, 2, 0x8000,
	  CELL_CMP, 2, 2, AL, 0, 0, B, { RG(0), IM(0) } },
	{ "lsls r0,r0,#2", 1, 0, 0x0080, 2, 0x8000,
	  CELL_SHL, 2, 3, AL, 0, R(0), B, { RG(0), RG(0), IM(2) } },
	{ "mov r0,r1", 1, 0, 0x4608, 2, 0x8000,
	  CELL_MOV, 2, 2, AL, 0, R(0), B, { RG(0), RG(1) } },
	{ "muls r0,r1,r0", 1, 0, 0x4348, 2, 0x8000,
	  CELL_MUL, 2, 3, AL, 0, R(0), B, { RG(0), RG(1), RG(0) } },
	{ "uxtb r0,r1", 1, 0, 0xb2c8, 2, 0x8000,
	  CELL_MOVZX, 2, 2, AL, 0, R(0), B, { RG(0), RG(1) } },
	{ "nop", 1, 0, 0xbf00, 2, 0x8000,
	  CELL_NOP, 2, 0, AL, 0, 0, B, { NO } },
	{ "it eq  (length right, class OTHER: the condition is not tracked)", 1, 0, 0xbf08, 2, 0x8000,
	  CELL_OTHER, 2, 0, AL, 0, 0, B, { NO } },
	{ "udf #0", 1, 0, 0xde00, 2, 0x8000,
	  CELL_UD, 2, 0, AL, 0, 0, B, { NO } },
	{ "movw r0,#0x1234  (Thumb-2)", 1, 0, 0xf2412034, 4, 0x8000,
	  CELL_MOV, 4, 2, AL, 0, R(0), B, { RG(0), IM(0x1234) } },
	{ "movt r0,#0xabcd  (Thumb-2)", 1, 0, 0xf6ca30cd, 4, 0x8000,
	  CELL_OR, 4, 2, AL, 0, R(0), B, { RG(0), IM(0xabcd0000u) } },
	{ "sdiv r0,r1,r2", 1, 0, 0xfb91f0f2, 4, 0x8000,
	  CELL_IDIV, 4, 3, AL, 0, R(0), B, { RG(0), RG(1), RG(2) } },
	{ "tbb [pc,r0]  (a table branch: an indirect jump)", 1, 0, 0xe8dff000, 4, 0x8000,
	  CELL_JMP, 4, 1, AL, CELL_F_INDIRECT, R(PC), B, { ME(PC, 0) } },
};

static void put(uint8_t *b, const struct tc *t)
{
	if (!t->thumb) {
		if (t->be) {
			b[0] = (uint8_t)(t->w >> 24); b[1] = (uint8_t)(t->w >> 16);
			b[2] = (uint8_t)(t->w >> 8);  b[3] = (uint8_t)t->w;
		} else {
			b[0] = (uint8_t)t->w;         b[1] = (uint8_t)(t->w >> 8);
			b[2] = (uint8_t)(t->w >> 16); b[3] = (uint8_t)(t->w >> 24);
		}
		return;
	}
	{
		uint32_t h1 = t->nb == 2 ? t->w : t->w >> 16;
		uint32_t h2 = t->w & 0xffffu;

		if (t->be) {
			b[0] = (uint8_t)(h1 >> 8); b[1] = (uint8_t)h1;
			b[2] = (uint8_t)(h2 >> 8); b[3] = (uint8_t)h2;
		} else {
			b[0] = (uint8_t)h1;        b[1] = (uint8_t)(h1 >> 8);
			b[2] = (uint8_t)h2;        b[3] = (uint8_t)(h2 >> 8);
		}
	}
}

static int operand_ok(const struct cell_operand *d, const struct opx *x)
{
	if (d->kind != x->kind)
		return 0;
	if (x->kind == CELL_O_REG && d->reg != x->reg)
		return 0;
	if (x->kind == CELL_O_MEM && d->reg != x->reg)
		return 0;
	if ((d->flags & x->fl) != x->fl)
		return 0;
	if (x->check_val >= 2) {
		/* a shifted register: the shift kind is check_val - 2, the amount disp */
		if (d->scale != x->check_val - 2u || d->disp != x->val)
			return 0;
	} else if (x->check_val) {
		if (x->kind == CELL_O_IMM && d->imm != (uint64_t)x->val)
			return 0;
		if (x->kind == CELL_O_MEM && d->disp != x->val)
			return 0;
		if (x->kind == CELL_O_NONE && d->imm != (uint64_t)x->val)
			return 0;
	}
	return 1;
}

static void curated(void)
{
	size_t i;

	printf("encodings:\n");
	for (i = 0; i < sizeof C / sizeof C[0]; i++) {
		const struct tc *t = &C[i];
		struct cell_insn k;
		uint8_t b[4];
		uint32_t n;
		unsigned q;
		int good;

		put(b, t);
		n = t->thumb ? cell_decode_t32(b, 4, t->va, t->be, &k)
			     : cell_decode_a32(b, 4, t->va, t->be, &k);
		good = n == t->len && k.len == t->len && k.op == t->op &&
		       k.n_op == t->n_op && k.cond == t->cond &&
		       k.flags == t->flags && k.wmask == t->wmask &&
		       k.target_va == t->target && k.target == t->target &&
		       k.at_va == t->va && k.at == t->va;
		for (q = 0; q < 3; q++)
			good = good && operand_ok(&k.o[q], &t->o[q]);
		/* a literal's address is the instruction's plus the displacement */
		if (t->o[1].fl & CELL_OF_RIPREL)
			good = good && (uint64_t)((int64_t)t->va + k.o[1].disp) ==
					(uint64_t)((int64_t)t->va + t->o[1].val);
		if (!good)
			printf("    got op %u len %u n_op %u cond %u flags %u wmask %llx target %llx\n",
			       k.op, k.len, k.n_op, k.cond, k.flags,
			       (unsigned long long)k.wmask,
			       (unsigned long long)k.target_va);
		ok(t->what, good);
	}
}

/*
 * The edges of the contract: too few bytes, a Thumb 32-bit instruction cut in
 * half, an unallocated encoding, and what an absent operand looks like.
 */
static void edges(void)
{
	static const uint8_t svc0[4] = { 0, 0, 0, 0xef };
	static const uint8_t t32[4] = { 0x00, 0xf0, 0x02, 0xf8 };      /* bl */
	static const uint8_t ud[4] = { 0xf0, 0x00, 0xf0, 0xe7 };       /* udf */
	struct cell_insn k;
	unsigned q;

	printf("edges:\n");
	ok("A32 with 3 bytes is 0", cell_decode_a32(svc0, 3, 0, 0, &k) == 0);
	ok("A32 with 0 bytes is 0", cell_decode_a32(svc0, 0, 0, 0, &k) == 0);
	ok("Thumb with 1 byte is 0", cell_decode_t32(t32, 1, 0, 0, &k) == 0);
	ok("Thumb 32-bit with 2 bytes is 0", cell_decode_t32(t32, 2, 0, 0, &k) == 0);
	ok("Thumb 32-bit with 4 bytes is 4", cell_decode_t32(t32, 4, 0, 0, &k) == 4);
	ok("Thumb 16-bit with 2 bytes is 2", cell_decode_t32(svc0, 2, 0, 0, &k) == 2);
	ok("a null buffer is 0", cell_decode_a32(NULL, 4, 0, 0, &k) == 0);
	ok("undefined is length 4 and CELL_UD", cell_decode_a32(ud, 4, 0, 0, &k) == 4 &&
	   k.op == CELL_UD && k.wmask == 0);
	cell_decode_a32(svc0, 4, 0x1234, 0, &k);
	for (q = 1; q < 3; q++)
		ok("an absent operand is CELL_O_NONE with no register",
		   k.o[q].kind == CELL_O_NONE && k.o[q].reg == CELL_REG_NONE);
	ok("no target is KOF_BROKEN, the same sentinel the other decoders use",
	   k.target == KOF_BROKEN && k.target_va == KOF_BROKEN);
}

int main(void)
{
	printf("decode a32/t32:\n");
	curated();
	edges();
	printf("decode a32/t32: %d checks, %s\n", checks, failures ? "FAILED" : "ok");
	return failures != 0;
}
