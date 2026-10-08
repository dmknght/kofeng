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

/*
 * THE SWEEP'S VIEW AGREES WITH THE GENERAL BUILDER. gt_x86_sweep builds the explicit
 * operands with the lean instantiation of the code gt_x86_operand runs; this
 * checks the two on generated encodings by narrowing gt_x86_operand's answer
 * the way the sweep's adapter used to (and the way the sweep now documents): the
 * first three of the general registers, memory operands, immediates and relative
 * offsets, and a mask of every general register written. Nothing here is a table
 * of expected answers - the check is that the two paths cannot drift apart.
 */
static uint64_t rng_s = 0x9e3779b97f4a7c15ull;

static unsigned rnd(unsigned n)
{
	rng_s ^= rng_s << 13;
	rng_s ^= rng_s >> 7;
	rng_s ^= rng_s << 17;
	return (unsigned)((rng_s >> 11) % n);
}

static void gen(uint8_t *b)
{
	static const uint8_t pf[] = { 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3 };
	unsigned i = 0, np = rnd(3) ? rnd(3) : rnd(7), k;

	for (k = 0; k < np; k++) {
		unsigned c = rnd(13);

		b[i++] = c < 11 ? pf[c] : (uint8_t)(0x40 + rnd(16));
	}
	switch (rnd(8)) {
	case 0: b[i++] = 0x0f; b[i++] = (uint8_t)rnd(256); break;
	case 1: b[i++] = 0x0f; b[i++] = rnd(2) ? 0x38 : 0x3a; b[i++] = (uint8_t)rnd(256); break;
	case 2: b[i++] = rnd(2) ? 0xc4 : 0xc5; b[i++] = (uint8_t)rnd(256); b[i++] = (uint8_t)rnd(256); b[i++] = (uint8_t)rnd(256); break;
	case 3: b[i++] = 0x62; b[i++] = (uint8_t)rnd(256); b[i++] = (uint8_t)rnd(256); b[i++] = (uint8_t)rnd(256); b[i++] = (uint8_t)rnd(256); break;
	default: b[i++] = (uint8_t)rnd(256); break;
	}
	while (i < 16)
		b[i++] = (uint8_t)rnd(256);
}

static int sweep_matches(const uint8_t *b, int mode)
{
	static const uint8_t accf[4] = { 0, GT_X86_SF_READ, GT_X86_SF_WRITE, GT_X86_SF_READ | GT_X86_SF_WRITE };
	struct gt_x86_insn x;
	struct gt_x86_sweep s;
	struct gt_x86_sop w[3];
	uint64_t wmask;
	unsigned i, k = 0, nexp;
	enum gt_status st = gt_x86_decode(&x, b, 16, mode), ss = gt_x86_sweep(&s, b, 16, mode);

	if (st != ss)
		return 0;
	if (st != GT_OK)
		return 1;
	for (i = 0; i < 3; i++) {
		static const struct gt_x86_sop none = GT_X86_SOP_NONE;

		w[i] = none;
	}
	wmask = gt_x86_wgpr(&x);
	nexp = gt_x86_nexp(&x);
	for (i = 0; i < nexp; i++) {
		struct gt_x86_op o;
		struct gt_x86_sop *v = &w[k < 3 ? k : 0];
		struct gt_x86_sop t = *v;

		gt_x86_operand(&x, i, &o);
		if ((o.acc & GT_X86_ACC_W) && o.type == GT_X86_OP_REG && o.rtype == GT_X86_REG_GPR && o.reg < 64u)
			wmask |= 1ull << gt_x86_gpr_of(&o);
		if (k >= 3)
			continue;
		t.size = (uint8_t)o.size;
		t.flags = accf[o.acc & 3u];
		switch (o.type) {
		case GT_X86_OP_REG:
			if (o.rtype != GT_X86_REG_GPR)
				continue;
			t.kind = GT_X86_SK_REG;
			t.reg = (uint8_t)gt_x86_gpr_of(&o);
			if (o.high8)
				t.flags |= GT_X86_SF_HIGH8;
			break;
		case GT_X86_OP_IMM:
			t.kind = GT_X86_SK_IMM;
			t.imm = (uint64_t)o.v;
			break;
		case GT_X86_OP_REL:
			t.kind = GT_X86_SK_REL;
			t.imm = (uint64_t)o.v;
			break;
		case GT_X86_OP_MEM:
			t.kind = GT_X86_SK_MEM;
			if (o.mf & GT_X86_M_BASE)
				t.reg = o.base;
			if (o.mf & GT_X86_M_INDEX) {
				t.index = o.index;
				t.scale = o.scale;
			}
			if (o.mf & GT_X86_M_DISP)
				t.disp = o.v;
			if (o.mf & GT_X86_M_RIPREL)
				t.flags |= GT_X86_SF_RIPREL;
			if (o.mf & GT_X86_M_SEG)
				t.seg = o.seg;
			break;
		default:
			continue;
		}
		w[k++] = t;
	}
	if (s.id != x.id || s.len != x.len || s.rep != x.rep || s.cond != gt_x86_cond(&x) ||
	    s.cat != gt_x86_cat(&x) || s.n != k || s.wmask != wmask)
		return 0;
	for (i = 0; i < 3; i++)
		if (s.op[i].kind != w[i].kind || s.op[i].reg != w[i].reg || s.op[i].index != w[i].index ||
		    s.op[i].scale != w[i].scale || s.op[i].size != w[i].size || s.op[i].flags != w[i].flags ||
		    s.op[i].seg != w[i].seg || s.op[i].disp != w[i].disp || s.op[i].imm != w[i].imm)
			return 0;
	return 1;
}

static void sweep_agrees(void)
{
	unsigned n, bad = 0, decoded = 0;

	printf("sweep view against gt_x86_operand:\n");
	for (n = 0; n < 2000000u; n++) {
		uint8_t b[16];
		struct gt_x86_insn x;
		int mode = (n & 1) ? 64 : 32;

		gen(b);
		decoded += gt_x86_decode(&x, b, 16, mode) == GT_OK;
		if (!sweep_matches(b, mode))
			bad++;
	}
	printf("  %u encodings, %u decode, %u differ\n", n, decoded, bad);
	ok("the sweep's operands are the general builder's, narrowed", bad == 0 && decoded > 500000u);
}

int main(void)
{
	printf("genotype x86:\n");
	curated();
	rip_relative();
	sweep_agrees();
	printf("genotype x86: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
