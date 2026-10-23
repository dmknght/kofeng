/*
 * lineage_asm.h - a small x86 / x86-64 assembler for the lineage tests: the instructions a generated
 * program needs, labels, and fixups against symbols the image builder places afterwards (an import's
 * stub or slot, a global).
 *
 * WRITTEN FOR THE TEST AND NOT FROM THE ENGINE'S DECODER: it encodes from the instruction set manual's
 * tables (ModRM, SIB, REX), so a decoder bug cannot make a test agree with itself. Header only, every
 * function static.
 */
#ifndef KGENOME_TESTS_LINEAGE_ASM_H
#define KGENOME_TESTS_LINEAGE_ASM_H

#include <stdint.h>
#include <string.h>

/* a header every test of the family includes whole: one that does not use a function does not warn */
#define LA_UNUSED __attribute__((unused))

#define LA_CODE_MAX  (64u * 1024u)
#define LA_FX_MAX    4096u
#define LA_LABEL_MAX 2048u

/* The registers, in the machine's own numbering (the same as the engine's cell numbering). */
enum { LA_AX = 0, LA_CX, LA_DX, LA_BX, LA_SP, LA_BP, LA_SI, LA_DI, LA_R8, LA_R9, LA_R10, LA_R11 };

/* A reference the image builder resolves once the layout is known. */
enum la_fx_kind {
	LA_FX_LABEL,    /* rel32 to a label of this code */
	LA_FX_RIP_SYM,  /* disp32 relative to the end of the instruction, to a symbol */
	LA_FX_ABS_SYM,  /* abs32 address of a symbol */
	LA_FX_REL_SYM   /* rel32 to a symbol (a call or a jump to a stub or a thunk) */
};

struct la_fx {
	uint32_t at;            /* where the 4 bytes are */
	uint32_t end;           /* the offset the displacement is relative to: the end of the instruction */
	int      kind;
	int      target;        /* a label, or a symbol */
};

struct la {
	uint8_t  b[LA_CODE_MAX];
	uint32_t n;
	struct la_fx fx[LA_FX_MAX];
	uint32_t nfx;
	int32_t  label[LA_LABEL_MAX];
	int      nlabel;
	int      wide;          /* 64-bit code: REX.W on the 64-bit forms */
	int      overflow;
};

static LA_UNUSED void la_init(struct la *a, int wide)
{
	memset(a, 0, sizeof *a);
	a->wide = wide;
}

static LA_UNUSED void la_b(struct la *a, unsigned v)
{
	if (a->n < LA_CODE_MAX)
		a->b[a->n++] = (uint8_t)v;
	else
		a->overflow = 1;
}

static LA_UNUSED void la_d(struct la *a, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		la_b(a, (v >> (8u * i)) & 0xffu);
}

static LA_UNUSED int la_label(struct la *a)
{
	if (a->nlabel >= (int)LA_LABEL_MAX) {
		a->overflow = 1;
		return 0;
	}
	a->label[a->nlabel] = -1;
	return a->nlabel++;
}

static LA_UNUSED void la_bind(struct la *a, int l)
{
	a->label[l] = (int32_t)a->n;
}

static LA_UNUSED void la_fx(struct la *a, int kind, int target)
{
	if (a->nfx < LA_FX_MAX) {
		a->fx[a->nfx].at = a->n;
		a->fx[a->nfx].end = a->n + 4u;      /* corrected by the caller when an immediate follows */
		a->fx[a->nfx].kind = kind;
		a->fx[a->nfx++].target = target;
	} else {
		a->overflow = 1;
	}
	la_d(a, 0);
}

/* REX for a 64-bit operation (W) naming reg and base registers that may be r8..r15. */
static LA_UNUSED void la_rex(struct la *a, int w, unsigned reg, unsigned base)
{
	unsigned rex = (w && a->wide ? 0x48u : 0x40u) | ((reg >> 3) & 1u) << 2 | ((base >> 3) & 1u);

	if (rex != 0x40u)
		la_b(a, rex);
}

/* ModRM + SIB + displacement for [base + disp] and a register field. */
static LA_UNUSED void la_mem(struct la *a, unsigned reg, unsigned base, int32_t disp)
{
	const unsigned r = reg & 7u, bb = base & 7u;
	const int d8 = disp >= -128 && disp <= 127;

	if (bb == 4u) {
		la_b(a, (d8 ? 0x44u : 0x84u) | r << 3);
		la_b(a, 0x24u);
	} else {
		la_b(a, (d8 ? 0x40u : 0x80u) | r << 3 | bb);
	}
	if (d8)
		la_b(a, (uint32_t)disp & 0xffu);
	else
		la_d(a, (uint32_t)disp);
}

/* mov reg, [base+disp]   (full width) */
static LA_UNUSED void la_load(struct la *a, unsigned reg, unsigned base, int32_t disp)
{
	la_rex(a, 1, reg, base);
	la_b(a, 0x8b);
	la_mem(a, reg, base, disp);
}

/* mov [base+disp], reg */
static LA_UNUSED void la_store(struct la *a, unsigned base, int32_t disp, unsigned reg)
{
	la_rex(a, 1, reg, base);
	la_b(a, 0x89);
	la_mem(a, reg, base, disp);
}

/* mov dst, src */
static LA_UNUSED void la_mov(struct la *a, unsigned dst, unsigned src)
{
	la_rex(a, 1, src, dst);
	la_b(a, 0x89);
	la_b(a, 0xc0u | (src & 7u) << 3 | (dst & 7u));
}

/* mov reg, imm32 (sign-extended on x86-64) */
static LA_UNUSED void la_movi(struct la *a, unsigned reg, int32_t imm)
{
	if (a->wide) {
		la_rex(a, 1, 0, reg);
		la_b(a, 0xc7);
		la_b(a, 0xc0u | (reg & 7u));
	} else {
		la_b(a, 0xb8u + (reg & 7u));
	}
	la_d(a, (uint32_t)imm);
}

/* xor reg32, reg32 */
static LA_UNUSED void la_zero(struct la *a, unsigned reg)
{
	la_rex(a, 0, reg, reg);
	la_b(a, 0x31);
	la_b(a, 0xc0u | (reg & 7u) << 3 | (reg & 7u));
}

/* mov reg, [rip+sym]  /  mov reg, [abs sym]  and the stores */
static LA_UNUSED void la_load_sym(struct la *a, unsigned reg, int sym)
{
	if (a->wide) {
		la_rex(a, 1, reg, 0);
		la_b(a, 0x8b);
		la_b(a, 0x05u | (reg & 7u) << 3);
		la_fx(a, LA_FX_RIP_SYM, sym);
	} else {
		la_b(a, 0x8b);
		la_b(a, 0x05u | (reg & 7u) << 3);
		la_fx(a, LA_FX_ABS_SYM, sym);
	}
}

static LA_UNUSED void la_store_sym(struct la *a, int sym, unsigned reg)
{
	if (a->wide) {
		la_rex(a, 1, reg, 0);
		la_b(a, 0x89);
		la_b(a, 0x05u | (reg & 7u) << 3);
		la_fx(a, LA_FX_RIP_SYM, sym);
	} else {
		la_b(a, 0x89);
		la_b(a, 0x05u | (reg & 7u) << 3);
		la_fx(a, LA_FX_ABS_SYM, sym);
	}
}

/* lea reg, [src+disp] */
static LA_UNUSED void la_lea(struct la *a, unsigned reg, unsigned src, int32_t disp)
{
	la_rex(a, 1, reg, src);
	la_b(a, 0x8d);
	la_mem(a, reg, src, disp);
}

/* add reg, imm8 / sub reg, imm8 (sign-extended) */
static LA_UNUSED void la_addi(struct la *a, unsigned reg, int8_t imm)
{
	la_rex(a, 1, 0, reg);
	la_b(a, 0x83);
	la_b(a, 0xc0u | (reg & 7u));
	la_b(a, (uint8_t)imm);
}

/* add rsp, imm32 / sub rsp, imm32 */
static LA_UNUSED void la_spadj(struct la *a, int sub, int32_t imm)
{
	la_rex(a, 1, 0, LA_SP);
	la_b(a, 0x81);
	la_b(a, (sub ? 0xe8u : 0xc0u) | LA_SP);
	la_d(a, (uint32_t)imm);
}

/* and rsp, -16 */
static LA_UNUSED void la_andsp16(struct la *a)
{
	la_rex(a, 1, 0, LA_SP);
	la_b(a, 0x83);
	la_b(a, 0xe4);
	la_b(a, 0xf0);
}

static LA_UNUSED void la_push(struct la *a, unsigned reg)
{
	la_rex(a, 0, 0, reg);
	la_b(a, 0x50u + (reg & 7u));
}

static LA_UNUSED void la_pop(struct la *a, unsigned reg)
{
	la_rex(a, 0, 0, reg);
	la_b(a, 0x58u + (reg & 7u));
}

static LA_UNUSED void la_pushi(struct la *a, int32_t imm)
{
	la_b(a, 0x68);
	la_d(a, (uint32_t)imm);
}

/* push [base+disp] */
static LA_UNUSED void la_push_mem(struct la *a, unsigned base, int32_t disp)
{
	la_rex(a, 0, 0, base);
	la_b(a, 0xff);
	la_mem(a, 6, base, disp);
}

static LA_UNUSED void la_ret(struct la *a)
{
	la_b(a, 0xc3);
}

static LA_UNUSED void la_ret_n(struct la *a, unsigned n)
{
	la_b(a, 0xc2);
	la_b(a, n & 0xffu);
	la_b(a, (n >> 8) & 0xffu);
}

static LA_UNUSED void la_int3(struct la *a)
{
	la_b(a, 0xcc);
}

/* call / jmp rel32 to a label of this code */
static LA_UNUSED void la_call_label(struct la *a, int l)
{
	la_b(a, 0xe8);
	la_fx(a, LA_FX_LABEL, l);
}

static LA_UNUSED void la_jmp_label(struct la *a, int l)
{
	la_b(a, 0xe9);
	la_fx(a, LA_FX_LABEL, l);
}

/* jcc rel32: cc 4 = e/z, 5 = ne/nz */
static LA_UNUSED void la_jcc_label(struct la *a, unsigned cc, int l)
{
	la_b(a, 0x0f);
	la_b(a, 0x80u + cc);
	la_fx(a, LA_FX_LABEL, l);
}

/* call / jmp rel32 to a symbol (a stub or a thunk) */
static LA_UNUSED void la_jmp_sym(struct la *a, int sym)
{
	la_b(a, 0xe9);
	la_fx(a, LA_FX_REL_SYM, sym);
}

static LA_UNUSED void la_call_sym(struct la *a, int sym)
{
	la_b(a, 0xe8);
	la_fx(a, LA_FX_REL_SYM, sym);
}

/* call [rip+sym] / call [abs sym] and the jumps */
static LA_UNUSED void la_call_slot(struct la *a, int sym)
{
	la_b(a, 0xff);
	la_b(a, 0x15);
	la_fx(a, a->wide ? LA_FX_RIP_SYM : LA_FX_ABS_SYM, sym);
}

static LA_UNUSED void la_jmp_slot(struct la *a, int sym)
{
	la_b(a, 0xff);
	la_b(a, 0x25);
	la_fx(a, a->wide ? LA_FX_RIP_SYM : LA_FX_ABS_SYM, sym);
}

/* call reg */
static LA_UNUSED void la_call_reg(struct la *a, unsigned reg)
{
	la_rex(a, 0, 0, reg);
	la_b(a, 0xff);
	la_b(a, 0xd0u | (reg & 7u));
}

/* test reg, reg */
static LA_UNUSED void la_test(struct la *a, unsigned reg)
{
	la_rex(a, 1, reg, reg);
	la_b(a, 0x85);
	la_b(a, 0xc0u | (reg & 7u) << 3 | (reg & 7u));
}

/* Pad with int3 to a multiple of `to`. */
static LA_UNUSED void la_align(struct la *a, unsigned to)
{
	while (a->n % to)
		la_int3(a);
}

/* Resolve the labels; the symbol fixups wait for the layout (la_patch). */
static LA_UNUSED int la_resolve_labels(struct la *a)
{
	uint32_t i;

	for (i = 0; i < a->nfx; i++) {
		struct la_fx *f = &a->fx[i];
		int32_t rel;

		if (f->kind != LA_FX_LABEL)
			continue;
		if (f->target < 0 || f->target >= a->nlabel || a->label[f->target] < 0)
			return 0;
		rel = a->label[f->target] - (int32_t)f->end;
		a->b[f->at] = (uint8_t)rel;
		a->b[f->at + 1u] = (uint8_t)((uint32_t)rel >> 8);
		a->b[f->at + 2u] = (uint8_t)((uint32_t)rel >> 16);
		a->b[f->at + 3u] = (uint8_t)((uint32_t)rel >> 24);
	}
	return !a->overflow;
}

#endif /* KGENOME_TESTS_LINEAGE_ASM_H */
