/*
 * lineage_cg.h - the lineage tests' code generator: a program of the model (lineage_ir.h) to x86 or x86-64
 * machine code for one of four targets - ELF x86-64 (System V), ELF i386 (cdecl), PE x64 (Windows) and PE x86
 * (stdcall imports, cdecl or stdcall functions) - through the assembler (lineage_asm.h).
 *
 * VARIETY IS THE POINT. Everything an optimiser and an unoptimising compiler do differently is drawn at
 * random per function, so the analysis is read against code that does not look alike: frames addressed
 * through the stack pointer or the frame pointer (and an epilogue that restores the stack from either), an
 * argument loaded straight into its register or built in a temporary first, a value left in rax from one
 * call to the next, imports reached through a stub, through the slot itself, or through a thunk, a
 * function that returns with `ret` or with `ret N`, a tail call as a jump. None of it changes what a
 * program MEANS, which is the whole of what the oracle knows.
 */
#ifndef KGENOME_TESTS_LINEAGE_CG_H
#define KGENOME_TESTS_LINEAGE_CG_H

#include "lineage_asm.h"
#include "lineage_ir.h"

enum { LG_T_ELF64, LG_T_ELF32, LG_T_PE64, LG_T_PE32 };

/* The imports of every image: the eight APIs of the model (1..8), the import with no capability that is the
 * condition of an `if` (9), and the one that is an unknown VALUE (10). Index 0 is unused. */
#define LG_NIMP 11
#define LG_IMP_COND 9
#define LG_IMP_VAL  10

static const char *const lg_elf_names[LG_NIMP] = { "?", "socket", "accept", "malloc", "connect", "listen", "bind", "read", "write", "getpid", "rand" };
static const char *const lg_pe_names[LG_NIMP] = { "?", "socket", "accept", "HeapAlloc", "connect", "listen", "bind", "recv", "send", "GetTickCount", "GetLastError" };

/* Symbols a fixup names: each import's stub, slot and thunk, the globals, the pointer table cell. */
#define LG_SYM_STUB(i)  (i)
#define LG_SYM_SLOT(i)  (LG_NIMP + (i))
#define LG_SYM_THUNK(i) (2 * LG_NIMP + (i))
#define LG_SYM_G(j)     (3 * LG_NIMP + (j))
#define LG_SYM_TAB      (3 * LG_NIMP + LG_MAXG)
#define LG_NSYM         (LG_SYM_TAB + 1)

struct lg_cg {
	struct la a;
	const struct lg_prog *p;
	struct lg_rng *r;
	int target, wide, word;
	int win;                        /* Windows x64 argument registers */
	int pe;
	uint32_t site_off[LG_MAXSITE];
	int fn_label[LG_MAXF];
	uint32_t fn_off[LG_MAXF], fn_end[LG_MAXF];
	int fn_style[LG_MAXF];          /* frame addressed through the frame pointer (1), the stack pointer (0), or the frame pointer with the
					 * stack pointer aligned after the frame is made (2: `and rsp, -16`, what main of a gcc program does) */
	int fn_std[LG_MAXF];            /* PE x86: the callee pops its arguments */
	int cur;                        /* the function being generated */
	int pushed;                     /* bytes pushed for a call in progress (an i386 stack-pointer frame) */
	int frame;
	int thunk_used[LG_NIMP];
	uint32_t thunk_off[LG_NIMP];
	int overflow;
};

#define LG_SLOT_P     (LG_MAXV)
#define LG_SLOT_T     (LG_MAXV + LG_MAXP)
#define LG_NSLOT      (LG_MAXV + LG_MAXP + 6)

static const unsigned lg_regs_sysv[4] = { LA_DI, LA_SI, LA_DX, LA_CX };
static const unsigned lg_regs_win[4] = { LA_CX, LA_DX, LA_R8, LA_R9 };

/* Where a slot is, as (base register, displacement). */
static LA_UNUSED void lg_slot(const struct lg_cg *c, int slot, unsigned *base, int32_t *disp)
{
	if (c->fn_style[c->cur]) {
		*base = LA_BP;
		*disp = -(int32_t)(c->word * (slot + 1));
	} else {
		*base = LA_SP;
		*disp = (int32_t)(c->word * slot + c->pushed);
	}
}

/* Where parameter `i` of an i386 function is: above the saved frame pointer and the return address. */
static LA_UNUSED void lg_param32(const struct lg_cg *c, int i, unsigned *base, int32_t *disp)
{
	if (c->fn_style[c->cur]) {
		*base = LA_BP;
		*disp = 8 + 4 * i;
	} else {
		*base = LA_SP;
		*disp = c->frame + 4 + 4 * i + c->pushed;
	}
}

static LA_UNUSED void lg_load_slot(struct lg_cg *c, unsigned reg, int slot)
{
	unsigned base;
	int32_t disp;

	lg_slot(c, slot, &base, &disp);
	la_load(&c->a, reg, base, disp);
}

static LA_UNUSED void lg_store_slot(struct lg_cg *c, int slot, unsigned reg)
{
	unsigned base;
	int32_t disp;

	lg_slot(c, slot, &base, &disp);
	la_store(&c->a, base, disp, reg);
}

static LA_UNUSED void lg_emit_call_target(struct lg_cg *c, int imp, int site)
{
	/* How a program reaches an import: through the stub or thunk a call lands on, or through the slot. */
	const unsigned v = lg_rnd(c->r, 4u);

	if (site >= 0)
		c->site_off[site] = c->a.n;
	if (!c->pe) {
		if (v == 0)
			la_call_slot(&c->a, LG_SYM_SLOT(imp));          /* -fno-plt */
		else
			la_call_sym(&c->a, LG_SYM_STUB(imp));
	} else if (c->wide) {
		la_call_slot(&c->a, LG_SYM_SLOT(imp));
	} else if (v < 2u) {
		la_call_slot(&c->a, LG_SYM_SLOT(imp));
	} else {
		c->thunk_used[imp] = 1;
		la_call_sym(&c->a, LG_SYM_THUNK(imp));
	}
}

static LA_UNUSED void lg_expr(struct lg_cg *c, int e, int depth);

static LA_UNUSED int lg_is_leaf(const struct lg_prog *p, int e)
{
	int k = p->ex[e].kind;

	return k == LG_E_VAR || k == LG_E_PARAM || k == LG_E_CONST || k == LG_E_STALE;
}

/* Put a leaf's value in a register. */
static LA_UNUSED void lg_leaf(struct lg_cg *c, unsigned reg, int e)
{
	const struct lg_expr *x = &c->p->ex[e];

	if (x->kind == LG_E_STALE) {
		return;                 /* no instruction: the register keeps what the last call left in it */
	} else if (x->kind == LG_E_VAR) {
		lg_load_slot(c, reg, x->x);
	} else if (x->kind == LG_E_PARAM) {
		if (c->wide) {
			lg_load_slot(c, reg, LG_SLOT_P + x->x);
		} else {
			unsigned base;
			int32_t disp;

			lg_param32(c, x->x, &base, &disp);
			la_load(&c->a, reg, base, disp);
		}
	} else if (lg_rnd(c->r, 2u)) {
		la_zero(&c->a, reg);
	} else {
		la_movi(&c->a, reg, 0x1000 + (int32_t)lg_rnd(c->r, 4096u));
	}
}

/*
 * A CALL: of an import (a node when it has a capability) or of a function of the program. `total` is how many
 * arguments the callee takes; the model supplies the first `n` as expressions and the rest are constants.
 */
static LA_UNUSED void lg_call(struct lg_cg *c, int imp, int callee, int site, const int *arg, int n, int total, int depth)
{
	int i;

	if (!c->wide) {
		/* cdecl pushes right to left; a stdcall import pops what was pushed */
		for (i = total - 1; i >= 0; i--) {
			if (i >= n || c->p->ex[arg[i]].kind == LG_E_STALE) {
				la_pushi(&c->a, (int32_t)(0x40 + i));
			} else if (c->p->ex[arg[i]].kind == LG_E_VAR) {
				unsigned base;
				int32_t disp;

				lg_slot(c, c->p->ex[arg[i]].x, &base, &disp);
				la_push_mem(&c->a, base, disp);
			} else {
				lg_expr(c, arg[i], depth + 1);
				la_push(&c->a, LA_AX);
			}
			c->pushed += 4;
		}
		if (callee >= 0)
			la_call_label(&c->a, c->fn_label[callee]);
		else
			lg_emit_call_target(c, imp, site);
		if (callee >= 0 ? !c->fn_std[callee] : !c->pe) {
			if (total)
				la_spadj(&c->a, 0, 4 * total);
		}
		c->pushed -= 4 * total;
		return;
	}
	{
		const unsigned *regs = c->win ? lg_regs_win : lg_regs_sysv;
		int direct = n == 1 && !lg_is_leaf(c->p, arg[0]) && lg_rnd(c->r, 2u);
		int tmp[3] = { -1, -1, -1 };

		/* the arguments that are not leaves are built first, each in a temporary of its own depth */
		const int pushy = lg_rnd(c->r, 3u) == 0;       /* hold the built arguments on the stack instead of in slots */
		int npush = 0;

		for (i = 0; i < n && !direct; i++) {
			tmp[i] = -1;
			if (!lg_is_leaf(c->p, arg[i])) {
				lg_expr(c, arg[i], depth + 1);
				if (pushy) {
					tmp[i] = -2;
					la_push(&c->a, LA_AX);
					c->pushed += c->word;
					npush++;
				} else {
					tmp[i] = LG_SLOT_T + 2 * depth + i;
					lg_store_slot(c, tmp[i], LA_AX);
				}
			}
		}
		/* a register left as it was is one a call has just destroyed: this one is made so by a call to an import that
		 * means nothing, so what the register holds is what any call leaves, on every path */
		for (i = 0; i < n; i++)
			if (c->p->ex[arg[i]].kind == LG_E_STALE) {
				lg_emit_call_target(c, LG_IMP_VAL, -1);
				break;
			}
		if (direct) {
			lg_expr(c, arg[0], depth + 1);
			la_mov(&c->a, regs[0], LA_AX);
		}
		/* what was pushed comes back last in first out */
		for (i = n - 1; i >= 0 && npush; i--)
			if (tmp[i] == -2) {
				la_pop(&c->a, regs[i]);
				c->pushed -= c->word;
				npush--;
			}
		for (i = direct ? 1 : 0; i < total; i++) {
			if (i >= n)
				la_movi(&c->a, regs[i], 0x40 + i);
			else if (tmp[i] >= 0)
				lg_load_slot(c, regs[i], tmp[i]);
			else if (tmp[i] == -1)
				lg_leaf(c, regs[i], arg[i]);
		}
		if (callee >= 0) {
			la_call_label(&c->a, c->fn_label[callee]);
		} else {
			lg_emit_call_target(c, imp, site);
		}
	}
}

static LA_UNUSED void lg_expr(struct lg_cg *c, int e, int depth)
{
	const struct lg_expr *x = &c->p->ex[e];
	int imp;

	switch (x->kind) {
	case LG_E_VAR:
	case LG_E_PARAM:
	case LG_E_CONST:
		lg_leaf(c, LA_AX, e);
		break;
	case LG_E_UNK:
		lg_emit_call_target(c, LG_IMP_VAL, -1);
		break;
	case LG_E_GLOBAL:
		la_load_sym(&c->a, LA_AX, LG_SYM_G(x->x));
		break;
	case LG_E_FIELD:
		lg_load_slot(c, LA_CX, 0);
		la_load(&c->a, LA_AX, LA_CX, (int32_t)(c->word * x->x));
		break;
	case LG_E_STALE:
		break;                  /* the register is whatever it was */
	case LG_E_ARITH:
		lg_expr(c, x->arg[0], depth + 1);
		la_b(&c->a, 0x6b);      /* imul eax, eax, 3 */
		la_b(&c->a, 0xc0);
		la_b(&c->a, 3);
		break;
	case LG_E_BYTE:
		lg_expr(c, x->arg[0], depth + 1);
		la_b(&c->a, 0xb0);      /* mov al, imm8 */
		la_b(&c->a, 0x20u + lg_rnd(c->r, 8u));
		break;
	case LG_E_DERIVE:
		lg_expr(c, x->arg[0], depth + 1);
		if (lg_rnd(c->r, 2u))
			la_lea(&c->a, LA_AX, LA_AX, 8);
		else
			la_addi(&c->a, LA_AX, 8);
		break;
	case LG_E_ICALL:
		lg_expr(c, x->arg[0], depth + 1);
		la_load_sym(&c->a, LA_AX, LG_SYM_TAB);
		la_call_reg(&c->a, LA_AX);
		break;
	case LG_E_API: {
		/* the real signatures: how many arguments each API takes on each side (a stdcall callee pops exactly this many) */
		static const int elf_total[LG_NAPI] = { 0, 3, 3, 1, 3, 2, 3, 3, 3 };
		static const int pe_total[LG_NAPI] = { 0, 3, 3, 3, 3, 2, 3, 4, 4 };

		imp = x->x;
		lg_call(c, imp, -1, x->site, x->arg, x->nargs, c->pe ? pe_total[imp] : elf_total[imp], depth);
		break;
	}
	case LG_E_CALL:
		lg_call(c, -1, x->x, -1, x->arg, x->nargs, c->p->fn[x->x].nparams, depth);
		break;
	default:
		break;
	}
}

static LA_UNUSED void lg_block(struct lg_cg *c, int blk, int epi);

/* The function's frame is torn down: before a return or a tail jump. */
static LA_UNUSED void lg_teardown(struct lg_cg *c)
{
	if (c->fn_style[c->cur]) {
		if (c->fn_style[c->cur] == 2 || lg_rnd(c->r, 2u)) {      /* (a realigned frame can only be left through the frame pointer) */
			la_mov(&c->a, LA_SP, LA_BP);
		} else {
			la_spadj(&c->a, 0, c->frame);
		}
		la_pop(&c->a, LA_BP);
	} else {
		la_spadj(&c->a, 0, c->frame);
	}
}

static LA_UNUSED void lg_stmt(struct lg_cg *c, int si, int epi)
{
	const struct lg_stmt *s = &c->p->st[si];
	int l_else, l_end, l_top;

	switch (s->kind) {
	case LG_S_ASSIGN:
		lg_expr(c, s->e, 0);
		lg_store_slot(c, s->x, LA_AX);
		break;
	case LG_S_GSTORE:
		lg_expr(c, s->e, 0);
		la_store_sym(&c->a, LG_SYM_G(s->x), LA_AX);
		break;
	case LG_S_FSTORE:
		lg_expr(c, s->e, 0);
		lg_load_slot(c, LA_CX, 0);
		la_store(&c->a, LA_CX, (int32_t)(c->word * s->x), LA_AX);
		break;
	case LG_S_EVAL:
		lg_expr(c, s->e, 0);
		break;
	case LG_S_IF:
		l_else = la_label(&c->a);
		l_end = la_label(&c->a);
		lg_emit_call_target(c, LG_IMP_COND, -1);
		la_test(&c->a, LA_AX);
		la_jcc_label(&c->a, 4, l_else);
		lg_block(c, s->a, epi);
		if (s->b >= 0)
			la_jmp_label(&c->a, l_end);
		la_bind(&c->a, l_else);
		if (s->b >= 0) {
			lg_block(c, s->b, epi);
			la_bind(&c->a, l_end);
		}
		break;
	case LG_S_WHILE:
		l_top = la_label(&c->a);
		l_end = la_label(&c->a);
		la_bind(&c->a, l_top);
		lg_emit_call_target(c, LG_IMP_COND, -1);
		la_test(&c->a, LA_AX);
		la_jcc_label(&c->a, 4, l_end);
		lg_block(c, s->a, epi);
		la_jmp_label(&c->a, l_top);
		la_bind(&c->a, l_end);
		break;
	case LG_S_RET:
		lg_expr(c, s->e, 0);
		la_jmp_label(&c->a, epi);
		break;
	case LG_S_TAIL: {
		const struct lg_expr *x = &c->p->ex[s->e];
		const int callee = x->x;
		/* an i386 tail call keeps its arguments where the function's own are (the callee reads the same words above its return
		 * address), so it takes no more than the function was given and both clean up the same way */
		const int ok = c->wide || x->nargs == 0 ||
			       (x->nargs <= c->p->fn[c->cur].nparams && !c->fn_std[c->cur] && !c->fn_std[callee]);

		if (!ok) {              /* an i386 tail call with stack arguments is a call and a return */
			lg_expr(c, s->e, 0);
			la_jmp_label(&c->a, epi);
		} else {
			/* the arguments are set exactly as for a call, then the frame goes and the jump replaces the call */
			const unsigned *regs = c->win ? lg_regs_win : lg_regs_sysv;
			int tmp[2] = { -1, -1 }, i;

			for (i = 0; i < x->nargs && c->wide; i++)
				if (!lg_is_leaf(c->p, x->arg[i])) {
					tmp[i] = LG_SLOT_T + i;
					lg_expr(c, x->arg[i], 1);
					lg_store_slot(c, tmp[i], LA_AX);
				}
			for (i = 0; i < x->nargs && c->wide; i++) {
				if (tmp[i] >= 0)
					lg_load_slot(c, regs[i], tmp[i]);
				else
					lg_leaf(c, regs[i], x->arg[i]);
			}
			if (!c->wide && x->nargs) {
				/* built first, then written over the incoming arguments, so no argument reads one already replaced */
				for (i = 0; i < x->nargs; i++) {
					lg_expr(c, x->arg[i], 1);
					la_push(&c->a, LA_AX);
					c->pushed += 4;
				}
				for (i = x->nargs - 1; i >= 0; i--) {
					unsigned base;
					int32_t disp;

					la_pop(&c->a, LA_AX);
					c->pushed -= 4;
					lg_param32(c, i, &base, &disp);
					la_store(&c->a, base, disp, LA_AX);
				}
			}
			lg_teardown(c);
			la_jmp_label(&c->a, c->fn_label[callee]);
		}
		break;
	}
	default:
		break;
	}
}

static LA_UNUSED void lg_block(struct lg_cg *c, int blk, int epi)
{
	int i;

	for (i = 0; i < c->p->blk[blk].n; i++)
		lg_stmt(c, c->p->blk[blk].st[i], epi);
}

static LA_UNUSED void lg_function(struct lg_cg *c, int fi)
{
	const struct lg_fn *f = &c->p->fn[fi];
	int epi = la_label(&c->a), i;

	c->cur = fi;
	c->pushed = 0;
	c->frame = (int)(((unsigned)c->word * (unsigned)LG_NSLOT + 15u) & ~15u);
	la_bind(&c->a, c->fn_label[fi]);
	c->fn_off[fi] = c->a.n;
	if (c->fn_style[fi]) {
		la_push(&c->a, LA_BP);
		la_mov(&c->a, LA_BP, LA_SP);
	}
	la_spadj(&c->a, 1, c->frame);
	if (c->fn_style[fi] == 2)
		la_andsp16(&c->a);
	if (c->wide) {
		const unsigned *regs = c->win ? lg_regs_win : lg_regs_sysv;

		for (i = 0; i < f->nparams; i++)
			lg_store_slot(c, LG_SLOT_P + i, regs[i]);
	}
	lg_block(c, f->body, epi);
	if (f->halts) {                 /* no `ret`, no jump out: the function stops */
		la_b(&c->a, 0x0f);
		la_b(&c->a, 0x0b);      /* ud2 */
		la_bind(&c->a, epi);
		c->fn_end[fi] = c->a.n;
		la_align(&c->a, 16);
		return;
	}
	la_zero(&c->a, LA_AX);          /* falling off the end returns nothing */
	if (f->dead >= 0) {
		la_jmp_label(&c->a, epi);
		lg_block(c, f->dead, epi);
	}
	la_bind(&c->a, epi);
	lg_teardown(c);
	if (!c->wide && c->fn_std[fi] && f->nparams)
		la_ret_n(&c->a, (unsigned)(4 * f->nparams));
	else
		la_ret(&c->a);
	c->fn_end[fi] = c->a.n;
	la_align(&c->a, 16);
}

/* Generate the whole program's code. Returns 0 when the assembler ran out of room. */
static LA_UNUSED int lg_codegen(struct lg_cg *c, const struct lg_prog *p, struct lg_rng *r, int target)
{
	int i;

	memset(c->site_off, 0, sizeof c->site_off);
	c->p = p;
	c->r = r;
	c->target = target;
	c->wide = target == LG_T_ELF64 || target == LG_T_PE64;
	c->word = c->wide ? 8 : 4;
	c->pe = target == LG_T_PE64 || target == LG_T_PE32;
	c->win = target == LG_T_PE64;
	c->overflow = 0;
	memset(c->thunk_used, 0, sizeof c->thunk_used);
	la_init(&c->a, c->wide);
	for (i = 0; i < p->nf; i++) {
		c->fn_label[i] = la_label(&c->a);
		c->fn_style[i] = (int)lg_rnd(r, 3u);
		c->fn_std[i] = target == LG_T_PE32 ? (int)lg_rnd(r, 2u) : 0;
	}
	for (i = 0; i < p->nf; i++)
		lg_function(c, i);
	/* the thunks a PE x86 program calls instead of the slot: `jmp [slot]`, after the functions */
	for (i = 1; i < LG_NIMP; i++)
		if (c->thunk_used[i]) {
			la_align(&c->a, 8);
			c->thunk_off[i] = c->a.n;
			la_jmp_slot(&c->a, LG_SYM_SLOT(i));
		}
	return la_resolve_labels(&c->a);
}

#endif /* KGENOME_TESTS_LINEAGE_CG_H */
