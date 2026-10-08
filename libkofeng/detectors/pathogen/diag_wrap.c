/*
 * diag_wrap.c - THE SYSCALL IS INSIDE A LIBRARY FUNCTION, AND THE PROGRAM IS
 * THE CALLERS.
 *
 * A bot built against a static libc does not execute `mov eax,41; syscall` where
 * it opens a socket. It executes `call socket`, and one function somewhere in the
 * binary holds the only `syscall` instruction there is:
 *
 *     socket:  push rbx
 *              movslq edx,rdx ; movslq esi,rsi ; movslq edi,rdi   <- the PARAMETERS
 *              mov eax,0x29
 *              syscall
 *
 * Read at that instruction the arguments are the function's own parameters, so
 * the node said "a socket of an unknown kind", stood in one place for every
 * socket the program makes, and could carry no link to anything - the descriptor
 * it returned goes to eighty call sites, and the arguments of those are the
 * caller's too. MEASURED on 1000 Bazaar Linux bots: 122 of 146 old Mirai had a
 * network node and one of them had a node with any link.
 *
 * SO THE NODES BELONG AT THE CALL SITES, which is where the program says what
 * it is doing, and the function is a SUMMARY that says what a call to it means:
 * which system call, and which of the caller's values become which argument.
 * That is what a relocatable object's imports already are - a name at a call
 * site with a capability - and the same machinery (an origin that is carried from
 * the node that produced a value to the node that takes it) links them.
 *
 *   1. SUMMARISE. Every syscall instruction has an entry: the nearest direct-call
 *      target before it. If the straight line from the entry to the instruction
 *      reaches it without a branch, and the registers the kernel reads are the
 *      function's parameters (possibly moved or widened on the way) or constants,
 *      the function is a wrapper and the summary says which.
 *   2. WALK THE CALLERS, function by function, with a small symbolic state: which
 *      node produced the value in each register, in each stack slot of this frame,
 *      and in each global. A call to a wrapper makes a node at the call, with the
 *      arguments the summary maps from what the caller holds; what it returns is
 *      that node.
 *
 * WHAT THIS DOES NOT CLAIM. The walk is linear in address order and takes no
 * branch, so a value is "carried" when nothing overwrote the place it was kept
 * before the next use - a MAY link, as the rest of the static routes are. A write
 * through a pointer clears nothing. Calls to anything but a wrapper forget the
 * registers a callee may clobber and keep what is on the stack and in globals.
 * x86 and x86-64 only; the stack arguments of cdecl are read, regparm and
 * fastcall are not.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kofdiag.h"
#include "diag_int.h"
#include "../../kofcore/kofcore.h"
#include "../../kofcore/kofmod/kofcap.h"
#include "../../kofcore/kofmod/cell.h"
#include "../../analyzers/parsers/binaries/elf/elf_parse.h"
#include <celllysis/celllysis.h>
#include "../../analyzers/nucleo/nucleo.h"
#include <celllysis/space.h>

/* How far before a syscall its function may begin. MEASURED on 27 sites in 25
 * static i386 bots, 33 bytes; glibc's wrappers with a cancellation check are
 * longer and are not summarised (they branch). A cost bound on a guess. */
#define W_SPAN   256u
/* Instructions from an entry to its syscall. A wrapper is a handful. */
#define W_BODY    48u
/* Stack slots remembered for one function. A frame that keeps more distinct
 * descriptors alive than this loses the oldest, which is a missed link. */
#define W_SLOTS  192u
/* Levels above the syscall are searched over every call target; past this many
 * targets (a 10 MB runtime) the search is not worth its cost and is not made. */
#define W_LEVELS_MAX_TGT 20000u

enum { V_UNK = 0, V_CONST, V_NODE, V_SADDR, V_PARAM, V_SET };

struct sv {
	uint8_t  t;
	uint16_t node;          /* V_NODE */
	int64_t  v;             /* V_CONST value, V_SADDR canonical offset, V_PARAM index,
				 * V_SET the bits known to be set (the rest unknown) */
};

static const struct sv UNK = { V_UNK, 0, 0 };

struct slot {
	int32_t   off;
	struct sv v;
};

/* The symbolic state of ONE function. */
struct fstate {
	struct sv reg[16];
	int32_t   sp;           /* bytes pushed since entry */
	int       bp_known;
	int32_t   bp_off;       /* canonical offset the frame pointer holds */
	struct slot slot[W_SLOTS];
	uint32_t  n_slot, next;
};

/* 4096 bits: a function-pointer table's worth of distinct globals read before
 * they are written is the realistic ceiling, and a full table only means the
 * second round runs, as it always did. */
#define GMISS_WORDS 64u
#define GMISS_BIT(a) ((unsigned)(((a) * 0x9e3779b97f4a7c15ull) >> 52) & 4095u)

/* One global that holds the result of a node. */
struct glob {
	uint64_t addr;
	struct sv v;
};

/* What a wrapper is. */
struct wsum {
	uint64_t entry, site;   /* file offsets; `site` is the syscall, or the call to an inner wrapper */
	struct sv nr;           /* V_CONST or V_PARAM */
	struct sv arg[6];       /* the kernel's arguments, in kernel order */
	/* i386 socketcall: the arguments of the OPERATION, which live in an array
	 * the wrapper (or the function around it) builds on its stack. */
	int      has_arr;
	struct sv arr[6];
	int      node_made;     /* a call-site node was made for it */
};

/* What a call to a wrapper means at one call site, in the caller's values. */
struct ev {
	struct sv nr;
	struct sv arg[6];
	int       has_arr;
	struct sv arr[6];
};

struct wctx {
	struct kof_diag_scan *s;
	const struct kof_obj_ctx *ctx;
	const uint8_t *base;
	uint64_t size;
	struct cell_space sp;           /* the object's code, as celllysis reads it */
	int wide;                       /* x86-64 */
	int w;                          /* the machine word, 4 or 8 */
	uint64_t *tgt;                  /* sorted unique direct-call targets */
	uint32_t n_tgt, cap_tgt;
	uint64_t *site;                 /* syscall instruction offsets */
	uint32_t n_site, cap_site;
	uint32_t *fret;                 /* per call target: the node + 1 its AX holds at ret */
	uint8_t  *fmiss;                /* per call target: a call asked before it was set */
	/*
	 * THE CODE, DECODED ONCE. pass_a reads every instruction of every
	 * executable segment to find the call targets and the syscall sites, and
	 * pass_b then reads the same instructions again - twice, when a global
	 * is read before it is written. Each read was a full decode, so the same
	 * bytes were decoded up to three times per scan. The first one keeps what
	 * it saw and the others walk that. See struct isrc.
	 */
	struct cell_insn *tr;
	uint32_t n_tr, cap_tr;
	struct { uint32_t first, n; uint8_t ok; } tseg[KOF_ELF_MAX_SEGMENTS];
	uint64_t *open;                 /* sites whose NUMBER the sweep could not read */
	uint32_t n_open, cap_open;
	struct wsum *ws;                /* the wrappers, by entry */
	uint32_t n_ws, cap_ws;
	struct glob *glob;
	uint32_t n_glob, cap_glob;
	/*
	 * WHETHER A SECOND WALK CAN SEE ANYTHING THE FIRST DID NOT - see the note
	 * at the two rounds in kof_diag_run_wrappers. A global read before the
	 * walk had put anything there sets its bit in `gmiss` (hashed, so a
	 * collision costs a needless second round and never a missed one); a
	 * global entry CREATED while its bit is set is the one case in which the
	 * second round differs.
	 */
	uint64_t gmiss[GMISS_WORDS];
	int      need_round2;
};

/* ---- the symbolic state ------------------------------------------------- */

static void st_reset(struct fstate *f)
{
	memset(f, 0, sizeof *f);
}

static struct slot *slot_find(struct fstate *f, int32_t off)
{
	uint32_t i;

	for (i = 0; i < f->n_slot; i++)
		if (f->slot[i].off == off)
			return &f->slot[i];
	return NULL;
}

static void slot_put(struct fstate *f, int32_t off, struct sv v)
{
	struct slot *p = slot_find(f, off);

	if (p) {
		p->v = v;
		return;
	}
	if (v.t == V_UNK)
		return;                 /* nothing to remember */
	if (f->n_slot < W_SLOTS) {
		f->slot[f->n_slot].off = off;
		f->slot[f->n_slot++].v = v;
		return;
	}
	f->slot[f->next].off = off;
	f->slot[f->next].v = v;
	f->next = (f->next + 1u) % W_SLOTS;
}

static struct sv slot_get(struct fstate *f, int32_t off)
{
	struct slot *p = slot_find(f, off);

	return p ? p->v : UNK;
}

static struct glob *glob_find(struct wctx *c, uint64_t addr)
{
	uint32_t i;

	for (i = 0; i < c->n_glob; i++)
		if (c->glob[i].addr == addr)
			return &c->glob[i];
	return NULL;
}

static void glob_put(struct wctx *c, uint64_t addr, struct sv v)
{
	struct glob *g = glob_find(c, addr);

	if (g) {
		g->v = v;
		return;
	}
	if (v.t != V_NODE)
		return;                 /* only a produced value is worth a global */
	if (c->gmiss[GMISS_BIT(addr) >> 6] & (1ull << (GMISS_BIT(addr) & 63u)))
		c->need_round2 = 1;     /* it was read before it existed */
	if (c->n_glob == c->cap_glob) {
		uint32_t nc = c->cap_glob ? c->cap_glob * 2u : 64u;
		struct glob *ng = realloc(c->glob, (size_t)nc * sizeof *ng);

		if (!ng)
			return;
		c->glob = ng;
		c->cap_glob = nc;
	}
	c->glob[c->n_glob].addr = addr;
	c->glob[c->n_glob++].v = v;
}

/* Where a memory operand is, in a space the walk can name: the frame (a
 * canonical offset from the function's entry stack pointer) or a global (an
 * address). 0 = somewhere else, which neither reads nor invalidates. */
enum { LOC_NONE = 0, LOC_STACK, LOC_GLOBAL };

static int mem_loc(const struct wctx *c, const struct fstate *f,
		   const struct cell_insn *in, const struct cell_operand *o,
		   int64_t *key)
{
	if (o->kind != CELL_O_MEM || o->index != CELL_REG_NONE)
		return LOC_NONE;
	if (o->seg != CELL_REG_NONE && o->seg != CELL_SEG_DS &&
	    o->seg != CELL_SEG_SS)
		return LOC_NONE;        /* fs: and gs: are thread data */
	if (o->flags & CELL_OF_RIPREL) {
		if (in->at_va == KOF_BROKEN)
			return LOC_NONE;
		*key = (int64_t)(in->at_va + in->len) + o->disp;
		return LOC_GLOBAL;
	}
	if (o->reg == CELL_REG_NONE) {
		*key = o->disp & (c->wide ? -1ll : 0xffffffffll);
		return LOC_GLOBAL;
	}
	if (o->reg == CELL_REG_SP) {
		*key = -(int64_t)f->sp + o->disp;
		return LOC_STACK;
	}
	if (o->reg == CELL_REG_BP && f->bp_known) {
		*key = (int64_t)f->bp_off + o->disp;
		return LOC_STACK;
	}
	/*
	 * ANY REGISTER THAT HOLDS A STACK ADDRESS names a frame slot the same way sp
	 * does. A variadic function spills its register arguments into a save area
	 * and reads them back through a pointer into it - `lea 0x20(%rsp),%rax;
	 * add $0x10,%rax; mov (%rax),%rdx` is how fcntl, open and ioctl fetch their
	 * third argument - so before this the F_SETFL flags were stored and then
	 * read from "somewhere else", and no fcntl node on x86-64 carried a flag.
	 */
	if (o->reg < 16u && f->reg[o->reg].t == V_SADDR) {
		*key = f->reg[o->reg].v + o->disp;
		return LOC_STACK;
	}
	return LOC_NONE;
}

static struct sv load(struct wctx *c, struct fstate *f,
		      const struct cell_insn *in, const struct cell_operand *o)
{
	int64_t key;

	switch (o->kind) {
	case CELL_O_REG:
		if (o->reg >= 16u || o->size < 4u)
			return UNK;
		return f->reg[o->reg];
	case CELL_O_IMM: {
		struct sv v = { V_CONST, 0, (int64_t)o->imm };

		return v;
	}
	case CELL_O_MEM:
		if (o->size < 4u)
			return UNK;
		switch (mem_loc(c, f, in, o, &key)) {
		case LOC_STACK:
			return slot_get(f, (int32_t)key);
		case LOC_GLOBAL: {
			struct glob *g = glob_find(c, (uint64_t)key);

			if (!g)
				c->gmiss[GMISS_BIT((uint64_t)key) >> 6] |=
					1ull << (GMISS_BIT((uint64_t)key) & 63u);
			return g ? g->v : UNK;
		}
		default:
			return UNK;
		}
	default:
		return UNK;
	}
}

static void store(struct wctx *c, struct fstate *f, const struct cell_insn *in,
		  const struct cell_operand *o, struct sv v)
{
	int64_t key;

	if (o->kind == CELL_O_REG) {
		if (o->reg < 16u)
			f->reg[o->reg] = o->size >= 4u ? v : UNK;
		return;
	}
	if (o->kind != CELL_O_MEM)
		return;
	if (o->size < 4u)
		v = UNK;
	switch (mem_loc(c, f, in, o, &key)) {
	case LOC_STACK:
		slot_put(f, (int32_t)key, v);
		break;
	case LOC_GLOBAL:
		glob_put(c, (uint64_t)key, v);
		break;
	default:
		break;
	}
}

/* ---- one instruction ------------------------------------------------------ */

/*
 * The effect of an instruction that is NOT a call on the symbolic state. A
 * handful of shapes are followed exactly - the moves, the widening, the stack
 * pointer - and everything else forgets what it writes, which is the honest
 * default: a register that was rewritten holds nothing this walk can name.
 */
static void st_step(struct wctx *c, struct fstate *f, const struct cell_insn *in)
{
	const struct cell_operand *d = &in->o[0], *s = &in->o[1];
	int w = c->w;
	uint32_t r;

	switch (in->op) {
	case CELL_NOP:
		return;
	case CELL_MOV:
		if (in->n_op >= 2u) {
			struct sv v = load(c, f, in, s);

			/* mov bp,sp: the frame pointer now names this frame. */
			if (d->kind == CELL_O_REG && d->reg == CELL_REG_BP &&
			    s->kind == CELL_O_REG && s->reg == CELL_REG_SP) {
				f->bp_known = 1;
				f->bp_off = -f->sp;
				f->reg[CELL_REG_BP].t = V_SADDR;
				f->reg[CELL_REG_BP].v = -f->sp;
				return;
			}
			/* A copy of the stack pointer is a stack ADDRESS. */
			if (d->kind == CELL_O_REG && s->kind == CELL_O_REG &&
			    s->reg == CELL_REG_SP && d->size >= 4u && d->reg < 16u) {
				f->reg[d->reg].t = V_SADDR;
				f->reg[d->reg].v = -f->sp;
				f->reg[d->reg].node = 0;
				return;
			}
			store(c, f, in, d, v);
			return;
		}
		break;
	case CELL_MOVSX:
	case CELL_MOVZX:
	case CELL_WIDEN:
		/* A 32-bit value widened to 64 is the same value as far as a
		 * handle or a parameter is concerned (movslq edx,rdx). */
		if (in->n_op >= 2u && d->kind == CELL_O_REG &&
		    s->kind == CELL_O_REG && s->size >= 4u && d->reg < 16u &&
		    s->reg < 16u) {
			f->reg[d->reg] = f->reg[s->reg];
			return;
		}
		if (in->op == CELL_WIDEN)
			return;         /* cdqe in place */
		break;
	case CELL_XCHG:
		if (in->n_op >= 2u && d->kind == CELL_O_REG &&
		    s->kind == CELL_O_REG && d->reg < 16u && s->reg < 16u) {
			struct sv t = f->reg[d->reg];

			f->reg[d->reg] = f->reg[s->reg];
			f->reg[s->reg] = t;
			return;
		}
		break;
	case CELL_LEA:
		if (in->n_op >= 2u && d->kind == CELL_O_REG && d->reg < 16u &&
		    s->kind == CELL_O_MEM && s->index == CELL_REG_NONE &&
		    !(s->flags & CELL_OF_RIPREL)) {
			if (s->reg == CELL_REG_SP) {
				f->reg[d->reg].t = V_SADDR;
				f->reg[d->reg].v = -(int64_t)f->sp + s->disp;
				f->reg[d->reg].node = 0;
				if (d->reg == CELL_REG_BP) {
					f->bp_known = 1;
					f->bp_off = (int32_t)f->reg[d->reg].v;
				}
				return;
			}
			if (s->reg == CELL_REG_BP && f->bp_known) {
				f->reg[d->reg].t = V_SADDR;
				f->reg[d->reg].v = (int64_t)f->bp_off + s->disp;
				f->reg[d->reg].node = 0;
				return;
			}
		}
		break;
	case CELL_XOR:
		if (in->n_op >= 2u && d->kind == CELL_O_REG && s->kind == CELL_O_REG &&
		    d->reg == s->reg && d->reg < 16u) {
			f->reg[d->reg].t = V_CONST;
			f->reg[d->reg].v = 0;
			f->reg[d->reg].node = 0;
			return;
		}
		break;
	case CELL_PUSH:
		if (in->n_op >= 1u) {
			struct sv v = load(c, f, in, d);

			f->sp += w;
			slot_put(f, -f->sp, v);
		}
		return;
	case CELL_POP:
		if (in->n_op >= 1u && d->kind == CELL_O_REG && d->reg < 16u)
			f->reg[d->reg] = slot_get(f, -f->sp);
		f->sp -= w;
		return;
	case CELL_ADD:
	case CELL_SUB:
		if (in->n_op >= 2u && d->kind == CELL_O_REG &&
		    d->reg == CELL_REG_SP && s->kind == CELL_O_IMM) {
			f->sp += in->op == CELL_SUB ? (int32_t)s->imm
						    : -(int32_t)s->imm;
			return;
		}
		/* A stack address moved by a constant is another stack address. */
		if (in->n_op >= 2u && d->kind == CELL_O_REG && d->reg < 16u &&
		    d->size >= 4u && s->kind == CELL_O_IMM &&
		    f->reg[d->reg].t == V_SADDR) {
			f->reg[d->reg].v += in->op == CELL_SUB ? -(int64_t)(int32_t)s->imm
							       : (int64_t)(int32_t)s->imm;
			return;
		}
		break;
	case CELL_OR:
		/*
		 * `flags | O_NONBLOCK`, where flags is whatever F_GETFL returned.
		 * The result is not a number, but it is a number with a bit that is
		 * certainly set, and that bit is the claim fcntl(F_SETFL) is read
		 * for. gcc writes the 0x800 as `or ah, 8` (80 cc 08): 80 of 95
		 * samples with an OR of that bit in the 146-sample mirai x86 set
		 * use that form, which a model that reads only 4-byte operands
		 * never sees.
		 */
		if (in->n_op >= 2u && d->kind == CELL_O_REG && d->reg < 16u &&
		    s->kind == CELL_O_IMM && d->size != 2u) {
			uint64_t bit = (uint64_t)s->imm;
			struct sv *rv = &f->reg[d->reg];

			if (d->size == 1u) {
				bit &= 0xffu;
				if (d->flags & CELL_OF_HIGH8)
					bit <<= 8;
			}
			if (rv->t == V_CONST) {
				rv->v |= (int64_t)bit;
			} else {
				int64_t keep = rv->t == V_SET ? rv->v : 0;

				rv->t = V_SET;
				rv->node = 0;
				rv->v = keep | (int64_t)bit;
			}
			return;
		}
		break;
	case CELL_RET:
		st_reset(f);
		return;
	case CELL_CMP:
	case CELL_TEST:
	case CELL_JCC:
	case CELL_JMP:
		return;                 /* nothing written; the walk is linear */
	default:
		break;
	}
	/* Anything else forgets what it wrote. */
	for (r = 0; r < 16u; r++)
		if (in->wmask & (1ull << r)) {
			if (r == CELL_REG_SP)
				continue;
			f->reg[r] = UNK;
		}
	{
		int64_t key;

		if (in->n_op && in->o[0].kind == CELL_O_MEM &&
		    (in->o[0].flags & CELL_OF_WRITE)) {
			switch (mem_loc(c, f, in, &in->o[0], &key)) {
			case LOC_STACK:
				slot_put(f, (int32_t)key, UNK);
				break;
			case LOC_GLOBAL:
				glob_put(c, (uint64_t)key, UNK);
				break;
			default:
				break;
			}
		}
	}
}

/* What a call to something the walk does not summarise leaves behind: the
 * registers the callee may use are gone, the frame and the globals are not. */
static void st_call_unknown(struct wctx *c, struct fstate *f)
{
	static const uint8_t cs64[] = { 0, 1, 2, 6, 7, 8, 9, 10, 11 };
	static const uint8_t cs32[] = { 0, 1, 2 };
	const uint8_t *cs = c->wide ? cs64 : cs32;
	uint32_t n = c->wide ? (uint32_t)sizeof cs64 : (uint32_t)sizeof cs32, i;

	for (i = 0; i < n; i++)
		f->reg[cs[i]] = UNK;
}

/* ---- pass A: call targets and syscall sites -------------------------------- */

static int u64_cmp(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

static int push_u64(uint64_t **v, uint32_t *n, uint32_t *cap, uint64_t x)
{
	if (*n == *cap) {
		uint32_t nc = *cap ? *cap * 2u : 256u;
		uint64_t *nv = realloc(*v, (size_t)nc * sizeof **v);

		if (!nv)
			return 0;
		*v = nv;
		*cap = nc;
	}
	(*v)[(*n)++] = x;
	return 1;
}

static int is_kernel_entry(const struct wctx *c, const struct cell_insn *in)
{
	const uint8_t *p = c->base + in->at;

	if (in->op == CELL_SYSCALL)
		return p[0] == 0x0fu && p[1] == 0x05u ? c->wide : !c->wide;
	if (in->op == CELL_INT && in->n_op && in->o[0].kind == CELL_O_IMM &&
	    in->o[0].imm == 0x80u)
		return 1;
	return 0;
}

/*
 * ---- ONE STREAM OF INSTRUCTIONS, WHEREVER IT COMES FROM ----------------------
 *
 * A segment's instructions are either walked out of the trace the first pass
 * kept or decoded as before, and the caller cannot tell which: it asks for the
 * next one. THE TRACE IS A CACHE, NOT A SECOND WALK - it holds exactly what
 * decoding would have returned, in the same order, resynchronising over the same
 * bytes, so a segment whose trace is complete is read from memory and one whose
 * trace is not (it outgrew W_TRACE_MAX) is decoded again, with the same result.
 *
 * THE BOUND IS ON MEMORY, NOT ON WHAT IS FOUND. An instruction is a hundred and
 * twenty bytes, so W_TRACE_MAX of them is a fixed ~30 MB however large the image;
 * past it nothing is dropped from the analysis, only from the cache.
 */
#define W_TRACE_MAX 262144u

struct isrc {
	struct wctx *c;
	const struct cell_insn *tr;     /* the cached stream, or NULL */
	uint32_t i, n;
	struct kof_cell_cur k;
	uint64_t end;
};

static int isrc_open(struct isrc *it, struct wctx *c, unsigned seg,
		     uint64_t off, uint64_t n)
{
	memset(it, 0, sizeof *it);
	it->c = c;
	it->end = off + n;
	if (c->tseg[seg].ok) {
		it->tr = c->tr + c->tseg[seg].first;
		it->n = c->tseg[seg].n;
		return 1;
	}
	return kof_cell_seek(&it->k, off, 0);
}

static int isrc_next(struct isrc *it, struct cell_insn *in)
{
	if (it->tr) {
		if (it->i >= it->n)
			return 0;
		*in = it->tr[it->i++];
		return 1;
	}
	while (it->k.at < it->end) {
		if (kof_cell_step(&it->k, &it->c->sp, in))
			return 1;
		it->k.at++;                     /* data in the code: step over it */
	}
	return 0;
}

/* Keep what pass_a saw. Once the cache is full it stays full: a segment that
 * did not fit whole is not cached at all, so a trace is never a prefix. */
static void trace_add(struct wctx *c, unsigned seg, const struct cell_insn *in)
{
	if (!c->tseg[seg].first && !c->tseg[seg].n)
		c->tseg[seg].first = c->n_tr;
	if (c->tseg[seg].ok == 2u)              /* already given up */
		return;
	if (c->n_tr == c->cap_tr) {
		uint32_t nc = c->cap_tr ? c->cap_tr * 2u : 4096u;
		struct cell_insn *nt;

		if (nc > W_TRACE_MAX)
			nc = W_TRACE_MAX;
		if (c->n_tr >= nc ||
		    !(nt = realloc(c->tr, (size_t)nc * sizeof *nt))) {
			c->tseg[seg].ok = 2u;
			return;
		}
		c->tr = nt;
		c->cap_tr = nc;
	}
	c->tr[c->n_tr++] = *in;
	c->tseg[seg].n++;
}

static int pass_a(struct wctx *c, unsigned seg, uint64_t off, uint64_t n)
{
	struct kof_cell_cur k;
	struct cell_insn in;

	/* Whether the instruction before ended a function's straight line. */
	int boundary = 1;

	memset(&k, 0, sizeof k);
	if (!kof_cell_seek(&k, off, 0))
		return 1;
	while (k.at < off + n) {
		if (!kof_cell_step(&k, &c->sp, &in)) {
			k.at++;                 /* data in the code: step over it */
			continue;
		}
		trace_add(c, seg, &in);
		if (in.op == CELL_CALL && !(in.flags & CELL_F_INDIRECT) &&
		    in.target != KOF_BROKEN) {
			if (!push_u64(&c->tgt, &c->n_tgt, &c->cap_tgt, in.target))
				return 0;
		} else if (in.op == CELL_JMP && !(in.flags & CELL_F_INDIRECT) &&
			   in.target != KOF_BROKEN && boundary) {
			/*
			 * A THUNK: `jmp X` as the first instruction of a function
			 * makes X an entry, though nothing CALLS it. musl keeps its
			 * generic syscall(nr, a1..a6) at X and gives the cancellable
			 * wrappers a one-instruction stub that jumps to it - sendto
			 * and connect both enter there, and with X not an entry the
			 * syscall inside it was attributed to no function and every
			 * socket send of the program was lost. Found by reading the
			 * 79 x86-64 Bazaar files that had a raw socket and no send.
			 */
			if (!push_u64(&c->tgt, &c->n_tgt, &c->cap_tgt, in.target))
				return 0;
		} else if (is_kernel_entry(c, &in)) {
			if (!push_u64(&c->site, &c->n_site, &c->cap_site, in.at))
				return 0;
		}
		boundary = in.op == CELL_RET || in.op == CELL_JMP ||
			   in.op == CELL_NOP;
	}
	/* Complete only if nothing was refused on the way. */
	c->tseg[seg].ok = c->tseg[seg].ok == 2u ? 0u : 1u;
	return 1;
}

static struct sv call_param(const struct wctx *c, struct fstate *f, unsigned i);
static void eval_call(const struct wctx *c, struct fstate *f,
		      const struct wsum *ws, struct ev *e);
static struct wsum *wsum_of(struct wctx *c, uint64_t entry);

/* ---- summarise one wrapper ------------------------------------------------- */

/* Parameter numbers from here up are registers, not stack slots. */
#define W_REG_PARAM 16u
#define W_VARIANTS 4u
#define W_PENDING  6u

static int site_open(const struct wctx *c, uint64_t at)
{
	uint32_t lo = 0, hi = c->n_open;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->open[mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->n_open && c->open[lo] == at;
}

/* One path through a wrapper that ended in a syscall or a call to a wrapper,
 * turned into a summary. 1 when it says something about the parameters. */
static int summarise_end(struct wctx *c, struct fstate *f, uint64_t entry,
			 const struct cell_insn *in, struct wsum *callee,
			 struct wsum *out)
{
	static const uint8_t k64[] = { CELL_REG_DI, CELL_REG_SI, CELL_REG_DX,
				       10u, 8u, 9u };
	static const uint8_t k32[] = { CELL_REG_BX, CELL_REG_CX, CELL_REG_DX,
				       CELL_REG_SI, CELL_REG_DI, CELL_REG_BP };
	const uint8_t *kr = c->wide ? k64 : k32;
	int any_param = 0;
	unsigned i;

	memset(out, 0, sizeof *out);
	out->entry = entry;
	out->site = in->at;
	if (!callee) {
		out->nr = f->reg[CELL_REG_AX];
		for (i = 0; i < 6; i++) {
			out->arg[i] = f->reg[kr[i]];
			if (out->arg[i].t != V_CONST && out->arg[i].t != V_PARAM &&
			    out->arg[i].t != V_SET)
				out->arg[i] = UNK;
			if (out->arg[i].t == V_PARAM)
				any_param = 1;
		}
	} else {
		struct ev e;

		eval_call(c, f, callee, &e);
		out->nr = e.nr;
		for (i = 0; i < 6; i++) {
			out->arg[i] = e.arg[i];
			if (out->arg[i].t != V_CONST && out->arg[i].t != V_PARAM &&
			    out->arg[i].t != V_SET)
				out->arg[i] = UNK;
			if (out->arg[i].t == V_PARAM)
				any_param = 1;
		}
		out->has_arr = e.has_arr;
		for (i = 0; i < 6 && e.has_arr; i++) {
			out->arr[i] = e.arr[i];
			if (out->arr[i].t != V_CONST && out->arr[i].t != V_PARAM)
				out->arr[i] = UNK;
			if (out->arr[i].t == V_PARAM)
				any_param = 1;
		}
	}
	if (out->nr.t != V_CONST && out->nr.t != V_PARAM)
		return 0;
	if (out->nr.t == V_PARAM)
		any_param = 1;
	/*
	 * A REGISTER PARAMETER (the number or an argument) is believed only where
	 * the sweep itself could not read the number. Held to every function, it
	 * accepted every syscall site that a mis-partitioned fragment reaches with
	 * the registers untouched, and made each call of the fragment a node:
	 * MEASURED on one x86 file, 40 -> 206 write nodes and the connect nodes
	 * gone. A real register-convention helper (musl's __vsyscall) is exactly
	 * the site the sweep reports as opaque.
	 */
	if (!callee && !site_open(c, in->at)) {
		if (out->nr.t == V_PARAM && out->nr.v >= (int64_t)W_REG_PARAM)
			return 0;
		/* An argument register nobody set is not a parameter either. */
		any_param = out->nr.t == V_PARAM;
		for (i = 0; i < 6; i++) {
			if (out->arg[i].t == V_PARAM &&
			    out->arg[i].v >= (int64_t)W_REG_PARAM)
				out->arg[i] = UNK;
			if (out->arg[i].t == V_PARAM)
				any_param = 1;
		}
	}
	return any_param;
}

/*
 * What the function that begins at `entry` is, if it is a wrapper: a path that
 * ends in a kernel entry (a level-0 wrapper, the one that holds the syscall) or
 * in a call to a wrapper already summarised (a wrapper of a wrapper - uClibc's
 * socket() is `build the array; call __socketcall(1, array)`). Both ends are the
 * same question - what does this mean in terms of MY parameters - so both are
 * answered by evaluating the state where the path ends.
 *
 * MORE THAN ONE PATH, because a wrapper branches on what it was asked: uClibc's
 * fcntl takes fcntl64 for the three commands that need it and fcntl for the
 * rest, and both are summarised. The paths here are forward conditional jumps
 * inside the function and nothing else; each gives a variant, and a call is
 * evaluated against every variant - so a call whose command is not known makes
 * the node either path would have made, and the nodes merge when they agree.
 */
static unsigned summarise(struct wctx *c, uint64_t entry, struct wsum *out)
{
	static const uint8_t p64[] = { CELL_REG_DI, CELL_REG_SI, CELL_REG_DX,
				       CELL_REG_CX, 8u, 9u };
	static const uint8_t pr32[] = { CELL_REG_AX, CELL_REG_CX, CELL_REG_DX,
					CELL_REG_BX, CELL_REG_SI, CELL_REG_DI,
					CELL_REG_BP };
	struct pend { struct fstate f; uint64_t at; unsigned n; } *pend;
	unsigned n_pend = 0, n_out = 0, i;

	pend = malloc(W_PENDING * sizeof *pend);
	if (!pend)
		return 0;
	st_reset(&pend[0].f);
	if (c->wide) {
		for (i = 0; i < 6; i++) {
			pend[0].f.reg[p64[i]].t = V_PARAM;
			pend[0].f.reg[p64[i]].v = i;
		}
	} else {
		/* cdecl: the return address is at offset 0 and the arguments above it */
		for (i = 0; i < 8; i++) {
			struct sv v = { V_PARAM, 0, (int64_t)i };

			slot_put(&pend[0].f, (int32_t)(4u + 4u * i), v);
		}
		/*
		 * AND THE REGISTERS, because i386 has no register convention that a
		 * libc is obliged to keep: musl's __vsyscall takes the number in eax
		 * and the arguments in edx, ecx and edi, and enters the kernel from a
		 * helper it reaches with a `call` to the middle of itself. A register
		 * parameter is numbered W_REG_PARAM + register, so a call site can say
		 * which of its own registers it means. MEASURED: 31 of the 400 x86
		 * Bazaar files had no node but one opaque site, all through this helper.
		 */
		for (i = 0; i < sizeof pr32; i++) {
			pend[0].f.reg[pr32[i]].t = V_PARAM;
			pend[0].f.reg[pr32[i]].v = (int64_t)(W_REG_PARAM + pr32[i]);
		}
	}
	pend[0].at = entry;
	pend[0].n = 0;
	n_pend = 1;
	while (n_pend && n_out < W_VARIANTS) {
		struct pend *p = &pend[--n_pend];
		struct kof_cell_cur k;
		struct cell_insn in;
		/*
		 * A COPY, not the table's own entry. The entry that was just taken is
		 * the very slot the next forward branch queues its taken path into, so
		 * walking it in place made the queued path inherit what the fall-through
		 * had since done to the state (musl's __vsyscall: the path that enters
		 * the kernel was evaluated with the stack the other path had pushed
		 * onto, and its number came out unknown).
		 */
		struct fstate fcur = p->f;
		struct fstate *f = &fcur;
		unsigned n_insn = p->n;

		memset(&k, 0, sizeof k);
		if (!kof_cell_seek(&k, p->at, 0))
			continue;
		for (;;) {
			struct wsum *callee = NULL;
			uint32_t v;
			int ended = 0;

			if (++n_insn > W_BODY)
				break;
			if (!kof_cell_step(&k, &c->sp, &in))
				break;
			/* A direct jump to a function already summarised is a TAIL
			 * CALL: the same question as a call that is followed by ret. */
			if ((in.op == CELL_CALL || in.op == CELL_JMP) &&
			    !(in.flags & CELL_F_INDIRECT) && in.target != KOF_BROKEN)
				callee = wsum_of(c, in.target);
			if (is_kernel_entry(c, &in)) {
				if (summarise_end(c, f, entry, &in, NULL, &out[n_out]))
					n_out++;
				break;
			}
			if (callee) {
				uint32_t base = (uint32_t)(callee - c->ws);

				/* A jump leaves the return address where it was, so on a
				 * stack-passed ABI the callee's arguments are one word
				 * further up than they are for a call. */
				if (in.op == CELL_JMP && !c->wide)
					f->sp -= c->w;

				for (v = base; v < c->n_ws && n_out < W_VARIANTS &&
					       c->ws[v].entry == c->ws[base].entry; v++)
					if (summarise_end(c, f, entry, &in, &c->ws[v],
							  &out[n_out]))
						n_out++;
				ended = 1;
			}
			if (ended)
				break;
			/*
			 * A CALL TO SOMETHING THAT IS NOT A WRAPPER does not end the walk:
			 * it clobbers the caller-saved registers and leaves the frame as it
			 * was. uClibc's fcntl brackets the real call with
			 * pthread_setcancelstate(1, ..) ... (0, ..), and stopping at the
			 * first of them summarised no fcntl at all - 84 of 86 x86 Bazaar
			 * files that set O_NONBLOCK produced no node for it.
			 */
			if (in.op == CELL_CALL) {
				st_call_unknown(c, f);
				continue;
			}
			if (in.op == CELL_JCC && in.target != KOF_BROKEN &&
			    in.target > in.at && in.target - entry <= W_SPAN &&
			    n_pend < W_PENDING) {
				/* the taken path, later; this one carries on */
				pend[n_pend].f = *f;
				pend[n_pend].at = in.target;
				pend[n_pend].n = n_insn;
				n_pend++;
				continue;
			}
			if (in.op == CELL_JMP && !(in.flags & CELL_F_INDIRECT) &&
			    in.target != KOF_BROKEN && in.target > in.at &&
			    in.target - entry <= W_SPAN) {
				if (!kof_cell_seek(&k, in.target, 0))
					break;
				continue;
			}
			/* a call to something else, a return, a jump out: not this path */
			if (in.op == CELL_CALL || in.op == CELL_JMP || in.op == CELL_JCC ||
			    in.op == CELL_RET || in.op == CELL_LOOP)
				break;
			st_step(c, f, &in);
		}
	}
	free(pend);
	return n_out;
}

/* Keeps the table sorted by entry as it grows, so the lookup above is valid at
 * every moment - the level search consults it while it is being extended. */
static int ws_insert(struct wctx *c, const struct wsum *t)
{
	uint32_t lo = 0, hi = c->n_ws;

	if (c->n_ws == c->cap_ws) {
		uint32_t nc = c->cap_ws ? c->cap_ws * 2u : 32u;
		struct wsum *nw = realloc(c->ws, (size_t)nc * sizeof *nw);

		if (!nw)
			return 0;
		c->ws = nw;
		c->cap_ws = nc;
	}
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->ws[mid].entry < t->entry)
			lo = mid + 1u;
		else
			hi = mid;
	}
	memmove(&c->ws[lo + 1u], &c->ws[lo], (size_t)(c->n_ws - lo) * sizeof *c->ws);
	c->ws[lo] = *t;
	c->n_ws++;
	return 1;
}

static struct wsum *wsum_of(struct wctx *c, uint64_t entry)
{
	uint32_t lo = 0, hi = c->n_ws;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->ws[mid].entry < entry)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->n_ws && c->ws[lo].entry == entry ? &c->ws[lo] : NULL;
}

/* The nearest call target at or before `site`, within W_SPAN. */
static int entry_of(const struct wctx *c, uint64_t site, uint64_t *entry)
{
	uint32_t lo = 0, hi = c->n_tgt;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->tgt[mid] <= site)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (!lo || site - c->tgt[lo - 1u] > W_SPAN)
		return 0;
	*entry = c->tgt[lo - 1u];
	return 1;
}

/* ---- the node a call to a wrapper makes ----------------------------------- */

/* The i-th integer parameter of a call, as the caller holds it. */
static struct sv call_param(const struct wctx *c, struct fstate *f, unsigned i)
{
	static const uint8_t p64[] = { CELL_REG_DI, CELL_REG_SI, CELL_REG_DX,
				       CELL_REG_CX, 8u, 9u };

	if (i >= W_REG_PARAM)
		return i - W_REG_PARAM < 16u ? f->reg[i - W_REG_PARAM] : UNK;
	if (c->wide)
		return i < 6u ? f->reg[p64[i]] : UNK;
	/* cdecl: the last value pushed is the first argument. At the call the
	 * stack pointer has not yet taken the return address, so argument i is
	 * i words above the top. */
	return slot_get(f, -f->sp + (int32_t)(4u * i));
}

/* The value of the j-th argument of a socketcall, read from the array the
 * caller built on its stack. */
static struct sv sockcall_arg(const struct wctx *c, struct fstate *f,
			      struct sv ptr, unsigned j)
{
	(void)c;
	if (ptr.t != V_SADDR)
		return UNK;
	return slot_get(f, (int32_t)(ptr.v + 4 * (int64_t)j));
}

/* The wrapper's summary evaluated against the caller's state. */
static void eval_call(const struct wctx *c, struct fstate *f,
		      const struct wsum *ws, struct ev *e)
{
	unsigned i;

	e->nr = ws->nr.t == V_PARAM ? call_param(c, f, (unsigned)ws->nr.v) : ws->nr;
	for (i = 0; i < 6u; i++) {
		struct sv v = ws->arg[i];

		e->arg[i] = v.t == V_PARAM ? call_param(c, f, (unsigned)v.v) : v;
	}
	e->has_arr = 0;
	if (ws->has_arr) {
		e->has_arr = 1;
		for (i = 0; i < 6u; i++) {
			struct sv v = ws->arr[i];

			e->arr[i] = v.t == V_PARAM ? call_param(c, f, (unsigned)v.v) : v;
		}
	} else if (!c->wide && e->nr.t == V_CONST && e->nr.v == 102 &&
		   e->arg[1].t == V_SADDR) {
		e->has_arr = 1;
		for (i = 0; i < 6u; i++)
			e->arr[i] = sockcall_arg(c, f, e->arg[1], i);
	}
}

static struct sv emit_call_node(struct wctx *c, struct fstate *f, struct wsum *ws,
				const struct cell_insn *in)
{
	struct kof_diag_scan *s = c->s;
	struct ev e;
	uint64_t arg[6], nr, sock_arr[6] = { 0 };
	struct sv av[6];
	unsigned have = 0, i;
	int bits = c->wide ? 64 : 32;
	uint16_t cap;
	uint8_t fl = 0;
	const char *nm = NULL;
	struct kof_diag_hit *h;

	eval_call(c, f, ws, &e);
	if (e.nr.t != V_CONST)
		return UNK;                     /* which system call is not known */
	nr = (uint64_t)e.nr.v;
	for (i = 0; i < 6u; i++) {
		av[i] = e.arg[i];
		if (av[i].t == V_CONST ||
		    (av[i].t == V_SET &&
		     kof_flow_arg_is_flags((unsigned)bits, (uint32_t)nr, i))) {
			arg[i] = (uint64_t)av[i].v;
			have |= 1u << i;
		} else {
			arg[i] = 0;
		}
	}
	/*
	 * i386's socketcall: the sub-call is argument 0 and the operation's own
	 * arguments are the array. What cap that is, and how its arguments map onto
	 * the roles, is the operation's - so the array replaces the register view.
	 */
	if (bits == 32 && nr == 102u) {
		unsigned jhave = 0, j;

		if (!(have & 1u))
			return UNK;             /* which operation is not known */
		for (j = 0; j < 6u; j++) {
			struct sv v = e.has_arr ? e.arr[j] : UNK;

			av[j] = v;
			if (v.t == V_CONST) {
				sock_arr[j] = (uint64_t)v.v;
				jhave |= 1u << j;
			} else {
				sock_arr[j] = 0;
			}
		}
		cap = kof_flow_cap_of_sockcall((uint32_t)arg[0], sock_arr, jhave, &fl);
		have = jhave;
	} else {
		cap = kof_flow_cap_of_syscall((unsigned)bits, (uint32_t)nr, arg, &fl);
		nm = kof_sys_name((unsigned)bits, (uint32_t)nr);
	}
	if (cap == KOF_NUCLEO_NONE)
		return UNK;
	h = kof_diag_hit_add(s, in->at, cap, fl);
	if (!h)
		return UNK;
	if ((cap == KOF_NUCLEO_ALLOC && !(have & (1u << 2))) ||
	    (cap == KOF_NUCLEO_NET_OPEN && (have & 3u) != 3u))
		h->bits |= KOF_DIAG_H_ARG_UNKNOWN;
	for (i = 0; i < 6u; i++) {
		uint8_t role = kof_diag_role_of_arg(cap, i);

		if (role != KOF_DIAG_ROLE_NONE && av[i].t == V_NODE)
			kof_diag_note_in(h, av[i].node, role,
					 KOF_DIAG_KIND_PRODUCED);
	}
	if (bits == 64 && nm && kof_sys_zero_on_success(nm))
		h->bits |= KOF_DIAG_H_ZERO_OK;
	ws->node_made = 1;
	if (kof_flow_hands_on(cap, nm)) {
		struct sv r = { V_NODE, (uint16_t)(s->n_hit - 1u), 0 };

		if (cap == KOF_NUCLEO_NET_OPEN || cap == KOF_NUCLEO_NET_RAW) {
			int nb = bits == 32 && nr == 102u
				 ? kof_flow_sockcall_nonblock((uint32_t)arg[0], sock_arr, have)
				 : kof_flow_sock_nonblock((unsigned)bits, (uint32_t)nr, arg, have);

			if (nb)
				kof_diag_hit_nonblock(s, in->at, r.node);
		}
		return r;
	}
	return UNK;
}

/* ---- pass B: the functions, in address order ------------------------------ */

/* Whether the node at `at` is one a function hands back to its callers. */
static int fret_site(const struct wctx *c, uint64_t at)
{
	uint32_t i;

	if (!c->fret)
		return 0;
	for (i = 0; i < c->n_tgt; i++)
		if (c->fret[i] && c->fret[i] - 1u < c->s->n_hit &&
		    c->s->hit[c->fret[i] - 1u].at == at)
			return 1;
	return 0;
}

/* The index of a call target, or -1. */
static int tgt_index(const struct wctx *c, uint64_t at)
{
	uint32_t lo = 0, hi = c->n_tgt;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->tgt[mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->n_tgt && c->tgt[lo] == at ? (int)lo : -1;
}

static int is_entry(const struct wctx *c, uint64_t at)
{
	uint32_t lo = 0, hi = c->n_tgt;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (c->tgt[mid] < at)
			lo = mid + 1u;
		else
			hi = mid;
	}
	return lo < c->n_tgt && c->tgt[lo] == at;
}

static void pass_b(struct wctx *c, unsigned seg, uint64_t off, uint64_t n)
{
	struct isrc it;
	struct cell_insn in;
	struct fstate f;
	int cur = -1;                   /* the call target this code belongs to */

	st_reset(&f);
	if (!isrc_open(&it, c, seg, off, n))
		return;
	while (!c->s->full && isrc_next(&it, &in)) {
		struct wsum *ws;

		if (is_entry(c, in.at)) {
			st_reset(&f);
			cur = tgt_index(c, in.at);
		}
		/*
		 * A FUNCTION THAT HANDS BACK WHAT IT MADE. Mirai builds its raw sockets
		 * in a helper - socket, IP_HDRINCL, O_NONBLOCK, `return fd` - and sends
		 * on the result in the attack routine, so the descriptor the send names
		 * is produced in another function. The helper's return value is the
		 * node; the callers, in the second walk, take it from there.
		 */
		if (in.op == CELL_RET && cur >= 0 && c->fret &&
		    f.reg[CELL_REG_AX].t == V_NODE) {
			if (!c->fret[cur] && c->fmiss && c->fmiss[cur])
				c->need_round2 = 1;     /* a caller above asked too early */
			c->fret[cur] = (uint32_t)f.reg[CELL_REG_AX].node + 1u;
		}
		if (in.op == CELL_CALL) {
			ws = (!(in.flags & CELL_F_INDIRECT) && in.target != KOF_BROKEN)
			     ? wsum_of(c, in.target) : NULL;
			{
				/* The arguments are read BEFORE the callee's clobbers are
				 * applied, and the result is put in AFTER them. A wrapper
				 * with several paths makes the node of each; they merge. */
				struct sv ret = UNK;

				if (ws) {
					uint32_t v, base = (uint32_t)(ws - c->ws);

					for (v = base; v < c->n_ws &&
						       c->ws[v].entry == c->ws[base].entry; v++) {
						struct sv r = emit_call_node(c, &f, &c->ws[v], &in);

						if (r.t != V_UNK && ret.t == V_UNK)
							ret = r;
					}
				}
				st_call_unknown(c, &f);
				/*
				 * The helper's OWN node wins over the one a summary makes at
				 * the call: the summary stops at the first wrapper the helper
				 * calls (the socket) and knows nothing of the option calls
				 * after it, so the node it makes at the call has none of the
				 * helper's later links, and a send on it could never reach the
				 * IP_HDRINCL that made the socket raw-with-header.
				 */
				if (c->fret && !(in.flags & CELL_F_INDIRECT) &&
				    in.target != KOF_BROKEN) {
					int ti = tgt_index(c, in.target);

					if (ti >= 0 && c->fret[ti]) {
						ret.t = V_NODE;
						ret.node = (uint16_t)(c->fret[ti] - 1u);
					} else if (ti >= 0 && c->fmiss) {
						c->fmiss[ti] = 1;
					}
				}
				f.reg[CELL_REG_AX] = ret;
			}
			continue;
		}
		st_step(c, &f, &in);
	}
}

/* ---- the entry point ----------------------------------------------------- */

static uint64_t seg_range(const struct kof_obj_ctx *ctx,
			  const struct kof_elf_info *e, uint32_t i,
			  uint64_t size, uint64_t *at)
{
	const struct kof_elf_seg *g = &e->seg[i];
	uint64_t have;

	if (g->type != 1u || !(g->perm & KOF_PERM_X))
		return 0;
	have = kof_clip_len(size, g->file_off, g->file_size);
	if (!have)
		return 0;
	*at = g->file_off;
	/* Start at the entry point when it is in this segment: the segment may
	 * begin with the ELF header, and a decode that starts there carries the
	 * desync into the code - see code_range in kofdiag.c, the same rule. */
	if (ctx->entry_off >= g->file_off && ctx->entry_off < g->file_off + have) {
		have -= ctx->entry_off - g->file_off;
		*at = ctx->entry_off;
	}
	return have;
}

void kof_diag_run_wrappers(struct kof_diag_scan *s,
			   const struct kof_obj_ctx *ctx,
			   const uint8_t *base, uint64_t size)
{
	const struct kof_elf_info *e = kof_elf(ctx);
	struct wctx c;
	uint32_t i;

	if (!e || !e->valid)
		return;
	if (ctx->arch != KOF_ARCH_X86 && ctx->arch != KOF_ARCH_X86_64)
		return;
	memset(&c, 0, sizeof c);
	c.s = s;
	c.ctx = ctx;
	c.base = base;
	kof_cell_space_init(&c.sp, ctx, base, size);
	c.size = size;
	c.wide = ctx->arch == KOF_ARCH_X86_64;
	c.w = c.wide ? 8 : 4;

	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		uint64_t at, have = seg_range(ctx, e, i, size, &at);

		if (have && !pass_a(&c, i, at, have))
			goto out;
	}
	if (!c.n_site)
		goto opaque;
	for (i = 0; i < s->n_hit; i++)
		if (s->hit[i].cap == KOF_NUCLEO_NONE &&
		    (s->hit[i].bits & KOF_DIAG_H_OPAQUE) &&
		    !push_u64(&c.open, &c.n_open, &c.cap_open, s->hit[i].at))
			goto out;
	/* qsort's base is declared nonnull, and with no elements it is NULL. */
	if (c.n_open)
		qsort(c.open, c.n_open, sizeof *c.open, u64_cmp);
	if (c.n_tgt)
		qsort(c.tgt, c.n_tgt, sizeof *c.tgt, u64_cmp);
	{
		uint32_t w = 0;

		for (i = 0; i < c.n_tgt; i++)
			if (!w || c.tgt[w - 1u] != c.tgt[i])
				c.tgt[w++] = c.tgt[i];
		c.n_tgt = w;
	}
	c.fret = calloc(c.n_tgt ? c.n_tgt : 1u, sizeof *c.fret);
	c.fmiss = calloc(c.n_tgt ? c.n_tgt : 1u, sizeof *c.fmiss);
	if (!c.fret || !c.fmiss)
		goto out;
	/*
	 * LEVEL 0: the functions that hold a syscall. LEVELS 1 AND 2: the functions
	 * whose straight line ends in a call to one already found. The third is
	 * where the nesting measured stops (socket() around __socketcall around
	 * the syscall) and a bound on a guess, not a limit on a result.
	 */
	c.cap_ws = c.n_site + 64u;
	c.ws = calloc(c.cap_ws, sizeof *c.ws);
	if (!c.ws)
		goto out;
	for (i = 0; i < c.n_site; i++) {
		uint64_t entry;
		struct wsum t[W_VARIANTS];
		unsigned nt, v;

		if (!entry_of(&c, c.site[i], &entry))
			continue;
		if (wsum_of(&c, entry))
			continue;
		nt = summarise(&c, entry, t);
		for (v = 0; v < nt; v++)
			(void)ws_insert(&c, &t[v]);
	}
	if (c.n_ws && c.n_tgt <= W_LEVELS_MAX_TGT) {
		unsigned level;

		for (level = 0; level < 2u; level++) {
			uint32_t added = 0;

			for (i = 0; i < c.n_tgt; i++) {
				struct wsum t[W_VARIANTS];
				unsigned nt, v;

				if (wsum_of(&c, c.tgt[i]))
					continue;
				nt = summarise(&c, c.tgt[i], t);
				for (v = 0; v < nt; v++) {
					if (!ws_insert(&c, &t[v]))
						break;
					added++;
				}
			}
			if (!added)
				break;
		}
	}
	if (!c.n_ws)
		goto opaque;
	/*
	 * TWICE, because a descriptor kept in a global is stored where the program
	 * dials out and read where it listens, and which of the two functions comes
	 * first in the file is the compiler's business. The second walk starts with
	 * every global the first one saw produced, so a read that came before the
	 * write in address order still finds it. The nodes it makes are the first
	 * walk's again, merged by site at the end of the scan, with the links the
	 * first walk could not yet have.
	 */
	{
		unsigned round;

		/*
		 * THE SECOND ROUND ONLY WHEN IT CAN DIFFER. It starts with the
		 * globals the first produced, so it changes the result exactly
		 * when some global was read before the first round had written it
		 * (need_round2) or a call asked for what a helper returns before the
		 * walk had reached the helper. Otherwise it would decode the whole image again
		 * to arrive at the same nodes: MEASURED, pass_b is a full linear
		 * decode and this was the third of three over the same bytes.
		 */
		for (round = 0; round < 2u; round++) {
			if (round && !c.need_round2)
				break;
			for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
				uint64_t at, have = seg_range(ctx, e, i, size, &at);

				if (have)
					pass_b(&c, i, at, have);
			}
		}
	}
	/* A wrapper some caller made a node for is answered at its callers; the
	 * node the sweep made at the syscall inside it spoke for every caller at
	 * once and for none of them, and is set aside. */
	for (i = 0; i < c.n_ws; i++) {
		uint32_t j;

		if (!c.ws[i].node_made || fret_site(&c, c.ws[i].site))
			continue;       /* a helper's own node is the one callers use */
		for (j = 0; j < s->n_hit; j++)
			if (s->hit[j].at == c.ws[i].site &&
			    !(s->hit[j].bits & KOF_DIAG_H_SUPERSEDED))
				s->hit[j].bits |= KOF_DIAG_H_SUPERSEDED;
	}
opaque:
	/* A socketcall of an unknown kind is a different statement from no
	 * socketcall at all: a site nobody called with a value this could read
	 * says so, once, rather than saying nothing. */
	for (i = 0; i < s->n_wrap; i++) {
		uint32_t j;
		int made = 0;

		for (j = 0; j < c.n_ws; j++)
			if (c.ws[j].site == s->wrap[i] && c.ws[j].node_made)
				made = 1;
		if (!made) {
			struct kof_diag_hit *h = kof_diag_hit_add(s, s->wrap[i],
								  KOF_NUCLEO_NONE, 0);

			if (h)
				h->bits |= KOF_DIAG_H_OPAQUE;
		}
	}
out:
	free(c.tgt);
	free(c.site);
	free(c.open);
	free(c.fret);
	free(c.tr);
	free(c.fmiss);
	free(c.ws);
	free(c.glob);
}
