/*
 * diag_wrapper_state.c - the symbolic state of one function: registers, stack slots and globals, and the step that updates it.
 * Part of the syscall-wrapper analysis; see diag_wrapper.c for what it is for and diag_wrapper_private.h for what the
 * files share.
 */
#include "diag_wrapper_private.h"

/* KNOWN DEFECT REV-D7e (2026-10-24, Inference) [sev L]: GMISS_BIT (the wrapper global-miss filter) is a hand-rolled hash with an unseeded multiplicative
 * hash, not the shared helper (diag_oatab.h / kof_hash64_slot): CLAUDE.md rule 2. Trigger: keys chosen by the file that
 * collide in the top bits. Effect: probe chains grow (the G1 flood in the script tables took 20.4 s for 65536 names).
 * Reproducer: none (review_arch D7, read). Fix: build it on kgenome_oatab (seeded, one probe step) like diag_text_sum. */
#define GMISS_BIT(a) ((unsigned)(((a) * 0x9e3779b97f4a7c15ull) >> 52) & 4095u)

/* Charge `n` bytes of the wrapper walk's own tables to the scan's ledger. 0 when
 * the allowance refuses (the ledger says KGENOME_OVER_BUDGET) - the caller keeps
 * what it has and does not grow. */
int kgenome_diag_wrapper_charge(struct kgenome_diag_wrapper_ctx *c, uint64_t n)
{
	if (!kgenome_ledger_charge(&c->s->led, n))
		return 0;
	c->charged += n;
	return 1;
}

/* ---- the symbolic state ------------------------------------------------- */

void kgenome_diag_wrapper_frame_reset(struct kgenome_diag_wrapper_frame *f)
{
	memset(f, 0, offsetof(struct kgenome_diag_wrapper_frame, slot));
}

/* A copy of a state: what is above the slot table, and the slots in use. */
void kgenome_diag_wrapper_frame_copy(struct kgenome_diag_wrapper_frame *dst, const struct kgenome_diag_wrapper_frame *src)
{
	memcpy(dst, src, offsetof(struct kgenome_diag_wrapper_frame, slot));
	memcpy(dst->slot, src->slot, (size_t)src->n_slot * sizeof src->slot[0]);
	/* A full table is a ring: every slot is live, and `next` is in the header. */
}

static struct kgenome_diag_wrapper_slot *slot_find(struct kgenome_diag_wrapper_frame *f, int32_t off)
{
	uint32_t i;

	for (i = 0; i < f->n_slot; i++)
		if (f->slot[i].off == off)
			return &f->slot[i];
	return NULL;
}

void kgenome_diag_wrapper_slot_put(struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f, int32_t off, struct kgenome_diag_wrapper_val v)
{
	struct kgenome_diag_wrapper_slot *p = slot_find(f, off);

	if (p) {
		p->v = v;
		return;
	}
	if (v.t == KGENOME_DIAG_WRAPPER_V_UNK)
		return;                 /* nothing to remember */
	if (f->n_slot < KGENOME_DIAG_WRAPPER_SLOTS) {
		f->slot[f->n_slot].off = off;
		f->slot[f->n_slot++].v = v;
		return;
	}
	/* THE FRAME HOLDS MORE LIVE SLOTS THAN KGENOME_DIAG_WRAPPER_SLOTS: the oldest is overwritten,
	 * which can be a link missed - said, not silent. */
	kgenome_diag_note(c->s, KGENOME_TRUNCATED);
	f->slot[f->next].off = off;
	f->slot[f->next].v = v;
	f->next = (f->next + 1u) % KGENOME_DIAG_WRAPPER_SLOTS;
}

struct kgenome_diag_wrapper_val kgenome_diag_wrapper_slot_get(struct kgenome_diag_wrapper_frame *f, int32_t off)
{
	struct kgenome_diag_wrapper_slot *p = slot_find(f, off);

	return p ? p->v : kgenome_diag_wrapper_unk;
}

static struct kgenome_diag_wrapper_glob *glob_find(struct kgenome_diag_wrapper_ctx *c, uint64_t addr)
{
	uint32_t i;

	for (i = 0; i < c->n_glob; i++)
		if (c->glob[i].addr == addr)
			return &c->glob[i];
	return NULL;
}

static void glob_put(struct kgenome_diag_wrapper_ctx *c, uint64_t addr, struct kgenome_diag_wrapper_val v)
{
	struct kgenome_diag_wrapper_glob *g = glob_find(c, addr);

	if (g) {
		g->v = v;
		return;
	}
	if (v.t != KGENOME_DIAG_WRAPPER_V_NODE)
		return;                 /* only a produced value is worth a global */
	if (c->gmiss[GMISS_BIT(addr) >> 6] & (1ull << (GMISS_BIT(addr) & 63u)))
		c->need_round2 = 1;     /* it was read before it existed */
	if (c->n_glob == c->cap_glob) {
		uint32_t nc = c->cap_glob ? c->cap_glob * 2u : 64u;
		struct kgenome_diag_wrapper_glob *ng;

		if (!kgenome_diag_wrapper_charge(c, (uint64_t)(nc - c->cap_glob) * sizeof *ng))
			return;
		ng = realloc(c->glob, (size_t)nc * sizeof *ng);
		if (!ng) {
			kgenome_diag_note(c->s, KGENOME_NOMEM);
			return;
		}
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

/*
 * 64-BIT ADDRESS ARITHMETIC WRAPS, as the machine's does. A virtual address, a register's
 * constant and a displacement are all the sample's: an ELF loaded near 2^63, or two such
 * constants added, overflowed the signed sum (undefined behaviour, found by running the engine
 * under UBSan on mutated binaries). Addresses are compared and keyed, never ordered by
 * magnitude, so the wrapped value is the right one.
 */
static inline int64_t wadd(int64_t a, int64_t b)
{
	return (int64_t)((uint64_t)a + (uint64_t)b);
}

static int mem_loc(const struct kgenome_diag_wrapper_ctx *c, const struct kgenome_diag_wrapper_frame *f,
		   const struct kgenome_diag_wrapper_insn *in, const struct kgenome_diag_wrapper_op *o,
		   int64_t *key)
{
	if (o->kind != KGENOME_CELL_O_MEM || o->index != KGENOME_CELL_REG_NONE)
		return LOC_NONE;
	if (o->seg != KGENOME_CELL_REG_NONE && o->seg != KGENOME_CELL_SEG_DS &&
	    o->seg != KGENOME_CELL_SEG_SS)
		return LOC_NONE;        /* fs: and gs: are thread data */
	if (o->flags & KGENOME_CELL_OF_RIPREL) {
		if (in->at_va == KGENOME_BROKEN)
			return LOC_NONE;
		*key = wadd((int64_t)(in->at_va + in->len), o->v);
		return LOC_GLOBAL;
	}
	if (o->reg == KGENOME_CELL_REG_NONE) {
		*key = o->v & (c->wide ? -1ll : 0xffffffffll);
		return LOC_GLOBAL;
	}
	if (o->reg == KGENOME_CELL_REG_SP) {
		*key = wadd(-(int64_t)f->sp, o->v);
		return LOC_STACK;
	}
	if (o->reg == KGENOME_CELL_REG_BP && f->bp_known) {
		*key = wadd((int64_t)f->bp_off, o->v);
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
	if (o->reg < 16u && f->reg[o->reg].t == KGENOME_DIAG_WRAPPER_V_SADDR) {
		*key = wadd(f->reg[o->reg].v, o->v);
		return LOC_STACK;
	}
	return LOC_NONE;
}

static struct kgenome_diag_wrapper_val load(struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f,
		      const struct kgenome_diag_wrapper_insn *in, const struct kgenome_diag_wrapper_op *o)
{
	int64_t key;

	switch (o->kind) {
	case KGENOME_CELL_O_REG:
		if (o->reg >= 16u || o->size < 4u)
			return kgenome_diag_wrapper_unk;
		return f->reg[o->reg];
	case KGENOME_CELL_O_IMM: {
		struct kgenome_diag_wrapper_val v = { KGENOME_DIAG_WRAPPER_V_CONST, 0, (int64_t)o->v };

		return v;
	}
	case KGENOME_CELL_O_MEM:
		if (o->size < 4u)
			return kgenome_diag_wrapper_unk;
		switch (mem_loc(c, f, in, o, &key)) {
		case LOC_STACK:
			return kgenome_diag_wrapper_slot_get(f, (int32_t)key);
		case LOC_GLOBAL: {
			struct kgenome_diag_wrapper_glob *g = glob_find(c, (uint64_t)key);

			if (!g)
				c->gmiss[GMISS_BIT((uint64_t)key) >> 6] |=
					1ull << (GMISS_BIT((uint64_t)key) & 63u);
			return g ? g->v : kgenome_diag_wrapper_unk;
		}
		default:
			return kgenome_diag_wrapper_unk;
		}
	default:
		return kgenome_diag_wrapper_unk;
	}
}

static void store(struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f, const struct kgenome_diag_wrapper_insn *in,
		  const struct kgenome_diag_wrapper_op *o, struct kgenome_diag_wrapper_val v)
{
	int64_t key;

	if (o->kind == KGENOME_CELL_O_REG) {
		if (o->reg < 16u)
			f->reg[o->reg] = o->size >= 4u ? v : kgenome_diag_wrapper_unk;
		return;
	}
	if (o->kind != KGENOME_CELL_O_MEM)
		return;
	if (o->size < 4u)
		v = kgenome_diag_wrapper_unk;
	switch (mem_loc(c, f, in, o, &key)) {
	case LOC_STACK:
		kgenome_diag_wrapper_slot_put(c, f, (int32_t)key, v);
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
void kgenome_diag_wrapper_frame_step(struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f, const struct kgenome_diag_wrapper_insn *in)
{
	const struct kgenome_diag_wrapper_op *d = &in->o[0], *s = &in->o[1];
	int w = c->w;
	uint32_t r;

	switch (in->op) {
	case KGENOME_CELL_NOP:
		return;
	case KGENOME_CELL_MOV:
		if (in->n_op >= 2u) {
			struct kgenome_diag_wrapper_val v = load(c, f, in, s);

			/* mov bp,sp: the frame pointer now names this frame. */
			if (d->kind == KGENOME_CELL_O_REG && d->reg == KGENOME_CELL_REG_BP &&
			    s->kind == KGENOME_CELL_O_REG && s->reg == KGENOME_CELL_REG_SP) {
				f->bp_known = 1;
				f->bp_off = -f->sp;
				f->reg[KGENOME_CELL_REG_BP].t = KGENOME_DIAG_WRAPPER_V_SADDR;
				f->reg[KGENOME_CELL_REG_BP].v = -f->sp;
				return;
			}
			/* A copy of the stack pointer is a stack ADDRESS. */
			if (d->kind == KGENOME_CELL_O_REG && s->kind == KGENOME_CELL_O_REG &&
			    s->reg == KGENOME_CELL_REG_SP && d->size >= 4u && d->reg < 16u) {
				f->reg[d->reg].t = KGENOME_DIAG_WRAPPER_V_SADDR;
				f->reg[d->reg].v = -f->sp;
				f->reg[d->reg].node = 0;
				return;
			}
			store(c, f, in, d, v);
			return;
		}
		break;
	case KGENOME_CELL_MOVSX:
	case KGENOME_CELL_MOVZX:
	case KGENOME_CELL_WIDEN:
		/* A 32-bit value widened to 64 is the same value as far as a
		 * handle or a parameter is concerned (movslq edx,rdx). */
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG &&
		    s->kind == KGENOME_CELL_O_REG && s->size >= 4u && d->reg < 16u &&
		    s->reg < 16u) {
			f->reg[d->reg] = f->reg[s->reg];
			return;
		}
		if (in->op == KGENOME_CELL_WIDEN)
			return;         /* cdqe in place */
		break;
	case KGENOME_CELL_XCHG:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG &&
		    s->kind == KGENOME_CELL_O_REG && d->reg < 16u && s->reg < 16u) {
			struct kgenome_diag_wrapper_val t = f->reg[d->reg];

			f->reg[d->reg] = f->reg[s->reg];
			f->reg[s->reg] = t;
			return;
		}
		break;
	case KGENOME_CELL_LEA:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u &&
		    s->kind == KGENOME_CELL_O_MEM && s->index == KGENOME_CELL_REG_NONE &&
		    !(s->flags & KGENOME_CELL_OF_RIPREL)) {
			if (s->reg == KGENOME_CELL_REG_SP) {
				f->reg[d->reg].t = KGENOME_DIAG_WRAPPER_V_SADDR;
				f->reg[d->reg].v = wadd(-(int64_t)f->sp, s->v);
				f->reg[d->reg].node = 0;
				if (d->reg == KGENOME_CELL_REG_BP) {
					f->bp_known = 1;
					f->bp_off = (int32_t)f->reg[d->reg].v;
				}
				return;
			}
			if (s->reg == KGENOME_CELL_REG_BP && f->bp_known) {
				f->reg[d->reg].t = KGENOME_DIAG_WRAPPER_V_SADDR;
				f->reg[d->reg].v = wadd((int64_t)f->bp_off, s->v);
				f->reg[d->reg].node = 0;
				return;
			}
		}
		break;
	case KGENOME_CELL_XOR:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && s->kind == KGENOME_CELL_O_REG &&
		    d->reg == s->reg && d->reg < 16u) {
			f->reg[d->reg].t = KGENOME_DIAG_WRAPPER_V_CONST;
			f->reg[d->reg].v = 0;
			f->reg[d->reg].node = 0;
			return;
		}
		break;
	case KGENOME_CELL_PUSH:
		if (in->n_op >= 1u) {
			struct kgenome_diag_wrapper_val v = load(c, f, in, d);

			f->sp += w;
			kgenome_diag_wrapper_slot_put(c, f, -f->sp, v);
		}
		return;
	case KGENOME_CELL_POP:
		if (in->n_op >= 1u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u)
			f->reg[d->reg] = kgenome_diag_wrapper_slot_get(f, -f->sp);
		f->sp -= w;
		return;
	case KGENOME_CELL_ADD:
	case KGENOME_CELL_SUB:
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG &&
		    d->reg == KGENOME_CELL_REG_SP && s->kind == KGENOME_CELL_O_IMM) {
			/*
			 * The immediate is the sample's. `sub esp, 0x7fffffff` twice, or an
			 * `add esp, 0x80000000` (whose negation is not an int), overflowed the
			 * 32-bit counter: undefined behaviour found by running the engine
			 * under UBSan on mutated stripped i386 binaries. The sum is made wide
			 * and held to +-2^30, where it is still "a frame no real function has"
			 * and where `-f->sp` cannot overflow either; no frame of real code
			 * comes near it, so what the walk concludes about one does not move.
			 */
			{
				int64_t imm = (int64_t)(int32_t)s->v;
				int64_t v = (int64_t)f->sp + (in->op == KGENOME_CELL_SUB ? imm : -imm);

				f->sp = v > KGENOME_DIAG_WRAPPER_SP_LIM ? KGENOME_DIAG_WRAPPER_SP_LIM
				      : v < -KGENOME_DIAG_WRAPPER_SP_LIM ? -KGENOME_DIAG_WRAPPER_SP_LIM
				      : (int32_t)v;
			}
			return;
		}
		/* A stack address moved by a constant is another stack address. */
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u &&
		    d->size >= 4u && s->kind == KGENOME_CELL_O_IMM &&
		    f->reg[d->reg].t == KGENOME_DIAG_WRAPPER_V_SADDR) {
			f->reg[d->reg].v = wadd(f->reg[d->reg].v, in->op == KGENOME_CELL_SUB ? -(int64_t)(int32_t)s->v
								    : (int64_t)(int32_t)s->v);
			return;
		}
		break;
	case KGENOME_CELL_OR:
		/*
		 * `flags | O_NONBLOCK`, where flags is whatever F_GETFL returned.
		 * The result is not a number, but it is a number with a bit that is
		 * certainly set, and that bit is the claim fcntl(F_SETFL) is read
		 * for. gcc writes the 0x800 as `or ah, 8` (80 cc 08): 80 of 95
		 * samples with an OR of that bit in the 146-sample mirai x86 set
		 * use that form, which a model that reads only 4-byte operands
		 * never sees.
		 */
		if (in->n_op >= 2u && d->kind == KGENOME_CELL_O_REG && d->reg < 16u &&
		    s->kind == KGENOME_CELL_O_IMM && d->size != 2u) {
			uint64_t bit = (uint64_t)s->v;
			struct kgenome_diag_wrapper_val *rv = &f->reg[d->reg];

			if (d->size == 1u) {
				bit &= 0xffu;
				if (d->flags & KGENOME_CELL_OF_HIGH8)
					bit <<= 8;
			}
			if (rv->t == KGENOME_DIAG_WRAPPER_V_CONST) {
				rv->v |= (int64_t)bit;
			} else {
				int64_t keep = rv->t == KGENOME_DIAG_WRAPPER_V_SET ? rv->v : 0;

				rv->t = KGENOME_DIAG_WRAPPER_V_SET;
				rv->node = 0;
				rv->v = keep | (int64_t)bit;
			}
			return;
		}
		break;
	case KGENOME_CELL_RET:
		kgenome_diag_wrapper_frame_reset(f);
		return;
	case KGENOME_CELL_CMP:
	case KGENOME_CELL_TEST:
	case KGENOME_CELL_JCC:
	case KGENOME_CELL_JMP:
		return;                 /* nothing written; the walk is linear */
	default:
		break;
	}
	/* Anything else forgets what it wrote. */
	for (r = 0; r < 16u; r++)
		if (in->wmask & (1ull << r)) {
			if (r == KGENOME_CELL_REG_SP)
				continue;
			f->reg[r] = kgenome_diag_wrapper_unk;
		}
	{
		int64_t key;

		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_MEM &&
		    (in->o[0].flags & KGENOME_CELL_OF_WRITE)) {
			switch (mem_loc(c, f, in, &in->o[0], &key)) {
			case LOC_STACK:
				kgenome_diag_wrapper_slot_put(c, f, (int32_t)key, kgenome_diag_wrapper_unk);
				break;
			case LOC_GLOBAL:
				glob_put(c, (uint64_t)key, kgenome_diag_wrapper_unk);
				break;
			default:
				break;
			}
		}
	}
}

/* What a call to something the walk does not kgenome_diag_wrapper_summarise leaves behind: the
 * registers the callee may use are gone, the frame and the globals are not. */
void kgenome_diag_wrapper_frame_call_unknown(struct kgenome_diag_wrapper_ctx *c, struct kgenome_diag_wrapper_frame *f)
{
	static const uint8_t cs64[] = { 0, 1, 2, 6, 7, 8, 9, 10, 11 };
	static const uint8_t cs32[] = { 0, 1, 2 };
	const uint8_t *cs = c->wide ? cs64 : cs32;
	uint32_t n = c->wide ? (uint32_t)sizeof cs64 : (uint32_t)sizeof cs32, i;

	for (i = 0; i < n; i++)
		f->reg[cs[i]] = kgenome_diag_wrapper_unk;
}
