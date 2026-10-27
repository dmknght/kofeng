/*
 * cursor.c - the walk: decode, translate, keep a map, follow what is known.
 * See celllysis.h for what this is for, and kofmod/cell.h for why a module
 * wants it.
 *
 * THREE JOBS AND THEY ARE DELIBERATELY SEPARATE.
 *
 *   DECODE is reached through kgenome_cell_decode, which picks the decoder; this file
 *     does not name one.
 *   THE CONSTANT MAP is cell_state.c: what a register holds, where that is
 *     knowable by reading forwards, from one decoded instruction.
 *   WHAT THIS FILE OWNS is the walk itself: the offset/address conversion
 *     through the space the owner supplied, the literal pool, and resolving an
 *     indirect branch from what the map holds.
 *
 * WHAT THE MAP WILL NOT DO, which is most of what an interpreter does. It does
 * not read memory - a value loaded from anywhere becomes unknown, because the
 * bytes at that address at that moment are not a thing this can know. It does
 * not take branches. It does not model flags. Every one of those is a place
 * where guessing would produce a number that looks like an answer, and the
 * whole value of this over the interpreter is that its answers are either
 * derived or absent.
 */

#include <stdint.h>
#include <string.h>

#include "celllysis.h"

/* ---- offsets and addresses ----------------------------------------------
 *
 * The cursor is an offset; a branch is computed in addresses. Both directions
 * are needed.
 */
static uint64_t off_to_va(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
			  uint64_t off)
{
	/* Inside the segment the last call established it is one addition -
	 * see struct kgenome_image_seg for why that is almost always. */
	if (k->seg_ok && off >= k->seg.lo && off < k->seg.hi)
		return off + (uint64_t)k->seg.delta;
	if (!sp->seg_at || !sp->seg_at(sp->priv, off, &k->seg))
		return KGENOME_BROKEN;
	k->seg_ok = 1;
	return off + (uint64_t)k->seg.delta;
}

/*
 * AND THE WAY BACK, FOR A BRANCH THAT STAYS IN THE SAME SEGMENT.
 *
 * Which nearly every branch does: a relative displacement cannot leave the
 * image and a compiler does not emit one that leaves the section. The segment
 * is a mapping in both directions, so the inverse is the same single
 * subtraction - and when the target IS somewhere else this falls through to
 * the owner's one resolver rather than growing a second copy of it.
 */
static uint64_t va_to_off(const struct kgenome_cell_cur *k,
			  const struct kgenome_cell_space *sp, uint64_t va)
{
	if (k->seg_ok) {
		uint64_t lo = k->seg.lo + (uint64_t)k->seg.delta;
		uint64_t hi = k->seg.hi + (uint64_t)k->seg.delta;

		if (va >= lo && va < hi)
			return va - (uint64_t)k->seg.delta;
	}
	return sp->off_of_va ? sp->off_of_va(sp->priv, va) : KGENOME_BROKEN;
}

/* ---- the cursor ---------------------------------------------------------- */

int kgenome_cell_seek(struct kgenome_cell_cur *k, uint64_t off, int keep)
{
	if (!k)
		return 0;
	k->at = off;
	k->open = 1;
	k->seg_ok = 0;                  /* see struct kgenome_cell_cur */
	if (!keep)
		kgenome_cell_state_reset(&k->st);
	return 1;
}

int kgenome_cell_reg(const struct kgenome_cell_cur *k, uint8_t r, uint64_t *out)
{
	return k ? kgenome_cell_state_reg(&k->st, r, out) : 0;
}

/*
 * A LITERAL-POOL LOAD IS A CONSTANT, and on ARM it is how almost every number
 * above eight bits is made: `ldr r7,[pc,#x]` where the word at pc+x is 281.
 * Nothing about it is unknown - the bytes are in the buffer - so the load is
 * rewritten as the MOV of an immediate it is, which is what the constant map
 * reads. x86 has no equivalent worth the name (its constants are immediates).
 *
 * Only an unsigned load of the whole word; a sign-extending or narrow load is
 * left as the memory read it is. Literal address = at_va + disp, the decoders'
 * convention (see decode_arm32.h).
 */
static void resolve_literal(const struct kgenome_cell_cur *k,
			    const struct kgenome_cell_space *sp, struct kgenome_cell_insn *in)
{
	uint64_t off, v = 0;
	uint32_t sz, i;

	if (in->op != KGENOME_CELL_MOV || in->n_op < 2u ||
	    in->o[1].kind != KGENOME_CELL_O_MEM || !(in->o[1].flags & KGENOME_CELL_OF_RIPREL) ||
	    in->at_va == KGENOME_BROKEN)
		return;
	sz = in->o[1].size;
	if (sz != 4u && sz != 8u)
		return;
	off = va_to_off(k, sp, in->at_va + (uint64_t)in->o[1].disp);
	if (off == KGENOME_BROKEN || off > sp->size || sp->size - off < sz)
		return;
	for (i = 0; i < sz; i++)
		v |= (uint64_t)sp->base[off + i] <<
		     (8u * (sp->be ? sz - 1u - i : i));
	in->o[1].kind = KGENOME_CELL_O_IMM;
	in->o[1].imm = v;
	in->o[1].reg = in->o[1].index = KGENOME_CELL_REG_NONE;
	in->o[1].flags = KGENOME_CELL_OF_READ;
}

static int cell_fetch(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
		      struct kgenome_cell_insn *out)
{
	uint64_t left, va;
	uint32_t n;

	if (!k || !k->open || !sp || !sp->base || !out || k->at >= sp->size)
		return 0;
	left = sp->size - k->at;
	if (left > 16u)
		left = 16u;             /* the longest an instruction can be */

	/*
	 * ONE DECODE PATH. This used to call a decoder itself, classify with a
	 * switch of its own and build its own operands - a complete copy of
	 * decode_x86.c standing beside it. The copy was written first and never
	 * caught up: when the enum gained KGENOME_CELL_SYSCALL and KGENOME_CELL_WIDEN and the
	 * decoder gained `wmask`, only one of the two learned them.
	 *
	 * MEASURED, and it is not a small drift: a `syscall` instruction came
	 * back as KGENOME_CELL_OTHER, so nothing reading an object through this cursor
	 * could see a Linux system call AT ALL - on a static binary that is
	 * every capability the program has. `cdq` was the same, and `wmask`
	 * was zero for every instruction, which is what the constant map needs
	 * to know which registers an instruction destroys.
	 */
	va = off_to_va(k, sp, k->at);
	n = sp->held ? sp->held(sp->held_priv, k->at, va, (uint32_t)left, out) : 0;
	if (!n)
		n = kgenome_cell_decode(sp->arch, sp->be && !sp->code_le, sp->base + k->at,
					(uint32_t)left, va, out);
	if (!n)
		return 0;
	if (sp->arch == KGENOME_ARCH_ARM || sp->arch == KGENOME_ARCH_ARM64)
		resolve_literal(k, sp, out);
	out->at = k->at;
	n = out->n_op;
	if (out->target_va != KGENOME_BROKEN)
		/* KNOWN DEFECT WP9-F4 (2026-10-25, M) [sev M]: kgenome_cell_next stores va_to_off() as insn.target without
		 * clamping it to the buffer (second call site likewise; space.c elf_seg gives a flat space [0, 2^64) to an
		 * ELF with no program header). Trigger: a segment size past the file (or no program header) and a branch
		 * landing past the buffer. Effect: target is a file offset past the object and not KGENOME_BROKEN (cell.h);
		 * a consumer indexing by it reads past the object. Reproducer: tests/lib/genome/diag_known_misses.c f4.
		 * Fix: after the assignment clamp `target >= sp->size` to KGENOME_BROKEN. */
		out->target = va_to_off(k, sp, out->target_va);
	return 1;
}

/*
 * WHAT A CALL LEAVES ALONE, for the constant map: the architecture's callee-saved registers, or every register when
 * the callee only fetches the program counter.
 *
 * x86's `call L; db "text"; L: pop reg` is a call that never returns to the call: the callee takes its own
 * return address off the stack and carries on in the same function, so nothing was overwritten (the same
 * decision the sweep's callee reader makes, CALLEE_GETPC). One decode of the callee's first instruction
 * answers it, asked only when the map holds a register a call could take away and only for a direct call.
 */
static uint16_t call_keeps(const struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
			   const struct kgenome_cell_insn *call)
{
	const uint16_t keeps = kgenome_cell_call_keeps(sp->arch);
	struct kgenome_cell_cur t;
	struct kgenome_cell_insn first;

	if (!(k->st.known & (uint16_t)~keeps) || (call->flags & KGENOME_CELL_F_INDIRECT) ||
	    call->target == KGENOME_BROKEN || call->target == call->at + call->len ||   /* `call next` is not a call at all */
	    (sp->arch != KGENOME_ARCH_X86 && sp->arch != KGENOME_ARCH_X86_64))
		return keeps;
	memset(&t, 0, sizeof t);
	t.at = call->target;
	t.open = 1;
	if (cell_fetch(&t, sp, &first) && first.op == KGENOME_CELL_POP)
		return 0xffffu;
	return keeps;
}

int kgenome_cell_step(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
		  struct kgenome_cell_insn *out)
{
	if (!cell_fetch(k, sp, out))
		return 0;
	k->at += out->len;
	return 1;
}

int kgenome_cell_next(struct kgenome_cell_cur *k, const struct kgenome_cell_space *sp,
		  struct kgenome_cell_insn *out)
{
	uint32_t n;

	if (!cell_fetch(k, sp, out))
		return 0;
	n = out->n_op;

	/*
	 * AND AN INDIRECT BRANCH RESOLVED FROM WHAT IS KNOWN - see
	 * kgenome_cell_next in celllysis.h.
	 *
	 * DONE BEFORE kgenome_cell_state_track, because a RET's target is the value
	 * still on the stack - tracking pops it.
	 */
	if (out->target == KGENOME_BROKEN) {
		uint64_t v = 0;
		int have = 0;

		if (out->op == KGENOME_CELL_RET)
			have = kgenome_cell_state_stack_top(&k->st, &v);
		else if ((out->op == KGENOME_CELL_JMP || out->op == KGENOME_CELL_CALL) && n &&
			 out->o[0].kind == KGENOME_CELL_O_REG && out->o[0].reg < 16u)
			have = kgenome_cell_reg(k, out->o[0].reg, &v);
		if (have) {
			out->target_va = v;
			out->target = va_to_off(k, sp, v);
		}
	}

	if (out->op == KGENOME_CELL_CALL)
		k->st.call_keeps = call_keeps(k, sp, out);
	kgenome_cell_state_track(&k->st, out);
	k->at += out->len;
	return 1;
}
