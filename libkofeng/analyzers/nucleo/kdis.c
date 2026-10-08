/*
 * kdis.c - the engine half of kofmod/kdis.h: the cursor over an object's code.
 * Read that header first; it says what this is for and why.
 *
 * THREE JOBS AND THEY ARE DELIBERATELY SEPARATE.
 *
 *   DECODE is genotype's, reached through decode.h; this file does not name it.
 *   THE CONSTANT MAP is genotype's too (kdis_state.c): what a register holds,
 *     where that is knowable by reading forwards, from one decoded instruction.
 *   WHAT THIS FILE OWNS is what needs the OBJECT: turning a file offset into an
 *     address and back through the PE or ELF layout, and resolving an indirect
 *     branch from what the map holds.
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

#include "kofcore.h"
#include "kofmod/kofsig.h"
#include "kofmod/pe.h"
#include "kofmod/elf.h"
#include "kofmod/kdis.h"
#include "kdis.h"
#include "../../disinfect/pzero.h"

#include "../../../libgenome/genotype/analysis/decode.h"



/* ---- offsets and addresses ----------------------------------------------
 *
 * The cursor is an offset; a branch is computed in addresses. Both directions
 * are needed and only one of them already existed.
 */
static uint64_t kdis_off_to_va(struct kof_kdis *k,
			       const struct kof_obj_ctx *ctx, uint64_t off)
{
	/* Inside the window the last call established, it is one addition -
	 * see the note on map_lo in kdis.h for why that is almost always. */
	if (k->map_ok && off >= k->map_lo && off < k->map_hi)
		return (uint64_t)((int64_t)off + k->map_delta);
	if (!ctx || !ctx->file_header)
		return KOF_BROKEN;
	if (ctx->format == KOF_FMT_PE) {
		const struct kof_pe_info *p = kof_pe(ctx);
		uint32_t i;

		if (!p->valid)
			return KOF_BROKEN;
		for (i = 0; i < p->sec_count; i++) {
			const struct kof_pe_sec *s = &p->sec[i];

			if (s->file_size && off >= s->file_off &&
			    off - s->file_off < s->file_size) {
				k->map_lo = s->file_off;
				k->map_hi = s->file_off + s->file_size;
				k->map_delta = (int64_t)(p->image_base +
							 s->mem_rva) -
					       (int64_t)s->file_off;
				k->map_ok = 1;
				return p->image_base + s->mem_rva +
				       (off - s->file_off);
			}
		}
		/* The headers map at the image base, one to one. */
		if (p->sec_count && off < p->sec[0].file_off) {
			k->map_lo = 0;
			k->map_hi = p->sec[0].file_off;
			k->map_delta = (int64_t)p->image_base;
			k->map_ok = 1;
			return p->image_base + off;
		}
		return KOF_BROKEN;
	}
	if (ctx->format == KOF_FMT_ELF) {
		const struct kof_elf_info *e = kof_elf(ctx);
		uint32_t i;

		/*
		 * A RELOCATABLE OBJECT HAS NO LOAD ADDRESS, AND THE FILE IS
		 * THE ONLY COHERENT ADDRESS SPACE IT HAS.
		 *
		 * A .ko carries no program header at all - readelf says so in
		 * as many words - so the loop below finds nothing and every
		 * instruction is decoded with an address of KOF_BROKEN. The
		 * consequence is silent and total: a relative branch is
		 * computed from that address, so `target` is broken for every
		 * call in the object, and anything matching a call against a
		 * relocation table compares two numbers that can never be
		 * equal. MEASURED - Diamorphine yielded 0 nodes from the
		 * symbol routine for this and no other reason.
		 *
		 * The identity is not a guess: a section's sh_addr in an
		 * ET_REL is zero, the linker has not placed anything yet, and
		 * kof_elf_relcalls already reports its sites as file offsets.
		 * Both sides then speak the same numbers.
		 */
		if (!e->seg_count) {
			k->map_lo = 0;
			k->map_hi = (uint64_t)-1;
			k->map_delta = 0;
			k->map_ok = 1;
			return off;
		}
		for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
			const struct kof_elf_seg *s = &e->seg[i];

			if (s->type != 1u || !s->file_size)   /* PT_LOAD */
				continue;
			if (off >= s->file_off &&
			    off - s->file_off < s->file_size) {
				k->map_lo = s->file_off;
				k->map_hi = s->file_off + s->file_size;
				k->map_delta = (int64_t)s->mem_addr -
					       (int64_t)s->file_off;
				k->map_ok = 1;
				return s->mem_addr + (off - s->file_off);
			}
		}
	}
	return KOF_BROKEN;
}

/*
 * AND THE WAY BACK, FOR A BRANCH THAT STAYS IN THE SAME SEGMENT.
 *
 * Which nearly every branch does: a relative displacement cannot leave the
 * image and a compiler does not emit one that leaves the section. The
 * window established above is a mapping in both directions, so the inverse
 * is the same single subtraction - and when the target IS somewhere else,
 * this falls through to the engine's one resolver rather than growing a
 * second copy of it.
 */
static uint64_t kdis_va_to_off(const struct kof_kdis *k,
			       const struct kof_obj_ctx *ctx, uint64_t va)
{
	if (k->map_ok) {
		uint64_t lo = (uint64_t)((int64_t)k->map_lo + k->map_delta);
		uint64_t hi = (uint64_t)((int64_t)k->map_hi + k->map_delta);

		if (va >= lo && va < hi)
			return (uint64_t)((int64_t)va - k->map_delta);
	}
	return kof_pz_addr_to_off(ctx, va);
}

/* ---- the cursor ---------------------------------------------------------- */

int kof_kdis_seek(struct kof_kdis *k, uint64_t off, int keep)
{
	if (!k)
		return 0;
	k->at = off;
	k->open = 1;
	/* A new walk may be a new object at the same context address - see
	 * the note on map_lo in kdis.h. */
	k->map_ok = 0;
	if (!keep) {
		kdis_state_reset(&k->st);
	}
	return 1;
}

int kof_kdis_reg(const struct kof_kdis *k, uint8_t r, uint64_t *out)
{
	return k ? kdis_state_reg(&k->st, r, out) : 0;
}

int kof_kdis_next(struct kof_kdis *k, const struct kof_obj_ctx *ctx,
		  const uint8_t *base, uint64_t size, struct kdis_insn *out)
{
	uint64_t left;
	uint32_t n;

	if (!k || !k->open || !ctx || !base || !out || k->at >= size)
		return 0;
	left = size - k->at;
	if (left > 16u)
		left = 16u;             /* the longest an instruction can be */

	/*
	 * THE DECODER IS kof_decode_x86 AND THERE IS NO SECOND ONE.
	 *
	 * This used to call NdDecodeEx itself, classify with a switch of its
	 * own and build its own operands - a complete copy of decode_x86.c
	 * standing beside it. The copy was written first and never caught
	 * up: when the enum gained KDIS_SYSCALL and KDIS_WIDEN and the
	 * decoder gained `wmask`, only one of the two learned them.
	 *
	 * MEASURED, and it is not a small drift: a `syscall` instruction came
	 * back as KDIS_OTHER, so nothing reading an object through this
	 * cursor could see a Linux system call AT ALL - on a static binary
	 * that is every capability the program has. `cdq` was the same, and
	 * `wmask` was zero for every instruction, which is what the constant
	 * map needs to know which registers an instruction destroys.
	 *
	 * One decoder now. Rule 10.
	 */
	n = kof_decode_x86(base + k->at, (uint32_t)left,
			   kdis_off_to_va(k, ctx, k->at),
			   ctx->arch == KOF_ARCH_X86_64 ? 64u : 32u, out);
	if (!n)
		return 0;
	out->at = k->at;
	n = out->n_op;
	if (out->target_va != KOF_BROKEN)
		out->target = kdis_va_to_off(k, ctx, out->target_va);

	/*
	 * AND AN INDIRECT BRANCH RESOLVED FROM WHAT IS KNOWN, which is the
	 * whole difference between decoding and pseudo-emulation.
	 *
	 * `jmp eax` has no target in the encoding, and a walk that gives up
	 * there gives up on every polymorphic stub - they all end by computing
	 * an address and going to it. When the constant map holds that
	 * register, or the modelled stack holds what a `ret` will take, the
	 * target IS known and saying so is not a guess.
	 *
	 * DONE BEFORE kdis_track, because a RET's target is the value still on
	 * the stack - tracking pops it.
	 */
	if (out->target == KOF_BROKEN) {
		uint64_t v = 0;
		int have = 0;

		if (out->op == KDIS_RET)
			have = kdis_state_stack_top(&k->st, &v);
		else if ((out->op == KDIS_JMP || out->op == KDIS_CALL) && n &&
			 out->o[0].kind == KDIS_O_REG && out->o[0].reg < 16u)
			have = kof_kdis_reg(k, out->o[0].reg, &v);
		if (have) {
			out->target_va = v;
			out->target = kdis_va_to_off(k, ctx, v);
		}
	}

	kdis_state_track(&k->st, out);
	k->at += out->len;
	return 1;
}
