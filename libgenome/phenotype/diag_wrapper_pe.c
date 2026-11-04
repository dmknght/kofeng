/*
 * diag_wrapper_pe.c - THE PE OBSERVER of the walk's one decode.
 *
 * The walk (diag_wrapper_walk.c, pass_a) decodes every code byte once. What a PORTABLE EXECUTABLE adds to that decode is not an ELF fact and is not a flag in the shared loop: it is
 * the questions below, asked by the loop of an observer it made at the start of the extent (`struct kgenome_diag_wrapper_pe`). An object that is not a PE has `pe == NULL` and the loop does not call
 * the observer at all (one pointer test per instruction).
 *
 * THE RULES (each is a fact of the format, with what it was measured on):
 *   - IMPORT STUBS. `jmp [slot]` with the slot in the import address table is the whole body of an import stub; it is recorded (diag_walk_thunks) when it starts a function.
 *   - ZERO FILL. `00 00` decodes as `add [rax],al`: the linker's fill of a section's tail and of alignment. Inside code the same bytes are the high half of a jump-table entry, so a zero
 *     run is padding only when it reaches the end of the extent (joined to the padding run that stands in front of it).
 *   - THE MARK AFTER A CALL. A single `int3` standing right after a call is the compiler's mark that the call does not return, and is the function's own byte (the unwind table's end
 *     covers it: measured on the PE oracle, h/oracle.c); the alignment padding after it is not.
 * What PE does NOT do and the loop therefore skips: a `jmp X` at a function start is not a thunk (a basic block as often as a function), and there is no sigreturn stub.
 */
#include "diag_wrapper_private.h"
#include <genotype/image/pe_image.h>

static int stub_push(struct kgenome_diag_walk *wk, uint64_t at, uint64_t len, uint64_t slot, int iat, int start)
{
	if (wk->n_thk == wk->cap_thk) {
		uint32_t nc = kgenome_grow_cap(wk->cap_thk, 256u);
		struct kgenome_diag_stub *nv = nc ? realloc(wk->thk, (size_t)nc * sizeof *nv) : NULL;

		if (!nv)
			return 0;
		wk->thk = nv;
		wk->cap_thk = nc;
	}
	wk->thk[wk->n_thk++] = (struct kgenome_diag_stub){ at, len, slot, (uint8_t)iat, (uint8_t)start };
	return 1;
}

void kgenome_diag_wrapper_pe_start(struct kgenome_diag_wrapper_pe *o, const struct kgenome_obj *obj)
{
	o->pe = obj->format == KGENOME_FMT_PE ? kgenome_obj_pe(obj) : NULL;
	o->zero_from = UINT64_MAX;
	o->tboundary = 1;
}

/* Where a padding run that begins at `in` really begins: after the call's own mark. */
uint64_t kgenome_diag_wrapper_pe_pad_from(const struct kgenome_cell_insn *in, int prev_call, uint64_t from)
{
	if (prev_call && (in->op == KGENOME_CELL_INT || (in->op == KGENOME_CELL_NOP && in->len == 1u)))
		return in->at + 1u;
	return from;
}

/* A byte pair of zeros starts or continues the zero run; anything else ends it. */
void kgenome_diag_wrapper_pe_zero(struct kgenome_diag_wrapper_pe *o, const struct kgenome_diag_wrapper_ctx *c, const struct kgenome_cell_insn *in)
{
	if (in->len == 2u && in->at + 2u <= c->size && !(c->base[in->at] | c->base[in->at + 1u])) {
		if (o->zero_from == UINT64_MAX)
			o->zero_from = in->at;
	} else {
		o->zero_from = UINT64_MAX;
	}
}

/* Bytes that decode as nothing were stepped over at `at` (the first of them): the run of zeros goes on only through a zero byte. */
void kgenome_diag_wrapper_pe_data(struct kgenome_diag_wrapper_pe *o, const struct kgenome_diag_wrapper_ctx *c, uint64_t at)
{
	o->tboundary = 0;
	if (at < c->size && c->base[at] != 0u)
		o->zero_from = UINT64_MAX;
}

/* A jump through a fixed slot: the body of an import stub when it starts a function and the slot is an entry of the IAT (when the image declares one). 0: memory ran out. */
int kgenome_diag_wrapper_pe_stub(const struct kgenome_diag_wrapper_pe *o, struct kgenome_diag_wrapper_ctx *c, const struct kgenome_cell_insn *in)
{
	const uint64_t slot = kgenome_cell_slot_of(in, c->wide, 0);
	const struct kgenome_pe_dir *iat;

	if (in->op != KGENOME_CELL_JMP || !(in->flags & KGENOME_CELL_F_INDIRECT))
		return 1;
	iat = &o->pe->dir[KGENOME_PE_DIR_IAT];
	if (slot != KGENOME_BROKEN && slot >= o->pe->image_base &&
	    !stub_push(c->wk, in->at, in->len, slot,
		       !iat->size || (slot - o->pe->image_base >= iat->rva && slot - o->pe->image_base - iat->rva < iat->size), o->tboundary))
		return 0;
	return 1;
}

/* After an instruction: may an import stub start at the next one? (the instruction before ended a function or was padding: a stub follows) */
void kgenome_diag_wrapper_pe_boundary(struct kgenome_diag_wrapper_pe *o, const struct kgenome_diag_wrapper_ctx *c, const struct kgenome_cell_insn *in, int boundary)
{
	o->tboundary = boundary || (in->op == KGENOME_CELL_INT && in->at < c->size && c->base[in->at] == 0xccu) ||
		       (in->len == 2u && in->at + 2u <= c->size && !(c->base[in->at] | c->base[in->at + 1u]));
}

/* The extent is over at `end` (the decode reached it at `at`): the zero fill that reaches it is one run with the padding in front of it when they touch. 0: memory ran out. */
int kgenome_diag_wrapper_pe_close(const struct kgenome_diag_wrapper_pe *o, struct kgenome_diag_wrapper_ctx *c, uint64_t at, uint64_t end)
{
	struct kgenome_diag_walk *w = c->wk;

	if (o->zero_from == UINT64_MAX || at != end || o->zero_from >= at)
		return 1;
	if (w->n_pad >= 2u && w->pad[w->n_pad - 1u] == o->zero_from) {
		w->pad[w->n_pad - 1u] = at;
		return 1;
	}
	return kgenome_diag_wrapper_push_u64(&w->pad, &w->n_pad, &w->cap_pad, o->zero_from) &&
	       kgenome_diag_wrapper_push_u64(&w->pad, &w->n_pad, &w->cap_pad, at);
}
