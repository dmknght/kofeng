/*
 * diag_origin.c - the origin map: which node each register and stack slot of the walk was last given its value by.
 * Part of the diagnose scan; see diag_scan.c for what it is for and diag_scan_private.h for what the
 * files share.
 */
#include "diag_scan_private.h"

void kgenome_diag_org_clear(struct kgenome_diag_orgs *w, uint8_t r)
{
	if (r < 16u) {
		w->reg[r].node = KGENOME_DIAG_ORG_NONE;
		/* The symbol goes with it: all three fields answer the same
		 * question - where did this value come from - and leaving one
		 * behind would have a register naming a symbol it no longer
		 * holds. */
		w->reg[r].symoff = 0;
		w->reg[r].symadd = 0;
	}
}

uint16_t kgenome_diag_org_of(const struct kgenome_diag_orgs *w, uint8_t r)
{
	return r < 16u ? w->reg[r].node : KGENOME_DIAG_ORG_NONE;
}

void kgenome_diag_org_set(struct kgenome_diag_orgs *w, uint8_t r, uint16_t node)
{
	if (r >= 16u)
		return;
	w->reg[r].node = node;
	/* One question, three fields - see struct kgenome_diag_org. A register that now
	 * holds what a node produced is no longer naming a symbol. */
	w->reg[r].symoff = 0;
	w->reg[r].symadd = 0;
}

/*
 * FORGET WHAT EVERY REGISTER THIS INSTRUCTION WRITES CAME FROM, then put
 * back the one case this follows.
 *
 * `wmask` and not the first operand, for the reason cell_track records: an
 * instruction writes registers it does not name, and names registers it
 * only reads. Getting that backwards on `mul` cost the i386 samples their
 * whole network half.
 */
void kgenome_diag_org_set_sym(struct kgenome_diag_orgs *w, uint8_t r, uint32_t symoff,
			  int32_t symadd)
{
	if (!w || r >= 16u)
		return;
	w->reg[r].node = KGENOME_DIAG_ORG_NONE;
	w->reg[r].symoff = symoff;
	w->reg[r].symadd = symadd;
}

uint32_t kgenome_diag_org_sym(const struct kgenome_diag_orgs *w, uint8_t r, int32_t *add)
{
	if (!w || r >= 16u)
		return 0;
	if (add)
		*add = w->reg[r].symadd;
	return w->reg[r].symoff;
}

void kgenome_diag_org_step(struct kgenome_diag_orgs *w, const struct kgenome_cell_insn *in)
{
	uint8_t r, d, e;

	if (in->op == KGENOME_CELL_PUSH) {
		uint16_t v = KGENOME_DIAG_ORG_NONE;

		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_REG)
			v = kgenome_diag_org_of(w, in->o[0].reg);
		if (w->n_stk < KGENOME_DIAG_ORG_STK)
			w->stk[w->n_stk].node = v;
		w->n_stk++;
		return;
	}
	if (in->op == KGENOME_CELL_POP) {
		uint16_t v = KGENOME_DIAG_ORG_NONE;

		if (w->n_stk) {
			w->n_stk--;
			if (w->n_stk < KGENOME_DIAG_ORG_STK)
				v = w->stk[w->n_stk].node;
		}
		/* A popped LIST names no operand; wmask has them all. */
		for (r = 0; r < 16u; r++)
			if (in->wmask & (1ull << r))
				kgenome_diag_org_clear(w, r);
		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_REG)
			kgenome_diag_org_set(w, in->o[0].reg, v);
		return;
	}
	if (in->op == KGENOME_CELL_XCHG && in->n_op > 1u &&
	    in->o[0].kind == KGENOME_CELL_O_REG && in->o[1].kind == KGENOME_CELL_O_REG) {
		uint16_t a;

		d = in->o[0].reg; e = in->o[1].reg;
		a = kgenome_diag_org_of(w, d);
		kgenome_diag_org_set(w, d, kgenome_diag_org_of(w, e));
		kgenome_diag_org_set(w, e, a);
		return;
	}
	if (in->op == KGENOME_CELL_MOV && in->n_op > 1u &&
	    in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].size >= 4u) {
		if (in->o[1].kind == KGENOME_CELL_O_REG) {
			/*
			 * A VALUE TAKEN FROM THE STACK POINTER IS A STACK
			 * ADDRESS, and that is a provenance of its own.
			 * msfvenom's i386 stager makes the stack executable
			 * and jumps into it; mprotect returns 0, so there is
			 * no pointer to follow from the allocation to the
			 * jump and the only thing that links them is that
			 * both addresses came off esp.
			 */
			kgenome_diag_org_set(w, in->o[0].reg,
				in->o[1].reg == (w->sp ? w->sp : KGENOME_CELL_REG_SP) ? KGENOME_DIAG_ORG_STACK
				: kgenome_diag_org_of(w, in->o[1].reg));
			return;
		}
		kgenome_diag_org_clear(w, in->o[0].reg);
		return;
	}
	/*
	 * AND/SHR/SHL OVER A STACK ADDRESS IS STILL A STACK ADDRESS. The
	 * i386 stager rounds esp down to a page with `shr 0xc; shl 0xc`
	 * before handing it to mprotect; killing the provenance there breaks
	 * the only link that sample has.
	 */
	if ((in->op == KGENOME_CELL_AND || in->op == KGENOME_CELL_SHR || in->op == KGENOME_CELL_SHL) &&
	    in->n_op && in->o[0].kind == KGENOME_CELL_O_REG &&
	    kgenome_diag_org_of(w, in->o[0].reg) == KGENOME_DIAG_ORG_STACK)
		return;

	for (r = 0; r < 16u; r++)
		if (in->wmask & (1ull << r))
			kgenome_diag_org_clear(w, r);
}

/* ---- the object's nodes --------------------------------------------------
 *
 * Flat and in the order the walk produced them, which for a linear sweep is
 * address order. Nothing depends on that order - see the note in
 * kofmod/kofdiagtree.h about why a provenance tree is not a sequence - but it
 * makes a dump readable, and a reader comparing two runs of the same object
 * gets the same file twice.
 */
