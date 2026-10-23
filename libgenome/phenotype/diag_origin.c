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
		/* The symbol, the second producer and the weakness go with it: they all answer the same
		 * question - where did this value come from - and leaving one
		 * behind would have a register naming a symbol it no longer
		 * holds. */
		memset(w->reg[r].alt_p1, 0, sizeof w->reg[r].alt_p1);
		w->reg[r].may = 0;
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
	/* One question, several fields - see struct kgenome_diag_org. A register that now
	 * holds what a node produced is no longer naming a symbol, and it holds it on every path. */
	memset(w->reg[r].alt_p1, 0, sizeof w->reg[r].alt_p1);
	w->reg[r].may = 0;
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
	memset(w->reg[r].alt_p1, 0, sizeof w->reg[r].alt_p1);
	w->reg[r].may = 0;
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
		uint16_t v = KGENOME_DIAG_ORG_NONE, alt[KGENOME_DIAG_ORG_ALT] = { 0 };
		uint8_t may = 0;

		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg < 16u) {
			v = w->reg[in->o[0].reg].node;
			memcpy(alt, w->reg[in->o[0].reg].alt_p1, sizeof alt);
			may = w->reg[in->o[0].reg].may;
		}
		if (w->n_stk >= KGENOME_DIAG_ORG_STK) {
			/* the slot this push reuses belongs to the push KGENOME_DIAG_ORG_STK below it */
			if (w->stk[w->n_stk % KGENOME_DIAG_ORG_STK] != KGENOME_DIAG_ORG_NONE &&
			    w->n_stk - KGENOME_DIAG_ORG_STK >= w->n_lost)
				w->stk_cut = 1;         /* an origin that is gone for good */
			if (w->n_stk - KGENOME_DIAG_ORG_STK + 1u > w->n_lost)
				w->n_lost = w->n_stk - KGENOME_DIAG_ORG_STK + 1u;
		}
		w->stk[w->n_stk % KGENOME_DIAG_ORG_STK] = v;
		memcpy(w->stk_alt_p1[w->n_stk % KGENOME_DIAG_ORG_STK], alt, sizeof alt);
		w->stk_may[w->n_stk % KGENOME_DIAG_ORG_STK] = may;
		w->n_stk++;
		return;
	}
	if (in->op == KGENOME_CELL_POP) {
		uint16_t v = KGENOME_DIAG_ORG_NONE, alt[KGENOME_DIAG_ORG_ALT] = { 0 };
		uint8_t may = 0;

		if (w->n_stk) {
			w->n_stk--;
			if (w->n_stk >= w->n_lost) {
				v = w->stk[w->n_stk % KGENOME_DIAG_ORG_STK];
				memcpy(alt, w->stk_alt_p1[w->n_stk % KGENOME_DIAG_ORG_STK], sizeof alt);
				may = w->stk_may[w->n_stk % KGENOME_DIAG_ORG_STK];
			}
		}
		/* A popped LIST names no operand; wmask has them all. */
		for (r = 0; r < 16u; r++)
			if (in->wmask & (1ull << r))
				kgenome_diag_org_clear(w, r);
		if (in->n_op && in->o[0].kind == KGENOME_CELL_O_REG && in->o[0].reg < 16u) {
			kgenome_diag_org_set(w, in->o[0].reg, v);
			memcpy(w->reg[in->o[0].reg].alt_p1, alt, sizeof alt);
			w->reg[in->o[0].reg].may = may;
		}
		return;
	}
	if (in->op == KGENOME_CELL_XCHG && in->n_op > 1u &&
	    in->o[0].kind == KGENOME_CELL_O_REG && in->o[1].kind == KGENOME_CELL_O_REG) {
		struct kgenome_diag_org a;

		d = in->o[0].reg; e = in->o[1].reg;
		if (d >= 16u || e >= 16u)
			return;
		a = w->reg[d];
		w->reg[d] = w->reg[e];
		w->reg[e] = a;
		/* the symbol was never swapped (it is a different question) and a node made here is not one */
		w->reg[d].symoff = w->reg[e].symoff = 0;
		w->reg[d].symadd = w->reg[e].symadd = 0;
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
			if (in->o[1].reg == (w->sp ? w->sp : KGENOME_CELL_REG_SP)) {
				kgenome_diag_org_set(w, in->o[0].reg, KGENOME_DIAG_ORG_STACK);
			} else if (in->o[0].reg < 16u && in->o[1].reg < 16u) {
				const struct kgenome_diag_org src = w->reg[in->o[1].reg];

				/* the whole origin moves: the second producer and the weakness with it */
				kgenome_diag_org_set(w, in->o[0].reg, src.node);
				memcpy(w->reg[in->o[0].reg].alt_p1, src.alt_p1, sizeof src.alt_p1);
				w->reg[in->o[0].reg].may = src.may;
			} else {
				kgenome_diag_org_clear(w, in->o[0].reg);
			}
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

/* ---- WHAT THE LINEAR WALK DOES AT A CONTROL TRANSFER ------------------------------------------
 *
 * See the note in diag_private.h. The origin map is one straight line's; these are what a call, a
 * return and a join of two paths do to it, so that a link that comes out of the walk is a link the
 * program can produce and is MAY when it is not on every path.
 */
int kgenome_diag_org_any(const struct kgenome_diag_orgs *w)
{
	uint32_t i;

	for (i = 0; i < 16u; i++)
		if (w->reg[i].node != KGENOME_DIAG_ORG_NONE)
			return 1;
	for (i = w->n_lost; i < w->n_stk; i++)
		if (w->stk[i % KGENOME_DIAG_ORG_STK] != KGENOME_DIAG_ORG_NONE)
			return 1;
	return 0;
}

void kgenome_diag_org_link(struct kgenome_diag_scan *s, struct kgenome_diag_hit *h,
			   const struct kgenome_diag_orgs *w, uint8_t r, uint8_t role, uint8_t kind)
{
	const struct kgenome_diag_org *o;
	unsigned i;

	if (!h || r >= 16u)
		return;
	o = &w->reg[r];
	if (o->node == KGENOME_DIAG_ORG_NONE)
		return;
	(void)kgenome_diag_note_in_how(s, h, o->node, role, kind,
				       o->may ? KGENOME_DIAG_LINK_MAY : KGENOME_DIAG_LINK_PROVEN);
	for (i = 0; i < KGENOME_DIAG_ORG_ALT && o->alt_p1[i]; i++)
		(void)kgenome_diag_note_in_how(s, h, (uint16_t)(o->alt_p1[i] - 1u), role, kind,
					       KGENOME_DIAG_LINK_MAY);
}

void kgenome_diag_org_demote(struct kgenome_diag_orgs *w, uint16_t mask)
{
	uint32_t i;

	for (i = 0; i < 16u; i++)
		if ((mask & (1u << i)) && w->reg[i].node != KGENOME_DIAG_ORG_NONE)
			w->reg[i].may = 1;
}

void kgenome_diag_org_kill(struct kgenome_diag_orgs *w, uint16_t mask)
{
	uint8_t r;

	for (r = 0; r < 16u; r++)
		if (mask & (1u << r))
			kgenome_diag_org_clear(w, r);
}

int kgenome_diag_org_kill_stack(struct kgenome_diag_orgs *w)
{
	uint32_t i;
	int lost = 0;

	for (i = w->n_lost; i < w->n_stk; i++)
		if (w->stk[i % KGENOME_DIAG_ORG_STK] != KGENOME_DIAG_ORG_NONE)
			lost = 1;
	/* an empty ring, and not one that remembers a depth: the next function starts at the bottom of its own
	 * frame (a phantom depth of a hundred slots was MEASURED to make the ring overflow in a long window) */
	w->n_stk = 0;
	w->n_lost = 0;
	return lost;
}

/* One register's two paths. `b` NULL: the path that holds nothing. 1 when a producer past the four is dropped. */
static int rec_merge(struct kgenome_diag_org *a, const struct kgenome_diag_org *b)
{
	static const struct kgenome_diag_org none = { KGENOME_DIAG_ORG_NONE, { 0 }, 0, 0, 0 };
	uint16_t pa[1u + KGENOME_DIAG_ORG_ALT], pb[1u + KGENOME_DIAG_ORG_ALT];
	uint16_t d[2u * (1u + KGENOME_DIAG_ORG_ALT)];
	unsigned na = 0, nb = 0, n = 0, i, k, in_b = 0;
	int lost = 0;

	if (!b)
		b = &none;
	/*
	 * A REGISTER THIS PATH HAS NO PRODUCER IN STAYS WITHOUT ONE, whatever the other path holds. The other
	 * path's producer could reach the consumer too - a link - but it would be a link the walk never made,
	 * and bringing a killed origin back at every join keeps windows open for the length of the function
	 * (MEASURED: 4 of 300 corpus files turned from whole to cut on the stack ring). Two producers, or one
	 * producer and a path with none, are what is merged (W4); one the walk already lost is not found again.
	 */
	if (a->node == KGENOME_DIAG_ORG_NONE)
		return 0;
	if (a->node == b->node && !memcmp(a->alt_p1, b->alt_p1, sizeof a->alt_p1) && a->may == b->may &&
	    a->symoff == b->symoff && a->symadd == b->symadd)
		return 0;
	/* the producers of each path, the node first, and the distinct ones of both in the walk's order */
	if (a->node != KGENOME_DIAG_ORG_NONE)
		pa[na++] = a->node;
	for (i = 0; na && i < KGENOME_DIAG_ORG_ALT && a->alt_p1[i]; i++)
		pa[na++] = (uint16_t)(a->alt_p1[i] - 1u);
	if (b->node != KGENOME_DIAG_ORG_NONE)
		pb[nb++] = b->node;
	for (i = 0; nb && i < KGENOME_DIAG_ORG_ALT && b->alt_p1[i]; i++)
		pb[nb++] = (uint16_t)(b->alt_p1[i] - 1u);
	for (i = 0; i < na + nb; i++) {
		const uint16_t v = i < na ? pa[i] : pb[i - na];

		for (k = 0; k < n; k++)
			if (d[k] == v)
				break;
		if (k == n)
			d[n++] = v;
	}
	/* the paths hold the same producers when every one of a's is b's and the counts agree */
	for (i = 0; i < na; i++) {
		for (k = 0; k < nb; k++)
			if (pa[i] == pb[k])
				break;
		in_b += k < nb;
	}
	if (n > 1u + KGENOME_DIAG_ORG_ALT) {
		lost = 1;
		n = 1u + KGENOME_DIAG_ORG_ALT;
	}
	{
		const int same_set = na == nb && in_b == na;
		const uint8_t may = (uint8_t)(a->may | b->may | (same_set ? 0u : 1u));

		a->node = n ? d[0] : KGENOME_DIAG_ORG_NONE;
		memset(a->alt_p1, 0, sizeof a->alt_p1);
		for (i = 1; i < n; i++)
			a->alt_p1[i - 1u] = (uint16_t)(d[i] + 1u);
		a->may = n ? may : 0u;
	}
	if (a->symoff != b->symoff || a->symadd != b->symadd) {
		a->symoff = 0;
		a->symadd = 0;
	}
	return lost;
}

int kgenome_diag_org_merge(struct kgenome_diag_orgs *to, const struct kgenome_diag_orgs *from)
{
	uint32_t i;
	int lost = 0;

	for (i = 0; i < 16u; i++)
		lost |= rec_merge(&to->reg[i], from ? &from->reg[i] : NULL);
	/*
	 * THE STACK, slot by slot from the bottom: slot i is the i-th push on both paths. A slot the other path
	 * does not hold (it is shallower, or the ring wrapped past it) is the path that holds nothing there, so
	 * what the walk's own path pushed is MAY. The walk's depth stays its own: it pops what it pushed.
	 */
	for (i = to->n_lost; i < to->n_stk; i++) {
		const unsigned s = i % KGENOME_DIAG_ORG_STK;
		struct kgenome_diag_org a = { to->stk[s], { 0 }, to->stk_may[s], 0, 0 };
		struct kgenome_diag_org b = { KGENOME_DIAG_ORG_NONE, { 0 }, 0, 0, 0 };
		int have = 0;

		memcpy(a.alt_p1, to->stk_alt_p1[s], sizeof a.alt_p1);
		if (from && i >= from->n_lost && i < from->n_stk) {
			b.node = from->stk[s];
			memcpy(b.alt_p1, from->stk_alt_p1[s], sizeof b.alt_p1);
			b.may = from->stk_may[s];
			have = 1;
		}
		lost |= rec_merge(&a, have ? &b : NULL);
		to->stk[s] = a.node;
		memcpy(to->stk_alt_p1[s], a.alt_p1, sizeof a.alt_p1);
		to->stk_may[s] = a.may;
	}
	return lost;
}

/* ---- the object's nodes --------------------------------------------------
 *
 * Flat and in the order the walk produced them, which for a linear sweep is
 * address order. Nothing depends on that order - see the note in
 * kofmod/kofdiagtree.h about why a provenance tree is not a sequence - but it
 * makes a dump readable, and a reader comparing two runs of the same object
 * gets the same file twice.
 */
