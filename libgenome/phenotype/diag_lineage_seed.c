/*
 * diag_lineage_seed.c - STAGE 3: the code no walk from a function's own entry reaches.
 * Part of the lineage stages; see diag_lineage_private.h.
 *
 * WHY THERE IS ANY. A function's entry is a place the partition chose - a symbol, or a call target when
 * the object kept no symbols - and the code the entry reaches through branches is its body. What a switch's
 * indirect jump leaves behind, the arms of a function the partition cut in two, a body entered only through a
 * pointer: none of it is reached from an entry, and a link inside it was never looked for. MEASURED on the
 * 100-file cells of the graph-research report, seeding such blocks as entries of their own added 336 links
 * to the static stripped ELF cell (212 of them on i386), 55 to the dynamic stripped one and 7 to a PE, and
 * nothing to the cells where the partition is the symbol table's (17 on static ELF with symbols). It
 * cost 1.2 to 5 times the walk it follows.
 *
 * WHAT IT CLAIMS. Less. A block entered by a seed is entered with every register `other` and nothing proved
 * about the frame, and about 3 in 20 of what it found was doubtful when read (padding between functions
 * and jump-table data decode as instructions too). So everything written from a seeded block is MAY -
 * the link passes through an entry nothing proved - and it never joins into a block the function's own
 * entry reached (propagate refuses it), so the links of the real body are exactly what they were without it.
 * A seeded block does not speak for the function either: its returns and its parameters are not the
 * function's summary. What it does know is the frame pointer (see frame_pointer).
 *
 * WHICH BLOCKS. Selected by predicate (the SEED row of diag_lineage_chain.c): an unreached block that holds a producer or a
 * call to a function of the object that reaches a node. A seeded entry knows nothing, so a token can only come from a producer
 * in the blocks it enters (and what they flow to, which the walk reaches by itself); and a call there is a context of its
 * callee. A block with neither adds no link and no context. The links are the same as seeding every unreached block
 * (tests/lib/genome/lineage_chain.c holds the two to it).
 */
#include "diag_lineage_private.h"

/* How far below a function's frame pointer a seeded entry puts its stack pointer: more than any frame. */
#define KGENOME_LINEAGE_SEED_DEPTH (1 << 20)

/*
 * WHAT A SEEDED ENTRY KNOWS: nothing - except the frame pointer, when the function has one. A function that keeps
 * its frame behind a frame pointer names every local through it (`[rbp-0x18]`), and the prologue that sets it is the first
 * instructions of the function; a block entered "from nowhere" is in the same frame, so its `[rbp-0x18]` is that slot and not
 * a place the walk cannot name. Read by stepping the prologue (what comes before the first call or branch) from the entry
 * state: when that leaves rbp holding a stack address, a seeded entry holds the same. A function that uses rbp for
 * something else leaves it unknown and so does the entry. THE STACK POINTER is a fresh base, and below the frame: with a
 * frame pointer the locals are the slots just under it, and a base of 0 put the block's pushes on top of them (a push and a
 * local naming one slot: measured, a link from a call whose result had only been pushed). It is far enough down that
 * what the block pushes and pops is consistent among itself and never meets a local.
 */
static void frame_pointer(struct kgenome_lineage *L, struct kgenome_lineage_val *bp)
{
	struct kgenome_lineage_state e;
	uint32_t i;

	kgenome_lineage_state_entry(L, &e, 0);
	for (i = 0; i < L->n_in; i++) {
		const struct kgenome_cell_insn *in = &L->in[i];

		if (in->op == KGENOME_CELL_CALL || in->op == KGENOME_CELL_JMP || in->op == KGENOME_CELL_JCC ||
		    in->op == KGENOME_CELL_LOOP || in->op == KGENOME_CELL_RET)
			break;
		kgenome_lineage_state_step(L, &e, in);
	}
	kgenome_lineage_val_other(bp);
	if (e.r[KGENOME_CELL_REG_BP].k == KGENOME_LINEAGE_A_STACK) {
		bp->k = KGENOME_LINEAGE_A_STACK;
		bp->v = e.r[KGENOME_CELL_REG_BP].v;
	}
	kgenome_lineage_state_free(L, &e);
}

void kgenome_lineage_seed(struct kgenome_lineage *L, struct kgenome_lineage_cfg *g, int all)
{
	struct kgenome_lineage_val bp;
	uint32_t b;

	frame_pointer(L, &bp);
	for (b = 0; b < g->nb; b++) {
		struct kgenome_lineage_state e;

		if (g->bs[b].valid || (!all && !kgenome_lineage_seed_block(g, b)))
			continue;
		kgenome_lineage_state_entry(L, &e, 0);
		e.seeded = 1;
		e.r[KGENOME_CELL_REG_BP] = bp;
		if (bp.k == KGENOME_LINEAGE_A_STACK)
			e.sp = (int32_t)(bp.v - KGENOME_LINEAGE_SEED_DEPTH);
		kgenome_lineage_cfg_enter(g, b, &e);
		if (!kgenome_lineage_cfg_run(L, g))
			return;
	}
}
