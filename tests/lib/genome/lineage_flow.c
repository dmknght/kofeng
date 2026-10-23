/*
 * lineage_flow - STAGE 1's substrate and its abstract locations: the links of one function, found by
 * following control flow over the registers and the stack slots (FLOW) and over a global and a field
 * of the object a node produced (LOCS), compared link for link with a concrete interpreter's account of the
 * generated program (lineage_ir.h) on four targets: ELF x86-64, ELF i386, PE x64, PE x86.
 *
 * THE GENERATOR draws frames through the stack pointer or the frame pointer, arguments loaded directly
 * or built in temporaries, imports reached through a stub, a slot or a thunk, `if` and `while`, a constant or an
 * unknown in place of a producer, a pointer plus an offset, a call through a pointer, and functions that are
 * called (opaquely: this test names no SUMM). THE ORACLE has no lattice: it runs every behaviour.
 * What it says every execution agrees on is MUST, what some does is MAY, and the engine is held to exactly that.
 */
#include "lineage_check.h"

int main(int argc, char **argv)
{
	const unsigned feat_base = LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL;
	long programs = 0, links = 0, stripped = 0;
	int n, found = 0;

	hk_args(argc, argv);
	n = (int)(60 * hk_scale());
	/* the registers and the frame alone */
	CK(lg_campaign(feat_base, KGENOME_LINEAGE_S_FLOW, n, 1000, &programs, &links, &stripped, &found) == 0);
	/* the frame plus globals and the object's fields, in programs that use them */
	CK(lg_campaign(feat_base | LG_F_MEM, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS, n, 5000, &programs, &links, &stripped, &found) == 0);
	/* the same programs read WITHOUT locations: a global and a field are an unknown value */
	CK(lg_campaign(feat_base | LG_F_MEM, KGENOME_LINEAGE_S_FLOW, n, 9000, &programs, &links, &stripped, &found) == 0);
	printf("lineage_flow: %ld programs, %ld links expected (%ld in the stripped twins, %d of them found), %d failure(s)\n", programs, links,
	       stripped, found, hk_fails);
	return hk_fails != 0;
}
