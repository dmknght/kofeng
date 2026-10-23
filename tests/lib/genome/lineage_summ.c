/*
 * lineage_summ - STAGE 2: what a call to a function of the program means, computed callee first. A producer in one
 * function reaches a node in another through a parameter, through a return, through a chain of helpers, through a
 * function that calls itself, through a tail jump; the links are MUST when one caller supplies one producer and no path
 * inside supplies another, MAY when several callers, several producers or a constant on some path do.
 *
 * COMPARED LINK FOR LINK with the oracle (lineage_ir.h), which here runs the program from its entry and descends into
 * every call, so each caller's value reaches the callee's nodes as it really would. Programs are generated with
 * calls (a function calls those after it), recursion (a function that calls itself under an unknown condition), tail
 * jumps, loops, globals and the object's fields, on the four targets.
 */
#include "lineage_check.h"

int main(int argc, char **argv)
{
	const unsigned feat = LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL | LG_F_REC | LG_F_MEM;
	long programs = 0, links = 0, stripped = 0;
	int n, found = 0;

	hk_args(argc, argv);
	n = (int)(80 * hk_scale());
	CK(lg_campaign(feat, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SUMM, n, 2000, &programs, &links, &stripped, &found) == 0);
	CK(lg_campaign(feat, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS | KGENOME_LINEAGE_S_SUMM, n, 6000, &programs, &links,
		       &stripped, &found) == 0);
	CK(lg_campaign(feat & ~(unsigned)LG_F_REC, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS | KGENOME_LINEAGE_S_SUMM, n,
		       11000, &programs, &links, &stripped, &found) == 0);
	printf("lineage_summ: skipped %ld/%ld/%ld (room/paths/code)\n", lg_skip[0], lg_skip[1], lg_skip[2]);
	printf("lineage_summ: %ld programs, %ld links expected (%ld in the stripped twins, %d of them found), %d failure(s)\n",
	       programs, links, stripped, found, hk_fails);
	return hk_fails != 0;
}
