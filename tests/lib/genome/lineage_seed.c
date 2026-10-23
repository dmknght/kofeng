/*
 * lineage_seed - STAGE 3: the code no walk from a function's entry reaches. The generator puts a few statements after
 * a function's last jump (code nothing jumps to and nothing falls into): flows inside it are found as an entry of its own,
 * every register and slot unknown, and every link written from it is MAY - the entry nothing proved - while the links of the
 * body the entry does reach are exactly what they are without the stage.
 *
 * The oracle runs such a region as a root of its own with every variable unknown and marks what it sees uncertain; the
 * same programs are also read WITHOUT the stage, where the region must contribute nothing.
 */
#include "lineage_check.h"

int main(int argc, char **argv)
{
	const unsigned feat = LG_F_CALL | LG_F_LOOP | LG_F_ICALL | LG_F_TAIL | LG_F_DEAD | LG_F_MEM;
	const unsigned all = KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_LOCS | KGENOME_LINEAGE_S_SUMM;
	long programs = 0, links = 0, stripped = 0;
	int n, found = 0;

	hk_args(argc, argv);
	n = (int)(60 * hk_scale());
	CK(lg_campaign(feat, KGENOME_LINEAGE_S_FLOW | KGENOME_LINEAGE_S_SEED, n, 3000, &programs, &links, &stripped, &found) == 0);
	CK(lg_campaign(feat, all | KGENOME_LINEAGE_S_SEED, n, 7000, &programs, &links, &stripped, &found) == 0);
	/* the same programs without the stage: the region is nothing */
	CK(lg_campaign(feat, all, n, 7000, &programs, &links, &stripped, &found) == 0);
	printf("lineage_seed: %ld programs, %ld links expected (%ld in the stripped twins, %d of them found), %d failure(s)\n", programs,
	       links, stripped, found, hk_fails);
	return hk_fails != 0;
}
