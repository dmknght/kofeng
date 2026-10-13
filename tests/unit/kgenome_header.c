/*
 * kgenome_header - the one public header compiles ON ITS OWN.
 *
 * This translation unit includes <kgenome.h> and nothing else of the tree - no
 * engine header, no part header by path - and uses one thing from each of the
 * header's parts. If the umbrella ever needs an include its caller does not
 * have, or a part header stops being self-contained, this stops compiling: the
 * property is "a caller includes <kgenome.h> and nothing else", the same as
 * <uncoat.h> for kuncoat, and a compile is the only honest test of it.
 */

#include <kgenome.h>

#include <stdio.h>
#include <string.h>

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

int main(void)
{
	struct kgenome_budget b;
	struct kgenome_ledger l;
	struct kgenome_cell_insn in;
	static const uint8_t nop[] = { 0x90 };
	struct kgenome_diag_hit h;
	struct kgenome_func_set fs;

	/* the shared headers */
	kgenome_budget_default(&b, 100000, 0);
	CK(b.max_nodes >= KGENOME_NODES_MIN);
	kgenome_ledger_init(&l, 1000);
	CK(kgenome_ledger_charge(&l, 600));
	CK(!kgenome_ledger_charge(&l, 600));
	CK(l.status == KGENOME_OVER_BUDGET);
	CK(!strcmp(kgenome_status_name(KGENOME_TRUNCATED), "truncated"));

	/* genotype: the decoder's status is the lib's status */
	CK(KGENOME_INVALID == KGENOME_BAD_INPUT);
	/* celllysis */
	memset(&in, 0, sizeof in);
	CK(kgenome_cell_decode_x86(nop, 1, 0x1000, 64u, &in) == 1u);
	CK(in.op == KGENOME_CELL_NOP);
	/* phenotype: the lineage products */
	memset(&h, 0, sizeof h);
	CK(sizeof h.in / sizeof h.in[0] == 4u);
	CK(kgenome_diag_scan_status(NULL) == KGENOME_BAD_INPUT);
	/* genotype/image: the function set carries the lib's status */
	memset(&fs, 0, sizeof fs);
	CK(fs.status == KGENOME_OK);
	/* the emulator's constants */
	CK(KGENOME_EMU_PAGE == 4096u);

	printf("kgenome header: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
