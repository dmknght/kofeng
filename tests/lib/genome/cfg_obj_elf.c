/*
 * cfg_obj_elf.c - the block layer's ELF seeds (phenotype/fntab_blocks.c): the entry point, .symtab, .dynsym and the unwind starts are seeds; a function
 * only a symbol names is read (SEED, not CALLED), the called ones are CALLED, the int3 fill between them is read by nothing. Built with the ELF writer of
 * the function-table tests (fntab_kit.h). Why the old tests missed it: (a) the layer is new.
 */
#include "fntab_kit.h"

#include <celllysis/cfg.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_private.h>

/* DISABLED by the owner 2026-11-16: these rows exercise the block layer's seeding (kgenome_fntab_blocks, phenotype/fntab_blocks.c), a function finder from decoded code;
 * the partition is made from metadata only and fntab_blocks.c is in #if 0. To re-enable: take this #if 0 out, the one in main and the one in fntab_blocks.c. */
#if 0
static const struct kgenome_cfg_obj_block *blk(const struct kgenome_cfg_obj *g, uint64_t off)
{
	const uint32_t i = kgenome_cfg_obj_block_at(g, off);

	return i != KGENOME_CFG_NONE && g->b[i].off == off ? &g->b[i] : NULL;
}

static void t_elf_seeds(void)
{
	unsigned dyn;

	for (dyn = 0; dyn < 2; dyn++) {
		static uint8_t t[0x40];
		const uint64_t va = 0x400000u + TEXT_OFF;
		struct sym s[4] = { { "s", va, 11, 0x12, 1 }, { "a", va + 0x10, 6, 0x12, 1 }, { "b", va + 0x20, 8, 0x12, 1 }, { "c", va + 0x30, 6, 0x12, 1 } };
		struct elf_in in;
		struct kgenome_elf_info ei;
		struct kgenome_obj o;
		struct kgenome_fntab_blocks_req rq;
		struct kgenome_cfg_obj g;
		uint32_t n, i, fill = 0;

		memset(&in, 0, sizeof in);
		in.c64 = 1; in.em = 62; in.base = 0x400000u; in.text = t; in.text_n = x86_text(t); in.sections = 1; in.sym = s; in.nsym = 4; in.dyn = (int)dyn;
		n = elf_build(&in, B);
		CK(parse(B, n, &ei, &o));
		memset(&rq, 0, sizeof rq);
		rq.obj = &o; rq.data = B; rq.data_n = n; rq.walk = kgenome_diag_walk_new();
		CK(kgenome_fntab_blocks(&rq, &g) == KGENOME_OK);
		CK(blk(&g, TEXT_OFF) && (blk(&g, TEXT_OFF)->flags & KGENOME_CFG_OBJ_B_SEED) && blk(&g, TEXT_OFF)->n_call == 2);
		CK(blk(&g, TEXT_OFF + 0x10) && (blk(&g, TEXT_OFF + 0x10)->flags & (KGENOME_CFG_OBJ_B_SEED | KGENOME_CFG_OBJ_B_CALLED)) == (KGENOME_CFG_OBJ_B_SEED | KGENOME_CFG_OBJ_B_CALLED));
		CK(blk(&g, TEXT_OFF + 0x30) && (blk(&g, TEXT_OFF + 0x30)->flags & (KGENOME_CFG_OBJ_B_SEED | KGENOME_CFG_OBJ_B_CALLED)) == KGENOME_CFG_OBJ_B_SEED);
		for (i = 0; i < g.n_b; i++)
			if (g.b[i].off >= TEXT_OFF + 11u && g.b[i].off < TEXT_OFF + 0x10u)
				fill++;
		CK(fill == 0 && g.n_fresh == 0 && g.n_e == 4);
		CK(g.e[0].src == (KGENOME_FN_S_ENTRY | (dyn ? KGENOME_FN_S_DYNSYM : KGENOME_FN_S_SYMTAB)));
		kgenome_cfg_obj_free(&g, NULL);
		kgenome_diag_walk_free(rq.walk);
	}
	/* a request the adapter refuses */
	{
		struct kgenome_cfg_obj g;
		struct kgenome_fntab_blocks_req rq;

		memset(&rq, 0, sizeof rq);
		CK(kgenome_fntab_blocks(&rq, &g) == KGENOME_BAD_INPUT && kgenome_fntab_blocks(NULL, &g) == KGENOME_BAD_INPUT && kgenome_fntab_blocks(&rq, NULL) == KGENOME_BAD_INPUT);
	}
}
#endif

int main(void)
{
#if 0 /* DISABLED by the owner 2026-11-16: the block layer's seeding */
	t_elf_seeds();
#else
	(void)elf_build; (void)parse; (void)x86_text; (void)B;   /* the kit's writer, kept for the rows when they are enabled again */
#endif
	printf("cfg_obj_elf: %d failure(s) of %lu checks\n", fails, checks);
	return fails != 0;
}
