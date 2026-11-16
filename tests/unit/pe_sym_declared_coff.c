/*
 * pe_sym_declared_coff.c - kof_syms_declared's PE case (sym_any.c), which until this
 * fix always answered 0 and let kof_syms_build_grow (funcs.h) size the KSYM block at
 * the KOF_SYM_MAX_RECS floor (4096) for every PE, however many COFF symbols the file
 * actually declares. A table past the floor then always cost a second pass: the first
 * build hit ROOM, KOF_SYM_TRUNC_ROOM set, and syms_grow regrew at 4x and rebuilt.
 *
 * THE FIX (minor, efficiency only - the grow loop already handled an undersized guess
 * correctly, so nothing here changes what a scan sees). kof_syms_declared now reads
 * the COFF table's own NumberOfSymbols for a PE (kgenome_pe_coff_count, pe_coff_sym.c
 * - the same header-and-bounds read kgenome_pe_coff_syms already does, factored once
 * as coff_table_at so neither re-derives it) and kof_syms_build_grow ADDS the caller's
 * import count to it (the two are different symbols: one does not replace the other,
 * unlike the old `if (!decl ...)` fallback which only used imports->n when nothing
 * else was known).
 *
 * THE TEST is a differential on `*passes`, not a hostile-input exercise -
 * kgenome_pe_coff_count's own bounds-checking is pe_coff_sym.c's (tested through
 * kgenome_pe_coff_syms elsewhere; fntab_pe.c, hostile_image.c). A PE with more COFF
 * FUNCTION symbols than the floor is built once; the fixed code sizes the buffer from
 * the real declared count and needs exactly one pass. Flipping kof_syms_declared's PE
 * case back to `return 0;` (the old answer) reproduces the old cost on this same file:
 * the floor-sized first build is cut for ROOM and syms_grow takes a second pass to
 * reach the same, otherwise-identical final block - confirmed both ways while writing
 * this fix, left as a comment here since the old code is gone from the tree.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/pe_image.h>
#include "../lib/genome/fntab_pe_kit.h"
#include "../../libkofeng/kofcore/kofmod/kofsym.h"
#include "../../libkofeng/analyzers/parsers/binaries/funcs.h"

/* One more than KOF_SYM_MAX_RECS (4096): every one of these is a real FUNCTION record
 * (type 0x20, class EXTERNAL, section 1 = the one CODE section, value 0) that
 * kof_pe_syms_with's coff_put keeps, so the declared count and the final record count
 * are the same number - the table is not read twice to get two different answers. */
#define NSYM 4200u

static void t_pe_coff_declared_sizes_in_one_pass(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	static struct csym sy[NSYM];
	uint8_t *buf = NULL;
	uint32_t cap = 0, passes = 0, n, i;

	pb_init(&p, 0x20000, 0, 0x14c);
	pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0x1000);
	for (i = 0; i < NSYM; i++) {
		sy[i].value = 0;
		sy[i].sec = 1;          /* 1-based: the one section above */
		sy[i].type = 0x20u;     /* FUNCTION */
		sy[i].cls = 2u;         /* EXTERNAL */
		sy[i].aux = 0;
	}
	pb_syms(&p, sy, NSYM);
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));

	n = kof_syms_build_grow(KOF_FMT_PE, p.b, p.n, &info, NULL, &buf, &cap, &passes);
	CK(n > KOF_SYM_HDRLEN);
	CK(buf != NULL);
	if (buf) {
		/* the fix: sized from the real declared count, so one pass reaches a
		 * complete block - not cut for room, every one of the NSYM symbols kept */
		CK(passes == 1u);
		CK(!kof_sym_truncated(buf, n));
		CK(kof_sym_count(buf, n) == NSYM);
	}
	free(buf);
	free(p.b);
}

int main(void)
{
	t_pe_coff_declared_sizes_in_one_pass();
	printf("pe_sym_declared_coff: %d failure(s)\n", fails);
	return fails != 0;
}
