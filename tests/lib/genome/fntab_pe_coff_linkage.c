/*
 * fntab_pe_coff_linkage.c - isolates the ROOT CAUSE of "PE-SYM-NAME-GAP"
 * (pe_elf_fixtures/INVENTORY_AND_PLAN.md group 23) at the libgenome layer.
 *
 * funcs.h's own comment on struct kgenome_func says the design: "The symbol this
 * function is, as the symbol block records it - its value and section - so a
 * tool shows the name from the block and not from here." The ELF strategy
 * (funcs.c:kgenome_fntab_symtab) honours that: it sets f.value = sy.value and
 * f.shndx = sy.shndx from the symbol it read. kgenome_fntab_pe_coff
 * (fntab_pe_coff.c) does NOT: `struct kgenome_func f; memset(&f, 0, sizeof f);`
 * is followed by f.off/f.source/f.len/f.end_source/f.flags, but f.value and
 * f.shndx are never touched, even though `val` (the COFF symbol's Value field)
 * and `sn` (its SectionNumber) are already local variables in the same loop.
 *
 * CONSEQUENCE, confirmed separately on a real unstripped mingw-w64 PE
 * (/mnt/games/normtest/pe_elf_fixtures/gen/scratch/g23/t23_x64.exe, x86_64,
 * COFF symbols local_calc@0x450, local_calc2@0x480, WinMain@0x4b0 - all present,
 * all nonzero values, not an ELF-VALUE0-NAME-GAP case): `kofexaminer --blocks`
 * shows every single function unit of that file as `func=(no symbol)`, even
 * though the boundaries (off/len/cfg_blocks) are all correct - the name path is
 * cut off entirely before it ever reaches a value/shndx comparison, because
 * there is nothing to compare: (value,shndx) is always (0,0) for a PE COFF
 * function. (kof_pe_syms_with, pe_sym.c, is the second half of the same gap -
 * it never emits a PE's own COFF local symbols into the KSYM block at all, only
 * import/export directory entries - so even a fixed value/shndx here would still
 * find no matching record; that half is engine-level, not libgenome, and is
 * reported separately, not tested here.)
 *
 * Coverage gap this closes: tests/lib/genome/fntab_pe.c:t_coff already builds
 * this exact fixture (five COFF symbols, one refused) and checks off/len/source/
 * end_source (fntab_pe.c:1159-1177), but NEVER reads ->value or ->shndx - which
 * is exactly why this fell through review (CLAUDE.md tests rule, reason (c):
 * the existing test checks the boundary result, not the full result).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/fntab.h>
#include <genotype/image/pe_image.h>
#include <phenotype/diag_scan.h>
#include <phenotype/diag_private.h>
#include <phenotype/frame.h>

#include "fntab_pe_kit.h"

/* Same fixture shape as fntab_pe.c:t_coff (kept deliberately small and separate
 * rather than touching that file, per the merge-gate manifest for this package). */
static void t_coff_value_shndx(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_fntab_list l;
	uint32_t t0;
	static const struct csym sy[] = {
		{ 0x00, 1, 0x20, 2, 0 },        /* main: no size */
		{ 0x20, 1, 0x20, 3, 9 },        /* helper: TotalSize 9, storage class STATIC */
	};

	pb_init(&p, 0x4000, 0, 0x14c);
	t0 = pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_entry(&p, 0);
	memset(p.b + t0, 0xcc, 0x70);
	memcpy(p.b + t0, "\x55\x8b\xec\x5d\xc3", 5);
	memcpy(p.b + t0 + 0x20, "\x55\x8b\xec\x33\xc0\x5d\xc3", 7);
	pb_syms(&p, sy, 2);
	pb_done(&p);

	{
		struct kgenome_obj obj;

		memset(&info, 0, sizeof info);
		memset(&obj, 0, sizeof obj);
		CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));
	}

	memset(&l, 0, sizeof l);
	kgenome_fntab_pe_coff(kof_buf_make(p.b, p.n), &info, &l);
	CK(l.n == 2);
	if (l.n == 2) {
		/* RED on the current code: value/shndx are left at the memset's 0,0
		 * for both entries, so these fail. The correct answer - what a
		 * consumer needs to find this function's name in the KSYM block
		 * later - is the raw COFF Value and the 1-based section number,
		 * exactly as the ELF symtab strategy already does (funcs.c). */
		CK(l.v[0].value == 0x00u && l.v[0].shndx == 1u);
		CK(l.v[1].value == 0x20u && l.v[1].shndx == 1u);
	}
	kgenome_fntab_list_free(&l);
	free(p.b);
}

int main(void)
{
	t_coff_value_shndx();
	printf("fntab_pe_coff_linkage: %d failure(s)\n", fails);
	return fails != 0;
}
