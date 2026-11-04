/*
 * pe_export_sym_flags.c - group 17 (import-by-ordinal, forwarded exports) of the PE/ELF
 * architecture-measurement fixture campaign (pe_elf_fixtures/INVENTORY_AND_PLAN.md).
 *
 * Import-by-ordinal is already exhaustively covered elsewhere (tests/lib/genome/
 * imports_fuzz.c fuzzes random ordinal/name mixes against an independent oracle,
 * tests/lib/genome/callnames.c and image_pe_attack.c pin ordinal display and hostile
 * ordinal tables) - nothing new to add there.
 *
 * Forwarded exports ARE already detected correctly on the BOUNDARY side
 * (kgenome_fntab_pe_export, pinned by tests/lib/genome/fntab_pe.c:t_exports and
 * t_export_forwarder_in_code: a forwarder's RVA, lying inside the export directory's
 * own [rva, rva+size) range, is excluded and never taken as a function start).
 *
 * This file is the NAME side of the same directory: kgenome_pe_exports (pe_image.c),
 * the walk kof_pe_syms_with/export_put (pe_sym.c) uses to put an export into the KSYM
 * symbol block. Reading kgenome_pe_exports (pe_image.c, no lo/hi forwarder check at
 * all, unlike its sibling kgenome_fntab_pe_export) found it does NOT skip a forwarder:
 * the forwarder string's own RVA is handed to export_put as if it were a function
 * address. export_put then computes KOF_SYM_F_IN_EXEC as `frva != 0`, with no check of
 * which section frva actually lands in - wrong for the forwarder (not a code address at
 * all) AND for a plain DATA export (a real address, but not inside an executable
 * section). KOF_SYM_F_IN_EXEC's own doc (kofmod/kofsym.h) says it is "the flags of the
 * SECTION the symbol lands in"; elf_sym.c computes it that way (SHF_EXECINSTR of the
 * real section); pe_sym.c's export_put does not.
 *
 * KNOWN DEFECT PE-EXPFWD-INEXEC (2026-11-05, M): see kgenome_pe_exports (pe_image.c).
 * This file PINS the current (wrong) behaviour so a fix flips these three rows.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <kgenome.h>
#include <genotype/image/pe_image.h>
#include "../lib/genome/fntab_pe_kit.h"
#include "../../libkofeng/analyzers/parsers/binaries/pe/pe_sym.h"

static const uint8_t *find_rec(const uint8_t *b, uint32_t n, const char *needle)
{
	uint32_t i;
	const uint8_t *r;

	for (i = 0; (r = kof_sym_rec(b, n, i)) != NULL; i++) {
		uint32_t l;
		const char *nm = kof_sym_name(b, n, r, &l);

		if (nm && l == strlen(needle) && !memcmp(nm, needle, l))
			return r;
	}
	return NULL;
}

/* Three named exports: "Alpha" (a real function in .text - IN_EXEC should be set),
 * "DataBlob" (a real address, but in .data - not executable), "Forward" (a forwarder:
 * its RVA lies inside the export directory itself, [0x3000, 0x3100), and is the
 * ADDRESS OF A STRING "other.Func", never code). */
static void t_export_forwarder_and_data_sym(void)
{
	struct pb p;
	struct kgenome_pe_info info;
	struct kgenome_obj obj;
	static uint8_t blk[8192];
	uint32_t x, n;
	const uint8_t *alpha, *data, *fwd;

	pb_init(&p, 0x4000, 0, 0x14c);
	pb_sec(&p, ".text", 0x1000, 0x200, 0x200, CH_CODE);
	pb_sec(&p, ".data", 0x2000, 0x200, 0x200, CH_DATA);
	x = pb_sec(&p, ".edata", 0x3000, 0x200, 0x200, CH_RDATA);
	pb_entry(&p, 0x1000);
	memset(p.b + 0x400 /* .text file offset */, 0xcc, 0x200);
	memcpy(p.b + 0x400, "\x55\x8b\xec\x5d\xc3", 5);         /* push ebp; mov ebp,esp; pop ebp; ret */
	w(p.b + x + 20, 3, 4);                                   /* NumberOfFunctions */
	w(p.b + x + 24, 3, 4);                                   /* NumberOfNames */
	w(p.b + x + 28, 0x3040, 4);                              /* AddressOfFunctions */
	w(p.b + x + 32, 0x3050, 4);                              /* AddressOfNames */
	w(p.b + x + 36, 0x3060, 4);                              /* AddressOfNameOrdinals */
	w(p.b + x + 0x40, 0x1000, 4);                            /* Alpha -> .text (real code) */
	w(p.b + x + 0x44, 0x2000, 4);                            /* DataBlob -> .data (not code) */
	w(p.b + x + 0x48, 0x3090, 4);                            /* Forward -> inside [0x3000,0x3100): a forwarder */
	w(p.b + x + 0x50, 0x3070, 4);
	w(p.b + x + 0x54, 0x3078, 4);
	w(p.b + x + 0x58, 0x3084, 4);
	w(p.b + x + 0x60, 0, 2); w(p.b + x + 0x62, 1, 2); w(p.b + x + 0x64, 2, 2);
	memcpy(p.b + x + 0x70, "Alpha", 6);
	memcpy(p.b + x + 0x78, "DataBlob", 9);
	memcpy(p.b + x + 0x84, "Forward", 8);
	memcpy(p.b + x + 0x90, "other.Func", 11);                /* the forwarder string itself */
	pb_dir(&p, KGENOME_PE_DIR_EXPORT, 0x3000, 0x100);
	pb_done(&p);

	memset(&info, 0, sizeof info);
	memset(&obj, 0, sizeof obj);
	CK(kgenome_pe_image_parse(kof_buf_make(p.b, p.n), &info, &obj));

	n = kof_pe_syms(kof_buf_make(p.b, p.n), &info, blk, sizeof blk);
	CK(n >= KOF_SYM_HDRLEN && kof_sym_count(blk, n) == 3u);

	alpha = find_rec(blk, n, "Alpha");
	data = find_rec(blk, n, "DataBlob");
	fwd = find_rec(blk, n, "Forward");
	CK(alpha && data && fwd);
	if (!alpha || !data || !fwd)
		return;

	/* correct: a real .text address is flagged IN_EXEC */
	CK((alpha[KOF_SYM_R_FLAGS] & KOF_SYM_F_IN_EXEC) != 0);
	CK(kof_sym_u64(alpha, KOF_SYM_R_VALUE) == 0x1000u);

	/* KNOWN DEFECT PE-EXPFWD-INEXEC (2026-11-05, M): this row pins it, green until fixed - a
	 * .data address is not executable, but export_put flags it IN_EXEC anyway (it only tests
	 * "frva != 0", never which section frva lands in). */
	CK((data[KOF_SYM_R_FLAGS] & KOF_SYM_F_IN_EXEC) != 0);
	CK(kof_sym_u64(data, KOF_SYM_R_VALUE) == 0x2000u);

	/* KNOWN DEFECT PE-EXPFWD-INEXEC (2026-11-05, M): this row pins it, green until fixed -
	 * "Forward" is a forwarder (kgenome_fntab_pe_export already excludes this exact RVA range
	 * from the function table, t_export_forwarder_in_code); kgenome_pe_exports has no such check
	 * and hands export_put the forwarder STRING's RVA as if it were a function address, which
	 * export_put then also flags IN_EXEC. */
	CK((fwd[KOF_SYM_R_FLAGS] & KOF_SYM_F_IN_EXEC) != 0);
	CK(kof_sym_u64(fwd, KOF_SYM_R_VALUE) == 0x3090u);
	free(p.b);
}

int main(void)
{
	t_export_forwarder_and_data_sym();
	printf("pe_export_sym_flags: %d failure(s)\n", fails);
	return fails != 0;
}
