/*
 * region_excluded - which regions "anywhere in the object" does not cover, decided by
 * the region's bit and not by how its enumerator is spelled.
 *
 * It was a substring test on the KOF_SCAN_* name (kof_mutation_region_excluded: "_HEAD",
 * "_SYM", "_SLIB"). The oracle below IS that test, kept here, and the check is that
 * kof_parser_region_unoffered says the same of EVERY region of EVERY parser - so the
 * move from a spelling to a bit changed no answer - plus the bits the spelling test
 * named and no parser lists (the host-built symbol halves), and a region that merely
 * contains the letters (an invented name) is not caught by a bit it does not hold.
 */

#include <stdio.h>
#include <string.h>
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/elf.h"

static int fails;

#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* The test this replaced, verbatim in effect. */
static int oracle_excluded(const char *enum_name)
{
	const char *p;

	if (!enum_name)
		return 1;
	for (p = enum_name; *p; p++) {
		if (!strncmp(p, "_HEAD", 5) || !strncmp(p, "_SYM", 4) || !strncmp(p, "_SLIB", 5))
			return 1;
	}
	return 0;
}

int main(void)
{
	uint32_t n, i, k, checked = 0, excluded = 0;
	const struct kof_parser *l = kof_parser_list(&n);

	CK(n == KOF_PARSER_COUNT);
	for (i = 0; i < n; i++) {
		uint32_t mask = kof_parser_region_unoffered(&l[i]);

		for (k = 0; k < l[i].n_regions; k++) {
			uint32_t bit = l[i].regions[k];
			const char *nm = l[i].region_name(bit);
			int want = oracle_excluded(nm), got = (mask & bit) != 0;

			if (want != got)
				printf("  format %u region %s: spelling says %d, bit says %d\n",
				       (unsigned)l[i].format, nm ? nm : "(null)", want, got);
			CK(want == got);
			checked++;
			excluded += (unsigned)got;
		}
		/* the symbol halves are built by the host and never offered, for any format */
		CK((mask & KOF_SCAN_SYM_IMP) && (mask & KOF_SCAN_SYM_EXP));
	}
	CK(kof_parser_region_unoffered(NULL) == KOF_SCAN_SYM);
	/* the known set: ELF headers and both library tails, every other format's header */
	CK(checked > 60u && excluded >= 20u);
	{
		const struct kof_parser *elf = kof_parser_of(KOF_FMT_ELF);

		CK(elf && (kof_parser_region_unoffered(elf) & KOF_SCAN_ELF_HEADERS));
		CK(elf && (kof_parser_region_unoffered(elf) & KOF_SCAN_ELF_SLIB_CODE));
		CK(elf && (kof_parser_region_unoffered(elf) & KOF_SCAN_ELF_SLIB_DATA));
		CK(elf && !(kof_parser_region_unoffered(elf) & KOF_SCAN_ELF_CODE));
		CK(elf && !(kof_parser_region_unoffered(elf) & KOF_SCAN_ELF_DATA));
	}
	if (fails) {
		printf("region_excluded: %d check(s) failed\n", fails);
		return 1;
	}
	printf("region_excluded: %u regions of %u parsers, bit and spelling agree (%u not offered)\n",
	       checked, n, excluded);
	return 0;
}
