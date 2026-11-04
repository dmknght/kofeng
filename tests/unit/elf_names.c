/*
 * elf_names - kof_elf_region_name and kof_elf_anomaly_name (analyzers/parsers/binaries/elf/elf_parse.h),
 * UNTESTED before this file (Phase 2 sweep of the ELF-analysis surface): grep of tests/lib/genome and
 * tests/unit found zero hits for either name before this file, and the PE-side twins
 * (kof_pe_region_name / kof_pe_anomaly_name) have none either - a paired-path gap, noted but out of this
 * ELF-only task's scope. These are ENGINE (libkofeng) functions, not libgenome, so this test lives in
 * tests/unit/ and not tests/lib/genome/ (CLAUDE.md section 12: a test that needs only one lib belongs in
 * tests/lib/<lib>/, the rest stay in tests/unit/).
 *
 * Both are table lookups with a different contract, by design: kof_elf_region_name takes one of the BIT
 * VALUES in kof_elf_region_bits[] (built from the same X-macro list as the switch, elf_parse.h
 * ELF_REGIONS), kof_elf_anomaly_name a plain small INDEX (the anomaly bits are 1ull<<index, elf_types.h;
 * the index is what a caller gets by walking the bits of the mask with ctz/ffs, never the mask itself).
 * Exhaustive over the whole small alphabet of each, plus the cap boundary (one past the last valid value,
 * and the type's extreme) per this project's test discipline.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include <genotype/image/elf_image.h>
#include "../../libkofeng/analyzers/parsers/binaries/elf/elf_parse.h"

static int fails;
#define CK(c) do { if (!(c)) { printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void)
{
	unsigned i;

	/* every declared region bit names itself, with the one spelling convention the header documents */
	CK(KOF_ELF_REGION_COUNT > 0);
	for (i = 0; i < KOF_ELF_REGION_COUNT; i++) {
		uint32_t bit = kof_elf_region_bits[i];
		const char *nm = kof_elf_region_name(bit);

		CK(nm != NULL && !strncmp(nm, "KOF_", 4) && strlen(nm) > 4);
		/* round trip: every OTHER declared bit gives a DIFFERENT name (no two regions collide) */
		{
			unsigned j;

			for (j = 0; j < KOF_ELF_REGION_COUNT; j++)
				if (j != i)
					CK(strcmp(nm, kof_elf_region_name(kof_elf_region_bits[j])) != 0);
		}
	}
	/* not a declared bit: 0, the OR of two declared bits (no case matches a combination), every bit of
	 * a 32-bit word outside the declared set, and the all-ones word */
	CK(kof_elf_region_name(0) == NULL);
	if (KOF_ELF_REGION_COUNT >= 2)
		CK(kof_elf_region_name(kof_elf_region_bits[0] | kof_elf_region_bits[1]) == NULL);
	CK(kof_elf_region_name(0xffffffffu) == NULL);
	for (i = 0; i < 32; i++) {
		uint32_t bit = 1u << i;
		unsigned j;
		int declared = 0;

		for (j = 0; j < KOF_ELF_REGION_COUNT; j++)
			if (kof_elf_region_bits[j] == bit)
				declared = 1;
		if (!declared)
			CK(kof_elf_region_name(bit) == NULL);
	}

	/* every anomaly index in range names itself; one past the end, and the extremes of `unsigned`, do not */
	for (i = 0; i < KGENOME_ELF_ANOM_COUNT; i++) {
		const char *nm = kof_elf_anomaly_name(i);
		unsigned j;

		CK(nm != NULL && *nm != 0);
		for (j = 0; j < KGENOME_ELF_ANOM_COUNT; j++)
			if (j != i)
				CK(strcmp(nm, kof_elf_anomaly_name(j)) != 0);
	}
	CK(kof_elf_anomaly_name(KGENOME_ELF_ANOM_COUNT) == NULL);
	CK(kof_elf_anomaly_name(KGENOME_ELF_ANOM_COUNT + 1u) == NULL);
	CK(kof_elf_anomaly_name(UINT_MAX) == NULL);
	CK(kof_elf_anomaly_name(UINT_MAX - 1u) == NULL);

	printf("elf_names: %d failure(s)\n", fails);
	return fails != 0;
}
