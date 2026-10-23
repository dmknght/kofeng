/*
 * diag_class.c - the class of an object, and the plan of lineage stages for it.
 * Part of the diagnose scan; the stages are described in diag_lineage.h.
 */
#include <stdint.h>

#include "diag_lineage.h"
#include <genotype/image/elf_types.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/pe_types.h>
#include <celllysis/arch.h>

#define KGENOME_PT_INTERP 3u

unsigned kgenome_diag_class_of(const struct kgenome_obj *obj)
{
	unsigned c = 0;
	uint32_t i;

	if (!obj || !obj->file_header)
		return 0;
	if (obj->arch == KGENOME_ARCH_X86_64)
		c |= KGENOME_CLASS_WIDE | KGENOME_CLASS_X86;
	else if (obj->arch == KGENOME_ARCH_X86)
		c |= KGENOME_CLASS_X86;
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		if (!e->valid)
			return 0;
		c |= KGENOME_CLASS_ELF;
		if (!e->sec_count)
			c |= KGENOME_CLASS_NOSECT;
		if (e->e_type == KGENOME_ELF_REL)
			c |= KGENOME_CLASS_REL;
		/* The loader's own test for "this needs a dynamic linker" - the one the diagnose gate uses. */
		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
			if (e->seg[i].type == KGENOME_PT_INTERP) {
				c |= KGENOME_CLASS_DYNAMIC;
				break;
			}
		for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
			if (e->sec[i].type == KGENOME_ELF_SHT_SYMTAB) {
				c |= KGENOME_CLASS_SYMBOLS;
				break;
			}
	} else if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		if (!p->valid)
			return 0;
		c |= KGENOME_CLASS_PE;
		if (p->dir[KGENOME_PE_DIR_DEBUG].rva && p->dir[KGENOME_PE_DIR_DEBUG].size)
			c |= KGENOME_CLASS_SYMBOLS;
		if (p->clr_off)
			c |= KGENOME_CLASS_MANAGED;
	}
	return c;
}

/*
 * ---- THE PLAN ----------------------------------------------------------------
 *
 * The COARSE filter: which stages are possible for a kind of object at all. One row per kind; the first row whose `mask` bits
 * equal `want` is the plan. What runs on which function and block is chosen from the code (diag_lineage_chain.c) inside it.
 *
 * DATA, with the measurement beside each row. THE RULE the rows follow: a stage is ON in a class when its marginal links
 * (the scan with every stage the row names against the same scan without that one) are at least 3% of the cell's links AND at
 * least 10 links per second of extra time per 100 files, or when it costs under 3% of the cell's baseline time and adds a link;
 * otherwise it is OFF and the number is the reason. Numbers: the 100-file cells of the graph-research set (26 for the
 * self-resolved PEs), links against the engine without the stages, the selection mode, one machine, timing noise about 5% of the
 * baseline (tests/lineage and harness/measure4.out of the report). "x" is time against the engine without the stages.
 *
 *   cell                 FLOW alone    LOCS adds         SUMM adds             SEED adds              rows below
 *   ELF dynamic, symbols +578   x1.17   +77 (7.2%) x0     +432 (40%) 32/s       +0                     FLOW LOCS SUMM
 *   ELF dynamic, stripped +226  x1.12   +19 (3.0%) x0     +321 (51%) 25/s       +130 (21%) 45/s        ALL
 *   ELF static, symbols  +144   x1.37   +402 (11%) x0.02  +1179 (32%) 460/s     +112 (3.0%) 460/s      ALL
 *   ELF static, stripped +127   x1.15   +46 (1.9%) x0.02  +266 (11%) 20/s       +100 (4.1%) 48/s       ALL
 *   ELF no sections      +7     x0.93   +8 (4.8%) x0      +19 (11%) 1.5/s       +9 (5.4%) 4.5/s        FLOW LOCS
 *   PE                   +27    x2.5    +0                 +60 (67%) 19/s        +2 (2.2%) 14/s         FLOW SUMM
 *   PE self-resolved     +1     x0.6    +0                 +0                    +0                     (the PE row: nothing to read)
 *
 * What the rows leave out and why: SEED in dynamic ELF with symbols (+0 of 1071 links - the partition is the symbol table's and
 * leaves no code unreached); LOCS in PE (+0 links; the PE code the cells hold keeps no descriptor in a global or a field); SEED in
 * PE (+2 links of 89, 2.2%, for 3% more time); SUMM and SEED in an ELF with no sections (+19 and +9 links for x3.2 and x0.4 more
 * time: 1.5 and 4.5 links a second, a tenth of the others). A RELOCATABLE ELF has a row of no stages: 100 kernel modules
 * (the REL cell, .ko) went through every stage (the node of a call is the field its relocation patches; the stages match it
 * inside the instruction) and added 0 links to the 21 the route made, in x10 the time (35 ms -> 352 ms for the 100): what a module
 * passes to the kernel is a pointer or a constant, not a producer's result. Managed PEs have no native code.
 *
 * READING AN UNREAD CALLEE ON DEMAND (KGENOME_LINEAGE_S_DEMAND) is on in no class: a function with no node in it and nothing useful
 * below it is not read, and the helper that only hands a parameter back is the price; reading it when a caller's result reaches a
 * consumer finds +0 / +1 / +4 / +8 / +0 links on the 100-file cells (dyn+sym 1072 vs 1073 links, dyn+strip 604 vs 603, static+sym 3698
 * vs 3694, static+strip 2535 vs 2527, PE 90 vs 90) for 54% more instructions on the static ELF with symbols (1.27 G -> 1.96 G on 10 files).
 */
struct lineage_row {
	unsigned mask, want;
	unsigned stages;
};

#define S_FLOW KGENOME_LINEAGE_S_FLOW
#define S_LOCS KGENOME_LINEAGE_S_LOCS
#define S_SUMM KGENOME_LINEAGE_S_SUMM
#define S_SEED KGENOME_LINEAGE_S_SEED
#define C(x)   KGENOME_CLASS_##x

static const struct lineage_row lineage_plan[] = {
	{ C(REL),                                   C(REL),                                   0 },
	{ C(MANAGED),                               C(MANAGED),                               0 },
	{ C(ELF) | C(NOSECT),                       C(ELF) | C(NOSECT),                       S_FLOW | S_LOCS },
	{ C(ELF) | C(DYNAMIC) | C(SYMBOLS),         C(ELF) | C(DYNAMIC) | C(SYMBOLS),         S_FLOW | S_LOCS | S_SUMM },
	{ C(ELF) | C(DYNAMIC),                      C(ELF) | C(DYNAMIC),                      S_FLOW | S_LOCS | S_SUMM | S_SEED },
	{ C(ELF),                                   C(ELF),                                   S_FLOW | S_LOCS | S_SUMM | S_SEED },
	{ C(PE),                                    C(PE),                                    S_FLOW | S_SUMM },
	{ 0, 0, 0 }
};

unsigned kgenome_diag_lineage_plan(unsigned cls)
{
	const struct lineage_row *r;

	if (!(cls & KGENOME_CLASS_X86))
		return 0;
	for (r = lineage_plan; r->mask || r->want || r->stages; r++)
		if ((cls & r->mask) == r->want)
			return r->stages;
	return 0;
}
