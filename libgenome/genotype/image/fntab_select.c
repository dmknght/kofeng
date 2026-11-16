/*
 * fntab_select.c - the PROBE and the SELECTOR of the function table (fntab.h).
 *
 * THE DECISION TABLE (owner 2026-11-16: the partition is made from loader/ABI metadata only - no strategy decodes code). Read top to bottom, the first row that matches
 * wins. `run` are the strategies that run, [c] marks one that only CHECKS (its entries nothing else names are counted in n_extra, not kept). STARTS is the start-only
 * tables the object has: INITARR (init/fini/preinit arrays), EXIDX (.ARM.exidx), and ENTRY (the entry point, asked by the orchestrator only when another source named a
 * function: the entry alone does not split an object). An object for which no row gives an entry is NO_META (fntab_build.c): one entry of trust NONE per code extent.
 *
 *   format  metadata                                      case              run
 *   ------  --------------------------------------------  ----------------  ----------------------------------
 *   ELF     .symtab present, not found empty              ELF_SYMTAB        SYMTAB, FDE, GOPCLN[c], STARTS
 *   ELF     no .symtab (or empty), .dynsym not empty      ELF_DYNSYM        DYNSYM, FDE, GOPCLN, STARTS
 *   ELF     no symbols, .eh_frame readable                ELF_FDE           FDE, GOPCLN, STARTS
 *   ELF     no symbols, no unwind, .gopclntab             ELF_GO            GOPCLN, STARTS
 *   ELF     none of those (a relocatable object: nothing) ELF_META          STARTS
 *   PE      (the PE rows are the PE's own table: fntab_pe_select.c)
 *   other   -                                             NONE              (empty)
 *
 * WHY THE SYMBOL TABLE IS NOT JOINED BY THE OTHER EXACT TABLES: it is exact where it exists (measured 339429 of 339496 x86-64 functions before the IFUNC fix) and the
 * old path took it alone; that is kept. The unwind table and the Go table run beside it as CHECKS so that a symbol table that lacks functions they name says so (state
 * PARTIAL, P_SYMTAB) without changing what the symbols gave. The start-only tables run as sources: a start inside a symbol body is dropped by the merge (counted), a start
 * outside every body is a function the symbols do not name.
 * "Found empty": the symbol table was read and held no function (a file stripped to a few symbols) - the orchestrator then asks again with symtab_empty set and the row
 * below applies; this is the one retry and it is visible in the meta, not a hidden fallback.
 * DISABLED by the owner 2026-11-16 (error-prone, lacks coverage): the entry walk's call targets (WALK) and the REACH step (ends and gap starts from the decoded flow) that the
 * DYNSYM, FDE and WALK rows ran; to re-enable, set KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH in those rows again and take the #if 0 out of phenotype/fntab_walk.c,
 * fntab_reach.c and kgenome_fntab_run_walk (fntab_build.c).
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/elf_types.h>
#include <genotype/image/pe_types.h>
#include "elf_image.h"
#include "pe_image.h"
#include "fntab_private.h"
#include "obj.h"

struct kgenome_fntab_plan kgenome_fntab_select(const struct kgenome_fntab_meta *m)
{
	struct kgenome_fntab_plan p;

	memset(&p, 0, sizeof p);
	if (!m)
		return p;
	if (m->format == KGENOME_FMT_ELF) {
		const uint16_t starts = (uint16_t)((m->has_initarr ? KGENOME_FNTAB_X_INITARR : 0u) | (m->has_exidx ? KGENOME_FNTAB_X_EXIDX : 0u) | KGENOME_FNTAB_X_ENTRY);
		const uint16_t go = m->has_gopcln ? KGENOME_FNTAB_X_GOPCLN : 0u;

		if (m->has_symtab && !m->symtab_empty) {
			p.ccase = KGENOME_FNTAB_C_ELF_SYMTAB;
			p.run = (uint16_t)(KGENOME_FNTAB_X_SYMTAB | (m->has_unwind ? KGENOME_FNTAB_X_FDE : 0u) | go | (m->elf_rel ? 0u : starts));
			/* PMA-6 (audit, round 3): the unwind table is a SOURCE beside the symbols, not a check: an FDE whose start no sized symbol names is an exact body of
			 * its own (HIGH); where both name one start with different ends the merge keeps the symbol's and flags DISAGREE */
			p.check_only = (uint16_t)(m->has_gopcln ? KGENOME_FN_S_GOPCLN : 0u);   /* in SOURCE bits (KGENOME_FN_S_*), what kgenome_fntab_merge reads */
		} else if (m->has_dynsym && !m->dynsym_empty && !m->elf_rel) {
			p.ccase = KGENOME_FNTAB_C_ELF_DYNSYM;
			p.run = (uint16_t)(KGENOME_FNTAB_X_DYNSYM | (m->has_unwind ? KGENOME_FNTAB_X_FDE : 0u) | go | starts);
		} else if (m->has_unwind && !m->elf_rel) {
			p.ccase = KGENOME_FNTAB_C_ELF_FDE;
			p.run = (uint16_t)(KGENOME_FNTAB_X_FDE | go | starts);
		} else if (m->has_gopcln && !m->elf_rel) {
			p.ccase = KGENOME_FNTAB_C_ELF_GO;
			p.run = (uint16_t)(go | starts);
		} else {
			p.ccase = KGENOME_FNTAB_C_ELF_META;
			p.run = m->elf_rel ? 0u : starts;
		}
	} else if (m->format == KGENOME_FMT_PE) {
		p = kgenome_pe_select(m);
	}
	return p;
}

/* Does the file offset lie in a section of stubs? (fntab_private.h) */
int kgenome_fntab_in_stub_section(const struct kgenome_elf_info *e, uint64_t off)
{
	uint32_t i;

	for (i = 1; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
		if (off >= e->sec[i].file_off && off - e->sec[i].file_off < e->sec[i].file_size && kgenome_elf_sec_is_stub(e, i))
			return 1;
	return 0;
}

int kgenome_fntab_elf_code_va(const struct kgenome_elf_info *e, uint64_t va, uint64_t *off)
{
	const struct kgenome_elf_seg *host;
	uint64_t o;

	if (!kgenome_elf_va_to_off(e, va, 1, &o))
		return 0;
	host = kgenome_elf_load_at_off(e, o);
	if (!host || !kgenome_elf_seg_is_code(host))      /* any executable segment (PMA-1): a stub section's code is code */
		return 0;
	*off = o;
	return 1;
}

int kgenome_fntab_elf_section(const struct kgenome_elf_info *e, uint32_t type, const char *name, uint32_t *idx)
{
	uint32_t i;

	for (i = 1; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
		if (e->sec[i].type == type && e->sec[i].file_size && (!name || !strcmp(e->sec[i].name, name))) {
			*idx = i;
			return 1;
		}
	return 0;
}

/* The section the unwind strategy reads, by what the format calls it: ".eh_frame" of type PROGBITS or the x86-64 unwind type. */
#define SHT_X86_64_UNWIND 0x70000001u
#define PT_GNU_EH_FRAME 0x6474e550u

int kgenome_fntab_eh_section(const struct kgenome_elf_info *e, uint32_t *idx)
{
	uint32_t i;

	for (i = 1; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *s = &e->sec[i];

		if ((s->type == KGENOME_ELF_SHT_PROGBITS || s->type == SHT_X86_64_UNWIND) &&
		    (s->flags & KGENOME_ELF_SHF_ALLOC) && s->file_size && !strcmp(s->name, ".eh_frame")) {
			*idx = i;
			return 1;
		}
	}
	return 0;
}

int kgenome_fntab_eh_segment(const struct kgenome_elf_info *e, uint32_t *idx)
{
	uint32_t i;

	for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
		if (e->seg[i].type == PT_GNU_EH_FRAME && e->seg[i].file_size >= 12u) {
			*idx = i;
			return 1;
		}
	return 0;
}

void kgenome_fntab_probe(uint32_t format, kof_buf file, const void *info, struct kgenome_fntab_meta *m)
{
	memset(m, 0, sizeof *m);
	m->format = (uint8_t)format;
	if (!info || !file.p)
		return;
	if (format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = info;
		struct kgenome_elf_shape sh;
		uint32_t i, k;

		if (!e->valid)
			return;
		m->elf_rel = e->e_type == KGENOME_ELF_REL;
		kgenome_elf_shape(e, &sh);
		m->has_symtab = sh.has_symtab;
		for (i = 1; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
			if (e->sec[i].type == KGENOME_ELF_SHT_DYNSYM && e->sec[i].file_size)
				m->has_dynsym = 1;
		/* an object file's pcrel values are relocations, not addresses: its unwind table names no function */
		m->has_unwind = (uint8_t)(!m->elf_rel && (kgenome_fntab_eh_section(e, &k) || kgenome_fntab_eh_segment(e, &k)));
		/* the start-only and Go tables: present by section type or name, or (no section table) by segment / dynamic tag; the strategies read them */
		for (i = 1; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
			if (e->sec[i].type >= 14u && e->sec[i].type <= 16u)     /* SHT_INIT_ARRAY, SHT_FINI_ARRAY, SHT_PREINIT_ARRAY */
				m->has_initarr = 1;
			if (e->sec[i].type == 0x70000001u && e->e_machine == 40u)       /* SHT_ARM_EXIDX of an ARM object */
				m->has_exidx = 1;
		}
		if (e->sec_count <= 1u)
			for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
				if (e->seg[i].type == 2u)               /* PT_DYNAMIC: the arrays may be named there (the strategy reads the tags) */
					m->has_initarr = 1;
				if (e->seg[i].type == 0x70000001u && e->e_machine == 40u)       /* PT_ARM_EXIDX */
					m->has_exidx = 1;
			}
		m->has_gopcln = (uint8_t)kgenome_fntab_elf_section(e, KGENOME_ELF_SHT_PROGBITS, ".gopclntab", &k);
	} else if (format == KGENOME_FMT_PE) {
		kgenome_pe_probe(file, info, m);
	}
}
