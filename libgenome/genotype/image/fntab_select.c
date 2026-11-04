/*
 * fntab_select.c - the PROBE and the SELECTOR of the function table (fntab.h).
 *
 * THE DECISION TABLE. Read top to bottom, the first row that matches wins. `run` are the strategies that run, [c] marks one that only CHECKS
 * (its entries nothing else names are counted in n_extra, not kept). Each row is a case of its own: a new case is a new row and a new
 * strategy, and no existing row or strategy changes.
 *
 *   format  metadata                                      case              run
 *   ------  --------------------------------------------  ----------------  ----------------------------------
 *   ELF     .symtab present, not found empty              ELF_SYMTAB        SYMTAB, FDE[c]
 *   ELF     no .symtab (or empty), .dynsym not empty      ELF_DYNSYM        DYNSYM, FDE, WALK, REACH
 *   ELF     no symbols, .eh_frame readable                ELF_FDE           FDE, WALK, REACH
 *   ELF     nothing                                       ELF_WALK          WALK, REACH
 *   PE      (the PE rows are the PE's own table: fntab_pe_select.c)
 *   other   -                                             NONE              (empty)
 *
 * WHY THE SYMBOL TABLE IS NOT COMBINED WITH THE WALK: it is exact where it exists and the walk guesses ends; the old path took the symbol
 * table alone and that is kept (the exact path is wrapped, not touched). The unwind table runs beside it as a CHECK so that a symbol
 * table that lacks functions the unwind table names says so (state PARTIAL, P_SYMTAB), without changing what the symbols gave.
 * "Found empty": the symbol table was read and held no function (a file stripped to a few symbols) - the orchestrator then asks again with
 * symtab_empty set and the row below applies; this is the one retry and it is visible in the meta, not a hidden fallback.
 *
 * REACH (ex-defect ELF-NO-REACH, fixed 2026-11-05): every ELF row that runs WALK now runs REACH beside it, exactly as every PE row that
 * runs WALK does (fntab_pe_select.c). fntab_reach.c (THE REACH STEP's own header) reads the walk's generic decode trace and padding-run
 * table (kgenome_diag_walk_pads: any architecture, any format - it records NOP runs of any width plus, on x86 only, int3/hlt runs) and
 * builds the CFG through kgenome_frame_make/kgenome_cfg_build, which are both format-generic; the one format-specific bit in that whole
 * chain, KGENOME_CFG_F_TRAP_EXITS (frame.c: "the int3/hlt after a CALL is MSVC's mark that the call does not return"), is already gated to
 * `format == KGENOME_FMT_PE && arch is x86/x64` and stays that way - ELF code that happens to end in an untagged int3 run still falls
 * through classify() as ordinary flow, which is correct for it. So there was no PE-specific logic to generalize: the three ELF rows that
 * already run WALK (DYNSYM, FDE, WALK) simply never asked REACH to run beside it. The flag keeps its name,
 * KGENOME_FNTAB_X_PE_REACH (fntab.h): its own definition comment there was already format-generic (no "PE" in it,
 * only the symbol carries one), a rename touches every reader and every test row for a purely cosmetic gain, and
 * the PE and ELF cases now read identically here - "set WALK, set REACH" - so a reader of THIS file is in no
 * danger of reading it as PE-only. Renamed only if a future reader is shown to actually have been misled by it.
 * ELF_SYMTAB is deliberately left out: it never sets WALK
 * (an ELF symbol's st_size already closes every one of its own entries, unlike a PE pdata/COFF table which only closes SOME of its
 * functions - PE_PDATA and PE_COFF both still run WALK + REACH beside their exact source for exactly that reason), so REACH would have no
 * trace to read and no gap to look at.
 * NOT GENERALIZED: fntab_reach.c's int3/hlt-specific padding-run filter (crosses_pad(), padded_start(), call_mark_at(), the `fell` check)
 * stays byte-literal to 0xcc/0xf4, i.e. the MSVC "the call does not return" trap convention. ELF toolchains (gcc/clang) do not use it;
 * their usual inter-function fill is NOP (0x90 / multi-byte 0F1F..), which this filter deliberately does NOT treat as a hard separator
 * (FNR-4's own measurement: a NOP run is exactly as likely to be a compiler's OWN loop-realignment padding INSIDE a function as the gap
 * between two functions, on any toolchain) - extending it to NOP for ELF was not attempted here and would need the same oracle-backed
 * measurement FNR-4 did for PE before it could be trusted; until then an ELF body that runs into real inter-function NOP padding is
 * covered by the plain next-start-less-padding END rule exactly as before (fntab_ends.c), not regressed, just not strengthened by this
 * change. REACH still helps ELF in the common case this defect named: a start the walk's call-target scan missed entirely (nothing calls
 * it) is now found from the gap behind the entry before it, as long as its own bytes decode and end (a `ret`, a jump out, or run into
 * recognized padding) - this needs no int3/hlt convention at all, see kgenome_fntab_reach()'s gap-walk loop.
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
		if (m->has_symtab && !m->symtab_empty) {
			p.ccase = KGENOME_FNTAB_C_ELF_SYMTAB;
			p.run = KGENOME_FNTAB_X_SYMTAB | (m->has_unwind ? KGENOME_FNTAB_X_FDE : 0u);
			p.check_only = (uint8_t)(m->has_unwind ? KGENOME_FN_S_FDE : 0u);   /* in SOURCE bits (KGENOME_FN_S_*), what kgenome_fntab_merge reads */
		} else if (m->has_dynsym && !m->dynsym_empty && !m->elf_rel) {
			p.ccase = KGENOME_FNTAB_C_ELF_DYNSYM;
			p.run = KGENOME_FNTAB_X_DYNSYM | (m->has_unwind ? KGENOME_FNTAB_X_FDE : 0u) | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH;
		} else if (m->has_unwind && !m->elf_rel) {
			p.ccase = KGENOME_FNTAB_C_ELF_FDE;
			p.run = KGENOME_FNTAB_X_FDE | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH;
		} else {
			p.ccase = KGENOME_FNTAB_C_ELF_WALK;
			p.run = m->elf_rel ? 0u : (KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_REACH);
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
	} else if (format == KGENOME_FMT_PE) {
		kgenome_pe_probe(file, info, m);
	}
}
