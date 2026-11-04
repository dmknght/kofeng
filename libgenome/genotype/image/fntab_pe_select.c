/*
 * fntab_pe_select.c - the PROBE and the SELECTOR of a PE's function table: the PE half of the pair fntab_select.c holds for ELF (the two are called through kgenome_fntab_probe
 * and kgenome_fntab_select by the format; each has its own decision table because what a PE offers - an exception table, COFF symbols, exports, TLS callbacks, import stubs,
 * sections with an RVA and a raw size - is not what an ELF offers).
 *
 * THE DECISION TABLE (first row that matches wins; `run` are the strategies of the case, in the order phenotype/fntab_build_pe.c runs them):
 *
 *   machine / metadata                                         case        run
 *   ---------------------------------------------------------  ----------  ------------------------------------------------------------
 *   a CLI header (managed code: the code is IL)                PE_CLR      (empty, state PARTIAL: P_MANAGED)
 *   x64, exception directory, not read empty                   PE_PDATA    PDATA, EXPORT, TLS, CFG, COFF[if the file has the table], WALK, THUNK, then GAPS
 *   x86 / x64, a COFF symbol table with functions              PE_COFF     COFF, EXPORT, TLS, CFG, WALK, THUNK
 *   x86 / x64, neither                                         PE_WALK     EXPORT, TLS, CFG, WALK, THUNK
 *   ARM64 or Thumb-2 (0xaa64, 0x1c2, 0x1c4)                    PE_ARM      ARMPDATA, EXPORT, TLS, CFG (no walk: see below)
 *   any other machine                                          PE_NONE     (empty, state PARTIAL: P_NO_TABLE)
 *   (a PE with no executable section that holds a byte of the file is PE_NOCODE, tested right after the managed row: empty, P_NO_CODE)
 *
 * THE MACHINES, one condition each (no ARM PE sample exists in the corpora: these rows are INFERENCE, tested on fixtures the PE writer of tests/lib/genome/fntab_pe.c makes):
 *   x86 / x64   the walk decodes it and every PE rule of the observer (diag_wrapper_pe.c) is written for it: the import stub is `jmp [slot]`, the zero fill `00 00`, the mark after a call int3.
 *   ARM64       the exception table has the same RUNTIME_FUNCTION table but 8-byte entries with the length inside (packed, or the xdata header): its own strategy, exact. NOT joined to the walk:
 *               kgenome_diag_walk_ensure admits a PE only for x86 / x64, because every PE analysis route (imports, API hashes, lineage) reads its trace as x86; lifting the gate changes those
 *               routes for a machine this tree has no sample of. NEXT: lift the gate with an identity measurement on the x86 corpus, give the observer the ARM64 stub (`adrp; ldr; br`) and the
 *               4-byte zero fill, and run REACH (the graph of ARM64 is built: cfg_isa.c).
 *   Thumb-2     the same table (length in halfwords, the start with its low bit set), its own strategy, exact. NO walk and no graph: the decoder has no Thumb (the architecture value says ARM and
 *               the bytes would be read as ARM words), so a function nothing names is missing (P_STARTS) and says so.
 *   ARM (0x1c0) and every other machine (MIPS, PowerPC, RISC-V, SH): the exception directory has other record layouts or none this tree can read; empty, P_NO_TABLE, named.
 *
 * The PE rows follow the same two rules as the ELF ones: the table that is EXACT where it exists comes first (the exception table, the COFF symbols) and what
 * guesses runs beside it only to add starts the exact one cannot hold (a leaf function has no unwind entry; the walk, the exports and the TLS callbacks name
 * starts, the import-stub strategy kinds the stubs); and a table that was READ and held no function is the next row (meta.pdata_empty / coff_empty: the one
 * retry, visible in the meta). PE x86 has no exception table at all, so its row is the walk's: the starts are call targets, exports and callbacks, the end is
 * the next start less the padding the decode saw (END_OPEN). The walk decodes x86 and x64 with one decoder, which is why one row serves both.
 *
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "pe_image.h"
#include "fntab_private.h"
#include "obj.h"

void kgenome_pe_probe(kof_buf file, const void *info, struct kgenome_fntab_meta *m)
{
	const struct kgenome_pe_info *p = info;

	m->pe_x64_pdata = p->valid && p->machine == 0x8664u && p->pe32_plus &&
			  p->dir[KGENOME_PE_DIR_EXCEPTION].rva && p->dir[KGENOME_PE_DIR_EXCEPTION].size;
	if (!p->valid)
		return;
	m->pe_x86 = p->machine == 0x14cu || p->machine == 0x8664u;
	m->pe_arm = p->machine == 0xaa64u || p->machine == 0x1c2u || p->machine == 0x1c4u;
	m->pe_clr = p->clr_len != 0;
	/* no executable section holds a byte of the file: the sections' own extent (the one the walk reads), summed */
	{
		uint32_t i;
		uint64_t at;

		m->pe_nocode = 1;
		for (i = 0; i < p->nsec && i < KGENOME_PE_MAX_SECTIONS; i++)
			if (kgenome_pe_sec_is_code(&p->sec[i]) && kgenome_pe_sec_extent(&p->sec[i], file.n, &at))
				m->pe_nocode = 0;
	}
	/* the COFF symbol table is a pair of fields of the file header: where, and how many records; an image mapped from memory has none */
	if (p->layout == KGENOME_PE_LAYOUT_FILE) {
		uint32_t at = 0, cnt = 0;

		if (kof_rd_u32(file, p->lfanew + 12u, 0, &at) && kof_rd_u32(file, p->lfanew + 16u, 0, &cnt) && at && cnt &&
		    at < file.n)
			m->pe_coff = 1;
	}
}

struct kgenome_fntab_plan kgenome_pe_select(const struct kgenome_fntab_meta *m)
{
	const uint16_t starts = KGENOME_FNTAB_X_PE_EXPORT | KGENOME_FNTAB_X_PE_TLS | KGENOME_FNTAB_X_PE_CFG | KGENOME_FNTAB_X_WALK | KGENOME_FNTAB_X_PE_THUNK;
	struct kgenome_fntab_plan p;

	memset(&p, 0, sizeof p);

	if (m->pe_clr) {
		p.ccase = KGENOME_FNTAB_C_PE_CLR;
	} else if (m->pe_nocode) {
		p.ccase = KGENOME_FNTAB_C_PE_NOCODE;
	} else if (m->pe_x64_pdata && !m->pdata_empty) {
		p.ccase = KGENOME_FNTAB_C_PE_PDATA;
		p.run = (uint16_t)(KGENOME_FNTAB_X_PDATA | starts | KGENOME_FNTAB_X_PE_REACH | (m->pe_coff ? KGENOME_FNTAB_X_PE_COFF : 0u));
	} else if (m->pe_x86 && m->pe_coff && !m->coff_empty) {
		p.ccase = KGENOME_FNTAB_C_PE_COFF;
		p.run = (uint16_t)(KGENOME_FNTAB_X_PE_COFF | starts | KGENOME_FNTAB_X_PE_REACH);
	} else if (m->pe_x86) {
		p.ccase = KGENOME_FNTAB_C_PE_WALK;
		p.run = (uint16_t)(starts | KGENOME_FNTAB_X_PE_REACH);
	} else if (m->pe_arm) {
		p.ccase = KGENOME_FNTAB_C_PE_ARM;
		p.run = (uint16_t)(KGENOME_FNTAB_X_PE_ARMPDATA | KGENOME_FNTAB_X_PE_EXPORT | KGENOME_FNTAB_X_PE_TLS | KGENOME_FNTAB_X_PE_CFG);
	} else {
		p.ccase = KGENOME_FNTAB_C_PE_NONE;
	}
	return p;
}
