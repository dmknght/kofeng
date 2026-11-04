/*
 * fntab_pe_pdata_arm.c - the exception-table strategy of an ARM64 or Thumb-2 PE: the RUNTIME_FUNCTION entries of `.pdata`, each 8 bytes (BeginAddress, UnwindData).
 *
 * THE FORMAT, as far as this reads it (Microsoft's "ARM64 exception handling" and "ARM exception handling"; no sample of either machine is in the corpora, so this is read from the
 * documentation and tested on fixtures the writer of tests/lib/genome/fntab_pe.c makes: Inference). The low two bits of UnwindData are a FLAG:
 *   0   UnwindData is the RVA of an xdata record, whose first word holds `FunctionLength` in bits 0..17 and `Vers` in bits 18..19 (must be 0); ARM adds bit 22, F: the record describes a
 *       FRAGMENT of a function, not a function.
 *   1,2 the unwind data is PACKED in the word: `FunctionLength` is bits 2..12 (11 bits).
 *   3   reserved: refused.
 * The length is in units of 4 bytes on ARM64 and of 2 bytes on Thumb-2. On Thumb-2 the BeginAddress has its low bit set for Thumb code (the even address is the function; the entry says
 * isa_mode THUMB). A function that needs no unwind data - a frameless leaf - has no entry: the exports, the TLS callbacks and (where the walk decodes the machine) the walk name it.
 *
 * WHAT IT IS EXACT FOR: START and END of every function that has an entry, by construction of the format. HOSTILE INPUT, counted (out->n_bad, P_BAD_FDE) and refused: a Begin outside every
 * executable section, an xdata outside the file, a version other than 0, the reserved flag, a zero length; an end past the raw bytes of the section is CLIPPED to them (flag CLIPPED). The
 * entry count is the directory's size over 8 bounded by the file; the all-zero entry is the table's zero fill.
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "pe_image.h"
#include "fntab_private.h"

#define PE_MACHINE_ARM64 0xaa64u

void kgenome_fntab_pdata_arm(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out)
{
	uint64_t tab, n_ent, i;
	const int arm64 = p && p->machine == PE_MACHINE_ARM64;
	const uint64_t unit = arm64 ? 4u : 2u;

	if (!file.p || !p || !p->valid || (!arm64 && p->machine != 0x1c2u && p->machine != 0x1c4u))
		return;
	if (!p->dir[KGENOME_PE_DIR_EXCEPTION].rva || !p->dir[KGENOME_PE_DIR_EXCEPTION].size)
		return;
	tab = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_EXCEPTION].rva);
	if (tab == KGENOME_BROKEN || tab >= file.n)
		return;
	n_ent = p->dir[KGENOME_PE_DIR_EXCEPTION].size / 8u;
	if (n_ent > (file.n - tab) / 8u)
		n_ent = (file.n - tab) / 8u;
	for (i = 0; i < n_ent; i++) {
		uint32_t b, u, xw;
		uint64_t off, send, len, uo;
		struct kgenome_func f;
		int thumb = 0, fragment = 0;

		if (!kof_rd_u32(file, tab + i * 8u, 0, &b) || !kof_rd_u32(file, tab + i * 8u + 4u, 0, &u))
			break;
		if (!b && !u)
			continue;                       /* the zero fill of the table */
		if (!arm64 && (b & 1u)) {
			thumb = 1;
			b &= ~1u;
		}
		if ((u & 3u) == 3u || !kgenome_fntab_pe_code_rva(p, file, b, &off, &send)) {
			out->n_bad++;
			out->partial |= KGENOME_FNTAB_P_BAD_FDE;
			continue;
		}
		if (u & 3u) {
			len = (uint64_t)((u >> 2) & 0x7ffu) * unit;          /* packed: FunctionLength, bits 2..12 */
		} else {
			uo = kgenome_pe_rva_to_off(p, u);
			if (uo == KGENOME_BROKEN || !kof_rd_u32(file, uo, 0, &xw) || ((xw >> 18) & 3u) != 0) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				continue;
			}
			len = (uint64_t)(xw & 0x3ffffu) * unit;              /* xdata: FunctionLength, bits 0..17 */
			fragment = !arm64 && ((xw >> 22) & 1u);
		}
		if (!len) {
			out->n_bad++;
			out->partial |= KGENOME_FNTAB_P_BAD_FDE;
			continue;
		}
		memset(&f, 0, sizeof f);
		f.source = KGENOME_FN_S_PDATA;
		f.end_source = KGENOME_FN_E_UNWIND;
		f.off = off;
		f.isa_mode = thumb ? KGENOME_FN_ISA_THUMB : KGENOME_FN_ISA_DEFAULT;
		if (len > send - off) {
			len = send - off;
			f.flags |= KGENOME_FN_F_CLIPPED;
		}
		f.len = len;
		if (fragment)
			f.kind = KGENOME_FN_FRAGMENT;       /* a further part of a function: a mask for the merge, never in the table (its owner is not named by the record) */
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
}
