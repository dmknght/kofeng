/*
 * fntab_pe_pdata.c - the exception-table strategy of the PE function table: the RUNTIME_FUNCTION entries of an x64 image (.pdata).
 *
 * THE FORMAT, as far as this reads it. An entry is three RVAs: BeginAddress, EndAddress, UnwindData. The unwind info is `u8 version:3 | flags:5`, `u8 prolog size`,
 * `u8 count of unwind codes`, `u8 frame register:4 | offset:4`, the codes (2 bytes each, the count rounded up to even), and then - when the flag UNW_FLAG_CHAININFO is set - the
 * RUNTIME_FUNCTION of the PARENT. A chained entry is not a function: it describes a further part of the parent's body (the cold half of a function the compiler split), so the
 * parent keeps its own entry and extent and the chained one is made a FRAGMENT (kind): a mask for the merge, which stops the walk from starting a function inside it, and which
 * the merge does not keep (set->n_extra). `value` of a fragment is the parent's start (file offset). A function the format cannot hold an entry for - a LEAF, which needs no unwind
 * data - is not here: the walk, the exports and the GAPS step name it.
 *
 * WHAT IT IS EXACT FOR: START and END of every non-leaf function, by construction of the format. NOT exact: an entry's EndAddress is the end of the part the entry describes; the
 * function it belongs to has further parts only through a chained entry.
 *
 * HOSTILE INPUT, each counted and none followed: the entry count is the directory's size over 12 bounded by the file (a loop of at most that many reads, and the list's own cap
 * KGENOME_FNTAB_MAX: said by P_CAP); an entry with Begin 0 and End 0 is the table's zero fill and is skipped silently; End <= Begin, a Begin outside every executable section, an unwind
 * info that lies outside the file, whose version is not 1 or 2, whose flags hold a bit the format does not define, whose chained parent lies outside the file, are REFUSED and counted
 * (out->n_bad, P_BAD_FDE); an End past the raw bytes of its section is CLIPPED to them (flag CLIPPED); an unwind address with its low bit set is an indirection the format defines and
 * this does not follow (its info is not read; the entry's own Begin and End stand, PDATA-1). Overlapping entries are the merge's: both stand and the overlap is recorded as disagreement. The chain is never followed, so a
 * chain loop costs nothing.
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "pe_image.h"
#include "fntab_private.h"

#define PE_MACHINE_AMD64 0x8664u
#define UNW_FLAG_CHAININFO 0x4u
#define UNW_FLAG_DEFINED 0x7u

void kgenome_fntab_pdata(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out)
{
	uint64_t tab, n_ent, i;

	if (!file.p || !p || !p->valid || p->machine != PE_MACHINE_AMD64 || !p->pe32_plus)
		return;
	if (!p->dir[KGENOME_PE_DIR_EXCEPTION].rva || !p->dir[KGENOME_PE_DIR_EXCEPTION].size)
		return;
	tab = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_EXCEPTION].rva);
	if (tab == KGENOME_BROKEN || tab >= file.n)
		return;
	/* As many entries as the directory declares and the file holds. */
	n_ent = p->dir[KGENOME_PE_DIR_EXCEPTION].size / 12u;
	if (n_ent > (file.n - tab) / 12u)
		n_ent = (file.n - tab) / 12u;
	for (i = 0; i < n_ent; i++) {
		uint32_t b, e, u;
		uint64_t off, send, uo, uend, len;
		uint8_t hdr, flags, ncodes;
		struct kgenome_func f;

		if (!kof_rd_u32(file, tab + i * 12u, 0, &b) || !kof_rd_u32(file, tab + i * 12u + 4u, 0, &e) ||
		    !kof_rd_u32(file, tab + i * 12u + 8u, 0, &u))
			break;
		if (!b && !e)
			continue;                       /* the zero fill of the table */
		if (e <= b || !kgenome_fntab_pe_code_rva(p, file, b, &off, &send)) {
			out->n_bad++;
			out->partial |= KGENOME_FNTAB_P_BAD_FDE;
			continue;
		}
		if (u & 1u) {
			/* UnwindData with its low bit set is an indirection to another entry's unwind info, which this does not follow: the unwind info is not read and the entry is
			 * not validated by it. What the entry says about the function (BeginAddress, EndAddress) does not depend on how the unwinder finds its info, so the body stands
			 * (PDATA-1, fixed: the entry's own Begin/End are kept, not dropped). We cannot know whether the unread unwind info would have UNW_FLAG_CHAININFO set, so an
			 * indirected entry is always kept as a plain function, never a FRAGMENT of a chained one - a narrow, untracked case if that combination occurs. */
			hdr = 0;
			flags = 0;
			ncodes = 0;
			uo = 0;
		} else {
			uo = kgenome_pe_rva_to_off(p, u);
			if (uo == KGENOME_BROKEN || uo >= file.n || file.n - uo < 4u) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				continue;
			}
			hdr = file.p[uo];
			flags = (uint8_t)(hdr >> 3);
			ncodes = file.p[uo + 2u];
			if ((hdr & 7u) < 1u || (hdr & 7u) > 2u || (flags & ~UNW_FLAG_DEFINED)) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				continue;
			}
		}
		memset(&f, 0, sizeof f);
		f.source = KGENOME_FN_S_PDATA;
		f.end_source = KGENOME_FN_E_UNWIND;     /* .pdata names nothing: value 0, shndx 0 */
		f.off = off;
		len = (uint64_t)e - b;
		if (len > send - off) {
			len = send - off;
			f.flags |= KGENOME_FN_F_CLIPPED;
		}
		f.len = len;
		if (flags & UNW_FLAG_CHAININFO) {
			/* the parent's RUNTIME_FUNCTION follows the codes: read as far as the file holds it, and its start must be code too */
			uint32_t pb;
			uint64_t poff, pend;

			uend = uo + 4u + (uint64_t)((ncodes + 1u) & ~1u) * 2u;
			if (!kof_rd_u32(file, uend, 0, &pb) || !kgenome_fntab_pe_code_rva(p, file, pb, &poff, &pend)) {
				out->n_bad++;
				out->partial |= KGENOME_FNTAB_P_BAD_FDE;
				continue;
			}
			f.kind = KGENOME_FN_FRAGMENT;
			f.value = poff;
		}
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
}

void kgenome_pe_funcs_build(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_func_set *out)
{
	struct kgenome_fntab_list l;

	memset(out, 0, sizeof *out);
	memset(&l, 0, sizeof l);
	kgenome_fntab_pdata(file, p, &l);
	kgenome_fntab_merge(&l, 0, out);
	kgenome_fntab_list_free(&l);
}
