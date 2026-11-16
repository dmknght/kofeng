/*
 * fntab_pe_export.c - the export-address-table strategy of the PE function table: the starts a DLL (or an EXE that exports) declares.
 *
 * THE FORMAT. IMAGE_EXPORT_DIRECTORY holds NumberOfFunctions and AddressOfFunctions, an array of that many RVAs (the export address table, indexed by ordinal - Base).
 * An entry is the RVA of the exported function, or - when it lies INSIDE the export directory's own range - the RVA of a forwarder string ("DLL.Name"), which is no code of this
 * image; an entry of 0 is an unused ordinal. This strategy reads the whole table, named or not (kgenome_pe_exports, which feeds the symbol block, reports named exports only and
 * is built for names), and takes an entry only when it is an address in an executable section's raw bytes. Starts only: an export names no size.
 *
 * HOSTILE INPUT: the count is bounded by what the file holds (the table lies in the file, 4 bytes an entry) and by the list's cap (said: P_CAP). A forwarder and a data export
 * (an address in no executable section) are counted in out->n_bad and left out; a table that does not lie in the file ends the read.
 */
#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "pe_image.h"
#include "fntab_private.h"

void kgenome_fntab_pe_export(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out)
{
	const struct kgenome_pe_dir *d;
	uint64_t dir, eat, i, n;
	uint32_t nfun, aof;

	if (!file.p || !p || !p->valid)
		return;
	d = &p->dir[KGENOME_PE_DIR_EXPORT];
	if (!d->rva || !d->size)
		return;
	dir = kgenome_pe_rva_to_off(p, d->rva);
	if (dir == KGENOME_BROKEN || dir >= file.n || file.n - dir < 40u)
		return;
	if (!kof_rd_u32(file, dir + 20u, 0, &nfun) || !kof_rd_u32(file, dir + 28u, 0, &aof) || !nfun || !aof)
		return;
	eat = kgenome_pe_rva_to_off(p, aof);
	if (eat == KGENOME_BROKEN || eat >= file.n)
		return;
	n = nfun;
	if (n > (file.n - eat) / 4u)
		n = (file.n - eat) / 4u;
	for (i = 0; i < n; i++) {
		uint32_t rva;
		uint64_t off, end;
		struct kgenome_func f;

		if (!kof_rd_u32(file, eat + i * 4u, 0, &rva))
			break;
		if (!rva)
			continue;
		if (kgenome_pe_export_is_forwarder(p, rva)) {      /* a forwarder string */
			out->n_bad++;
			continue;
		}
		if (!kgenome_fntab_pe_code_rva(p, file, rva, &off, &end)) {
			out->n_bad++;                              /* data */
			continue;
		}
		memset(&f, 0, sizeof f);
		f.off = off;
		/* The pair the symbol block keys the export's name on (pe_sym.c, export_put: value = the RVA, shndx 0xffff, "not a section"), so kof_func_name finds it.
		 * Without it every export was fcn_<off> (NM-1, measured on four x64 DLLs: 19/19, 1/1, 76/76, 4/4 exports unnamed). An export by ordinal has no record and stays unnamed. */
		f.value = rva;
		f.shndx = 0xffffu;
		f.source = KGENOME_FN_S_EXPORT;
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
}
