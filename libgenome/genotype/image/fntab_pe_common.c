/*
 * fntab_pe_common.c - what the PE strategies of the function table (fntab.h) share: where the code is.
 * Read the decision table in fntab_select.c; the strategies are fntab_pe_pdata.c, fntab_pe_export.c, fntab_pe_tls.c, fntab_pe_coff.c.
 */
#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "pe_image.h"
#include "fntab_private.h"

int kgenome_fntab_pe_code_rva(const struct kgenome_pe_info *p, kof_buf file, uint64_t rva, uint64_t *off, uint64_t *end)
{
	const struct kgenome_pe_sec *s;
	uint64_t o, e;

	o = kgenome_pe_rva_to_off(p, rva);
	if (o == KGENOME_BROKEN || o >= file.n)
		return 0;
	s = kgenome_pe_sec_at_off(p, o);
	if (!s || !kgenome_pe_sec_is_code(s))
		return 0;
	e = s->file_off + s->file_size;
	if (e > file.n || e < s->file_off)
		e = file.n;
	if (o >= e)
		return 0;
	*off = o;
	*end = e;
	return 1;
}
