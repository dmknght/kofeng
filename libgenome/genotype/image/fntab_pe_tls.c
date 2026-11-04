/*
 * fntab_pe_tls.c - the TLS-callback strategy of the PE function table: code the loader calls before the entry point, which nothing in the image calls.
 *
 * THE FORMAT. The TLS directory is IMAGE_TLS_DIRECTORY: StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks - four pointers (4 bytes in PE32, 8 in PE32+, VAs
 * and not RVAs). AddressOfCallBacks points at an array of pointers to the callbacks, ended by a null. Starts only.
 *
 * HOSTILE INPUT: the array is read until its null, the file's end or KGENOME_FNTAB_TLS_MAX entries (a bound of cost, a longer array is said: P_CAP); a VA below the image base, or an
 * address in no executable section, is counted in out->n_bad and left out.
 */
#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "pe_image.h"
#include "fntab_private.h"

/* A pointer of the image's width. */
static int rd_ptr(kof_buf f, uint64_t off, uint64_t w, uint64_t *v)
{
	uint32_t x;

	if (w == 8u)
		return kof_rd_u64(f, off, 0, v);
	if (!kof_rd_u32(f, off, 0, &x))
		return 0;
	*v = x;
	return 1;
}

void kgenome_fntab_pe_tls(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out)
{
	const struct kgenome_pe_dir *d;
	uint64_t dir, cb_va, cb, w, i;

	if (!file.p || !p || !p->valid)
		return;
	d = &p->dir[KGENOME_PE_DIR_TLS];
	if (!d->rva || !d->size)
		return;
	w = p->pe32_plus ? 8u : 4u;
	dir = kgenome_pe_rva_to_off(p, d->rva);
	if (dir == KGENOME_BROKEN || dir >= file.n || file.n - dir < 4u * w)
		return;
	if (!rd_ptr(file, dir + 3u * w, w, &cb_va))
		return;
	if (!cb_va || cb_va < p->image_base)
		return;
	cb = kgenome_pe_rva_to_off(p, cb_va - p->image_base);
	if (cb == KGENOME_BROKEN || cb >= file.n)
		return;
	for (i = 0; i <= KGENOME_FNTAB_TLS_MAX; i++) {
		uint64_t va = 0, off, end;
		struct kgenome_func f;

		if (i == KGENOME_FNTAB_TLS_MAX) {            /* one more than the bound and still no null: said, not silent */
			if (rd_ptr(file, cb + i * w, w, &va) && va)
				out->partial |= KGENOME_FNTAB_P_CAP;
			break;
		}
		if (!rd_ptr(file, cb + i * w, w, &va))
			break;
		if (!va)
			break;
		if (va < p->image_base || !kgenome_fntab_pe_code_rva(p, file, va - p->image_base, &off, &end)) {
			out->n_bad++;
			continue;
		}
		memset(&f, 0, sizeof f);
		f.off = off;
		f.source = KGENOME_FN_S_ENTRY;
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
}
