/*
 * fntab_pe_coff.c - the COFF-symbol-table strategy of the PE function table: the functions a toolchain that keeps the table (GNU ld: MinGW, Cygwin) left in the image.
 *
 * THE FORMAT, the END rule and the hostile-input discipline for the table itself are pe_coff_sym.c's header comment: this file is now a thin consumer of
 * kgenome_pe_coff_syms, which is the ONE walk of that table (shared with the engine's KSYM builder, kof_pe_syms_with in pe_sym.c, which needs the same
 * records' NAMES on top of what this strategy needs - their off/value/shndx/size). What was here before this split - the record layout, the aux-record
 * skip, the section/value bounds-checking - is unchanged; it moved, byte for byte, into the shared walk.
 *
 * Measured on the 697 x64 images of the oracle corpus that keep the table: section RVA + Value is the BeginAddress of an exception-table entry for every
 * non-leaf function (exp, h/ of this change), and the symbols name the leaf functions the exception table cannot.
 */
#include <string.h>

#include <kofcore.h>
#include <genotype/image/pe_types.h>
#include "funcs.h"
#include "pe_image.h"
#include "fntab_private.h"

struct coff_build_ctx {
	struct kgenome_fntab_list *out;
};

static int coff_build_cb(void *user, const struct kgenome_pe_coff_sym *s)
{
	struct coff_build_ctx *c = user;
	struct kgenome_func f;

	memset(&f, 0, sizeof f);
	f.off = s->off;
	f.source = KGENOME_FN_S_COFF;
	f.value = s->value;
	f.shndx = s->shndx;
	if (s->has_size) {
		f.len = s->size;
		f.end_source = KGENOME_FN_E_SYMBOL;
	} else {
		f.flags |= KGENOME_FN_F_SIZE0;
	}
	return kgenome_fntab_list_add(c->out, &f);
}

void kgenome_fntab_pe_coff(kof_buf file, const struct kgenome_pe_info *p, struct kgenome_fntab_list *out)
{
	struct coff_build_ctx c;
	uint32_t n_bad = 0;

	c.out = out;
	kgenome_pe_coff_syms(file, p, coff_build_cb, &c, &n_bad);
	out->n_bad += n_bad;
}
