/*
 * callnames.c - kof_callnames_build and the spelling. See callnames.h.
 */
#include <stdio.h>
#include <string.h>

#include <genotype/image/pe_image.h>

#include "callnames.h"
#include "genome_obj.h"
#include "parsers/binaries/pe/pe_sym.h"

int kof_callnames_applicable(const struct kof_obj_ctx *ctx)
{
	struct kgenome_obj g;

	kof_genome_obj(ctx, &g);
	return kgenome_callnames_applicable(&g);
}

int kof_callnames_build(const struct kof_obj_ctx *ctx, kof_buf data, struct kgenome_ledger *led, struct kgenome_callnames *out)
{
	struct kgenome_obj g;

	kof_genome_obj(ctx, &g);
	return kgenome_callnames_build(&(const struct kgenome_callnames_req){ .obj = &g, .file = data, .led = led }, out);
}

/* The ELF name: the bytes at `nameoff` up to a NUL, the end of the object or the room, printable; the object's own bytes are not trusted to end. */
static size_t elf_name(kof_buf d, uint64_t nameoff, char *out, size_t room)
{
	size_t k = 0;

	if (!nameoff || nameoff >= d.n)
		return 0;
	while (k < room && nameoff + k < d.n && d.p[nameoff + k]) {
		unsigned char ch = d.p[nameoff + k];

		out[k++] = ch >= 0x20 && ch < 0x7f ? (char)ch : '?';
	}
	return k;
}

int kof_callnames_name(const struct kgenome_callnames *t, kof_buf data, enum kof_callname_via via, uint64_t off, char *out, size_t cap)
{
	const struct kgenome_callname *e;

	if (!cap)
		return 0;
	out[0] = 0;
	e = t ? kgenome_callnames_at(t, off) : NULL;
	if (!e || e->kind != (via == KOF_CALLNAME_VIA_TARGET ? KGENOME_CALLNAME_STUB : KGENOME_CALLNAME_SLOT))
		return 0;
	if (t->format == KGENOME_FMT_PE) {
		char sym[KOF_PE_SPELL_MAX];
		const struct kgenome_pe_imp imp = { 0, e->nameoff, e->ordinal, e->dll };

		if (e->dll >= t->n_dll)
			return 0;
		(void)kof_pe_import_spell(data, &imp, t->dll[e->dll], sym);
		snprintf(out, cap, "%s", sym);
		return out[0] != 0;
	}
	{
		const char *suffix = via == KOF_CALLNAME_VIA_TARGET ? "@plt" : "@got";
		size_t room = cap > 6u ? cap - 5u : 0, n = room ? elf_name(data, e->nameoff, out, room) : 0;

		if (!n) {
			out[0] = 0;
			return 0;
		}
		memcpy(out + n, suffix, 5);     /* the suffix and its NUL: room left them */
		return 1;
	}
}
