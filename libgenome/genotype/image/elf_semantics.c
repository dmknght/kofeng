/*
 * elf_semantics.c - what the ELF headers mean, as words and facts for a tool (declared in elf_image.h):
 * linking and symbol/debug shape, the section that holds the entry. Pure functions of the parsed view.
 */
#include "elf_image.h"

#include <stdint.h>
#include <string.h>

/* ---- what the headers mean ------------------------------------------------------------------------------ */

#define KGENOME_ELF_PT_DYNAMIC 2u
#define KGENOME_ELF_PT_INTERP  3u

void kgenome_elf_shape(const struct kgenome_elf_info *e, struct kgenome_elf_shape *out)
{
	uint32_t i, ns, nc;
	int load = 0, dyn = 0, interp = 0;

	memset(out, 0, sizeof *out);
	if (!e->valid)
		return;
	ns = e->seg_count < KGENOME_ELF_MAX_SEGMENTS ? e->seg_count : KGENOME_ELF_MAX_SEGMENTS;
	for (i = 0; i < ns; i++) {
		load   |= e->seg[i].type == KGENOME_ELF_PT_LOAD;
		dyn    |= e->seg[i].type == KGENOME_ELF_PT_DYNAMIC;
		interp |= e->seg[i].type == KGENOME_ELF_PT_INTERP;
	}
	out->linking = interp ? KGENOME_ELF_LINK_DYNAMIC :
		       dyn    ? KGENOME_ELF_LINK_DYNAMIC_NOINTERP :
		       load   ? KGENOME_ELF_LINK_STATIC : KGENOME_ELF_LINK_NONE;
	nc = e->sec_count < KGENOME_ELF_MAX_SECTIONS ? e->sec_count : KGENOME_ELF_MAX_SECTIONS;
	for (i = 0; i < nc; i++) {
		const struct kgenome_elf_sec *s = &e->sec[i];

		if (s->type == KGENOME_ELF_SHT_SYMTAB && s->file_size)
			out->has_symtab = 1;
		if (strncmp(s->name, ".debug_", 7) == 0)
			out->has_debug = 1;
	}
}

int kgenome_elf_entry_sec(const struct kgenome_elf_info *e, uint32_t *index, uint64_t *delta)
{
	uint32_t i, nc;

	if (!e->valid)
		return -1;
	nc = e->sec_count < KGENOME_ELF_MAX_SECTIONS ? e->sec_count : KGENOME_ELF_MAX_SECTIONS;
	for (i = 0; i < nc; i++) {
		const struct kgenome_elf_sec *s = &e->sec[i];

		if (!(s->flags & KGENOME_ELF_SHF_ALLOC) || s->type == KGENOME_ELF_SHT_NULL ||
		    s->type == KGENOME_ELF_SHT_NOBITS || !s->file_size)
			continue;
		if (e->entry_addr >= s->mem_addr && e->entry_addr - s->mem_addr < s->file_size) {
			*index = i;
			*delta = e->entry_addr - s->mem_addr;
			return 0;
		}
	}
	return -1;
}
