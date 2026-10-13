/*
 * addr.c - an address the file uses, as an offset into it, and back.
 *
 * Moved from libkofeng/scanners/pzero.c: the translation is read from the
 * program headers or the section table, which is the genome's knowledge of the
 * image; the cure arithmetic around it (pzero.c) stays with the engine, which
 * keeps the same two names through pzero.h.
 */

#include <kofcore.h>
#include "elf_image.h"
#include "addr.h"

/*
 * THE WAY BACK, AND IT HAD NO PUBLIC SPELLING.
 *
 * kgenome_pz_addr_to_off has existed since the cures needed it: a rule knows an
 * address and has to reach the bytes. The opposite question - a caller that
 * knows a FILE OFFSET and has to put a machine at it - had only a static
 * copy inside the decoder, so the first caller outside it had nowhere to ask.
 *
 * KGENOME_BROKEN when the offset is in no mapped region, which is a fact about
 * the file rather than a failure: a .ko has no segments at all, and an
 * offset in an ELF's section headers is in no PT_LOAD.
 */
uint64_t kgenome_pz_off_to_addr(const struct kgenome_obj *obj, uint64_t off)
{
	if (!obj || !obj->file_header)
		return KGENOME_BROKEN;
	if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);
		uint32_t i;

		if (!p->valid)
			return KGENOME_BROKEN;
		for (i = 0; i < p->sec_count; i++) {
			const struct kgenome_pe_sec *s = &p->sec[i];

			if (s->file_size && off >= s->file_off &&
			    off - s->file_off < s->file_size)
				return p->image_base + s->mem_rva +
				       (off - s->file_off);
		}
		return KGENOME_BROKEN;
	}
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
		uint32_t i;

		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
			const struct kgenome_elf_seg *s = &e->seg[i];

			if (s->type != KGENOME_ELF_PT_LOAD || !s->file_size)
				continue;
			if (off >= s->file_off &&
			    off - s->file_off < s->file_size)
				return s->mem_addr + (off - s->file_off);
		}
	}
	return KGENOME_BROKEN;
}

uint64_t kgenome_pz_addr_to_off(const struct kgenome_obj *obj, uint64_t addr)
{
	if (!obj || !obj->file_header)
		return KGENOME_BROKEN;
	if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		/* PE stores an RVA, so the image base comes off first when the
		 * caller handed over a virtual address. */
		if (addr >= p->image_base)
			addr -= p->image_base;
		return kgenome_pe_rva_to_off(p, addr);
	}
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);
		uint32_t i;

		/*
		 * THE SEGMENT AND NOT THE SECTION.
		 *
		 * A saved entry point is an address that must be mapped, and
		 * what maps is PT_LOAD. A stripped file has no sections at
		 * all and is exactly the file a cure is most often asked
		 * about.
		 */
		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
			const struct kgenome_elf_seg *s = &e->seg[i];

			if (s->type != KGENOME_ELF_PT_LOAD || !s->file_size)
				continue;
			if (addr >= s->mem_addr &&
			    addr - s->mem_addr < s->file_size)
				return s->file_off + (addr - s->mem_addr);
		}
	}
	return KGENOME_BROKEN;
}
