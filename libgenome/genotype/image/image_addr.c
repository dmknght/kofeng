/*
 * image_addr.c - an address the file uses, as an offset into it, and back.
 *
 * The translation is read from the program headers or the section table, which
 * is the genome's knowledge of the image.
 */

#include <kofcore.h>
#include "elf_image.h"
#include "image_addr.h"

/*
 * THE WAY BACK, AND IT HAD NO PUBLIC SPELLING.
 *
 * kgenome_image_addr_to_off has existed since the cures needed it: a rule knows an
 * address and has to reach the bytes. The opposite question - a caller that
 * knows a FILE OFFSET and has to put a machine at it - had only a static
 * copy inside the decoder, so the first caller outside it had nowhere to ask.
 *
 * KGENOME_BROKEN when the offset is in no mapped region, which is a fact about
 * the file rather than a failure: a .ko has no segments at all, and an
 * offset in an ELF's section headers is in no PT_LOAD.
 */
uint64_t kgenome_image_off_to_addr(const struct kgenome_obj *obj, uint64_t off)
{
	struct kgenome_image_seg g;

	if (!kgenome_image_seg_at(obj, off, &g))
		return KGENOME_BROKEN;
	return off + (uint64_t)g.delta;            /* modular: a delta is a signed offset in two's complement */
}

int kgenome_image_seg_at(const struct kgenome_obj *obj, uint64_t off,
			 struct kgenome_image_seg *out)
{
	if (!obj || !obj->file_header)
		return 0;
	if (obj->format == KGENOME_FMT_PE) {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);
		const struct kgenome_pe_sec *s;

		if (!p->valid)
			return 0;
		s = kgenome_pe_sec_at_off(p, off);
		if (!s)
			return 0;
		out->lo = s->file_off;
		out->hi = s->file_off + s->file_size;
		out->delta = (int64_t)((p->image_base + s->mem_rva) - s->file_off);
		return 1;
	}
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_seg *s = kgenome_elf_load_at_off(kgenome_obj_elf(obj), off);

		if (!s)
			return 0;
		out->lo = s->file_off;
		out->hi = s->file_off + s->file_size;
		out->delta = (int64_t)(s->mem_addr - s->file_off);
		return 1;
	}
	return 0;
}

uint64_t kgenome_image_addr_to_off(const struct kgenome_obj *obj, uint64_t addr)
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
		uint64_t off;

		/*
		 * THE SEGMENT AND NOT THE SECTION.
		 *
		 * A saved entry point is an address that must be mapped, and
		 * what maps is PT_LOAD. A stripped file has no sections at
		 * all and is exactly the file a cure is most often asked
		 * about.
		 */
		if (kgenome_elf_va_to_off(kgenome_obj_elf(obj), addr, 0, &off))
			return off;
	}
	return KGENOME_BROKEN;
}
