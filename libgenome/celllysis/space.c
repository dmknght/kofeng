/*
 * space.c - the object-layout half of celllysis's address space.
 *
 * Offset to address is the PE section table or the ELF program headers; address
 * to offset is the engine's own resolver. Both are the engine's knowledge, which
 * is why they are here and not in libgenome.
 */

#include <stdint.h>

#include <kofcore.h>
#include <genotype/image/obj.h>
#include <genotype/image/image_addr.h>
#include "space.h"

/* The headers map at the image base, one to one: the one place a PE offset
 * outside every section still has an address. */
static int pe_seg(const struct kgenome_obj *obj, uint64_t off,
		  struct kgenome_image_seg *out)
{
	const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

	if (!p->valid)
		return 0;
	if (kgenome_image_seg_at(obj, off, out))
		return 1;
	if (p->sec_count && off < p->sec[0].file_off) {
		out->lo = 0;
		out->hi = p->sec[0].file_off;
		out->delta = (int64_t)p->image_base;
		return 1;
	}
	return 0;
}

static int elf_seg(const struct kgenome_obj *obj, uint64_t off,
		   struct kgenome_image_seg *out)
{
	const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

	/*
	 * A RELOCATABLE OBJECT HAS NO LOAD ADDRESS, AND THE FILE IS THE ONLY
	 * COHERENT ADDRESS SPACE IT HAS.
	 *
	 * A .ko carries no program header at all - readelf says so in as many
	 * words - so the segment lookup finds nothing and every instruction is
	 * decoded with an address of KGENOME_BROKEN. The consequence is silent and
	 * total: a relative branch is computed from that address, so `target`
	 * is broken for every call in the object, and anything matching a call
	 * against a relocation table compares two numbers that can never be
	 * equal. MEASURED - Diamorphine yielded 0 nodes from the symbol routine
	 * for this and no other reason.
	 *
	 * The identity is not a guess: a section's sh_addr in an ET_REL is
	 * zero, the linker has not placed anything yet, and kgenome_elf_relcalls
	 * already reports its sites as file offsets. Both sides then speak the
	 * same numbers.
	 */
	if (!e->seg_count) {
		out->lo = 0;
		out->hi = (uint64_t)-1;
		out->delta = 0;
		return 1;
	}
	return kgenome_image_seg_at(obj, off, out);
}

static int obj_seg_at(void *priv, uint64_t off, struct kgenome_image_seg *out)
{
	const struct kgenome_obj *obj = priv;

	if (!obj->file_header)
		return 0;
	if (obj->format == KGENOME_FMT_PE)
		return pe_seg(obj, off, out);
	if (obj->format == KGENOME_FMT_ELF)
		return elf_seg(obj, off, out);
	return 0;
}

static uint64_t obj_off_of_va(void *priv, uint64_t va)
{
	return kgenome_image_addr_to_off(priv, va);
}

void kgenome_cell_space_init(struct kgenome_cell_space *sp, const struct kgenome_obj *obj,
			 const uint8_t *base, uint64_t size)
{
	sp->base = base;
	sp->size = size;
	sp->arch = obj->arch;
	/* The ELF header says which way the code is written. */
	sp->be = kgenome_obj_big_endian(obj);
	sp->code_le = kgenome_obj_code_little_endian(obj);
	sp->priv = (void *)(uintptr_t)obj;
	sp->seg_at = obj_seg_at;
	sp->off_of_va = obj_off_of_va;
	sp->held = NULL;
	sp->held_priv = NULL;
}
