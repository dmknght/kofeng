/*
 * space.c - the object-layout half of celllysis's address space.
 *
 * Offset to address is the PE section table or the ELF program headers; address
 * to offset is the engine's own resolver. Both are the engine's knowledge, which
 * is why they are here and not in libgenome.
 */

#include <stdint.h>

#include "kofcore.h"
#include "kofmod/kofsig.h"
#include "kofmod/pe.h"
#include "kofmod/elf.h"
#include "../../libkofeng/disinfect/pzero.h"
#include "space.h"

static int pe_seg(const struct kof_obj_ctx *ctx, uint64_t off,
		  struct cell_seg *out)
{
	const struct kof_pe_info *p = kof_pe(ctx);
	uint32_t i;

	if (!p->valid)
		return 0;
	for (i = 0; i < p->sec_count; i++) {
		const struct kof_pe_sec *s = &p->sec[i];

		if (s->file_size && off >= s->file_off &&
		    off - s->file_off < s->file_size) {
			out->lo = s->file_off;
			out->hi = s->file_off + s->file_size;
			out->delta = (int64_t)(p->image_base + s->mem_rva) -
				     (int64_t)s->file_off;
			return 1;
		}
	}
	/* The headers map at the image base, one to one. */
	if (p->sec_count && off < p->sec[0].file_off) {
		out->lo = 0;
		out->hi = p->sec[0].file_off;
		out->delta = (int64_t)p->image_base;
		return 1;
	}
	return 0;
}

static int elf_seg(const struct kof_obj_ctx *ctx, uint64_t off,
		   struct cell_seg *out)
{
	const struct kof_elf_info *e = kof_elf(ctx);
	uint32_t i;

	/*
	 * A RELOCATABLE OBJECT HAS NO LOAD ADDRESS, AND THE FILE IS THE ONLY
	 * COHERENT ADDRESS SPACE IT HAS.
	 *
	 * A .ko carries no program header at all - readelf says so in as many
	 * words - so the loop below finds nothing and every instruction is
	 * decoded with an address of KOF_BROKEN. The consequence is silent and
	 * total: a relative branch is computed from that address, so `target`
	 * is broken for every call in the object, and anything matching a call
	 * against a relocation table compares two numbers that can never be
	 * equal. MEASURED - Diamorphine yielded 0 nodes from the symbol routine
	 * for this and no other reason.
	 *
	 * The identity is not a guess: a section's sh_addr in an ET_REL is
	 * zero, the linker has not placed anything yet, and kof_elf_relcalls
	 * already reports its sites as file offsets. Both sides then speak the
	 * same numbers.
	 */
	if (!e->seg_count) {
		out->lo = 0;
		out->hi = (uint64_t)-1;
		out->delta = 0;
		return 1;
	}
	for (i = 0; i < e->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		const struct kof_elf_seg *s = &e->seg[i];

		if (s->type != 1u || !s->file_size)   /* PT_LOAD */
			continue;
		if (off >= s->file_off && off - s->file_off < s->file_size) {
			out->lo = s->file_off;
			out->hi = s->file_off + s->file_size;
			out->delta = (int64_t)s->mem_addr - (int64_t)s->file_off;
			return 1;
		}
	}
	return 0;
}

static int obj_seg_at(void *priv, uint64_t off, struct cell_seg *out)
{
	const struct kof_obj_ctx *ctx = priv;

	if (!ctx->file_header)
		return 0;
	if (ctx->format == KOF_FMT_PE)
		return pe_seg(ctx, off, out);
	if (ctx->format == KOF_FMT_ELF)
		return elf_seg(ctx, off, out);
	return 0;
}

static uint64_t obj_off_of_va(void *priv, uint64_t va)
{
	return kof_pz_addr_to_off(priv, va);
}

void kof_cell_space_init(struct cell_space *sp, const struct kof_obj_ctx *ctx,
			 const uint8_t *base, uint64_t size)
{
	sp->base = base;
	sp->size = size;
	sp->arch = ctx->arch;
	/* The ELF header says which way the code is written. */
	sp->be = ctx->format == KOF_FMT_ELF && ctx->file_header &&
		 ((const uint8_t *)ctx->file_header)[5] == 2u;
	sp->priv = (void *)ctx;
	sp->seg_at = obj_seg_at;
	sp->off_of_va = obj_off_of_va;
}
