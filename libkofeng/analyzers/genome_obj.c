/*
 * genome_obj.c - fill kgenome's object descriptor from the engine's context.
 * See genome_obj.h.
 */
#include <kofmod/kofsig.h>
#include "genome_obj.h"

/* The descriptor's format values are the engine's. */
_Static_assert((int)KGENOME_FMT_ELF == (int)KOF_FMT_ELF, "format values differ");
_Static_assert((int)KGENOME_FMT_PE == (int)KOF_FMT_PE, "format values differ");

void kof_genome_obj(const struct kof_obj_ctx *ctx, struct kgenome_obj *out)
{
	out->format = ctx->format;
	out->arch = ctx->arch;
	out->subtype = ctx->subtype;
	out->reserved = 0;
	out->obj_size = ctx->obj_size;
	out->entry_off = ctx->entry_off;
	out->file_header = ctx->file_header;
}

void kof_genome_obj_store(struct kof_obj_ctx *ctx, const struct kgenome_obj *obj)
{
	ctx->format = obj->format;
	ctx->arch = obj->arch;
	ctx->subtype = obj->subtype;
	ctx->obj_size = obj->obj_size;
	ctx->entry_off = obj->entry_off;
	ctx->file_header = obj->file_header;
}
