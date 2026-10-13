/*
 * genome_obj.h - the engine's object, handed to kgenome as the descriptor kgenome
 * defines.
 *
 * kgenome never sees `struct kof_obj_ctx`: it takes a `struct kgenome_obj`
 * (<genotype/image/obj.h>), and this is the one place that knows both. A HEAD
 * function of the engine - one that holds a context and calls the lib - builds
 * the descriptor here and passes it. The descriptor is a snapshot of the facts
 * the lib reads; it borrows nothing from the context except `file_header`.
 */
#ifndef KOFENG_GENOME_OBJ_H
#define KOFENG_GENOME_OBJ_H

#include <genotype/image/obj.h>

struct kof_obj_ctx;

/* Fill `out` from `ctx`. */
void kof_genome_obj(const struct kof_obj_ctx *ctx, struct kgenome_obj *out);

/*
 * The other direction, for the parsers: the genome parse writes its answer into
 * a descriptor (format, arch, subtype, size, entry, parsed view) and this puts
 * those fields back into the context. Nothing else of the context is touched.
 */
void kof_genome_obj_store(struct kof_obj_ctx *ctx, const struct kgenome_obj *obj);

#endif /* KOFENG_GENOME_OBJ_H */
