/*
 * space.h - an engine object's code, as celllysis reads it.
 *
 * The cursor walks a buffer through a `struct cell_space` and does not know what
 * a PE or an ELF is. This is the one place that builds that space from the
 * engine's object - the PE section table or the ELF program headers - so a
 * second reader of object layout does not appear next to the parsers. It is the
 * only celllysis file that includes the engine's object types; the walk itself
 * (cursor.c) and everything under it stay free of them.
 */
#ifndef KOFENG_NUCLEO_SPACE_H
#define KOFENG_NUCLEO_SPACE_H

#include <stdint.h>

#include "celllysis.h"

struct kof_obj_ctx;

/*
 * `base`/`size` are the bytes the walk reads - normally the object's own, and
 * for a payload lifted out of a variable, that. The space borrows `ctx`: it
 * must outlive the walk, as the buffer must.
 */
void kof_cell_space_init(struct cell_space *sp, const struct kof_obj_ctx *ctx,
			 const uint8_t *base, uint64_t size);

#endif /* KOFENG_NUCLEO_SPACE_H */
