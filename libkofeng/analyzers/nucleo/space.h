/*
 * space.h - an object's code, as celllysis wants to read it.
 *
 * celllysis (libgenome/celllysis) walks a buffer and converts between file
 * offsets and addresses, but it does not know what a PE or an ELF is: that is
 * the engine's. This is the one place that turns an object into the address
 * space celllysis asks for, so the two stay apart and a second reader of
 * object layout does not appear next to the parsers.
 */
#ifndef KOFENG_NUCLEO_SPACE_H
#define KOFENG_NUCLEO_SPACE_H

#include <stdint.h>

#include <celllysis/celllysis.h>

struct kof_obj_ctx;

/*
 * `base`/`size` are the bytes the walk reads - normally the object's own, and
 * for a payload lifted out of a variable, that. The space borrows `ctx`: it
 * must outlive the walk, as the buffer must.
 */
void kof_cell_space_init(struct cell_space *sp, const struct kof_obj_ctx *ctx,
			 const uint8_t *base, uint64_t size);

#endif /* KOFENG_NUCLEO_SPACE_H */
