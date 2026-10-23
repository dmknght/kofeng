#ifndef KGENOME_IMAGE_ADDR_H
#define KGENOME_IMAGE_ADDR_H

#include <stdint.h>

struct kgenome_obj;

/*
 * AN ADDRESS THE FILE USES, AS AN OFFSET INTO IT.
 *
 * A saved entry point is an address; every request a cure makes is an offset.
 * PE answers this from its section table and ELF from its program headers,
 * and doing it here rather than in each rule is what stops a module
 * dispatching on format.
 *
 * KGENOME_BROKEN when no region of the file is mapped there.
 */
/*
 * The mapping that holds a file offset: [lo, hi) of the file and the constant to
 * add to an offset inside it to get its address. The one lookup behind
 * kgenome_image_off_to_addr and behind the cell space (celllysis/space.c), which
 * adds the policies of its own (the PE headers, a relocatable ELF) on top.
 * Zero when no PE section or PT_LOAD holds the offset.
 */
struct kgenome_image_seg {
	uint64_t lo, hi;
	int64_t  delta;
};
int kgenome_image_seg_at(const struct kgenome_obj *obj, uint64_t off,
			 struct kgenome_image_seg *out);

uint64_t kgenome_image_addr_to_off(const struct kgenome_obj *obj, uint64_t addr);
/* And back - KGENOME_BROKEN for an offset in no mapped region. */
uint64_t kgenome_image_off_to_addr(const struct kgenome_obj *obj, uint64_t off);

#endif /* KGENOME_IMAGE_ADDR_H */
