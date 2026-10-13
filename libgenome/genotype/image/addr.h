#ifndef KGENOME_IMAGE_ADDR_H
#define KGENOME_IMAGE_ADDR_H

#include <stdint.h>

struct kgenome_obj;

/* Moved from scanners/pzero.h, which includes this header and so keeps both
 * names reachable for its callers. */
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
uint64_t kgenome_pz_addr_to_off(const struct kgenome_obj *obj, uint64_t addr);
/* And back - KGENOME_BROKEN for an offset in no mapped region. */
uint64_t kgenome_pz_off_to_addr(const struct kgenome_obj *obj, uint64_t off);

#endif /* KGENOME_IMAGE_ADDR_H */
