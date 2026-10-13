/*
 * range.h - a range of bytes of an object: an offset and a length.
 *
 * A generic type, so it is defined in core. It is used by rangelist.h (the
 * geometry of a set of ranges), by the region resolvers of the parsers, by the
 * genome libs that partition an object, and by modules, which receive it through
 * <kofmod/kofsig.h> (that header re-exports this one). Types only: no function
 * lives here, and nothing here depends on anything but <stdint.h>.
 *
 * It used to be defined in the libgenome image directory, which made core
 * (rangelist.h, through kofsig.h) depend on the genome lib. A lib may include core;
 * core may not include a lib.
 */
#ifndef KOFENG_RANGE_H
#define KOFENG_RANGE_H

#include <stddef.h>
#include <stdint.h>

/*
 * THE INTERVAL TYPES OF THE TREE, and why each is its own type.
 *
 *   struct kof_range    (here)       a range of bytes of ONE OBJECT: offset, length.
 *   struct kof_run      (here)       a kof_range plus the class that claims it - the
 *                                    parsers' run lists (runlist.h) and the `run[]`
 *                                    array of every kofmod/ parser info. Same first
 *                                    two members, so a run is read as a range.
 *   struct kofa_run     (aproc.h)    a range of a PROCESS's address space
 *   struct kofw_diff_range (wdiff.h) (orbit): `addr`, not `off`, because it is a
 *                                    virtual address in another process and an object
 *                                    offset must never be mistaken for one.
 *   struct kgenome_emu_wrange (emu_private.h)  a HALF-OPEN [lo, hi) of guest addresses
 *                                    an emulated run watches. Half-open, not
 *                                    offset+length, because what it answers is "is this
 *                                    address inside" for a table of them, and the end
 *                                    of one range is the start of the next with no
 *                                    off + len to wrap at the top of the address space.
 */

/* A resolved range. len == 0 means the extent is empty. */
struct kof_range {
	uint64_t off;
	uint64_t len;
};

/* One run of bytes and what claims it: a range and the class number the format
 * gave it (the format's own enum - enum kof_zip_class and the like). `reserved`
 * keeps the record at 24 bytes and is zero. */
struct kof_run {
	uint64_t off, len;
	uint32_t cls;
	uint32_t reserved;
};

_Static_assert(offsetof(struct kof_run, len) == offsetof(struct kof_range, len) &&
	       offsetof(struct kof_run, off) == offsetof(struct kof_range, off),
	       "a kof_run begins with a kof_range");

#endif /* KOFENG_RANGE_H */
