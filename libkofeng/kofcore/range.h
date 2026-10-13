/*
 * range.h - a range of bytes of an object: an offset and a length.
 *
 * A generic type, so it is defined in core. It is used by rangelist.h (the
 * geometry of a set of ranges), by the region resolvers of the parsers, by the
 * genome libs that partition an object, and by modules, which receive it through
 * <kofmod/kofsig.h> (that header re-exports this one). Types only: no function
 * lives here, and nothing here depends on anything but <stdint.h>.
 *
 * It used to be defined in libgenome/genotype/image/range.h, which made core
 * (rangelist.h, through kofsig.h) depend on the genome lib. A lib may include core;
 * core may not include a lib.
 */
#ifndef KOFENG_RANGE_H
#define KOFENG_RANGE_H

#include <stdint.h>

/* A resolved range. len == 0 means the extent is empty. */
struct kof_range {
	uint64_t off;
	uint64_t len;
};

#endif /* KOFENG_RANGE_H */
