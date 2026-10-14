/*
 * dbcrc.h - kof_crc32 computed eight bytes a step, for the parts of a pack that are read whole (dbcrc.c).
 */
#ifndef KOFENG_DBCRC_H
#define KOFENG_DBCRC_H

#include <stdint.h>

/* The same value as kof_crc32_cont(prev, data, len) of kofcore.h, over a buffer in pieces or at once:
 * kof_crc32_fast_cont(kof_crc32_fast_cont(0, a, na), b, nb) is the CRC of a followed by b. */
uint32_t kof_crc32_fast_cont(uint32_t prev, const void *data, uint64_t len);

#endif /* KOFENG_DBCRC_H */
