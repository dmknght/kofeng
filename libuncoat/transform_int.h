#ifndef KUNCOAT_TRANSFORM_INT_H
#define KUNCOAT_TRANSFORM_INT_H

/*
 * transform_int.h - what the dispatcher (transform.c), the ciphers
 * (decryptors/ciphers.c) and the codings (decoders/codings.c) share and nothing
 * else sees. Private to the lib: it is not in uncoat.h.
 */

#include <stdint.h>

#include "transform.h"

typedef enum kuncoat_status kuncoat_st_t;

/* Arguments are checked once, in kuncoat_transform. The stream routines: one byte
 * out for each byte in, so a short room is the only way to stop early. */
static inline kuncoat_st_t kuncoat_room_end(uint64_t w, uint64_t n)
{
	return w < n ? KUNCOAT_OVER_BUDGET : KUNCOAT_OK;
}

#endif /* KUNCOAT_TRANSFORM_INT_H */
