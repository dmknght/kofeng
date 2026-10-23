#ifndef KUNCOAT_STRFN_H
#define KUNCOAT_STRFN_H

/*
 * decoders/strfn.h - the string functions of kuncoat_transform: KUNCOAT_ALGO_REPLACE, TRANSLATE,
 * SLICE, CASE, TRIM and REPEAT. Same contract as kuncoat_coding (codings.h): the step and buffers are trusted,
 * the answer is appended at out[*w], the result says why it stopped.
 */

#include <stdint.h>

#include "../transform.h"

enum kuncoat_status kuncoat_strfn(const struct kuncoat_step *s,
				  const uint8_t *in, uint64_t n,
				  uint8_t *out, uint64_t cap, uint64_t *w);

#endif /* KUNCOAT_STRFN_H */
