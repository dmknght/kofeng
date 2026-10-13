#ifndef KUNCOAT_CODINGS_H
#define KUNCOAT_CODINGS_H

/*
 * decoders/codings.h - the text codings of kuncoat_transform: KUNCOAT_ALGO_B64,
 * HEX, URL, ADD, CAESAR and REVERSE.
 *
 * The public entry is kuncoat_transform (transform.h), which checks the step once
 * and sends a coding here. kuncoat_coding is the part that does the work: it
 * trusts the step and the buffers, appends at out[*w] and returns why it stopped
 * (the contract is transform.h's). An algorithm that is not a coding is
 * KUNCOAT_UNSUPPORTED.
 */

#include <stdint.h>

#include "../transform.h"

enum kuncoat_status kuncoat_coding(const struct kuncoat_step *s,
				   const uint8_t *in, uint64_t n,
				   uint8_t *out, uint64_t cap, uint64_t *w);

#endif /* KUNCOAT_CODINGS_H */
