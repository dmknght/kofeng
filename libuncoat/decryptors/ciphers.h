#ifndef KUNCOAT_CIPHERS_H
#define KUNCOAT_CIPHERS_H

/*
 * decryptors/ciphers.h - the keyed ciphers of kuncoat_transform: KUNCOAT_ALGO_XOR_KEY,
 * XOR_COUNTER, XOR_ADD32, PLACEHOLDER_SUB, X86_SUB_CHAIN and RC4.
 *
 * The public entry is kuncoat_transform (transform.h), which checks the step once
 * and sends a cipher here. kuncoat_cipher is the part that does the work: it
 * trusts the step and the buffers, appends at out[*w] and returns why it stopped
 * (the contract is transform.h's). An algorithm that is not a cipher is
 * KUNCOAT_UNSUPPORTED.
 */

#include <stdint.h>

#include "../transform.h"

enum kuncoat_status kuncoat_cipher(const struct kuncoat_step *s,
				   const uint8_t *in, uint64_t n,
				   uint8_t *out, uint64_t cap, uint64_t *w);

#endif /* KUNCOAT_CIPHERS_H */
