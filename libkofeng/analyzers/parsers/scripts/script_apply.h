#ifndef KOF_SCRIPT_APPLY_H
#define KOF_SCRIPT_APPLY_H

/*
 * script_apply.h - the engine's half of kgenome_textual_apply_fn: the function of bytes a script calls, run by kuncoat.
 *
 * ONE PLACE for what `base64_decode`, `str_replace`, `strrev` and the rest DO, so that the form that rewrites a call on
 * literals, the evaluator that follows a variable to its value and the gate that asks for the names a script builds all get the
 * same bytes. Nothing here keeps state, so it can be handed to the lib as it is (`user` is not read).
 *
 * NOT HERE: the inflate family (gzinflate, gzuncompress, gzdecode). Their output has no bound the input gives and the scanner's
 * budget and inflate state are what bound it, so the engine's decode stage runs them (objctx_script_dec.c); asked here, they
 * are refused.
 */

#include <stdint.h>

#include <textual/textual.h>

/* The most bytes `c` can write for `len` bytes in, or 0 for an op this does not run. */
uint64_t kof_script_apply_room(const struct kgenome_textual_call *c, uint64_t len);

/* kgenome_textual_apply_fn. */
int kof_script_apply(void *user, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out,
		     uint32_t cap, uint32_t *n_out);

#endif /* KOF_SCRIPT_APPLY_H */
