/*
 * stub_pat.h - "the entry point begins with THESE bytes", for a module whose
 * stub has a fixed shape and a few variable bytes.
 *
 * Module-side helper, like ep_shape.h (which is for a table of rows with a
 * wildcard MASK; this is for rows over a table of 16-bit cells, 0x100 meaning
 * "any byte"). Written out in msf_x86_sub_00.c and msf_x86_dword_00.c word for
 * word.
 *
 * A MACRO THAT DEFINES THE FUNCTION, invoked where the module had it: a blob is
 * linked with -ffunction-sections and its bytes follow the order the functions
 * were emitted in, so a plain static function moved up into this header would
 * reorder the blob. See upx_method.h.
 *
 *     KOF_STUB_DEFINE_IS(stub_is, coding, stub_pat)
 *
 * defines `static int stub_is(ctx, ep, c)`: do the coding[c].n cells at
 * stub_pat[coding[c].at] match the object at `ep`? Reads inside the object only,
 * so a file that ends inside the pattern matches nothing.
 */

#ifndef KOF_STUB_PAT_H
#define KOF_STUB_PAT_H

#define KOF_STUB_DEFINE_IS(name, rows, pat)                                \
static int name(const struct kof_obj_ctx *ctx, uint64_t ep, uint32_t c)    \
{                                                                          \
	uint32_t i;                                                        \
                                                                           \
	if (!kof_in_obj(ep, (rows)[c].n))                                  \
		return 0;                                                  \
	for (i = 0; i < (rows)[c].n; i++) {                                \
		uint16_t w = (pat)[(rows)[c].at + i];                      \
                                                                           \
		if (w != 0x100u && kof_u8(ep + i) != (uint8_t)w)           \
			return 0;                                          \
	}                                                                  \
	return 1;                                                          \
}

#endif /* KOF_STUB_PAT_H */
