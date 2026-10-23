#ifndef KGENOME_TEXTUAL_ASPX_H
#define KGENOME_TEXTUAL_ASPX_H

/*
 * aspx.h - the aspx directory's one header, private to the family: its row.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_aspx;

/* The control escapes (letter, byte) of a c# string: read by aspx_value.c. */
#define KGENOME_TEXTUAL_CS_CTL "n\nt\tr\ra\ab\bf\fv\v"
int kgenome_textual_aspx_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			       uint8_t *out, uint32_t *n);

#endif /* KGENOME_TEXTUAL_ASPX_H */
