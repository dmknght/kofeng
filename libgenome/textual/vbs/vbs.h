#ifndef KGENOME_TEXTUAL_VBS_H
#define KGENOME_TEXTUAL_VBS_H

/*
 * vbs.h - the vbs directory's one header, private to the family: its row.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_vbs;

int kgenome_textual_vbs_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n);

/* The row's function table (vbs_fn.c). */
extern const struct kgenome_textual_fn_table kgenome_textual_vbs_fn_table;

#endif /* KGENOME_TEXTUAL_VBS_H */
