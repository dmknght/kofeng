#ifndef KGENOME_TEXTUAL_JS_H
#define KGENOME_TEXTUAL_JS_H

/*
 * js.h - the js directory's one header, private to the family: its row.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_js;

int kgenome_textual_js_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			     uint8_t *out, uint32_t *n);

/* The pairs (letter, byte) of the control escapes: what the value reader (js_value.c) turns into a byte and what the quote (js_lang.c) writes one as. */
#define KGENOME_TEXTUAL_JS_CTL "n\nr\rt\tb\bf\fv\v"
/* The row of a javascript string (js_value.c), which js_lang.c's `unescape_str` reads its escapes with. */
extern const struct kgenome_textual_esc kgenome_textual_js_esc;

/* The row's function table (js_fn.c). */
extern const struct kgenome_textual_fn_table kgenome_textual_js_fn_table;

#endif /* KGENOME_TEXTUAL_JS_H */
