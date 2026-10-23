#ifndef KGENOME_TEXTUAL_PY_H
#define KGENOME_TEXTUAL_PY_H

/*
 * py.h - the py directory's one header, private to the family: its row and its lexer.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_py;

int kgenome_textual_py_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			     uint8_t *out, uint32_t *n);
void kgenome_textual_py_lex(struct kgenome_textual_lexer *lx);

/* The control escapes (letter, byte) of a str: read by py_value.c, written by the quote in py_lang.c. */
#define KGENOME_TEXTUAL_PY_CTL "n\nt\tr\ra\ab\bf\fv\v"
/* The row of a str and of a bytes literal (py_value.c), and the one a literal's prefix says. */
extern const struct kgenome_textual_esc kgenome_textual_py_str_esc, kgenome_textual_py_bytes_esc;
const struct kgenome_textual_esc *kgenome_textual_py_esc_row(const uint8_t *lit, uint32_t open_len);

/* The row's `unescape_str`: see textual_lang.h and py_esc.c. */
uint32_t kgenome_textual_py_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out);

/* The row's function table (py_fn.c). */
extern const struct kgenome_textual_fn_table kgenome_textual_py_fn_table;

#endif /* KGENOME_TEXTUAL_PY_H */
