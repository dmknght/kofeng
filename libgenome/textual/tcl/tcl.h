#ifndef KGENOME_TEXTUAL_TCL_H
#define KGENOME_TEXTUAL_TCL_H

/*
 * tcl.h - the tcl directory's one header, private to the family: its row, its lexer and the readers that
 * the lexer, the form and the value hook share.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_tcl;

void kgenome_textual_tcl_lex(struct kgenome_textual_lexer *lx);

/*
 * The numeric escape at `i` (the backslash) of a word, as tcl 8.6 reads it: "\xH" or "\xHH" (at most two digits), "\o", "\oo" or "\ooo"
 * (the third digit only when the first is 0-3, so at most \377), "\uH" to "\uHHHH", "\UH" to "\UHHHHHHHH" (a digit that would take
 * the value past U+10FFFF is not read). Its length, in `*v` its value (a code point; past U+FFFF it is U+FFFD, as tcl 8.6 has it), in `*digits` how many digits it took; 0 when it is not one -
 * "\x" with no digit is the letter x. `*max` is how many digits it could have taken.
 */
uint32_t kgenome_textual_tcl_esc_at(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *v, uint32_t *digits, uint32_t *max);

/* The bytes of the text in p[0..n) as tcl reads a word's content: a braced one (nothing but backslash-newline is substituted) or a double-quoted/bare one (escapes). 0 when a
 * "$name" or "[" substitution is in it. At most n bytes are written to `out`; their count in `*w`. */
int kgenome_textual_tcl_text_value(const uint8_t *p, uint32_t n, int braced, uint8_t *out, uint32_t *w_out);

/* The reader of words, commands and assignments (tcl_cmd.c) and the row's function table (tcl_fn.c). */
extern const struct kgenome_textual_cmd_syntax kgenome_textual_tcl_syntax;
extern const struct kgenome_textual_fn_table kgenome_textual_tcl_fn_table;

/* The control escapes (letter, byte) of a double-quoted word: read by tcl_value.c, written by the quote in tcl_lang.c. */
#define KGENOME_TEXTUAL_TCL_CTL "a\ab\bf\fn\nr\rt\tv\v"
/* The row's `value` and `unescape_str`: see tcl_value.c and tcl_esc.c. */
int kgenome_textual_tcl_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n);
uint32_t kgenome_textual_tcl_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out);

#endif /* KGENOME_TEXTUAL_TCL_H */
