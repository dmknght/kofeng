#ifndef KGENOME_TEXTUAL_PHP_H
#define KGENOME_TEXTUAL_PHP_H

/*
 * php.h - the php directory's one header, private to the family: its row and its lexer.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_php;

void kgenome_textual_php_lex(struct kgenome_textual_lexer *lx);
/* The row's `tag_own` (php_lex.c). */
uint32_t kgenome_textual_php_tag_own(const uint8_t *tag, uint32_t len, int close);
int kgenome_textual_php_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n);
/* Past the "{...}" that starts at `j` in a double quoted string (php_lex.c): the lexer's reading of an interpolation, which the form's unescape skips by too. */
uint32_t kgenome_textual_php_skip_braces(const uint8_t *p, uint32_t n, uint32_t j);
/* The row of a double quoted php string (php_value.c) and the row's `unescape_str` (php_esc.c); asp's jscript islands borrow it. */
extern const struct kgenome_textual_esc kgenome_textual_php_dq;
uint32_t kgenome_textual_php_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out);
/* The row's function table (php_fn.c). */
extern const struct kgenome_textual_fn_table kgenome_textual_php_fn_table;
/* The calls php decodes a literal with, read backwards from it (php_anchor.c). */
extern const struct kgenome_textual_call_style kgenome_textual_php_calls;

#endif /* KGENOME_TEXTUAL_PHP_H */
