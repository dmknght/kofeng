#ifndef KGENOME_TEXTUAL_BAT_H
#define KGENOME_TEXTUAL_BAT_H

/*
 * bat.h - the bat directory's one header, private to the family: its row and its lexer.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_bat;

void kgenome_textual_bat_lex(struct kgenome_textual_lexer *lx);

/* The reader of words, commands and assignments (bat_cmd.c) and the row's function table (bat_fn.c). */
extern const struct kgenome_textual_cmd_syntax kgenome_textual_bat_syntax;
extern const struct kgenome_textual_fn_table kgenome_textual_bat_fn_table;

/* The value of a closed string with nothing in it to expand: the bytes between its quotes. 0 otherwise. */
int kgenome_textual_bat_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n);

#endif /* KGENOME_TEXTUAL_BAT_H */
