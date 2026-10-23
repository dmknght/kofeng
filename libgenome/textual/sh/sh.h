#ifndef KGENOME_TEXTUAL_SH_H
#define KGENOME_TEXTUAL_SH_H

/*
 * sh.h - the sh directory's one header, private to the family: its row and its lexer.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_sh;

void kgenome_textual_sh_lex(struct kgenome_textual_lexer *lx);

/* The reader of words, commands and assignments (sh_cmd.c) and the row's function table (sh_fn.c). */
extern const struct kgenome_textual_cmd_syntax kgenome_textual_sh_syntax;

/* The row's `value` (sh_cmd.c): the bytes of a quoted run that expands nothing. 0 otherwise. */
int kgenome_textual_sh_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags, uint8_t *out, uint32_t *n);
extern const struct kgenome_textual_fn_table kgenome_textual_sh_fn_table;

#endif /* KGENOME_TEXTUAL_SH_H */
