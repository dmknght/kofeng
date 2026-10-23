#ifndef KGENOME_TEXTUAL_JSP_H
#define KGENOME_TEXTUAL_JSP_H

/*
 * jsp.h - the jsp directory's one header, private to the family: its row, and what its files share.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_jsp;

/* The control escapes (letter, byte) of a java string that every java reads the same way: read by jsp_value.c, written by the quote in jsp_lang.c. */
#define KGENOME_TEXTUAL_JAVA_CTL "n\nt\tr\rb\bf\f"
/* The page host's `markup` hook for jsp (jsp_lex.c): <jsp:scriptlet> and the like, and EL. */
uint32_t kgenome_textual_jsp_markup(struct kgenome_textual_lexer *lx, const struct kgenome_textual_page *pg,
				    uint32_t at);

/* The row's call_chain (jsp_decode.c): the java calls that decode a literal. */
int kgenome_textual_jsp_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n);
uint32_t kgenome_textual_jsp_call_chain(const uint8_t *tail, uint32_t n, uint8_t *chain, uint32_t cap,
				    uint32_t *from);

#endif /* KGENOME_TEXTUAL_JSP_H */
