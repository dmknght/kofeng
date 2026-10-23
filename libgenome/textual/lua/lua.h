#ifndef KGENOME_TEXTUAL_LUA_H
#define KGENOME_TEXTUAL_LUA_H

/*
 * lua.h - the lua directory's one header, private to the family: its row, its lexer and the three
 * readers (a line break, an escape, a literal's value) that the lexer, the form and the value hook share.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_lua;

void kgenome_textual_lua_lex(struct kgenome_textual_lexer *lx);

/* The control escapes (letter, byte) of a short string: read by lua_value.c, written by the quote in lua_lang.c. */
#define KGENOME_TEXTUAL_LUA_CTL "a\ab\bf\fn\nr\rt\tv\v"
/* The line break at `i`: 1 for "\n" or "\r", 2 for "\r\n" and "\n\r" (lua reads either pair as ONE break), 0 when none. */
uint32_t kgenome_textual_lua_nl(const uint8_t *p, uint32_t n, uint32_t i);


/*
 * The numeric escape at `i` (the backslash) in a short string: "\xHH" (exactly two hex digits), "\ddd" (one to three
 * decimal digits, at most 255) or "\u{H...}" (at most 0x7FFFFFFF). Its length and, in `*v`, its value; 0 when it is
 * not one of those or is not valid (lua stops with an error there).
 */
uint32_t kgenome_textual_lua_esc_at(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *v);

/* The row's `value` and `unescape_str`: see lua_value.c and lua_esc.c. */
int kgenome_textual_lua_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			      uint8_t *out, uint32_t *n);
uint32_t kgenome_textual_lua_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out);

/* The row's function table (lua_fn.c). */
extern const struct kgenome_textual_fn_table kgenome_textual_lua_fn_table;

#endif /* KGENOME_TEXTUAL_LUA_H */
