/*
 * lua_lang.c - the row for lua: its lexer, what closing up two tokens would change, and what the form needs to know.
 *
 * WHAT THE ROW LEAVES OUT, AND WHY.
 *   - concat / concat_adjacent: lua joins strings with "..", and the row's `concat` is ONE byte. A join is only read by
 *     the form to put a decoder over it, and lua has no decoder by name (below), so the join is left off. "a" .. "b"
 *     is two literals, as typed. (Naming "." would make the form hold "a" . "b" as a join, which no lua program says.)
 *   - call_chain / payload_ok: the standard library has no function from an encoded string to bytes. base64, hex,
 *     url and zlib decoding are not in it (string.unpack and string.pack are about binary layouts, not encodings). The
 *     two calls a payload goes through, load("text") and the 5.1 loadstring("text"), take TEXT and RUN it: the argument
 *     is a program, not bytes a decoder id could name, so there is nothing for the decode hook to be asked and the
 *     chain is NULL. [Inference] A host's own functions (nginx's ngx.decode_base64, luasocket's mime.unb64) are not the
 *     language's; they are not listed on purpose.
 *   - join_brace, continuation, ws_significant: a line break is white space to lua, as any blank; there is no
 *     continuation backslash; the form keeps one line break where there were several (a statement may end there).
 *
 * universal_eol IS ON: lua's lexer counts "\n", "\r", "\r\n" and "\n\r" as one line break each (inclinenumber), so a
 * comment and an unclosed one-line string end at a lone CR too, and the form must write that CR as a line break or the
 * string would swallow what follows it. The row's other universal_eol effects are python-only (they need `continuation`).
 */

#include <kofcore.h>

#include "lua.h"

/*
 * WOULD CLOSING THESE TWO UP MAKE ONE TOKEN OF TWO, OR START A COMMENT OR A LONG BRACKET:
 *   - an operator byte then "=": == ~= <= >=;
 *   - "- -" is "--", a comment; ". ." is "..", and a third makes "..."; "/ /", "< <", "> >" and ": :" are //, <<, >>, ::;
 *   - "[ [" and "[ =" and "= [" would make "[[", "[=" and "=[", which open a long string or comment when the
 *     bytes between make "[=*[": the pair is kept apart wherever a "[" meets a "[" or an "=";
 *   - a hex digit then ".": "1 .. 2" must not become "1..2", nor "0xe .. x" "0xe..x": one malformed numeral each (a numeral
 *     takes every hex digit and ".", and a glue cannot tell a name that ends in "e" from a number that does);
 *   - "." then a letter or "_": "5. until" must not become "5.until", a malformed number too (found by running the form of
 *     generated programs through luac). A glue sees two bytes and cannot tell "5." from "a." or "..", so "a .. b" is
 *     written "a.. b": one byte, only where a blank was typed.
 * Not here, on purpose: "+ +", "* *", "% %", "^ ^", "# #", "~ ~" and "& &" are two tokens either way, and
 * a name next to a name is the form's own rule.
 */
static int lua_glue(uint8_t a, uint8_t b)
{
	if (kgenome_textual_glue_assign(a, b, "=~<>") || kgenome_textual_glue_twice(a, b, "-./<>:"))
		return 1;
	if ((a == '[' && (b == '[' || b == '=')) || (a == '=' && b == '['))
		return 1;
	if (a == '.' && kgenome_textual_ident_start(b))
		return 1;
	return b == '.' && kof_hex_val(a) >= 0;
}

/* A single quoted short string: the backslash and the quote escaped, a control byte as its letter or \ddd (three decimal digits, so that a digit
 * after it is not read into it): a raw line break cannot be in a short string. */
static const struct kgenome_textual_quote quote = { .q = '\'', .bs = "\\", .letters = KGENOME_TEXTUAL_LUA_CTL, .ctl = 'd' };

const struct kgenome_textual_lang kgenome_textual_lang_lua = {
	.name = "lua",
	.id = KGENOME_TEXTUAL_LANG_LUA,
	.lex = kgenome_textual_lua_lex,
	.glue = lua_glue,
	.universal_eol = 1,
	.keep_hashbang = 1,
	.unescape_str = kgenome_textual_lua_unescape,
	.fn_table = &kgenome_textual_lua_fn_table,
	.member_dot = 1,
	.value = kgenome_textual_lua_value,
	.quote = &quote,
};
