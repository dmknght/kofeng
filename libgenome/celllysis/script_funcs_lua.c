/*
 * script_funcs_lua.c - the functions of a LUA text (script_private.h, kgenome_script_strategy).
 *
 * THE SPECIFICATION READ (Lua 5.4 Reference Manual, 3.3 "Statements", 3.4.11 "Function Definitions", and the complete syntax in 9;
 * 5.1 to 5.3 have the same block grammar):
 *   - A FUNCTION is "function funcname funcbody" (funcname = Name {"." Name} [":" Name]), "local function Name funcbody", or the
 *     expression "function funcbody" (anonymous: name length 0). funcbody = "(" [parlist] ")" block "end". "local" directly in front
 *     (blanks and line breaks between) belongs to the declaration and the entry starts there; an anonymous function starts at its
 *     keyword (what is in front of it is the expression it is a part of).
 *   - THE BLOCKS that close with "end": function, "if ... then ... end" (elseif / else / then open nothing), "while exp do ... end"
 *     and "for ... do ... end" (the loop's "do" is part of the loop: counted ONCE), "do ... end" standing alone. "repeat block until
 *     exp" closes with "until", not "end". The entry ends after the "end" that closes the function.
 *   - Keywords are reserved (2.1): a field or a method can never be named "end", so a CODE word equal to a keyword IS the keyword.
 *     Strings ("...", '...', [[...]], [==[...]==]) and comments (--, --[[...]]) are the lexer's STRING and COMMENT spans and are never
 *     read for a keyword.
 *   - Only OUTERMOST functions are entries: a function inside an open function (named, local or anonymous) is the outer's.
 *   - OPEN (KGENOME_FN_F_END_OPEN, run to the end of the text): the text ended before the "end" that closes it.
 * ONE PASS over the CODE words with a block counter; no stack. The loop's "do" is remembered as (pending, the block level of its
 * loop): a "do" at that level is the loop's.
 *
 * NOT MEASURED on real text: no .lua file in /mnt/games/normtest/fix_island/corpus and no lua on this machine (2026-11-14); the
 * tests are the only evidence.
 *
 * LIMITS, named: a while/for whose CONDITION holds an anonymous function with a loop of its own ("while f(function() while x do end
 * end) do") replaces the outer loop's pending "do" by the inner one's, and the outer "do" then opens a block that never closes (the
 * function runs on, END_OPEN at worst); a stack of pending loops is the next algorithm, not built (no such text was seen).
 */

#include "script_private.h"

#include <textual/textual.h>

static int lua_name_start(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c >= 0x80u;
}

static int lua_name_byte(uint8_t c)
{
	return lua_name_start(c) || (c >= '0' && c <= '9');
}

static int lua_space(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

static int lua_is(const uint8_t *p, uint64_t s, uint64_t e, const char *kw)
{
	uint64_t len = strlen(kw);

	return e - s == len && memcmp(p + s, kw, len) == 0;
}

static uint64_t lua_word_end(const struct kgenome_script_text *t, uint64_t i)
{
	while (i < t->n && t->code[i] && lua_name_byte(t->p[i]))
		i++;
	return i;
}

/* The funcname after "function" at `k` (Name {"." Name} [":" Name]): its end, `k` itself when there is none (anonymous). */
static uint64_t lua_funcname(const struct kgenome_script_text *t, uint64_t k)
{
	const uint8_t *p = t->p;
	uint64_t j = k;

	if (k >= t->n || !t->code[k] || !lua_name_start(p[k]))
		return k;
	j = lua_word_end(t, k);
	while (j + 1u < t->n && t->code[j] && (p[j] == '.' || p[j] == ':') && t->code[j + 1u] && lua_name_start(p[j + 1u])) {
		int method = p[j] == ':';

		j = lua_word_end(t, j + 1u);
		if (method)
			break;
	}
	return j;
}

int kgenome_script_funcs_lua(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	const uint8_t *p = t->p;
	uint64_t n = t->n, i = 0, depth = 0, fdepth = 0, off = 0, name_off = 0, name_len = 0, pend_depth = 0;
	uint64_t local_at = n;          /* where the "local" right before this word began; n when the word before was not it */
	int on = 0, pend = 0;

	if (n >= 3u && p[0] == 0xefu && p[1] == 0xbbu && p[2] == 0xbfu)
		i = 3u;
	while (i < n) {
		uint64_t s = i, e;

		if (!t->code[i] || !lua_name_start(p[i])) {
			if (t->code[i] && !lua_space(p[i]))
				local_at = n;
			if (!t->code[i] && t->kind[i] != KGENOME_TEXTUAL_COMMENT)
				local_at = n;
			if (t->code[i] && p[i] >= '0' && p[i] <= '9')
				i = lua_word_end(t, i);          /* a number: "1end" is not a keyword after it either */
			else
				i++;
			continue;
		}
		e = lua_word_end(t, i);
		i = e;
		if (lua_is(p, s, e, "function")) {
			uint64_t k = e, j;

			while (k < n && t->code[k] && lua_space(p[k]))
				k++;
			j = lua_funcname(t, k);
			depth++;
			if (!on) {
				on = 1;
				fdepth = depth;
				off = local_at < n ? local_at : s;
				name_off = j > k ? k : 0;
				name_len = j - k;
			}
			i = j > k ? j : e;
		} else if (lua_is(p, s, e, "if") || lua_is(p, s, e, "repeat")) {
			depth++;
		} else if (lua_is(p, s, e, "while") || lua_is(p, s, e, "for")) {
			depth++;
			pend = 1;
			pend_depth = depth;
		} else if (lua_is(p, s, e, "do")) {
			if (pend && pend_depth == depth)
				pend = 0;
			else
				depth++;
		} else if (lua_is(p, s, e, "end") || lua_is(p, s, e, "until")) {
			if (depth)
				depth--;
			if (pend && pend_depth > depth)
				pend = 0;
			if (on && depth < fdepth) {
				on = 0;
				if (!kgenome_script_emit(l, off, e, name_off, name_len, 0))
					return 0;
			}
		}
		local_at = lua_is(p, s, e, "local") ? s : n;
	}
	if (on && !kgenome_script_emit(l, off, n, name_off, name_len, KGENOME_FN_F_END_OPEN))
		return 0;
	return 1;
}
