/*
 * diag_text_interp.c - a string that holds code: the command a backtick or `qx{}` runs, the `$x`, `${x}`, `$h{k}`, `$(cmd)` and `#{expr}` a double quoted string interpolates, and the
 * command a shell substitutes between backticks.
 *
 * THE LEXER SAYS WHAT A STRING IS AND NOT WHAT IS IN IT: a backtick is one string span and the `$q` inside it is text to it. A string that runs a command is an act of the program, and
 * the variables in it are what the program hands that command, so the route reads them: the row says which openers are a command (`cmd_str`: "`", "qx", "%x"), which syntax interpolates
 * (`interp`), and what the table calls running one (`cmd_row`). The tokens of the string's code are made by lexing that code again - the same lexer, the same sink, one level down
 * (`nest`, bounded) - so a `$ENV{QUERY_STRING}` in a perl backtick is read exactly as the one outside it is, and a `$(curl u | sh)` in a double quoted shell string is a command.
 *
 * TWO KINDS OF TOKEN carry them. 'c' is a string that runs a command: the walk makes the node (the row's `cmd_row`) and reads the tokens that follow - as many as the token says
 * (`open` and `close` hold the count) - as its arguments. 'b' is a block of code that stands where a value is (sh's backtick): the walk reads its tokens as a group in which a command is
 * due. A plain string that interpolates stays an 'S', and the variables it holds are tokens after it, read as what flows into whatever the string flows into.
 * WHAT IS NOT READ: a variable with an index in sh ("$a[1]"), "$((...))", `@{[ ... ]}` of perl, a string with a heredoc body, a `\\$`.
 */

#include <string.h>

#include "diag_text_walk.h"
#include <celllysis/nucleo.h>

#define NEST_MAX 4u             /* interpolations inside interpolations: what a file writes must not choose how deep the route goes */

/* The code in bytes [from, to) of the text, lexed as the language's own code and cut into tokens by the same sink. */
static int nested(struct kgenome_dtx *x, uint32_t from, uint32_t to)
{
	struct kgenome_textual_lex_req q = { x->in + from, to - from, x->lang->id, KGENOME_TEXTUAL_FRAGMENT, kgenome_dtx_sink, x };
	struct kgenome_textual_lex_res lr;
	uint32_t keep = x->shift;

	if (to <= from)
		return !x->oom;
	if (x->nest >= NEST_MAX) {      /* code inside a string inside a string ...: the text past the bound is not read, and said */
		kgenome_dtx_cut(x);
		return !x->oom;
	}
	x->nest++;
	x->shift = from;
	(void)kgenome_textual_lex(&q, &lr);
	x->shift = keep;
	x->nest--;
	return !x->oom;
}

/* The byte after the bracket group that opens at `k` (`o`) and closes with `c`, counting the same bracket inside; 0 when it does not close before `to`. */
static uint32_t group_end(const struct kgenome_dtx *x, uint32_t k, uint32_t to, char o, char c)
{
	uint32_t level = 0;

	for (; k < to; k++) {
		if (x->in[k] == '\\') {
			k++;
		} else if (x->in[k] == o) {
			level++;
		} else if (x->in[k] == c && --level == 0) {
			return k + 1u;
		}
	}
	return 0;
}

/* The tokens made since token `first` are the block's: its count is kept in the token, saturating (what does not fit is read as tokens that follow the block). */
static void set_count(struct kgenome_dtx *x, uint32_t first)
{
	uint32_t n = x->nt - first - 1u;

	if (n > 0xffffu)
		n = 0xffffu;
	x->t[first].open = (uint8_t)(n >> 8);
	x->t[first].close = (uint8_t)(n & 0xffu);
}

/* The code a "$" at `k` begins, in a string whose content ends at `to`: the end of what was read, `k` when it is nothing this reads. */
static uint32_t dollar(struct kgenome_dtx *x, uint32_t k, uint32_t to)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t e, r;
	uint8_t n = k + 1u < to ? x->in[k + 1u] : 0u;

	if (n == '(' && l->cmd) {                          /* $(cmd): a command, as the shell reads it outside the string */
		e = group_end(x, k + 1u, to, '(', ')');
		return e && !(k + 2u < to && x->in[k + 2u] == '(') && nested(x, k, e) ? e : k;
	}
	if (n == '{') {                                                         /* ${name} */
		for (r = k + 2u; r < to && kgenome_dtx_identc(x, x->in[r]); r++)
			;
		if (r == k + 2u || r >= to || x->in[r] != '}')
			return k;
		return kgenome_dtx_push(x, k + 2u, r - k - 2u, 'V', 0, 0, 0) ? r + 1u : k;
	}
	if (!kgenome_dtx_identc(x, n) || n == '\\')
		return k;
	for (r = k + 2u; r < to && kgenome_dtx_identc(x, x->in[r]); r++)
		;
	if (l->hash_key && r < to && (x->in[r] == '{' || x->in[r] == '[')) {    /* $h{key}, $a[0]: read as the code it is, so `$ENV{QUERY_STRING}` is the request */
		e = group_end(x, r, to, (char)x->in[r], x->in[r] == '{' ? '}' : ']');
		return e && nested(x, k, e) ? e : k;
	}
	return kgenome_dtx_push(x, k + 1u, r - k - 1u, 'V', 0, 0, 0) ? r : k;
}

/* The bytes between two backticks that begin at `k`: the end of the string, or 0. A backslash escapes. */
static uint32_t tick_end(const struct kgenome_dtx *x, uint32_t k, uint32_t to)
{
	for (k++; k < to; k++) {
		if (x->in[k] == '\\')
			k++;
		else if (x->in[k] == '`')
			return k;
	}
	return 0;
}

/* A shell's backtick, between `from` and `to` (the ticks excluded): a block of code that stands where a value is. */
static int block(struct kgenome_dtx *x, uint32_t at, uint32_t from, uint32_t to)
{
	uint32_t first = x->nt;

	if (!kgenome_dtx_push(x, at, to - from + 2u, 'b', 0, 0, 0))
		return 0;
	if (!nested(x, from, to))
		return 0;
	set_count(x, first);
	return 1;
}

/* The code a string holds, in its content [from, to): a variable, an expression, a command. */
static int scan(struct kgenome_dtx *x, uint32_t from, uint32_t to)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t k = from, e;

	while (k < to) {
		uint8_t c = x->in[k];

		if (c == '\\') {
			k += 2u;
		} else if (c == '$' && (l->interp == 1u || l->interp == 3u)) {
			e = dollar(x, k, to);
			k = e > k ? e : k + 1u;
		} else if (c == '#' && l->interp == 2u && k + 1u < to && x->in[k + 1u] == '{') {
			e = group_end(x, k + 1u, to, '{', '}');
			if (e && !nested(x, k + 2u, e - 1u))
				return 0;
			k = e ? e : k + 1u;
		} else if (c == '#' && l->interp == 4u) {                               /* "#expr#"; "##" is a "#" */
			if (k + 1u < to && x->in[k + 1u] == '#') {
				k += 2u;
				continue;
			}
			for (e = k + 1u; e < to && x->in[e] != '#'; e++)
				;
			if (e < to && !nested(x, k + 1u, e))
				return 0;
			k = e < to ? e + 1u : to;
		} else if (c == '`' && l->interp == 3u && (e = tick_end(x, k, to)) != 0) {
			if (!block(x, k, k + 1u, e))
				return 0;
			k = e + 1u;
		} else {
			k++;
		}
		if (x->oom)
			return 0;
	}
	return 1;
}

/* Does the string span begin with one of the row's command openers: "`" for the byte, "qx" for "qx{" and "qx(". */
static int is_command(const struct kgenome_dtx *x, uint32_t off, uint32_t open)
{
	uint32_t k;

	for (k = 0; x->lang->cmd_str && x->lang->cmd_str[k]; k++) {
		size_t n = strlen(x->lang->cmd_str[k]);

		if (n <= open && n + 1u >= open && !memcmp(x->in + off, x->lang->cmd_str[k], n))
			return 1;
	}
	return 0;
}

/* Does a string span of a language whose strings interpolate hold code: not one in single quotes (nothing in it is anything), and a here-document only when its flag says so. The lexer's
 * INTERP flag is the string's escapes (ruby's `"a #{b}"` has none set) and is no answer for a quoted string. */
static int interpolates(const struct kgenome_dtx *x, const struct kgenome_textual_span *sp, uint32_t off)
{
	if (sp->open_len)
		return x->in[off] != '\'';
	return (sp->flags & KGENOME_TEXTUAL_F_INTERP) != 0;
}

int kgenome_dtx_sink_str(struct kgenome_dtx *x, const struct kgenome_textual_span *sp, uint32_t off)
{
	const struct kgenome_dtx_lang *l = x->lang;
	uint32_t from = off + sp->open_len, to = off + sp->len - sp->close_len, first = x->nt;
	int cmd = l->interp && is_command(x, off, sp->open_len), sh_tick = l->interp == 3u && sp->open_len == 1u && x->in[off] == '`';
	int interp = l->interp && (cmd || (l->interp_all && interpolates(x, sp, off)));     /* a command string always interpolates */

	if (sp->len < sp->open_len + sp->close_len || (sp->flags & KGENOME_TEXTUAL_F_OPEN))
		cmd = sh_tick = interp = 0;
	if (sh_tick)
		return block(x, off, from, to);         /* `cmd`: a command substitution, whose code is read where it stands */
	if (!cmd && !interp)
		return kgenome_dtx_push(x, off, sp->len, 'S', (uint8_t)sp->open_len, (uint8_t)sp->close_len, sp->flags);
	if (!kgenome_dtx_push(x, off, sp->len, cmd ? 'c' : 'S', (uint8_t)sp->open_len, (uint8_t)sp->close_len, sp->flags))
		return 0;
	if (!scan(x, from, to))
		return 0;
	if (cmd)
		set_count(x, first);
	return 1;
}

/* The block whose token is `i`: a command string runs (a node of the row's name, whose arguments are what the string interpolates), a block of code is read as a group. The index of
 * its last token. */
uint32_t kgenome_dtx_block(struct kgenome_dtx *x, struct kgenome_dtx_walk *w, uint32_t i)
{
	uint32_t cnt = ((uint32_t)x->t[i].open << 8) | x->t[i].close, end = i + 1u + cnt;
	uint8_t pos = w->cmd_pos, lead = w->cmd_lead;
	int32_t n = -1;

	if (end > x->nt)
		end = x->nt;
	if (x->t[i].k == 'c') {
		uint16_t cap = x->lang->cmd_row ? kgenome_dtx_cap(x, (const uint8_t *)x->lang->cmd_row, (uint32_t)strlen(x->lang->cmd_row), NULL) : KGENOME_NUCLEO_NONE;

		if (cap != KGENOME_NUCLEO_NONE) {
			n = kgenome_dtx_add_node(x, i, cap, x->lang->cmd_row, 0);
			x->site[i] = n;
			kgenome_dtx_flow(x, w, n, NULL);
		}
	}
	kgenome_dtx_push_frame(w, n, 0, NULL, 0);
	if (x->t[i].k == 'b')
		kgenome_dtx_cmd_open(w, 1);
	kgenome_dtx_walk_range(x, w, i + 1u, end);
	kgenome_dtx_close_frame(x, w);
	if (x->t[i].k == 'b') {
		(void)kgenome_dtx_cmd_close(w);
		kgenome_dtx_cmd_flush(x, w);
	}
	w->cmd_pos = pos;
	w->cmd_lead = lead;
	return end - 1u;
}

/* The tags of a page whose tags are calls: every tag ends the statement before it, "#" bounds an expression in output text and is no tag; a tag the table has a row for gives its name. */
int kgenome_dtx_sink_tag(struct kgenome_dtx *x, const struct kgenome_textual_span *sp, uint32_t off)
{
	const char *o = x->lang->tag_calls;
	size_t ol = strlen(o);
	uint32_t k;

	if (sp->len == 1u && x->in[off] == '#')
		return !x->oom;
	if (!kgenome_dtx_push_term(x, off))
		return 0;
	if (sp->len <= ol)
		return 1;
	for (k = 0; k < ol; k++)
		if (kof_lower_byte(x->in[off + k]) != (uint8_t)o[k])
			return 1;
	if (kgenome_dtx_cap(x, x->in + off + 1u, sp->len - 1u, NULL) == KGENOME_NUCLEO_NONE)
		return 1;
	return kgenome_dtx_push(x, off + 1u, sp->len - 1u, 'g', 0, 0, 0);
}
