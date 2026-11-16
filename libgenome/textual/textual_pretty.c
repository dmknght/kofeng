/*
 * textual_pretty.c - kgenome_textual_pretty (textual.h): a text laid out for a PERSON to read, indented by
 * block nesting. Never re-entered (textual.h's own header says why - JavaScript's Annex B "-->" is the one
 * byte-for-byte example measured so far, not the only language a REAL line break inserted into re-lexable
 * text could silently change the reading of), so this needs none of kgenome_textual_form's capacity
 * bookkeeping: one lex pass, bytes emitted directly, `cap` is however much a caller can spare and running out
 * of it only truncates the cosmetic job, never the canonical (un-indented) text this is laid out FROM.
 *
 * Unlike the form (textual.h: "every comment goes, a trailing one too: it is a gap"), a comment is NOT
 * stripped here - the form's rule is for pattern MATCHING, and a person reading the file wants to see the
 * file's own comments, not have them disappear.
 */

#include <kofcore.h>

#include "textual_lang.h"
#include "textual_private.h"

#define KGENOME_TEXTUAL_PRETTY_INDENT_MAX   20u
#define KGENOME_TEXTUAL_PRETTY_INDENT_WIDTH 2u

struct tpretty {
	const uint8_t *in;
	const struct kgenome_textual_lang *lang;
	uint8_t       *out;
	uint32_t       cap, w;
	uint32_t       block_depth, expr_depth;
	uint8_t        pend;    /* a break is open, not yet written: settle()'s own coalescing (textual_form.c) -
				  * a trigger and a real "\n" that follows it are the SAME break, charged once */
	uint8_t        sp;      /* a plain run of blanks was seen and owes ONE separating space, same place a
				  * break would go - NOT a break: "return $o" keeps its one space, a run of several
				  * collapses to one, same as `settle()`'s own ident-ident case (textual_form.c), but
				  * here for EVERY run, because this is read by a person and not re-lexed - dropping
				  * it always (the bug this field fixes) read as "return$o" */
	uint8_t        any;     /* a byte has already been written - a break pending before anything at all (a
				  * leading blank line) is dropped, the same way a trailing one (nothing after it)
				  * never gets flushed either (the loop simply ends with `pend` still set) */
	uint8_t        full;    /* `cap` ran out - res->truncated */
};

static void tp_put(struct tpretty *tp, uint8_t c)
{
	if (tp->w < tp->cap)
		tp->out[tp->w++] = c;
	else
		tp->full = 1u;
}

/* Write whatever break is open, at the CURRENT block_depth - a caller about to write "}" lowers block_depth
 * FIRST (code_token_byte's own order, textual_form.c), so a break this flushes right in front of a "}" is
 * indented to the OUTER depth, never the inner one, whichever byte asked for it. */
static void tp_break(struct tpretty *tp)
{
	uint32_t d, k;

	if (!tp->pend)
		return;
	tp->pend = 0;
	if (!tp->any)
		return;
	tp_put(tp, '\n');
	d = tp->block_depth > KGENOME_TEXTUAL_PRETTY_INDENT_MAX ? KGENOME_TEXTUAL_PRETTY_INDENT_MAX : tp->block_depth;
	for (k = 0; k < d * KGENOME_TEXTUAL_PRETTY_INDENT_WIDTH; k++)
		tp_put(tp, ' ');
}

/* Write the one owed separating space, unless a break is pending too (a break already separates,
 * on its own line - the space it would have owed is moot) or nothing has been written yet. */
static void tp_sep(struct tpretty *tp)
{
	if (tp->pend) {
		tp_break(tp);
		tp->sp = 0;
		return;
	}
	if (tp->sp && tp->any)
		tp_put(tp, ' ');
	tp->sp = 0;
}

static void tp_verbatim(struct tpretty *tp, const struct kgenome_textual_span *s)
{
	uint32_t i;

	tp_sep(tp);
	for (i = 0; i < s->len; i++)
		tp_put(tp, tp->in[s->off + i]);
	if (s->len)
		tp->any = 1u;
}

static int tp_sink(void *u, const struct kgenome_textual_span *s)
{
	struct tpretty *tp = u;
	uint32_t i;

	/* A STRING, a TAG, markup or a COMMENT - copied exactly as typed, same as the form's own rule for a
	 * string or markup (textual.h) but, unlike the form, a comment too: this is for a person, not a matcher.
	 * A language with no `stmt_delim` row (shell, vbscript today - keyword-delimited blocks are a later
	 * design, textual.h's own header on this call) takes the SAME path for CODE: no block rule to indent by,
	 * so every byte of it is copied through exactly as typed as well, one case covering both. `stmt_delim` is
	 * this call's own gate, not kgenome_textual_form's `stmt_semi` (textual_lang.h: the two are deliberately
	 * separate fields, so that a language added here never changes form's own, tested, re-entered output). */
	if (s->kind != KGENOME_TEXTUAL_CODE || !tp->lang->stmt_delim) {
		tp_verbatim(tp, s);
		return 1;
	}
	for (i = 0; i < s->len; i++) {
		uint8_t c = tp->in[s->off + i];

		if (c == '\n' || c == '\r') {
			tp->pend = 1u;
			continue;
		}
		if (kgenome_textual_blank_in(c, tp->lang->word_vt_ff)) {
			if (!tp->pend)
				tp->sp = 1u;
			continue;
		}
		if (c == '}') {
			if (tp->block_depth)
				tp->block_depth--;
			/* "}" always dedents onto its own line, whatever was (or was not) already open in front
			 * of it - the one case textual_form.c's own chase (STATUS.md, 2026-11-11) found missing
			 * when only an ALREADY-open break was re-flushed. */
			tp->pend = 1u;
		}
		tp_sep(tp);
		tp_put(tp, c);
		tp->any = 1u;
		if (c == '{') {
			tp->block_depth++;
			tp->pend = 1u;
		} else if (c == '(' || c == '[') {
			tp->expr_depth++;
		} else if ((c == ')' || c == ']') && tp->expr_depth) {
			tp->expr_depth--;
		} else if (c == ';' && !tp->expr_depth) {
			tp->pend = 1u;
		} else if (c == '}') {
			/*
			 * A "}" that closes a VALUE (a function expression assigned, passed, or indexed), not a
			 * block of a statement, is immediately followed - once any blank OR LINE BREAK in between
			 * is skipped - by ";", ",", ")" or "]": the SAME statement/argument/expression continues
			 * onto it, so no break goes between them. Owner-reported (2026-11-11): "w=function(){
			 * ...};" read back with its ";" alone on the next line ("}" then a lone ";") - the break
			 * this queues unconditionally after every "}" does not know the difference from a "}" that
			 * ends a block and is followed by the NEXT statement, where the break is exactly right.
			 * THE LINE BREAK MATTERS: the owner's own real sample already had "}" and ";" on two
			 * SOURCE lines of their own (a deobfuscator's prior formatting), so skipping only
			 * `kgenome_textual_blank_in` (never true for "\n") stopped the lookahead AT the "\n" and
			 * still forced the break - this call lays text out by its OWN block nesting, not the
			 * source's existing line breaks (textual.h's whole premise), so a "\n" here is skipped the
			 * same as a space. Limited to the current span: a "}" at a span's own end (crossing into a
			 * string, comment, or a new sink call) falls back to the old, safe behaviour - always break.
			 */
			uint32_t j = i + 1u;
			uint8_t next = 0;

			while (j < s->len && (tp->in[s->off + j] == '\n' || tp->in[s->off + j] == '\r' ||
					      kgenome_textual_blank_in(tp->in[s->off + j], tp->lang->word_vt_ff)))
				j++;
			if (j < s->len)
				next = tp->in[s->off + j];
			if (next != ';' && next != ',' && next != ')' && next != ']') {
				tp->pend = 1u;
			} else {
				/*
				 * GLUED, NOT JUST UNBROKEN: the bytes skipped above (blank or "\n"/"\r") are
				 * consumed here, by advancing `i` past them, rather than left for the next
				 * iterations of this SAME loop to meet one at a time - the "\n" branch at the
				 * top of this loop sets `pend` unconditionally and would otherwise undo this
				 * decision the moment it saw that very same byte. `sp` is not set either: "}"
				 * and ";"/","/")"/"]" glue with no space between them, same as "(" and ")" do.
				 */
				i = j - 1u;
			}
		}
	}
	return 1;
}

enum kgenome_textual_status kgenome_textual_pretty(const struct kgenome_textual_pretty_req *rq,
						   struct kgenome_textual_pretty_res *res)
{
	const struct kgenome_textual_lang *lang = kgenome_textual_lang_find(rq->lang);
	struct tpretty tp;
	struct kgenome_textual_lex_req lq;
	struct kgenome_textual_lex_res lr;
	enum kgenome_textual_status st;

	res->n_out = 0;
	res->truncated = 0;
	if (!lang)
		return KGENOME_TEXTUAL_NO_LANG;
	tp = (struct tpretty){ .in = rq->in, .lang = lang, .out = rq->out, .cap = rq->cap };
	lq = (struct kgenome_textual_lex_req){ rq->in, rq->n, rq->lang, rq->flags, tp_sink, &tp };
	st = kgenome_textual_lex(&lq, &lr);
	res->n_out = tp.w;
	res->truncated = tp.full;
	return st;
}
