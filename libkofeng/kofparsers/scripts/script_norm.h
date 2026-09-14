/*
 * script_norm.h - putting a script into ONE form, so a signature written on it
 * survives how it happened to be typed.
 *
 * WHAT THIS IS FOR. The same program can be written a thousand ways that differ
 * only in whitespace: "eval (" and "eval(", a brace at the end of a line or on
 * the next one, four spaces of indent or a tab or none. A marker matches the
 * bytes it was given, so each of those is a different marker, and a rule written
 * against one build of a family misses the next one for no better reason than
 * that somebody's editor is configured differently.
 *
 * WHAT IT IS NOT FOR, and the line is the whole design: this is about FORM, not
 * about hiding. A file that builds its own source out of string fragments, or
 * writes "\160\x68" where it means "ph", is doing something else and is dealt
 * with somewhere else - after an anchor says it is worth the cost. Nothing here
 * decodes anything, evaluates anything, or renames anything.
 *
 * ONLY OUTSIDE STRING LITERALS. Inside one, every byte is a value: "a   b" is
 * not "a b", and a "#" in a URL is not a comment. So the pass carries a small
 * state machine and the table below tells it what opens what.
 *
 * THE LANGUAGE MATTERS AND THERE IS NO WAY AROUND IT. Whitespace between a name
 * and a "(" is nothing in php and is the argument separator in sh - "ls -la" and
 * "ls-la" are different commands. That is one flag, not a parser.
 */

#ifndef KOFENG_SCRIPT_NORM_H
#define KOFENG_SCRIPT_NORM_H

#include <kofmod/script.h>
#include "../../core/kofcore.h"

/*
 * WHAT ONE LANGUAGE NEEDS SAYING ABOUT IT.
 *
 * Seven fields and no code. Everything the pass does is driven from here, so
 * adding a language is a row rather than a branch - and a language this build
 * has no row for is not normalised at all, which is the right answer: guessing
 * that "'" opens a string would turn an apostrophe in a comment into the start
 * of one and take the rest of the file with it.
 */
struct kof_lex {
	/* "//", "#", "--", "REM" - NULL terminated, unused slots NULL. */
	const char *line_cmt[3];
	/* The block comment's two halves, or NULL when the language has none.
	 * C style is slash-star and star-slash; PowerShell is "<#" and "#>". */
	const char *blk_open, *blk_close;
	/* Which bytes open a single-line string. Usually "\"'". */
	const char *quotes;
	/*
	 * WHAT MAKES A STRING SPAN LINES - a php heredoc, a js backtick, a
	 * python triple quote.
	 *
	 * Not handled: recognised. Everything this pass does is line shaped and
	 * every one of those operations is wrong inside a multi-line string, so
	 * the presence of one of these anywhere in the input means the whole
	 * input is left alone. Conservative on purpose - a file that normalises
	 * to the wrong thing is worse than one that does not normalise.
	 */
	const char *ml_open[3];
	/* Does a backslash escape inside '...' - sh: no, php: only \' and \\,
	 * js and python: yes. Only whether the NEXT byte is skipped. */
	uint8_t     sq_escapes;
	/* ';' where a statement ends with one, 0 where a newline ends it. */
	uint8_t     stmt_end;
	/*
	 * IS WHITESPACE PART OF THE SYNTAX - sh and batch: yes.
	 *
	 * "eval (" and "eval(" are one thing in php; "ls -la" and "ls-la" are
	 * two in sh, and the two have the same shape - a word byte, a space, a
	 * non-word byte. No lexical rule separates them, so it is stated.
	 */
	uint8_t     ws_significant;
};

/* The table for a kind, or NULL when this build has no row for it. NULL for
 * KOF_SCRIPT_ANY, which is the point: an unnamed language is not guessed at. */
const struct kof_lex *kof_lex_for(uint8_t script_kind);

/*
 * WHAT TO DO. A mask rather than a level, because they are independent and a
 * caller that wants the cheap half should not have to take the rest.
 */
enum {
	KOF_NORM_EOL     = 1u << 0,  /* CRLF -> LF */
	KOF_NORM_INDENT  = 1u << 1,  /* drop leading whitespace on a line */
	KOF_NORM_BLANK   = 1u << 2,  /* drop lines with nothing on them */
	KOF_NORM_COMMENT = 1u << 3,  /* drop lines that are only a comment */
	KOF_NORM_SPACE   = 1u << 4,  /* collapse, and close up, outside strings */
	KOF_NORM_BRACE   = 1u << 5,  /* a lone "{" joins the line above it */
	KOF_NORM_ALL     = 0x3fu
};

/*
 * Write the normalised form of `in` into `out`, and answer how long it is.
 *
 * Answers 0 when nothing was done - no table for the kind, a multi-line string
 * construct present, or no room - and a caller that gets 0 should use the
 * input as it stands rather than treat it as an empty file.
 *
 * NEVER LONGER THAN THE INPUT. Every operation removes bytes or leaves them, so
 * `cap` of `n` always suffices; the parameter is there so a caller can pass a
 * smaller buffer and be told rather than trusted.
 */
uint32_t kof_script_norm(const struct kof_lex *lx, const uint8_t *in,
			 uint32_t n, uint8_t *out, uint32_t cap,
			 uint32_t what);

#endif /* KOFENG_SCRIPT_NORM_H */
