/*
 * bat_lex.c - THE LEXER OF WINDOWS BATCH (.BAT, .CMD): where a string is, where a comment is, and nothing else.
 *
 * There is no cmd.exe here, so no rule below was checked against one. Each says where it comes from: [corpus] is
 * counted in 2642 real .bat/.cmd files (4.1 MB) by the test's corpus mode and a grep, [recalled] is cmd's documented parse as
 * the author remembers it and is [Unverified].
 *
 * WHAT IT DELIVERS. STRING: a double quoted "..." run, delimiters included (INTERP when it holds %var%, %1, %~dp0, %%i or
 * !var!). COMMENT: a REM line or a "::" line. Everything else is CODE: command words, labels, operators, the text of
 * ECHO (it is data and not a string, but a quote in it still groups, as it does in every argument).
 *
 * QUOTES. A quote toggles; there is no escape inside one, so "a""b" is two runs side by side [recalled]. A quote
 * ends at the end of its line: cmd reads a line at a time and "^" in quotes is a plain byte, so nothing continues
 * a string onto the next line. One that is not closed is an OPEN string to the end of the line [recalled].
 * Outside quotes "^" escapes the next byte, a quote included (^" does not open a string) [recalled; corpus: 1 file
 * has `for /f ^"usebackq^ eol^=^` and reads this way].
 *
 * LINE ENDS. A line ends at "\n" only. "\r" is a blank wherever it is: CRLF and LF files read the same, and a
 * lone CR is not a line break [recalled: cmd drops every CR of a line]. A comment or an open string stops before
 * the CRs of its CRLF, so the break is code like the break of every other line; at the very end of the text, with no
 * "\n" after it, a CR stays in the literal (the form writes it as it is, and the lex of the form must read it the same). [corpus: 1932 of 2642 files use
 * CRLF, 53 LF, 214 are empty; none of the files has a lone CR break that matters].
 *
 * CARET AT THE END OF A LINE ("^" then optional CRs then "\n") joins the next line to this one. The join is
 * transparent: whether a command word may follow is what it was before the caret, and the next line is not a
 * line start (a label or "::" there is not one) [recalled; corpus: 17 lines end with ^]. Lines of nothing but blanks
 * (and "@(,;=") after a caret stay in the join, and so does a REM that is the first thing on a continued line,
 * with the command that was due: the form takes blank lines and comments out, and a line that was behind them
 * must read as it does in the form of it, where the caret is the line before [Unverified: cmd ends the command at an
 * empty line; the effect is that a line is shown as code and not as a label or a comment, the safe side]. NOT DONE: cmd escapes
 * the first byte of the continued line, so a "\"" or "&" in column 0 there would be literal. Doing it would make
 * the lexer read the white space the form takes out (the indentation), and the form of a form would not be
 * itself, so a column-0 quote after a continuation is lexed as a quote [Unverified: no case in the corpus].
 *
 * REM. The word REM (any case, after any "@"s) at the START OF A COMMAND is a comment to the end of the line,
 * "&" and ")" in it included [recalled; corpus: 3467 comment lines (REM and "::"), 0 in any other position, and the count of
 * a grep per file is the lexer's]. The word ends at a blank, a
 * delimiter (, ; =), the end, or any byte that is not a name byte but is not an operator or a quote: "REM=" (a polyglot
 * line in the corpus), "REM." (the form the brief names) and "rem-----" (a banner in a Symantec installer) are
 * comments. "rem&", "rem|", "rem(", "rem)", "rem<", "rem>", "rem^" and "rem\"" are NOT: the operator ends the
 * word and cmd may run what follows it, so reading them as comments could hide a command; they are left as code
 * [Unverified]. "r^em" is code for the same reason [Unverified]. A trailing "^" does not continue a REM line:
 * if cmd does, the next line is shown as code instead of hidden, the safe side [Unverified; corpus: 0 REM lines end with ^].
 *
 * START OF A COMMAND is: the start of a line, after "&" "&&" "||" "|" (a "(" or "@" after one of these keeps it).
 * NOT DONE: the command after the condition of IF, after ELSE and after DO is a command start too, so
 * "if x rem y" is a comment in cmd and code here [corpus: 0 lines].
 *
 * "::". A line whose first byte after blanks is ":" is a label, and "::" is the label that is used as a comment:
 * a comment to the end of the line [recalled; corpus: 151 lines, 0 after "&"]. A label line is code to its end and is not
 * read for quotes (cmd ignores what follows the label name; corpus: 33 label lines hold a quote). Only a line
 * start counts: after "&" cmd reads "::" as a drive name and fails, so it is code there [recalled].
 *
 * ENCODINGS. A UTF-8 BOM ("EF BB BF") at the start of a line, after blanks if any, is code and does not begin the
 * line: the first line of a file is read as its author meant it, and so is any other, because the form takes
 * lines out and one that was second can be first in the form of it, and the form of a form has to read as the form
 * (cmd on a console that is not UTF-8 would fail on it [Unverified]). UTF-16 (a BOM "FF FE" or "FE FF" at the
 * start of a line) is NOT READ: from the mark to the end of the text it is CODE. cmd cannot run such a file
 * [Unverified], reading its ASCII bytes as if they were text would put a quote or a REM in the wrong place, and the
 * spans still partition it. A UTF-16 file without a BOM is bytes with NULs and is lexed as bytes (a NUL is a byte that is not
 * a name byte, so "r\0e\0m\0" is never REM).
 *
 * BOUNDS. No stack, no depth: the parentheses of a block are not tracked, because no span depends on them (a
 * ")" inside quotes or after ^ never gets looked at, and a REM or "::" line ends at its break whatever it holds).
 * Every byte is visited once and each line is scanned for its end once.
 */

#include <string.h>

#include "bat.h"

/* Is `c` the end of the word REM: not a name byte, not an operator or quote that could be the start of what cmd runs next. */
static int rem_ends(const uint8_t *p, uint32_t n, uint32_t i)
{
	return i >= n || (!kgenome_textual_ident(p[i]) && !kof_byte_in_set(p[i], "&|()<>^\""));
}

/* The index of the "\n" that ends the line holding `i`, or n. */
static uint32_t line_end(const uint8_t *p, uint32_t n, uint32_t i)
{
	const uint8_t *e = memchr(p + i, '\n', n - i);

	return e ? (uint32_t)(e - p) : n;
}

/*
 * Where a line's text stops: before the CRs of its CRLF. `end` is the "\n" or the end of the text; at the end of the text
 * the CRs stay in the literal, because the form writes it as it is and a lex of the form must read it the same way.
 */
static uint32_t text_end(const uint8_t *p, uint32_t n, uint32_t from, uint32_t end)
{
	while (end < n && end > from && p[end - 1u] == '\r')
		end--;
	return end;
}

/*
 * Does the text between a string's quotes hold a variable: "%%" (a "%" or a FOR variable), "%1", "%*", "%~dp0", "%name%",
 * "!name!". One pass: a "%" or "!" waits for its partner, and a partner that is next to it is no name.
 */
static int holds_variable(const uint8_t *p, uint32_t a, uint32_t b)
{
	uint32_t i, pct = 0, bang = 0;

	for (i = a; i < b; i++) {
		if (p[i] == '%') {
			if (i + 1u < b && (p[i + 1u] == '%' || p[i + 1u] == '*' || p[i + 1u] == '~' || kof_is_digit(p[i + 1u])))
				return 1;
			if (pct && pct < i)
				return 1;
			pct = i + 1u;
		} else if (p[i] == '!') {
			if (bang && bang < i)
				return 1;
			bang = i + 1u;
		}
	}
	return 0;
}

/* A string whose opening quote is at `i`: delivered, and the index after it. One scan: to the closing quote or to the line's end. */
static uint32_t string_at(struct kgenome_textual_lexer *lx, uint32_t i)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, j = i + 1u, stop;
	uint8_t flags = 0, close = 0;

	while (j < n && p[j] != '"' && p[j] != '\n')
		j++;
	if (j < n && p[j] == '"') {
		stop = j;
		close = 1;
	} else {
		stop = text_end(p, n, i + 1u, j);
		flags |= KGENOME_TEXTUAL_F_OPEN;
	}
	if (holds_variable(p, i + 1u, stop))
		flags |= KGENOME_TEXTUAL_F_INTERP;
	(void)kgenome_textual_span_at(lx, i, stop + close, KGENOME_TEXTUAL_STRING, flags, 1, close);
	return stop + close;
}

/* A comment from `i` to the end of its line, `open` bytes of it the word or the marker: delivered, and the index after it. */
static uint32_t comment_at(struct kgenome_textual_lexer *lx, uint32_t i, uint32_t open)
{
	uint32_t stop = text_end(lx->p, lx->n, i + open, line_end(lx->p, lx->n, i + open));

	(void)kgenome_textual_span_at(lx, i, stop, KGENOME_TEXTUAL_COMMENT, 0, open, 0);
	return stop;
}

/*
 * The state of the walk: is a command word due, has anything but blanks been read on this line, and is the line a
 * continuation (a caret ended the one before, and only blanks and breaks have been read since).
 */
struct bat_pos {
	uint8_t cmd, bol, join;
};

/* A "^" at `i`: a continuation (the join is transparent) or an escape of the next byte. The index after it. */
static uint32_t caret_at(const uint8_t *p, uint32_t n, uint32_t i, struct bat_pos *st)
{
	uint32_t j = i + 1u;

	while (j < n && p[j] == '\r')
		j++;
	st->bol = 0;
	if (j < n && p[j] == '\n') {
		st->join = 1;
		return j + 1u;
	}
	st->cmd = st->join = 0;
	return i + 2u <= n ? i + 2u : n;
}

/* A byte at a line start that is ":": a label line, or a "::" comment. The index after it. */
static uint32_t label_at(struct kgenome_textual_lexer *lx, uint32_t i)
{
	if (i + 1u < lx->n && lx->p[i + 1u] == ':')
		return comment_at(lx, i, 2u);
	return line_end(lx->p, lx->n, i);
}

/* A command word at `i` (a name byte): REM is a comment, any other word is read whole. The index after it. */
static uint32_t word_at(struct kgenome_textual_lexer *lx, uint32_t i, struct bat_pos *st)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, j = i;

	st->bol = 0;
	/* a comment on a continued line leaves the line after it continued too, and a command due stays due: the form takes
	 * the comment out, and what followed it must read as it does when the caret is the line before it [Unverified: cmd] */
	if (i + 3u <= n && kgenome_textual_ci_eq(p + i, "rem", 3u) && rem_ends(p, n, i + 3u))
		return comment_at(lx, i, 3u);
	st->cmd = st->join = 0;
	while (j < n && kgenome_textual_ident(p[j]))
		j++;
	return j;
}

/*
 * One byte that is not a name byte, a quote, a caret or a line break: what it does to the state of the walk. "&" and "|"
 * start a command; "@" (a prefix), the delimiters and "(" leave the state as it was (a join too: they are the
 * blanks and prefixes of the line), so "@rem" and "(rem" after a start keep a word due; anything else is in the middle of a command, a redirection included (its next word is a file).
 */
static void symbol_at(uint8_t c, struct bat_pos *st)
{
	st->bol = 0;
	if (kof_byte_in_set(c, "@(,;="))
		return;
	st->join = 0;
	st->cmd = c == '&' || c == '|';
}

/* KNOWN DEFECT D15c (2026-10-24, R) [sev M]: kgenome_textual_bat_lex starts a command only at a line start or after & && || |, not after the condition of IF, after ELSE or after DO ("NOT DONE" at the head of this file).
 * Trigger: `if x rem y` or `... do rem y`: cmd reads a comment there. Effect: the lexer delivers it as code, so its words reach the form and the graph (corpus: 0 such lines).
 * Reproducer: none yet. Fix: re-arm st.cmd after the IF condition (the diag row already knows it: `cond`), after ELSE and after DO. */
void kgenome_textual_bat_lex(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = lx->pos;
	struct bat_pos st = { 1, 1, 0 };

	while (i < n && !lx->refused) {
		uint8_t c = p[i];

		if (c == '\n') {
			/* a line of blanks after a caret does not end the join: the form takes blank lines out, and a line that was
			 * second after one must read as the form of it does [Unverified: cmd ends the command at an empty line] */
			if (!st.join)
				st.cmd = st.bol = 1;
			i++;
			continue;
		}
		if (kgenome_textual_blank(c)) {
			i++;
			continue;
		}
		/* UTF-16 is not read: see ENCODINGS */
		if (st.bol && i + 1u < n && ((c == 0xffu && p[i + 1u] == 0xfeu) || (c == 0xfeu && p[i + 1u] == 0xffu)))
			break;
		if (st.bol && c == 0xefu && i + 2u < n && p[i + 1u] == 0xbbu && p[i + 2u] == 0xbfu) {
			i += 3u;
		} else if (c == ':' && st.bol) {
			i = label_at(lx, i);
		} else if (c == '"') {
			st.cmd = st.bol = st.join = 0;
			i = string_at(lx, i);
		} else if (c == '^') {
			i = caret_at(p, n, i, &st);
		} else if (st.cmd && kgenome_textual_ident(c)) {
			i = word_at(lx, i, &st);
		} else {
			symbol_at(c, &st);
			i++;
		}
	}
	/* the rest (code after the last literal, or what is not read) is delivered as code */
	if (!lx->refused && lx->pos < n)
		(void)kgenome_textual_emit(lx, n - lx->pos, KGENOME_TEXTUAL_CODE, 0, 0, 0);
}
