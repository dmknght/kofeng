#ifndef KGENOME_TEXTUAL_STATUS_H
#define KGENOME_TEXTUAL_STATUS_H

/*
 * textual_status.h - whether a lex of a text is complete, and if not, in what way.
 *
 * A status is a value and never a silent "nothing": a string that ran to the end of the
 * file unclosed is something a reader of the spans has to be told, because every pass
 * after the lexer treats a closed literal as a value and an open one as a fragment.
 */

enum kgenome_textual_status {
	/* Every byte is in a span and every literal and comment was closed. */
	KGENOME_TEXTUAL_OK = 0,
	/*
	 * A string, a comment or a heredoc ran to the end of the input without its
	 * closer. The spans still partition the input; the ones that did this carry
	 * KGENOME_TEXTUAL_F_OPEN, and `n_open` in the result counts them. This is what
	 * a truncated file, a file with a stray quote and a generator's template look
	 * like, and the caller decides whether to use the spans.
	 */
	KGENOME_TEXTUAL_OPEN,
	/* No row for this language in this build. Nothing was emitted. */
	KGENOME_TEXTUAL_NO_LANG,
	/* The sink answered 0: the walk stopped there. The spans so far were delivered. */
	KGENOME_TEXTUAL_REFUSED,
	/* The output buffer is smaller than KGENOME_TEXTUAL_FORM_CAP(n). Nothing is written. */
	KGENOME_TEXTUAL_SMALL,
	/* kgenome_textual_value: the literal has no value the text can give - it interpolates, or has an escape
	 * the lib does not compute, or the language's literals are not known to it. */
	KGENOME_TEXTUAL_NO_VALUE
};

#endif /* KGENOME_TEXTUAL_STATUS_H */
