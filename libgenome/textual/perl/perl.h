#ifndef KGENOME_TEXTUAL_PERL_H
#define KGENOME_TEXTUAL_PERL_H

/*
 * perl.h - the perl directory's one header, private to the family: its row, its lexer and what the
 * lexer's files share (the words of the language, the delimited constructs, the multi-line blocks).
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_perl;

void kgenome_textual_perl_lex(struct kgenome_textual_lexer *lx);

/* The row's `value` and `unescape_str`: see perl_value.c and perl_esc.c. */
int kgenome_textual_perl_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			       uint8_t *out, uint32_t *n);
extern const struct kgenome_textual_esc kgenome_textual_perl_dq_esc;   /* a double quoted string's escapes: perl_value.c */
uint32_t kgenome_textual_perl_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out);

/* ---- the words (perl_kw.c) ---- */

/* What a word is to the lexer. Only what changes how the bytes after it are read is a class. */
enum kgenome_textual_perl_kw_kind {
	KGENOME_TEXTUAL_PERL_KW_TERM = 1,    /* a value, or a function whose argument is optional: an operator follows (shift, time, last) */
	KGENOME_TEXTUAL_PERL_KW_ARGS,        /* takes a term next: a "/" after it begins a pattern, "<<" a here-document (split, and, if, die) */
	KGENOME_TEXTUAL_PERL_KW_QUOTE,       /* q qq qw qx qr m s tr y: a delimiter follows */
	KGENOME_TEXTUAL_PERL_KW_SUB,         /* sub: a name, a prototype, a block */
	KGENOME_TEXTUAL_PERL_KW_NAME,        /* package use no require: a name follows, and a quote word there is the name's */
	KGENOME_TEXTUAL_PERL_KW_FORMAT,      /* format NAME =  and the picture lines after it */
	KGENOME_TEXTUAL_PERL_KW_PRINT,       /* print printf say: a file handle may stand between it and its argument */
	KGENOME_TEXTUAL_PERL_KW_END          /* __END__ __DATA__: nothing after the line is code */
};

/* The quote-like operators, in the order the table in perl_quote.c is */
enum kgenome_textual_perl_quote_op {
	KGENOME_TEXTUAL_PERL_OP_Q, KGENOME_TEXTUAL_PERL_OP_QQ, KGENOME_TEXTUAL_PERL_OP_QW, KGENOME_TEXTUAL_PERL_OP_QX,
	KGENOME_TEXTUAL_PERL_OP_QR, KGENOME_TEXTUAL_PERL_OP_M, KGENOME_TEXTUAL_PERL_OP_S, KGENOME_TEXTUAL_PERL_OP_TR,
	KGENOME_TEXTUAL_PERL_OP_Y
};

struct kgenome_textual_perl_kw_row {
	const char *name;
	uint8_t     kind;       /* enum kgenome_textual_perl_kw_kind */
	uint8_t     block;      /* a "{" after it opens a block, not a hash (do, eval, else, map, grep, sort) */
	uint8_t     arg;        /* KGENOME_TEXTUAL_PERL_KW_QUOTE: enum kgenome_textual_perl_quote_op */
};

/* The row for the word [w, w + len), or NULL when it is not a keyword of the language. */
const struct kgenome_textual_perl_kw_row *kgenome_textual_perl_kw(const uint8_t *w, uint32_t len);

/* ---- delimited constructs, here-documents, pod and formats (perl_quote.c) ---- */

/*
 * The text whose opening delimiter is at p[j], to the byte after its closing delimiter: a bracket nests, a
 * backslash escapes the byte after it, anything else closes on its own kind. 0 when it does not close.
 * Perl finds the end of a quoted text BEFORE it reads what is in it, so there is nothing else to know.
 */
uint32_t kgenome_textual_perl_delim(const uint8_t *p, uint32_t n, uint32_t j);

/* Past white space and "#" comments from `j`: where a delimiter or a "=>" would be. */
uint32_t kgenome_textual_perl_skip(const uint8_t *p, uint32_t n, uint32_t j);

/*
 * The quote-like construct of operator `op` whose word is [at, at + wl) in the text. Answers its end (the byte
 * after its last delimiter and its flags) - `*closed` says whether it closed; an unclosed one runs to the end -
 * and 0 when no delimiter follows the word, which then is not an operator at all. `*open` is the bytes in front of the
 * first part's text and `*close` the bytes after the last one (its delimiter and the flags).
 */
uint32_t kgenome_textual_perl_quote(const uint8_t *p, uint32_t n, uint32_t at, uint32_t wl, uint8_t op, int *closed,
				    uint32_t *open, uint32_t *close);

/* A pattern literal "/.../flags", its "/" at `at`. Same answer as above. */
uint32_t kgenome_textual_perl_match(const uint8_t *p, uint32_t n, uint32_t at, int *closed, uint32_t *close);

/* Does the operator for a quote word `op` interpolate (flag INTERP on the span): qq and qx, but not with "'" for the delimiter. */
int kgenome_textual_perl_op_interp(uint8_t op, uint8_t delim);

/* A here-document operator, "<<" at `i`: the length of the whole operator (0 when it is not one), and the tag. */
struct kgenome_textual_perl_here {
	uint32_t off, len;      /* the tag, in the text */
	uint8_t  interp;        /* the body interpolates: not a "'" tag, not "<<\TAG" */
	uint8_t  indent;        /* "<<~": the closing line may be indented */
	uint8_t  quoted;        /* the tag was in quotes */
	uint8_t  spaced;        /* blanks stood between "<<" (or "<<~") and the quote: perl allows that only where a term is expected */
};
uint32_t kgenome_textual_perl_here_op(const uint8_t *p, uint32_t n, uint32_t i, struct kgenome_textual_perl_here *h);

/* The body of a here-document that begins at line start `i`: its end - the end of the closing line without
 * the line break, or `n` - and the closing line's length in `*close`, which is 0 for an empty tag's empty
 * line too: `*closed` says whether there was a closing line. */
uint32_t kgenome_textual_perl_here_body(const uint8_t *p, uint32_t n, uint32_t i, const struct kgenome_textual_perl_here *h,
					uint32_t *close, int *closed);

/* The pod block that begins at `i`: its end - after the "=cut" line, without its line break, or `n`. */
uint32_t kgenome_textual_perl_pod_end(const uint8_t *p, uint32_t n, uint32_t i);

/* A "format NAME =" line at `i` (the word `format` ends at `w`): the end of the line with its break, or 0. */
uint32_t kgenome_textual_perl_format_head(const uint8_t *p, uint32_t n, uint32_t w);

/* The picture lines of a format that begin at line start `i`: end as for a here-document body, closed by a line ".". */
uint32_t kgenome_textual_perl_format_body(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *close);

/* The row's function table (perl_fn.c). */
extern const struct kgenome_textual_fn_table kgenome_textual_perl_fn_table;

#endif /* KGENOME_TEXTUAL_PERL_H */
