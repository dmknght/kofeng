#ifndef KGENOME_TEXTUAL_RUBY_H
#define KGENOME_TEXTUAL_RUBY_H

/*
 * ruby.h - the ruby directory's one header, private to the family: its row, its lexer, and what the lexer's two
 * halves share. Code (ruby_lex.c) and literals (ruby_str.c) call each other - a "#{ ... }" in a string is code, and
 * code holds strings - so the scan state and the two entry points are here.
 */

#include "../textual_lang.h"

extern const struct kgenome_textual_lang kgenome_textual_lang_ruby;

/* The row's function table (ruby_fn.c). */
extern const struct kgenome_textual_fn_table kgenome_textual_ruby_fn_table;

void kgenome_textual_ruby_lex(struct kgenome_textual_lexer *lx);

int kgenome_textual_ruby_value(const uint8_t *lit, uint32_t len, uint32_t open_len, uint32_t close_len, uint8_t flags,
			       uint8_t *out, uint32_t *n);

/* The row of an interpolating literal (ruby_value.c). */
extern const struct kgenome_textual_esc kgenome_textual_ruby_dq_esc;

/* The row's `unescape_str`: see textual_lang.h and ruby_esc.c. */
uint32_t kgenome_textual_ruby_unescape(const uint8_t *s, uint32_t len, uint32_t open_len, uint8_t *out);

/*
 * THE LEXER'S SHARED STATE. A "#{ ... }" inside a literal is code with literals of its own, so the literal scanner
 * (ruby_str.c) calls the code scanner (ruby_lex.c) and the code scanner calls it back. The recursion is bounded by
 * KGENOME_RUBY_DEPTH: a literal nested deeper is not opened and the one that holds it is open to the end of the text, which
 * delivers every byte and keeps the work linear - the work is one read of each byte, because a literal that fails
 * is never scanned again.
 */
#define KGENOME_RUBY_DEPTH 64u
#define KGENOME_RUBY_HEREDOCS 32u       /* "<<A, <<B" on one line, queued for their line; more are read as shifts */

struct kgenome_ruby_heredoc {
	uint32_t off, len;      /* the identifier, in the text */
	uint8_t  indent;        /* "<<-" and "<<~": the closing line may be indented */
	uint8_t  raw;           /* 'ID': no escape and no interpolation */
};

struct kgenome_ruby_scan {
	struct kgenome_textual_lexer *lx;
	const uint8_t *p;
	uint32_t       n;
	uint32_t       depth;           /* code scans in progress: 0 is the text itself, which is delivered */
	uint32_t       nhd;             /* heredocs waiting for the next line */
	uint32_t       hfail[3];        /* a quoted heredoc id (" ' `) found no closing quote before this offset: asking again before it is no */
	uint8_t        flushing;        /* their bodies are being read: a heredoc opened in one is a shift (see ruby_lex.c) */
	struct kgenome_ruby_heredoc hd[KGENOME_RUBY_HEREDOCS];
};

/* One literal found by ruby_str.c: where it ends, its delimiters and its flags (KGENOME_TEXTUAL_F_*). */
struct kgenome_ruby_lit {
	uint32_t end, open, close;
	uint8_t  flags;
};

/*
 * The code that begins at `i`, inside "#{": up to and past the "}" that closes it, whose offset + 1 is the answer.
 * 0 when the text ends first or the nesting is past KGENOME_RUBY_DEPTH. Nothing is delivered from inside.
 */
uint32_t kgenome_ruby_code_nested(struct kgenome_ruby_scan *sc, uint32_t i);

/*
 * The quoted literal whose opening delimiter byte is at `i`: ' " or `. `*lit` is filled; an unclosed one runs
 * to the end of the text and is OPEN. `interp` says "#{...}", "#@x" and escapes are read (not for ').
 */
void kgenome_ruby_quoted(struct kgenome_ruby_scan *sc, uint32_t i, uint8_t quote, struct kgenome_ruby_lit *lit);

/* The percent literal at `i` ("%q(" and the rest): 1 and `*lit` when it is one, 0 when the "%" is something else. */
int kgenome_ruby_percent(struct kgenome_ruby_scan *sc, uint32_t i, struct kgenome_ruby_lit *lit);

/* The regular expression whose "/" is at `i`, its options included. */
void kgenome_ruby_regex(struct kgenome_ruby_scan *sc, uint32_t i, struct kgenome_ruby_lit *lit);

/* The body of a heredoc from `i` (a line start) to the end of its closing line. `lit->open` is 0. */
void kgenome_ruby_heredoc_body(struct kgenome_ruby_scan *sc, uint32_t i, const struct kgenome_ruby_heredoc *hd, struct kgenome_ruby_lit *lit);

/* The length of the global variable at `i` ("$name", "$1", "$'", "$-w"), 0 when there is none; and of an instance or
 * class variable ("@x", "@@x"). A quote after "$" is part of the name, which is what keeps `$'` from opening a string. */
uint32_t kgenome_ruby_gvar_len(const uint8_t *p, uint32_t n, uint32_t i);
uint32_t kgenome_ruby_ivar_len(const uint8_t *p, uint32_t n, uint32_t i);

/* What follows a "#" in a literal that interpolates and is not "{": the variable it names ("#@x", "#$x"), its length; else 0. */
uint32_t kgenome_ruby_dvar_len(const uint8_t *p, uint32_t n, uint32_t i);

#endif /* KGENOME_TEXTUAL_RUBY_H */
