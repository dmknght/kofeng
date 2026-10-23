#ifndef KGENOME_TEXTUAL_SPAN_H
#define KGENOME_TEXTUAL_SPAN_H

#include <stdint.h>

/*
 * textual_span.h - what a lexer says about a text: a list of spans that PARTITION it.
 *
 * Every byte of the input is in exactly one span, in order, with no gap and no overlap.
 * That is the one invariant, and it is what lets each later pass (the form, the fold,
 * the unit cut, the anchor) read the same list and not lex again.
 *
 * A span says WHAT its bytes are and nothing about what they mean. It does not decode
 * a literal and does not name an identifier: a pass that needs the value of a string
 * reads the bytes between the delimiters, which the span locates.
 */

enum kgenome_textual_kind {
	/* Text outside the language: HTML around php, and what follows a halt marker.
	 * Verbatim; a pass leaves it alone. */
	KGENOME_TEXTUAL_MARKUP = 0,
	/* The delimiters that enter and leave the language: "<?php", "<?=", "?>". */
	KGENOME_TEXTUAL_TAG,
	/* Code: names, numbers, operators, whitespace. Outside every literal and comment. */
	KGENOME_TEXTUAL_CODE,
	/* One string literal, delimiters included. The value is [open_len, len - close_len). */
	KGENOME_TEXTUAL_STRING,
	/* One comment, delimiters included. A line comment does not include its line break. */
	KGENOME_TEXTUAL_COMMENT,
	KGENOME_TEXTUAL_KIND_COUNT
};

/* A backslash is an escape in this string (and a double quoted php string may interpolate): the form may
 * write a spelled-out byte as itself, where the language says its escapes are those. Not set for a string
 * that is verbatim - php's single quotes, a raw python string, a nowdoc. */
#define KGENOME_TEXTUAL_F_INTERP  0x1u
/* It was not closed before the end of the input. close_len is 0. */
#define KGENOME_TEXTUAL_F_OPEN    0x2u
/* A heredoc or a nowdoc. The value's last line break is not part of the value. */
#define KGENOME_TEXTUAL_F_HERE    0x4u

/* A TAG that leaves the language ("?>"), as opposed to one that enters it. */
#define KGENOME_TEXTUAL_F_CLOSE   0x8u

struct kgenome_textual_span {
	uint32_t off, len;
	uint32_t open_len;      /* delimiter bytes at the start of a STRING or COMMENT */
	uint32_t close_len;     /* and at its end; 0 when F_OPEN */
	uint8_t  kind;          /* enum kgenome_textual_kind */
	uint8_t  flags;         /* KGENOME_TEXTUAL_F_* */
};

#endif /* KGENOME_TEXTUAL_SPAN_H */
