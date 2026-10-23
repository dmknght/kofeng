#ifndef KGENOME_TEXTUAL_FORM_PRIVATE_H
#define KGENOME_TEXTUAL_FORM_PRIVATE_H

/*
 * textual_form_private.h - what the two files of the form share and nobody else reads: the state of one form, the pieces it holds, and the
 * entry points of the call stage (textual_form_call.c) into the writer (textual_form.c) and back.
 *
 * textual_form.c is the writer: one pass over the lexer's spans that writes the form. textual_form_call.c is the stage between them that
 * writes a call on literals as the literal it evaluates to; it reads and writes `struct kgenome_tform` and nothing else of the writer's, and the
 * writer's three entry points it needs are below.
 */

#include "textual_lang.h"

/*
 * A span the form made itself (the literal a call on literals was rewritten to) has its bytes in the OUTPUT buffer, at the top
 * of it - above `cap`, which is lowered to keep what is written from reaching them - and is told by this flag, which no lexer
 * sets. Every read of a held span's bytes goes through kgenome_tform_sp().
 */
#define KGENOME_TFORM_F_SYN 0x80u

struct kgenome_tform_piece {
	struct kgenome_textual_span s;
	uint32_t from, end;     /* the input it stands for: where it begins and the position after it (a rewritten call: its name and its ")") */
	uint8_t pend;           /* white space before the piece */
	uint8_t op_pend;        /* and before the operator that precedes it */
	uint8_t op;             /* an operator was typed between it and the piece before (not so where they sit side by side) */
};

/*
 * CALLS ON LITERALS - the log of one that is being read. `str_replace('k', '', 'ckrekatek')` is read WITHOUT being written: its
 * tokens and literals go here, and when its ")" comes and every argument is a literal or a number (or a call of the same kind,
 * which has been through this already) the call is run and what is written is the literal it evaluates to. Anything else
 * that comes first - a variable, an operator, a literal that interpolates - and the log is written as it would have been, item by
 * item, through the same two entry points the text came in by (code_token_byte, string_piece). Nothing here writes a byte
 * of its own to the output except that literal.
 */
#define KGENOME_TFORM_CALL_ITEMS 160u         /* tokens and literals of every open call together; a longer one is written as typed */
#define KGENOME_TFORM_CALL_DEPTH 4u           /* calls open inside calls */
#define KGENOME_TFORM_CALL_ARGS  16u          /* the most arguments a row of the table has (String.fromCharCode takes one a character) */
#define KGENOME_TFORM_CALL_TOKEN 24u          /* the longest name or number held: longer is not one of the table's (its longest is "String.fromCodePoint", 20) */

enum { KGENOME_TFORM_CI_CODE = 0, KGENOME_TFORM_CI_STR };
struct kgenome_tform_item {
	uint8_t  kind;
	uint8_t  pend;          /* the white space in front of it */
	uint8_t  n;             /* KGENOME_TFORM_CI_CODE: the bytes in t */
	uint8_t  t[KGENOME_TFORM_CALL_TOKEN];
	struct kgenome_textual_span s;  /* KGENOME_TFORM_CI_STR */
	uint32_t from, end;     /* the input it stands for: where it begins, and the position after it */
};

enum { KGENOME_TFORM_PH_NAME = 0, KGENOME_TFORM_PH_ARG, KGENOME_TFORM_PH_NUM, KGENOME_TFORM_PH_NEXT };
struct kgenome_tform_frame {
	struct kgenome_textual_fn fn;
	uint32_t from;          /* where its name began in the input */
	uint8_t  first;         /* its name's place in the log */
	uint8_t  phase;         /* KGENOME_TFORM_PH_NAME: "(" is next; KGENOME_TFORM_PH_ARG: an argument is next; KGENOME_TFORM_PH_NUM: digits are being read; KGENOME_TFORM_PH_NEXT: "," or ")" is next */
	uint8_t  n_args;
	uint8_t  join;          /* a "." was read and a literal (or a call that became one) has to follow, as part of the argument before it */
	/* The log places of each argument: its first item and its last. They are one item, or literals joined by "." with the operators between. */
	uint8_t  arg_a[KGENOME_TFORM_CALL_ARGS], arg_z[KGENOME_TFORM_CALL_ARGS];
};

struct kgenome_tform {
	const struct kgenome_textual_lang *lang;
	const uint8_t *in;
	uint8_t       *out;
	uint64_t       cap;
	uint32_t       w;
	/* White space seen and not yet written, because what it becomes depends on the byte
	 * that follows it: 0 none, 1 a gap, 2 a line break. */
	uint8_t        pend;
	/* Code or a string was written since the block was opened. A block that never gets one
	 * is dropped whole. */
	uint8_t        formed;
	/* Where the block's opening tag began in `out`, plus one; 0 outside a block. */
	uint32_t       island;
	/* The value of `w` right after a "{" written on a line of its own (so `out[w - 2]` is the
	 * line break in front of it): if a line break is the next thing written, the brace goes up
	 * onto the line above. Nothing resets it: any byte written moves `w` and it no longer
	 * matches. 0 is none, and `w` is never 0 after a brace. */
	uint32_t       brace;
	/* The value of `w` right after the blank written to keep "<<<LABEL" from ending its line (settle); like `brace`, any byte written moves `w` past it. */
	uint32_t       hsp;
	uint8_t        full;
	/* What the last literal written left at the end of the output (any byte written after it clears this): bit 0, a line break (LF or CR) INSIDE
	 * it (js: an unclosed string that ends in a backslash and a break and is cut at the next one), so that a break written next is not
	 * redundant, and leaving it out would read what follows as the string's; bit 1, that it was not closed, so a "{" is not joined
	 * onto the line it ends: it would be the string's. */
	uint8_t        lit_end;
	/* The last byte written is the line break of a continuation: the line after it is the same line, so the
	 * white space at its start is a separator and not indentation. */
	uint8_t        joined;
	/* Where `w` was before the backslash of that continuation (and the break written in front of it), with the break
	 * that was waiting and what the last literal left: a python text that ends on one gives all three back. */
	uint32_t       cont_w;
	uint8_t        cont_pend, cont_lit;
	/* The value of `w` right after a literal that was not closed was copied as typed (only for a lang with
	 * `open_tail`): a line break written next would be part of it. Like `brace`, any byte written moves `w`. */
	uint32_t       open_end;
	/* The last bytes of code, white space and comments left out, which is what the lang row reads
	 * the decoders in front of a literal from. Kept as the last FORM_TAIL bytes of a buffer twice
	 * that size, so one is a store and a slide is once in FORM_TAIL bytes. Emptied by anything
	 * that is not code: what is in front of a literal is the code since the last token. */
	uint8_t        tail[2u * 128u];
	uint32_t       tail_n;
	/*
	 * A STRING UNDER A DECODER IS HELD until the byte after it is seen: it is the payload only if the next code
	 * byte closes the argument (")" or ","), and what is written for it differs. A literal that is joined to
	 * another ("a" . "b", "a" + "b", python's "a" "b") is held with them: the payload is the join. Each piece
	 * keeps the white space that stood before it and before the operator that led to it, so that a
	 * join that turns out to be something else - "a" . $x - is written exactly as it would have been.
	 */
	struct {
		uint8_t  on;
		uint8_t  fold;          /* fold_ahead said so when it began: a refused decoder is then written as no decoder would have */
		uint8_t  after_op;      /* an operator was read and a literal has to follow */
		uint8_t  op_pend;       /* the white space in front of that operator */
		uint8_t  chain[KGENOME_TEXTUAL_CHAIN_MAX];
		uint32_t n_chain;
		/* where the calls that wrap the first literal begin in `tail` (from), and the part of `tail` that was in
		 * the reader's window (off, len): what the output holds for them, to be written again renamed */
		uint32_t from, off, len;
		uint32_t n;
		/* The pieces are the caller's stack (kgenome_textual_form), not part of this struct: they are read only up to `n`, and
		 * zeroing ten kilobytes of them for every call was the larger part of what a small text cost. */
		struct kgenome_tform_piece *p;
	} held;
	uint8_t        keep_joins;      /* KGENOME_TEXTUAL_KEEP_JOINS */
	/* python: the depth of brackets open in the code written so far. A line break ends a statement only at depth 0, and a
	 * join of literals goes on across one inside a bracket. Counted for python only: no other lang reads a break that way. */
	uint32_t       depth;
	uint8_t        py;
	uint8_t        track;           /* depth is counted: python, and php for the bracket of an echo */
	uint32_t       echo_depth;      /* php: the depth after the bracket opened for an echo, 0 when none is open */
	/* php: the depth after a bracket that was TYPED right behind an echo or a print, until it closes (0 when none is open). An echo inside the argument
	 * of another is written as it was typed, whether the outer bracket was opened here (echo_depth) or in the text: the form of `echo print 'x'`
	 * is `echo(print 'x')`, and a form that wrote the inner one a call when it read `echo(print 'x')` was not its own. */
	uint32_t       echo_typed;
	kgenome_textual_decode_fn decode;
	void          *decode_user;
	uint32_t       n;               /* the input's length */
	uint32_t       n_decoded, n_refused, n_folded;
	/* calls on literals: the stage is on (the lang has a table, a `value` and a `quote`, the caller a hook, and joins are not kept) */
	uint8_t        fold_calls;
	/* What the table's rewritten functions look like, read off it when the form begins: the bytes a name starts with (both cases where the
	 * language folds them; "\" too, it may stand in front) and the shortest and longest name. A name outside them is not looked up. */
	uint8_t        call_heads[256];
	uint8_t        call_prefix[256];        /* the first three bytes of a name, hashed (call_hash): a name whose bucket is empty is not the table's */
	uint8_t        call_min, call_max;
	uint8_t        call_dots;      /* a name of the table has a "." in it (String.fromCharCode) */
	kgenome_textual_apply_fn apply;
	void          *apply_user;
	uint8_t        nframe;          /* calls open: the log holds them */
	uint8_t        n_it;
	struct kgenome_tform_item *it;           /* the caller's stack, read only up to n_it */
	struct kgenome_tform_frame fr[KGENOME_TFORM_CALL_DEPTH];
	/* What the output keeps at its top: the bytes of literals made here, held (or in the log) until they are written. `cap0` is what the
	 * caller gave; `cap` is that less `syn_used`. Given back when nothing holds one (see form_sink). */
	uint64_t       cap0;
	uint32_t       syn_used;
	uint32_t       n_calls;
	uint32_t       n_fn[KGENOME_TEXTUAL_DEC_COUNT];
};

/* The bytes of a span: the text's, or the output's own for one the form made. */
static inline const uint8_t *kgenome_tform_sp(const struct kgenome_tform *f, const struct kgenome_textual_span *s)
{
	return (s->flags & KGENOME_TFORM_F_SYN ? f->out : f->in) + s->off;
}


/* the writer's, for the call stage: a literal as a held piece or a written one, a byte of code, the position of what is next after white space and comments */
void kgenome_tform_string_piece(struct kgenome_tform *f, const struct kgenome_textual_span *s, uint32_t after, uint32_t from);
void kgenome_tform_code_token_byte(struct kgenome_tform *f, uint8_t c);
uint32_t kgenome_tform_skip_gap(const struct kgenome_tform *f, uint32_t i);

/* the call stage's, for the writer (textual_form_call.c) */
void kgenome_tform_call_table(struct kgenome_tform *f);
void kgenome_tform_call_abort(struct kgenome_tform *f);
int kgenome_tform_call_string(struct kgenome_tform *f, const struct kgenome_textual_span *s);
uint32_t kgenome_tform_call_take(struct kgenome_tform *f, uint8_t c, uint32_t pos);

#endif /* KGENOME_TEXTUAL_FORM_PRIVATE_H */
