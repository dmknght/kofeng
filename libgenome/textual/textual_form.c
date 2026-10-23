/*
 * textual_form.c - the form of a text: how it was typed, taken out, over the spans of its lexer.
 * See kgenome_textual_form in textual.h for what that is and what is never touched.
 *
 * ONE PASS, ONE LEX. The lexer says what each run of bytes is; this reads each span as it
 * arrives and writes the form, so nothing is held but the output. What the output needs to know
 * about the bytes it already wrote is three things - the last byte, whether code has been
 * written in this block, and whether the last line is a lone brace that could still join the
 * line above - and they are the members of `struct kgenome_tform`.
 */

#include <string.h>

#include <kofcore.h>

#include "textual_form_private.h"

#define FORM_PIECES 256u

#define FORM_TAIL 128u

static void put(struct kgenome_tform *f, uint8_t c)
{
	if (f->w >= f->cap) {
		f->full = 1;
		return;
	}
	f->out[f->w++] = c;
	f->lit_end = 0;
}

/* `len` bytes at `src`. memmove: a literal made here is read from the top of the same buffer. */
static void copy_bytes(struct kgenome_tform *f, const uint8_t *src, uint32_t len)
{
	if (len > f->cap - f->w) {
		f->full = 1;
		return;
	}
	memmove(f->out + f->w, src, len);
	f->w += len;
	f->lit_end = 0;
}

static void copy(struct kgenome_tform *f, uint32_t off, uint32_t len)
{
	copy_bytes(f, f->in + off, len);
}

static void tail_push(struct kgenome_tform *f, uint8_t c)
{
	if (f->tail_n == sizeof f->tail) {
		memmove(f->tail, f->tail + FORM_TAIL, FORM_TAIL);
		f->tail_n = FORM_TAIL;
	}
	f->tail[f->tail_n++] = c;
}

/*
 * Would a line break written now be the end of the line a heredoc opens on: `<<<LABEL`, `<<<"LABEL"`, `<<<'LABEL'` at the end of the output. "<<<HTML?>" is no
 * heredoc (the label ends its line or it is not one), and "<<<HTML<nl>?>" is one, to the end of the text.
 */
static int heredoc_opener_end(const struct kgenome_tform *f)
{
	uint32_t w = f->w, k = 0;
	uint8_t q = 0;

	if (!f->lang->heredoc_eol)
		return 0;
	if (w && (f->out[w - 1u] == '\'' || f->out[w - 1u] == '"'))
		q = f->out[--w];
	while (w && kgenome_textual_ident(f->out[w - 1u])) {
		w--;
		k++;
	}
	if (!k || kof_is_digit(f->out[w]))
		return 0;
	if (q) {
		if (!w || f->out[w - 1u] != q)
			return 0;
		w--;
	}
	while (w && (f->out[w - 1u] == ' ' || f->out[w - 1u] == '\t'))
		w--;
	return w >= 3u && f->out[w - 1u] == '<' && f->out[w - 2u] == '<' && f->out[w - 3u] == '<';
}

/*
 * A "{" alone on its line goes up onto the line above (`brace == w` says it is one): the line break behind it is taken back, and the blank
 * that settle wrote in front of that break to keep "<<<LABEL" from ending its line (`hsp`: where `w` was right after it) with it.
 */
static void brace_up(struct kgenome_tform *f)
{
	f->brace = 0;                   /* the join takes two bytes back when there is a blank, and two more are written: `w` would be `brace` again */
	if (f->hsp && f->hsp + 2u == f->w && f->out[f->w - 3u] == ' ') {
		f->out[f->w - 3u] = '{';
		f->w -= 2u;
	} else {
		f->out[f->w - 2u] = '{';
		f->w--;
	}
}

/*
 * Write what is waiting, given the byte about to follow it. Answers 1 when a line break was
 * written, which is what makes a "{" a lone one.
 */
static int settle(struct kgenome_tform *f, uint8_t next, int heredoc)
{
	int broke = 0;

	/* The tail has no white space, except what parts two words: "return window" would be one name, and a decoder
	 * read out of it would take "return" with it when the calls are found again in the output. */
	if (f->pend && f->tail_n && kgenome_textual_ident(next) && kgenome_textual_ident(f->tail[f->tail_n - 1u]))
		tail_push(f, ' ');
	if (f->pend && f->w) {
		uint8_t last = f->out[f->w - 1u];

		if (f->pend == 2u) {
			if (f->brace == f->w && f->w >= 2u)
				brace_up(f);            /* The brace was alone on its line: take the line break behind it back. */
			if (f->out[f->w - 1u] != '\n' || (f->lit_end & 1u) ||
			    (f->joined && (f->lang->vb_lines || f->lang->universal_eol))) {
				/* (vb and python: after a continuation the break written is the join, so this one is the
				 * statement's end and stays - "x = 1 \<nl><nl>y = 2" is two statements, and so is a comment
				 * on the line after the backslash. After a literal that ends in a break of its own the break is
				 * written, and as the same byte: "\n" after a CR would make one "\r\n" with it.)
				 * php: the text had something between "<<<LABEL" and its line break (a blank, a comment: else it was a heredoc, not code), and a break
				 * written right behind the label would open one. */
				if (heredoc_opener_end(f)) {
					put(f, ' ');
					f->hsp = f->w;
				}
				/* "\r" again only where a lone CR is a line break (python, vbscript): in the shell a CR is a blank, and the "\n" typed after a heredoc's "EOF\r" is the
				 * line break that ends the terminator's line (written as "\r" the terminator was "EOF\r\rid": L15 of the lexer audit) */
				put(f, (f->lit_end & 1u) && f->out[f->w - 1u] == '\r' && (f->lang->universal_eol || f->lang->vb_lines) ? '\r' : '\n');
				broke = 1;
			}
		} else if ((last != '\n' || f->joined) &&
			   (f->lang->ws_significant || heredoc ||
			    (kgenome_textual_ident(last) && kgenome_textual_ident(next)) || f->lang->glue(last, next) ||
			    (f->lang->glue_tail && f->lang->glue_tail(f->tail, f->tail_n, next)))) {
			put(f, ' ');
		}
	}
	f->pend = 0;
	f->joined = 0;
	return broke;
}

/* A byte of code. */
static void code_byte(struct kgenome_tform *f, uint8_t c)
{
	int open = (f->lit_end & 2u) != 0, broke = settle(f, c, 0);

	tail_push(f, c);
	put(f, c);
	/* A "#!" that the FORM puts at the start of its output is no hashbang in the text it was made from (js: ` #!x`, the blank in front of it dropped; lua: `# !`, the length
	 * operator and a "!", the gap between them closed), and the next pass reads the interpreter's line there, a comment: one blank keeps it off byte 0, and the next pass drops
	 * it and puts the same one back (L22). A hashbang that was typed at byte 0 is a comment span, and never comes here. */
	if (c == '!' && f->w == 2u && f->out[0] == '#' && f->lang->keep_hashbang && f->w < f->cap) {
		memmove(f->out + 1, f->out, 2u);
		f->out[0] = ' ';
		f->w = 3u;
	}
	if (f->track) {
		if (c == '(' || c == '[' || c == '{')
			f->depth++;
		else if ((c == ')' || c == ']' || c == '}') && f->depth) {
			f->depth--;
			/* a bracket typed in the text closes the one the form opened as well (echo );), and then the echo is over */
			if (f->depth < f->echo_typed)
				f->echo_typed = 0;
			if (f->depth < f->echo_depth)
				f->echo_depth = 0;
		}
	}
	if (c == '{' && broke && !open && f->lang->join_brace &&
	    (!f->lang->join_ok || (f->w >= 2u && f->lang->join_ok(f->out, f->w - 2u))))
		f->brace = f->w;
	f->formed = 1;
}

static int resolve_held(struct kgenome_tform *f, uint8_t next);

/* A line break ends the statement: python's rule outside brackets (js shares only what a line terminator is). */
static inline int py_lines(const struct kgenome_tform *f)
{
	return f->py && f->depth == 0;
}

/* A byte of code that is not white space: it ends what a held string was waiting to see. */
static void replay_held(struct kgenome_tform *f);

/*
 * What the byte after held literals means for them. 1 when the byte is the operator that joins them and is held with
 * them (the caller writes nothing); 0 when it ended the join - the literals are written, decoded or as typed - and the
 * caller goes on to write the byte.
 */
static int held_step(struct kgenome_tform *f, uint8_t c)
{
	if (!f->held.on)
		return 0;
	/* python: a line break outside brackets ends the statement, so what is on the next line is not joined to this one */
	if (!f->held.after_op && f->lang->concat && c == f->lang->concat &&
	    !(f->pend == 2u && py_lines(f))) {
		if (f->held.n < FORM_PIECES) {
			/* the operator that joins literals: held, and a literal has to follow */
			f->held.op_pend = f->pend;
			f->pend = 0;
			f->held.after_op = 1;
			return 1;
		}
		f->n_refused += f->held.n_chain != 0;   /* more pieces than are joined: it stays as typed, and a decoder's is said */
	}
	if (f->held.after_op) {
		replay_held(f);
		return 0;
	}
	return resolve_held(f, c);
}

/*
 * php: "echo" and "print" are written as calls. `next` is the first byte after the word; the word is what ends the
 * tail - with a name boundary in front (not "$echo", "->echo", "::echo") and not continued by `next` ("echoes").
 */
static void echo_open(struct kgenome_tform *f, uint8_t next)
{
	static const char *const kw[] = { "echo", "print" };
	uint32_t k;

	if (!f->lang->echo_call || f->echo_depth || f->echo_typed || next == ';' || (!f->pend && kgenome_textual_ident(next)))
		return;
	/* both words end in a letter that few names do (echo: "o", print: "t"): asked at every "(" and every byte that follows a token, so the rest waits for it */
	if (!f->tail_n || ((f->tail[f->tail_n - 1u] | 0x20u) != 'o' && (f->tail[f->tail_n - 1u] | 0x20u) != 't'))
		return;
	for (k = 0; k < 2u; k++) {
		uint32_t l = (uint32_t)strlen(kw[k]);

		if (f->tail_n < l || !kgenome_textual_ci_eq(f->tail + f->tail_n - l, kw[k], l))
			continue;
		if (f->tail_n > l) {
			uint8_t b = f->tail[f->tail_n - l - 1u];

			if (kgenome_textual_ident(b) || b == '$' || b == '>' || b == ':' || b == '\\')
				continue;
		}
		if (next == '(') {                      /* typed with its bracket: nothing to write, and nothing inside it is wrapped */
			f->echo_typed = f->depth + 1u;
			return;
		}
		code_byte(f, '(');
		f->echo_depth = f->depth;
		return;
	}
}

/*
 * The bracket an echo opened, closed: before the ";", the tag or the end that ends the argument. NOT in front of a halt marker's own ";" or "?>":
 * `__halt_compiler()` is a statement of its own, and a bracket written inside it (`__halt_compiler());`) is no longer one - what follows it is
 * then code, and the data the program reads from there is changed. The bracket is left as typed in a text that does that (it is not php).
 */
static void echo_close(struct kgenome_tform *f)
{
	if (!f->echo_depth)
		return;
	f->echo_depth = 0;
	if (f->tail_n >= 17u && kgenome_textual_ci_eq(f->tail + f->tail_n - 17u, "__halt_compiler()", 17u))
		return;
	code_byte(f, ')');
}

static void code_token_byte(struct kgenome_tform *f, uint8_t c)
{
	if (held_step(f, c))
		return;
	if (!f->echo_depth) {
		if (f->lang->echo_call)         /* tested here: the call was a function call per code byte of every language */
			echo_open(f, c);
	}
	else if (c == ';' && f->depth == f->echo_depth)
		echo_close(f);
	code_byte(f, c);
}

/* The line break a continuation backslash takes, at `k` in the span: "\n", and where the language reads every
 * ending (python) "\r\n" and "\r" too. Its length, or 0. */
static uint32_t cont_break(const struct kgenome_tform *f, const struct kgenome_textual_span *s, uint32_t k)
{
	const uint8_t *p = f->in + s->off;

	if (k >= s->len)
		return 0;
	if (p[k] == '\n')
		return 1u;
	if (!f->lang->universal_eol || p[k] != '\r')
		return 0;
	return k + 1u < s->len && p[k + 1u] == '\n' ? 2u : 1u;
}


/* The bytes that continue a name (kgenome_textual_ident), as a table: asked of the byte before every byte of code that could begin one. */
static const uint8_t call_cont[256] = {
	/* 0x00 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0x10 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	/* 0x20 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0x30 */ 1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,
	/* 0x40 */ 0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0x50 */ 1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,1,
	/* 0x60 */ 0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0x70 */ 1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
	/* 0x80 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0x90 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	/* 0xa0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xb0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	/* 0xc0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xd0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	/* 0xe0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xf0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
};

/*
 * `calls` is a constant in each of the two copies below (code_span, code_span_calls), so the loop of a language with no calls to
 * rewrite is the loop it was: measured 3.4% on the form of a php corpus when it was a test per byte of one loop.
 */
static inline __attribute__((always_inline)) void code_span_body(struct kgenome_tform *f, const struct kgenome_textual_span *s, int calls)
{
	uint32_t i, len;
	/* (calls) whether the last byte of code was one that continues a name: a name of the table can only start where it was not. Carried from byte
	 * to byte, so that asking costs one table read of the byte in hand and not a look back into the input and a second read. The byte before the
	 * span is whatever ended the span before it, which is never code. */
	uint32_t prev_name = calls && s->off ? call_cont[f->in[s->off - 1u]] : 0u;

	for (i = 0; i < s->len; i++) {
		uint8_t c = f->in[s->off + i];

		if (f->lang->continuation && c == kgenome_textual_cont_byte(f->lang) && (len = cont_break(f, s, i + 1u)) != 0) {
			/* the break belongs to the backslash: written with it, and no line break is pending */
			held_step(f, c);        /* literals waiting for this byte are written first: what is given back is after them */
			if (!f->joined) {     /* the first of a run of them: "x \<nl>\<nl>" gives back both */
				f->cont_w = f->w;
				f->cont_pend = f->pend;
				f->cont_lit = f->lit_end;
			}
			code_byte(f, c);
			put(f, '\n');
			f->pend = 0;
			f->joined = 1;
			i += len;
		} else if (f->lang->continuation && c == kgenome_textual_cont_byte(f->lang) && i + 1u < s->len) {
			/* a backslash and the byte after it are one thing: an escaped blank is a letter of its word */
			code_token_byte(f, c);
			code_token_byte(f, f->in[s->off + ++i]);
		} else if (f->lang->vb_lines && c == '_' && (len = kgenome_textual_vb_cont(f->in, s->off + s->len, s->off + i)) != 0) {
			/* vb: the "_" and its line break are one thing, written together; the gap before the "_"
			 * is kept by the row's glue (a continuation is a "_" after a space) */
			code_token_byte(f, c);
			put(f, '\n');
			f->pend = 0;
			f->joined = 1;
			i += len - 1u;
		} else if (c == '\n' || (c == '\r' && (f->lang->vb_lines || f->lang->universal_eol) && (i + 1u >= s->len || f->in[s->off + i + 1u] != '\n')) ||
			   (c == '\r' && i == 0 && (f->lit_end & 2u))) {
			/* (the last alternative: a one-line string that did not close ended at this CR, so it is a line break to the form as well; written as a blank the next
			 * literal was closed up against the string - `"` CR `"` became `""`, a string that the next pass read as closed: L23) */
			f->pend = 2u;
			prev_name = 0;
		} else if (kgenome_textual_blank_in(c, f->lang->word_vt_ff)) {
			f->pend = f->pend ? f->pend : 1u;
			prev_name = 0;
		} else if (calls) {
			/* one test, true for a call being read and for a byte a name of the table starts with and nothing else (a branch on each of the two
			 * was measured at 12% of the form in time for 7% in instructions: the starts are as good as random, and mispredicted) */
			uint32_t hit = (uint32_t)f->nframe | ((uint32_t)f->call_heads[c] & (prev_name ^ 1u)), took = 0;

			prev_name = call_cont[c];
			if (hit)
				took = kgenome_tform_call_take(f, c, s->off + i);
			if (took) {
				i += took - 1u;
				prev_name = call_cont[f->in[s->off + i]];
			} else {
				code_token_byte(f, c);
			}
		} else {
			code_token_byte(f, c);
		}
	}
}

static void code_span(struct kgenome_tform *f, const struct kgenome_textual_span *s)
{
	code_span_body(f, s, 0);
}

static void code_span_calls(struct kgenome_tform *f, const struct kgenome_textual_span *s)
{
	code_span_body(f, s, 1);
}

/*
 * php: a double-quoted literal with nothing in it that single quotes read differently - no "$" to interpolate, no
 * backslash to escape, no "'" to end it - is the same text either way, and is written with single quotes. Judged on
 * what was WRITTEN, from `at`: "\41" is the byte "!" by then and the literal is as plain as "!" was, which is what a
 * second pass reads and has to find the same.
 */
static void plain_dq(struct kgenome_tform *f, const struct kgenome_textual_span *s, uint32_t at)
{
	uint32_t i;

	if (!f->lang->norm_quote || s->kind != KGENOME_TEXTUAL_STRING || (s->flags & (KGENOME_TEXTUAL_F_HERE | KGENOME_TEXTUAL_F_OPEN)) ||
	    s->open_len != 1u || s->close_len != 1u || f->w < at + 2u || f->out[at] != '"' || f->out[f->w - 1u] != '"')
		return;
	for (i = at + 1u; i + 1u < f->w; i++)
		if (f->out[i] == '$' || f->out[i] == '\\' || f->out[i] == '\'')
			return;
	f->out[at] = f->out[f->w - 1u] = '\'';
}

/* Copied as typed: a string, a comment that never closed. The first byte settles what is waiting. */
static void verbatim_span(struct kgenome_tform *f, const struct kgenome_textual_span *s)
{
	settle(f, kgenome_tform_sp(f, s)[0], (s->flags & KGENOME_TEXTUAL_F_HERE) != 0);
	uint32_t at = f->w;

	if (s->kind == KGENOME_TEXTUAL_STRING && (s->flags & KGENOME_TEXTUAL_F_INTERP) && f->lang->unescape_str) {
		if (s->len > f->cap - f->w)
			f->full = 1;
		else
			f->w += f->lang->unescape_str(kgenome_tform_sp(f, s), s->len, s->open_len, f->out + f->w);
	} else {
		copy_bytes(f, kgenome_tform_sp(f, s), s->len);
	}
	plain_dq(f, s, at);
	/* python: an unclosed one-line string can end in a backslash and a lone CR (the CR is escaped, the next break
	 * ends the string). The break written after it is "\n", and "\r\n" would read as ONE escaped break, so the
	 * string would go on past it; a CR is a line break whichever it is typed as, so it is written as "\n". */
	if (f->lang->universal_eol && s->kind == KGENOME_TEXTUAL_STRING && (s->flags & KGENOME_TEXTUAL_F_OPEN) &&
	    f->w && f->out[f->w - 1u] == '\r')
		f->out[f->w - 1u] = '\n';
	if ((s->flags & KGENOME_TEXTUAL_F_OPEN) && f->lang->open_tail)
		f->open_end = f->w;
	f->lit_end = (uint8_t)((s->kind == KGENOME_TEXTUAL_STRING && f->w && (f->out[f->w - 1u] == '\n' || f->out[f->w - 1u] == '\r') ? 1u : 0u) |
			       ((s->flags & KGENOME_TEXTUAL_F_OPEN) ? 2u : 0u));
	f->formed = 1;
}

/* The operator that joined two held literals, written as typed, with the white space that stood in front of it. */
static void put_concat(struct kgenome_tform *f, uint8_t pend)
{
	f->pend = pend;
	code_byte(f, f->lang->concat);
}

/*
 * THE HELD LITERALS AS TYPED: written exactly as the stream would have written them, the operators between them
 * included. What is waiting in f->pend when this is called is the white space after the last of them (or after the
 * operator that was read last), and is left waiting for whatever comes next.
 */
static void replay_held(struct kgenome_tform *f)
{
	uint8_t acc = f->pend;
	uint32_t i;

	f->held.on = 0;
	for (i = 0; i < f->held.n; i++) {
		if (i && f->held.p[i].op)
			put_concat(f, f->held.p[i].op_pend);
		f->pend = f->held.p[i].pend;
		verbatim_span(f, &f->held.p[i].s);
	}
	if (f->held.after_op && f->lang->concat)        /* an operator with no literal after it */
		put_concat(f, f->held.op_pend);
	f->held.after_op = 0;
	f->pend = acc;
}

/*
 * THE CALLS AROUND A DECODED LITERAL KEEP BEING THERE - they are how the text came to be, and a reader (a person or a
 * matcher) needs that - but they are no longer called what they were: "base64_decode(" in front of text that is no
 * longer base64 says something false about it. Each name in the chain is written with DECODED_MARK in front of it,
 * "decoded_base64_decode(", the one spelling the languages with a call by name all read as a name. Answers where the
 * output goes back to (the start of the outermost call), or -1 when the output does not end with the bytes the reader
 * took the calls from - white space apart - and they are left alone.
 */
#define DECODED_MARK "decoded_"

static int64_t calls_back(const struct kgenome_tform *f)
{
	const uint8_t *calls = f->tail + f->held.off + f->held.from;
	uint32_t n = f->held.len - f->held.from, w = f->w;

	while (n) {
		if (!w)
			return -1;
		if (f->out[w - 1u] == calls[n - 1u] ||
		    (calls[n - 1u] == ' ' && (f->out[w - 1u] == '\n' || f->out[w - 1u] == '\t'))) {
			n--;
		} else if (f->out[w - 1u] != ' ' && f->out[w - 1u] != '\n' && f->out[w - 1u] != '\t') {
			return -1;
		}
		w--;
	}
	return (int64_t)w;
}

/* The calls written again from `w`, from what the reader saw, with the mark in front of the name of each call whose "(" is
 * still open at the end - the calls the literal is the argument of; "getDecoder()" in "getDecoder().decode(" is not one. */
static void calls_rewrite(struct kgenome_tform *f, uint32_t w)
{
	const uint8_t *calls = f->tail + f->held.off + f->held.from;
	uint32_t n = f->held.len - f->held.from, i, run = 0, have = 0, top = 0;
	uint8_t open[2u * 128u];                /* the "(" not yet closed, as an index in `calls` */
	uint32_t at[2u * 128u];

	for (i = 0; i < n; i++) {
		if (calls[i] == '(')
			at[top++] = i;
		else if (calls[i] == ')' && top)
			top--;
	}
	memset(open, 0, n);
	while (top)
		open[at[--top]] = 1;
	f->w = w;
	for (i = 0; i < n; i++) {
		uint8_t c = calls[i];

		if (c == '(' && have && open[i]) {
			memmove(f->out + run + (sizeof DECODED_MARK - 1u), f->out + run, f->w - run);
			memcpy(f->out + run, DECODED_MARK, sizeof DECODED_MARK - 1u);
			f->w += (uint32_t)sizeof DECODED_MARK - 1u;
		}
		if (kgenome_textual_ident(c) || c == '$') {
			if (!have)
				run = f->w;
			have = 1;
		} else {
			have = 0;
		}
		f->out[f->w++] = c;
	}
}

/*
 * THE VALUE, NOT THE TEXT, IS WHAT A DECODER READS: "YWJj\n" is four letters and a line break, which the text
 * is not. A language that has a value hook gives it, and the bytes are written into the buffer ahead of the
 * output - where the decoded text will go, so they cost no room of their own and are dead when the hook is done.
 * The pieces of a join are valued one after the other and are one value. A literal with no value (it
 * interpolates, it has an escape the lib does not compute) is not offered, and nor is the join it is in; nor is a
 * join in a language that cannot value a literal. Answers 0 for those.
 */
static int held_value(struct kgenome_tform *f, const uint8_t **val, uint32_t *vl)
{
	const struct kgenome_textual_span *s0 = &f->held.p[0].s;
	uint8_t *scratch = f->out + f->w + 4u;
	uint64_t need = (uint64_t)f->held.p[f->held.n - 1u].end - f->held.p[0].from;
	uint32_t i, n = 0;

	if (!f->lang->value) {
		if (f->held.n > 1u)
			return 0;
		*val = kgenome_tform_sp(f, s0) + s0->open_len;
		*vl = s0->len - s0->open_len - s0->close_len;
		return 1;
	}
	/* the input the pieces stand for bounds their values, except a literal made here: that one is bounded by its own bytes */
	for (i = 0; i < f->held.n; i++)
		if (f->held.p[i].s.flags & KGENOME_TFORM_F_SYN)
			need += f->held.p[i].s.len;
	if (f->w + 4u + need > f->cap)
		return 0;
	for (i = 0; i < f->held.n; i++) {
		const struct kgenome_textual_span *p = &f->held.p[i].s;
		uint32_t nv = 0;

		if (p->len < p->open_len + p->close_len ||
		    !f->lang->value(kgenome_tform_sp(f, p), p->len, p->open_len, p->close_len, p->flags, scratch + n, &nv))
			return 0;
		n += nv;
	}
	*val = scratch;
	*vl = n;
	return 1;
}

static int ends_expr(const struct kgenome_tform *f, uint8_t next)
{
	return next == ')' || next == ',' || next == ';' || next == ']' || next == '}' ||
	       (f->pend == 2u && (f->lang->vb_lines || py_lines(f)));
}

/*
 * Do two pieces' texts, written one after the other, mean what they meant apart. They do not when the first ends in a
 * variable the second would extend, or in an escape that is still waiting for digits - "\1", "\x4", "\u00" - and the second begins with one it would take: "\1" . "2"
 * is the byte 1 and a "2", and "\12" is a line feed. Those joins stay as typed.
 */
static int seam_ok(const uint8_t *a, uint32_t na, uint8_t b)
{
	uint32_t t = 0, bs = 0, v;
	uint8_t k;

	/*
	 * A VARIABLE AT THE END OF THE FIRST TEXT TAKES WHAT THE SECOND BEGINS WITH: "$a" . "b$c" written as one literal is
	 * "$ab$c", the variable $ab. The name, an index "[", a property "->" or a brace "{" would all be read as part of it.
	 * (A language whose double quotes do not interpolate has no sigil to find, so this never refuses there.)
	 */
	for (v = 0; v < na && kgenome_textual_ident(a[na - 1u - v]); v++)
		;
	if (v < na && (a[na - 1u - v] == '$' || a[na - 1u - v] == '@') &&
	    (kgenome_textual_ident(b) || b == '[' || b == '{' || b == '-' || b == ':'))
		return 0;
	while (t < na && t < 9u && kgenome_textual_ident(a[na - 1u - t]))
		t++;
	if (t == na || a[na - 1u - t] != '\\')
		return 1;
	for (bs = 1; bs < na - t && a[na - 1u - t - bs] == '\\'; bs++)
		;
	if (bs & 1u ? 0 : 1)
		return 1;               /* an even run of backslashes: the last is not an escape's */
	k = a[na - t];
	if (k >= '0' && k <= '7')
		return !(t < 3u && b >= '0' && b <= '7');
	if (k == 'x' || k == 'u' || k == 'U')
		return !(t - 1u < (k == 'x' ? 2u : k == 'u' ? 4u : 8u) && kof_hex_val(b) >= 0);
	return 1;
}

/*
 * A JOIN OF LITERALS THAT NO DECODER READS is one literal, and the view shows it as one: "ev" . "al" is how a name is
 * kept from a scan, and the join is the obfuscation. The pieces' own bytes are joined as they were typed - no value is
 * computed, no escape is added or taken away - so the literal is the first piece's delimiters round every piece's text, and
 * only pieces with the same delimiters are one (the same delimiters read the text between them the same way). Only when
 * the pieces end the expression (the byte after them closes an argument, a list, a block or the statement - or is the
 * line's end where the language has no other terminator): what follows a join can bind tighter than it
 * ("a" + "b".length), and then the pieces are not one value. `end` is that: ends_expr for the byte after them, 1 where
 * the text or the block ends. Answers 0: no byte is consumed here.
 */
static int fold_held(struct kgenome_tform *f, int end)
{
	const struct kgenome_textual_span *s0 = &f->held.p[0].s;
	uint8_t after = f->pend;
	uint32_t i;
	/* only a literal that a quote opens is a string being joined: %w[a b] + %w[c], qw(a) . qw(b), m/a/ . m/b/ and a backquoted
	 * command are lists, patterns and commands, and one literal of their text is another thing */
	int same = f->held.fold && f->held.n > 1u && end && s0->open_len >= 1u && s0->open_len <= 8u && s0->close_len <= 8u &&
		   (kgenome_tform_sp(f, s0)[s0->open_len - 1u] == '"' || kgenome_tform_sp(f, s0)[s0->open_len - 1u] == '\'');

	for (i = 1; i < f->held.n && same; i++) {
		const struct kgenome_textual_span *p = &f->held.p[i].s;

		same = !(p->flags & KGENOME_TEXTUAL_F_HERE) && p->len >= p->open_len + p->close_len &&
		       p->open_len == s0->open_len && p->close_len == s0->close_len &&
		       (f->lang->norm_quote ||          /* php: judged on what is written, below */
			(memcmp(kgenome_tform_sp(f, p), kgenome_tform_sp(f, s0), s0->open_len) == 0 &&
			 memcmp(kgenome_tform_sp(f, p) + p->len - p->close_len, kgenome_tform_sp(f, s0) + s0->len - s0->close_len,
				s0->close_len) == 0));
	}
	if (same && (s0->flags & KGENOME_TEXTUAL_F_HERE))
		same = 0;
	if (same) {
		/* each piece is written the way it is on its own (an escape spelled out is its byte), and the delimiters between
		 * them go: the same bytes that would have been written, less what the join took away. The seam is judged on
		 * those bytes - what a second pass over the output would read. A SEAM THAT WOULD CHANGE WHAT AN ESCAPE MEANS
		 * ENDS THE RUN, and only that run: the literal written so far is closed, the operator is written as it was typed,
		 * and the pieces from the refused one on are joined in a run of their own. "ev" . "al" . "$" . "x" is `'eval' . '$x'`
		 * and not four pieces because of one seam. */
		uint32_t k = 0, joined = 0;

		f->held.on = 0;
		for (;;) {
			const struct kgenome_textual_span *r0 = &f->held.p[k].s;
			uint32_t pstart, at;
			uint8_t d_open[8], d_close[8];

			if (k && f->held.p[k].op)
				put_concat(f, f->held.p[k].op_pend);
			f->pend = f->held.p[k].pend;
			settle(f, kgenome_tform_sp(f, r0)[0], 0);
			pstart = f->w;
			f->held.p[k].pend = 0;          /* settled: nothing may write the white space again */
			verbatim_span(f, r0);
			if (f->full)
				return 0;
			memcpy(d_open, f->out + pstart, r0->open_len);
			memcpy(d_close, f->out + f->w - r0->close_len, r0->close_len);
			f->w -= r0->close_len;
			for (i = k + 1u; i < f->held.n; i++) {
				const struct kgenome_textual_span *p = &f->held.p[i].s;

				at = f->w;
				f->pend = 0;
				verbatim_span(f, p);
				if (f->full)
					return 0;
				/* the delimiters as WRITTEN are the same (php: "a" written 'a' is a single quoted literal like the rest) */
				if (f->w - at < p->open_len + p->close_len || memcmp(f->out + at, d_open, p->open_len) != 0 ||
				    memcmp(f->out + f->w - p->close_len, d_close, p->close_len) != 0 ||
				    !seam_ok(f->out + pstart + r0->open_len, at - pstart - r0->open_len,
					     f->w - at > p->open_len + p->close_len ? f->out[at + p->open_len] : 0)) {
					f->w = at;              /* this piece starts the next run; this run's literal is closed */
					memcpy(f->out + f->w, d_close, r0->close_len);
					f->w += r0->close_len;
					break;
				}
				memmove(f->out + at, f->out + at + p->open_len, f->w - at - p->open_len);
				f->w -= p->open_len;
				joined++;
				if (i + 1u < f->held.n)
					f->w -= p->close_len;
			}
			if (i == f->held.n) {
				if (k + 1u == f->held.n) {      /* a run of the last piece alone: its close was taken for the join */
					memcpy(f->out + f->w, d_close, r0->close_len);
					f->w += r0->close_len;
				}
				break;
			}
			k = i;
		}
		f->lit_end = 0;
		if (joined)
			f->n_folded++;
		f->pend = after;
		return 0;
	}
	replay_held(f);
	return 0;
}

/*
 * THE HELD LITERALS, once the byte after them is known. A payload when that byte closes the argument and the
 * caller's hook decodes what they hold; otherwise what they would be with no decoder at all. What is written for a
 * payload is the first literal with its VALUE replaced by the decoded text, quotes and all as they were typed - no escape
 * is added: what part of the view is decoded is the caller's to say, from the ranges it asks for - inside the calls that
 * were typed around it, which stay and are renamed (calls_back) - and only when the rest of the text still fits behind it.
 * Answers 0: `next` is never consumed here.
 */
static int resolve_held(struct kgenome_tform *f, uint8_t next)
{
	const struct kgenome_textual_span *s0 = &f->held.p[0].s;
	uint8_t after = f->pend;
	const uint8_t *dec = NULL, *val;
	uint32_t dl = 0, vl = 0, open = s0->open_len, close = s0->close_len;
	int ok;

	if (!f->held.n_chain)
		return fold_held(f, ends_expr(f, next));
	ok = next == ')' || next == ',';

	if (ok && !held_value(f, &val, &vl)) {
		ok = 0;
		f->n_refused++;
	}
	if (ok && f->lang->payload_ok && !f->lang->payload_ok(val, vl, f->held.chain, f->held.n_chain)) {
		ok = 0;
		f->n_refused++;
	}
	if (ok && vl && s0->len >= open + close) {
		f->held.on = 0;
		if (f->decode(f->decode_user, f->held.chain, f->held.n_chain, val, vl, &dec, &dl)) {
			uint64_t reserve = KGENOME_TEXTUAL_FORM_CAP(f->n - f->held.p[f->held.n - 1u].end);
			int64_t back = calls_back(f);
			uint64_t marks = back >= 0 ? (uint64_t)f->held.n_chain * (sizeof DECODED_MARK - 1u) : 0;

			if (f->w + marks + open + dl + close + reserve <= f->cap) {
				if (back >= 0)
					calls_rewrite(f, (uint32_t)back);
				f->pend = f->held.p[0].pend;
				settle(f, kgenome_tform_sp(f, s0)[0], 0);
				copy_bytes(f, kgenome_tform_sp(f, s0), open);
				if (dl) {
					memcpy(f->out + f->w, dec, dl);
					f->w += dl;
				}
				copy_bytes(f, kgenome_tform_sp(f, s0) + s0->len - close, close);
				f->lit_end = 0;
				f->formed = 1;
				f->n_decoded++;
				f->pend = after;
				return 0;
			}
		}
		f->held.on = 1;         /* refused or no room: written as typed, below */
		ok = 1;
	}
	if (ok)
		f->n_refused++;
	return fold_held(f, ends_expr(f, next));       /* refused: what it would have been with no decoder at all */
}

/* The held literals, as they were typed: what arrived next was not the end of their argument. */
static void flush_held(struct kgenome_tform *f)
{
	if (!f->held.on)
		return;
	if (f->held.after_op)
		replay_held(f);
	else
		fold_held(f, 1);        /* a block or the text ends the expression */
}

/*
 * A tag is the language's, not the program's, and is copied - except its line break, which is
 * one "\n" however the file ends its lines: "<?php\r\n", "<?php\r" and "<?php\n" are the same
 * tag. A lone carriage return has to go too, and not only the pair: left, the code line break
 * after it would make it a pair the next time the text is read, and the form would change.
 */
static void copy_tag(struct kgenome_tform *f, const struct kgenome_textual_span *s)
{
	uint32_t len = s->len;

	if (len && f->in[s->off + len - 1u] == '\n' && len >= 2u && f->in[s->off + len - 2u] == '\r') {
		copy(f, s->off, len - 2u);
		put(f, '\n');
	} else if (len && f->in[s->off + len - 1u] == '\r') {
		copy(f, s->off, len - 1u);
		put(f, '\n');
	} else {
		copy(f, s->off, len);
	}
}

/*
 * May the island that began at out[island - 1] go. Not when the markup in front of it ends where a tag could begin - "<", "<?", "<%", "<?ph", "<?php":
 * what is left joins what comes after, and `<?php<?php` (the first is markup, php wants a blank after it) with the island gone is `<?php`, which is a tag.
 */
static int island_goes(const struct kgenome_tform *f)
{
	uint32_t w = f->island - 1u, t = 0;

	while (t < 3u && w && kgenome_textual_ident(f->out[w - 1u])) {
		w--;
		t++;
	}
	if (w && (f->out[w - 1u] == '?' || f->out[w - 1u] == '%'))
		w--;
	return !(w && f->out[w - 1u] == '<');
}

/* A tag and markup are the language's, not the program's, and are copied. */
static void tag_span(struct kgenome_tform *f, const struct kgenome_textual_span *s)
{
	echo_close(f);
	f->echo_typed = 0;
	if (s->flags & KGENOME_TEXTUAL_F_CLOSE) {
		if (f->island && !f->formed && island_goes(f)) {
			/* An island with no code in it goes whole - its opening tag and this one. */
			f->w = f->island - 1u;
			f->island = 0;
			f->pend = 0;
			f->brace = 0;
			return;
		}
		/* A line break between the code and the tag that closes the block, unless there is one - or it would make a heredoc of what follows. */
		if (f->formed && f->w && f->out[f->w - 1u] != '\n' && f->open_end != f->w && !heredoc_opener_end(f))
			put(f, '\n');
		f->pend = 0;
		f->brace = 0;
		copy_tag(f, s);
		f->island = 0;
		f->formed = 0;
		return;
	}
	f->island = f->lang->islands ? f->w + 1u : 0u;
	f->formed = 0;
	f->pend = 0;
	f->brace = 0;
	copy_tag(f, s);
}

/*
 * The input position of the next byte that is not white space or a comment, from `i`: the three spellings of a comment the languages with a join have,
 * a continuation, and where the language ends a statement at a line break (python) the break itself. A wrong skip costs a replay (a join) or a
 * call that is not taken, and a join or a call with a comment in it is what hides one from a reader. The one gap rule: a literal's join and a
 * call's arguments both read it.
 *
 * THE COMMENTS ARE THE LEXER'S READERS (kgenome_textual_c_block_end, kgenome_textual_line_end), not a loop of this function's own. Two copies
 * differed in exactly two places, and both are the copy's: an UNCLOSED block comment came back past the end by one or two (`i += 2` after a loop
 * that had already reached the end; the shared reader answers the end), which every caller reads as "nothing follows" (they test i >= n), so the
 * answer is the same; and a line comment ran to the next LF, past a lone CR - a line break in python, javascript, vbscript and tcl - into the line
 * after it, where the lexer had ended the comment. That one is a difference in what a join or a call is found past (tests/lib/genome/textual_gap.c).
 */
uint32_t kgenome_tform_skip_gap(const struct kgenome_tform *f, uint32_t i)
{
	for (;;) {
		if (i < f->n && py_lines(f) && (f->in[i] == '\n' || f->in[i] == '\r'))
			break;          /* a line break ends a python statement: see held_step */
		if (i < f->n && kof_is_space_byte(f->in[i])) {
			i++;
		} else if (i + 1u < f->n && f->lang->continuation && f->in[i] == kgenome_textual_cont_byte(f->lang) &&
			   (f->in[i + 1u] == '\n' || f->in[i + 1u] == '\r')) {
			i += 2u;                /* a continuation: the next line is this one */
		} else if ((f->lang->gap_comments & KGENOME_TEXTUAL_GAP_BLOCK) && i + 1u < f->n && f->in[i] == '/' && f->in[i + 1u] == '*') {
			int closed;

			i = kgenome_textual_c_block_end(f->in, f->n, i, &closed);
		} else if (i < f->n && (((f->lang->gap_comments & KGENOME_TEXTUAL_GAP_HASH) && f->in[i] == '#') ||
					((f->lang->gap_comments & KGENOME_TEXTUAL_GAP_LINE) && i + 1u < f->n && f->in[i] == '/' && f->in[i + 1u] == '/'))) {
			i = kgenome_textual_line_end(f->in, f->n, i);
		} else {
			break;
		}
	}
	return i;
}

/*
 * Does a literal begin a join? Looked at in the input, past white space: the operator the language joins with, or - where
 * literals side by side are one - a quote or a prefix letter. A wrong yes costs a replay; a no is what most literals
 * get, so they are never held.
 */
static int fold_ahead(const struct kgenome_tform *f, const struct kgenome_textual_span *s, uint32_t after)
{
	uint32_t i;

	if (f->keep_joins || f->lang->nofold || (!f->lang->concat && !f->lang->concat_adjacent) || (s->flags & KGENOME_TEXTUAL_F_OPEN) ||
	    (s->flags & KGENOME_TEXTUAL_F_HERE))
		return 0;
	i = kgenome_tform_skip_gap(f, after);
	if (i < f->n && py_lines(f) && (f->in[i] == '\n' || f->in[i] == '\r'))
		return 0;
	if (i >= f->n)
		return 0;
	if (f->lang->concat && f->in[i] == f->lang->concat)
		return 1;
	return f->lang->concat_adjacent && (f->in[i] == '"' || f->in[i] == '\'' || kgenome_textual_ident(f->in[i]));
}

/* Does the output end inside what could be the opening of a tag: "<", "</", "<c", "<cfs" - up to a few letters after it. */
static int opener_end(const struct kgenome_tform *f)
{
	uint32_t w = f->w, t = 0;

	while (w && t < 4u && kgenome_textual_ident(f->out[w - 1u])) {
		w--;
		t++;
	}
	if (w && f->out[w - 1u] == '/')
		w--;
	return w && f->out[w - 1u] == '<';
}

/*
 * A LITERAL ARRIVES: the lexer's, or one the form made from a call. Joined to the ones held, or the first of a group that is
 * held (a join, or the payload of a decoder), or written. `after` is the input position after what it stands for - fold_ahead
 * reads the operator from there - and `from` where that text begins.
 */
static void string_piece(struct kgenome_tform *f, const struct kgenome_textual_span *s, uint32_t after, uint32_t from)
{
	if (f->held.on && !(s->flags & KGENOME_TEXTUAL_F_OPEN) && f->held.n < FORM_PIECES &&
	    (f->held.after_op ||
	     (f->lang->concat_adjacent && !(f->pend == 2u && py_lines(f))))) {
		/* a literal joined to the one held: after the operator, or side by side where the language joins those */
		uint32_t k = f->held.n++;

		f->held.p[k].s = *s;
		f->held.p[k].from = from;
		f->held.p[k].end = after;
		f->held.p[k].op = f->held.after_op;
		f->held.p[k].op_pend = f->held.op_pend;
		f->held.p[k].pend = f->pend;
		f->held.after_op = 0;
		f->pend = 0;
		f->tail_n = 0;
		return;
	}
	flush_held(f);
	if (!f->echo_depth && !(s->flags & (KGENOME_TEXTUAL_F_OPEN | KGENOME_TEXTUAL_F_HERE)))
		echo_open(f, kgenome_tform_sp(f, s)[0]);
	f->held.off = f->tail_n > FORM_TAIL ? f->tail_n - FORM_TAIL : 0;
	f->held.len = f->tail_n - f->held.off;
	f->held.n_chain = 0;
	f->held.fold = (uint8_t)fold_ahead(f, s, after);
	if ((f->decode && (f->lang->call_chain || f->lang->calls) && !(s->flags & KGENOME_TEXTUAL_F_OPEN) &&
	     (f->held.n_chain = kgenome_textual_lang_chain(f->lang, f->tail + f->held.off, f->held.len, f->held.chain,
							  KGENOME_TEXTUAL_CHAIN_MAX, &f->held.from)) != 0) ||
	    f->held.fold) {
		f->held.on = 1;
		f->held.after_op = 0;
		f->held.n = 1;
		f->held.p[0].s = *s;
		f->held.p[0].from = from;
		f->held.p[0].end = after;
		f->held.p[0].pend = f->pend;
		f->held.p[0].op_pend = 0;
		f->held.p[0].op = 0;
		f->pend = 0;
	} else {
		verbatim_span(f, s);
	}
	f->tail_n = 0;
}

/* The writer's entry points for the call stage (textual_form_call.c): the two static functions it needs, under the names the private header
 * gives them (kgenome_tform_skip_gap, its third, is not static and has no entry point of its own). */
void kgenome_tform_string_piece(struct kgenome_tform *f, const struct kgenome_textual_span *s, uint32_t after, uint32_t from)
{
	string_piece(f, s, after, from);
}

void kgenome_tform_code_token_byte(struct kgenome_tform *f, uint8_t c)
{
	code_token_byte(f, c);
}

static int form_sink(void *u, const struct kgenome_textual_span *s)
{
	struct kgenome_tform *f = u;

	/* a call is read through code and literals only; a tag, markup or a comment that does not end is not part of one */
	if (f->nframe && s->kind != KGENOME_TEXTUAL_CODE && s->kind != KGENOME_TEXTUAL_STRING &&
	    (s->kind != KGENOME_TEXTUAL_COMMENT || (s->flags & KGENOME_TEXTUAL_F_OPEN)))
		kgenome_tform_call_abort(f);
	switch (s->kind) {
	case KGENOME_TEXTUAL_CODE:
		if (f->fold_calls)
			code_span_calls(f, s);
		else
			code_span(f, s);
		break;
	case KGENOME_TEXTUAL_STRING:
		if (!f->nframe || !kgenome_tform_call_string(f, s))
			string_piece(f, s, s->off + s->len, s->off);
		break;
	case KGENOME_TEXTUAL_COMMENT:
		if (s->flags & KGENOME_TEXTUAL_F_OPEN ||
		    (s->off == 0 && f->lang->keep_hashbang && s->len >= 2u && f->in[0] == '#' && f->in[1] == '!')) {
			flush_held(f);
			verbatim_span(f, s);
			f->tail_n = 0;
			if (!(s->flags & KGENOME_TEXTUAL_F_OPEN)) {
				/* the interpreter's line is a line: what follows it is on the next line (powershell's `#!` CR `"` came out `#! "`, one line the next pass read as one comment), and
				 * where another CR follows the comment's own, the CRs the lexer left in it are the line's end and not its text (ruby's `#!` CR CR LF came out `#!` CR LF, the
				 * next pass `#!` LF). A CR before the LF that ends it is kept as typed (perl, lua: the form of a CRLF script is as it was): L22 of the lexer audit. */
				uint32_t after = s->off + s->len;

				if (after < f->n && f->in[after] == '\r')
					while (f->w && f->out[f->w - 1u] == '\r')
						f->w--;
				f->pend = 2u;
			}
		} else if (f->lang->comment_break && f->lang->comment_break(f->in + s->off, s->len)) {
			f->pend = 2u;           /* one that holds a line terminator is a line break (js) */
		} else if (!f->pend) {
			f->pend = 1u;           /* a comment is a gap */
		}
		break;
	case KGENOME_TEXTUAL_TAG:
		flush_held(f);
		tag_span(f, s);         /* before the tail is emptied: it is what echo_close reads a halt marker from */
		f->tail_n = 0;
		break;
	default:                                /* markup */
		flush_held(f);
		/* A bracket an echo opened is not closed here: the only markup that no tag came before is what follows a halt marker, which is data the
		 * program reads, and a byte written in front of it is a byte of it. */
		f->echo_depth = f->echo_typed = 0;
		f->tail_n = 0;
		/* Markup that follows an island nothing closed - what comes after a halt marker -
		 * ends it, and an island that held no code goes. */
		if (f->island && !f->formed && island_goes(f))
			f->w = f->island - 1u;
		f->island = 0;
		/* A comment that stood between two pieces of markup is gone, and where the two halves would be read as one
		 * token - "<c" and "fset", "<" and "%" - the row's glue keeps a gap in its place (else the form of that form
		 * is another text). Only at the end of what could be a tag's opening - text on either side of a comment is just
		 * text, and joining it changes nothing. */
		if (f->pend && f->w && s->len && f->lang->glue && opener_end(f) && f->lang->glue(f->out[f->w - 1u], f->in[s->off]))
			put(f, ' ');
		f->pend = 0;
		f->brace = 0;
		f->formed = 0;
		copy(f, s->off, s->len);
		break;
	}
	return !f->full;
}

enum kgenome_textual_status kgenome_textual_form(const struct kgenome_textual_form_req *rq,
						 struct kgenome_textual_form_res *res)
{
	const struct kgenome_textual_lang *lang = kgenome_textual_lang_find(rq->lang);
	struct kgenome_tform_piece pieces[FORM_PIECES];
	struct kgenome_tform_item items[KGENOME_TFORM_CALL_ITEMS];     /* not cleared: read only up to n_it */
	struct kgenome_tform f = { .held.p = pieces, .it = items, .lang = lang, .in = rq->in, .out = rq->out, .cap = rq->cap,
			  .cap0 = rq->cap, .decode = rq->decode, .decode_user = rq->decode_user, .n = rq->n,
			  .apply = rq->apply, .apply_user = rq->apply_user,
			  .fold_calls = lang && lang->fn_table && lang->value && lang->quote && rq->apply &&
					!(rq->flags & KGENOME_TEXTUAL_KEEP_JOINS) && rq->cap <= 0xffffffffu,
			  .keep_joins = (rq->flags & KGENOME_TEXTUAL_KEEP_JOINS) != 0,
			  .py = lang && lang->continuation && lang->universal_eol,
			  .track = lang && ((lang->continuation && lang->universal_eol) || lang->echo_call) };
	struct kgenome_textual_lex_req lq = { rq->in, rq->n, rq->lang, rq->flags, form_sink, &f };
	struct kgenome_textual_lex_res lr;
	enum kgenome_textual_status st;

	if (f.fold_calls)
		kgenome_tform_call_table(&f);
	res->n_out = res->n_open = res->n_decoded = res->n_refused = res->n_folded = res->n_calls = res->n_bound = 0;
	memset(res->n_fn, 0, sizeof res->n_fn);
	if (!lang)
		return KGENOME_TEXTUAL_NO_LANG;
	if (rq->cap < KGENOME_TEXTUAL_FORM_CAP(rq->n))
		return KGENOME_TEXTUAL_SMALL;
	st = kgenome_textual_lex(&lq, &lr);
	if (f.nframe)
		kgenome_tform_call_abort(&f);         /* the text ended inside a call */
	flush_held(&f);
	echo_close(&f);
	/* An island still open at the end of the text, with nothing in it, goes too. */
	if (f.island && !f.formed && island_goes(&f))
		f.w = f.island - 1u;
	if (f.brace == f.w && f.w >= 2u)
		brace_up(&f);
	/* python: a continuation with nothing after it - the line after the backslash was a comment, and the text
	 * ended - is a statement that ends there, and "\<nl>" at the end of a text would be an unfinished one. */
	if (f.joined && lang->universal_eol) {
		f.w = f.cont_w;
		f.pend = f.cont_pend;
		f.lit_end = f.cont_lit;
	}
	/* python: a one-line string that is not closed ends where its line does, so a text that ends on that line break
	 * keeps it - without it the string would end at the end of the text, where an f-string whose field is open reads
	 * differently (the form of `t"{={<nl>}:#<nl>` was not its own form). */
	if (lang->universal_eol && (f.lit_end & 2u) && f.pend == 2u && f.w)
		put(&f, '\n');
	if (f.full || st == KGENOME_TEXTUAL_REFUSED)
		return KGENOME_TEXTUAL_SMALL;
	res->n_out = f.w;
	res->n_open = lr.n_open;
	res->n_decoded = f.n_decoded;
	res->n_folded = f.n_folded;
	res->n_refused = f.n_refused;
	res->n_calls = f.n_calls;
	res->n_bound = lr.n_bound;
	memcpy(res->n_fn, f.n_fn, sizeof res->n_fn);
	return lr.n_open ? KGENOME_TEXTUAL_OPEN : KGENOME_TEXTUAL_OK;
}
