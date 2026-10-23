/*
 * sh_lex.c - the posix shell lexer: where code is, and what is a string, a comment or a here-document.
 *
 * WHAT IT DECIDES: the quotes - '...' (nothing inside is anything), "..." (a backslash, and $(...),
 * ${...} and `...` inside it, which may hold quotes of their own), $'...' - the comments, and the
 * bodies of here-documents. Everything else is code, and a command substitution at the top level is
 * lexed as the code it is, so its quotes and comments are found like any others.
 *
 * A LINE ENDS AT "\n" AND AT NOTHING ELSE: a carriage return is a blank, so a CRLF file reads the same as an LF one and a lone one is not a line break to a comment or to the line that names the interpreter.
 *
 * A "#" IS A COMMENT ONLY WHERE A WORD BEGINS: "echo a#b" is the word a#b, "echo $#" is a parameter,
 * "echo a;#b" is a comment. A "#" after a backslash-escaped blank is still inside its word.
 *
 * A HERE-DOCUMENT'S BODY BEGINS ON THE NEXT LINE, not where its operator is: the rest of the operator's
 * line is still code, and several operators on one line queue their bodies in order. "<<<" is a
 * here-string, a word, and not one. Arithmetic - "$((1<<n))" - is skipped as one piece, so a shift is
 * never read as an operator that swallows the rest of the file.
 *
 * Quoting that nests - "$(...)" in a double quoted string - is found by one function that calls itself
 * for each level, bounded at SH_DEPTH: what a file chooses must not choose how much stack a scan takes.
 * Past it the string is open to the end of the file, delivered as such.
 *
 * THE WORK OF "((" THAT DO NOT CLOSE IS BOUNDED BY THE TEXT. An arithmetic "((" that does not close was found out by walking to the end of the text, and the byte after it
 * was asked again, and the one after that: a text of n "(" cost n^2/2 steps (L3 of the lexer audit). The steps the failed groups of ONE lex walk are charged to one allowance
 * of the text's length (and a page): a file whose unclosed "((" cost that much has read every byte of itself once for them, and the later "((" are read as code, as the failed
 * ones were. Nothing is deleted: a failed group is code in this lexer, its strings and comments are found by the main loop whatever it did; what can differ, in a text the
 * shell itself refuses to run, is a "<<" inside a later balanced "((...))", read as a here-document operator once the allowance is spent.
 */

#include <string.h>

#include "sh.h"

#define SH_DEPTH KGENOME_TEXTUAL_SH_DEPTH        /* the same bound as the word reader's (sh_cmd.c): one spelling */
#define SH_HEREDOCS 8u              /* operators waiting for their line, at once */

/* Past the single quoted string that starts at `j`: nothing inside is special. 0 when it does not close. */
static uint32_t skip_sq(const uint8_t *p, uint32_t n, uint32_t j)
{
	const uint8_t *e = memchr(p + j + 1u, '\'', n - j - 1u);

	return e ? (uint32_t)(e - p) + 1u : 0;
}

static uint32_t dq_end(const uint8_t *p, uint32_t n, uint32_t j, uint32_t depth);
static int word_start(const uint8_t *p, uint32_t i);

/*
 * Past the group that opens at `j` with `open` and closes with `close`, counting the same bracket
 * inside it and stepping over a quote or a backslash as a unit. 0 when it does not close or the
 * nesting is past the bound.
 */
static uint32_t skip_group(const uint8_t *p, uint32_t n, uint32_t j, uint8_t open, uint8_t close,
			   uint32_t depth, uint64_t *spent)
{
	uint32_t level = 0, from = j, at;

	if (depth > SH_DEPTH)
		return 0;
	while (j < n) {
		uint8_t c = p[j];

		if (c == '\\') {
			j += 2u;
			continue;
		}
		if (c == '\'' || c == '"' || c == '`') {
			at = j;
			j = c == '\'' ? skip_sq(p, n, j) : c == '"' ? dq_end(p, n, j + 1u, depth + 1u) : kgenome_textual_skip_quoted(p, n, j);
			if (!j) {
				if (spent)
					*spent += (uint64_t)(at - from);
				return 0;
			}
			continue;
		}
		/* a comment in a command: the quotes and brackets in it are text */
		if (c == '#' && open == '(' && word_start(p, j)) {
			while (j < n && p[j] != '\n')
				j++;
			continue;
		}
		if (c == open)
			level++;
		else if (c == close && --level == 0)
			return j + 1u;
		j++;
	}
	if (spent)
		*spent += (uint64_t)(n - from);
	return 0;
}

/* Past the double quoted string whose opening quote is before `j`. 0 when it does not close. */
static uint32_t dq_end(const uint8_t *p, uint32_t n, uint32_t j, uint32_t depth)
{
	if (depth > SH_DEPTH)
		return 0;
	while (j < n) {
		uint8_t c = p[j];

		if (c == '\\') {
			j += 2u;
			continue;
		}
		if (c == '"')
			return j + 1u;
		if (c == '$' && j + 1u < n && (p[j + 1u] == '(' || p[j + 1u] == '{')) {
			j = skip_group(p, n, j + 1u, p[j + 1u], p[j + 1u] == '(' ? ')' : '}', depth + 1u, NULL);
			if (!j)
				return 0;
			continue;
		}
		if (c == '`') {
			j = kgenome_textual_skip_quoted(p, n, j);
			if (!j)
				return 0;
			continue;
		}
		j++;
	}
	return 0;
}

/* Is the byte at `e` escaped: an odd number of backslashes end just before it. */
static int escaped(const uint8_t *p, uint32_t e)
{
	uint32_t run = 0;

	while (e > run && p[e - run - 1u] == '\\')
		run++;
	return run & 1u;
}

/*
 * May a "#" at `i` begin a comment: at the start of a word, and not behind an escaped blank. A line
 * break counts as the start of one even when a backslash escapes it: a comment cannot be continued
 * onto the next line, so "# c \<newline># d" is two comments, and what the shell makes of
 * "a\<newline>#b" - the one word a#b - is a line that begins with a "#" here, read as a comment.
 */
static int word_start(const uint8_t *p, uint32_t i)
{
	uint8_t c;

	if (i == 0)
		return 1;
	c = p[i - 1u];
	if (c == '\n')
		return 1;
	if (!(c == ' ' || c == '\t' || c == '\r' || c == ';' || c == '&' || c == '|' || c == '(' ||
	      c == ')' || c == '<' || c == '>'))
		return 0;
	return !escaped(p, i - 1u);
}

static int meta(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ';' || c == '&' || c == '|' ||
	       c == '<' || c == '>' || c == '(' || c == ')';
}

struct heredoc {
	uint32_t off, len;      /* the delimiter, in the text */
	uint8_t  strip;         /* "<<-": leading tabs of the closing line do not count */
	uint8_t  quoted;        /* a quoted or escaped delimiter: the body does not expand */
};

/*
 * "<<" or "<<-" and a delimiter word, at `i`. On success the operator is queued and the answer is
 * where the delimiter ends; 0 when it is not a here-document - a here-string, a delimiter that
 * is not a word, a full queue - and the caller reads "<<" as code.
 */
static uint32_t heredoc_op(const uint8_t *p, uint32_t n, uint32_t i, struct heredoc *q, uint32_t *nq)
{
	uint32_t j = i + 2u, s, e;
	uint8_t strip = 0, quoted = 0;

	if (*nq >= SH_HEREDOCS || (j < n && p[j] == '<'))
		return 0;
	if (j < n && p[j] == '-') {
		strip = 1;
		j++;
	}
	while (j < n && kgenome_textual_blank_in(p[j], kgenome_textual_lang_sh.word_vt_ff))      /* the shell's blanks, as the form reads them (VT and FF are word bytes): the row's flag, the one rule */
		j++;
	if (j >= n)
		return 0;
	if (p[j] == '\'' || p[j] == '"') {
		const uint8_t *c = memchr(p + j + 1u, p[j], n - j - 1u);

		if (!c)
			return 0;
		s = j + 1u;
		e = (uint32_t)(c - p);
		j = e + 1u;
		quoted = 1;
	} else {
		if (p[j] == '\\') {
			quoted = 1;
			j++;
		}
		s = j;
		while (j < n && !meta(p[j]))
			j++;
		e = j;
	}
	if (e == s)
		return 0;
	q[*nq].off = s;
	q[*nq].len = e - s;
	q[*nq].strip = strip;
	q[*nq].quoted = quoted;
	(*nq)++;
	return j;
}

/*
 * The bodies of the queued here-documents, one after another from `i` (the first byte of the line
 * after the operators'). Each is a string running through its delimiter's line; one that is not closed
 * runs to the end and is open. Answers where the last one ends, and 0 when the sink stopped.
 */
static uint32_t heredoc_bodies(struct kgenome_textual_lexer *lx, uint32_t i, const struct heredoc *q, uint32_t nq)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, k;

	for (k = 0; k < nq; k++) {
		uint32_t ls, end = n, close = 0;
		uint8_t fl = KGENOME_TEXTUAL_F_HERE | (q[k].quoted ? 0u : KGENOME_TEXTUAL_F_INTERP);
		int open = 1;

		/* The next body begins after the break that ends the last delimiter's line. */
		if (k && i < n && p[i] == '\n')
			i++;
		ls = i;
		while (ls < n) {
			const uint8_t *nl = memchr(p + ls, '\n', n - ls);
			uint32_t le = nl ? (uint32_t)(nl - p) : n, a = ls, b = le;

			if (q[k].strip)
				while (a < b && p[a] == '\t')
					a++;
			if (b > a && p[b - 1u] == '\r')
				b--;
			if (b - a == q[k].len && memcmp(p + a, p + q[k].off, q[k].len) == 0) {
				end = le;
				close = le - ls;
				open = 0;
				break;
			}
			if (!nl)
				break;
			ls = le + 1u;
		}
		if (!kgenome_textual_lit(lx, i, end, KGENOME_TEXTUAL_STRING, fl, 0, close, !open))
			return 0;
		i = end;
	}
	return i;
}

void kgenome_textual_sh_lex(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = 0, nq = 0;
	struct heredoc q[SH_HEREDOCS];
	uint64_t spent = 0, allowance = (uint64_t)n + 65536u;   /* the steps of "((" that did not close, and what they may cost (see the head of the file) */
	int bound = 0;

	/* The line that names the interpreter is the language's, not a comment to be dropped. */
	if (n >= 2u && p[0] == '#' && p[1] == '!') {
		while (i < n && p[i] != '\n')
			i++;
		/* its carriage return, in a CRLF file, is white space after it and not part of the line */
		while (i > 2u && p[i - 1u] == '\r')
			i--;
		if (!kgenome_textual_emit(lx, i, KGENOME_TEXTUAL_TAG, 0, 0, 0))
			return;
	}
	while (i < n) {
		uint8_t c = p[i];
		uint32_t j;
		int ok = 1;

		if (c == '\n') {
			i++;
			if (nq) {
				i = heredoc_bodies(lx, i, q, nq);
				nq = 0;
				if (!i)
					return;
			}
		} else if (c == '\\') {
			i += 2u;
		} else if (c == '#' && word_start(p, i)) {
			j = i;
			while (j < n && p[j] != '\n')
				j++;
			ok = kgenome_textual_span_at(lx, i, j, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0);
			i = j;
		} else if (c == '\'' || c == '"' || c == '`' || (c == '$' && i + 1u < n && (p[i + 1u] == '\'' || p[i + 1u] == '"'))) {
			uint32_t at = i, open = 1u;
			uint8_t fl = 0;

			if (c == '$') {
				open = 2u;
				c = p[i + 1u];
				i++;
			}
			if (c == '\'' && open == 1u)
				j = skip_sq(p, n, i);
			else if (c == '\'')
				j = kgenome_textual_skip_quoted(p, n, i);           /* $'...': escapes */
			else if (c == '"') {
				j = dq_end(p, n, i + 1u, 0);
				fl = KGENOME_TEXTUAL_F_INTERP;
			} else {
				j = kgenome_textual_skip_quoted(p, n, i);           /* `...`: a command, expanded */
				fl = KGENOME_TEXTUAL_F_INTERP;
			}
			i = j ? j : n;
			ok = kgenome_textual_lit(lx, at, i, KGENOME_TEXTUAL_STRING, fl, open, 1u, j != 0);
		} else if (c == '<' && i + 1u < n && p[i + 1u] == '<') {
			j = heredoc_op(p, n, i, q, &nq);
			i = j ? j : i + 2u;
		} else if (c == '(' && i + 1u < n && p[i + 1u] == '(') {
			/* arithmetic: one piece, so a shift in it is not an operator and a quote in it is found */
			if (spent <= allowance) {
				j = skip_group(p, n, i, '(', ')', 0, &spent);
				i = j ? j : i + 1u;
			} else {
				bound = 1;              /* the failed groups have cost what they may: this one is code, and the walk says so */
				i++;
			}
		} else {
			i++;
		}
		if (!ok)
			return;
	}
	lx->n_bound += (uint32_t)bound;
	kgenome_textual_code_to(lx, n);
}
