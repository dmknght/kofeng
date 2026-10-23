/*
 * tcl_lex.c - the tcl lexer: where a command's words are, and what is a string or a comment.
 *
 * Every rule is the twelve rules of tcl 8.6 (the manual page "Tcl"), checked one case each against the tclsh 8.6.16 of the
 * machine it was written on (tests/lib/genome/textual_tcl.c): the generated programs and every .tcl file of the machine have
 * the same bytecode (::tcl::unsupported::disassemble, which drops comments and the layout of a command) as their form.
 *
 * WHAT IS CODE AND WHAT IS A STRING. Tcl is mostly strings, and this lexer says so in the most literal way it can:
 *   - A BRACED WORD {...} is a STRING (delimiters counted, no escape, no INTERP). It is very often a script - the body of
 *     proc, if, while, foreach, eval - and it is NOT lexed as one. Reason: the body is a script only to the command that
 *     takes it; "{...}" is the same bytes for `set x {a b}` and for `if 1 {puts a}`, and nothing in the text says which. A
 *     reader that wants the body as code lexes the bytes between the braces again with this lexer (a script starts where it
 *     starts); a marker that wants the text sees it in one span. The price is stated: a "#" comment inside a body is part of
 *     the string, the form does not remove it, and a "$x" in it is not seen.
 *   - A DOUBLE-QUOTED WORD "..." is a STRING (INTERP) - unless it holds a "[": then it is a STRING without INTERP, because
 *     the command in the brackets is code, where a backslash is read the way a bare word reads it and a brace word has none.
 *     The command is found to the matching "]" (it has strings of its own, quotes among them) and stays in the one span.
 *   - EVERYTHING ELSE IS CODE: command names, bare words, "$var", "${var}", "$a(index)", ";", blanks - and the code of a
 *     "[command]" in a BARE word, which is lexed to its own end (its own braced and quoted words are STRING spans) as a nested
 *     script, to a depth of TCL_DEPTH. A "$" does not begin a string.
 *   - A COMMENT is "#" where a command can begin - the start of a script, after a ";" or a line break, after a "[", after a
 *     continuation that was at a command's start - to the end of the line; a backslash and the byte after it are a pair in it, so
 *     "\<line break>" continues the comment on the next line, and a backslash, a backslash, a line break does not. "#" anywhere
 *     else is a letter of a word ("puts a # b" has four words; after "\<line break>" in the middle of a command it is a word too).
 *     A comment inside a bracket runs to the line break, a "]" in it included. A "#!" line at byte 0 is one, kept by the form.
 *
 * THE BYTES THAT END A WORD: a space, tab, VT or FF; a line break; ";"; a "\<line break>" (outside braces and quotes it is a
 * gap); inside "[...]" a "]" too. A quote or a brace in the middle of a bare word is a letter ("a{b c}" is two words); after the
 * closing quote or brace of a word that is not followed by a gap tcl says "extra characters": the word goes on here as a bare
 * one, so that the text is read the one way. LINE BREAKS: "\n", "\r\n" and a lone "\r" are one each (a file read by `source`).
 *
 * "$": "${...}" to the first "}" (no nesting; blanks, quotes and brackets in it are the name's) is a STRING with "${" and "}" as its
 * delimiters; "$name" with letters, digits, "_" and "::" (a run of colons) is code; "$name(" opens an index that runs to ")"
 * with a backslash and the byte after it as a pair, "$" and "[...]" in it, and anything else - blanks and line breaks
 * included - being the index's: "$a(b c)" is one word, and the index is a STRING with "(" and ")" as its delimiters (INTERP
 * unless a "[" is in it), because its blanks are part of the key and a form must keep them. No ")" before the end of the text
 * is tcl's "missing )": the span is open to the end, as an unclosed quote is. A "{" after "$" with no "}" after it is a letter. A "$"
 * that is followed by none of these is a letter.
 *
 * BOUNDED: "[" and "(" nest as deep as TCL_DEPTH and no deeper; past it the rest of the text is one OPEN string - a quoted word
 * from its quote, a bracket from its "[" - so that no text chooses how much stack a scan takes. Each byte is looked at once:
 * the one search that looks ahead (the "}" of "${") knows from one pass over the text whether there is one at all.
 *
 * NOT DECODED: tcl's strings are characters, the lexer reads bytes; a byte of 0x80 or more is an ordinary byte of a word. NUL is one too.
 */

#include "tcl.h"

#define TCL_DEPTH 64u

struct tcl {
	struct kgenome_textual_lexer *lx;
	const uint8_t *p;
	uint32_t       n;
	uint32_t       rbrace;          /* one past the last "}" of the text, 0 when there is none */
	uint32_t       brackets;        /* "[" met so far, at any depth: a quoted word that met one has code in it */
	uint8_t        over;            /* a nesting past TCL_DEPTH: everything unwinds, the caller delivers the rest */
	uint8_t        stop;            /* the sink refused */
};

static uint32_t tcl_script(struct tcl *t, uint32_t i, uint32_t depth, int nested, int emit);
static uint32_t tcl_var(struct tcl *t, uint32_t i, uint32_t depth, int emit);

static int tcl_dead(const struct tcl *t)
{
	return t->over || t->stop;
}

static int tcl_name(uint8_t c)
{
	return kof_is_digit(c) || kof_is_alpha(c) || c == '_';
}

/* A backslash at `j` followed by a line break: the length of both, else 0. */
static uint32_t tcl_cont(const struct tcl *t, uint32_t j)
{
	uint32_t nl = kgenome_textual_eol_at(t->p, t->n, j + 1u);

	return nl ? 1u + nl : 0u;
}

/* Past a backslash at `j` and the byte it escapes; a line break is one byte for this, "\r\n" included. */
static uint32_t tcl_pair(const struct tcl *t, uint32_t j)
{
	uint32_t c = tcl_cont(t, j);

	if (j + 1u >= t->n)
		return t->n;
	return j + (c ? c : 2u);
}

/* The code up to `at` and then [at, e) as `kind`: what a span needs. */
static void tcl_span(struct tcl *t, uint32_t at, uint32_t e, uint8_t kind, uint8_t flags, uint32_t open, uint32_t close)
{
	if (!kgenome_textual_span_at(t->lx, at, e, kind, flags, open, close))
		t->stop = 1;
}

/* The code up to `at`, and the nesting is past the bound. */
static uint32_t tcl_overflow(struct tcl *t, uint32_t at, int emit)
{
	if (emit && !kgenome_textual_code_to(t->lx, at))
		t->stop = 1;
	t->over = 1;
	return t->n;
}

/* The comment whose "#" is at `i`: to the line break, a backslash and the byte after it being a pair. */
static uint32_t tcl_comment(struct tcl *t, uint32_t i, int emit)
{
	uint32_t j = i + 1u;

	while (j < t->n && !kgenome_textual_eol_byte(t->p[j]))
		j = t->p[j] == '\\' ? tcl_pair(t, j) : j + 1u;
	if (emit)
		tcl_span(t, i, j, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0);
	return j;
}

/* Past the "[...]" whose bracket is at `i`: its script, and the "]" if there is one. */
static uint32_t tcl_bracket(struct tcl *t, uint32_t i, uint32_t depth, int emit)
{
	uint32_t j;

	t->brackets++;
	if (depth >= TCL_DEPTH)
		return tcl_overflow(t, i, emit);
	j = tcl_script(t, i + 1u, depth + 1u, 1, emit);
	if (tcl_dead(t))
		return t->n;
	return j < t->n && t->p[j] == ']' ? j + 1u : j;
}

/*
 * A double-quoted word or the index of "$name(", whose opener is at `at`, as a STRING from the opener to the byte `close` that ends it. A
 * backslash and the byte after it are a pair, "$" and "[" begin substitutions (read to their ends at `inner` levels, and not delivered),
 * anything else is the text. INTERP unless a "[" was in it, because the command in the brackets is code; open when `close` never came
 * (tcl's "missing )" and an unclosed quote alike). Its end.
 */
static uint32_t tcl_enclosed(struct tcl *t, uint32_t at, uint8_t close, uint32_t inner, int emit)
{
	const uint8_t *p = t->p;
	uint32_t k = at + 1u, closed = 0, cmd = t->brackets;

	if (emit && !kgenome_textual_code_to(t->lx, at))
		t->stop = 1;
	while (k < t->n && !tcl_dead(t) && !closed) {
		uint8_t c = p[k];

		if (c == close) {
			closed = 1;
			k++;
		} else if (c == '\\') {
			k = tcl_pair(t, k);
		} else if (c == '$') {
			k = tcl_var(t, k, inner, 0);
		} else if (c == '[') {
			k = tcl_bracket(t, k, inner, 0);
		} else {
			k++;
		}
	}
	if (tcl_dead(t))
		return t->n;
	if (emit)
		tcl_span(t, at, k, KGENOME_TEXTUAL_STRING,
			 (uint8_t)((cmd != t->brackets ? 0u : KGENOME_TEXTUAL_F_INTERP) | (closed ? 0u : KGENOME_TEXTUAL_F_OPEN)), 1u, closed ? 1u : 0u);
	return k;
}

/*
 * The index of "$name(" whose "(" is at `j`: what is in it is the index's TEXT - "$a(b  c)" is the key "b  c", and a form that closed up
 * the blanks would read another array - with substitutions in it, like a double-quoted word (tcl_enclosed).
 */
static uint32_t tcl_index(struct tcl *t, uint32_t j, uint32_t depth, int emit)
{
	if (depth >= TCL_DEPTH)
		return tcl_overflow(t, j, emit);
	return tcl_enclosed(t, j, ')', depth + 1u, emit);
}

/*
 * Past the substitution that begins at the "$" at `i`: the "$" alone when nothing that is a name follows. "${name}" is a STRING
 * (open "${", close "}"): the name is the bytes between, blanks and quotes and brackets in it too, and a form must not touch them.
 */
static uint32_t tcl_var(struct tcl *t, uint32_t i, uint32_t depth, int emit)
{
	const uint8_t *p = t->p;
	uint32_t n = t->n, j = i + 1u;

	if (j < n && p[j] == '{') {
		const uint8_t *e = t->rbrace > j + 1u ? memchr(p + j + 1u, '}', n - j - 1u) : NULL;

		if (!e)
			return j;
		j = (uint32_t)(e - p) + 1u;
		if (emit)
			tcl_span(t, i, j, KGENOME_TEXTUAL_STRING, 0, 2u, 1u);
		return j;
	}
	while (j < n) {
		if (tcl_name(p[j]))
			j++;
		else if (p[j] == ':' && j + 1u < n && p[j + 1u] == ':')
			while (j < n && p[j] == ':')
				j++;
		else
			break;
	}
	return j < n && p[j] == '(' ? tcl_index(t, j, depth, emit) : j;
}

/* Past the bare word that starts at `j`; `nested` is a "]" ends it. */
static uint32_t tcl_bare(struct tcl *t, uint32_t j, uint32_t depth, int nested, int emit)
{
	const uint8_t *p = t->p;

	while (j < t->n && !tcl_dead(t)) {
		uint8_t c = p[j];

		if (kgenome_textual_hblank(c) || kgenome_textual_eol_byte(c) || c == ';' || (nested && c == ']') || (c == '\\' && tcl_cont(t, j)))
			break;
		if (c == '\\')
			j = tcl_pair(t, j);
		else if (c == '$')
			j = tcl_var(t, j, depth, emit);
		else if (c == '[')
			j = tcl_bracket(t, j, depth, emit);
		else
			j++;
	}
	return j;
}

/* The braced word whose brace is at `i`: to the matching brace, "\{" and "\}" not counted. */
static uint32_t tcl_braced(struct tcl *t, uint32_t i, int emit)
{
	const uint8_t *p = t->p;
	uint32_t j = i + 1u, nest = 1u, closed = 0;

	while (j < t->n && !closed) {
		uint8_t c = p[j];

		if (c == '\\') {
			j = tcl_pair(t, j);
			continue;
		}
		if (c == '{')
			nest++;
		else if (c == '}')
			closed = --nest == 0;
		j++;
	}
	if (emit)
		tcl_span(t, i, j, KGENOME_TEXTUAL_STRING, closed ? 0u : KGENOME_TEXTUAL_F_OPEN, 1u, closed ? 1u : 0u);
	return j;
}

/* The word at `i`, which is not a gap, a line break, a ";" or (nested) a "]". */
static uint32_t tcl_word(struct tcl *t, uint32_t i, uint32_t depth, int nested, int emit)
{
	uint8_t c = t->p[i];
	uint32_t j;

	if (c == '"')
		j = tcl_enclosed(t, i, '"', depth, emit);
	else if (c == '{')
		j = tcl_braced(t, i, emit);
	else
		return tcl_bare(t, i, depth, nested, emit);
	/* anything but a gap after the closer is tcl's error "extra characters": read on as one word */
	return tcl_dead(t) ? t->n : tcl_bare(t, j, depth, nested, emit);
}

/* The words of one command from `i`, to the byte that ends it (a line break, ";", or a "]" when nested), or `n`. */
static uint32_t tcl_command(struct tcl *t, uint32_t i, uint32_t depth, int nested, int emit)
{
	const uint8_t *p = t->p;
	uint32_t k;

	while (i < t->n && !tcl_dead(t)) {
		uint8_t c = p[i];

		if (kgenome_textual_hblank(c))
			i++;
		else if (c == '\\' && (k = tcl_cont(t, i)) != 0)
			i += k;
		else if (kgenome_textual_eol_byte(c) || c == ';' || (nested && c == ']'))
			return i;
		else
			i = tcl_word(t, i, depth, nested, emit);
	}
	return i;
}

/* The commands of a script from `i`; nested, to the "]" that ends it (not consumed) or `n`. */
static uint32_t tcl_script(struct tcl *t, uint32_t i, uint32_t depth, int nested, int emit)
{
	const uint8_t *p = t->p;
	uint32_t k;

	while (i < t->n && !tcl_dead(t)) {
		uint8_t c = p[i];

		if (kgenome_textual_hblank(c) || kgenome_textual_eol_byte(c) || c == ';')
			i++;
		else if (c == '\\' && (k = tcl_cont(t, i)) != 0)
			i += k;
		else if (nested && c == ']')
			return i;
		else if (c == '#')
			i = tcl_comment(t, i, emit);
		else
			i = tcl_command(t, i, depth, nested, emit);
	}
	return i;
}

void kgenome_textual_tcl_lex(struct kgenome_textual_lexer *lx)
{
	struct tcl t = { .lx = lx, .p = lx->p, .n = lx->n };
	uint32_t k;

	for (k = t.n; k && !t.rbrace; k--)
		t.rbrace = t.p[k - 1u] == '}' ? k : 0u;
	(void)tcl_script(&t, 0, 0, 0, 1);
	if (t.over && !t.stop)
		tcl_span(&t, lx->pos, t.n, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_OPEN, 1u, 0);
	else if (!t.stop)
		(void)kgenome_textual_code_to(lx, t.n);
}
