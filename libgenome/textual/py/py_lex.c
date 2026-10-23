/*
 * py_lex.c - the python lexer: where code is, and what is a string or a comment.
 *
 * Every rule below was read off the interpreter's own tokenizer (python 3.13, `tokenize`) and is pinned by a
 * known answer in tests/lib/genome/textual_py.c, which also generates programs and checks the lexer against what
 * the generator wrote. The lexer was compared with `tokenize` on the standard library and on every .py file of the
 * machine it was written on; where it differs on purpose it says so below ("ur").
 *
 * LINE ENDINGS. "\n", "\r\n" and a lone "\r" all end a line, as in the interpreter (it translates them before
 * it tokenizes): a comment and an unclosed one-line string stop before the break, and a backslash escapes
 * "\r\n" as ONE break, so a CRLF file does not end a string that a backslash continued.
 *
 * COMMENTS. "#" outside a string runs to the end of the line.
 * A BACKSLASH OUTSIDE A STRING AND THE BYTE AFTER IT ARE ONE THING, a line break (the continuation) or not:
 * the interpreter stops at a backslash that is followed by anything else ("unexpected character after line
 * continuation"), so there is no program to read there, and what is read instead is what the form reads - the
 * same pairing as the form's - so that closing up the comment in "\\ # c" cannot turn a stray backslash into a
 * continuation (found by mutating generated programs: the form of "t'{'\\#<nl>" was not its own form when "\\#" was a
 * backslash and a comment). It also means a quote after a stray backslash does not begin a string.
 *
 * STRINGS. ' and " and the triple forms of both. A prefix is a name directly in front of the quote and is
 * part of the string - b'x' is one token - but only a prefix the language has: r u b f t alone, rb br rf fr
 * rt tr in any case and either order, and ur (python 2 only; python 3 reads "ur" as a name followed by a
 * string, and this lexer does not, because the code it is for - old malware - is python 2). "bu", "uu" and
 * "print" in front of a quote are a name and a string, as in the interpreter. "t" is the template string of
 * 3.14 (PEP 750), which is lexed as an f-string: [Unverified here - 3.13 has no such prefix, so it is taken
 * from the PEP and tested only by a known answer].
 * A backslash escapes the next byte, a line break included, in a raw string as in any other: r"\"" is the
 * string \". A one-line string that is not closed ends at its line; a triple one runs to the end.
 *
 * F-STRINGS, THE WAY 3.12 READS THEM (PEP 701): the text is a literal part with fields in it, and a field
 * "{ expression [=] [!conversion] [:spec] }" is real code, with strings of its own - of any quote, the
 * f-string's own included - comments, line breaks, and fields in its spec. So the end of an f-string is found
 * by a small machine with an explicit stack (frames): LIT is a literal part, EXPR the code of a field, SPEC the
 * text after its ":".
 *   - LIT: "{{" and "}}" are the two bytes themselves; "{" opens a field; a lone "}" is an error and a plain
 *     byte here. A backslash escapes the next byte EXCEPT a brace: f"\{x}" is a backslash and a field, raw
 *     or not. "\N{name}" is one unit in a non-raw string (the name is looked for within PY_NAME_MAX bytes;
 *     CPython's own bound is the same order, [Unverified]) and "\N" then a field in a raw one.
 *   - EXPR: strings (with a prefix, and an f-string pushes frames), "#" comments to the end of the line,
 *     brackets counted, ":" at depth 0 begins the spec (f"{x:=5}" is the spec "=5"; a walrus or a lambda
 *     needs parentheses, as the interpreter requires), "}" at depth 0 ends the field.
 *   - SPEC: like LIT, but "}" ends the field and "{" always opens a nested one (f"{x:{{}}}" holds a field
 *     that is the expression "{}", read off the interpreter).
 * The stack holds PY_FSTR_LEVELS f-strings at most, the interpreter's own limit (MAXFSTRINGLEVEL, 150,
 * [Unverified: from memory of CPython's source]); a string nested deeper than that is lexed as a plain one,
 * which no program that compiles reaches.
 * AN F-STRING WHOSE FIELD NEVER CLOSES is not a program (a truncated file, a stray "f'{"), and is read as far
 * as the scan went: to the end of the text when the field was still open there, or to where a string inside
 * it was not closed ("f\"{x\"<nl>" - the interpreter refuses that too), and it is flagged OPEN, like a triple
 * string that runs to the end. Every byte the scan read is in that span, so nothing is read twice (the work
 * is linear by construction - a text of "f'{<nl>" repeated, or of "f\'\'\'{(<nl>", is in the test) and what
 * follows is lexed from where the scan stopped, not from the "{" it began at. That is also what keeps the form
 * of a form its own: a flat rescan from the "{" lexed the bytes after it as code and comments, which the
 * form then closed up or dropped, and the next lex of the result scanned those bytes as part of a field
 * (found by mutating generated programs and asking that the form of a form be itself).
 *
 * NUMBERS ARE NOT LEXED: a digit is skipped like any code byte. A number followed by a name ("1if x else 2",
 * "0x1for y") is a number and a keyword, and no keyword is a string prefix, so no byte of a string can be
 * taken for a number's. What the interpreter calls an error ("1f'x'") is not code.
 *
 * Not decoded: a file in another encoding (UTF-16, a BOM) is read as bytes: a byte of 0x80 or more is a name
 * byte, as it is for the interpreter whatever the encoding declaration says.
 */

#include "py.h"

#define PY_FSTR_LEVELS 150u             /* MAXFSTRINGLEVEL */
#define PY_FRAMES (3u * PY_FSTR_LEVELS) /* an f-string, a field and a spec each */
#define PY_NAME_MAX 256u

/* What the prefix says. */
#define PY_P_RAW 0x1u
#define PY_P_FMT 0x2u           /* f or t: fields */
#define PY_P_STR 0x4u           /* a legal prefix, with a quote after it */

enum py_mode { PY_LIT, PY_EXPR, PY_SPEC };

struct py_frame {
	uint32_t nest;          /* EXPR: brackets open */
	uint8_t  mode, quote, triple, raw;
};

static int py_quote(uint8_t c)
{
	return c == '"' || c == '\'';
}

/* Is there a triple quote at `j`. */
static int py_triple_at(const uint8_t *p, uint32_t n, uint32_t j)
{
	return j + 2u < n && p[j + 1u] == p[j] && p[j + 2u] == p[j];
}

/*
 * The prefix [s, e) of a string, as flags; 0 when it is not one. Letters are ASCII only: a name byte of 0x80
 * or more is never part of a prefix. The ones that are: r u b f t alone; rb br rf fr rt tr; and ur.
 */
static uint32_t py_prefix(const uint8_t *p, uint32_t s, uint32_t e)
{
	uint8_t a, b = 0;

	if (e - s > 2u)
		return 0;
	a = (uint8_t)(p[s] | 0x20u);
	if (e - s == 2u)
		b = (uint8_t)(p[s + 1u] | 0x20u);
	if (!b) {
		if (a == 'r')
			return PY_P_STR | PY_P_RAW;
		if (a == 'f' || a == 't')
			return PY_P_STR | PY_P_FMT;
		return a == 'u' || a == 'b' ? PY_P_STR : 0u;
	}
	if ((a == 'r' && (b == 'b' || b == 'f' || b == 't')) ||
	    (b == 'r' && (a == 'b' || a == 'f' || a == 't' || a == 'u')))
		return PY_P_STR | PY_P_RAW | (a == 'f' || a == 't' || b == 'f' || b == 't' ? PY_P_FMT : 0u);
	return 0;
}

/*
 * The name that starts at `i`: its end, and in `*fl` the prefix flags when a quote follows it and it is one
 * (PY_P_STR set), else 0. A name is read whole, so "bar'x'" is not an "r" prefix.
 */
static uint32_t py_name(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *fl)
{
	uint32_t j = i + 1u;

	while (j < n && kgenome_textual_ident(p[j]))
		j++;
	*fl = j < n && py_quote(p[j]) ? py_prefix(p, i, j) : 0u;
	return j;
}

/*
 * The end of the plain string whose first quote is at `q`: after its closer, or where it stopped being one -
 * at its line's break for a one-line string, at `n` for any. `*closed` says which.
 */
static uint32_t py_plain_end(const uint8_t *p, uint32_t n, uint32_t q, int triple, int *closed)
{
	uint8_t quote = p[q];
	uint32_t j = q + (triple ? 3u : 1u);

	*closed = 0;
	while (j < n) {
		uint8_t c = p[j];

		if (c == '\\') {
			j = kgenome_textual_skip_escape(p, n, j);
		} else if (c == quote && (!triple || py_triple_at(p, n, j))) {
			*closed = 1;
			return j + (triple ? 3u : 1u);
		} else if (!triple && kgenome_textual_eol_byte(c)) {
			return j;
		} else {
			j++;
		}
	}
	return n;
}

/* Is "\N{name}" at `j` (the backslash), a name closed within PY_NAME_MAX bytes: the byte after the "}", else 0. */
static uint32_t py_named_at(const uint8_t *p, uint32_t n, uint32_t j)
{
	uint32_t k = j + 3u, stop = j + 3u + PY_NAME_MAX;

	if (j + 2u >= n || p[j + 1u] != 'N' || p[j + 2u] != '{')
		return 0;
	for (; k < n && k < stop; k++) {
		if (p[k] == '}')
			return k + 1u;
		if (kgenome_textual_eol_byte(p[k]) || py_quote(p[k]))
			return 0;
	}
	return 0;
}

struct py_scan {
	const uint8_t *p;
	uint32_t       n;
	struct py_frame fr[PY_FRAMES];
	uint32_t       sp;
	uint32_t       had_field;       /* a field was opened */
	uint32_t       fail;            /* a string in a field was not closed: the field is not one */
};

/* The literal frame of the f-string the top frame belongs to: itself, or the one a field and a spec sit on. */
static uint32_t py_lit_of(const struct py_scan *sc)
{
	uint32_t k = sc->sp;

	while (k && sc->fr[k - 1u].mode != PY_LIT)
		k--;
	return k - 1u;
}

static int py_push(struct py_scan *sc, enum py_mode mode, uint8_t quote, uint8_t triple, uint8_t raw)
{
	struct py_frame *f;

	if (sc->sp >= PY_FRAMES)
		return 0;
	f = &sc->fr[sc->sp++];
	f->nest = 0;
	f->mode = (uint8_t)mode;
	f->quote = quote;
	f->triple = triple;
	f->raw = raw;
	return 1;
}

/* One step in a literal part or a spec, at `j`. Answers where it goes on. */
static uint32_t py_lit_step(struct py_scan *sc, uint32_t j)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, e;
	uint8_t c = p[j];
	int spec = sc->fr[sc->sp - 1u].mode == PY_SPEC;

	if (c == '\\') {
		if (j + 1u < n && (p[j + 1u] == '{' || p[j + 1u] == '}'))
			return j + 1u;
		e = sc->fr[py_lit_of(sc)].raw ? 0u : py_named_at(p, n, j);
		return e ? e : kgenome_textual_skip_escape(p, n, j);
	}
	if (c == '{') {
		if (!spec && j + 1u < n && p[j + 1u] == '{')
			return j + 2u;
		if (py_push(sc, PY_EXPR, 0, 0, 0))
			sc->had_field = 1;
		return j + 1u;
	}
	if (c == '}') {
		if (spec) {
			sc->sp -= 2u;           /* the spec, and the field it belongs to */
			return j + 1u;
		}
		return j + 1u + (j + 1u < n && p[j + 1u] == '}');
	}
	return j + 1u;
}

/* One step in the code of a field, at `j`. */
static uint32_t py_expr_step(struct py_scan *sc, uint32_t j)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, fl = 0, q = j;
	struct py_frame *f = &sc->fr[sc->sp - 1u];
	uint8_t c = p[j];

	if (py_quote(c) || (kgenome_textual_ident_start(c))) {
		int closed, triple;

		if (!py_quote(c)) {
			q = py_name(p, n, j, &fl);
			if (!(fl & PY_P_STR))
				return q;
		}
		triple = py_triple_at(p, n, q);
		if ((fl & PY_P_FMT) &&
		    py_push(sc, PY_LIT, p[q], (uint8_t)triple, (uint8_t)((fl & PY_P_RAW) != 0)))
			return q + (triple ? 3u : 1u);
		q = py_plain_end(p, n, q, triple, &closed);
		sc->fail |= !closed;
		return q;
	}
	if (c == '#') {
		while (j < n && !kgenome_textual_eol_byte(p[j]))
			j++;
		return j;
	}
	if (c == '\\')
		return kgenome_textual_eol_byte(j + 1u < n ? p[j + 1u] : 0u) ? kgenome_textual_skip_escape(p, n, j) : j + 1u;
	if (c == '(' || c == '[' || c == '{') {
		f->nest++;
	} else if (c == ')' || c == ']') {
		if (f->nest)
			f->nest--;
	} else if (c == '}') {
		if (f->nest)
			f->nest--;
		else
			sc->sp--;
	} else if (c == ':' && !f->nest) {
		(void)py_push(sc, PY_SPEC, 0, 0, 0);
	}
	return j + 1u;
}

/*
 * One step in a literal part or a spec when the byte at `j` ends the f-string - its own quote, or the break
 * of its line when it is a one-line one. Answers 1 when it did, with `*closed` set for a quote.
 */
static int py_fstring_stops(struct py_scan *sc, uint32_t *jp, int *closed)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, j = *jp, k = py_lit_of(sc);
	const struct py_frame *lf = &sc->fr[k];
	int quote = p[j] == lf->quote && (!lf->triple || py_triple_at(p, n, j));

	if (!quote && !(kgenome_textual_eol_byte(p[j]) && !lf->triple))
		return 0;
	if (quote)
		*jp = j + (lf->triple ? 3u : 1u);
	sc->sp = k;
	*closed = quote && !k;
	sc->fail |= !quote && k;
	return 1;
}

/*
 * The f-string whose first quote is at `q`: where it ends and whether it was closed. `*fields` is set when
 * it has a field in it. A field that was still open where the scan stopped makes it open (see the header).
 */
static uint32_t py_fstring_end(struct py_scan *sc, uint32_t q, int raw, int *closed, uint32_t *fields)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, j;
	int triple = py_triple_at(p, n, q);

	sc->sp = 0;
	sc->had_field = 0;
	sc->fail = 0;
	(void)py_push(sc, PY_LIT, p[q], (uint8_t)triple, (uint8_t)raw);
	*closed = 0;
	j = q + (triple ? 3u : 1u);
	while (j < n && sc->sp && !sc->fail) {
		if (sc->fr[sc->sp - 1u].mode == PY_EXPR)
			j = py_expr_step(sc, j);
		else if (!py_fstring_stops(sc, &j, closed))
			j = py_lit_step(sc, j);
	}
	*fields = sc->had_field;
	return j > n ? n : j;
}

/*
 * The string whose prefix starts at `at` and whose first quote is at `q`: deliver it, and the code before it.
 * Answers 0 once the sink has stopped; lx->pos is where the lexer goes on.
 */
static int py_string(struct kgenome_textual_lexer *lx, struct py_scan *sc, uint32_t at, uint32_t q, uint32_t fl)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, e, fields = 0, open;
	int triple = py_triple_at(p, n, q), closed = 0;

	if (fl & PY_P_FMT)
		e = py_fstring_end(sc, q, (fl & PY_P_RAW) != 0, &closed, &fields);
	else
		e = py_plain_end(p, n, q, triple, &closed);
	open = q - at + (triple ? 3u : 1u);
	/* The form may write a spelled-out byte as itself only where the whole span is one literal: an
	 * f-string with a field has code in it, and an r'\x41' in there is not an escape. */
	return kgenome_textual_lit(lx, at, e, KGENOME_TEXTUAL_STRING,
				   (uint8_t)((fl & PY_P_RAW) || fields ? 0u : KGENOME_TEXTUAL_F_INTERP), open, triple ? 3u : 1u, closed);
}

void kgenome_textual_py_lex(struct kgenome_textual_lexer *lx)
{
	const uint8_t *p = lx->p;
	uint32_t n = lx->n, i = 0;
	struct py_scan sc = { .p = p, .n = n };

	while (i < n) {
		uint8_t c = p[i];

		if (c == '#') {
			uint32_t j = i;

			while (j < n && !kgenome_textual_eol_byte(p[j]))
				j++;
			if (!kgenome_textual_span_at(lx, i, j, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0))
				return;
			i = j;
		} else if (c == '\\') {
			i = kgenome_textual_skip_escape(p, n, i);
		} else if (py_quote(c)) {
			if (!py_string(lx, &sc, i, i, 0))
				return;
			i = lx->pos;
		} else if (kgenome_textual_ident_start(c)) {
			uint32_t fl, j = py_name(p, n, i, &fl);

			if (fl & PY_P_STR) {
				if (!py_string(lx, &sc, i, j, fl))
					return;
				i = lx->pos;
			} else {
				i = j;
			}
		} else {
			i++;
		}
	}
	kgenome_textual_code_to(lx, n);
}
