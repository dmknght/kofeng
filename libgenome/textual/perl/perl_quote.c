/*
 * perl_quote.c - what has a beginning and an end in perl, found without reading what is inside: the quote-like
 * operators, a pattern literal, a here-document, pod and a format.
 *
 * PERL FINDS THE END OF A QUOTED TEXT BEFORE IT READS WHAT IS IN IT. "@{[ "x" ]}" is NOT one string: the second
 * quote ends it (perl 5.44: "Missing right curly or square bracket, within string"), so what interpolates is
 * of no concern to the lexer and a quoted text is found by its delimiters alone - a bracket nests, a backslash
 * takes the byte after it, anything else closes on its own kind.
 *
 * DELIMITERS (every rule here was run against perl 5.44, `perl -c` and a run that prints the result):
 *   - any byte can open: q{a{b}c} nests, q#a# with the "#" attached is a delimiter, and q #a<newline> {b} is a
 *     comment and then the delimiter "{" - white space and comments may stand between the word and it. A word
 *     byte opens only after white space ("q xabcx" is the string abc), because attached it would be part of the
 *     word. The caller has already met "=>" and a hash-subscript "}" - those make the word a bareword.
 *   - s, tr and y have two parts. With a bracket the second part has a delimiter of its own after any white
 *     space and comments ("s{a} # c<newline> {b}", "s(a)[b]", "s{a}/b/"; a "#" attached to the first part is
 *     the delimiter, "s{a}#b#", and perl 5.44 says "Substitution replacement not terminated" for "s{a}#c<newline>{b}");
 *     with any other bracket the second part closes on the same byte ("s/a/b/", "s###", "s'a'b'").
 *   - the flags are the letters the operator has (m: msixxnpogcdual, qr: msixxnpodual, s: those and er, tr and y:
 *     cdsr) directly after the last delimiter, for the closers flags_end lists. Only those letters: "m/x/ if" has white space in it,
 *     and "m/x/if" is an error in perl 5.44 ("Unknown regexp modifier"), so what the lexer does with it is its own choice (it takes
 *     the flags perl knows and leaves the rest), which is why the row's `glue` keeps a space between a closing delimiter and a word.
 *
 * A SPAN HERE IS ONE CONSTRUCT, all its parts and its flags: a two-part operator is one STRING (its middle
 * delimiters and its second part are inside the span, so a form copies it as typed), and its value is for
 * nobody (perl_value.c says so). s///e's replacement is code, and is inside the span too: perl finds the end
 * of it by delimiter before it evals it, as above.
 *
 * A HERE-DOCUMENT is "<<" and a tag directly after it - a bare word, a quoted one ("<<'EOF'", `<<"EOF"`, with
 * white space allowed before the quote: "<< \"EOF\""), "<<\EOF", and "<<~" in front of any of them for the
 * indented form. A bare tag after white space ("<< EOF") is not one in perl 5.28 and later, and is not here. Its
 * body is the lines after the line the operator is on, to a line that is the tag and nothing else; with "<<~"
 * leading blanks of that line do not count, and a "\r" before the line break never does (perl reads a CRLF file
 * as an LF one; checked with a body and a terminator typed with CRLF). That CR is not in the span: see here_body.
 *
 * NOT DONE, and found in perl: when a quoted text or a pattern that began on the operator's line runs over the
 * line break, perl takes the body from the line after the operator's own - the quoted text goes on after the body
 * ("print <<A, "x<newline>y";" prints the body first, and the string is "x" and what follows the terminator).
 * Spans partition the text and cannot be in two pieces; here the text goes on being the quoted text, and the body
 * is read at the next line break outside any literal. [Unverified] beyond the one case run; no file of the
 * corpus has it.
 *
 * POD is "=word" where a statement can begin (the caller knows that) to a LATER line that begins "=cut" (a word
 * boundary after it), or to the end of the text: a pod with no "=cut" is allowed, and an "=cut" with no pod before
 * it begins one (`=cut<newline>print 1;` compiles and prints nothing: the first line is not the one that ends it).
 *
 * A FORMAT is "format NAME =" ending its line, and the picture lines after it to a line that is "." and white space.
 * They are text, with "@<<<" and "#" in them that are not comments, and the lines of arguments are code that is
 * not lexed here: the whole block is one verbatim span, as a here-document's body is.
 */

#include "perl.h"

uint32_t kgenome_textual_perl_delim(const uint8_t *p, uint32_t n, uint32_t j)
{
	uint8_t o = p[j], c = kgenome_textual_close_of(o);
	uint32_t k = j + 1u, depth = 1u;

	while (k < n) {
		uint8_t b = p[k];

		if (b == '\\' && o != '\\') {
			if (k + 1u >= n)
				return 0;
			k += 2u;
			continue;
		}
		if (b == c) {
			if (c == o || --depth == 0)
				return k + 1u;
		} else if (b == o) {
			depth++;
		}
		k++;
	}
	return 0;
}

uint32_t kgenome_textual_perl_skip(const uint8_t *p, uint32_t n, uint32_t j)
{
	while (j < n) {
		if (p[j] == '#') {
			while (j < n && p[j] != '\n')
				j++;
		} else if (kof_is_space_byte(p[j])) {
			j++;
		} else {
			break;
		}
	}
	return j;
}

int kgenome_textual_perl_op_interp(uint8_t op, uint8_t delim)
{
	return op == KGENOME_TEXTUAL_PERL_OP_QQ || (op == KGENOME_TEXTUAL_PERL_OP_QX && delim != '\'');
}

/* The letters that may follow the last delimiter of the operator. */
static const char *flags_of(uint8_t op)
{
	switch (op) {
	case KGENOME_TEXTUAL_PERL_OP_QR:
		return "msixnpodual";
	case KGENOME_TEXTUAL_PERL_OP_M:
		return "msixnpogcdual";
	case KGENOME_TEXTUAL_PERL_OP_S:
		return "msixnpogcdualer";
	case KGENOME_TEXTUAL_PERL_OP_TR:
	case KGENOME_TEXTUAL_PERL_OP_Y:
		return "cdsr";
	default:
		return "";
	}
}

/*
 * The flags after the closer that ends at `j`. Only after a closer the row's `glue` keeps a space behind ("/ ) ] } > ! | # , : %"):
 * the form closes up white space, and flags that the form's input did not have would make the form of the form another text
 * ("m;x; if" is "m;x;if", where the lexer would read "i" as a flag). A construct that closes with any other byte - perl allows all
 * of them - has its flag letters read as a word, and "s@a@b@s ) {" is File::Spec::Cygwin's: the word is a quote word after a
 * term, which tok_word does not take for an operator. Counted on the corpus, the other closers are 2 to 11 constructs each
 * of 2700 files, and one of them (s&a&b& and) has a word after it.
 */
static uint32_t flags_end(const uint8_t *p, uint32_t n, uint32_t j, const char *set)
{
	if (j == 0 || !kof_byte_in_set(p[j - 1u], "/)]}>!|#,:%"))
		return j;
	while (j < n && kof_byte_in_set(p[j], set))
		j++;
	return j;
}

uint32_t kgenome_textual_perl_quote(const uint8_t *p, uint32_t n, uint32_t at, uint32_t wl, uint8_t op, int *closed,
				    uint32_t *open, uint32_t *close)
{
	uint32_t j = at + wl, e, e2, f;

	*closed = 0;
	*close = 0;
	/* a "#" right after the word is the delimiter; after white space it begins a comment */
	if (j < n && p[j] != '#')
		j = kgenome_textual_perl_skip(p, n, j);
	if (j >= n)
		return 0;
	*open = j + 1u - at;
	e = kgenome_textual_perl_delim(p, n, j);
	if (e && (op == KGENOME_TEXTUAL_PERL_OP_S || op == KGENOME_TEXTUAL_PERL_OP_TR || op == KGENOME_TEXTUAL_PERL_OP_Y)) {
		if (kgenome_textual_close_of(p[j]) != p[j]) {
			/* as for the first: "#" attached is the second part's delimiter ("s{a}#b#"), after white space it is a comment */
			uint32_t k = e < n && p[e] == '#' ? e : kgenome_textual_perl_skip(p, n, e);

			e2 = k < n ? kgenome_textual_perl_delim(p, n, k) : 0;
		} else {
			e2 = kgenome_textual_perl_delim(p, n, e - 1u);
		}
		e = e2;
	}
	if (!e)
		return n;
	f = flags_end(p, n, e, flags_of(op));
	*closed = 1;
	*close = 1u + (f - e);
	return f;
}

uint32_t kgenome_textual_perl_match(const uint8_t *p, uint32_t n, uint32_t at, int *closed, uint32_t *close)
{
	uint32_t e = kgenome_textual_perl_delim(p, n, at), f;

	*closed = 0;
	*close = 0;
	if (!e)
		return n;
	f = flags_end(p, n, e, flags_of(KGENOME_TEXTUAL_PERL_OP_M));
	*closed = 1;
	*close = 1u + (f - e);
	return f;
}

/* ---- here-documents ---- */

uint32_t kgenome_textual_perl_here_op(const uint8_t *p, uint32_t n, uint32_t i, struct kgenome_textual_perl_here *h)
{
	uint32_t j = i + 2u, k, e;

	h->indent = h->quoted = h->spaced = 0;
	h->interp = 1;
	if (j < n && p[j] == '~') {
		h->indent = 1;
		j++;
	}
	k = j;
	while (k < n && kgenome_textual_blank(p[k]))
		k++;
	if (k < n && (p[k] == '"' || p[k] == '\'' || p[k] == '`')) {
		uint8_t q = p[k];

		for (e = k + 1u; e < n && p[e] != q && p[e] != '\n'; e++)
			;
		if (e >= n || p[e] != q)
			return 0;
		h->off = k + 1u;
		h->len = e - (k + 1u);
		h->quoted = 1;
		h->spaced = k > j;
		h->interp = q != '\'';
		return e + 1u - i;
	}
	/* "<<~ EOF" with blanks after the "~" is read as "<<~EOF": the form closes the blanks up (glue says no to that), and "<<~" and
	 * a bare word is no other valid text but "1 <<~ 2", which follows a term and is not asked */
	if (h->indent)
		j = k;
	if (j + 1u < n && p[j] == '\\' && kgenome_textual_ident_start(p[j + 1u])) {
		h->interp = 0;
		j++;
	}
	if (j >= n || !kgenome_textual_ident_start(p[j]))
		return 0;
	for (e = j; e < n && kgenome_textual_ident(p[e]); e++)
		;
	h->off = j;
	h->len = e - j;
	return e - i;
}

/* Is the line [a, b) - leading blanks of an indented one and a "\r" at its end not counted - the tag. */
static int line_is_tag(const uint8_t *p, uint32_t a, uint32_t b, const struct kgenome_textual_perl_here *h)
{
	if (h->indent)
		while (a < b && (p[a] == ' ' || p[a] == '\t'))
			a++;
	if (b > a && p[b - 1u] == '\r')
		b--;
	return b - a == h->len && memcmp(p + a, p + h->off, h->len) == 0;
}

uint32_t kgenome_textual_perl_here_body(const uint8_t *p, uint32_t n, uint32_t i, const struct kgenome_textual_perl_here *h,
					uint32_t *close, int *closed)
{
	uint32_t ls = i;

	*close = 0;
	*closed = 0;
	while (ls < n) {
		const uint8_t *nl = memchr(p + ls, '\n', n - ls);
		uint32_t le = nl ? (uint32_t)(nl - p) : n;

		if (line_is_tag(p, ls, le, h)) {
			/* the "\r" of a CRLF closing line is not the span's: a span that ends in a CR is one the form takes for a literal
			 * that holds a line break, and writes the next break as a CR, which perl does not read as one */
			uint32_t e = le > ls && p[le - 1u] == '\r' ? le - 1u : le;   /* one CR: line_is_tag takes no more */

			*close = e - ls;
			*closed = 1;
			/* an empty tag closes at an empty line, which is no byte of the span unless its break is: with it the body
			 * and its end are not nothing (the form would drop a span of no bytes, and a blank line with it) */
			if (e == ls && nl) {
				*close = le + 1u - ls;
				return le + 1u;
			}
			return e;
		}
		if (!nl)
			break;
		ls = le + 1u;
	}
	return n;
}

/* ---- pod and format ---- */

static int is_cut(const uint8_t *p, uint32_t n, uint32_t ls)
{
	return n - ls >= 4u && memcmp(p + ls, "=cut", 4) == 0 &&
	       (ls + 4u >= n || !kof_is_alpha(p[ls + 4u]));
}

uint32_t kgenome_textual_perl_pod_end(const uint8_t *p, uint32_t n, uint32_t i)
{
	const uint8_t *nl = memchr(p + i, '\n', n - i);
	uint32_t ls = nl ? (uint32_t)(nl - p) + 1u : n;

	/* the line that begins the pod is not the one that ends it, "=cut" or not: `=cut<newline>print 1;` prints nothing */
	while (ls < n) {
		uint32_t le;

		nl = memchr(p + ls, '\n', n - ls);
		le = nl ? (uint32_t)(nl - p) : n;
		if (is_cut(p, n, ls))
			return le;
		if (!nl)
			break;
		ls = le + 1u;
	}
	return n;
}

uint32_t kgenome_textual_perl_format_head(const uint8_t *p, uint32_t n, uint32_t w)
{
	uint32_t j = w;

	while (j < n && (p[j] == ' ' || p[j] == '\t'))
		j++;
	while (j < n && (kgenome_textual_ident(p[j]) || p[j] == ':'))
		j++;
	while (j < n && (p[j] == ' ' || p[j] == '\t'))
		j++;
	if (j >= n || p[j] != '=')
		return 0;
	for (j++; j < n && (p[j] == ' ' || p[j] == '\t' || p[j] == '\r'); j++)
		;
	return j < n && p[j] == '\n' ? j + 1u : 0;
}

uint32_t kgenome_textual_perl_format_body(const uint8_t *p, uint32_t n, uint32_t i, uint32_t *close)
{
	uint32_t ls = i;

	*close = 0;
	while (ls < n) {
		const uint8_t *nl = memchr(p + ls, '\n', n - ls);
		uint32_t le = nl ? (uint32_t)(nl - p) : n, k = ls + 1u;

		if (p[ls] == '.') {
			while (k < le && (p[k] == ' ' || p[k] == '\t' || p[k] == '\r'))
				k++;
			if (k == le) {
				/* the "." line without a CR it may end in (see here_body) */
				uint32_t e = le;

				while (e > ls + 1u && (p[e - 1u] == '\r' || p[e - 1u] == ' ' || p[e - 1u] == '\t'))
					e--;

				*close = e - ls;
				return e;
			}
		}
		if (!nl)
			break;
		ls = le + 1u;
	}
	return n;
}
