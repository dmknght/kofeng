/*
 * ruby_str.c - where a ruby literal ends: '...', "...", `...`, the percent literals, a regular expression, a
 * heredoc body, and the "#{ ... }" inside the ones that interpolate.
 *
 * Every literal here is found by the same loop (body_scan): a backslash and the byte after it are one thing, a
 * "#" in a literal that interpolates may begin "#{code}" or "#@name" or "#$name", and a paired delimiter - ( [ { < -
 * counts the same bracket inside it. What differs per literal is the delimiter pair and whether the "#" and the
 * escapes are read, which is the one table in kgenome_ruby_percent. The rules were read off ruby 3.3's own lexer (Ripper)
 * and are pinned by tests/lib/genome/textual_ruby.c.
 *
 * "#{" IS CODE, with literals of its own and a "}" that closes it, so body_scan calls the code scanner
 * (kgenome_ruby_code_nested) and the code scanner calls back for every literal it meets. A literal that does not close -
 * the text ends, or the nesting passes KGENOME_RUBY_DEPTH - is open to the end of the text, and what it held is never
 * scanned again, so the whole lex reads each byte once.
 *
 * A "$" VARIABLE AFTER "#" TAKES ITS PUNCTUATION WITH IT, quote included: "#$"" is the variable $" and the string goes on, as in
 * the interpreter (parser_peek_variable_name) - so `"cost #$"` is not a closed string. It is the same rule that keeps `$'` and
 * `$"` in code from opening a string (kgenome_ruby_gvar_len).
 *
 * THE DELIMITER OF A PERCENT LITERAL is any byte that is not a letter, a digit, 0x80 or above, or white space. The interpreter
 * takes a blank too ("% a ", "%\na\n"), which is not read here: the form writes a run of blanks as one space and "\r\n" as
 * "\n", so a blank delimiter would become another one (found by asking that the form of a form be itself). The closer is looked
 * for before the escape, so a backslash may delimit (%\ab\), as it may in the interpreter.
 *
 * A HEREDOC BODY is read line by line (kgenome_ruby_heredoc_body); see there.
 */

#include "ruby.h"

/* The bytes after "$" that make a variable of one character: ~ * $ ? ! @ / \ ; , . = : < > " & ` ' + 0 */
static int gname_punct(uint8_t c)
{
	return kof_byte_in_set(c, "~*$?!@/\\;,.=:<>\"&`'+0");
}

uint32_t kgenome_ruby_gvar_len(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint32_t k = i + 1u;

	if (k >= n || p[i] != '$')
		return 0;
	if (gname_punct(p[k]))
		return 2u;
	if (p[k] == '-')
		return k + 1u < n && kgenome_textual_ident(p[k + 1u]) ? 3u : 0u;
	if (kof_is_digit(p[k]) || kgenome_textual_ident_start(p[k])) {
		int digits = kof_is_digit(p[k]);

		while (k < n && (digits ? kof_is_digit(p[k]) : kgenome_textual_ident(p[k])))
			k++;
		return k - i;
	}
	return 0;
}

uint32_t kgenome_ruby_ivar_len(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint32_t k = i + 1u;

	if (i >= n || p[i] != '@')
		return 0;
	if (k < n && p[k] == '@')
		k++;
	if (k >= n || !kgenome_textual_ident_start(p[k]))
		return 0;
	while (k < n && kgenome_textual_ident(p[k]))
		k++;
	return k - i;
}

uint32_t kgenome_ruby_dvar_len(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint32_t k;

	if (i + 1u >= n || p[i] != '#')
		return 0;
	k = p[i + 1u] == '$' ? kgenome_ruby_gvar_len(p, n, i + 1u) : p[i + 1u] == '@' ? kgenome_ruby_ivar_len(p, n, i + 1u) : 0u;
	return k ? k + 1u : 0u;
}

/*
 * The body of a literal from `*ip` (the first byte after its opening delimiter) to its closer `c`; `o` is the
 * opening delimiter, which differs from `c` for the paired ones and nests. Answers 1 with `*ip` past the closer, or 0
 * with `*ip` at the end of the text. `*had` is set when something in it interpolates.
 */
static int body_scan(struct kgenome_ruby_scan *sc, uint32_t *ip, uint8_t o, uint8_t c, int interp, int *had)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, i = *ip, nest = 0, k;

	while (i < n) {
		uint8_t b = p[i];

		/* the closer is looked for before the escape: a literal may be delimited by a backslash (%\ab\), as in the interpreter */
		if (b == c && c == '\\') {
			*ip = i + 1u;
			return 1;
		}
		if (b == '\\') {
			i = kgenome_textual_skip_escape(p, n, i);
			continue;
		}
		if (interp && b == '#' && i + 1u < n) {
			if (p[i + 1u] == '{') {
				*had = 1;
				i = kgenome_ruby_code_nested(sc, i + 2u);
				if (!i)
					break;
				continue;
			}
			k = kgenome_ruby_dvar_len(p, n, i);
			if (k) {
				*had = 1;
				i += k;
				continue;
			}
		}
		if (b == c) {
			if (!nest) {
				*ip = i + 1u;
				return 1;
			}
			nest--;
		} else if (b == o && o != c) {
			nest++;
		}
		i++;
	}
	*ip = n;
	return 0;
}

/* A literal that escapes (and, with `had` clear, can be written with its escapes spelled out): the INTERP flag. */
static uint8_t lit_flags(int escapes, int had, int closed)
{
	return (uint8_t)((escapes && !had ? KGENOME_TEXTUAL_F_INTERP : 0u) | (closed ? 0u : KGENOME_TEXTUAL_F_OPEN));
}

static uint8_t here_flags(int escapes, int had, int closed)
{
	return (uint8_t)(lit_flags(escapes, had, closed) | KGENOME_TEXTUAL_F_HERE);
}

void kgenome_ruby_quoted(struct kgenome_ruby_scan *sc, uint32_t i, uint8_t quote, struct kgenome_ruby_lit *lit)
{
	int had = 0, escapes = quote != '\'';
	uint32_t j = i + 1u;
	int closed = body_scan(sc, &j, quote, quote, escapes, &had);

	lit->end = j;
	lit->open = 1u;
	lit->close = closed ? 1u : 0u;
	lit->flags = lit_flags(escapes, had, closed);
}

/* The options after a regular expression's closer: every letter, the interpreter takes them all and refuses the ones it does not know. */
static uint32_t regex_opts(const uint8_t *p, uint32_t n, uint32_t j)
{
	uint32_t opts = 0;

	while (j + opts < n && kof_is_alpha(p[j + opts]))
		opts++;
	return opts;
}

int kgenome_ruby_percent(struct kgenome_ruby_scan *sc, uint32_t i, struct kgenome_ruby_lit *lit)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, j = i + 1u, opts = 0;
	uint8_t type = 'Q', o, c;
	int interp, closed, had = 0;

	if (j >= n)
		return 0;
	if (kof_is_alpha(p[j]) || kof_is_digit(p[j])) {
		type = p[j++];
		/* "%w" and the rest: a letter that is not one of these is an error in the interpreter, and here the "%" is an operator */
		if (!kof_byte_in_set(type, "qQwWiIrsx") || j >= n)
			return 0;
	}
	o = p[j];
	/* not a blank. The interpreter takes "% a ", "%q\ta\t" and "%\na\n" as literals, but the form writes every run of blanks as one
	 * space and "\r\n" as "\n", so a blank that is a delimiter would become another one (found asking that the form of a form be
	 * itself: a CR, a "% " read where "%\r" was not, a "\n" where "\r\n" was). No program writes one. */
	if (o >= 0x80u || kof_is_space_byte(o) ||
	    kof_is_alpha(o) || kof_is_digit(o))
		return 0;
	c = kgenome_textual_close_of(o);
	/* what reads "#{" and escapes: Q, W, I, r, x and the bare form; not q, w, i, s */
	interp = !kof_byte_in_set(type, "qwis");
	j++;
	closed = body_scan(sc, &j, o, c, interp, &had);
	if (closed && type == 'r')
		opts = regex_opts(p, n, j);
	lit->end = j + opts;
	lit->open = (type == 'Q' && p[i + 1u] == o ? 2u : 3u);
	lit->close = closed ? 1u + opts : 0u;
	/* W and I split on white space and r is a pattern: an escape spelled out there says something else written plain */
	lit->flags = lit_flags(kof_byte_in_set(type, "Qx"), had, closed);
	return 1;
}

void kgenome_ruby_regex(struct kgenome_ruby_scan *sc, uint32_t i, struct kgenome_ruby_lit *lit)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, j = i + 1u, opts = 0;
	int had = 0, closed = body_scan(sc, &j, '/', '/', 1, &had);

	if (closed)
		opts = regex_opts(p, n, j);
	lit->end = j + opts;
	lit->open = 1u;
	lit->close = closed ? 1u + opts : 0u;
	lit->flags = lit_flags(0, had, closed);
}

/*
 * A HEREDOC BODY, line by line from `i`. The closing line is the identifier alone - "<<-" and "<<~" let it be
 * indented, and a "\r" before the line break is not part of it - and a line that begins inside a "#{ }" or after a
 * backslash-newline is not looked at: the interpreter reads those as the middle of one line. A raw body (<<'ID') has
 * no escape and no interpolation, so every line is looked at.
 */
void kgenome_ruby_heredoc_body(struct kgenome_ruby_scan *sc, uint32_t i, const struct kgenome_ruby_heredoc *hd, struct kgenome_ruby_lit *lit)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, pos = i, k;
	int had = 0;

	lit->open = 0;
	lit->close = 0;
	for (;;) {
		uint32_t le = pos, ce, a;

		if (pos >= n) {
			lit->end = n;
			lit->flags = here_flags(!hd->raw, had, 0);
			return;
		}
		while (le < n && p[le] != '\n')
			le++;
		ce = le > pos && p[le - 1u] == '\r' ? le - 1u : le;
		a = pos;
		if (hd->indent)
			while (a < ce && kof_is_space_byte(p[a]))
				a++;
		if (ce - a == hd->len && memcmp(p + a, p + hd->off, hd->len) == 0) {
			lit->end = ce;
			lit->close = ce - pos;
			lit->flags = here_flags(!hd->raw, had, 1);
			return;
		}
		if (hd->raw) {
			pos = le < n ? le + 1u : n;
			continue;
		}
		k = pos;
		while (k < n && p[k] != '\n') {
			uint32_t d;

			if (p[k] == '\\') {
				k = kgenome_textual_skip_escape(p, n, k);
			} else if (p[k] == '#' && k + 1u < n && p[k + 1u] == '{') {
				had = 1;
				k = kgenome_ruby_code_nested(sc, k + 2u);
				if (!k) {
					lit->end = n;
					lit->flags = here_flags(1, had, 0);
					return;
				}
			} else if ((d = kgenome_ruby_dvar_len(p, n, k)) != 0) {
				had = 1;
				k += d;
			} else {
				k++;
			}
		}
		pos = k < n ? k + 1u : n;
	}
}
