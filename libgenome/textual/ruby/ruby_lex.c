/*
 * ruby_lex.c - THE LEXER OF RUBY: where code is, and what is a string, a comment or a heredoc.
 *
 * Every rule below was read off ruby 3.3's own lexer (`Ripper.lex`, ruby 3.3.8 run from the host's libraries) and is pinned by a
 * known answer in tests/lib/genome/textual_ruby.c. The lexer was compared with it, span for span, on every .rb file of the
 * machine it was written on (21329 files, 139 MB: ruby's library, its gems and metasploit): all agree (one has syntax errors, and
 * ripper still lexes it the same); and on 12000 generated programs that ruby reads without an error.
 *
 * RUBY CANNOT BE LEXED FROM THE BYTES ALONE: "/" is a division or a regular expression, "%" a modulo or a literal, "?" a ternary or a
 * character, "<<" a shift or a heredoc, ":" a ternary or a symbol, and which it is depends on what came BEFORE. The interpreter
 * keeps a lexer state for that (EXPR_BEG, EXPR_END, EXPR_ARG, EXPR_DOT, ...) and so does this, reduced to the six values those
 * questions need:
 *   BEG    an operand is expected - after an operator, a bracket, "," ";" a line break, a keyword that takes one, a def's ")"
 *   END    a value just ended - a number, a literal, ")" "]" "}", a variable, "end" "self" "nil" ...
 *   ARG    a name that may be a method called without brackets - `puts /x/`, `puts %w[a]`, `puts <<A`: the interpreter asks
 *          "is there a space before and none after", and so does this
 *   DOT    after "." "::" "&.": the next word is a method name, whatever it is spelled, and an operator is its name
 *   FNAME  after def / alias / undef: the same, and "/" "%" "<<" "`" are method names to define
 *   CLASS  after class / module: "<<" is the singleton form (class << self) and not a heredoc
 * It is not the interpreter's in one way: a LOCAL VARIABLE (or a parameter) is END there - "x /2" is a division when x was
 * assigned - and is ARG here, because a name is not tracked. Where that decides the answer the lexer takes the method reading, the
 * one `puts /x/` needs. Measured: no file of the 21329 differs; of 5066 copies of real files with spaces added or removed at
 * random (the ones ripper still reads as a program), 6 differ, every one a name followed by " /", " <<" or " %" with no space
 * after it. [Inference] a tracker that ignored scope would turn some method names into variables, and was not written.
 *
 * COMMENTS. A "#" comment runs to the line break ("\r\n" is the break, so its "\r" is not in the comment). "=begin" and "=end" lines
 * are a block comment, "__END__" alone on a line ends the program: the rest of the text is data, one STRING. The interpreter wants
 * them at column 0, followed by white space (=begin) or the line break (__END__). The FORM takes every line's indentation, the
 * blanks at its end and its comment out, so a marker the interpreter would not read could be one in the text the form writes, and
 * the form of a form would not be itself (found by asking that property of generated programs and of fragments of the language).
 * The lexer therefore reads a marker after leading blanks - every blank the form drops, a CR and a form feed included - and
 * with blanks or a "#" comment after it. No program the interpreter accepts has such a line, except an indented "__END__" called
 * as a method, which nobody writes; a marker line with a comment is delivered whole, the comment in the span, which the form keeps.
 *
 * A BACKSLASH AND ITS LINE BREAK JOIN TWO LINES, and so does the form write them - which also takes out every blank line and
 * comment line that follows (it writes one break, the backslash's). The text it writes is then read that way here too: after a
 * continuation a blank or comment line does not end the statement. [The interpreter ends it there: "x = 1 \<nl># c<nl>y = 2" is two
 * statements, and the form's "x = 1 \<nl>y = 2" is not - the form's to fix, reported.] For the same reason "?\<newline>" is a "?" and
 * a continuation here, and a character in the interpreter.
 *
 * A CHARACTER LITERAL (?a, ?\n, ?\C-a) IS CODE, not a string: it has no escape for the form to write, and as a STRING the form would
 * join "?a" + "?b" into "?ab". It is found all the same, because "?"" and "?'" and "?#" must not open a string or a comment.
 *
 * A HEREDOC (<<ID <<-ID <<~ID, the ID bare or in "" '' ``) begins on the line AFTER its operator: the rest of the operator's line is
 * code and several operators on a line queue their bodies in order (KGENOME_RUBY_HEREDOCS of them; one more is read as a shift).
 * The body is a STRING with the HERE flag that runs through its closing line, which the interpreter wants alone on it ("-" and "~"
 * let it be indented). An operator is code, as in sh. One inside "#{ }" is queued too (the standard library's forwardable.rb has
 * "#{<<-"begin;"}") and gets its body after the line the string ends on; one met while a body is being read is a shift.
 *
 * A NUL, ^D OR ^Z WHERE A TOKEN WOULD BEGIN ENDS THE PROGRAM, as in the interpreter (ripper has no token after one); inside a literal or a
 * comment it is a byte like another. What follows is one STRING, like the data after __END__.
 *
 * NOT MODELLED, and said so: a heredoc whose operator is followed on its line by a string that runs past the line break; a blank
 * (space, tab, CR, line break) as the delimiter of a percent literal (ruby_str.c); the end of the program inside a "#{ }"; and
 * interpolation deeper than KGENOME_RUBY_DEPTH, which is open to the end.
 */

#include <kofcore.h>

#include "ruby.h"

enum rb_state { RB_BEG, RB_END, RB_ARG, RB_DOT, RB_FNAME, RB_CLASS };

struct rb_kw {
	const char *w;
	uint8_t     len;
	uint8_t     st;
	uint8_t     names;      /* alias and undef: how many names follow */
};

#define KW(word, state, count) { word, (uint8_t)(sizeof word - 1u), state, count }

/* The reserved words and the state each leaves; every other word is a name (ARG). */
static const struct rb_kw kw[] = {
	KW("alias", RB_FNAME, 2), KW("undef", RB_FNAME, 1), KW("def", RB_FNAME, 0),
	KW("class", RB_CLASS, 0), KW("module", RB_CLASS, 0),
	KW("and", RB_BEG, 0), KW("or", RB_BEG, 0), KW("not", RB_BEG, 0), KW("if", RB_BEG, 0), KW("unless", RB_BEG, 0),
	KW("while", RB_BEG, 0), KW("until", RB_BEG, 0), KW("elsif", RB_BEG, 0), KW("else", RB_BEG, 0),
	KW("case", RB_BEG, 0), KW("when", RB_BEG, 0), KW("in", RB_BEG, 0), KW("then", RB_BEG, 0), KW("do", RB_BEG, 0),
	KW("begin", RB_BEG, 0), KW("ensure", RB_BEG, 0), KW("rescue", RB_BEG, 0), KW("return", RB_BEG, 0),
	KW("break", RB_BEG, 0), KW("next", RB_BEG, 0), KW("for", RB_BEG, 0), KW("BEGIN", RB_BEG, 0), KW("END", RB_BEG, 0),
	KW("defined?", RB_ARG, 0), KW("super", RB_ARG, 0), KW("yield", RB_ARG, 0),
	KW("end", RB_END, 0), KW("self", RB_END, 0), KW("true", RB_END, 0), KW("false", RB_END, 0), KW("nil", RB_END, 0),
	KW("redo", RB_END, 0), KW("retry", RB_END, 0), KW("__FILE__", RB_END, 0), KW("__LINE__", RB_END, 0),
	KW("__ENCODING__", RB_END, 0),
};

/* The reserved word `w` (len bytes): its table row, or NULL. A word is only looked up if it could be one. */
static const struct rb_kw *kw_find(const uint8_t *w, uint32_t len)
{
	uint32_t k;

	if (len < 2u || len > 12u)
		return NULL;
	for (k = 0; k < sizeof kw / sizeof kw[0]; k++)
		if (kw[k].len == len && kw[k].w[0] == (char)w[0] && memcmp(kw[k].w, w, len) == 0)
			return &kw[k];
	return NULL;
}

/* The operators that are a method's name (after "def", ".", ":"), longest first: "[]=" before "[]", "<=>" before "<=". */
static uint32_t op_name(const uint8_t *p, uint32_t n, uint32_t i)
{
	static const char *const op[] = {
		"[]=", "<=>", "===", "[]", "**", "+@", "-@", "!@", "~@", "==", "=~", "!=", "!~", "<<", ">>", "<=", ">=",
		"+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">", "`",
	};
	uint32_t k;

	for (k = 0; k < sizeof op / sizeof op[0]; k++) {
		uint32_t l = (uint32_t)strlen(op[k]);

		if (n - i >= l && memcmp(p + i, op[k], l) == 0)
			return l;
	}
	return 0;
}

static uint32_t word_end(const uint8_t *p, uint32_t n, uint32_t i)
{
	while (i < n && kgenome_textual_ident(p[i]))
		i++;
	return i;
}

/* A "?" or "!" that ends a method name: not when "=" follows ("a!=b", "a?==b"). */
static uint32_t name_suffix(const uint8_t *p, uint32_t n, uint32_t e)
{
	return e < n && (p[e] == '?' || p[e] == '!') && !(e + 1u < n && p[e + 1u] == '=') ? e + 1u : e;
}

/* Length of the character at `i` (utf-8: the lead byte says), at least 1 and never past the end. */
static uint32_t char_len(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint32_t l = p[i] >= 0xf0u ? 4u : p[i] >= 0xe0u ? 3u : p[i] >= 0xc0u ? 2u : 1u;

	return l > n - i ? n - i : l;
}

/* The end of the escape whose backslash is at `j`: \n \x41 \101 A \u{41} \C-a \M-\C-a \cx, else the byte after. */
static uint32_t escape_end(const uint8_t *p, uint32_t n, uint32_t j)
{
	for (;;) {
		uint32_t k = j + 1u, m;
		uint8_t c;

		if (k >= n)
			return n;
		c = p[k];
		if (c == 'u' && k + 1u < n && p[k + 1u] == '{') {
			/* one character: at most six digits, so the look is bounded and "?\u{" repeated is not quadratic */
			for (m = k + 2u; m < n && m < k + 10u && p[m] != '}' && p[m] != '\n'; m++)
				;
			return m < n && p[m] == '}' ? m + 1u : k + 2u;
		}
		if (c == 'u' || c == 'x' || (uint8_t)(c - '0') < 8u) {
			uint32_t max = c == 'u' ? 4u : c == 'x' ? 2u : 3u;

			m = c == 'u' || c == 'x' ? k + 1u : k;
			for (; m < n && max && (c == 'u' || c == 'x' ? kof_hex_val(p[m]) >= 0 : (uint8_t)(p[m] - '0') < 8u); m++, max--)
				;
			return m;
		}
		if ((c == 'C' || c == 'M') && k + 1u < n && p[k + 1u] == '-') {
			k += 2u;
		} else if (c == 'c') {
			k++;
		} else {
			return k + char_len(p, n, k);
		}
		/* control and meta take one more character or escape */
		if (k >= n)
			return n;
		if (p[k] != '\\')
			return k + char_len(p, n, k);
		j = k;
	}
}

/* The character literal at `i`, a "?": its end, or 0 when the "?" is the ternary operator. */
static uint32_t char_literal(const uint8_t *p, uint32_t n, uint32_t i)
{
	uint8_t c;

	if (i + 1u >= n)
		return 0;
	c = p[i + 1u];
	if (kof_is_space_byte(c))
		return 0;
	if (c == '\\') {
		/* "?\<newline>" is a character in the interpreter. Here it is "?" and a continuation: the form reads a backslash and its
		 * line break so, and drops the comment or blank line that follows, which would then not be the end of the literal's line */
		if (i + 2u < n && (p[i + 2u] == '\n' || p[i + 2u] == '\r'))
			return 0;
		return escape_end(p, n, i + 1u);
	}
	/* "?ab" is not a character: a letter or digit followed by another name byte is the operator ("x ?y : z" stays) */
	if ((kof_is_alpha(c) || kof_is_digit(c) || c == '_') && i + 2u < n &&
	    kgenome_textual_ident(p[i + 2u]))
		return 0;
	return i + 1u + char_len(p, n, i + 1u);
}

static int rb_emit(struct kgenome_ruby_scan *sc, uint32_t at, uint32_t end, uint8_t kind, const struct kgenome_ruby_lit *lit,
		   uint32_t open, uint32_t close)
{
	return kgenome_textual_span_at(sc->lx, at, end, kind, lit ? lit->flags : 0u, open, close);
}

/* The end of the line that holds `i`, before its "\n" - and before the "\r" of a "\r\n" - or the end of the text. */
static uint32_t line_end(const uint8_t *p, uint32_t n, uint32_t i)
{
	while (i < n && p[i] != '\n')
		i++;
	return i < n && i > 0 && p[i - 1u] == '\r' ? i - 1u : i;
}

/* A block comment begun by the "=begin" at `j`: delivered through its "=end" line (or to the end, open). */
static int block_comment(struct kgenome_ruby_scan *sc, uint32_t j, uint32_t *ip)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, ls = j, end = n, close = 0;
	struct kgenome_ruby_lit lit = { .flags = KGENOME_TEXTUAL_F_OPEN };

	for (;;) {
		while (ls < n && p[ls] != '\n')
			ls++;
		if (ls >= n)
			break;
		ls++;
		if (n - ls >= 4u && memcmp(p + ls, "=end", 4) == 0 && (ls + 4u >= n || kof_is_space_byte(p[ls + 4u]))) {
			end = line_end(p, n, ls);
			close = 4u;
			lit.flags = 0;
			break;
		}
	}
	*ip = end;
	return rb_emit(sc, j, end, KGENOME_TEXTUAL_COMMENT, &lit, 6u, close);
}

/*
 * A line start in the text itself: "=begin" opens a block comment and "__END__" ends the program. Two things are read more widely
 * than the interpreter reads them, because the form would otherwise make a marker of a line that was not one (and the form of a
 * form would not be itself): leading blanks (the form drops the indentation of every line), and what the form drops from the end
 * of a line - blanks and a "#" comment: "=begin # c" and "__END__  # c" are markers. A marker line with a comment on it is
 * delivered whole, the comment inside the span, so the form keeps it as typed. `*ip` moves past what was delivered; 0 only when the
 * sink stopped.
 */
static int line_start(struct kgenome_ruby_scan *sc, uint32_t *ip)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, j = *ip, k, eol;

	while (j < n && kgenome_textual_blank(p[j]))
		j++;
	if (n - j >= 6u && p[j] == '=' && memcmp(p + j + 1u, "begin", 5) == 0 &&
	    (j + 6u >= n || kof_is_space_byte(p[j + 6u]) || p[j + 6u] == '#'))
		return block_comment(sc, j, ip);
	if (n - j < 7u || memcmp(p + j, "__END__", 7) != 0)
		return 1;
	for (k = j + 7u; k < n && kgenome_textual_blank(p[k]); k++)
		;
	if (k < n && p[k] == '#')
		k = line_end(p, n, k);
	if (k < n && p[k] == '\r' && k + 1u < n && p[k + 1u] == '\n')
		eol = 2;
	else if (k < n && p[k] == '\n')
		eol = 1;
	else if (k == n)
		eol = 0;
	else
		return 1;
	*ip = n;
	return rb_emit(sc, j, n, KGENOME_TEXTUAL_STRING, NULL, k + eol - j, 0);
}

/* The bodies of the queued heredocs, from the line start `*ip`; `*ip` is left at the end of the last one's closing line. */
static int heredoc_bodies(struct kgenome_ruby_scan *sc, uint32_t *ip)
{
	uint32_t k, i = *ip;

	sc->flushing = 1;
	for (k = 0; k < sc->nhd && i < sc->n; k++) {
		struct kgenome_ruby_lit lit;

		kgenome_ruby_heredoc_body(sc, i, &sc->hd[k], &lit);
		if (!rb_emit(sc, i, lit.end, KGENOME_TEXTUAL_STRING, &lit, 0, lit.close)) {
			sc->flushing = 0;
			return 0;
		}
		i = lit.end;
		if (k + 1u < sc->nhd)
			i += kgenome_textual_eol_at(sc->p, sc->n, i);
	}
	sc->nhd = 0;
	sc->flushing = 0;
	*ip = i;
	return 1;
}

/* "<<" at `i` as a heredoc operator: queued, and the answer is where the identifier ends; 0 when it is a shift. */
static uint32_t heredoc_open(struct kgenome_ruby_scan *sc, uint32_t i)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, j = i + 2u, s, e;
	struct kgenome_ruby_heredoc *h;
	uint8_t indent = 0, raw = 0;

	if (j < n && (p[j] == '-' || p[j] == '~')) {
		indent = 1;
		j++;
	}
	if (j >= n || sc->nhd >= KGENOME_RUBY_HEREDOCS || sc->flushing)
		return 0;
	if (p[j] == '"' || p[j] == '\'' || p[j] == '`') {
		uint32_t *fail = &sc->hfail[p[j] == '"' ? 0 : p[j] == '\'' ? 1 : 2];

		raw = p[j] == '\'';
		if (j < *fail)
			return 0;
		for (e = j + 1u; e < n && p[e] != p[j] && p[e] != '\n'; e++)
			;
		if (e >= n || p[e] != p[j]) {
			*fail = e;      /* a later "<<\"" on this line has no closer either: the line is read once, not once for each */
			return 0;
		}
		s = j + 1u;
		j = e + 1u;
	} else if (kgenome_textual_ident(p[j])) {
		s = j;
		e = j = word_end(p, n, j);
	} else {
		return 0;
	}
	h = &sc->hd[sc->nhd++];
	h->off = s;
	h->len = e - s;
	h->indent = indent;
	h->raw = raw;
	return j;
}

/* One position of the scan: where it is, the state, and what an alias or undef still has to name. */
struct rb_pos {
	uint32_t i;
	uint32_t parens;        /* "(" open */
	uint32_t defdepth;      /* the depth of the "(" of a def's parameter list, whose ")" leaves BEG, not END; 0 none */
	uint8_t  st;
	uint8_t  names;
	uint8_t  defparen;      /* a "def" was read and its "(" has not been */
	uint8_t  cont;          /* a backslash joined the line to the next and nothing but blanks and comments has come since */
};

/* A method name has been read ("def x", "alias a b", "a.<<"): the state it leaves, and one name of an alias is used up. */
static void name_done(struct rb_pos *ps)
{
	if (ps->names > 1u) {
		ps->names--;
		ps->st = RB_FNAME;
	} else {
		ps->names = 0;
		ps->st = RB_END;
	}
}

/* A word at `s`..`e` has been read: the state it leaves. A reserved word is only one outside a method name's place. */
static void word_state(struct rb_pos *ps, const uint8_t *p, uint32_t s, uint32_t e)
{
	const struct rb_kw *k;

	if (ps->st == RB_FNAME) {
		name_done(ps);
		return;
	}
	if (ps->st == RB_DOT) {
		ps->st = RB_ARG;
		return;
	}
	k = kw_find(p + s, e - s);
	ps->st = k ? k->st : RB_ARG;
	ps->names = k ? k->names : 0u;
	if (k && k->st == RB_FNAME && !k->names)
		ps->defparen = 1;
}

/* "ident" at `i`: a word, its "?" or "!", a label's ":", a setter's "="; the state it leaves. */
static uint32_t scan_word(struct rb_pos *ps, const uint8_t *p, uint32_t n)
{
	uint32_t s = ps->i, e = name_suffix(p, n, word_end(p, n, s));

	if (ps->st == RB_FNAME && e < n && p[e] == '=' &&
	    !(e + 1u < n && (p[e + 1u] == '~' || p[e + 1u] == '>' || (p[e + 1u] == '=' && !(e + 2u < n && p[e + 2u] == '>')))))
		e++;
	else if (ps->st != RB_FNAME && e < n && p[e] == ':' && !(e + 1u < n && p[e + 1u] == ':')) {
		/* a label ("a: 1", "if: 2"): the operand that follows is an operand */
		ps->st = RB_BEG;
		return e + 1u;
	}
	word_state(ps, p, s, e);
	return e;
}

/* A literal found at `i` was delivered or skipped: the position after it. Answers 0 when the sink stopped or, inside a
 * "#{", the literal ran to the end of the text (so nothing can close the interpolation). */
static int literal_done(struct kgenome_ruby_scan *sc, struct rb_pos *ps, const struct kgenome_ruby_lit *lit)
{
	if (sc->depth == 0 && !rb_emit(sc, ps->i, lit->end, KGENOME_TEXTUAL_STRING, lit, lit->open, lit->close))
		return 0;
	ps->i = lit->end;
	ps->st = RB_END;
	return 1;
}

static int space_before(const uint8_t *p, uint32_t i)
{
	return i > 0 && kof_is_space_byte(p[i - 1u]);
}

/* May the "%" or "/" at `ps->i` begin a literal: an operand is expected, or it is the first argument of a command called without
 * brackets (`puts /x/`, `puts %w[a]`: a space before it and none after, and not "/=" or "%="). */
static int literal_may_begin(const struct kgenome_ruby_scan *sc, const struct rb_pos *ps)
{
	const uint8_t *p = sc->p;
	uint32_t i = ps->i, n = sc->n;

	return ps->st == RB_BEG || ps->st == RB_CLASS ||
	       (ps->st == RB_ARG && space_before(p, i) && i + 1u < n && !kof_is_space_byte(p[i + 1u]) && p[i + 1u] != '=');
}

/* The "%" or "/" at `ps->i` is the operator, or "%=" or "/=": an operand is expected after it. */
static void operator_assign(const struct kgenome_ruby_scan *sc, struct rb_pos *ps)
{
	uint32_t i = ps->i;

	ps->i = i + 1u + (i + 1u < sc->n && sc->p[i + 1u] == '=');
	ps->st = RB_BEG;
}

/* "%" at `ps->i`: a literal, or the modulo operator. Answers 0 when the sink stopped. */
static int scan_percent(struct kgenome_ruby_scan *sc, struct rb_pos *ps)
{
	struct kgenome_ruby_lit lit;

	if (literal_may_begin(sc, ps) && kgenome_ruby_percent(sc, ps->i, &lit))
		return literal_done(sc, ps, &lit);
	operator_assign(sc, ps);
	return 1;
}

/* "/" at `ps->i`: a regular expression, or division. */
static int scan_slash(struct kgenome_ruby_scan *sc, struct rb_pos *ps)
{
	struct kgenome_ruby_lit lit;

	if (literal_may_begin(sc, ps)) {
		kgenome_ruby_regex(sc, ps->i, &lit);
		return literal_done(sc, ps, &lit);
	}
	operator_assign(sc, ps);
	return 1;
}

/* ":" at `ps->i`: "::", the ternary's colon, or a symbol (whose quote, if any, opens an ordinary string next). */
static void scan_colon(struct rb_pos *ps, const uint8_t *p, uint32_t n)
{
	uint32_t i = ps->i, k;
	uint8_t c = i + 1u < n ? p[i + 1u] : 0u, before = ps->st;

	ps->i = i + 1u;
	ps->st = RB_BEG;
	if (c == ':') {
		ps->i = i + 2u;
		ps->st = RB_DOT;
		return;
	}
	/* after a value it is the ternary's colon; a quote after it is the string of ":\"x\"", lexed as any other */
	if (before == RB_END || c == 0 || kof_is_space_byte(c) || c == '#' || c == '"' || c == '\'')
		return;
	if (kgenome_textual_ident_start(c)) {
		ps->i = name_suffix(p, n, word_end(p, n, i + 1u));
		ps->st = RB_END;
	} else if ((k = c == '@' ? kgenome_ruby_ivar_len(p, n, i + 1u) : c == '$' ? kgenome_ruby_gvar_len(p, n, i + 1u) :
		    op_name(p, n, i + 1u)) != 0) {
		ps->i = i + 1u + k;
		ps->st = RB_END;
	}
}

static uint32_t scan_code(struct kgenome_ruby_scan *sc, uint32_t i);

uint32_t kgenome_ruby_code_nested(struct kgenome_ruby_scan *sc, uint32_t i)
{
	uint32_t e;

	if (sc->depth >= KGENOME_RUBY_DEPTH)
		return 0;
	sc->depth++;
	e = scan_code(sc, i);
	sc->depth--;
	return e;
}

/* The line break at `ps->i`: the statement ends unless the state was waiting for an operand, and the heredocs waiting go. */
static int scan_newline(struct kgenome_ruby_scan *sc, struct rb_pos *ps)
{
	ps->i++;
	ps->defparen = 0;
	/* after a continuation a blank line or a comment line does not end the statement: the form takes both out and the line
	 * the backslash joined would then be the next one, so the text it writes is read that way here too (see the header) */
	if (!ps->cont && (ps->st == RB_END || ps->st == RB_ARG)) {
		ps->st = RB_BEG;
		ps->names = 0;
	}
	if (sc->depth)
		return 1;
	if (sc->nhd)
		return heredoc_bodies(sc, &ps->i);
	return line_start(sc, &ps->i);
}

/* "<" at `ps->i`: "<<" is a heredoc operator where an operand may begin - or after a name with a space before it. */
static void scan_less(struct kgenome_ruby_scan *sc, struct rb_pos *ps)
{
	const uint8_t *p = sc->p;
	uint32_t i = ps->i, n = sc->n, j = 0;
	uint8_t before = ps->st;

	ps->st = RB_BEG;
	ps->i = i + 1u;
	if (i + 1u >= n || p[i + 1u] != '<')
		return;
	ps->i = i + 2u;
	if (before == RB_BEG || (before == RB_ARG && space_before(p, i)))
		j = heredoc_open(sc, i);
	if (j) {
		ps->i = j;
		ps->st = RB_END;
	} else if (ps->i < n && p[ps->i] == '=') {
		ps->i++;
	}
}

/*
 * One byte of code that is none of the literals, by class. Everything here moves `ps` and keeps the state; the
 * quotes, "%", "/", "<", ":", "?" and the words are above.
 */
static void scan_other(struct rb_pos *ps, const uint8_t *p, uint32_t n, uint32_t *braces)
{
	uint32_t i = ps->i, k;
	uint8_t c = p[i];

	if ((ps->st == RB_DOT || ps->st == RB_FNAME) && kof_byte_in_set(c, "+-*/%<>=!~&|^[`") &&
	    (k = op_name(p, n, i)) != 0) {
		/* a method named by an operator: "def /(x)", "a.<<(b)": it is not a literal */
		ps->i = i + k;
		name_done(ps);
	} else if (c == '.') {
		uint32_t e = i;

		while (e < n && p[e] == '.' && e - i < 3u)
			e++;
		ps->i = e;
		ps->st = e - i > 1u ? RB_BEG : RB_DOT;
	} else if (c == '&' && i + 1u < n && p[i + 1u] == '.') {
		ps->i = i + 2u;
		ps->st = RB_DOT;
	} else if (c == '(') {
		ps->i = i + 1u;
		ps->st = RB_BEG;
		ps->parens++;
		if (ps->defparen) {
			ps->defdepth = ps->parens;
			ps->defparen = 0;
		}
	} else if (c == ')' || c == ']') {
		ps->i = i + 1u;
		ps->st = RB_END;
		if (c == ')' && ps->parens) {
			/* the interpreter's grammar sets BEG after a def's parameter list: "def f(a) /x/ end" is a pattern */
			if (ps->parens == ps->defdepth) {
				ps->st = RB_BEG;
				ps->defdepth = 0;
			}
			ps->parens--;
		}
	} else if (c == '{') {
		ps->i = i + 1u;
		ps->st = RB_BEG;
		(*braces)++;
	} else if (c == '}') {
		ps->i = i + 1u;
		ps->st = RB_END;
		*braces -= *braces != 0;
	} else if (c == '@' || c == '$') {
		k = c == '@' ? kgenome_ruby_ivar_len(p, n, i) : kgenome_ruby_gvar_len(p, n, i);
		ps->i = i + (k ? k : 1u);
		ps->st = k ? RB_END : RB_BEG;
	} else if (kof_is_digit(c)) {
		ps->i = word_end(p, n, i);
		ps->st = RB_END;
	} else {
		ps->i = i + 1u;
		ps->st = RB_BEG;
		if (c == '=' || c == ';')
			ps->defparen = 0;       /* "def f = 1" and "def f; (x)" have no parameter list */
	}
}

/* A "#" comment at `ps->i`: delivered (in the text itself), and the position is left at its line's end. */
static int scan_comment(struct kgenome_ruby_scan *sc, struct rb_pos *ps)
{
	uint32_t e = line_end(sc->p, sc->n, ps->i);

	if (sc->depth == 0 && !rb_emit(sc, ps->i, e, KGENOME_TEXTUAL_COMMENT, NULL, 1u, 0))
		return 0;
	ps->i = e;
	return 1;
}

/*
 * The code from `i`. In the text itself (depth 0) it delivers the strings and comments and the code between them and
 * answers the end of the text, or 0 when the sink stopped. Inside "#{" it delivers nothing and answers the offset past
 * the "}" that closes it, or 0 when the text ends first.
 */
static uint32_t scan_code(struct kgenome_ruby_scan *sc, uint32_t i)
{
	const uint8_t *p = sc->p;
	uint32_t n = sc->n, braces = 0;
	struct rb_pos ps = { .i = i, .st = RB_BEG };
	struct kgenome_ruby_lit lit;
	int ok = 1;

	if (sc->depth == 0) {
		uint32_t bom = n >= 3u && p[0] == 0xefu && p[1] == 0xbbu && p[2] == 0xbfu ? 3u : 0u;

		ps.i = bom;
		if (!line_start(sc, &ps.i))
			return 0;
	}
	while (ps.i < n && ok) {
		uint8_t c = p[ps.i];
		uint32_t at = ps.i, k;

		if (!(kof_is_space_byte(c) || c == '#' || c == '\\'))
			ps.cont = 0;
		if ((c == 0 || c == 4u || c == 26u) && sc->depth == 0) {
			/* a NUL, ^D or ^Z where a token would begin ends the program: ripper has no token after it. What follows is delivered as
			 * one string, as the data after __END__ is, so that nothing in it is read as code and the form keeps it. */
			ok = rb_emit(sc, at, n, KGENOME_TEXTUAL_STRING, NULL, 1u, 0);
			ps.i = n;
		} else if (c == '\n') {
			ok = scan_newline(sc, &ps);
		} else if (kgenome_textual_blank(c)) {
			ps.i++;
			while (ps.i < n && (p[ps.i] == ' ' || p[ps.i] == '\t'))   /* indentation and gaps are runs */
				ps.i++;
		} else if (kgenome_textual_ident_start(c)) {
			/* a word is the commonest token, and no byte of it is one of the branches below: tested before them */
			ps.i = scan_word(&ps, p, n);
		} else if (c == '#') {
			ok = scan_comment(sc, &ps);
		} else if (c == '\\') {
			/* a backslash and the byte after it are one thing; a line break as that byte joins the lines, and the
			 * interpreter reads a heredoc's body from the line after it all the same */
			ps.i = kgenome_textual_skip_escape(p, n, at);
			if (ps.i > at + 1u && p[ps.i - 1u] == '\n') {
				ps.cont = 1;
				if (sc->depth == 0)
					ok = sc->nhd ? heredoc_bodies(sc, &ps.i) : line_start(sc, &ps.i);
			} else {
				ps.cont = 0;
			}
		} else if (c == '\'' || c == '"' || (c == '`' && ps.st != RB_DOT && ps.st != RB_FNAME)) {
			kgenome_ruby_quoted(sc, at, c, &lit);
			ok = literal_done(sc, &ps, &lit);
		} else if (c == '%' && ps.st != RB_DOT && ps.st != RB_FNAME) {
			ok = scan_percent(sc, &ps);
		} else if (c == '/' && ps.st != RB_DOT && ps.st != RB_FNAME) {
			ok = scan_slash(sc, &ps);
		} else if (c == '<' && ps.st != RB_DOT && ps.st != RB_FNAME) {
			scan_less(sc, &ps);
		} else if (c == ':') {
			scan_colon(&ps, p, n);
		} else if (c == '?' && ps.st != RB_END) {
			k = char_literal(p, n, at);
			ps.i = k ? k : at + 1u;
			ps.st = k ? RB_END : RB_BEG;
		} else if (c == '}' && sc->depth && braces == 0) {
			return at + 1u;
		} else {
			scan_other(&ps, p, n, &braces);
		}
	}
	if (!ok)
		return 0;
	if (sc->depth)
		return 0;
	return kgenome_textual_code_to(sc->lx, n) ? n : 0;
}

void kgenome_textual_ruby_lex(struct kgenome_textual_lexer *lx)
{
	struct kgenome_ruby_scan sc = { .lx = lx, .p = lx->p, .n = lx->n };

	if (lx->n)
		(void)scan_code(&sc, 0);
}
