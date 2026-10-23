/*
 * perl_lex.c - the perl lexer: where code is, and what is a string, a comment, a here-document, pod or data.
 *
 * Every rule below was read off perl 5.44 (`perl -c`, `perl -MO=Deparse`, and a run that prints what a construct came to).
 * tests/lib/genome/textual_perl.c has a case for each, `perl(...)` where perl itself confirms it; the lexer was compared with
 * perl on the 2021 .pl and .pm files of the machine it was written on (perl_quote.c's header says how).
 *
 * WHAT PERL'S LEXER KNOWS THAT THIS ONE MUST: whether a TERM or an OPERATOR comes next. "/" is a pattern in the first case and
 * a division in the second, "<<" a here-document or a shift, "%" a hash or a modulus, "{" a block, a hash or a subscript; a
 * word like "s" or "y" is an operator that takes a delimiter, or a bareword key. There is no grammar here: `prev` is the class
 * of the last significant token, set by every token, and is all it asks.
 *   PV_STMT   a statement can begin: the start, after ";", after a "{" that opens a block, after the "}" that closes one, after "LABEL:".
 *   PV_OP     an operator, "(", "[", ",", "=", "?", ":": a term follows.    PV_KW   a word that takes a term (perl_kw.c).
 *   PV_TERM   a value ended: a variable, a number, a string, "]", the "}" of a subscript or a hash, of a do or an eval.
 *   PV_RPAREN ")": an operator follows, and a "{" after it is a block ("if (x) {").
 *   PV_IDENT  a user's name: an operator follows (the lexer cannot know what it was declared to take), a "{" is a block.
 *   PV_ARROW  "->": a method name, a subscript or a postfix dereference follows.   PV_SIGIL  "$" "@" "%" "&" "*" waiting
 *             for the "{" or "$" that is its name's place.
 * "++" and "--" after a term leave it a term ("$i++ / 2"); before one they are operators.
 *
 * BRACES. A "{" is a block after PV_STMT, PV_RPAREN, PV_IDENT and after a word that takes a block (do, eval, sub, else, map,
 * grep, sort); a subscript after a term or "->" (a bareword inside it is a string, "$h{s}"); a dereference after a sigil
 * ("@{...}"); a hash after an operator or after any other word ("return {"). Each is remembered, one bit, to say what its "}" is:
 * after a block a statement can begin (so "=pod" can, and "/x/" is a pattern), after the others, and after the block of a do,
 * an eval or an anonymous sub, a term has ended ("do { 1 } / 2"). PERL_KINDS levels are remembered; beyond them a "}" is read
 * as the end of a term, which is what data nested that deep is. That is a choice of reading, not a loss: nothing but
 * what the kind decides above changes class by it.
 *
 * COMMENTS. "#" to the end of the line - a "\n" only: perl reads CRLF as LF, and a lone CR is a blank - wherever a token can
 * begin. It is not one after "$" ($#a, $#{x}, $#$x), as the delimiter of q s m y tr qq qw qx qr (attached), nor in a string. A
 * "#!" line at byte 0 is a comment the row keeps.
 *
 * POD is "=word" where a statement can begin and the first thing on its line, to a LATER "=cut" line or the end of the text.
 * Perl needs column 0 and the word attached; this needs neither, because at a place where a statement begins an "=" is not code -
 * perl says "syntax error" - and the form moves every line's first token to column 0 and closes up "= word", so a pod that
 * began only there would be read differently by the form's own output (found by running the form on its own output: "= c" at
 * the start of a text became "=c"). The price is a statement read as pod when this lexer thinks a statement begins and one
 * does not: after a "}" it took for a block's. On the corpus no file differs from perl for it.
 *
 * __END__ AND __DATA__ end the program: the rest of the line is code (perl ignores it) and every byte after it is data. The
 * data is one STRING span with no delimiters and no flag, verbatim, because it is neither code nor a comment the form may drop -
 * it can be a payload that a program reads through DATA - and because a "no close" flag would make every script with a data
 * section count as an unclosed literal. A word of that name is the marker wherever a word can be, except after "->", as a key
 * ("{__END__}", "__END__ =>") and as a name. A "format NAME =" line and its picture lines, to the "." line, are one verbatim
 * HERE span (their "#" and "@<<<" are not code); the argument lines in it are code that is not lexed.
 *
 * THE FILE HANDLE OF A PRINT. "print $fh <<EOF" and "print STDERR <<EOF" are here-documents and "$x <<EOF" is a shift: only
 * the word before decides, so after print, printf and say the one token that follows (a bare word, a scalar, a "{...}") is
 * remembered as a handle and "<<" after it may open one. A user's function name before "<<" is read as a list operator too
 * ("warnings::warn <<EOD" in I18N/Collate.pm), and a number or a variable that is not a handle is not.
 *
 * WHAT IS NOT DONE: what a quoted text holds (perl_quote.c's header says why that needs no reading); prototype and signature
 * syntax beyond skipping a prototype; attributes (":lvalue", ":prototype($$)", ":Path('/x')" are code, strings in them are
 * strings, and the form closes up the white space of "prototype( )"); a here-document whose body is cut in two by a quoted
 * text over the line break (perl_quote.c); "print $fh /x/" and "print $x /2", which perl guesses by white space and this reads as
 * a division; and a "?...?" pattern (removed in perl 5.22). [Unverified] a user's sub with a prototype that takes a block ("try {"):
 * the name before "{" is read as a block's.
 *
 * Linear: every byte is read by one token; a look ahead (the "=>" after a word, the ">" after a "<", the end of a "format" line)
 * stops at the end of the line or the white space it skips, and a construct that does not close runs to the end of the text and
 * ends the lexing there. The queue of here-document operators on one line is PERL_HERE_MAX; the one after it is read as the
 * start of a here-document that never closes, to the end of the text.
 */

#include "perl.h"

#define PERL_HERE_MAX 64u       /* operators waiting for a line break: nobody types more on one line */
#define PERL_KINDS 256u         /* braces whose kind is remembered, see above */

enum perl_prev { PV_STMT, PV_OP, PV_KW, PV_TERM, PV_RPAREN, PV_IDENT, PV_ARROW, PV_SIGIL };

struct perl_st {
	struct kgenome_textual_lexer *lx;
	const uint8_t *p;
	uint32_t       n;
	uint32_t       i;
	uint8_t        prev;
	uint8_t        bol;             /* only blanks since the start of the line */
	uint8_t        kw_block;        /* the last word takes a block (1), a block that is a term (2) */
	uint8_t        name_next;       /* the next word is a name (1) or a sub's name (2) */
	uint8_t        proto_ok;        /* a "(" may open a prototype */
	uint8_t        bare_key;        /* just after the "{" of a subscript: a word before "}" is a string */
	uint8_t        print;           /* 1 after print, 2 after the file handle that follows it */
	uint8_t        print_kw, cand, print_force;
	uint8_t        label;           /* the word just read is a label: the ":" after it leaves a statement's place free */
	uint32_t       fh_depth;        /* the depth of the "{" of "print {$fh}", 0 when none */
	uint32_t       depth;
	uint32_t       no_gt;           /* a "<" before here finds no ">" on its line */
	uint64_t       kinds[PERL_KINDS / 64u];
	uint32_t       nhd;
	struct kgenome_textual_perl_here hd[PERL_HERE_MAX];
};

/* Past the blanks from `j`: what a line holds between two tokens, the bytes the form closes up (never a line break). */
static uint32_t blanks(const uint8_t *p, uint32_t n, uint32_t j)
{
	while (j < n && kgenome_textual_blank(p[j]))
		j++;
	return j;
}

static int term_next(uint8_t prev)
{
	return prev == PV_STMT || prev == PV_OP || prev == PV_KW;
}

/* One construct as a STRING span from `at`, and the lexer goes on at `end`. Answers 0 once the sink has stopped. */
static int put_str(struct perl_st *s, uint32_t at, uint32_t end, uint32_t open, uint32_t close, uint8_t flags)
{
	s->i = end;
	return kgenome_textual_span_at(s->lx, at, end, KGENOME_TEXTUAL_STRING, flags, open, close);
}

/* The flag that says a construct did not close, for the ones that have a closing delimiter of their own. */
static uint8_t open_flag(int closed)
{
	return closed ? 0u : KGENOME_TEXTUAL_F_OPEN;
}

/* Is "=>" the next thing after `j`, white space and comments between: the word before it is a string. */
static int fat_after(const uint8_t *p, uint32_t n, uint32_t j)
{
	j = kgenome_textual_perl_skip(p, n, j);
	return j + 1u < n && p[j] == '=' && p[j + 1u] == '>';
}

/*
 * A variable's or a sub's name with "::" in it, and the old package separator: the end of the one that starts at `j`.
 * "$main'win32" and "&www'message(...)" are what the perlasm scripts of openssl and old cgi code write (found by a lexer that
 * took the quote for a string's: x86nasm.pl and webget.pl of the corpus ended OPEN).
 */
static uint32_t name_end(const uint8_t *p, uint32_t n, uint32_t j)
{
	for (;;) {
		while (j < n && kgenome_textual_ident(p[j]))
			j++;
		if (j + 1u < n && p[j] == ':' && p[j + 1u] == ':') {
			j += 2u;
			if (j < n && kgenome_textual_ident(p[j]))
				continue;
		} else if (j + 1u < n && p[j] == '\'' && kgenome_textual_ident_start(p[j + 1u])) {
			j++;
			continue;
		}
		return j;
	}
}

/*
 * A word, with "::" and the old package separator "'" in it. A "'" and a letter continue a name that is not a perl
 * word: perl 5.44 reads "foo'x'" as foo::x and a quote, and "print'a'" as a string ("print" is a word of its own).
 */
static uint32_t word_end(const uint8_t *p, uint32_t n, uint32_t at)
{
	uint32_t j = at;
	int plain = 1;

	for (;;) {
		while (j < n && kgenome_textual_ident(p[j]))
			j++;
		if (j + 1u < n && p[j] == ':' && p[j + 1u] == ':') {
			/* "s::x" is a substitution with ":" for its delimiter, not a package (perl 5.44, and its toke.c says so for every
			 * quote word); "Foo::s" is a name */
			const struct kgenome_textual_perl_kw_row *r = plain ? kgenome_textual_perl_kw(p + at, j - at) : NULL;

			if (r && r->kind == KGENOME_TEXTUAL_PERL_KW_QUOTE)
				return j;
			plain = 0;
			j += 2u;
			if (j < n && kgenome_textual_ident(p[j]))
				continue;
			return j;
		}
		if (j + 1u < n && p[j] == '\'' && kgenome_textual_ident_start(p[j + 1u]) &&
		    !(plain && kgenome_textual_perl_kw(p + at, j - at))) {
			plain = 0;
			j++;
			continue;
		}
		return j;
	}
}

static void kind_set(struct perl_st *s, uint32_t d, int nonblock)
{
	uint64_t bit = 1ull << (d & 63u);

	if (d >= PERL_KINDS)
		return;
	if (nonblock)
		s->kinds[d >> 6] |= bit;
	else
		s->kinds[d >> 6] &= ~bit;
}

static int kind_get(const struct perl_st *s, uint32_t d)
{
	return d >= PERL_KINDS ? 1 : (int)((s->kinds[d >> 6] >> (d & 63u)) & 1u);
}

/* ---- the bytes that begin a token ---- */

static void tok_open_brace(struct perl_st *s, uint8_t ps)
{
	int block, term = 0;

	switch (s->prev) {
	case PV_STMT:
	case PV_RPAREN:
	case PV_IDENT:
		block = 1;
		break;
	case PV_KW:
		block = s->kw_block != 0;
		term = s->kw_block == 2;        /* do { } eval { } sub { }: the "}" ends a term */
		break;
	default:
		block = 0;
		break;
	}
	kind_set(s, s->depth, !block || term);
	s->depth++;
	s->bare_key = s->prev == PV_TERM || s->prev == PV_ARROW || s->prev == PV_SIGIL;
	if (ps == 1u && !s->fh_depth)
		s->fh_depth = s->depth;
	s->prev = block ? PV_STMT : PV_OP;
	s->i++;
}

static void tok_close_brace(struct perl_st *s)
{
	int block = 1;

	if (s->fh_depth && s->depth == s->fh_depth) {
		s->print_force = 2;
		s->fh_depth = 0;
	}
	if (s->depth) {
		s->depth--;
		block = !kind_get(s, s->depth);
	}
	s->prev = block ? PV_STMT : PV_TERM;
	s->i++;
}

/* "(" after sub or a sub's name: a prototype is only prototype characters (blanks, but no line break: the one a here-document waits for
 * is not skipped), and is code that is skipped whole. */
static uint32_t proto_at(const struct perl_st *s)
{
	uint32_t j = s->i + 1u;

	while (j < s->n && kof_byte_in_set(s->p[j], "$@%&*;\\[]_+ \t"))
		j++;
	return j < s->n && s->p[j] == ')' ? j + 1u : 0;
}

/* A number: the digits and what perl lets into one (0x1f, 1_000, 1e-5, 1.5.6). */
static void tok_number(struct perl_st *s)
{
	const uint8_t *p = s->p;
	uint32_t n = s->n, j = s->i;
	int hex = p[j] == '0' && j + 1u < n && (p[j + 1u] | 0x20u) == 'x';

	if (p[j] == '.')
		j++;
	for (;;) {
		while (j < n && kgenome_textual_ident(p[j]))
			j++;
		if (j + 1u < n && p[j] == '.' && kof_is_digit(p[j + 1u])) {
			j++;
			continue;
		}
		if (!hex && j + 1u < n && (p[j - 1u] | 0x20u) == 'e' && (p[j] == '+' || p[j] == '-') && kof_is_digit(p[j + 1u])) {
			j += 2u;
			continue;
		}
		break;
	}
	s->i = j;
	s->prev = PV_TERM;
}

/* "$": a variable, a special one, a dereference or the name's place. */
static void tok_dollar(struct perl_st *s)
{
	const uint8_t *p = s->p;
	uint32_t n = s->n, j = s->i + 1u, k = j;
	uint8_t c, d;

	/* perl lets blanks stand between a sigil and its name ("$ x"): the blanks the form closes up, a CR and a form feed too */
	k = blanks(p, n, k);
	if (k < n && kgenome_textual_ident_start(p[k])) {
		s->i = name_end(p, n, k);
		s->prev = PV_TERM;
		s->cand = 1;
		return;
	}
	s->i = j;
	s->prev = PV_OP;
	if (k > j && k < n && (p[k] == '{' || p[k] == '$'))
		s->prev = PV_SIGIL;
	if (k > j || j >= n)
		return;
	c = p[j];
	d = j + 1u < n ? p[j + 1u] : 0;
	if (c == '{') {
		s->prev = PV_SIGIL;
	} else if (c == '$') {
		if (kgenome_textual_ident_start(d) || d == '{' || d == '$' || (d == ':' && j + 2u < n && p[j + 2u] == ':'))
			s->prev = PV_SIGIL;
		else {
			s->i = j + 1u;
			s->prev = PV_TERM;
		}
	} else if (c == '#') {
		if (d == '{' || d == '$') {
			s->i = j + 1u;
			s->prev = PV_SIGIL;
		} else if (kgenome_textual_ident_start(d)) {
			s->i = name_end(p, n, j + 1u);
			s->prev = PV_TERM;
		} else {
			s->i = j + 1u + (d == '+' || d == '-');
			s->prev = PV_TERM;
		}
	} else if (c == ':' && d == ':' && j + 2u < n && kgenome_textual_ident_start(p[j + 2u])) {
		s->i = name_end(p, n, j);
		s->prev = PV_TERM;
	} else if (kof_is_digit(c)) {
		while (s->i < n && kof_is_digit(p[s->i]))
			s->i++;
		s->prev = PV_TERM;
	} else if (c == '^') {
		s->i = j + 1u + ((uint8_t)(d - 'A') < 26u || kof_byte_in_set(d, "[]\\^_?"));
		s->prev = PV_TERM;
	} else if (kof_byte_in_set(c, "&`'+!@/\\,;.<>()[]|~:?-=%*\"")) {
		/* a special variable: "$'" and "$\"" hold a quote, and the quote is not a string's */
		s->i = j + 1u;
		s->prev = PV_TERM;
	}
}

/* Is the byte at `j` the name of a special variable, in the glob "*" in front of it. Not "$": "*$" and a "$" that has its own
 * name after it are the same bytes, and the glob of the pid - English.pm's "*$<tab>;" - is "*" and "$" and ";" all the same. */
static int glob_punct(const uint8_t *p, uint32_t j)
{
	return kof_byte_in_set(p[j], "\\\"&`'+!@/,;.<>()[]|~:?-=%*^");
}

/*
 * "@", and "%" "&" "*" where a term is expected: a variable, a dereference or the name's place. Elsewhere an operator.
 * Perl lets blanks stand between ANY sigil and its name ("% h", "@ a", "& $c", "* $x": run, each is the variable), so they do
 * here; a "{" or "$" after them is the name's place, and a special name ("%+", "*;") has to be attached.
 */
static void tok_sigil(struct perl_st *s)
{
	const uint8_t *p = s->p;
	uint32_t n = s->n, j = s->i + 1u, k = j;
	uint8_t c = p[s->i], d = j < n ? p[j] : 0, dk;

	if (c != '@' && !term_next(s->prev)) {
		s->i = j + (d == c && (c == '&' || c == '*'));
		s->prev = PV_OP;
		return;
	}
	k = blanks(p, n, k);
	dk = k < n ? p[k] : 0;
	if (c == '&' && d == '&') {
		s->i = j + 1u;
		s->prev = PV_OP;
	} else if (c == '*' && k == j && j < n && glob_punct(p, j)) {
		/* the glob of a special variable, as English.pm writes them: *" *; *, *\ *$ *^W */
		s->i = j + 1u + (d == '^' && j + 1u < n && (uint8_t)(p[j + 1u] - 'A') < 26u);
		s->prev = PV_TERM;
	} else if (c == '%' && d == '^' && j + 1u < n && (uint8_t)(p[j + 1u] - 'A') < 26u) {
		s->i = j + 2u;
		s->prev = PV_TERM;
	} else if (kgenome_textual_ident_start(dk) || (dk == ':' && k + 2u < n && p[k + 1u] == ':' && kgenome_textual_ident_start(p[k + 2u]))) {
		s->i = name_end(p, n, dk == ':' ? k + 2u : k);
		s->prev = PV_TERM;
	} else if (dk == '{' || dk == '$') {
		s->i = j;
		s->prev = PV_SIGIL;
	} else if (k == j && (c == '@' || c == '%') && (d == '-' || d == '+' || (c == '%' && d == '!'))) {
		s->i = j + 1u;
		s->prev = PV_TERM;
	} else {
		s->i = j + (d == c && c == '*');
		s->prev = PV_OP;
	}
}

/* "-": "->", "--", "-=", a file test ("-s $f"), or minus. */
static void tok_minus(struct perl_st *s)
{
	const uint8_t *p = s->p;
	uint32_t n = s->n, j = s->i + 1u;
	uint8_t d = j < n ? p[j] : 0;

	if (d == '>') {
		uint32_t k;

		j++;
		s->prev = PV_ARROW;
		/* a postfix dereference: ->@* ->$* ->%* ->&* ->** ->$#*, and a slice ->@[ ->@{ ->%[ ->%{ (blanks after the arrow too: the
		 * form closes them up, and "-> $#*" must read as "->$#*") */
		k = blanks(p, n, j);
		if (k + 1u < n && kof_byte_in_set(p[k], "@$%&*") && p[k + 1u] == '*') {
			j = k + 2u;
			s->prev = PV_TERM;
		} else if (k + 2u < n && p[k] == '$' && p[k + 1u] == '#' && p[k + 2u] == '*') {
			j = k + 3u;
			s->prev = PV_TERM;
		} else if (k + 1u < n && (p[k] == '@' || p[k] == '%') && (p[k + 1u] == '[' || p[k + 1u] == '{')) {
			j = k + 1u;
			s->prev = PV_TERM;
		}
		s->i = j;
	} else if (d == '-') {
		s->i = j + 1u;
		s->prev = s->prev == PV_TERM || s->prev == PV_RPAREN ? PV_TERM : PV_OP;
	} else if (kof_byte_in_set(d, "rwxoRWXOezsfdlpSbctugkTBMAC") && (j + 1u >= n || !kgenome_textual_ident(p[j + 1u])) &&
		   !fat_after(p, n, j + 1u)) {
		/* perl reads "-s" as the file test wherever it stands, "$x -s/a/b/" is a syntax error in it */
		s->i = j + 1u;
		s->kw_block = 0;
		s->prev = PV_KW;
	} else {
		s->i = j + (d == '=');
		s->prev = PV_OP;
	}
}

/* "+" and the rest of the operators that are one byte or two and decide nothing else. */
static void tok_plus(struct perl_st *s)
{
	const uint8_t *p = s->p;
	uint32_t j = s->i + 1u;
	uint8_t d = j < s->n ? p[j] : 0;

	if (d == '+') {
		s->i = j + 1u;
		s->prev = s->prev == PV_TERM || s->prev == PV_RPAREN ? PV_TERM : PV_OP;
	} else {
		s->i = j + (d == '=');
		s->prev = PV_OP;
	}
}

/* "/": a pattern where a term is expected, else "/", "//", "/=", "//=". */
static int tok_slash(struct perl_st *s)
{
	uint32_t at = s->i, e, close;
	int closed;

	if (term_next(s->prev)) {
		e = kgenome_textual_perl_match(s->p, s->n, at, &closed, &close);
		s->prev = PV_TERM;
		return put_str(s, at, e, 1u, close, open_flag(closed));
	}
	s->i++;
	if (s->i < s->n && s->p[s->i] == '/')
		s->i++;
	if (s->i < s->n && s->p[s->i] == '=')
		s->i++;
	s->prev = PV_OP;
	return 1;
}

/* "<": a here-document, a "<FH>" or "<$fh>" or "<*.c>", a shift, or less than. */
static int tok_less(struct perl_st *s, uint8_t ps)
{
	const uint8_t *p = s->p;
	uint32_t n = s->n, i = s->i, len = 0, e;
	struct kgenome_textual_perl_here h = { 0 };

	if (i + 1u < n && p[i + 1u] == '<') {
		len = kgenome_textual_perl_here_op(p, n, i, &h);
		/* after a term it is a shift - perl 5.44: "$x <<"EOF"" is $x shifted by "EOF", and "3 <<"2"" is 12 - except after the
		 * file handle of a print ("print $fh <<EOF", "print STDERR <<EOF") and after the name of a function
		 * ("warnings::warn <<EOD", found in I18N/Collate.pm: a name is a list operator as often as not; perl
		 * 5.44 reads "f <<EOF" as a here-document when f is a sub it has met). Not with blanks before the quote after a
		 * handle: "print $fh << "A"" is a syntax error in it, and "croak << "EOT"" (File::Temp) is a here-document */
		if (len && (term_next(s->prev) || s->prev == PV_IDENT || (ps == 2u && !h.spaced))) {
			if (s->nhd == PERL_HERE_MAX)
				return put_str(s, i, n, 0, 0, KGENOME_TEXTUAL_F_HERE | KGENOME_TEXTUAL_F_OPEN);
			s->hd[s->nhd++] = h;
			s->prev = PV_TERM;
			/* a quoted tag is text between its quotes - white space in it is the tag's, "<<"    EOT"" - so it is a span of its
			 * own, and a here one: the form does not join it to a literal that follows ("<<"A" . "x"") */
			if (h.quoted)
				return put_str(s, h.off - 1u, i + len, 1u, 1u, KGENOME_TEXTUAL_F_HERE);
			s->i = i + len;
			return 1;
		}
		s->i = i + 2u + (i + 2u < n && p[i + 2u] == '=');
		s->prev = PV_OP;
		return 1;
	}
	if (term_next(s->prev) && i >= s->no_gt) {
		/* the ">" of a glob or readline, on this line: ONE walk, to the first ">" or the line's end. The line's end used to be found first, to the end of the line,
		 * for every "<" - `<a>,<a>,...` on one line cost n^2/2 steps (L6 of the lexer audit) - and a line with no ">" after this "<" has none after the next, which is
		 * remembered (no_gt). */
		uint32_t k = i + 1u;

		while (k < n && p[k] != '>' && p[k] != '\n')
			k++;
		if (k < n && p[k] == '>') {
			s->i = k + 1u;
			s->prev = PV_TERM;
			return 1;
		}
		s->no_gt = k;
	}
	e = i + 1u;
	s->i = e + (e < n && p[e] == '=');
	s->prev = PV_OP;
	return 1;
}

/* A string with the delimiter at `s->i`: ' " ` */
static int tok_string(struct perl_st *s)
{
	uint32_t at = s->i, e = kgenome_textual_perl_delim(s->p, s->n, at);
	uint8_t flags = (uint8_t)(s->p[at] == '\'' ? 0u : KGENOME_TEXTUAL_F_INTERP);

	s->prev = PV_TERM;
	if (!e)
		return put_str(s, at, s->n, 1u, 0, flags | KGENOME_TEXTUAL_F_OPEN);
	return put_str(s, at, e, 1u, 1u, flags);
}

/* "=": the start of pod, or an operator. */
static int tok_equal(struct perl_st *s)
{
	const uint8_t *p = s->p;
	uint32_t i = s->i;

	uint32_t k = blanks(p, s->n, i + 1u);

	if (s->bol && s->prev == PV_STMT && k < s->n && kof_is_alpha(p[k])) {
		uint32_t e = kgenome_textual_perl_pod_end(p, s->n, i);

		s->i = e;
		return kgenome_textual_span_at(s->lx, i, e, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0);
	}
	s->i = i + 1u;
	s->prev = PV_OP;
	return 1;
}

/* A line break in code: the here-documents queued on the line have their bodies next. */
static int here_flush(struct perl_st *s)
{
	const uint8_t *p = s->p;
	uint32_t n = s->n, i = s->i, k, close, end;
	int closed;

	for (k = 0; k < s->nhd; k++) {
		const struct kgenome_textual_perl_here *h = &s->hd[k];
		uint8_t fl = KGENOME_TEXTUAL_F_HERE | (h->interp ? KGENOME_TEXTUAL_F_INTERP : 0u);

		/* the next body begins after the break that ends the last terminator's line (a CRLF's CR is code, outside its span) */
		if (k)
			i += kgenome_textual_eol_at(p, n, i) == 2u ? 2u : (i < n && p[i] == '\n');
		end = kgenome_textual_perl_here_body(p, n, i, h, &close, &closed);
		if (!kgenome_textual_lit(s->lx, i, end, KGENOME_TEXTUAL_STRING, fl, 0, close, closed))
			return 0;
		i = end;
	}
	s->nhd = 0;
	s->i = i;
	return 1;
}

/*
 * A word. Its class decides what comes after it; the quote-like operators and the ends of the program also decide
 * what the bytes after it ARE. Not a keyword: after "->" (a method), as a name, as a key before "=>" or in "{...}",
 * and with "::" in it.
 */
static int tok_word(struct perl_st *s, uint8_t nn, uint8_t bk, uint8_t ps)
{
	const uint8_t *p = s->p;
	uint32_t n = s->n, at = s->i, e = word_end(p, n, at), after;
	const struct kgenome_textual_perl_kw_row *k = NULL;
	int fat, key, arrow = s->prev == PV_ARROW;

	after = kgenome_textual_perl_skip(p, n, e);
	fat = fat_after(p, n, e);
	key = bk && after < n && p[after] == '}';
	if (!fat && !key && !nn && !arrow)
		k = kgenome_textual_perl_kw(p + at, e - at);
	s->i = e;
	if (!k) {
		/* "LABEL: {": a bare block is not a hash, and a statement begins after the colon */
		s->label = s->prev == PV_STMT && !fat && !key && !nn && after + 1u < n && p[after] == ':' && p[after + 1u] != ':';
		s->prev = fat || key ? PV_TERM : PV_IDENT;
		s->proto_ok = nn == 2u;
		s->cand = !fat && !arrow;
		return 1;
	}
	s->kw_block = k->block;
	switch (k->kind) {
	case KGENOME_TEXTUAL_PERL_KW_TERM:
		s->prev = PV_TERM;
		break;
	case KGENOME_TEXTUAL_PERL_KW_PRINT:
		s->print_kw = 1;
		s->prev = PV_KW;
		break;
	case KGENOME_TEXTUAL_PERL_KW_SUB:
		s->name_next = 2;
		s->proto_ok = 1;
		s->prev = PV_KW;
		break;
	case KGENOME_TEXTUAL_PERL_KW_NAME:
		s->name_next = 1;
		s->prev = PV_KW;
		break;
	case KGENOME_TEXTUAL_PERL_KW_FORMAT: {
		uint32_t h = s->prev == PV_STMT ? kgenome_textual_perl_format_head(p, n, e) : 0, close, end;

		s->prev = PV_KW;
		if (!h)
			break;
		/* the line that names the format is code; the picture lines, to the "." line, are text */
		end = kgenome_textual_perl_format_body(p, n, h, &close);
		s->prev = PV_STMT;
		return put_str(s, h, end, 0, close, (uint8_t)(KGENOME_TEXTUAL_F_HERE | open_flag(close != 0)));
	}
	case KGENOME_TEXTUAL_PERL_KW_END: {
		const uint8_t *nl = memchr(p + e, '\n', n - e);
		uint32_t ds = nl ? (uint32_t)(nl - p) + 1u : n;

		s->prev = PV_STMT;
		if (ds >= n) {
			s->i = n;
			return 1;
		}
		return put_str(s, ds, n, 0, 0, 0);
	}
	case KGENOME_TEXTUAL_PERL_KW_QUOTE: {
		uint32_t open = 0, close = 0, qe;
		int closed;

		/*
		 * After a term a quote word is no operator: an operand cannot follow an operand, and the letters of a pattern's flags
		 * ("s@a@b@s ) {") or a word the form closed up against it ("m;x;s") are not the start of another. Not after a print's file
		 * handle, which is a term and is followed by one ("print $fh q{x}").
		 */
		if ((s->prev == PV_TERM || s->prev == PV_RPAREN) && ps != 2u) {
			/* a term still: what follows reads as it does after the flags that the same letters are when attached */
			s->prev = PV_TERM;
			break;
		}

		/* "-s" is the file test, not s/// ("$x -s/a/b/" is a syntax error in perl) */
		if (e - at == 1u && p[at] == 's' && at && p[at - 1u] == '-') {
			s->prev = PV_KW;
			break;
		}
		qe = kgenome_textual_perl_quote(p, n, at, e - at, k->arg, &closed, &open, &close);
		s->prev = PV_TERM;
		if (!qe)
			break;
		return put_str(s, at, qe, open, close,
			       (uint8_t)((kgenome_textual_perl_op_interp(k->arg, p[at + open - 1u]) ? KGENOME_TEXTUAL_F_INTERP : 0u) |
					 open_flag(closed)));
	}
	default:
		s->prev = PV_KW;
		break;
	}
	return 1;
}

void kgenome_textual_perl_lex(struct kgenome_textual_lexer *lx)
{
	struct perl_st s = { .lx = lx, .p = lx->p, .n = lx->n, .bol = 1 };
	const uint8_t *p = s.p;
	uint32_t n = s.n;

	while (s.i < n) {
		uint8_t c = p[s.i], ps, nn, po, bk, lab;
		int ok = 1;

		if (c == '\n') {
			s.i++;
			s.bol = 1;
			if (s.nhd && !here_flush(&s))
				return;
			continue;
		}
		if (kgenome_textual_blank(c)) {
			s.i++;
			continue;
		}
		if (c == '#') {
			uint32_t j = s.i;

			while (j < n && p[j] != '\n')
				j++;
			if (!kgenome_textual_span_at(lx, s.i, j, KGENOME_TEXTUAL_COMMENT, 0, 1u, 0))
				return;
			s.i = j;
			continue;
		}
		ps = s.print;
		nn = s.name_next;
		po = s.proto_ok;
		bk = s.bare_key;
		lab = s.label;
		s.print = s.name_next = s.proto_ok = s.cand = s.bare_key = s.label = 0;
		if (c == '\'' || c == '"' || c == '`')
			ok = tok_string(&s);
		else if (c == '$')
			tok_dollar(&s);
		else if (c == '@' || c == '%' || c == '&' || c == '*')
			tok_sigil(&s);
		else if (kof_is_digit(c) || (c == '.' && term_next(s.prev) && s.i + 1u < n && kof_is_digit(p[s.i + 1u])))
			tok_number(&s);
		else if (kgenome_textual_ident_start(c))
			ok = tok_word(&s, nn, bk, ps);
		else if (c == '/')
			ok = tok_slash(&s);
		else if (c == '<')
			ok = tok_less(&s, ps);
		else if (c == '=')
			ok = tok_equal(&s);
		else if (c == '-')
			tok_minus(&s);
		else if (c == '+')
			tok_plus(&s);
		else if (c == '{')
			tok_open_brace(&s, ps);
		else if (c == '}')
			tok_close_brace(&s);
		else if (c == '(') {
			uint32_t e = po ? proto_at(&s) : 0;

			s.i = e ? e : s.i + 1u;
			s.prev = e ? PV_RPAREN : PV_OP;
		} else if (c == ')') {
			s.i++;
			s.prev = PV_RPAREN;
		} else if (c == ']') {
			s.i++;
			s.prev = PV_TERM;
		} else if (c == ';') {
			s.i++;
			s.prev = PV_STMT;
		} else if (c == ':' && s.i + 2u < n && p[s.i + 1u] == ':' && kgenome_textual_ident_start(p[s.i + 2u])) {
			/* "::name" is a name of its own, and so is not a quote word or a marker: "p ::s" and "p::s" must read alike */
			s.i = word_end(p, n, s.i + 2u);
			s.prev = PV_IDENT;
		} else if (c == ':') {
			s.i++;
			s.prev = lab ? PV_STMT : PV_OP;
		} else {
			s.i++;
			s.prev = PV_OP;
		}
		if (!ok)
			return;
		s.bol = 0;
		if (s.print_kw) {
			s.print = 1;
			s.print_kw = 0;
		} else if (ps == 1u && s.cand) {
			s.print = 2;
		}
		if (s.print_force) {
			s.print = s.print_force;
			s.print_force = 0;
		}
	}
	kgenome_textual_code_to(lx, n);
}
