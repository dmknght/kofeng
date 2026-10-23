/*
 * perl_lang.c - the row for perl: its lexer, what closing up two tokens would change, the decoders a script calls on
 * its own literals, and what the form needs to know.
 *
 * WHITE SPACE IS NOT SYNTAX IN PERL except in the places `glue` lists, so the form closes it up and keeps a line break
 * (a statement does not end at one, but a "#" comment, a here-document and pod are about lines). `join_brace`,
 * `continuation` and `universal_eol` stay off: "{" on its own line is the same program, a backslash at the end of a line is
 * not a continuation, and a lone CR is a blank. `value` and `unescape_str` are perl_value.c and perl_esc.c.
 *
 * THERE IS NO `concat`, on purpose, and the reason is measured. The form joins two literals by their TEXT - the first's bytes
 * without its closing delimiter, the second's without its opening one - which is one literal in php or python and is not in perl:
 *   - "$a" . "b" is the variable $a and "b", and "$ab" is another variable. Counted on the 2021 files of /usr, 449 joins of
 *     two double quoted literals, 5 of them (all in ExtUtils/Constant/Base.pm: "if ($name_param" . "[$check] ..." is an element,
 *     joined) change what they say; of 168 joins in the 652 other files, 12 do;
 *   - a quote-like operator is not a string: m/a/ . m/b/, qw(a) . qw(b) and `a` . `b` (two commands) are not m/ab/, qw(ab) and
 *     `ab`, and y;;; . y;;<tab>; (found by the form-of-form property) is written as something neither pass reads alike.
 * The row has no hook to say "not these" (a `join_ok(a, b)` in textual_form.c's fold_held is what it would take, and is
 * a change to that file), so the joins are left as typed: "ev" . "al" is not folded and decode_base64("a" . "b") is not
 * offered to a decoder. Turning `.concat = '.'` on is the one line that restores both.
 */

#include "perl.h"

/*
 * WOULD CLOSING THESE TWO UP CHANGE WHAT THE LEXER READS (the byte before the gap, the byte after it). Every line is a
 * case perl 5.44 or the form's own output found, and the oracle (`perl -MO=Deparse` of the text and of its form) is the judge:
 *   - an operator and what makes a longer one: "+ +" "- -" "* *" "/ /" ". ." ": :" "& &" "| |" "< <" "> >" "= =" "~ ~", and "="
 *     after any operator byte ("+=" "<=" "!=" "||=" ".="), "=~" "=>" "!~" "->". A digit then "." is a decimal point, and a digit
 *     then "(" is not a call ("use CPAN 1.80 ();" is not "1.80()").
 *   - "-" and a letter that is a file test: "- s/a/b/" is a minus and a substitution, "-s/a/b/" is a file test, which is what
 *     perl reads wherever "-s" stands (`$x -s/a/b/` is a syntax error in it).
 *   - a sigil and what follows: "$ ;" is "$" and ";" and "$;" is a variable; "$$ if" is the pid and "$$if" is "$" and $if;
 *     "$# +" is not "$#+" (the last index of @+), "$^ [" is not "$^[". A name after
 *     a sigil other than "$" closes up: perl reads "% h" and "@ a" as %h and @a, and so does the lexer.
 *   - a name and "'": "foo 'x'" is a name and a string, "foo'x'" is the name foo::x and a quote.
 *   - a name and ":": "p ::s" is not "p::s", and "%overload:: and" is not "%overload::and".
 *   - a word and a sigil, a quote or a backslash: "print $fh $x" and "print $fh "x"" are errors with the space gone ("Scalar found
 *     where operator expected"), because the handle is a variable and only the white space tells it from an operand. The row cannot
 *     tell a handle from another word, so the space stays after every word: "my $x" and "return "x"" keep theirs, which costs a
 *     byte, and "print$x" does not become the form of "print $x".
 *   - "<" before a tag or a quote, and a name or "\" before "<<": "<< EOF" is not a here-document and "<<EOF" is, "print $out <<EOT"
 *     is one and "print $out<<EOT" a shift, "<<\ EOF" is not "<<\EOF".
 *   - a closing delimiter and a word: "m/x/ if $y" has white space where "m/x/if" is an error ("Unknown regexp modifier /f": every
 *     letter after a pattern is read as a flag, valid or not; "s/^&//foreach @_" in Exporter/Heavy.pm was the first to say so). A
 *     pattern can close with any byte; / ) ] } > ! | # , : % are the ones in the corpus with a word after them ("s,a,b,or ref",
 *     "m:^/:s", "m%x% and"), and are the ones the lexer reads flags behind (perl_quote.c, flags_end). The others (; = - + . & * ~ ^ @ " ')
 *     are 2 to 11 constructs each in the 2700 files, one of them with a word after it ("s&a&b& and" in os2/backwardify.pl): a space is
 *     not kept there, and the form changes that one.
 * "print FH (...)" is NOT one of these any more, and is kept by `glue_tail` below (L16 of the lexer audit): "FH(" is a call and "FH (" a handle - perl -MO=Deparse
 * says `print FH 1` and `print FH(1)` - and the form closed the blank up, which changed the program on the 8 of 2700 files that write it ("print FILEHANDLE (" in the avis
 * code). What stays closed up is the blank before "(" everywhere else - "if (" and "if(" are one form - and after "$fh" ("print $fh (1)" and "print $fh(1)" are the same to perl).
 */
static int perl_glue(uint8_t a, uint8_t b)
{
	if (kgenome_textual_glue_assign(a, b, "+-*/%.&|^<>!=:~") || kgenome_textual_glue_twice(a, b, "+-*/.:&|<>=~"))
		return 1;
	if ((a == '=' && (b == '~' || b == '>')) || (a == '!' && b == '~') || (a == '-' && b == '>'))
		return 1;
	if (kgenome_textual_ident(a) && (b == '<' || b == ':' || b == '\''))
		return 1;
	if (kof_is_digit(a) && (b == '.' || b == '('))
		return 1;
	if (a == '-' && kof_byte_in_set(b, "rwxoRWXOezsfdlpSbctugkTBMAC"))
		return 1;
	if (kof_byte_in_set(a, "$@%&*") && !kgenome_textual_ident(b) && b != '{' && b != '$')
		return 1;
	if (a == '$' && (kgenome_textual_ident(b) || b == '$'))
		return 1;
	if (a == '#' && kof_byte_in_set(b, "+-{$*"))
		return 1;
	if ((a == '^' && ((uint8_t)(b - 'A') < 26u || kof_byte_in_set(b, "[]\\^_?"))) ||
	    (a == '\\' && kgenome_textual_ident(b)))
		return 1;
	if (kgenome_textual_ident(a) && kof_byte_in_set(b, "$@%&\"`\\"))
		return 1;
	if (a == '<' && (kgenome_textual_ident(b) || kof_byte_in_set(b, "\"'`~\\")))
		return 1;
	if (a == ':' && kgenome_textual_ident(b))
		return 1;
	return kof_byte_in_set(a, "/)]}>!|#,:%") && kgenome_textual_ident(b);
}

/* A blank in front of "(" that is kept: the last word of the code written so far is a bareword and the word before it is print, printf or say, so the bareword is a handle
 * and the blank says so (`tail` has no white space but the one blank between two words: "print FH"; "print$fh" has none, `$fh` is not a bareword). Only a blank that was typed
 * is asked about: none is written. */
static int perl_glue_tail(const uint8_t *tail, uint32_t n, uint8_t next)
{
	static const char *const verb[] = { "print", "printf", "say" };
	uint32_t e = n, w, k;

	if (next != '(')
		return 0;
	while (e && (kgenome_textual_ident(tail[e - 1u]) || tail[e - 1u] == ':'))
		e--;
	if (e == n || !e || tail[e - 1u] != ' ')
		return 0;
	e--;                                                    /* the blank between the two words */
	for (w = e; w && kgenome_textual_ident(tail[w - 1u]); w--)
		;
	if (w && (tail[w - 1u] == '$' || tail[w - 1u] == '@' || tail[w - 1u] == '%' || tail[w - 1u] == '>' || tail[w - 1u] == ':'))
		return 0;                                       /* $print, @say, ->print, ::print: a name of something else */
	for (k = 0; k < sizeof verb / sizeof verb[0]; k++)
		if (e - w == strlen(verb[k]) && !memcmp(tail + w, verb[k], e - w))
			return 1;
	return 0;
}

/*
 * THE DECODERS, as they are written, read by the name. Perl calls a function by name with the literal as its
 * first argument, and only these really exist in the language or its core modules (checked with `perl -M`):
 *   - MIME::Base64 (core): decode_base64, and MIME::Base64::decode, its alias (the bare "decode" is Encode's and a dozen
 *     others', so only the qualified spelling is a row: "Base64x.decode" below, see the walk);
 *   - Compress::Zlib (core): uncompress is zlib's (RFC 1950), memGunzip gzip's (it takes a gzip member);
 *   - URI::Escape (CPAN, not installed here, [Unverified] from its documentation): uri_unescape. It leaves "+" as it
 *     is where the url decoder the hook runs turns it into a space, so a value with one is not offered (payload_ok).
 * NOT EXPRESSIBLE, and so not here: pack("H*", "4142") and unpack("u", ...) name their coding in an argument BEFORE the
 * literal, and the chain reads the code in front of the literal for "(" and a name; a call written with no
 * parentheses ("decode_base64 'x'") has no "("; scalar reverse("abc") is a reversal only in scalar context, which the
 * text does not say; decode_base64url reads another alphabet than the base64 decoder the hook runs [Unverified
 * whether that one refuses a "-" or "_"]; an inflate stream (Compress::Zlib::inflateInit) is an object; tr/// is not a call.
 */
static const struct kgenome_textual_decoder_row decoder_row[] = {
	{ "Base64x.decode",  KGENOME_TEXTUAL_DEC_B64 },
	{ "decode_base64",   KGENOME_TEXTUAL_DEC_B64 },
	{ "memGunzip",       KGENOME_TEXTUAL_DEC_GZIP },
	{ "uncompress",      KGENOME_TEXTUAL_DEC_ZLIB },
	{ "uri_unescape",    KGENOME_TEXTUAL_DEC_RAWURL },     /* keeps "+" [Unverified: URI::Escape is not installed here; its documentation says so] */
};

/* Names are case sensitive, there is no "@" and no leading "\"; "Module::name" is how a call is qualified (read below). */
static const struct kgenome_textual_call_style style = {
	.rows = decoder_row, .n_rows = sizeof decoder_row / sizeof decoder_row[0], .qualify = '.',
};

/*
 * "MIME::Base64::decode_base64(" has "::" where the walk knows one byte to qualify a name with. The code is read
 * from a copy in which each "::" is "x." (same length, so `*from` is an offset in the original): "x" is a name byte and "."
 * the qualifier, and the walk then reads "MIMEx.Base64x.decode_base64" as one qualified name, takes the last words that
 * match a row, and begins the outermost call at the "M". A "." typed in the code is a qualifier too ("$a.decode_base64(": the
 * name starts at "a", and the "$" stays in front): perl's "." joins strings, and the call is still decode_base64's.
 */
static uint32_t perl_call_chain(const uint8_t *tail, uint32_t n, uint8_t *chain, uint32_t cap, uint32_t *from)
{
	uint8_t buf[256];
	uint32_t skip = n > sizeof buf ? n - (uint32_t)sizeof buf : 0, m = n - skip, i, k;

	memcpy(buf, tail + skip, m);
	for (i = 0; i + 1u < m; i++) {
		if (buf[i] == ':' && buf[i + 1u] == ':') {
			buf[i] = 'x';
			buf[i + 1u] = '.';
			i++;
		}
	}
	k = kgenome_textual_call_chain(&style, buf, m, chain, cap, from);
	*from += skip;
	return k;
}

/* A single quoted string: only the quote and the backslash are read, as in php's, and every other byte, a line break too, is itself. */
static const struct kgenome_textual_quote quote = { .q = '\'', .bs = "\\" };

const struct kgenome_textual_lang kgenome_textual_lang_perl = {
	.name = "perl",
	.id = KGENOME_TEXTUAL_LANG_PERL,
	.gap_comments = KGENOME_TEXTUAL_GAP_HASH,
	.lex = kgenome_textual_perl_lex,
	.glue = perl_glue,
	.glue_tail = perl_glue_tail,
	.keep_hashbang = 1,
	.unescape_str = kgenome_textual_perl_unescape,
	.call_chain = perl_call_chain,
	.fn_table = &kgenome_textual_perl_fn_table,
	.value = kgenome_textual_perl_value,
	.quote = &quote,
};
