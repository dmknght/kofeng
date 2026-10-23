/*
 * genome / textual_ruby - the ruby lexer and form of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED, and what each part is evidence of:
 *
 *   (a) KNOWN ANSWERS (textual_ruby_cases.h), one per rule with the neighbour it could be confused for. A case is the text and
 *       the one line it must come out as (kind letter, bytes in braces; S* = escapes the form may write, S! = not closed,
 *       S# = a heredoc body - see textual_check.h). `rb(...)` is a case ruby 3.3.8's own lexer agrees with, span for span: a
 *       scratch script outside the tree reads this file's case table, lexes every `rb(` text with `Ripper` and compares;
 *       `rbx(...)` is a case no interpreter confirms, and says why where it is.
 *   (b) A GENERATOR of ruby programs (textual_ruby_gen.h). Tokens of known class - code, literal (every kind, with
 *       interpolations to depth three), heredoc (one to three on a line), comment, block comment, __END__ - are laid out with
 *       the operators that are ambiguous written where there is only one reading, in one of two line-ending styles, and the
 *       lexer's spans must equal what the generator wrote, byte for byte: kind, offset, length, delimiters and the flags. The
 *       form of each program must be its own form, fit its cap, keep every literal's value, and keep no comment. The
 *       programs are valid ruby: a scratch program includes the generator, writes N of them to disk, `ruby -c` and `Ripper`
 *       read each and ripper's string and comment tokens are compared with what the generator knew. The numbers of that run
 *       and of the run over the files of the machine are a measurement and are in the report, not here: a comment that
 *       carries one goes stale.
 *   (c) THE PARTITION and the idempotence of the form on random text from a ruby alphabet and from fragments of the
 *       language, a text cut at every length, nesting past the bound, and hostile texts read in time linear in them.
 *   (d) FORM, VALUE and decoder known answers; the decode hook is a fake decoder (the contract is what is asserted, not an
 *       algorithm). The form's spelled-out bytes were checked against ruby's own eval: a scratch program evaluates the text and
 *       its form and compares what they hold.
 *
 * Everything goes through <kgenome.h> and nothing else: a test of a language is a test of the API.
 */

#include "textual_check.h"

#include <time.h>

#define RB KGENOME_TEXTUAL_LANG_RUBY

static void rb(const char *src, const char *want)
{
	expect_lang(RB, src, want);
}

/* Not confirmed by the interpreter here: the reason is the comment at the call. */
static void rbx(const char *src, const char *want)
{
	expect_lang(RB, src, want);
}

#include "textual_ruby_cases.h"
#include "textual_ruby_gen.h"

/* ---- (d) the form ---- */

static void fm(const char *src, const char *want)
{
	form_lang(RB, src, want);
}

static void forms(void)
{
	fm("", "");
	/* white space between two tokens is syntax in ruby - "puts -x" is a call, "puts - x" a subtraction, "foo /x/" a pattern and
	 * "foo / x" a division - so one space stays wherever there was any (and never more, and none where there was none); the
	 * indentation, the blank lines and the comments go, and a line break stays one. Not `glue`: a space kept before "-" and
	 * dropped after it would turn "a - 1" into "a -1". */
	/* lines and spacing */
	fm("x  =  1   # c\n\n\n  y = 2\n", "x = 1\ny = 2");
	fm("puts   \"a\"  \n  puts  /re/   # c\n", "puts \"a\"\nputs /re/");
	fm("foo( 1 ,2 )  \n", "foo( 1 ,2 )");
	fm("class A  <  B\n  def  f( a )\n    a  +  1\n  end\nend\n", "class A < B\ndef f( a )\na + 1\nend\nend");
	fm("# only\n", "");
	fm("\fx = 1\n\t\n  # c\n", "x = 1");
	fm("x = a  # c1\n# c2\n\n# c3\ny = 2", "x = a\ny = 2");
	fm("x = 1;;  y = 2", "x = 1;; y = 2");
	/* a comment is a gap */
	fm("a # c\nb", "a\nb");
	fm("x = (a #c\n  + b)", "x = (a\n+ b)");
	/* white space is syntax: one space stays wherever there was any */
	fm("a ? b : c\nx = y ?1:2\nputs -x\nputs - x\nfoo /x/\nfoo / x\n", "a ? b : c\nx = y ?1:2\nputs -x\nputs - x\nfoo /x/\nfoo / x");
	fm("puts (1)\nputs(1)\nfoo [1]\nfoo[1]\nputs %w[a]\nx = a % b", "puts (1)\nputs(1)\nfoo [1]\nfoo[1]\nputs %w[a]\nx = a % b");
	/* line breaks */
	fm("x = [1,  2]\r\ny = {a:   1}\r\n", "x = [1, 2]\ny = {a: 1}");
	fm("x = 1 # c\r\ny = 2\r\n", "x = 1\ny = 2");
	fm("x = 1\ry = 2", "x = 1 y = 2");
	fm("x = 1 + \\\n   2\ny = 3", "x = 1 + \\\n 2\ny = 3");
	fm("x = 1 + \\\r\n   2\r\ny = 3\r\n", "x = 1 + \\\r\n2\ny = 3");
	/* the interpreter line stays, the other comments go */
	fm("#!/usr/bin/env ruby\n# c\nx = 1\n", "#!/usr/bin/env ruby\nx = 1");
	fm("# frozen_string_literal: true\nx = 1", "x = 1");
	/* block comments and __END__ */
	fm("=begin\ncomment\n=end\nputs 1\n", "puts 1");
	fm("puts 1\n=begin\nc\n=end\nputs 2", "puts 1\nputs 2");
	fm("puts 1\n__END__\ndata  here  \n\n", "puts 1\n__END__\ndata  here  \n\n");
	fm("puts 1\n  =begin\nx\n  =end\nputs 2", "puts 1\n=begin\nx\n  =end\nputs 2");
	/* literals are every byte of themselves */
	fm("puts \"a#{ x  +  1 }b\"   # c\n", "puts \"a#{ x  +  1 }b\"");
	fm("x = 'a   b' + \"c   d\"  # c", "x = 'a   b' + \"c   d\"");
	fm("x = %w[ a   b ] + %q(c   d)", "x = %w[ a   b ] + %q(c   d)");
	fm("x = /a   b/i  # c", "x = /a   b/i");
	fm("x = <<~A   # c\n    a  b  \n  c\nA\ny = 1", "x = <<~A\n    a  b  \n  c\nA\ny = 1");
	fm("puts <<A, <<'B'\n  one \nA\n  two #{x} \nB\nputs 3", "puts <<A, <<'B'\n  one \nA\n  two #{x} \nB\nputs 3");
	fm("x = \"a\n   b\" # c", "x = \"a\n   b\"");
	/* what is not closed is kept as typed */
	fm("x = 'abc", "x = 'abc");
	fm("x  =  \"a#{ b", "x = \"a#{ b");
	fm("x\n=begin\nabc  d", "x\n=begin\nabc  d");
	fm("puts <<A\n  no end  ", "puts <<A\n  no end  ");
	/* character literals, symbols and variables with a quote in them */
	fm("x = ?a + ?\" # c\ny = :\"a b\"  # c", "x = ?a + ?\"\ny = :\"a b\"");
	fm("puts $'  # c\nputs $\"\nx = $` + \"a\" # '", "puts $'\nputs $\"\nx = $` + \"a\"");
}

/* The spelled-out bytes of a ruby literal, written as themselves where ruby reads them as an escape in a literal that escapes. Each
 * case below was evaluated with ruby, the text and its form, and holds the same value. */
static void unescapes(void)
{
	/* spelled-out bytes are written as themselves */
	fm("x = \"\\x65\\x76\\x61\\x6c\" + \"\\101\\102\"", "x = \"eval\" + \"AB\"");
	fm("x = \"\\x41B\\x4a\\x4A\\x4\"", "x = \"ABJJ\\x4\"");
	fm("x = \"\\u0041\\u{42}\\u{0043}\\u{41 42}\\u00e9\"", "x = \"ABC\\u{41 42}\\u00e9\"");
	fm("x = %Q(\\x43) + %(\\x44) + %W[\\x41 \\x42].join + :\"\\x45\".to_s", "x = %Q(C) + %(D) + %W[\\x41 \\x42].join + :\"E\".to_s");
	/* spelled-out bytes are written as themselves, in a command */
	fm("x = `echo \\x41` + %x(echo \\102)", "x = `echo A` + %x(echo B)");
	/* spelled-out bytes are written as themselves */
	fm("x = <<A\n\\x41\\101\nA\ny = <<~B\n  \\x41\\x20z\nB\n", "x = <<A\n\\x41\\101\nA\ny = <<~B\n  \\x41\\x20z\nB");
	fm("x = :\"\\x41\".to_s + ?\\x41", "x = :\"A\".to_s + ?\\x41");
	/* an escape that is not an escape here stays as typed */
	fm("x = '\\x41\\101' + %q(\\x41) + %w[\\x41].join + %s(\\x41).to_s\ny = [/\\x41/, %r(\\x41)].map(&:source).join", "x = '\\x41\\101' + %q(\\x41) + %w[\\x41].join + %s(\\x41).to_s\ny = [/\\x41/, %r(\\x41)].map(&:source).join");
	fm("x = \"\\n\\t\\s\\e\\a\\M-a\\C-a\\cA\\\\x41\\\\\\x41\"", "x = \"\\n\\t\\s\\e\\a\\M-a\\C-a\\cA\\\\x41\\\\A\"");
	/* what would change the literal is not written */
	fm("x = \"\\x22\\x27\\x5c\\x23\\x40\\x24\\x7b\\x7d\\x60\\x00\\x7f\\x01\\x80\\xff\"", "x = \"\\x22\\x27\\x5c\\x23\\x40\\x24\\x7b\\x7d\\x60\\x00\\x7f\\x01\\x80\\xff\"");
	fm("x = \"\\x23{y}\\x23@a\\x23$b\" + \"\\x23\\x7b\"", "x = \"\\x23{y}\\x23@a\\x23$b\" + \"\\x23\\x7b\"");
	fm("x = %Q(\\x28\\x29) + %Q[\\x5b\\x5d] + %Q<\\x3c\\x3e> + %Q|\\x7c| + %(\\x28\\x29\\x41)", "x = %Q(\\x28\\x29) + %Q[\\x5b\\x5d] + %Q<\\x3c\\x3e> + %Q|\\x7c| + %(\\x28\\x29A)");
	fm("x = <<A\n\\x20\\x41\\x09\nA\ny = <<~B\n  \\x20z\nB\n", "x = <<A\n\\x20\\x41\\x09\nA\ny = <<~B\n  \\x20z\nB");
	/* two neighbours can still change what a written byte means */
	fm("x = \"\\0\\x31\" + \"\\1\\x32\" + \"\\01\\x33\" + \"\\x4\\x61\" + \"\\x4\\x67\"", "x = \"\\0\\x31\" + \"\\1\\x32\" + \"\\01\\x33\" + \"\\x4\\x61\" + \"\\x4g\"");
	fm("x = \"\\x41\\x31\\0\\x41\\x31\"", "x = \"A1\\0A1\"");
	/* values that are not a byte */
	fm("x = \"\\777\\400\\u0100\\u00e9\\u{e9}\"", "x = \"\\777\\400\\u0100\\u00e9\\u{e9}\"");
}

/* ---- VALUE ---- */

struct first {
	struct kgenome_textual_span sp;
	int found;
};

static int first_sink(void *u, const struct kgenome_textual_span *s)
{
	struct first *f = u;

	if (!f->found && s->kind == KGENOME_TEXTUAL_STRING) {
		f->sp = *s;
		f->found = 1;
	}
	return 1;
}

/* The value of the first literal of `src` through the public API: the `n` bytes `want`, or NULL for "has none". */
static void val(const char *src, const char *want, uint32_t n)
{
	struct first f = { .found = 0 };
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = RB,
					      .sink = first_sink, .user = &f };
	struct kgenome_textual_lex_res rs;
	uint8_t out[512];
	struct kgenome_textual_value_req vq;
	struct kgenome_textual_value_res vs;
	enum kgenome_textual_status st;

	(void)kgenome_textual_lex(&rq, &rs);
	if (!f.found) {
		printf("  FAIL value: no literal in  %s\n", src);
		fails++;
		return;
	}
	vq = (struct kgenome_textual_value_req){ .lang = RB, .lit = (const uint8_t *)src + f.sp.off, .len = f.sp.len,
						 .open_len = f.sp.open_len, .close_len = f.sp.close_len, .flags = f.sp.flags,
						 .out = out, .cap = sizeof out };
	st = kgenome_textual_value(&vq, &vs);
	if (!want ? st != KGENOME_TEXTUAL_NO_VALUE : (st != KGENOME_TEXTUAL_OK || vs.n_out != n || memcmp(out, want, n))) {
		printf("  FAIL value of  %s  (status %d, %u bytes)\n", src, (int)st, vs.n_out);
		fails++;
	}
}

static void values(void)
{
	/* a value ruby's eval gives; each literal was evaluated and the bytes it holds are what is written */
	val("'a\\nb'", "a\\nb", 4);
	val("'a\\'b\\\\c'", "a'b\\c", 5);
	val("'\\\\'", "\\", 1);
	val("''", "", 0);
	val("'a\\xb'", "a\\xb", 4);
	val("\"a\\nb\"", "a\nb", 3);
	val("\"\\x41\\101A\\u{41}\\e\\s\\t\\0\"", "AAAA\x1b \t\x00", 8);
	val("\"\\q\\#\\\"\\\\\"", "q#\"\\", 4);
	val("\"a\\\nb\"", "ab", 2);
	val("\"#\"", "#", 1);
	val("\"#a\"", "#a", 2);
	val("\"\\#{x}\"", "#{x}", 4);
	val("\"\\#@a\"", "#@a", 3);
	val("\"a\nb\"", "a\nb", 3);
	val("\"\\777\\400\\x4\\x41\\1\\01\\001\"", "\xff\x00\x04" "A\x01\x01\x01", 7);
	val("\"\xc3\xa9\\u{20AC}\\u{1F600}\"", "\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80", 9);
	val("\"\\xff\\xfe\"", "\xff\xfe", 2);
	val("%q(a\\)b\\\\c(d))", "a)b\\c(d)", 8);
	val("%q[a\\]b]", "a]b", 3);
	val("%q|a\\|b\\n|", "a|b\\n", 5);
	val("%Q(a\\)b\\n)", "a)b\n", 4);
	val("%(x\\ny)", "x\ny", 3);
	val("%Q[a\\x41]", "aA", 2);
	val("%Q<a<b>c>", "a<b>c", 5);
	val("%(a\\(b)", "a(b", 3);
	val("\"a\r\nb\"", "a\nb", 3);
	val("'a\r\nb'", "a\nb", 3);
	val("\"\\\r\nz\"", "z", 1);
	val("\"\xc3\xa9\"", "\xc3\xa9", 2);
	val("\"\\\\x41\"", "\\x41", 4);
	val("\"\\\\\\x41\"", "\\A", 2);
	val("\"\\z\\y\\8\\9\"", "zy89", 4);
	val("\"\\a\\b\\f\\v\\r\"", "\x07\x08\x0c\x0b\r", 5);
	val("%q()", "", 0);
	val("\"\"", "", 0);
	val("%Q()", "", 0);
	val("'a\\\nb'", "a\\\nb", 4);
	val("\"\\101\"", "A", 1);
	/* no value: it interpolates, it has an escape the interpreter refuses or this reader would misread, or it is not a string */
	val("\"#{x}\"", NULL, 0);
	val("\"a#@b\"", NULL, 0);
	val("\"a#$b\"", NULL, 0);
	val("\"#$1\"", NULL, 0);
	val("\"\\u{41 42}\"", NULL, 0);
	val("\"\\xZ\"", NULL, 0);
	val("\"\\x\"", NULL, 0);
	val("\"\\u12\"", NULL, 0);
	val("\"\\u\"", NULL, 0);
	val("\"\\u{}\"", NULL, 0);
	val("\"\\u{110000}\"", NULL, 0);
	val("\"\\ud800\"", NULL, 0);
	val("\"\\M-a\"", NULL, 0);
	val("\"\\C-a\"", NULL, 0);
	val("\"\\cA\"", NULL, 0);
	val("`ls`", NULL, 0);
	val("%x(ls)", NULL, 0);
	val("%w[a b]", NULL, 0);
	val("%W[a b]", NULL, 0);
	val("%i[a]", NULL, 0);
	val("%r{a}", NULL, 0);
	val("%s(a)", NULL, 0);
	val("/a/", NULL, 0);
	val("<<A\nb\nA", NULL, 0);
	/* the data after __END__ is the value of its span, as typed */
	val("x\n__END__\nab\r\ncd", "ab\r\ncd", 6);
	val("__END__", "", 0);
}

/* ---- the decode hook ---- */

/* THE DECODE HOOK, with a decoder that is not one: it wraps the value in angle brackets and upper cases it. What it
 * shows is what the lib decides - which literal, under which calls, in which order, and when it is let alone. */
static uint8_t last_chain[KGENOME_TEXTUAL_CHAIN_MAX];
static uint32_t last_n_chain, hook_calls;
static uint8_t hook_out[256];

static int fake_decode(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len,
		       const uint8_t **out, uint32_t *out_len)
{
	uint32_t i;

	(void)user;
	hook_calls++;
	memcpy(last_chain, chain, n_chain);
	last_n_chain = n_chain;
	if (!len || in[0] == '!' || len + 2u > sizeof hook_out)
		return 0;
	hook_out[0] = '<';
	for (i = 0; i < len; i++)
		hook_out[1u + i] = (uint8_t)((in[i] >= 'a' && in[i] <= 'z') ? in[i] - 32 : in[i]);
	hook_out[len + 1u] = '>';
	*out = hook_out;
	*out_len = len + 2u;
	return 1;
}

static struct kgenome_textual_form_res dform(const char *src, const char *want)
{
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = RB,
					       .out = fbuf, .decode = fake_decode };
	struct kgenome_textual_form_res rs;

	rq.cap = KGENOME_TEXTUAL_FORM_CAP(rq.n) + 64u;
	hook_calls = last_n_chain = 0;
	kgenome_textual_form(&rq, &rs);
	if (rs.n_out != strlen(want) || memcmp(fbuf, want, rs.n_out)) {
		fbuf[rs.n_out < sizeof fbuf ? rs.n_out : sizeof fbuf - 1u] = 0;
		printf("  FAIL decode of  %s\n       got    %s\n       wanted %s\n", src, fbuf, want);
		fails++;
	}
	return rs;
}

static int chain_is(uint32_t n, const uint8_t *want)
{
	return last_n_chain == n && !memcmp(last_chain, want, n);
}

static void decoders(void)
{
	static const uint8_t b64[] = { KGENOME_TEXTUAL_DEC_B64 },
		b64_zlib[] = { KGENOME_TEXTUAL_DEC_B64, KGENOME_TEXTUAL_DEC_ZLIB },
		url[] = { KGENOME_TEXTUAL_DEC_URL }, gz[] = { KGENOME_TEXTUAL_DEC_GZIP }, zl[] = { KGENOME_TEXTUAL_DEC_ZLIB };
	struct kgenome_textual_form_res rs;

	/* Base64's three decoders, qualified or not (after "include Base64"), with a "::" in front or not, a ' or a " literal, a %q and a %Q one */
	rs = dform("eval(Base64.decode64(\"abc\"))", "eval(Base64.decoded_decode64(\"<ABC>\"))");
	CK(rs.n_decoded == 1 && rs.n_refused == 0 && hook_calls == 1 && chain_is(1, b64));
	dform("eval(decode64('abc'))", "eval(decoded_decode64('<ABC>'))");
	CK(chain_is(1, b64));
	dform("x = Base64.strict_decode64('abc'); y = Base64.urlsafe_decode64(%q(d)); z = ::Base64.decode64(%Q(e))",
	      "x = Base64.decoded_strict_decode64('<ABC>'); y = Base64.decoded_urlsafe_decode64(%q(<D>)); z = ::Base64.decoded_decode64(%Q(<E>))");
	CK(hook_calls == 3 && chain_is(1, b64));
	/* urlsafe_decode64 reads "-" and "_" for "+" and "/", which the engine's decoder would skip: a value with either is not offered */
	rs = dform("Base64.urlsafe_decode64('a-b'); Base64.decode64('a_b'); Base64.decode64('a+b/')",
		   "Base64.urlsafe_decode64('a-b'); Base64.decode64('a_b'); Base64.decoded_decode64('<A+B/>')");
	CK(rs.n_refused == 2 && rs.n_decoded == 1 && hook_calls == 1);
	/* the chain, innermost first, and it ends at the first name that is not a decoder - eval, Marshal.load - which is not this lib's
	 * business; the "::" of Zlib::Inflate is read as the name Inflate.inflate */
	dform("eval(Zlib::Inflate.inflate(Base64.decode64(\"ab\")))", "eval(Zlib::Inflate.decoded_inflate(Base64.decoded_decode64(\"<AB>\")))");
	CK(chain_is(2, b64_zlib));
	dform("Marshal.load(Zlib.inflate(Base64.decode64('ab')))", "Marshal.load(Zlib.decoded_inflate(Base64.decoded_decode64('<AB>')))");
	CK(chain_is(2, b64_zlib));
	dform("Zlib::Inflate.new.inflate(Base64.decode64('ab'))", "Zlib::Inflate.new.decoded_inflate(Base64.decoded_decode64('<AB>'))");
	CK(chain_is(2, b64_zlib));
	dform("Zlib.gunzip('ab')", "Zlib.decoded_gunzip('<AB>')");
	CK(chain_is(1, gz));
	dform("Zlib::Inflate.inflate('ab')", "Zlib::Inflate.decoded_inflate('<AB>')");
	CK(chain_is(1, zl));
	/* white space and comments between the calls are gaps */
	dform("eval ( Base64 . decode64 ( 'ab' ) )", "eval ( Base64.decoded_decode64( '<AB>' ) )");
	CK(hook_calls == 1);
	dform("Base64.decode64(  # c\n 'ab' # d\n )", "Base64.decoded_decode64(\n'<AB>'\n)");
	CK(hook_calls == 1);
	/* url: the two that turn a "+" into a space, as the decoder does */
	dform("CGI.unescape('%41+b'); URI.decode_www_form_component('%41')", "CGI.decoded_unescape('<%41+B>'); URI.decoded_decode_www_form_component('<%41>')");
	CK(hook_calls == 2 && chain_is(1, url));
	/* NOT a decoder: the name has to end at a dot or at its start; the ones that keep the "+"; the encoders; a call with no brackets; a
	 * variable; a method called on a literal; a literal that is not the whole argument */
	dform("my_decode64('ab'); Base64.encode64('ab'); CGI.unescapeURIComponent('%41'); URI.decode_uri_component('%41'); Base64.decode64 'ab'",
	      "my_decode64('ab'); Base64.encode64('ab'); CGI.unescapeURIComponent('%41'); URI.decode_uri_component('%41'); Base64.decode64 'ab'");
	CK(hook_calls == 0);
	dform("Base64.decode64(x); 'YWJj'.unpack1('m'); ['YWJj'].pack('m'); Base64.decode64('a'.upcase)",
	      "Base64.decode64(x); 'YWJj'.unpack1('m'); ['YWJj'].pack('m'); Base64.decode64('a'.upcase)");
	CK(hook_calls == 0);
	/* a second argument after the literal is kept, and the literal is still the payload */
	dform("Zlib::Inflate.inflate('ab', 1)", "Zlib::Inflate.decoded_inflate('<AB>', 1)");
	CK(hook_calls == 1);
	/* interpolating literals have no value, so the hook is not asked; a literal with an escaped "#{" is no interpolation */
	dform("Base64.decode64(\"a#{b}\"); Base64.decode64(\"#{b}\"); Base64.decode64(\"a\\#{b}\")",
	      "Base64.decode64(\"a#{b}\"); Base64.decode64(\"#{b}\"); Base64.decoded_decode64(\"<A#{B}>\")");
	CK(hook_calls == 1);
	/* the value, not the text: an escape is what it stands for, and a single quoted "\n" is two characters */
	dform("Base64.decode64(\"a\\nb\"); Base64.decode64('a\\nb')", "Base64.decoded_decode64(\"<A\nB>\"); Base64.decoded_decode64('<A\\NB>')");
	CK(hook_calls == 2);
	/* a join of literals is not offered (the row has no join), a heredoc's body is not after the call, a %w is no string */
	dform("Base64.decode64('a' + 'b'); Base64.decode64(%w[a]); Base64.decode64(<<A)\nab\nA\n",
	      "Base64.decode64('a' + 'b'); Base64.decode64(%w[a]); Base64.decode64(<<A)\nab\nA");
	CK(hook_calls == 0);
	/* refused: the literal stays as typed and the refusal is counted; and one still open is not offered */
	rs = dform("Base64.decode64('!ab')", "Base64.decode64('!ab')");
	CK(rs.n_decoded == 0 && rs.n_refused == 1 && hook_calls == 1);
	dform("Base64.decode64('ab", "Base64.decode64('ab");
	CK(hook_calls == 0);
}

/* ---- (c) any text at all ---- */

/* The form of a form is itself, and the output fits its cap, on texts made of the language's fragments. */
static void fragment_property(uint32_t lang, uint32_t seed)
{
	static const char *const frag[] = {
		"=begin\n", "=end\n", "=end", "=begin", "__END__\n", "__END__", "  ", "\t", "\n", "\r\n", "\r", "<<A\n", "<<-B\n", "<<~C", "<<'D'\n",
		"A\n", "B\n", "C\n", "D\n", "  A\n", "\"", "'", "`", "#{", "}", "#", "# c", "%w[", "%q(", "%Q|", "%(", "]", ")", "|", "/", "/i", "?",
		"?a", "?\"", ":", "::", ":\"", "\\", "\\\n", "$'", "$\"", "$`", "x", " x ", "puts ", "foo(", "= ", "+ ", "-", "*", "%", "<<", "<", ">",
		"{", "[", "(", ",", ";", ".", "\xc3\xa9", "#@a", "#$1", "\\x41", "\\u{41}", "\\101", "\\x4", "\\0", "if ", "end ", "def ", "class ",
		"return ", "when ", "then ", "do |x| ", "=",
	};
	uint8_t b[400];
	uint32_t s = seed, i, n, k, w1, w2;

	for (i = 0; i < 30000u; i++) {
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res rs;
		enum kgenome_textual_status st;
		uint32_t parts;

		s = s * 1103515245u + 12345u;
		parts = (s >> 16) % 40u;
		n = 0;
		for (k = 0; k < parts; k++) {
			const char *f;
			size_t l;

			s = s * 1103515245u + 12345u;
			f = frag[(s >> 16) % (sizeof frag / sizeof frag[0])];
			l = strlen(f);
			if (n + l > sizeof b)
				break;
			memcpy(b + n, f, l);
			n += (uint32_t)l;
		}
		rq = (struct kgenome_textual_form_req){ .in = b, .n = n, .lang = lang, .out = fbuf, .cap = KGENOME_TEXTUAL_FORM_CAP(n) };
		st = kgenome_textual_form(&rq, &rs);
		w1 = rs.n_out;
		if ((st != KGENOME_TEXTUAL_OK && st != KGENOME_TEXTUAL_OPEN) || w1 > KGENOME_TEXTUAL_FORM_CAP(n)) {
			printf("  FAIL form status %d or length %u on a fragment text of %u bytes\n", (int)st, w1, n);
			fails++;
			return;
		}
		rq = (struct kgenome_textual_form_req){ .in = fbuf, .n = w1, .lang = lang, .out = fbuf2, .cap = KGENOME_TEXTUAL_FORM_CAP(w1) };
		st = kgenome_textual_form(&rq, &rs);
		w2 = rs.n_out;
		if (w2 != w1 || memcmp(fbuf, fbuf2, w1)) {
			printf("  FAIL the form is not its own form, input of %u bytes:\n  ", n);
			for (k = 0; k < n; k++)
				printf(b[k] >= 0x20 && b[k] < 0x7f && b[k] != '\\' ? "%c" : "\\x%02x", b[k]);
			printf("\n");
			fails++;
			return;
		}
	}
}

static void properties(void)
{
	/* the spans partition the text, and the form of a form is itself, on text drawn from what changes the lexer's mind: quotes of
	 * all three kinds, a backslash, braces, hash, the percent letters, "<" and "/" and "?" and ":", line breaks of all three
	 * kinds, the characters of a name and of a number */
	partition_for(RB, "#'\"`\\\n\r\t {}()[]<>%/?:$@=!-+*&|,;.~wWqQiIrsxA1_^", 2024u);
	partition_for(RB, "'\"\\{}#%w(\n:", 77u);
	partition_for(RB, "<<-~'\"A\n =b", 31u);
	partition_for(RB, "#{}\"%Q(\\$1'`\n/?", 9u);
	form_property_for(RB, "#'\"`\\\n\r\t {}()[]<>%/?:$@=!-+*&|,;.~wWqQiIrsxA1_^", 99u);
	form_property_for(RB, "'\"\\\nx41\\0u{}. =#<A", 5u);
	form_property_for(RB, "=begin\nend_x A<>\r\t", 6u);
	fragment_property(RB, 7u);
	fragment_property(RB, 8u);
}

/* A sink that refuses after `left` spans. */
struct stopper {
	uint32_t left, got;
};

static int stop_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct stopper *c = u;

	(void)sp;
	c->got++;
	return c->left && --c->left != 0;
}

/* A sink that refuses ends the walk at that span, wherever the lexer is - in a heredoc body, an interpolation, a block comment, the data
 * after __END__ - and nothing is delivered after it. */
static void refusals(void)
{
	static const char sample[] =
		"x = \"a#{b}\" # c\nputs <<A, <<~B\n  h #{i}\nA\n  j\nB\n=begin\nk\n=end\ny = %w[a b] + /c/i\n__END__\nm\n";
	uint32_t k;

	for (k = 1; k <= 24u; k++) {
		struct stopper st = { k, 0 };
		struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)sample, .n = (uint32_t)(sizeof sample - 1u), .lang = RB,
						      .sink = stop_sink, .user = &st };
		struct kgenome_textual_lex_res rs;
		enum kgenome_textual_status s = kgenome_textual_lex(&rq, &rs);

		if (s == KGENOME_TEXTUAL_REFUSED ? st.got != k : (st.got >= k)) {
			printf("  FAIL a sink that refuses after %u spans got %u (status %d)\n", k, st.got, (int)s);
			fails++;
			return;
		}
	}
}

/* Takes every span of a long text and keeps only what the partition needs: where the next one must begin. */
struct whole {
	uint32_t next, n, broken;
};

static int whole_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct whole *c = u;

	if (sp->off != c->next || !sp->len)
		c->broken = 1;
	c->next = sp->off + sp->len;
	c->n++;
	return 1;
}

#define T(s) { s, (uint32_t)(sizeof s - 1u) }

/* The spans partition a text cut at every length, and a deeply nested or hostile one is read in time proportional to it. */
static void hostile(void)
{
	static const char sample[] =
		"#!/usr/bin/ruby\nx = \"a#{b ? %w[c d] : 'e'}\" + /f#{g}/i # c\ny = <<~A + <<'B'\n  h #{i}\nA\nj\nB\n=begin\nk\n=end\nz = ?\" + $' + :\"l\"\n__END__\nm\n";
	static struct rend r;
	uint32_t n;

	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, RB);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* interpolation nested to the bound: one string below it, and above it open to the end of the text with every byte delivered */
	{
		static char deep[16384];
		uint32_t w = 0, i;

		for (i = 0; i < 60u; i++, w += 3)
			memcpy(deep + w, "\"#{", 3);
		deep[w++] = 'x';
		for (i = 0; i < 60u; i++, w += 2)
			memcpy(deep + w, "}\"", 2);
		lex(&r, deep, w, RB);
		CK(!r.broken && r.out[0] == 'S' && r.out[1] == '{' && !strchr(r.out, 'C') && !strchr(r.out, '!'));
		for (w = 0, i = 0; i < 300u; i++, w += 3)
			memcpy(deep + w, "\"#{", 3);
		deep[w++] = 'x';
		for (i = 0; i < 300u; i++, w += 2)
			memcpy(deep + w, "}\"", 2);
		lex(&r, deep, w, RB);
		CK(!r.broken && r.out[0] == 'S' && r.out[1] == '!' && !strchr(r.out, 'C'));
	}
	/* NUL bytes, and the three line endings, inside every kind of literal and comment */
	{
		static const struct { const char *s; uint32_t n; } t[] = {
			T("x = \"a\0b\" # c\0d\n"), T("x = 'a\0b'\r\ny = <<A\r\nb\0c\r\nA\r\n"), T("x = %w[a\0b]\ry = /a\0/"),
			T("=begin\0\n=end\0\n__END__\0\n\0"), T("x = \"a\rb\" + 'c\rd' # e\rf\ng = <<A\rbody\rA\r"), T("x = ?\0 + $\0 + :\0"),
		};
		uint32_t k;

		for (k = 0; k < sizeof t / sizeof t[0]; k++) {
			lex(&r, t[k].s, t[k].n, RB);
			CK(!r.broken);
		}
	}
	/* LINEAR WORK. Each of these is a text that never closes what it opens, repeated until it is 600 KB. A lexer that read to the end
	 * for every opener it could not close would do some 10^11 steps here; this takes a blink, and the bound on the whole is a few
	 * seconds even under a sanitizer. */
	{
		static const char *const unit[] = {
			"\"#{", "x = <<\"", "x <<'", "?\\u{", "%w[", "%Q(a #{ ", "/#{", "=begin\n", "x = <<A, <<B, <<C, <<D\n", "puts <<`", "\"#@", "%q(\\",
			"a <<-\"ab", "x /y#{\"", ":\"a#{", "\"a\\\n#{ <<A\n", "<<~A\n#{", "#{'", "x = %", "def f(a) %w[\n", "x = <<\"a\nb <<\"c ",
		};
		static uint8_t big[600u * 1024u];
		clock_t t0 = clock();
		uint32_t k;

		for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
			size_t ul = strlen(unit[k]);
			uint32_t w = 0;
			struct whole c = { 0 };
			struct kgenome_textual_lex_req rq;
			struct kgenome_textual_lex_res rs;
			enum kgenome_textual_status st;

			while (w + ul <= sizeof big) {
				memcpy(big + w, unit[k], ul);
				w += (uint32_t)ul;
			}
			rq = (struct kgenome_textual_lex_req){ .in = big, .n = w, .lang = RB, .sink = whole_sink, .user = &c };
			st = kgenome_textual_lex(&rq, &rs);
			CK((st == KGENOME_TEXTUAL_OPEN || st == KGENOME_TEXTUAL_OK) && c.next == w && !c.broken && rs.n_span == c.n);
		}
		CK((double)(clock() - t0) / CLOCKS_PER_SEC < 30.0);
	}
	/* more heredocs on one line than are queued: the first RUBY_HEREDOCS take their bodies, the rest are code, and nothing is lost */
	{
		static char many[8192];
		uint32_t w = 0, i;

		for (i = 0; i < 40u; i++)
			w += (uint32_t)snprintf(many + w, sizeof many - w, "<<A%u, ", i);
		w += (uint32_t)snprintf(many + w, sizeof many - w, "x\n");
		for (i = 0; i < 40u; i++)
			w += (uint32_t)snprintf(many + w, sizeof many - w, "b\nA%u\n", i);
		lex(&r, many, w, RB);
		CK(!r.broken);
	}
}

/* ---- (b) the generator ---- */

static struct gen gg;

/* All the spans of a text, kept. */
struct all {
	struct kgenome_textual_span *p;
	uint32_t n, cap;
};

static int all_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct all *a = u;

	if (a->n < a->cap)
		a->p[a->n] = *sp;
	a->n++;
	return 1;
}

static struct kgenome_textual_span span_a[EXP_MAX], span_b[EXP_MAX];

/* Lex `in` into `a`; 1 when they fit. */
static int lex_all(const uint8_t *in, uint32_t n, struct all *a)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = RB, .sink = all_sink, .user = a };
	struct kgenome_textual_lex_res rs;

	a->n = 0;
	(void)kgenome_textual_lex(&rq, &rs);
	return a->n <= a->cap;
}

static int same_span(const struct kgenome_textual_span *a, const struct kgenome_textual_span *b)
{
	return a->off == b->off && a->len == b->len && a->open_len == b->open_len && a->close_len == b->close_len && a->kind == b->kind &&
	       a->flags == b->flags;
}

/* The value of a string span, or -1 when it has none, else its length written to `out`. */
static int span_value(const uint8_t *in, const struct kgenome_textual_span *s, uint8_t *out)
{
	struct kgenome_textual_value_req vq = { .lang = RB, .lit = in + s->off, .len = s->len, .open_len = s->open_len,
						.close_len = s->close_len, .flags = s->flags, .out = out, .cap = s->len };
	struct kgenome_textual_value_res vs;

	return kgenome_textual_value(&vq, &vs) == KGENOME_TEXTUAL_OK ? (int)vs.n_out : -1;
}

/* The generated program lexes as the generator knew; its form is its own form, fits its cap, keeps every literal's value and keeps no comment. */
static int generated(uint64_t seed)
{
	static uint8_t form1[2u * GEN_MAX], form2[3u * GEN_MAX], v1[GEN_MAX], v2[GEN_MAX];
	struct all a = { span_a, 0, EXP_MAX }, b = { span_b, 0, EXP_MAX };
	struct kgenome_textual_form_req rq;
	struct kgenome_textual_form_res rs, rs2;
	enum kgenome_textual_status st;
	uint32_t i, j;
	int n1, n2;

	memset(&gg, 0, sizeof gg);
	gg.s = 0x9e3779b97f4a7c15ull ^ (seed * 0x2545f4914f6cdd1dull);
	program(&gg);
	if (gg.over) {
		printf("  FAIL the generator overran its buffer (seed %llu)\n", (unsigned long long)seed);
		fails++;
		return 0;
	}
	if (!lex_all(gg.b, gg.n, &a) || a.n != gg.nx) {
		printf("  FAIL seed %llu: %u spans, the generator wrote %u\n", (unsigned long long)seed, a.n, gg.nx);
		fails++;
		return 0;
	}
	for (i = 0; i < a.n; i++) {
		if (!same_span(&span_a[i], &gg.x[i])) {
			printf("  FAIL seed %llu, span %u: kind %u at %u+%u delimiters %u/%u flags %u; the generator wrote kind %u at %u+%u %u/%u flags %u\n",
			       (unsigned long long)seed, i, span_a[i].kind, span_a[i].off, span_a[i].len, span_a[i].open_len, span_a[i].close_len,
			       span_a[i].flags, gg.x[i].kind, gg.x[i].off, gg.x[i].len, gg.x[i].open_len, gg.x[i].close_len, gg.x[i].flags);
			fails++;
			return 0;
		}
	}
	/* the form */
	rq = (struct kgenome_textual_form_req){ .in = gg.b, .n = gg.n, .lang = RB, .out = form1, .cap = KGENOME_TEXTUAL_FORM_CAP(gg.n) };
	st = kgenome_textual_form(&rq, &rs);
	if (st != KGENOME_TEXTUAL_OK) {
		printf("  FAIL seed %llu: form status %d\n", (unsigned long long)seed, (int)st);
		fails++;
		return 0;
	}
	rq = (struct kgenome_textual_form_req){ .in = form1, .n = rs.n_out, .lang = RB, .out = form2, .cap = KGENOME_TEXTUAL_FORM_CAP(rs.n_out) };
	st = kgenome_textual_form(&rq, &rs2);
	if (st != KGENOME_TEXTUAL_OK || rs2.n_out != rs.n_out || memcmp(form1, form2, rs.n_out)) {
		printf("  FAIL seed %llu: the form is not its own form\n", (unsigned long long)seed);
		fails++;
		return 0;
	}
	/* the literals are the same, one for one, with the same value, and no comment is left but a first line "#!" */
	if (!lex_all(form1, rs.n_out, &b)) {
		printf("  FAIL seed %llu: the form has too many spans\n", (unsigned long long)seed);
		fails++;
		return 0;
	}
	for (i = 0, j = 0; i < a.n; i++) {
		if (span_a[i].kind != KGENOME_TEXTUAL_STRING)
			continue;
		while (j < b.n && span_b[j].kind != KGENOME_TEXTUAL_STRING)
			j++;
		if (j >= b.n) {
			printf("  FAIL seed %llu: the form lost a literal\n", (unsigned long long)seed);
			fails++;
			return 0;
		}
		n1 = span_value(gg.b, &span_a[i], v1);
		n2 = span_value(form1, &span_b[j], v2);
		if (n1 != n2 || (n1 > 0 && memcmp(v1, v2, (size_t)n1)) || span_a[i].flags != span_b[j].flags) {
			printf("  FAIL seed %llu: a literal changed value or flags (%d, %d)\n", (unsigned long long)seed, n1, n2);
			fails++;
			return 0;
		}
		j++;
	}
	for (i = 0; i < b.n; i++) {
		if (span_b[i].kind == KGENOME_TEXTUAL_COMMENT && !(span_b[i].off == 0 && form1[0] == '#' && form1[1] == '!')) {
			printf("  FAIL seed %llu: the form keeps a comment\n", (unsigned long long)seed);
			fails++;
			return 0;
		}
	}
	for (i = 0, n1 = 0; i < b.n; i++)
		n1 += span_b[i].kind == KGENOME_TEXTUAL_STRING;
	for (i = 0, n2 = 0; i < a.n; i++)
		n2 += span_a[i].kind == KGENOME_TEXTUAL_STRING;
	if (n1 != n2) {
		printf("  FAIL seed %llu: %d literals, the form has %d\n", (unsigned long long)seed, n2, n1);
		fails++;
		return 0;
	}
	return 1;
}

/* NUL, ^D AND ^Z where a token would begin end the program (ripper has no token after one: the rest is one string here), and are bytes like
 * another in a literal or a comment. The texts have NULs, so they are given with their length and the spans are read as numbers: the
 * renderer of textual_check.h writes a C string. The two in a literal agree with ripper span for span; the ones that end the program
 * are not confirmed (ripper has nothing after the byte to compare). */
struct want {
	uint8_t kind;
	uint32_t off, len, open, close;
	uint8_t flags;
};

static void spans_are(const char *src, uint32_t n, const struct want *w, uint32_t nw)
{
	static struct kgenome_textual_span sp[64];
	struct all a = { sp, 0, 64 };
	uint32_t i;

	if (!lex_all((const uint8_t *)src, n, &a) || a.n != nw) {
		printf("  FAIL a text with a NUL, ^D or ^Z: %u spans, wanted %u\n", a.n, nw);
		fails++;
		return;
	}
	for (i = 0; i < nw; i++) {
		if (sp[i].kind != w[i].kind || sp[i].off != w[i].off || sp[i].len != w[i].len || sp[i].open_len != w[i].open ||
		    sp[i].close_len != w[i].close || sp[i].flags != w[i].flags) {
			printf("  FAIL a text with a NUL, ^D or ^Z: span %u is kind %u at %u+%u, delimiters %u/%u, flags %u\n", i, sp[i].kind,
			       sp[i].off, sp[i].len, sp[i].open_len, sp[i].close_len, sp[i].flags);
			fails++;
			return;
		}
	}
}

static void ends(void)
{
	/* (octal escapes: a hex escape in C takes every hex digit that follows it) */
	static const char t1[] = "x = 1\n\004 y = \"a#{b}\" # c\nz = 2\n", t2[] = "x = 1\n\032 y = \"a\"\n", t3[] = "x = 1\n\0 y = \"a\"\n",
		t4[] = "a\0", t5[] = "\0", t6[] = "x = \"a\0b\" # c\0d\ny = <<A\nb\0\nA\n", t7[] = "x = %w[a\004b] + /c\032/",
		t8[] = "x = \"#{ 1 \0 }\" + 'y'";
	const uint8_t C = KGENOME_TEXTUAL_CODE, S = KGENOME_TEXTUAL_STRING, K = KGENOME_TEXTUAL_COMMENT;
	const uint8_t I = KGENOME_TEXTUAL_F_INTERP, H = KGENOME_TEXTUAL_F_HERE;
	const struct want w1[] = { { C, 0, 6, 0, 0, 0 }, { S, 6, sizeof t1 - 7u, 1, 0, 0 } };
	const struct want w2[] = { { C, 0, 6, 0, 0, 0 }, { S, 6, sizeof t2 - 7u, 1, 0, 0 } };
	const struct want w3[] = { { C, 0, 6, 0, 0, 0 }, { S, 6, sizeof t3 - 7u, 1, 0, 0 } };
	const struct want w4[] = { { C, 0, 1, 0, 0, 0 }, { S, 1, 1, 1, 0, 0 } };
	const struct want w5[] = { { S, 0, 1, 1, 0, 0 } };
	const struct want w6[] = { { C, 0, 4, 0, 0, 0 }, { S, 4, 5, 1, 1, I }, { C, 9, 1, 0, 0, 0 }, { K, 10, 5, 1, 0, 0 }, { C, 15, 9, 0, 0, 0 },
				   { S, 24, 4, 0, 1, (uint8_t)(H | I) }, { C, 28, 1, 0, 0, 0 } };
	const struct want w7[] = { { C, 0, 4, 0, 0, 0 }, { S, 4, 7, 3, 1, 0 }, { C, 11, 3, 0, 0, 0 }, { S, 14, 4, 1, 1, 0 } };

	spans_are(t1, sizeof t1 - 1u, w1, 2);
	spans_are(t2, sizeof t2 - 1u, w2, 2);
	spans_are(t3, sizeof t3 - 1u, w3, 2);
	spans_are(t4, sizeof t4 - 1u, w4, 2);
	spans_are(t5, sizeof t5 - 1u, w5, 1);
	spans_are(t6, sizeof t6 - 1u, w6, 7);
	spans_are(t7, sizeof t7 - 1u, w7, 4);
	/* NOT MODELLED: inside a "#{ }" the interpreter ends the program at the byte, and the lexer reads on - the string closes there and the text
	 * after it is lexed as code */
	{
		static struct kgenome_textual_span sp[16];
		struct all a = { sp, 0, 16 };

		CK(lex_all((const uint8_t *)t8, sizeof t8 - 1u, &a) && a.n == 4 && sp[1].kind == KGENOME_TEXTUAL_STRING &&
		   (sp[1].flags & KGENOME_TEXTUAL_F_OPEN) == 0 && sp[3].kind == KGENOME_TEXTUAL_STRING);
	}
}

static void generator(void)
{
	uint64_t seed;
	uint32_t ok = 0, strings = 0, i;

	for (seed = 1; seed <= 4000u; seed++) {
		if (!generated(seed))
			return;
		ok++;
		for (i = 0; i < gg.nx; i++)
			strings += gg.x[i].kind == KGENOME_TEXTUAL_STRING;
	}
	/* the generator makes what it says: it is not a test of nothing */
	CK(ok == 4000u && strings > 20000u);
}

int main(void)
{
	cases();
	generator();
	ends();
	forms();
	unescapes();
	values();
	decoders();
	properties();
	refusals();
	hostile();
	printf("textual ruby: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
