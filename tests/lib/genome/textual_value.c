/*
 * textual_value - kgenome_textual_value: what a string literal HOLDS, for every language that has a reading of its
 * literals, through <kgenome.h> alone.
 *
 * A literal is lexed inside a minimal program, so the span - and with it the open_len, close_len and flags the call
 * is given - is what the lexer really makes of it. A case is the program, the language, and the bytes the value must be
 * ("%" hex pairs for the unprintable ones), or NONE when the literal has no value without running the program.
 *
 * WHAT IS PINNED: each language's own escapes and the way it differs from the others - "\q" is two bytes in php and
 * python, one in javascript and an error in java and c#; "\x" takes two digits in python and javascript and one to
 * four in c#; a unicode escape is utf-8, a "\xE9" in a python str is a character and in a bytes literal a byte; a raw
 * literal, a nowdoc, a verbatim string have no escapes; and every literal that depends on the program (a $name, a ${ },
 * a field, an interpolated hole, a text block) has no value. Then the properties: the value is never longer than the
 * text between the delimiters, a short buffer is SMALL, and a language with no reading says so.
 */

#include "textual_check.h"

struct first {
	struct kgenome_textual_span s;
	int have;
};

static int take(void *u, const struct kgenome_textual_span *s)
{
	struct first *f = u;

	if (!f->have && s->kind == KGENOME_TEXTUAL_STRING) {
		f->s = *s;
		f->have = 1;
	}
	return 1;
}

/* "%41%0a" in `want` is the bytes 0x41 0x0a; "%%" is a percent. */
static uint32_t bytes_of(const char *want, uint8_t *b)
{
	uint32_t w = 0;

	while (*want) {
		if (want[0] == '%' && want[1] == '%') {
			b[w++] = '%';
			want += 2;
		} else if (want[0] == '%') {
			b[w++] = (uint8_t)(kof_hex_val((uint8_t)want[1]) * 16 + kof_hex_val((uint8_t)want[2]));
			want += 3;
		} else {
			b[w++] = (uint8_t)*want++;
		}
	}
	return w;
}

#define NONE ((const char *)0)

static void val(uint32_t lang, const char *prog, const char *want)
{
	struct first f = { .have = 0 };
	struct kgenome_textual_lex_req lq = { .in = (const uint8_t *)prog, .n = (uint32_t)strlen(prog), .lang = lang,
					      .sink = take, .user = &f };
	struct kgenome_textual_lex_res ls;
	uint8_t got[512], exp[512];
	struct kgenome_textual_value_req rq;
	struct kgenome_textual_value_res rs;
	enum kgenome_textual_status st;
	uint32_t ne = want ? bytes_of(want, exp) : 0;

	kgenome_textual_lex(&lq, &ls);
	if (!f.have) {
		printf("  FAIL no string in  %s\n", prog);
		fails++;
		return;
	}
	rq = (struct kgenome_textual_value_req){ .lang = lang, .lit = (const uint8_t *)prog + f.s.off, .len = f.s.len,
						 .open_len = f.s.open_len, .close_len = f.s.close_len,
						 .flags = f.s.flags, .out = got, .cap = sizeof got };
	st = kgenome_textual_value(&rq, &rs);
	if (!want ? st != KGENOME_TEXTUAL_NO_VALUE
		  : (st != KGENOME_TEXTUAL_OK || rs.n_out != ne || memcmp(got, exp, ne))) {
		uint32_t i;

		printf("  FAIL value of  %s\n       status %d, got %u bytes:", prog, (int)st, rs.n_out);
		for (i = 0; i < rs.n_out; i++)
			printf(" %02x", got[i]);
		printf("\n       wanted %s", want ? "" : "no value");
		for (i = 0; i < ne; i++)
			printf(" %02x", exp[i]);
		printf("\n");
		fails++;
	}
	/* never longer than the text between the delimiters */
	CK(rs.n_out <= f.s.len - f.s.open_len - f.s.close_len);
}

#define PHP KGENOME_TEXTUAL_LANG_PHP
#define JS  KGENOME_TEXTUAL_LANG_JS
#define PY  KGENOME_TEXTUAL_LANG_PY
#define JSP KGENOME_TEXTUAL_LANG_JSP
#define ASPX KGENOME_TEXTUAL_LANG_ASPX
#define VBS KGENOME_TEXTUAL_LANG_VBS

static void php(void)
{
	/* single quotes: a backslash and a quote are the only escapes, "\n" is two bytes */
	val(PHP, "<?php 'a\\'b\\\\c\\nd';", "a'b\\c\\nd");
	val(PHP, "<?php 'a$x{$y}';", "a$x{$y}");
	/* double quotes: the full set; an unknown escape keeps its backslash; \x one or two digits; octal wraps to a byte */
	val(PHP, "<?php \"a\\nb\\tc\\e\";", "a%0ab%09c%1b");
	val(PHP, "<?php \"\\x41\\102\\u{e9}\\u{1F600}\";", "AB%c3%a9%f0%9f%98%80");
	val(PHP, "<?php \"\\x4\\x4g\\400\\$x\\q\\\\\";", "%04%04g%00$x\\q\\");
	val(PHP, "<?php \"YWJj\\n\";", "YWJj%0a");
	/* what is filled in by the program is not a value */
	val(PHP, "<?php \"a$x\";", NONE);
	val(PHP, "<?php \"a{$x}\";", NONE);
	val(PHP, "<?php \"a${x}\";", NONE);
	val(PHP, "<?php \"a$\";", "a$");
	val(PHP, "<?php \"a$1 {b} $ \";", "a$1 {b} $ ");
	val(PHP, "<?php \"a\\$x\";", "a$x");
	/* heredoc: the line break before the closer is not in the value; a nowdoc has no escapes */
	val(PHP, "<?php $a = <<<E\nab\ncd\nE;", "ab%0acd");
	val(PHP, "<?php $a = <<<E\nab\r\ncd\r\nE;", "ab%0d%0acd");
	val(PHP, "<?php $a = <<<E\n\\x41\n$y\nE;", NONE);
	val(PHP, "<?php $a = <<<'E'\n\\x41 $y\nE;", "\\x41 $y");
	val(PHP, "<?php $a = <<<E\n\nE;", "");
}

static void js(void)
{
	val(JS, "'a\\/b\\'c\\\\d';", "a/b'c\\d");
	val(JS, "'\\x41\\u0042\\u{43}\\101';", "ABCA");
	val(JS, "'\\q\\\"';", "q\"");
	val(JS, "'\\0\\x00';", "%00%00");
	val(JS, "'\\xE9\\u00e9';", "%c3%a9%c3%a9");
	val(JS, "'a\\\nb\\\r\nc';", "abc");
	val(JS, "'\\n\\r\\t\\b\\f\\v';", "%0a%0d%09%08%0c%0b");
	val(JS, "'\\u{1F600}';", "%f0%9f%98%80");
	val(JS, "'\\uD83D\\uDE00';", "%f0%9f%98%80");           /* a surrogate pair is one character */
	val(JS, "'\\uD83D';", NONE);                             /* one alone has no utf-8 form */
	val(JS, "'\\uDE00\\uD83D';", NONE);
	val(JS, "'\\x4';", "x4");                              /* \x needs two digits: otherwise it is an "x" */
	/* a template: its text, but not with a substitution; a regex is not a string */
	val(JS, "`a\\`b\\n`;", "a`b%0a");
	val(JS, "`a${b}c`;", NONE);
	val(JS, "`a$b {c}`;", "a$b {c}");
	val(JS, "x = /a\\/b/g;", NONE);
}

static void py(void)
{
	val(PY, "'a\\nb\\tc\\\\d\\'e\\\"f'", "a%0ab%09c\\d'e\"f");
	val(PY, "r'a\\nb\\'c'", "a\\nb\\'c");
	val(PY, "b'\\xe9\\101\\u0041'", "%e9A\\u0041");
	val(PY, "'\\xe9\\u00e9\\U0001F600'", "%c3%a9%c3%a9%f0%9f%98%80");
	val(PY, "'\\q\\8'", "\\q\\8");
	val(PY, "'a\\\nb'", "ab");
	val(PY, "'\\N{DASH}'", NONE);
	val(PY, "b'\\N{DASH}'", "\\N{DASH}");
	val(PY, "f'a{{b}}c'", "a{b}c");
	val(PY, "f'a{x}c'", NONE);
	val(PY, "f'a}c'", NONE);
	val(PY, "rf'\\n{{'", "\\n{");
	val(PY, "fr'\\x41'", "\\x41");
	val(PY, "'''x\ny'''", "x%0ay");
	val(PY, "Rb\"\\x41\"", "\\x41");
	val(PY, "'\\x4'", "\\x4");                             /* two digits exactly: otherwise it is not an escape */
}

static void java(void)
{
	val(JSP, "<% String s = \"a\\tb\\101\\477\\u0041\\s\\\\\"; %>", "a%09bA'7A %5c");
	val(JSP, "<% String s = \"\\q\"; %>", NONE);
	val(JSP, "<% String s = \"\\x41\"; %>", NONE);
	val(JSP, "<% String s = \"\"\"\n  x\n  \"\"\"; %>", NONE);      /* a text block: indentation rule not applied */
	val(JSP, "<% char c = '\\n'; %>", "%0a");
	val(JSP, "<% String s = \"\\uD83D\\uDE00\\uD83D\"; %>", NONE);
}

static void csharp(void)
{
	val(ASPX, "<% var s = \"\\x41B\\x4G\\0\\u0041\\U0001F600\\a\"; %>", "%d0%9b%04G%00A%f0%9f%98%80%07");
	val(ASPX, "<% var s = \"\\q\"; %>", NONE);
	val(ASPX, "<% var s = @\"a\"\"b\\n\"; %>", "a\"b\\n");
	val(ASPX, "<% var s = $\"a{{b}}\\n\"; %>", "a{b}%0a");
	val(ASPX, "<% var s = $\"a{x}\"; %>", NONE);
	val(ASPX, "<% var s = $@\"a{{b}}\"\"\\n\"; %>", "a{b}\"\\n");
	val(ASPX, "<% var s = \"\"\"raw\"\"\"; %>", NONE);
}

static void vbscript(void)
{
	val(VBS, "x = \"a\"\"b\\n\"", "a\"b\\n");
	val(VBS, "x = \"\"", "");
}

static void properties(void)
{
	static const char src[] = "<?php \"abcdef\\n\";";
	struct first f = { .have = 0 };
	struct kgenome_textual_lex_req lq = { .in = (const uint8_t *)src, .n = sizeof src - 1u, .lang = PHP,
					      .sink = take, .user = &f };
	struct kgenome_textual_lex_res ls;
	struct kgenome_textual_value_req rq;
	struct kgenome_textual_value_res rs;
	uint8_t out[64];

	kgenome_textual_lex(&lq, &ls);
	CK(f.have);
	rq = (struct kgenome_textual_value_req){ .lang = PHP, .lit = (const uint8_t *)src + f.s.off, .len = f.s.len,
						 .open_len = f.s.open_len, .close_len = f.s.close_len,
						 .flags = f.s.flags, .out = out, .cap = 7 };
	/* the buffer must hold the text between the delimiters (the value is never longer): 8 bytes here */
	CK(kgenome_textual_value(&rq, &rs) == KGENOME_TEXTUAL_SMALL && rs.n_out == 0);
	rq.cap = 8;
	CK(kgenome_textual_value(&rq, &rs) == KGENOME_TEXTUAL_OK && rs.n_out == 7);
	/* a language the lib has no row for, one with no reading of its literals, and a span that does not fit its length */
	rq.lang = KGENOME_TEXTUAL_LANG_NONE;
	CK(kgenome_textual_value(&rq, &rs) == KGENOME_TEXTUAL_NO_LANG);
	rq.lang = KGENOME_TEXTUAL_LANG_ASP;   /* sh reads its literals since step 3; asp's rows have no literal reading */
	CK(kgenome_textual_value(&rq, &rs) == KGENOME_TEXTUAL_NO_VALUE);
	rq.lang = PHP;
	rq.open_len = rq.len + 1u;
	CK(kgenome_textual_value(&rq, &rs) == KGENOME_TEXTUAL_NO_VALUE);
}

/*
 * THROUGH THE FORM: the decode hook is given the VALUE of the literal, not its text. A hook that records what it
 * is given and refuses, so the form leaves the literal alone and the test reads only the input.
 */
static uint8_t seen[256];
static uint32_t seen_n, calls;

static int record(void *u, const uint8_t *chain, uint32_t nc, const uint8_t *in, uint32_t len, const uint8_t **out,
		  uint32_t *out_len)
{
	(void)u;
	(void)chain;
	(void)nc;
	(void)out;
	(void)out_len;
	calls++;
	seen_n = len < sizeof seen ? len : (uint32_t)sizeof seen;
	memcpy(seen, in, seen_n);
	return 0;
}

static void hook_sees(uint32_t lang, const char *src, const char *want)
{
	static uint8_t o[4096];
	uint8_t exp[256];
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = lang,
					       .out = o, .cap = sizeof o, .decode = record };
	struct kgenome_textual_form_res rs;
	uint32_t ne = want ? bytes_of(want, exp) : 0;

	calls = seen_n = 0;
	kgenome_textual_form(&rq, &rs);
	if (want ? (calls != 1 || seen_n != ne || memcmp(seen, exp, ne)) : calls != 0) {
		printf("  FAIL the hook of  %s\n       calls %u, saw %u bytes\n", src, calls, seen_n);
		fails++;
	}
}

static void through_the_form(void)
{
	/* php: escapes applied; single quotes are not; a $name is not offered; a heredoc has no final line break */
	hook_sees(PHP, "<?php base64_decode(\"a\\x62\\n\");", "ab%0a");
	hook_sees(PHP, "<?php base64_decode('a\\nb');", "a\\nb");
	hook_sees(PHP, "<?php base64_decode(\"a$b\");", NONE);
	hook_sees(PHP, "<?php f(base64_decode(<<<E\nab\ncd\nE\n));", "ab%0acd");
	/* js and python: the same, by their own rules */
	hook_sees(JS, "atob(\"a\\x62\\/\");", "ab/");
	hook_sees(JS, "atob(`a${b}`);", NONE);
	hook_sees(PY, "base64.b64decode(\"a\\x62\\\n\")", "ab");
	hook_sees(PY, "base64.b64decode(r\"a\\x62\")", "a\\x62");
	hook_sees(PY, "base64.b64decode(f\"{x}\")", NONE);
}

/*
 * JOINED LITERALS: the payload is the join. A join that is not one - a name, a number, another operator in it, a
 * literal with no value, more pieces than the lib holds - is written exactly as it would have been with no decoder at
 * all: the property `refusing hook == no hook`, checked on every text below, is what makes the held pieces safe.
 */
static void same_as_no_hook(uint32_t lang, const char *src)
{
	static uint8_t a[4096], b[4096];
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = lang,
					       .out = a, .cap = sizeof a };
	struct kgenome_textual_form_res ra, rb;

	kgenome_textual_form(&rq, &ra);
	rq.out = b;
	rq.decode = record;
	kgenome_textual_form(&rq, &rb);
	if (ra.n_out != rb.n_out || memcmp(a, b, ra.n_out)) {
		printf("  FAIL a refused join is written differently from no decoder at all:  %s\n", src);
		fails++;
	}
}

static void joins(void)
{
	static const struct { uint32_t lang; const char *src; } t[] = {
		{ PHP, "<?php f(base64_decode(\"a\" . $x));" },
		{ PHP, "<?php f(base64_decode(\"a\" . \"b\" . 5));" },
		{ PHP, "<?php f(base64_decode(\"a\"   .   \"b\"  *  2));" },
		{ PHP, "<?php f(base64_decode(\"a\" . \"$x\"));" },
		{ PHP, "<?php f(base64_decode(\"a\" . /* c */ \"b\" . ));" },
		{ PHP, "<?php f(base64_decode(\"a\"\n .\n \"b\" ?? 1));" },
		{ JS, "atob(\"a\" + \"b\" + x); atob(\"a\" + + \"b\"); atob(\"a\" +" },
		{ JS, "atob(\"a\" + `b${c}`);" },
		{ PY, "b64decode(\"a\" \"b\" x); b64decode(\"a\" + \"b\" + f(c)); b64decode('a' 'b' + )" },
		{ PY, "b64decode(\"a\" \\\n \"b\" , 1)" },
	};
	unsigned i;

	for (i = 0; i < sizeof t / sizeof t[0]; i++)
		same_as_no_hook(t[i].lang, t[i].src);
	/* a join: every piece's value, in order, is what the hook is given */
	hook_sees(PHP, "<?php base64_decode(\"ab\" . \"c\\x64\" . 'e\\nf');", "abcde\\nf");
	hook_sees(PHP, "<?php base64_decode( \"ab\"\n  .\t'cd' /* c */ );", "abcd");
	hook_sees(JS, "atob(\"ab\" + 'cd' + `e\\n`)", "abcde%0a");
	hook_sees(PY, "base64.b64decode(\"ab\" 'cd' \"\\x65\")", "abcde");
	hook_sees(PY, "base64.b64decode(\"ab\" + 'cd' \"e\")", "abcde");
	hook_sees(PY, "base64.b64decode(b\"ab\" # c\n  b\"cd\")", "abcd");
	hook_sees(PHP, "<?php base64_decode(\"a\" . \"$x\");", NONE);       /* one piece has no value: none is offered */
	hook_sees(PHP, "<?php base64_decode(\"a\" . $x);", NONE);
	hook_sees(JS, "atob(\"a\" + b);", NONE);
	hook_sees(JS, "atob(\"a\" b);", NONE);                               /* no operator, not python: not a join */
}

/*
 * THE PROPERTY THAT MAKES HOLDING LITERALS SAFE, on text nobody wrote: for sequences of the pieces that make a decoder
 * call - the call, literals of every kind, the join operators, names, brackets, white space, comments, a stray backslash
 * - a hook that refuses everything must leave the form byte for byte what it is with no hook at all. Whatever the text is
 * - truncated, unbalanced, a join that is not one - the held literals are written as typed.
 */
static void refusal_changes_nothing(uint32_t lang, const char *const *piece, uint32_t n_piece, const char *lead,
				    uint32_t seed)
{
	static char src[512];
	static uint8_t a[2048], b[2048];
	uint32_t s = seed, i, k, len;

	for (i = 0; i < 30000u; i++) {
		struct kgenome_textual_form_req rq;
		struct kgenome_textual_form_res ra, rb;

		s = s * 1103515245u + 12345u;
		len = (s >> 16) % 14u;
		strcpy(src, lead);
		for (k = 0; k < len; k++) {
			s = s * 1103515245u + 12345u;
			strcat(src, piece[(s >> 16) % n_piece]);
		}
		rq = (struct kgenome_textual_form_req){ .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = lang,
							.out = a, .cap = sizeof a };
		kgenome_textual_form(&rq, &ra);
		rq.out = b;
		rq.decode = record;
		kgenome_textual_form(&rq, &rb);
		if (ra.n_out != rb.n_out || memcmp(a, b, ra.n_out)) {
			printf("  FAIL a refused literal changes the form (language %u):  %s\n", lang, src);
			fails++;
			return;
		}
	}
}

static void refusal_property(void)
{
	static const char *const php_p[] = { "base64_decode(", "str_rot13(", "strrev(", "\"ab\"", "'cd'", "\"$x\"", "\"\\x41\"", " . ", ".",
					     "$v", " ", "\n", "/* c */", "# c\n", ")", ",", "(", "1", "\\", "<<<E\nz\nE\n", ";",
					     " ?>t<?php ", "{", "}" };
	static const char *const js_p[] = { "atob(", "unescape(", "\"ab\"", "'cd'", "`e${x}`", "`g`", "/r/", " + ", "+", "v", " ", "\n",
					    "/* c */", "// c\n", ")", ",", "(", "1", "\\", ";", "{", "}", "\"\\u00e9\"" };
	static const char *const py_p[] = { "b64decode(", "base64.b64decode(", "unquote(", "\"ab\"", "'cd'", "r'e\\x'", "f'{x}'", "b'z'",
					    " + ", "+", "v", " ", "\n", "# c\n", ")", ",", "(", "1", "\\\n", "\\", "'''t\nu'''", ":",
					    "[", "]" };

	refusal_changes_nothing(PHP, php_p, sizeof php_p / sizeof php_p[0], "<?php ", 5u);
	refusal_changes_nothing(JS, js_p, sizeof js_p / sizeof js_p[0], "", 6u);
	refusal_changes_nothing(PY, py_p, sizeof py_p / sizeof py_p[0], "", 7u);
}

static void many_pieces(void)
{
	static char src[8192];
	static uint8_t o[16384];
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .lang = PHP, .out = o, .cap = sizeof o,
					       .decode = record };
	struct kgenome_textual_form_res rs;
	uint32_t i, n;

	/* 200 pieces are joined; 300 are more than the lib holds, and stay as typed and are said to */
	for (n = 200; n <= 300; n += 100) {
		size_t w = (size_t)sprintf(src, "<?php base64_decode(\"a\"");

		for (i = 1; i < n; i++)
			w += (size_t)sprintf(src + w, " . \"a\"");
		strcpy(src + w, ");");
		rq.n = (uint32_t)strlen(src);
		calls = seen_n = 0;
		kgenome_textual_form(&rq, &rs);
		if (n == 200)
			CK(calls == 1 && seen_n == 200u && rs.n_refused == 1u);    /* the hook was asked, and refused */
		else
			CK(calls == 0 && rs.n_refused >= 1u);
	}
}

int main(void)
{
	php();
	js();
	py();
	java();
	csharp();
	vbscript();
	properties();
	through_the_form();
	joins();
	many_pieces();
	refusal_property();
	printf("textual value: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
