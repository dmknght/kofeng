/*
 * genome / textual_py - the python lexer and form of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED, and what each part is evidence of:
 *
 *   (a) KNOWN ANSWERS, one per rule with the neighbour it could be confused for. A case is the text and the
 *       one line it must come out as (kind letter, bytes in braces; S* = a backslash is an escape in it,
 *       S! = not closed - see textual_check.h). `py(...)` is a case python 3.13's own tokenizer agrees with:
 *       a scratch script outside the tree reads this file, renders every `py(` text from `tokenize` and
 *       compares; `pyx(...)` is a case no interpreter here can confirm - python 2, the 3.14 template string,
 *       or text that is not a program - and says why where it is.
 *   (b) A GENERATOR of python programs (textual_py_gen.h). Tokens of known class - code, string (every prefix,
 *       quote, escape, nesting of f-string), comment - are laid out with correct indentation, line
 *       continuations and comments in odd places, in one of three line-ending styles, and the lexer's spans must
 *       equal what the generator knows, byte for byte: kind, offset, length, delimiters and the flags. The form
 *       of each program must keep every string, keep no comment and be its own form. Programs are valid python:
 *       a scratch program includes the generator, writes N of them to disk and python's compile() reads each.
 *       The numbers of that run and of the comparison with `tokenize` are a measurement and are in the report,
 *       not here: a comment that carries one goes stale.
 *   (c) THE PARTITION and the idempotence of the form on random text from a python alphabet, a text cut at every
 *       length, f-strings nested past the interpreter's limit, and hostile texts read in time linear in them.
 *   (d) FORM and decoder known answers, the decode hook with a fake decoder (the contract is what is asserted,
 *       not an algorithm).
 *
 * Everything goes through <kgenome.h> and nothing else: a test of a language is a test of the API.
 */

#include "textual_check.h"

#include <time.h>

#define PY KGENOME_TEXTUAL_LANG_PY

static void py(const char *src, const char *want)
{
	expect_lang(PY, src, want);
}

/* Not confirmed by the interpreter here (python 2, 3.14, not a program): the reason is the comment at the call. */
static void pyx(const char *src, const char *want)
{
	expect_lang(PY, src, want);
}

static void prefixes(void)
{
	/* every prefix the language has, in the cases it is written in: raw ones do not interpret a backslash */
	static const struct { const char *p; int raw; } ok[] = {
		{ "r", 1 }, { "R", 1 }, { "u", 0 }, { "U", 0 }, { "b", 0 }, { "B", 0 }, { "f", 0 }, { "F", 0 },
		{ "rb", 1 }, { "rB", 1 }, { "Rb", 1 }, { "RB", 1 }, { "br", 1 }, { "bR", 1 }, { "Br", 1 }, { "BR", 1 },
		{ "rf", 1 }, { "rF", 1 }, { "Rf", 1 }, { "RF", 1 }, { "fr", 1 }, { "fR", 1 }, { "Fr", 1 }, { "FR", 1 },
	};
	/* a name in front of a quote that is not one of those is a name and a string: bu, ub, uf, fb, bf, uu, bb,
	 * ff, rr, ru, rub and the rest ("ur" is python 2 and is below) */
	static const char *const no[] = { "bu", "ub", "uf", "fu", "bf", "fb", "uu", "bb", "ff", "rr", "ru", "rub",
					  "bur", "print", "x", "R2", "_r", "r_", "b1", "rbf" };
	char src[64], want[96];
	unsigned i;

	for (i = 0; i < sizeof ok / sizeof ok[0]; i++) {
		snprintf(src, sizeof src, "x=%s\"a\\\\\"", ok[i].p);
		snprintf(want, sizeof want, "C{x=}S%s{%s\"a\\\\\"}", ok[i].raw ? "" : "*", ok[i].p);
		py(src, want);
		snprintf(src, sizeof src, "%s'''a'''", ok[i].p);
		snprintf(want, sizeof want, "S%s{%s'''a'''}", ok[i].raw ? "" : "*", ok[i].p);
		py(src, want);
	}
	for (i = 0; i < sizeof no / sizeof no[0]; i++) {
		snprintf(src, sizeof src, "%s\"a\"", no[i]);
		snprintf(want, sizeof want, "C{%s}S*{\"a\"}", no[i]);
		py(src, want);
	}
	/* a name is read whole: "bar'x'" is not an r prefix, and a digit or a name byte of 0x80 or more makes a name */
	py("bar'x' rb'y'", "C{bar}S*{'x'}C{ }S{rb'y'}");
	py("caf\xc3\xa9'x'", "C{caf\xc3\xa9}S*{'x'}");
	py("\xc3\xa9" "f'x'", "C{\xc3\xa9" "f}S*{'x'}");
	/* the prefix is part of the string, the neighbours on either side are not */
	py("a.rb'x'", "C{a.}S{rb'x'}");
	py("(b'x',B\"y\")", "C{(}S*{b'x'}C{,}S*{B\"y\"}C{)}");
	/* python 2: "ur" and "UR" are prefixes there, python 3 reads a name and a string; this lexer is for the code
	 * that is still python 2, and "ru" is neither */
	pyx("ur'x' uR'y' Ur'z' UR'w' ru'v'", "S{ur'x'}C{ }S{uR'y'}C{ }S{Ur'z'}C{ }S{UR'w'}C{ ru}S*{'v'}");
	/* the template string of 3.14 (PEP 750) is lexed like an f-string; 3.13 has no such prefix */
	pyx("t'a{b}' T\"c\" rt'd' Tr'e{f}'", "S{t'a{b}'}C{ }S*{T\"c\"}C{ }S{rt'd'}C{ }S{Tr'e{f}'}");
}

static void quotes(void)
{
	py("'a' \"b\" '''c''' \"\"\"d\"\"\"", "S*{'a'}C{ }S*{\"b\"}C{ }S*{'''c'''}C{ }S*{\"\"\"d\"\"\"}");
	/* the other quote is a byte of the string, two of the same kind are not a closer of a triple one */
	py("'a\"b' \"a'b\" '''a''b''' \"\"\"a\"\"b\"\"\" '''a'b'''", "S*{'a\"b'}C{ }S*{\"a'b\"}C{ }S*{'''a''b'''}C{ }S*{\"\"\"a\"\"b\"\"\"}C{ }S*{'''a'b'''}");
	/* empty: "" is a string, """ opens a triple one, "" "x" is two strings and """x" is not */
	py("'' \"\" '''''' \"\"\"\"\"\"", "S*{''}C{ }S*{\"\"}C{ }S*{''''''}C{ }S*{\"\"\"\"\"\"}");
	py("\"\" \"x\"", "S*{\"\"}C{ }S*{\"x\"}");
	pyx("\"\"\"x\"", "S*!{\"\"\"x\"}");
	/* adjacent strings are two spans: implicit concatenation is the parser's */
	py("'a''b'\"c\"'''d'''", "S*{'a'}S*{'b'}S*{\"c\"}S*{'''d'''}");
	/* a triple string holds line breaks, comment markers and quotes of both kinds */
	py("x = '''a # b\n\"\"\" 'c\n''' # d", "C{x = }S*{'''a # b\n\"\"\" 'c\n'''}C{ }K{# d}");
	/* four quotes: the first three close, the fourth opens a string that is not closed */
	pyx("\"\"\"a\"\"\"\"", "S*{\"\"\"a\"\"\"}S*!{\"}");
	/* unclosed: a one-line string ends at its line, a triple one at the end of the text */
	pyx("'abc", "S*!{'abc}");
	pyx("'abc\ndef'", "S*!{'abc}C{\ndef}S*!{'}");
	pyx("'abc\r\ndef", "S*!{'abc}C{\r\ndef}");
	pyx("'abc\rdef", "S*!{'abc}C{\rdef}");
	pyx("\"\"\"abc\ndef", "S*!{\"\"\"abc\ndef}");
	pyx("'''abc''", "S*!{'''abc''}");
	pyx("\"\"\"", "S*!{\"\"\"}");
	pyx("\"\"", "S*{\"\"}");
	pyx("\"", "S*!{\"}");
	pyx("rb'", "S!{rb'}");
	/* a backslash at the very end does not run off it */
	pyx("'a\\", "S*!{'a\\}");
	pyx("r'a\\", "S!{r'a\\}");
	pyx("'''a\\", "S*!{'''a\\}");
}

static void escapes(void)
{
	/* a backslash escapes the next byte, in a raw string too: r"\"" is the string \" and r'\' is not closed */
	py("'a\\'b' 'c\\\\' \"d\\\"e\" x", "S*{'a\\'b'}C{ }S*{'c\\\\'}C{ }S*{\"d\\\"e\"}C{ x}");
	py("r\"\\\"\" r'\\\\' x", "S{r\"\\\"\"}C{ }S{r'\\\\'}C{ x}");
	pyx("r'\\' x", "S!{r'\\' x}");
	py("'\\\\' x", "S*{'\\\\'}C{ x}");
	py("'\\\\\\'' x", "S*{'\\\\\\''}C{ x}");
	/* a backslash and the line break after it continue a one-line string, whichever the break is */
	py("x='a\\\nb' y", "C{x=}S*{'a\\\nb'}C{ y}");
	py("x='a\\\r\nb' y", "C{x=}S*{'a\\\r\nb'}C{ y}");
	py("x='a\\\rb' y", "C{x=}S*{'a\\\rb'}C{ y}");
	py("x=\"a\\\n\\\nb\" y", "C{x=}S*{\"a\\\n\\\nb\"}C{ y}");
	py("x=r'a\\\nb' y", "C{x=}S{r'a\\\nb'}C{ y}");
	/* spelled-out bytes and names are escapes of the string, not of the lexer */
	py("'\\x41\\101\\u0041\\U00000041\\N{LATIN SMALL LETTER A}\\n\\0'", "S*{'\\x41\\101\\u0041\\U00000041\\N{LATIN SMALL LETTER A}\\n\\0'}");
	py("b'\\x41\\101\\n' rb'\\x41'", "S*{b'\\x41\\101\\n'}C{ }S{rb'\\x41'}");
	/* a quote after a backslash in a triple string is not a closer; the one after a pair of them is */
	py("'''a\\'''' x", "S*{'''a\\''''}C{ x}");
	py("\"\"\"a\\\"\"\"\" x", "S*{\"\"\"a\\\"\"\"\"}C{ x}");
	py("'''a\\\\''' x", "S*{'''a\\\\'''}C{ x}");
}

static void fstrings(void)
{
	/* a field is code: no byte of it is an escape of the string, so the string is not flagged */
	py("f\"a{b}c\" x", "S{f\"a{b}c\"}C{ x}");
	py("f\"a\\x41c\"", "S*{f\"a\\x41c\"}");
	/* "{{" and "}}" are bytes, not a field */
	py("f\"{{x}}\" f'}}{{'", "S*{f\"{{x}}\"}C{ }S*{f'}}{{'}");
	py("f\"}}{x}\" x", "S{f\"}}{x}\"}C{ x}");
	/* conversion, the debugging "=", a spec, a spec with fields of its own, to any depth */
	py("f\"{x!r}{x=}{x = }{x=!s:>5}{x:{w}.{p}}{x:{y:{z}}}\"", "S{f\"{x!r}{x=}{x = }{x=!s:>5}{x:{w}.{p}}{x:{y:{z}}}\"}");
	py("f\"{x!r:>{w}}\" f\"{x:=5}\" f\"{(y:=5)}\"", "S{f\"{x!r:>{w}}\"}C{ }S{f\"{x:=5}\"}C{ }S{f\"{(y:=5)}\"}");
	/* "{{}}" in a spec is a field whose expression is "{}" */
	py("f\"{x:{{}}}\" z", "S{f\"{x:{{}}}\"}C{ z}");
	/* strings in a field: the same quote (3.12), the other, triple ones, and a brace or a hash in them */
	py("f\"{\"a\"}\" f'{'b'}' f\"{'c'}\" f'{\"d\"}' x", "S{f\"{\"a\"}\"}C{ }S{f'{'b'}'}C{ }S{f\"{'c'}\"}C{ }S{f'{\"d\"}'}C{ x}");
	py("f\"{'}'}\" f\"{'{'}\" f\"{'#'}\" f\"{\"}\"}\" x", "S{f\"{'}'}\"}C{ }S{f\"{'{'}\"}C{ }S{f\"{'#'}\"}C{ }S{f\"{\"}\"}\"}C{ x}");
	py("f\"{'''a'b'''}\" f'''{\"\"\"x\"\"\"}''' y", "S{f\"{'''a'b'''}\"}C{ }S{f'''{\"\"\"x\"\"\"}'''}C{ y}");
	py("f\"{'\\\"'}\" f'{\"\\'\"}' y", "S{f\"{'\\\"'}\"}C{ }S{f'{\"\\'\"}'}C{ y}");
	/* an f-string in an f-string, and the same quote all the way down */
	py("f\"{f\"{1}\"}\" f\"{f'{f\"{1}\"}'}\" f\"{f\"{f\"{f\"{x}\"}\"}\"}\" y",
	   "S{f\"{f\"{1}\"}\"}C{ }S{f\"{f'{f\"{1}\"}'}\"}C{ }S{f\"{f\"{f\"{f\"{x}\"}\"}\"}\"}C{ y}");
	py("f\"{rf'{x}'}\" f\"{b'x'}\" f\"{r'\\x41'}\" y", "S{f\"{rf'{x}'}\"}C{ }S{f\"{b'x'}\"}C{ }S{f\"{r'\\x41'}\"}C{ y}");
	/* brackets and colons in an expression: a colon inside brackets is not a spec, a lambda needs parentheses */
	py("f\"{x[1:2]}{d['k']}{d[1:2]!r:>5}{(lambda a: a)(1)}{ {1:2}[1] }{[i for i in y]}\" z",
	   "S{f\"{x[1:2]}{d['k']}{d[1:2]!r:>5}{(lambda a: a)(1)}{ {1:2}[1] }{[i for i in y]}\"}C{ z}");
	/* the field of a one-line f-string may run over lines, and has a comment of its own, braces and quotes in it */
	py("f'{x\n+1}' y", "S{f'{x\n+1}'}C{ y}");
	py("f'{x # c } \" \n}' y", "S{f'{x # c } \" \n}'}C{ y}");
	py("f'{a\\\n}' y", "S{f'{a\\\n}'}C{ y}");
	py("f\"\"\"{x[\"a\"]} \"b\" ''c\n{y}\"\"\" z", "S{f\"\"\"{x[\"a\"]} \"b\" ''c\n{y}\"\"\"}C{ z}");
	/* a backslash does not escape a brace: f"\{x}" is a backslash and a field, raw or not; "\\" is a pair */
	py("f\"\\{6}\" rf\"\\{6}\" f\"\\\\{x}\" y", "S{f\"\\{6}\"}C{ }S{rf\"\\{6}\"}C{ }S{f\"\\\\{x}\"}C{ y}");
	/* \N{...} is a name in a str and "\N" then a field in a raw one */
	py("f\"\\N{DIGIT ONE}\" f\"\\N{DIGIT ONE}{1}\" rf\"\\N{x}\" y", "S*{f\"\\N{DIGIT ONE}\"}C{ }S{f\"\\N{DIGIT ONE}{1}\"}C{ }S{rf\"\\N{x}\"}C{ y}");
	/* the quote of the string, escaped, is not its end, in a raw one too */
	py("f\"\\\"{x}\" rf\"\\\"{x}\" y", "S{f\"\\\"{x}\"}C{ }S{rf\"\\\"{x}\"}C{ y}");
	/* fields side by side, and strings after them */
	py("f\"{a}\" f'{b}' \"c\"", "S{f\"{a}\"}C{ }S{f'{b}'}C{ }S*{\"c\"}");
	py("f\"{a}{b}\"f'{c}'", "S{f\"{a}{b}\"}S{f'{c}'}");
	/* NOT PROGRAMS. A lone "}" is a byte. A field that is still open where the scan stops - the end of the text, or a
	 * string inside it that is not closed - makes the f-string open, and the span is every byte the scan read, so
	 * nothing is read twice and what follows starts where the scan stopped. */
	pyx("f\"a}b\" x", "S*{f\"a}b\"}C{ x}");
	pyx("f\"abc{x", "S!{f\"abc{x}");
	pyx("f\"abc{x\" y", "S!{f\"abc{x\" y}");
	pyx("f\"abc{x\"\ny = 1", "S!{f\"abc{x\"}C{\ny = 1}");
	pyx("f\"{x\nq\" z", "S!{f\"{x\nq\" z}");
	pyx("f'{' y", "S!{f'{' y}");
	pyx("f\"{x:\" y\"", "S{f\"{x:\"}C{ y}S*!{\"}");
	pyx("f'''{x\n", "S!{f'''{x\n}");
	pyx("f\"{\"#\"(\n:\"#", "S!{f\"{\"#\"(\n:\"#}");
	/* the work is linear: a text made of nothing but this is in the property test */
	pyx("f'{\nf'{\n", "S!{f'{\nf'{\n}");
}

static void numbers(void)
{
	/* a number is not lexed, and no keyword is a prefix: a number then a name is a number and a name */
	py("1if x else 2", "C{1if x else 2}");
	py("[1for x in 'ab']", "C{[1for x in }S*{'ab'}C{]}");
	py("x=1if'a'else'b'", "C{x=1if}S*{'a'}C{else}S*{'b'}");
	py("0x1for y in z", "C{0x1for y in z}");
	py("0xfor'x'", "C{0xfor}S*{'x'}");
	py("1_000 0b101 0o17 1e-3 1j .5 1. 0xB", "C{1_000 0b101 0o17 1e-3 1j .5 1. 0xB}");
	py("1or\"a\" 1and'b' 1in'c' 1is'd'", "C{1or}S*{\"a\"}C{ 1and}S*{'b'}C{ 1in}S*{'c'}C{ 1is}S*{'d'}");
	py("x = 0xb'y'", "C{x = 0xb}S*{'y'}");
	py("1.real 1 .real x1'y'", "C{1.real 1 .real x1}S*{'y'}");
	/* keywords next to a string with no space between them */
	py("a if b else'c'", "C{a if b else}S*{'c'}");
	py("not'a' in'b' or'c' and'd'", "C{not}S*{'a'}C{ in}S*{'b'}C{ or}S*{'c'}C{ and}S*{'d'}");
	py("lambda:'x'", "C{lambda:}S*{'x'}");
	py("def f():\n return'x'\n", "C{def f():\n return}S*{'x'}C{\n}");
}

static void comments(void)
{
	py("# c\nx", "K{# c}C{\nx}");
	py("x = 1 # c\ny", "C{x = 1 }K{# c}C{\ny}");
	/* a comment ends at any line break */
	py("# c\r\nx", "K{# c}C{\r\nx}");
	py("# c\rx", "K{# c}C{\rx}");
	/* a comment marker in a string is the string's, and a quote or a backslash in a comment is the comment's */
	py("'#' # \"x' ''' \\\ny", "S*{'#'}C{ }K{# \"x' ''' \\}C{\ny}");
	py("'a'#c\n\"b\"#d", "S*{'a'}K{#c}C{\n}S*{\"b\"}K{#d}");
	/* the interpreter line, an encoding declaration and a byte order mark are comments to a lexer */
	py("#!/usr/bin/env python\n# -*- coding: latin-1 -*-\nx", "K{#!/usr/bin/env python}C{\n}K{# -*- coding: latin-1 -*-}C{\nx}");
	py("\xef\xbb\xbf# c\nx", "C{\xef\xbb\xbf}K{# c}C{\nx}");
	/* in brackets, with a comment after each element */
	py("x = [1, # a\n 'b', # c\n]", "C{x = [1, }K{# a}C{\n }S*{'b'}C{, }K{# c}C{\n]}");
	py("x = (  # '''\n 1)", "C{x = (  }K{# '''}C{\n 1)}");
	/* comments in a field of an f-string are the string's */
	py("f'{x # not a comment\n}' # is", "S{f'{x # not a comment\n}'}C{ }K{# is}");
}

static void continuations(void)
{
	py("x = 1 + \\\n 2", "C{x = 1 + \\\n 2}");
	py("x = 1 + \\\r\n 2", "C{x = 1 + \\\r\n 2}");
	py("x = 1 + \\\r 2", "C{x = 1 + \\\r 2}");
	py("x = 1 \\\n# c\ny", "C{x = 1 \\\n}K{# c}C{\ny}");
	py("x = 'a' \\\n 'b'", "C{x = }S*{'a'}C{ \\\n }S*{'b'}");
	py("x = 1 \\\n \\\n + 2 # c", "C{x = 1 \\\n \\\n + 2 }K{# c}");
	/* NOT PROGRAMS: a backslash and the byte after it are one thing outside a string, as they are to the form - the
	 * interpreter stops at one that is not a continuation - so a quote after it begins nothing, and a "#" that
	 * follows it is no comment. The form closing up the comment must not turn it into a continuation. */
	pyx("x = \\\"a\"", "C{x = \\\"a}S*!{\"}");
	pyx("x = 1 \\#c\ny", "C{x = 1 \\#c\ny}");
	pyx("x = 1 \\ # c", "C{x = 1 \\ }K{# c}");
	pyx("x \\", "C{x \\}");
	pyx("\\", "C{\\}");
	/* form feed and tab are white space */
	py("\fx = 1\t# c\n\t'a'", "C{\fx = 1\t}K{# c}C{\n\t}S*{'a'}");
}

static void python2(void)
{
	/* none of these is python 3; what old malware writes is lexed the same way */
	pyx("print \"a %s\" % b, 'c'\n", "C{print }S*{\"a %s\"}C{ % b, }S*{'c'}C{\n}");
	pyx("print\"x\"", "C{print}S*{\"x\"}");
	pyx("print >>f, 'x' # c", "C{print >>f, }S*{'x'}C{ }K{# c}");
	pyx("x = `y` + \"z\"", "C{x = `y` + }S*{\"z\"}");
	pyx("if a <> b: print 'x'", "C{if a <> b: print }S*{'x'}");
	pyx("exec \"code\" in d", "C{exec }S*{\"code\"}C{ in d}");
	pyx("x = 0777L + 0xFFL # c", "C{x = 0777L + 0xFFL }K{# c}");
	pyx("raise E, 'msg'\nexcept E, e: pass", "C{raise E, }S*{'msg'}C{\nexcept E, e: pass}");
	pyx("x = ur'\\d' + u'\\u1234'", "C{x = }S{ur'\\d'}C{ + }S*{u'\\u1234'}");
}

static void modern(void)
{
	py("@dec('x')\ndef f(a: 'int' = \"b\", *c, **d) -> 'e': pass", "C{@dec(}S*{'x'}C{)\ndef f(a: }S*{'int'}C{ = }S*{\"b\"}C{, *c, **d) -> }S*{'e'}C{: pass}");
	py("if (n := 'x'): pass", "C{if (n := }S*{'x'}C{): pass}");
	py("match x:\n    case 'a' | \"b\":\n        pass\n    case {'k': v}: pass",
	   "C{match x:\n    case }S*{'a'}C{ | }S*{\"b\"}C{:\n        pass\n    case {}S*{'k'}C{: v}: pass}");
	py("async def f():\n    async with a('x') as b: await c(\"y\")", "C{async def f():\n    async with a(}S*{'x'}C{) as b: await c(}S*{\"y\"}C{)}");
	py("type X = 'y'\nx: 'List[int]' = []", "C{type X = }S*{'y'}C{\nx: }S*{'List[int]'}C{ = []}");
	py("class A(B, metaclass=M):\n    '''doc\n    string'''\n    x = lambda: 'y'", "C{class A(B, metaclass=M):\n    }S*{'''doc\n    string'''}C{\n    x = lambda: }S*{'y'}");
	py("a = b if c else d; e = 'f'; g = [*h, *'ij']", "C{a = b if c else d; e = }S*{'f'}C{; g = [*h, *}S*{'ij'}C{]}");
}

#include "textual_py_gen.h"

/* ---- (d) the form ---- */

static void fm(const char *src, const char *want)
{
	form_lang(PY, src, want);
}

static void forms(void)
{
	fm("", "");
	/* indentation goes - the form is for a marker to match, not for the interpreter - and a line break stays one;
	 * blank lines, comments and the white space inside a line go */
	fm("if x :\n    y = 1  # c\n\n\n    z = 2\n", "if x:\ny=1\nz=2");
	fm("def f(a, b = 2):\n    return a+b\n", "def f(a,b=2):\nreturn a+b");
	fm("if x:\n\tpass\n", "if x:\npass");
	fm("# only\n", "");
	fm("\fx = 1\n\t\n  # c\n", "x=1");
	fm("x = a  # c1\n# c2\n\n# c3\ny = 2", "x=a\ny=2");
	/* a name next to a name keeps its space, and a digit is a name byte here: "1if" is typed as it is */
	fm("x = a if b else c", "x=a if b else c");
	fm("x = 1 if y else 2 ; z = 1 or 2", "x=1 if y else 2;z=1 or 2");
	fm("x = a if b else\"c\"; y = 1if z else 2", "x=a if b else\"c\";y=1if z else 2");
	fm("lambda x: x; lambda *a, y=1: a", "lambda x:x;lambda*a,y=1:a");
	fm("not  x; a  and  b; a  in  b", "not x;a and b;a in b");
	/* a comment is a gap: it separates two names */
	fm("a # c\nb", "a\nb");
	fm("x = (a #c\n  + b)", "x=(a\n+b)");
	/* what closing up would change keeps its space. "* *" is "**", "/ /" is "//", "< <" and "> >" shift, a
	 * digit then "." is "1.real" which is not python, an operator then "=" is an assignment operator; the
	 * pairs that are two tokens either way - "- -", "+ +", "< -", ". ." - close up */
	fm("x = b * * c; x = b / / c; x = b < < c", "x=b* *c;x=b/ /c;x=b< <c");
	fm("x = 1 .real; y = a . b", "x=1 .real;y=a.b");
	fm("x = b - -c; x = - - b; x = + + b; x = a < -b; x = a ** -b", "x=b--c;x=--b;x=++b;x=a<-b;x=a**-b");
	fm("x = a : = 1", "x=a: =1");
	fm("x = a == b; y = a ! = b; z = a < = b", "x=a==b;y=a! =b;z=a< =b");
	fm("x = a - > b", "x=a- >b");
	fm("x [ 1 : 2 ]; y = a [ : : 2 ]; z = a [ 1 : ]", "x[1:2];y=a[::2];z=a[1:]");
	fm("x = [ 1 , 2 ]; print(a, file = f); d = { 1 : 2 }", "x=[1,2];print(a,file=f);d={1:2}");
	fm("x: int = 5\nif (n := 5): pass", "x:int=5\nif(n:=5):pass");
	fm("x = a ; y = b ;", "x=a;y=b;");
	fm("@ dec ( 1 )\ndef f(): pass", "@dec(1)\ndef f():pass");
	fm("from . import x\nimport a . b", "from.import x\nimport a.b");
	/* two strings: the space stays where the quotes would meet - "" "y" is two strings, """y" is not */
	fm("x = \"\" \"y\"; x = \"a\" \"b\"; x = 'a' \"b\"; x = '' ''", "x=\"y\";x=\"ab\";x='a'\"b\";x=''");
	/* a line continuation keeps its break, whichever the break is typed as, and the white space after it is a gap */
	fm("x = 1 + \\\n    2", "x=1+\\\n2");
	fm("x = 1 + \\\r\n    2\r\ny = 3\r\n", "x=1+\\\n2\ny=3");
	fm("x = 1 + \\\r    2\ry = 3", "x=1+\\\n2\ny=3");
	fm("x = a \\\n if b else c", "x=a\\\nif b else c");
	/* a lone CR is a line break, as the interpreter reads it */
	fm("a = 1\rb = 2\r", "a=1\nb=2");
	fm("a = 1 # c\rb = 2", "a=1\nb=2");
	/* a string is every byte of itself, a triple one with its line breaks and its indentation */
	fm("x = \"a   b\" + 'c\\'  d'  # c", "x=\"a   b\"+'c\\'  d'");
	fm("x = \"\"\"a\n    b  \"\"\"  # c", "x=\"\"\"a\n    b  \"\"\"");
	fm("x = f\"{ a }  {b!r:>{w}}\" + r\"a  b\"", "x=f\"{ a }  {b!r:>{w}}\"+r\"a  b\"");
	fm("x = f\"{ '#' }\"  # c", "x=f\"{ '#' }\"");
	/* a string that is not closed is kept as typed; the form of it is the text up to it, formed */
	fm("x = 'abc", "x='abc");
	fm("x  =  f\"{a", "x=f\"{a");
}

/* The spelled-out bytes of a python string, written as themselves: exactly what a python string reads as an escape. */
static void unescapes(void)
{
	/* the names a script spells so that no marker finds them */
	fm("x = \"\\x65\\x76\\x61\\x6c\" + '\\101\\102'", "x=\"eval\"+'AB'");
	fm("x = \"\\x41B\\x4a\\x4A\"", "x=\"ABJJ\"");
	fm("x = '''\\x41\n\\101'''", "x='''A\nA'''");
	fm("x = u\"\\x41\" + U'\\x42' + b'\\x43' + B\"\\x44\"", "x=u\"A\"+U'B'+b'C'+B\"D\"");
	/* \u and \U are escapes in a str and not in bytes, and a byte above 0x7e is not written as itself */
	fm("x = \"\\u0041\\U00000042\" + b'\\u0041' + '\\u00e9\\u2022'", "x=\"AB\"+b'\\u0041'+'\\u00e9\\u2022'");
	fm("x = \"\\U00110000\\u004\" + \"\\N{LATIN SMALL LETTER A}\"", "x=\"\\U00110000\\u004\\N{LATIN SMALL LETTER A}\"");
	/* exactly two hex digits, up to \377, and "\501" is U+0141 in a str, which no byte can stand for */
	fm("x = '\\x4' + '\\x' + '\\501' + '\\777' + '\\1011'", "x='\\x4\\x\\501\\777A1'");
	/* a byte that is not printable, a quote of either kind, a backslash and a brace stay as typed */
	fm("x = '\\x0a\\x7f\\x01\\2\\7' + '\\x22\\x27\\x5c\\x7b\\x7d'", "x='\\x0a\\x7f\\x01\\2\\7\\x22\\x27\\x5c\\x7b\\x7d'");
	fm("x = \"\\x27\" + '\\x22' + \"\\x22\"", "x=\"\\x27\"+'\\x22'+\"\\x22\"");
	/* a backslash and the byte after it are a pair: \\x41 is a backslash and the text x41 */
	fm("x = '\\\\x41' + '\\\\\\x41'", "x='\\\\x41\\\\A'");
/* an escape still waiting for digits does not take the next piece's: "\\1" + "2" is two things, "\\12" is one */
	fm("x = '\\1' + '2'; y = '\\x4' + 'a'; z = '\\x41' + 'a'; w = '\\1' + 'a'", "x='\\1'+'2';y='\\x4'+'a';z='Aa';w='\\1a'");
	fm("x = '\\x4\\x61' + '\\x4\\x67'", "x='\\x4\\x61\\x4g'");
	fm("x = '\\u12\\x34' + '\\u12\\x67'", "x='\\u12\\x34\\u12g'");
	/* not a string that has an escape in it: raw, and an f-string with a field in it (code in there has strings
	 * of its own - r'\x41' - where nothing is an escape), but an f-string with none is a plain string */
	fm("x = r'\\x41' + rb'\\x41' + Rb'\\101'", "x=r'\\x41'+rb'\\x41'+Rb'\\101'");
	fm("x = f'\\x41{a}' + f\"{r'\\x41'}\\x41\" + rf'\\x41'", "x=f'\\x41{a}'+f\"{r'\\x41'}\\x41\"+rf'\\x41'");
	fm("x = f'\\x41' + f'\\x41{{' + f'\\x7b' + F\"\\x41\\N{DIGIT ONE}\"", "x=f'A'+f'A{{'+f'\\x7b'+F\"A\\N{DIGIT ONE}\"");
	/* a comment holding an escape is a comment, and goes */
	fm("x = 1 # '\\x41'", "x=1");
}

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
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = PY,
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
		hex[] = { KGENOME_TEXTUAL_DEC_HEX }, url[] = { KGENOME_TEXTUAL_DEC_URL }, rawurl[] = { KGENOME_TEXTUAL_DEC_RAWURL },
		gz[] = { KGENOME_TEXTUAL_DEC_GZIP }, zl[] = { KGENOME_TEXTUAL_DEC_ZLIB };
	struct kgenome_textual_form_res rs;

	/* the call, qualified by its module or not (after "from base64 import b64decode"), a str or a bytes literal */
	rs = dform("exec(base64.b64decode(\"abc\"))", "exec(base64.decoded_b64decode(\"<ABC>\"))");
	CK(rs.n_decoded == 1 && rs.n_refused == 0 && hook_calls == 1 && chain_is(1, b64));
	dform("exec(b64decode('abc'))", "exec(decoded_b64decode('<ABC>'))");
	CK(chain_is(1, b64));
	dform("x = base64.b64decode(b'abc') + base64.standard_b64decode(B\"d\")",
	      "x=base64.decoded_b64decode(b'<ABC>')+base64.decoded_standard_b64decode(B\"<D>\")");
	CK(hook_calls == 2);
	/* the chain, innermost first, however the calls are qualified and spaced, and it ends at the first name that is
	 * not a decoder - marshal.loads, compile, exec - which is not this lib's business */
	dform("exec(marshal.loads(zlib.decompress(base64.b64decode(\"ab\"))))",
	      "exec(marshal.loads(zlib.decoded_decompress(base64.decoded_b64decode(\"<AB>\"))))");
	CK(chain_is(2, b64_zlib));
	dform("exec(decompress(b64decode('ab')))", "exec(decoded_decompress(decoded_b64decode('<AB>')))");
	CK(chain_is(2, b64_zlib));
	/* (a name that ends in a digit keeps the space before a dot - "1 .real" is not "1.real" and the form cannot tell
	 * the name from the number - which costs one byte on "base64 . b64decode" and nothing on "base64.b64decode") */
	dform("exec ( zlib . decompress ( base64 . b64decode ( 'ab' ) ) )", "exec(zlib.decoded_decompress(base64.decoded_b64decode('<AB>')))");
	CK(chain_is(2, b64_zlib));
	dform("exec(compile(base64.b64decode('ab'), 'f', 'exec'))", "exec(compile(base64.decoded_b64decode('<AB>'),'f','exec'))");
	CK(chain_is(1, b64) && hook_calls == 1);
	dform("x = a.b.base64.b64decode('ab')", "x=a.b.base64.decoded_b64decode('<AB>')");
	CK(chain_is(1, b64));
	/* hex, gzip, url */
	dform("binascii.unhexlify('41')", "binascii.decoded_unhexlify('<41>')");
	CK(chain_is(1, hex));
	dform("a2b_hex('41'); bytes.fromhex('41 42'); bytearray.fromhex('41')",
	      "decoded_a2b_hex('<41>');bytes.decoded_fromhex('<41 42>');bytearray.decoded_fromhex('<41>')");
	CK(hook_calls == 3 && chain_is(1, hex));
	/* unquote and unquote_to_bytes KEEP "+" (verified with python 3); only unquote_plus reads it as a space */
	dform("urllib.parse.unquote('%41%42')", "urllib.parse.decoded_unquote('<%41%42>')");
	CK(chain_is(1, rawurl));
	dform("urllib.unquote_plus('a+b'); unquote_to_bytes('%41')", "urllib.decoded_unquote_plus('<A+B>');decoded_unquote_to_bytes('<%41>')");
	CK(hook_calls == 2 && chain_is(1, rawurl));         /* the last asked was unquote_to_bytes */
	dform("urllib.unquote_plus('a+b')", "urllib.decoded_unquote_plus('<A+B>')");
	CK(chain_is(1, url));
	dform("gzip.decompress(b'ab')", "gzip.decoded_decompress(b'<AB>')");
	CK(chain_is(1, gz));
	/* "decompress" is zlib's when the module is zlib or unknown and gzip's when it is gzip; bz2 and lzma have no
	 * decoder id, so the call ends the chain - what is under it is decoded, what it makes is not */
	dform("zlib.decompress('ab')", "zlib.decoded_decompress('<AB>')");
	CK(chain_is(1, zl));
	dform("bz2.decompress('ab'); lzma.decompress('ab')", "bz2.decompress('ab');lzma.decompress('ab')");
	CK(hook_calls == 0);
	dform("bz2.decompress(base64.b64decode('ab'))", "bz2.decompress(base64.decoded_b64decode('<AB>'))");
	CK(chain_is(1, b64));
	/* NOT a decoder: the name has to end at a dot or at its start - my_b64decode - and float.fromhex reads a
	 * hexadecimal float; a keyword argument or a second argument is not the payload */
	dform("my_b64decode('ab'); float.fromhex('0x1p3'); fromhex('41'); Base64.B64decode('x')",
	      "my_b64decode('ab');float.fromhex('0x1p3');fromhex('41');Base64.B64decode('x')");
	CK(hook_calls == 0);
	dform("b64decode(s='ab'); b64decode(x, 'ab')", "b64decode(s='ab');b64decode(x,'ab')");
	CK(hook_calls == 0);
	/* the literals have to be the whole of the argument: a join of literals ("+" or side by side) is the payload, an
	 * expression on it is not */
	dform("b64decode('a' + 'b'); b64decode('a' 'b'); b64decode('a'[::-1]); b64decode('a'.upper())",
	      "decoded_b64decode('<AB>');decoded_b64decode('<AB>');b64decode('a'[::-1]);b64decode('a'.upper())");
	CK(hook_calls == 2);
	/* a second argument after it is kept (altchars, validate) and the literal is still the payload */
	dform("b64decode('ab', altchars=x)", "decoded_b64decode('<AB>',altchars=x)");
	CK(hook_calls == 1);
	/* a comment between the literal and the bracket is a gap */
	dform("b64decode(  # c\n 'ab' # d\n )", "decoded_b64decode(\n'<AB>'\n)");
	CK(hook_calls == 1);
	/* NOT EXPRESSIBLE: the coding is named in an argument after the literal, or the literal has no call in front of it */
	dform("codecs.decode('616263', 'hex'); codecs.decode('x', 'rot13'); 'YWJj'.decode('base64'); 'abc'[::-1]; ''.join(reversed('abc'))",
	      "codecs.decode('616263','hex');codecs.decode('x','rot13');'YWJj'.decode('base64');'abc'[::-1];''.join(reversed('abc'))");
	CK(hook_calls == 0);
	/* refused: the literal stays as typed and the refusal is counted; and one still open is not offered */
	rs = dform("b64decode('!ab')", "b64decode('!ab')");
	CK(rs.n_decoded == 0 && rs.n_refused == 1 && hook_calls == 1);
	dform("b64decode('ab", "b64decode('ab");
	CK(hook_calls == 0);
	/* an f-string with a field has no value (the field is the program's), so the hook is not asked; one without a field has
	 * one, with "{{" read as a brace */
	dform("b64decode(f'a{x}')", "b64decode(f'a{x}')");
	CK(hook_calls == 0);
	dform("b64decode(f'a{{b')", "decoded_b64decode(f'<A{B>')");
	CK(hook_calls == 1);
}

/* ---- (c) any text at all ---- */

static void properties(void)
{
	/* the spans partition the text, and the form of a form is itself, on text drawn from what changes the lexer's
	 * mind: quotes of both kinds, a backslash, braces, hash, prefix letters, line breaks of all three kinds, the
	 * characters of an operator and of a number */
	partition_for(PY, "#'\"\\\n\r\t\f {}()[]:=*/<>-+.@!,;_rbfutRBFU\\N019xX", 2024u);
	partition_for(PY, "'\"\\{}#fr\n:!=", 77u);
	partition_for(PY, "f\"'''{{}}:\\N#\n", 31u);
	form_property_for(PY, "#'\"\\\n\r\t\f {}()[]:=*/<>-+.@!,;_rbfutRBFU\\N019xX", 99u);
	form_property_for(PY, "'\"\\\nx41\\0u{}rb. =", 5u);
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

/* The spans partition a text cut at every length, and a deeply nested or hostile one is read in time proportional to it. */
static void hostile(void)
{
	static const char sample[] =
		"#!/usr/bin/python\nx = f\"a{b!r:>{w}}{'}'}\" rb'\\x41' \"\"\"t\n#\"\"\" # c\\\ny = (1 +\\\n  2) # d\nz = f'''{x[\"a\"]}''' + ur'\\d'\n";
	static struct rend r;
	uint32_t n;

	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, PY);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* f-strings nested past the interpreter's limit of 150 are lexed (as plain strings below it), not crashed on */
	{
		static char deep[8192];
		uint32_t w = 0, i;

		for (i = 0; i < 400u; i++) {
			memcpy(deep + w, "f\"{", 3);
			w += 3;
		}
		memcpy(deep + w, "x", 1);
		w++;
		for (i = 0; i < 400u; i++) {
			memcpy(deep + w, "}\"", 2);
			w += 2;
		}
		lex(&r, deep, w, PY);
		CK(!r.broken);
		/* below the limit it is one string */
		for (w = 0, i = 0; i < 100u; i++, w += 3)
			memcpy(deep + w, "f\"{", 3);
		deep[w++] = 'x';
		for (i = 0; i < 100u; i++, w += 2)
			memcpy(deep + w, "}\"", 2);
		lex(&r, deep, w, PY);
		CK(!r.broken && r.out[0] == 'S' && r.out[1] == '{' && !strchr(r.out, 'C'));
	}
	/* LINEAR WORK. Each of these is a text whose f-string fields never close, repeated until it is 600 KB. A lexer
	 * that read to the end for every "{" it could not close would do some 10^11 steps here; this takes a blink,
	 * and the bound on the whole is a few seconds even under a sanitizer. */
	{
		static const char *const unit[] = { "f'{\n", "f\"{x:{y:{\n", "x = f'{ \\N{\n", "f\'\'\'{(\n", "f\'\'\'{ [ \n", "{{{{f'{'{\\N{" };
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
			rq = (struct kgenome_textual_lex_req){ .in = big, .n = w, .lang = PY, .sink = whole_sink, .user = &c };
			st = kgenome_textual_lex(&rq, &rs);
			CK((st == KGENOME_TEXTUAL_OPEN || st == KGENOME_TEXTUAL_OK) && c.next == w && !c.broken && rs.n_span == c.n);
		}
		CK((double)(clock() - t0) / CLOCKS_PER_SEC < 20.0);
	}
}

int main(void)
{
	prefixes();
	quotes();
	escapes();
	fstrings();
	numbers();
	comments();
	continuations();
	python2();
	modern();
	generator();
	forms();
	unescapes();
	decoders();
	properties();
	hostile();
	printf("textual py: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
