/*
 * genome / textual_vbs - the VBScript lexer and form of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED, in four layers (see textual_check.h for how a span list is written: C code, S string,
 * K comment, S! a string that was not closed):
 *
 *  1. KNOWN ANSWERS. Every rule of textual_vb.c with the neighbour it could be taken for: "'" and Rem and a
 *     quote inside a string; "" doubling and two adjacent strings; "_" at the end of a line and "_" in a
 *     name; ":" and "::"; Rem where a statement begins (line start, after ":", after Then and Else) and where
 *     one does not (after an expression, after ".", inside a name, after a continuation); a date literal;
 *     "[name]"; the script encoder block; CR, LF and CRLF.
 *  2. A GENERATOR. Random valid programs built from tokens whose class is known at the moment they are
 *     placed - a Rem is written as a comment only where the generator has put a statement start, and as a
 *     name (a decoy) where it has not - laid out with random blanks, line breaks, ":" separators, continuations,
 *     comments and strings holding ' Rem "" : _ # [. The expected span list is built as the text is, and
 *     the lexer must give exactly it, as a vbs file and as the body of an asp island.
 *  3. PROPERTIES of any input: the spans partition it; the form of a form is itself; and on every generated
 *     program the form has no comment left and reads back, with blanks and comments out, as the same tokens.
 *  4. FORM KNOWN ANSWERS: what is closed up and what is not ("a& h1", "a< >b", "a (1)", "_" and its break).
 *
 * THE ORACLE. This tree has no VBScript interpreter, so nothing here is checked against the real one; the
 * rules marked [Inference] in textual_vb.c are decisions, and the generator agrees with them by construction.
 * A second implementation (pygments' VBScriptLexer) was compared on real files by a scratch tool; its
 * mismatches are classes the known answers below pin the other way, each with the reason.
 */

#include "textual_check.h"

#define VBS KGENOME_TEXTUAL_LANG_VBS
#define ASP KGENOME_TEXTUAL_LANG_ASP

static void vb(const char *src, const char *want)
{
	expect_lang(VBS, src, want);
}

static void asp(const char *src, const char *want)
{
	expect_lang(ASP, src, want);
}

static void form(const char *src, const char *want)
{
	form_lang(VBS, src, want);
}

static void comments(void)
{
	vb("", "");
	vb("x = 1 ' c", "C{x = 1 }K{' c}");
	vb("'c\nb", "K{'c}C{\nb}");
	/* a comment stops at any of the three line breaks, and the break is not in it */
	vb("' c\r\nb", "K{' c}C{\r\nb}");
	vb("' c\rb", "K{' c}C{\rb}");
	/* an apostrophe in a comment is the comment's, a quote too: nothing starts a string in it */
	vb("' it's \"x\n\"y\"", "K{' it's \"x}C{\n}S{\"y\"}");
	/* and the other way: "'" and Rem inside a string are the string's */
	vb("x = \"a ' b\" ' c", "C{x = }S{\"a ' b\"}C{ }K{' c}");
	vb("x = \"Rem a\"", "C{x = }S{\"Rem a\"}");
	vb("\"Rem\" : Rem c", "S{\"Rem\"}C{ : }K{Rem c}");
	/* a "_" ending a comment does not continue it: the next line is code */
	vb("' x _\ny", "K{' x _}C{\ny}");
	/* no block comment: slash-star and a "<!--" are code */
	vb("a /* b */ c", "C{a /* b */ c}");
}

static void rem(void)
{
	vb("Rem x", "K{Rem x}");
	vb("rem x", "K{rem x}");
	vb("REM x", "K{REM x}");
	vb("rEm x", "K{rEm x}");
	vb("  \t Rem x", "C{  \t }K{Rem x}");
	/* a Rem that is alone on its line: only itself, the next line is code (pygments swallows it) */
	vb("Rem\nb", "K{Rem}C{\nb}");
	vb("Rem", "K{Rem}");
	vb("a\nRem\nb", "C{a\n}K{Rem}C{\nb}");
	/* the word ends at the first byte that is not a name byte; the comment runs to the line's end, a ':' ends nothing */
	vb("Rem:x : y", "K{Rem:x : y}");
	vb("Rem.x", "K{Rem.x}");
	vb("Rem\"x\"", "K{Rem\"x\"}");
	vb("Rem(x)", "K{Rem(x)}");
	/* after ':' - and after '::', which is two separators - Rem begins a comment */
	vb("a : Rem y", "C{a : }K{Rem y}");
	vb("a:Rem y", "C{a:}K{Rem y}");
	vb("a::Rem y", "C{a::}K{Rem y}");
	vb("a : : Rem y", "C{a : : }K{Rem y}");
	/* a separator inside the comment does not begin another statement: the whole line is the comment */
	vb("Rem a : Rem b\nc", "K{Rem a : Rem b}C{\nc}");
	/* after Then and Else on a one-line If */
	vb("If a Then Rem x", "C{If a Then }K{Rem x}");
	vb("If a Then b Else Rem x", "C{If a Then b Else }K{Rem x}");
	vb("IF a THEN rem x", "C{IF a THEN }K{rem x}");
	vb("Select Case a\nCase Else Rem x", "C{Select Case a\nCase Else }K{Rem x}");
	/* not a comment: after an expression, after '.', inside a name, as a name of its own */
	vb("x = 1 Rem y", "C{x = 1 Rem y}");
	vb("x = Rem", "C{x = Rem}");
	vb("a.Rem y", "C{a.Rem y}");
	vb("a . Rem y", "C{a . Rem y}");
	vb("Remark = 1", "C{Remark = 1}");
	vb("Rem_x = 1", "C{Rem_x = 1}");
	vb("xrem = 1", "C{xrem = 1}");
	vb("a:xRem = 1", "C{a:xRem = 1}");
	vb("Rem1 = 1", "C{Rem1 = 1}");
	vb("a.Then Rem y", "C{a.Then Rem y}");
	vb("Thenx Rem y", "C{Thenx Rem y}");
	vb("xThen Rem y", "C{xThen Rem y}");
	vb("Dim a, Rem", "C{Dim a, Rem}");
	vb("f(Rem)", "C{f(Rem)}");
	/* the keyword does not begin a statement when it ends a name: "Else" in "Elsewhere" */
	vb("Elsewhere Rem y", "C{Elsewhere Rem y}");
	/* "'" still opens a comment after an expression, which Rem does not */
	vb("x = 1 'y", "C{x = 1 }K{'y}");
	/* the next line begins a statement */
	vb("x = 1\nRem y", "C{x = 1\n}K{Rem y}");
	vb("x = 1\r\nRem y", "C{x = 1\r\n}K{Rem y}");
	vb("x = 1\rRem y", "C{x = 1\r}K{Rem y}");
	/* Rem that is not whole: a name followed by bytes >= 0x80 is one name */
	vb("Rem\xc3\xa9 y", "C{Rem\xc3\xa9 y}");
}

static void strings(void)
{
	vb("a = \"x\"", "C{a = }S{\"x\"}");
	vb("\"\"", "S{\"\"}");
	vb("\"\"\"\"", "S{\"\"\"\"}");
	vb("\"a\"\"b\"", "S{\"a\"\"b\"}");
	/* "" doubling and two adjacent strings are different things */
	vb("\"a\" \"b\"", "S{\"a\"}C{ }S{\"b\"}");
	vb("\"\" \"\"", "S{\"\"}C{ }S{\"\"}");
	vb("\"\"\"\"\"\"", "S{\"\"\"\"\"\"}");
	vb("\"\"\"\" & \"\"", "S{\"\"\"\"}C{ & }S{\"\"}");
	/* an odd quote leaves the string open, to the end of its line */
	vb("\"\"\"", "S!{\"\"\"}");
	vb("\"abc", "S!{\"abc}");
	vb("\"abc\ndef", "S!{\"abc}C{\ndef}");
	vb("\"abc\r\ndef", "S!{\"abc}C{\r\ndef}");
	vb("\"abc\rdef", "S!{\"abc}C{\rdef}");
	vb("\"abc\nRem x", "S!{\"abc}C{\n}K{Rem x}");
	vb("\"abc\n'x", "S!{\"abc}C{\n}K{'x}");
	vb("\"a\"\"", "S!{\"a\"\"}");
	/* no escape: a backslash is a letter, and does not protect the quote after it */
	vb("\"a\\\"b", "S{\"a\\\"}C{b}");
	vb("\"a\\\\\" c", "S{\"a\\\\\"}C{ c}");
	/* "_" at the end of a string's line is not a continuation: the string is open there */
	vb("\"a _\nb\"", "S!{\"a _}C{\nb}S!{\"}");
	/* a string does not begin a statement: Rem after one is a name */
	vb("\"a\" Rem x", "S{\"a\"}C{ Rem x}");
	/* URLs, paths and SQL: what a webshell has in its strings */
	vb("Set o = CreateObject(\"WScript.Shell\")", "C{Set o = CreateObject(}S{\"WScript.Shell\"}C{)}");
	vb("c = \"cmd.exe /c \"\"dir\"\" & echo 'x'\"", "C{c = }S{\"cmd.exe /c \"\"dir\"\" & echo 'x'\"}");
}

static void continuation(void)
{
	/* a "_" that ends its line, blanks allowed after it, joins the next line: Rem there is a name */
	vb("x = 1 + _\nRem y", "C{x = 1 + _\nRem y}");
	vb("x = 1 + _  \t\r\nRem y", "C{x = 1 + _  \t\r\nRem y}");
	vb("x = 1 + _\r\n  Rem y", "C{x = 1 + _\r\n  Rem y}");
	vb("x = 1 + _\rRem y", "C{x = 1 + _\rRem y}");
	vb("x = 1 +_\nRem y", "C{x = 1 +_\nRem y}");
	/* the state before the "_" is kept: after ':' the next line still begins a statement */
	vb("a : _\nRem y", "C{a : _\n}K{Rem y}");
	vb("If a Then _\nRem y", "C{If a Then _\n}K{Rem y}");
	/* "'" is a comment on the next line of a continuation */
	vb("a _\n' c\nb", "C{a _\n}K{' c}C{\nb}");
	/* a blank line after the continuation is a line: the next statement begins */
	vb("a _\n\nRem y", "C{a _\n\n}K{Rem y}");
	/* "_" in a name is a letter: "foo_" and "_foo" are names, whatever follows */
	vb("foo_\nRem y", "C{foo_\n}K{Rem y}");
	vb("foo_ _\nRem y", "C{foo_ _\nRem y}");
	vb("a = foo_\nRem y", "C{a = foo_\n}K{Rem y}");
	vb("a = _foo\nRem y", "C{a = _foo\n}K{Rem y}");
	vb("a = b_c _\nRem y", "C{a = b_c _\nRem y}");
	vb("a = 1_\nRem y", "C{a = 1_\n}K{Rem y}");
	vb("a = __\nRem y", "C{a = __\n}K{Rem y}");
	/* "_" before a comment is not a continuation, and a "_" at the end of the text has nothing to join */
	vb("a _ ' c\nRem y", "C{a _ }K{' c}C{\n}K{Rem y}");
	vb("a _", "C{a _}");
	vb("a _  ", "C{a _  }");
	/* a quote before the "_" does not make it part of a name */
	vb("a = \"x\"_\nRem y", "C{a = }S{\"x\"}C{_\nRem y}");
	/* a continuation inside a date or a bracket is not one: those are not read for it */
	vb("a = #1/1/2000#_\nRem y", "C{a = #1/1/2000#_\nRem y}");
}

static void separators(void)
{
	vb("a:b", "C{a:b}");
	vb("a::b", "C{a::b}");
	vb("a : b : ' c", "C{a : b : }K{' c}");
	/* "::" is two separators, never a scope operator: there is none, and Rem shows it (above) */
	vb("Dim a: Dim b :Rem x", "C{Dim a: Dim b :}K{Rem x}");
	/* a colon inside a string or a comment separates nothing */
	vb("\"a:Rem b\" ' x : Rem y", "S{\"a:Rem b\"}C{ }K{' x : Rem y}");
	vb("x = \":\" Rem y", "C{x = }S{\":\"}C{ Rem y}");
}

static void literals(void)
{
	/* hex, octal, floats: code */
	vb("a = &HFF + &O17 + 1.5e5 + .5", "C{a = &HFF + &O17 + 1.5e5 + .5}");
	vb("a = &HFF ' c", "C{a = &HFF }K{' c}");
	/* a date literal is skipped whole: the ':' in the time begins no statement, so Rem after it is a name */
	vb("d = #1/1/2000 10:30:00# ' c", "C{d = #1/1/2000 10:30:00# }K{' c}");
	vb("d = #10:30# Rem x", "C{d = #10:30# Rem x}");
	vb("d = #Jan 5, 2000#\nRem x", "C{d = #Jan 5, 2000#\n}K{Rem x}");
	/* not a date: an apostrophe, a quote or a line break inside it, an empty one, one that never closes */
	vb("#a'b#", "C{#a}K{'b#}");
	vb("x = #a \"b#", "C{x = #a }S!{\"b#}");
	vb("##", "C{##}");
	vb("x = #1/1/2000", "C{x = #1/1/2000}");
	vb("x = #1/1\n2000#", "C{x = #1/1\n2000#}");
	vb("x = #10:30 ' c#", "C{x = #10:30 }K{' c#}");
	/* an extended identifier is skipped whole, a quote or an apostrophe in it opens nothing */
	vb("[a'b] = 1 ' c", "C{[a'b] = 1 }K{' c}");
	vb("[a\"b] = 1", "C{[a\"b] = 1}");
	vb("[Rem] = 1", "C{[Rem] = 1}");
	vb("[a b]:Rem c", "C{[a b]:}K{Rem c}");
	vb("[a ' c", "C{[a }K{' c}");
	vb("[a\n]", "C{[a\n]}");
	vb("[]", "C{[]}");
	/* the member and With forms */
	vb("With o\n .Write x\n End With", "C{With o\n .Write x\n End With}");
	vb("With o : .Rem = 1 : End With", "C{With o : .Rem = 1 : End With}");
	vb("If a Then .Write 1", "C{If a Then .Write 1}");
}

static void encoded(void)
{
	/* a script encoder block is one opaque STRING: its body has apostrophes, quotes, colons and line breaks */
	vb("x = #@~^AAAAAA==ab'c\"d:e\nRem f_^g#h^#~@ y", "C{x = }S{#@~^AAAAAA==ab'c\"d:e\nRem f_^g#h^#~@}C{ y}");
	vb("#@~^AAAAAA==^#~@", "S{#@~^AAAAAA==^#~@}");
	vb("#@~^^#~@", "S{#@~^^#~@}");
	/* it ends at the first terminator; what follows is code again, and Rem after it is a name */
	vb("#@~^a^#~@ Rem x", "S{#@~^a^#~@}C{ Rem x}");
	vb("#@~^a^#~@^#~@", "S{#@~^a^#~@}C{^#~@}");
	/* not closed: open to the end */
	vb("#@~^AAAAAA==abc\ndef", "S!{#@~^AAAAAA==abc\ndef}");
	vb("#@~^", "S!{#@~^}");
	vb("#@~^a^#~", "S!{#@~^a^#~}");
	/* near misses are a date or code: "#@~" and "#@" */
	vb("#@~ x", "C{#@~ x}");
	vb("# @~^ x", "C{# @~^ x}");
	/* inside a string or a comment it is theirs */
	vb("\"#@~^a\" ' #@~^b", "S{\"#@~^a\"}C{ }K{' #@~^b}");
	/* in an asp island the page ends it first */
	asp("<% #@~^abc %>x", "T{<%}C{ }S!{#@~^abc }T{%>}M{x}");
	asp("<% #@~^abc^#~@ y %>x", "T{<%}C{ }S{#@~^abc^#~@}C{ y }T{%>}M{x}");
}

static void webshell(void)
{
	/* the patterns a webshell and a dropper use: all code, strings and comments, nothing else */
	vb("Execute(\"x\" & Chr(34) & \"y\")", "C{Execute(}S{\"x\"}C{ & Chr(34) & }S{\"y\"}C{)}");
	vb("Eval(Request(\"a\"))", "C{Eval(Request(}S{\"a\"}C{))}");
	vb("ExecuteGlobal r\nExecute \"Rem x\"", "C{ExecuteGlobal r\nExecute }S{\"Rem x\"}");
	vb("s = Chr(&H41) & Chr(Asc(\"b\") + 1)", "C{s = Chr(&H41) & Chr(Asc(}S{\"b\"}C{) + 1)}");
	/* multi-line concatenation with '& _' */
	vb("s = \"a\" & _\n    \"b\" & _\n    \"c\"", "C{s = }S{\"a\"}C{ & _\n    }S{\"b\"}C{ & _\n    }S{\"c\"}");
	vb("s = \"a\" & _ ' not a continuation\n\"b\"", "C{s = }S{\"a\"}C{ & _ }K{' not a continuation}C{\n}S{\"b\"}");
	vb("Set sh = CreateObject(\"WScript\" & \".Shell\") : sh.Run \"cmd /c \" & c, 0, True",
	   "C{Set sh = CreateObject(}S{\"WScript\"}C{ & }S{\".Shell\"}C{) : sh.Run }S{\"cmd /c \"}C{ & c, 0, True}");
	vb("On Error Resume Next\nRem hide\n' also\nDim x : x = 1",
	   "C{On Error Resume Next\n}K{Rem hide}C{\n}K{' also}C{\nDim x : x = 1}");
	vb("If Err.Number <> 0 Then Err.Clear Else Rem none", "C{If Err.Number <> 0 Then Err.Clear Else }K{Rem none}");
	/* classic asp: islands, with the page's rule that %> ends the island, in a string or a comment too */
	asp("<% Rem x %>y", "T{<%}C{ }K{Rem x }T{%>}M{y}");
	asp("<%\nIf a Then Rem b\n%>", "T{<%}C{\nIf a Then }K{Rem b}C{\n}T{%>}");
	asp("<% a = \"x %> y", "T{<%}C{ a = }S!{\"x }T{%>}M{ y}");
	asp("<% ' c %>y<% Rem d %>", "T{<%}C{ }K{' c }T{%>}M{y}T{<%}C{ }K{Rem d }T{%>}");
	asp("<% x = 1 : Rem y %>", "T{<%}C{ x = 1 : }K{Rem y }T{%>}");
	asp("<% x = _\nRem y %>", "T{<%}C{ x = _\nRem y }T{%>}");
	asp("<% x _ %>", "T{<%}C{ x _ }T{%>}");
}

/* ---- the form ------------------------------------------------------------------------ */

static void forms(void)
{
	form("", "");
	form("x = 1  +  2", "x=1+2");
	form("x = 1 ' c\ny = 2", "x=1\ny=2");
	form("Rem c\nx", "x");
	form("If a Then Rem c", "If a Then");
	form("x = 1 : Rem c", "x=1:");
	/* a gap that is a name byte on each side stays one space */
	form("If  a   Then  b", "If a Then b");
	form("Dim a, b", "Dim a,b");
	/* the pairs closing up would change */
	form("a = b & c", "a=b&c");
	form("a = b & h1", "a=b& h1");
	form("a = b & o1", "a=b& o1");
	form("a = b & 1", "a=b& 1");
	form("a = 1 & b", "a=1 &b");
	form("a & &H10", "a& &H10");
	form("a = - -b", "a=- -b");
	form("If a < > b Then", "If a< >b Then");
	form("If a <> b Then", "If a<>b Then");
	form("If a < b Then", "If a<b Then");
	form("If a = < b Then", "If a= <b Then");
	form("a = 1 .5", "a=1 .5");
	/* "a (1)" and "a(1)" are not closed onto each other */
	form("a (1)", "a (1)");
	form("a(1)", "a(1)");
	form("Call a (1)", "Call a (1)");
	form("x = (1)", "x=(1)");
	form("f(1) (2)", "f(1) (2)");
	/* two strings stay two */
	form("a \"x\" \"y\"", "a\"x\" \"y\"");
	/* two strings joined by "&" are one string where the join ends the expression (the row says concat '&'); this was pinned the other way (kept as typed) until the
	 * owner required a join in every language that has one. The doubled quote is each piece's own escape, so the pieces meet without a seam. */
	form("\"x\" & \"y\"", "\"xy\"");
	form("x = \"a\" & \"b\"", "x=\"ab\"");
	form("x = \"a\" & \"b\" & \"c\"\ny = 1", "x=\"abc\"\ny=1");
	form("f(\"a\" & \"b\", 1)", "f(\"ab\",1)");
	form("x = \"a\"\"\" & \"b\"", "x=\"a\"\"b\"");
	form("x = \"a\" & \"\"\"b\"", "x=\"a\"\"b\"");
	/* and not where something else is part of the expression: a name between them, more after them, a ":" that is not an end this form knows */
	form("x = \"a\" & vbCrLf & \"b\"", "x=\"a\"&vbCrLf&\"b\"");
	form("x = \"a\" & \"b\" & c", "x=\"a\"&\"b\"&c");
	form("x = \"a\" & \"b\" : y = 1", "x=\"a\"&\"b\":y=1");
	form("x = \"a\" & &H41", "x=\"a\"& &H41");
	/* a string is never touched */
	form("x = \"a  ''  Rem\" ' c", "x=\"a  ''  Rem\"");
	form("x = \"\"\"\"  :  \"b", "x=\"\"\"\":\"b");
	/* an encoded block and an open string are copied */
	form("x = #@~^AA==a  b\n'c^#~@  y", "x=#@~^AA==a  b\n'c^#~@y");
	form("x = \"abc  \n y", "x=\"abc  \ny");
	/* a date: closed up inside, a space kept in front of it after a name */
	form("d = #1/1/2000#", "d=#1/1/2000#");
	form("Case #1/1/2000#", "Case #1/1/2000#");
	/* line breaks: blank lines and indentation go, CRLF and a lone CR are one break */
	form("a\n\n\n  b", "a\nb");
	form("a\r\nb", "a\nb");
	form("a\rb", "a\nb");
	form("a \r\n\r\n b ", "a\nb");
	form("a:b", "a:b");
	form("a :  : b", "a::b");
	/* the continuation and its break stay together, the space before the "_" stays */
	form("foo _\n  bar", "foo _\nbar");
	form("foo _\r\n  bar", "foo _\nbar");
	form("x = 1 + _\n 2", "x=1+ _\n2");
	form("x = a &_\n b", "x=a&_\nb");
	form("a = \"x\" & _\n   \"y\" & _\n   \"z\"", "a=\"x\"& _\n\"y\"& _\n\"z\"");
	/* a blank line after one is the statement's end, and stays: closing it up would join two statements */
	form("a _\n\n b", "a _\n\nb");
	form("a _\n\n\n\n b", "a _\n\nb");
	form("a _\n' c\n b", "a _\n\nb");
	/* "_" in a name is a letter and is no continuation */
	form("foo_\n  bar", "foo_\nbar");
	form("a = _x\nb", "a= _x\nb");
	/* "_" before a comment is no continuation: the comment goes and the break is the statement's */
	form("a _ ' c\nb", "a _\nb");
	/* a lone "_" at the end of the text */
	form("a _", "a _");
	/* in an island of asp the form still keeps what it must */
	form_lang(ASP, "<% a = 1 ' c\n%>", "<%a=1\n%>");
}

/* ---- the generator --------------------------------------------------------------------- */

#define EXP_MAX 4096u

static uint32_t n_rem, n_cont, n_enc, n_decoy, n_open;     /* what the generator wrote, so a run says it covered it */

struct gen {
	uint32_t s;
	char     buf[16384];
	size_t   w;
	struct kgenome_textual_span exp[EXP_MAX];
	uint32_t ne;
	int      fresh;         /* a statement begins here, as the generator has placed it */
	int      line_over;     /* the line was ended by a comment or an open string */
	int      last;          /* class of the last token: 0 none/blank, 1 name byte, 2 punct, 3 string, 4 '#', 5 ']' */
	int      dot;           /* the last token was a lone ".": a Then or Else after it is a member's name */
	const char *eol;
};

static uint32_t rnd(struct gen *g, uint32_t n)
{
	g->s ^= g->s << 13;
	g->s ^= g->s >> 17;
	g->s ^= g->s << 5;
	return g->s % n;
}

static void seg(struct gen *g, uint8_t kind, uint8_t flags, uint32_t open, uint32_t close, const char *text, size_t len)
{
	struct kgenome_textual_span *e = g->ne ? &g->exp[g->ne - 1u] : NULL;

	if (!len)
		return;
	if (g->w + len >= sizeof g->buf - 64u || g->ne + 2u >= EXP_MAX) {
		g->line_over = 2;
		return;
	}
	if (e && e->kind == KGENOME_TEXTUAL_CODE && kind == KGENOME_TEXTUAL_CODE) {
		e->len += (uint32_t)len;
	} else {
		e = &g->exp[g->ne++];
		e->off = (uint32_t)g->w;
		e->len = (uint32_t)len;
		e->kind = kind;
		e->flags = flags;
		e->open_len = open;
		e->close_len = close;
	}
	memcpy(g->buf + g->w, text, len);
	g->w += len;
}

static void code(struct gen *g, const char *t)
{
	seg(g, KGENOME_TEXTUAL_CODE, 0, 0, 0, t, strlen(t));
}

static const char *const blanks[] = { " ", "  ", "\t", " \t ", "   ", "\f", " \v" };

/* A gap in front of a token of class `next`: required where two tokens would otherwise be one. */
static void gap(struct gen *g, int next)
{
	int need = (g->last == 1 && (next == 1 || next == 5)) || (g->last == 3 && next == 3) ||
		   (g->last == 4 && next == 4) || (g->last == 3 && next == 5);

	if (need || rnd(g, 3) != 0)
		code(g, blanks[rnd(g, sizeof blanks / sizeof *blanks)]);
}

static const char *const words[] = {
	"x", "Foo1", "remark", "Rem_x", "xrem", "foo_", "_x", "123", "&HFF", "&O17", "1.5e5", ".5", "Dim", "Set",
	"Chr(34)", "Execute", "a.Rem", "a.Then", "a.Else", "o.Rem", ".Write", ".Rem", "Thenx", "xThen", "Elsewhere",
	"Rem1", "rem2", "REMARK", "End", "If", "Call", "Eval", "k.m.n", "Option", "Class"
};
static const char *const puncts[] = { "(", ")", ",", "=", "+", "&", "-", "<>", "<=", ">=", "\\", "^", "*", "/", "." };
static const char *const dates[] = { "#1/1/2000#", "#10:30:00#", "#1/1/2000 10:30 PM#", "#Jan 5, 2000#", "#12:00:00 AM#" };
static const char *const brackets[] = { "[a b]", "[it's]", "[a\"b]", "[x:y]", "[Rem]", "[a _]", "[ ' ]" };
static const char *const keys[] = { "Then", "THEN", "then", "Else", "ELSE", "else", "tHeN" };
static const char *const rems[] = { "Rem", "REM", "rem", "rEm" };
static const char *const decoys[] = { "Rem", "REM", "rem" };
static const char *const frag[] = { "a", "b", "Rem", "'", "\"\"", ":", "_", "#", "[", "]", " ", "\\", "x1", " _", "%", "(", ")", "&", ",", "\t", "\xc3\xa9" };

/* Text for a string or a comment: bytes from frag, no line break. `quote` allows a doubled quote. */
static void text_of(struct gen *g, char *out, size_t cap, int quote)
{
	uint32_t n = rnd(g, 7), k;
	size_t w = 0;

	out[0] = 0;
	for (k = 0; k < n; k++) {
		const char *f = frag[rnd(g, sizeof frag / sizeof *frag)];

		if (!quote && strcmp(f, "\"\"") == 0)
			f = "\"";
		if (w + strlen(f) + 1u >= cap)
			break;
		memcpy(out + w, f, strlen(f));
		w += strlen(f);
		out[w] = 0;
	}
}

static void put_string(struct gen *g)
{
	char t[128], s[160];

	text_of(g, t, sizeof t, 1);
	snprintf(s, sizeof s, "\"%s\"", t);
	seg(g, KGENOME_TEXTUAL_STRING, 0, 1, 1, s, strlen(s));
	g->fresh = 0;
	g->last = 3;
}

/* A string that the line ends: no closing quote, and at least one byte after the opening one. */
static void put_open_string(struct gen *g)
{
	char t[128], s[160];

	text_of(g, t, sizeof t, 1);
	/* the content must not end the string: a doubled quote pair is content, a lone one cannot occur */
	snprintf(s, sizeof s, "\"%sz", t);
	seg(g, KGENOME_TEXTUAL_STRING, KGENOME_TEXTUAL_F_OPEN, 1, 0, s, strlen(s));
	g->line_over = 1;
	n_open++;
}

static void put_comment(struct gen *g)
{
	char t[128], s[160];

	text_of(g, t, sizeof t, 1);
	snprintf(s, sizeof s, "'%s", t);
	seg(g, KGENOME_TEXTUAL_COMMENT, 0, 1, 0, s, strlen(s));
	g->line_over = 1;
}

/* A Rem comment, from a statement start: Rem, then anything that is not a name byte, then text. */
static void put_rem(struct gen *g)
{
	static const char *const tails[] = { " ", "\t", ":", ".", "\"", "(", "", "  ", "&", "," };
	char t[128], s[200];
	const char *tail = tails[rnd(g, sizeof tails / sizeof *tails)];

	text_of(g, t, sizeof t, 1);
	if (!*tail && *t && (uint8_t)(((uint8_t)t[0] | 0x20u) - 'a') < 26u)
		tail = " ";
	else if (!*tail && *t && (t[0] == '_' || (uint8_t)t[0] >= 0x80u || (uint8_t)((uint8_t)t[0] - '0') < 10u))
		tail = " ";
	snprintf(s, sizeof s, "%s%s%s", rems[rnd(g, 4)], tail, t);
	seg(g, KGENOME_TEXTUAL_COMMENT, 0, 3, 0, s, strlen(s));
	g->line_over = 1;
	n_rem++;
}

static void put_encoded(struct gen *g)
{
	char s[200] = "#@~^AAAAAA==";
	uint32_t n = rnd(g, 10), k;
	size_t w = strlen(s);
	static const char body[] = "ab'\"c:\n\r_ #[Rem\t%";

	for (k = 0; k < n; k++)
		s[w++] = body[rnd(g, sizeof body - 1u)];
	memcpy(s + w, "^#~@", 5);
	seg(g, KGENOME_TEXTUAL_STRING, 0, 4, 4, s, strlen(s));
	n_enc++;
	g->fresh = 0;
	g->last = 4;
}

static void put_item(struct gen *g)
{
	uint32_t t = rnd(g, 100);
	const char *w;
	int dot = g->dot;

	g->dot = 0;
	if (t < 22) {
		w = words[rnd(g, sizeof words / sizeof *words)];
		gap(g, 1);
		code(g, w);
		g->fresh = 0;
		g->last = 1;
	} else if (t < 34) {
		w = keys[rnd(g, sizeof keys / sizeof *keys)];
		gap(g, 1);
		code(g, w);
		g->fresh = !dot;
		g->last = 1;
	} else if (t < 48) {
		w = puncts[rnd(g, sizeof puncts / sizeof *puncts)];
		gap(g, 2);
		code(g, w);
		g->fresh = 0;
		g->dot = strcmp(w, ".") == 0;
		g->last = 2;
	} else if (t < 62) {
		gap(g, 3);
		put_string(g);
	} else if (t < 68 && !g->fresh) {
		w = decoys[rnd(g, 3)];
		n_decoy++;
		gap(g, 1);
		code(g, w);
		g->last = 1;
	} else if (t < 72) {
		w = dates[rnd(g, sizeof dates / sizeof *dates)];
		gap(g, 4);
		code(g, w);
		g->fresh = 0;
		g->last = 4;
	} else if (t < 76) {
		w = brackets[rnd(g, sizeof brackets / sizeof *brackets)];
		gap(g, 5);
		code(g, w);
		g->fresh = 0;
		g->last = 5;
	} else if (t < 80) {
		gap(g, 4);
		put_encoded(g);
	} else {
		gap(g, 2);
		code(g, ":");
		g->fresh = 1;
		g->last = 2;
	}
}

/* One line, up to its break. Answers 1 when the line ends in a continuation, which the caller then follows. */
static int put_line(struct gen *g, int last_line)
{
	uint32_t n = rnd(g, 7), k, end = rnd(g, 10);

	g->line_over = 0;
	if (rnd(g, 3) == 0)
		code(g, blanks[rnd(g, sizeof blanks / sizeof *blanks)]);
	g->last = 0;
	g->dot = 0;
	for (k = 0; k < n && !g->line_over; k++)
		put_item(g);
	if (g->line_over)
		return 0;
	if (end == 0 && g->fresh) {
		gap(g, 1);
		put_rem(g);
	} else if (end == 1) {
		gap(g, 2);
		put_comment(g);
	} else if (end == 2) {
		gap(g, 3);
		put_open_string(g);
	} else if (end == 3 && !last_line) {
		/* a continuation: a gap before the "_" unless the byte before it cannot be part of a name */
		if (g->last == 1 || g->last == 0 ? rnd(g, 2) : rnd(g, 3) == 0)
			code(g, blanks[rnd(g, sizeof blanks / sizeof *blanks)]);
		else if (g->last == 1)
			code(g, " ");
		code(g, "_");
		n_cont++;
		if (rnd(g, 3) == 0)
			code(g, blanks[rnd(g, sizeof blanks / sizeof *blanks)]);
		return 1;
	}
	return 0;
}

/* A program: lines, one break style. */
static void gen_program(struct gen *g, uint32_t seed)
{
	static const char *const eols[] = { "\n", "\r\n", "\r" };
	uint32_t lines, k;

	g->s = seed * 2654435761u + 1u;
	if (!g->s)
		g->s = 1;
	g->w = 0;
	g->ne = 0;
	g->fresh = 1;
	g->eol = eols[rnd(g, 3)];
	lines = 1u + rnd(g, 8);
	for (k = 0; k < lines && g->line_over != 2; k++) {
		int cont = put_line(g, k + 1u == lines);

		if (g->line_over == 2)
			break;
		if (k + 1u < lines || cont) {
			code(g, g->eol);
			if (!cont)
				g->fresh = 1;
			else
				lines += k + 1u == lines;      /* a continuation always has a line after it */
		}
	}
	g->buf[g->w] = 0;
}

struct got {
	struct kgenome_textual_span s[EXP_MAX];
	uint32_t n;
};

static int collect(void *u, const struct kgenome_textual_span *s)
{
	struct got *g = u;

	if (g->n < EXP_MAX)
		g->s[g->n] = *s;
	g->n++;
	return 1;
}

static int same(const struct kgenome_textual_span *a, const struct kgenome_textual_span *b, uint32_t shift)
{
	return a->off == b->off + shift && a->len == b->len && a->kind == b->kind &&
	       (a->flags & (uint8_t)~KGENOME_TEXTUAL_F_CLOSE) == b->flags && a->open_len == b->open_len &&
	       a->close_len == b->close_len;
}

static void show(const char *what, const char *t, size_t n, const struct kgenome_textual_span *s, uint32_t ns)
{
	uint32_t k;
	static const char K[] = "MTCSK";

	printf("  %s on:\n    ", what);
	for (k = 0; k < n; k++)
		printf((uint8_t)t[k] >= 0x20 && (uint8_t)t[k] < 0x7f ? "%c" : "\\x%02x", (uint8_t)t[k]);
	printf("\n    spans:");
	for (k = 0; k < ns && k < 40u; k++)
		printf(" %c%s[%u,%u,%u,%u]", K[s[k].kind], s[k].flags & KGENOME_TEXTUAL_F_OPEN ? "!" : "", s[k].off,
		       s[k].len, s[k].open_len, s[k].close_len);
	printf("\n");
}

static uint32_t gen_checked, gen_bad, gen_spans, gen_comments, gen_strings, gen_asp_checked;

static void check_generated(struct gen *g, uint32_t seed)
{
	static struct got got;
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)g->buf, .n = (uint32_t)g->w, .lang = VBS,
					      .sink = collect, .user = &got };
	struct kgenome_textual_lex_res rs;
	uint32_t k, bad = 0;

	got.n = 0;
	kgenome_textual_lex(&rq, &rs);
	if (got.n != g->ne)
		bad = 1;
	for (k = 0; !bad && k < g->ne; k++)
		if (!same(&got.s[k], &g->exp[k], 0))
			bad = 1;
	gen_checked++;
	gen_spans += g->ne;
	for (k = 0; k < g->ne; k++) {
		gen_comments += g->exp[k].kind == KGENOME_TEXTUAL_COMMENT;
		gen_strings += g->exp[k].kind == KGENOME_TEXTUAL_STRING;
	}
	if (bad) {
		if (gen_bad++ < 3u) {
			printf("  FAIL generated program %u (vbs)\n", seed);
			show("expected", g->buf, g->w, g->exp, g->ne);
			show("got", g->buf, g->w, got.s, got.n < EXP_MAX ? got.n : EXP_MAX);
		}
		fails++;
	}
}

/* The same program as the body of an asp island: "<% " in front (the blank keeps "<%=" from being a tag),
 * "%>" behind, and the same spans between. */
static void check_generated_asp(struct gen *g, uint32_t seed)
{
	static struct got got;
	static char text[16384 + 8];
	struct kgenome_textual_lex_req rq = { .in = (const uint8_t *)text, .lang = ASP, .sink = collect, .user = &got };
	struct kgenome_textual_lex_res rs;
	uint32_t k, bad = 0, n, first = 0, body;

	if (g->ne + 4u >= EXP_MAX || g->w + 8u >= sizeof text)
		return;
	memcpy(text, "<% ", 3u);
	memcpy(text + 3, g->buf, g->w);
	memcpy(text + 3u + g->w, "%>", 2u);
	n = (uint32_t)g->w + 5u;
	rq.n = n;
	got.n = 0;
	kgenome_textual_lex(&rq, &rs);
	/* expected: TAG "<%", the blank joined to the program's first span when that is code, the rest, TAG "%>" */
	first = g->ne && g->exp[0].kind == KGENOME_TEXTUAL_CODE;
	body = g->ne + (first ? 0u : 1u);
	if (got.n != body + 2u || got.s[0].kind != KGENOME_TEXTUAL_TAG || got.s[0].len != 2u ||
	    got.s[body + 1u].kind != KGENOME_TEXTUAL_TAG || got.s[body + 1u].len != 2u ||
	    got.s[body + 1u].off != 3u + (uint32_t)g->w)
		bad = 1;
	if (!bad && first && (got.s[1].kind != KGENOME_TEXTUAL_CODE || got.s[1].off != 2u || got.s[1].len != g->exp[0].len + 1u))
		bad = 1;
	if (!bad && !first && (got.s[1].kind != KGENOME_TEXTUAL_CODE || got.s[1].off != 2u || got.s[1].len != 1u))
		bad = 1;
	for (k = first ? 1u : 0u; !bad && k < g->ne; k++)
		if (!same(&got.s[k + (first ? 1u : 2u)], &g->exp[k], 3u))
			bad = 1;
	gen_asp_checked++;
	if (bad) {
		if (gen_bad++ < 3u) {
			printf("  FAIL generated program %u (asp island)\n", seed);
			show("got", text, n, got.s, got.n < EXP_MAX ? got.n : EXP_MAX);
		}
		fails++;
	}
}

/* ---- properties on generated programs ---------------------------------------------------- */

/*
 * The program as tokens: strings and open strings as typed, code with its blanks and line breaks out.
 *
 * A join `"a" & "b"` of two closed strings is ONE string, as the form writes it (the row says concat '&'): the closing quote of the first and the opening quote of the second go
 * (the doubled quote of either is its own escape, so the two texts meet without a seam). The form joins only where the join ends the expression, and this does not ask: it
 * folds EVERY such pair in the stream, of the program and of its form alike, so what is compared is the same program whether the form joined that pair or left it as typed.
 * Whether it joined is the pinned cases' (form("\"x\" & \"y\"", ...)). A comment and white space between the pieces are not tokens; any other code byte, a second "&" and an open
 * string end the join.
 */
static size_t tokens_of(const uint8_t *in, uint32_t n, char *out, size_t cap)
{
	static struct got got;
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = VBS, .sink = collect, .user = &got };
	struct kgenome_textual_lex_res rs;
	uint32_t k, i;
	size_t w = 0;
	int last_str = 0, amp = 0;      /* the last token is a closed string that can take a join; and an "&" came after it and is not written yet */

	got.n = 0;
	kgenome_textual_lex(&rq, &rs);
	for (k = 0; k < got.n && k < EXP_MAX; k++) {
		const struct kgenome_textual_span *s = &got.s[k];

		if (s->kind == KGENOME_TEXTUAL_COMMENT)
			continue;
		if (s->kind == KGENOME_TEXTUAL_STRING) {
			int joinable = !(s->flags & KGENOME_TEXTUAL_F_OPEN) && s->len >= 2u;

			if (last_str && amp && joinable) {
				/* closed string, "&", closed string: the first's closing quote and marker and the second's opening quote are not there */
				w -= 2u;
				for (i = 1; i < s->len && w + 2u < cap; i++)
					out[w++] = (char)in[s->off + i];
				out[w++] = '\1';
				amp = 0;
				continue;
			}
			if (amp && w + 2u < cap)
				out[w++] = '&';
			amp = 0;
			for (i = 0; i < s->len && w + 2u < cap; i++)
				out[w++] = (char)in[s->off + i];
			out[w++] = '\1';
			last_str = joinable;
			continue;
		}
		for (i = 0; i < s->len && w + 2u < cap; i++) {
			uint8_t c = in[s->off + i];

			if (s->kind == KGENOME_TEXTUAL_CODE && (c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r' || c == '\n'))
				continue;
			if (s->kind == KGENOME_TEXTUAL_CODE && c == '&' && last_str && !amp) {
				amp = 1;                /* straight after a closed string: a join, if a closed string follows */
				continue;
			}
			if (amp)
				out[w++] = '&';
			amp = 0;
			last_str = 0;
			out[w++] = (char)c;
		}
	}
	if (amp && w + 2u < cap)
		out[w++] = '&';
	out[w] = 0;
	return w;
}

static uint32_t form_checked, form_bad;

static void check_form_of(struct gen *g, uint32_t seed, uint32_t lang)
{
	static uint8_t o1[16384 * 2], o2[16384 * 2];
	static char t1[16384 * 2], t2[16384 * 2];
	static struct got got;
	struct kgenome_textual_form_req rq = { .in = (const uint8_t *)g->buf, .n = (uint32_t)g->w, .lang = lang,
					       .out = o1, .cap = KGENOME_TEXTUAL_FORM_CAP(g->w) };
	struct kgenome_textual_form_res rs;
	struct kgenome_textual_lex_req lq;
	struct kgenome_textual_lex_res lr;
	uint32_t k, w1;
	size_t a, b;
	int bad = 0;

	if (kgenome_textual_form(&rq, &rs) != KGENOME_TEXTUAL_OK && rs.n_out == 0 && g->w)
		bad = 1;
	w1 = rs.n_out;
	form_checked++;
	/* the form is itself */
	rq = (struct kgenome_textual_form_req){ .in = o1, .n = w1, .lang = lang, .out = o2, .cap = KGENOME_TEXTUAL_FORM_CAP(w1) };
	kgenome_textual_form(&rq, &rs);
	if (rs.n_out != w1 || memcmp(o1, o2, w1))
		bad |= 2;
	/* no comment left, and the same tokens */
	lq = (struct kgenome_textual_lex_req){ .in = o1, .n = w1, .lang = lang, .sink = collect, .user = &got };
	got.n = 0;
	kgenome_textual_lex(&lq, &lr);
	for (k = 0; k < got.n && k < EXP_MAX; k++)
		if (got.s[k].kind == KGENOME_TEXTUAL_COMMENT)
			bad |= 4;
	if (lang == VBS) {
		a = tokens_of((const uint8_t *)g->buf, (uint32_t)g->w, t1, sizeof t1);
		b = tokens_of(o1, w1, t2, sizeof t2);
		if (a != b || memcmp(t1, t2, a))
			bad |= 8;
	}
	if (bad) {
		if (form_bad++ < 3u) {
			printf("  FAIL form of generated program %u (reason %d)\n", seed, bad);
			show("input", g->buf, g->w, g->exp, g->ne);
			printf("    form: ");
			for (k = 0; k < w1; k++)
				printf(o1[k] >= 0x20 && o1[k] < 0x7f ? "%c" : "\\x%02x", o1[k]);
			printf("\n");
		}
		fails++;
	}
}

static void generated(void)
{
	static struct gen g;
	uint32_t seed;

	for (seed = 1; seed <= 8000u; seed++) {
		gen_program(&g, seed);
		check_generated(&g, seed);
		check_generated_asp(&g, seed);
		check_form_of(&g, seed, VBS);
	}
	printf("  generated: %u programs lexed as vbs, %u as asp islands, %u forms checked; %u spans, %u comments, %u strings expected\n",
	       gen_checked, gen_asp_checked, form_checked, gen_spans, gen_comments, gen_strings);
	printf("  of them: %u Rem comments, %u continuations, %u decoy Rem names, %u script encoder blocks, %u open strings\n",
	       n_rem, n_cont, n_decoy, n_enc, n_open);
	CK(gen_comments > 3000u && gen_strings > 8000u && n_rem > 500u && n_cont > 500u && n_decoy > 1000u &&
	   n_enc > 500u && n_open > 500u);
}

/* ---- any input --------------------------------------------------------------------------- */

static void properties(void)
{
	const char *alpha = "ab Rem'\"#[]_:\n\r\t ()&.@~^<>=0Hh,\\%";

	partition_for(VBS, alpha, 11u);
	form_property_for(VBS, alpha, 12u);
	partition_for(ASP, "ab Rem'\"_:\n<%>% =#@~^", 13u);
	form_property_for(ASP, "ab Rem'\"_:\n<%>% =#@~^", 14u);
}

int main(void)
{
	comments();
	rem();
	strings();
	continuation();
	separators();
	literals();
	encoded();
	webshell();
	forms();
	generated();
	properties();
	if (fails)
		printf("textual_vbs: %d FAILED\n", fails);
	else
		printf("textual_vbs: ok\n");
	return fails != 0;
}
