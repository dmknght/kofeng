/*
 * genome / textual_tcl - the tcl lexer and form of the textual part, through <kgenome.h> alone.
 *
 * WHAT IS ASSERTED, and what each part is evidence of:
 *
 *   (a) KNOWN ANSWERS, one per rule of the language with the neighbour it could be confused for. A case is the text and the
 *       one line it must come out as (kind letter, bytes in braces; S* = a backslash is an escape in it, S! = not closed,
 *       K = comment - see textual_check.h). Where the text is a program, tclsh 8.6.16 of the machine it was written on agrees
 *       with the rule: a scratch script of the report reads the cases written to disk (-DTCL_DUMP_DIR) and compiles each
 *       (::tcl::unsupported::disassemble) - `tc` is a case that compiles, `tcx` one that does not, or is not a whole program, and
 *       says why at the call. The form cases (`fm`) compare the bytecode of the program with the bytecode of its form.
 *   (b) A GENERATOR of tcl programs (textual_tcl_gen.h) with the spans it knows, the form of each, and the form's idempotence.
 *   (c) THE PARTITION and the idempotence of the form on random text from a tcl alphabet and from any byte, a text cut at every
 *       length, and hostile texts (brackets and parentheses nested past the bound, a huge unclosed literal of each kind, a text of
 *       "$a(" and "${" with nothing to close them, NUL bytes, every line ending) read in time linear in them.
 *   (d) FORM known answers, the VALUE of words through kgenome_textual_value, and that tcl has NO decoder row: a hook is never asked.
 *
 * Everything goes through <kgenome.h> and nothing else: a test of a language is a test of the API.
 */

#include "textual_check.h"

#include <time.h>

#define TCL KGENOME_TEXTUAL_LANG_TCL

#ifdef TCL_DUMP_DIR
static void dump(const char *tag, const char *src)
{
	static unsigned k;
	char name[256];
	FILE *f;

	snprintf(name, sizeof name, TCL_DUMP_DIR "/%s%04u.tcl", tag, k++);
	f = fopen(name, "wb");
	if (f) {
		fwrite(src, 1, strlen(src), f);
		fclose(f);
	}
}
#else
#define dump(tag, src) ((void)0)
#endif

static void tc(const char *src, const char *want)
{
	dump("lex", src);
	expect_lang(TCL, src, want);
}

/* Not a program tcl compiles (a literal not closed, a word after a closer) or not a whole one: the comment at the call says why. */
static void tcx(const char *src, const char *want)
{
	expect_lang(TCL, src, want);
}

static void comments(void)
{
	/* "#" is a comment where a command can begin: the start, after a line break, after ";" with or without a blank */
	tc("# c\nputs a", "K{# c}C{\nputs a}");
	tc("puts a\n# c\nputs b", "C{puts a\n}K{# c}C{\nputs b}");
	tc("puts a;# c\nputs b", "C{puts a;}K{# c}C{\nputs b}");
	tc("puts a; # c\nputs b", "C{puts a; }K{# c}C{\nputs b}");
	tc("puts a ;# c", "C{puts a ;}K{# c}");
	tc("  \t# c\nx", "C{  \t}K{# c}C{\nx}");
	tc("#", "K{#}");
	/* anywhere else it is a letter: an argument, a word's middle, after a closer */
	tc("puts a # b\nputs a#b", "C{puts a # b\nputs a#b}");
	tc("puts {a} ;#c", "C{puts }S{{a}}C{ ;}K{#c}");
	tc("set x #y", "C{set x #y}");
	/* a comment continues over "\<line break>", and "\\<line break>" is a backslash and the line's end */
	tc("# a \\\n b\nputs", "K{# a \\\n b}C{\nputs}");
	tc("# a \\\\\nputs", "K{# a \\\\}C{\nputs}");
	tc("# a \\\\\\\nb\nputs", "K{# a \\\\\\\nb}C{\nputs}");
	tc("# a \\\r\n b\r\nputs", "K{# a \\\r\n b}C{\r\nputs}");
	tc("# a \\\r b\rputs", "K{# a \\\r b}C{\rputs}");
	/* every line ending ends a line comment: a file is read with them translated */
	tc("# c\r\nx", "K{# c}C{\r\nx}");
	tc("# c\rx", "K{# c}C{\rx}");
	tc("# c\n\rx", "K{# c}C{\n\rx}");
	/* a quote, a brace or a bracket in a comment is the comment's: braces in it still count in a braced body, which is a string here */
	tc("# it's \"x\" { [ \nputs a", "K{# it's \"x\" { [ }C{\nputs a}");
	/* after a "\<line break>" at a command's START "#" begins a comment; in the middle of a command it is a word */
	tc("\\\n# c\nputs a", "C{\\\n}K{# c}C{\nputs a}");
	tc("puts a \\\n# x\nputs b", "C{puts a \\\n# x\nputs b}");
	tc("puts a;\\\n# x\nputs b", "C{puts a;\\\n}K{# x}C{\nputs b}");
	/* in a "[": a comment at the script's start, to the line break, and its "]" is the comment's */
	tc("set x [# c ]\n foo]\n", "C{set x [}K{# c ]}C{\n foo]\n}");
	tc("set x [foo ;# c ]\n bar {q}]", "C{set x [foo ;}K{# c ]}C{\n bar }S{{q}}C{]}");
	tc("set x [foo # c]", "C{set x [foo # c]}");
	/* the interpreter line */
	tcx("#!/usr/bin/tclsh\nputs a", "K{#!/usr/bin/tclsh}C{\nputs a}");
	tcx("#!/bin/sh\n# restart \\\nexec tclsh \"$0\"\nputs a", "K{#!/bin/sh}C{\n}K{# restart \\\nexec tclsh \"$0\"}C{\nputs a}");
	tcx(" #!x", "C{ }K{#!x}");
}

static void braces(void)
{
	/* a braced word is a string, nested by balanced braces; "\{" and "\}" are not counted, "\\" is a pair */
	tc("puts {a b}", "C{puts }S{{a b}}");
	tc("puts {}", "C{puts }S{{}}");
	tc("puts {a {b {c}} d} x", "C{puts }S{{a {b {c}} d}}C{ x}");
	tc("puts {a \\{ b} x", "C{puts }S{{a \\{ b}}C{ x}");
	tc("puts {a \\} b} x", "C{puts }S{{a \\} b}}C{ x}");
	tc("puts {a \\\\} x", "C{puts }S{{a \\\\}}C{ x}");
	tc("puts {a \\\\\\} b} x", "C{puts }S{{a \\\\\\} b}}C{ x}");
	/* a quote, a bracket, a hash, a dollar and a semicolon in it are text; so are line breaks, of any kind */
	tc("puts {\" [ # $x ; \"}", "C{puts }S{{\" [ # $x ; \"}}");
	tc("proc f {} {\n    puts a ;# c\n}\nf", "C{proc f }S{{}}C{ }S{{\n    puts a ;# c\n}}C{\nf}");
	tc("puts {a\r\nb} {a\rb} {a\\\nb}", "C{puts }S{{a\r\nb}}C{ }S{{a\rb}}C{ }S{{a\\\nb}}");
	/* a script body is a string and is not lexed: a comment, a quote and a brace in it do nothing - and a brace in a comment in it
	 * counts, which is tcl's own rule (the well-known trap): the body ends at the "}" in "# }", and what follows is code again */
	tc("if {$x} {\n# {a}\nputs \"a\"\n}", "C{if }S{{$x}}C{ }S{{\n# {a}\nputs \"a\"\n}}");
	tc("if {$x} {\n# }\nputs \"a}\"\n}", "C{if }S{{$x}}C{ }S{{\n# }}C{\nputs }S*{\"a}\"}C{\n}}");
	tcx("if {$x} {\n# {\nputs a\n}", "C{if }S{{$x}}C{ }S!{{\n# {\nputs a\n}}");
	/* a brace in the middle of a bare word is a letter, and a brace is a word's start only at its start */
	tc("puts a{b c} d", "C{puts a{b c} d}");
	tc("puts a}b {c}", "C{puts a}b }S{{c}}");
	/* not closed: to the end of the text, flagged */
	tcx("puts {a b", "C{puts }S!{{a b}");
	tcx("puts {a {b}", "C{puts }S!{{a {b}}");
	tcx("puts {\\", "C{puts }S!{{\\}");
	tcx("{", "S!{{}");
	/* after the closing brace tcl says "extra characters": the word goes on, as a bare one */
	tcx("puts {a}b c", "C{puts }S{{a}}C{b c}");
}

static void quotes(void)
{
	tc("puts \"a b\" x", "C{puts }S*{\"a b\"}C{ x}");
	tc("puts \"\" x", "C{puts }S*{\"\"}C{ x}");
	/* a backslash escapes the next byte, the quote included, and a line break is the string's */
	tc("puts \"a\\\"b\" x", "C{puts }S*{\"a\\\"b\"}C{ x}");
	tc("puts \"a\\\\\" x", "C{puts }S*{\"a\\\\\"}C{ x}");
	tc("puts \"a\\\nb\" x", "C{puts }S*{\"a\\\nb\"}C{ x}");
	tc("puts \"a\\\r\nb\" x", "C{puts }S*{\"a\\\r\nb\"}C{ x}");
	tc("puts \"a\nb\" x", "C{puts }S*{\"a\nb\"}C{ x}");
	tc("puts \"a\rb\" x", "C{puts }S*{\"a\rb\"}C{ x}");
	/* a brace, a hash, a semicolon, a "]" and a "$" with no name are text in it */
	tc("puts \"{ # ; ] $ } ( )\" x", "C{puts }S*{\"{ # ; ] $ } ( )\"}C{ x}");
	/* "$name", "${name}", "$name(index)" are the program's but stay in the string (INTERP: a backslash is an escape in it) */
	tc("puts \"$a ${b c} $d(e f) $::g::h\" x", "C{puts }S*{\"$a ${b c} $d(e f) $::g::h\"}C{ x}");
	tc("puts \"${a\"b\" x", "C{puts }S*{\"${a\"}C{b\" x}");
	tc("puts \"$a(b\"c) x\"", "C{puts }S*{\"$a(b\"c) x\"}");
	/* a quote in the middle of a bare word is a letter */
	tc("puts a\"b c\"d", "C{puts a\"b c\"d}");
	/* a "[" in it: the command in the brackets is code, with strings of its own, found to the matching "]"; the span has no INTERP */
	tc("puts \"a [b] c\" x", "C{puts }S{\"a [b] c\"}C{ x}");
	tc("puts \"a [string length \"b c\"] d\" x", "C{puts }S{\"a [string length \"b c\"] d\"}C{ x}");
	tc("puts \"[list {a\"} ]\"]\" x", "C{puts }S{\"[list {a\"} ]\"}C{]\" x}");
	tc("puts \"a [b ; # c ]\n d] e\" x", "C{puts }S{\"a [b ; # c ]\n d] e\"}C{ x}");
	tc("puts \"a [b [c \"[d]\"]] e\" x", "C{puts }S{\"a [b [c \"[d]\"]] e\"}C{ x}");
	tc("puts \"a \\[b] c\" x", "C{puts }S*{\"a \\[b] c\"}C{ x}");
	tc("puts \"$a([b \"c\"]) d\" x", "C{puts }S{\"$a([b \"c\"]) d\"}C{ x}");
	tc("puts \"$a([b {\\x41}]) \\x41\" x", "C{puts }S{\"$a([b {\\x41}]) \\x41\"}C{ x}");
	/* not closed: to the end of the text */
	tcx("puts \"abc", "C{puts }S*!{\"abc}");
	tcx("puts \"a [b \"c\"", "C{puts }S!{\"a [b \"c\"}");
	tcx("\"\\", "S*!{\"\\}");
	/* after the closing quote tcl says "extra characters": the word goes on as a bare one */
	tcx("puts \"a\"b c", "C{puts }S*{\"a\"}C{b c}");
	tcx("puts {a}\"b c\" x", "C{puts }S{{a}}C{\"b c\" x}");
	tcx("puts \"a\"{b c} x", "C{puts }S*{\"a\"}C{{b c} x}");
}

static void substitutions(void)
{
	/* the code in the brackets of a BARE word is lexed to its end, its own strings and comments are spans */
	tc("set x [string length \"a b\"]", "C{set x [string length }S*{\"a b\"}C{]}");
	tc("set x [list {a b} \"c\"]y", "C{set x [list }S{{a b}}C{ }S*{\"c\"}C{]y}");
	tc("set x [a [b {c}] \"d\"]", "C{set x [a [b }S{{c}}C{] }S*{\"d\"}C{]}");
	tc("set x a[b {c}]d", "C{set x a[b }S{{c}}C{]d}");
	tc("set x [a ; b # c\n d]", "C{set x [a ; b # c\n d]}");
	tc("set x [a\n# c ]\nb]", "C{set x [a\n}K{# c ]}C{\nb]}");
	tc("set x [a {b]}]", "C{set x [a }S{{b]}}C{]}");
	tc("set x [a \"b]\"]", "C{set x [a }S*{\"b]\"}C{]}");
	tc("set x [a]b]", "C{set x [a]b]}");
	tc("set x \\[a b]", "C{set x \\[a b]}");
	/* an unclosed "[" is code to the end of the text */
	tcx("set x [a {b} \"c\"", "C{set x [a }S{{b}}C{ }S*{\"c\"}");
	/* "$": a braced name is a STRING to the first "}", with "${" and "}" as its delimiters; a name is code; an index is a STRING from
	 * its "(" to its ")" - blanks and line breaks in it are the key's - with substitutions, quotes and braces in it */
	tc("puts ${a b} \"c\"", "C{puts }S{${a b}}C{ }S*{\"c\"}");
	tc("puts ${a\"b} \"c\"", "C{puts }S{${a\"b}}C{ }S*{\"c\"}");
	tc("puts ${a[b} {c}", "C{puts }S{${a[b}}C{ }S{{c}}");
	tc("puts ${} {c}", "C{puts }S{${}}C{ }S{{c}}");
	tc("puts $a(b c) {d}", "C{puts $a}S*{(b c)}C{ }S{{d}}");
	tc("puts $a(b\nc) {d}", "C{puts $a}S*{(b\nc)}C{ }S{{d}}");
	tc("puts $a(b;c) {d}", "C{puts $a}S*{(b;c)}C{ }S{{d}}");
	tc("puts $a(\"b c\") {d}", "C{puts $a}S*{(\"b c\")}C{ }S{{d}}");
	tc("puts $a([b {c}]) {d}", "C{puts $a}S{([b {c}])}C{ }S{{d}}");
	tc("puts $a($b(c d)) {e}", "C{puts $a}S*{($b(c d))}C{ }S{{e}}");
	tc("puts $a(\\)b) {c}", "C{puts $a}S*{(\\)b)}C{ }S{{c}}");
	tc("puts $a::b::c(d e) {f}", "C{puts $a::b::c}S*{(d e)}C{ }S{{f}}");
	tc("puts $a(b)$c(d) e", "C{puts $a}S*{(b)}C{$c}S*{(d)}C{ e}");
	tc("puts $a(\\x41)", "C{puts $a}S*{(\\x41)}");
	/* what is not a substitution: a "$" alone, "$" and a colon, "$" and a brace with no closer */
	tc("puts $ {a}", "C{puts $ }S{{a}}");
	tc("puts $:a {b}", "C{puts $:a }S{{b}}");
	tcx("puts ${a b", "C{puts ${a b}");
	tcx("puts $ {", "C{puts $ }S!{{}");
	/* an index with no ")" is tcl's "missing )": open to the end of the text, whatever follows */
	tcx("puts $a(b c {d}", "C{puts $a}S*!{(b c {d}}");
	tcx("puts $a( {d}\nputs \"x\"", "C{puts $a}S*!{( {d}\nputs \"x\"}");
	tc("puts \"a$\" {b}", "C{puts }S*{\"a$\"}C{ }S{{b}}");
	/* a backslash and the byte after it are a pair in a bare word: an escaped blank, ";", quote, brace and "[" are letters of it */
	tc("puts a\\ b\\;c\\\"d\\{e\\[f g", "C{puts a\\ b\\;c\\\"d\\{e\\[f g}");
	tc("puts a\\\\ {b}", "C{puts a\\\\ }S{{b}}");
	/* a "\<line break>" between words is a gap, and in the middle of a bare word it ends the word */
	tc("puts a\\\n {b}\\\n  \"c\"", "C{puts a\\\n }S{{b}}C{\\\n  }S*{\"c\"}");
	tc("puts \\\n{a}", "C{puts \\\n}S{{a}}");
	tc("puts a\\\n{b} c\\\n\"d\" e\\\n#f", "C{puts a\\\n}S{{b}}C{ c\\\n}S*{\"d\"}C{ e\\\n#f}");
}

static void line_endings(void)
{
	tc("a\n{b}\n# c\n\"d\"\n", "C{a\n}S{{b}}C{\n}K{# c}C{\n}S*{\"d\"}C{\n}");
	tc("a\r\n{b}\r\n# c\r\n\"d\"\r\n", "C{a\r\n}S{{b}}C{\r\n}K{# c}C{\r\n}S*{\"d\"}C{\r\n}");
	tc("a\r{b}\r# c\r\"d\"\r", "C{a\r}S{{b}}C{\r}K{# c}C{\r}S*{\"d\"}C{\r}");
	/* a line break ends a command in every kind, so "#" after it begins a comment */
	tc("a b\r# c", "C{a b\r}K{# c}");
	tc("a b\r\n# c", "C{a b\r\n}K{# c}");
	/* blanks: space, tab, VT and FF part words; NBSP and NUL do not */
	tc("a\tb\vc\fd # e\n", "C{a\tb\vc\fd # e\n}");
	tc("a\tb;\v# c\n", "C{a\tb;\v}K{# c}C{\n}");
	/* NUL bytes are bytes */
	{
		static const char nul[] = "a\0b {c\0d} \"e\0f\" # g\0h\n;# i\0j";
		static struct rend r;

		lex(&r, nul, sizeof nul - 1u, TCL);
		CK(!r.broken && strstr(r.out, "S{{c") && strstr(r.out, "S*{\"e") && strstr(r.out, "K{;") == NULL);
		CK(strchr(r.out, 'K') == NULL || strstr(r.out, "K{# i") != NULL);
	}
}

#include "textual_tcl_gen.h"

/* ---- (d) the form ---- */

static void fm(const char *src, const char *want)
{
	dump("form_in", src);
	dump("form_out", want);
	form_lang(TCL, src, want);
}

/* A form of text that is not a program (or whose program is not the form's). */
static void fmx(const char *src, const char *want)
{
	form_lang(TCL, src, want);
}

static void forms(void)
{
	fm("", "");
	/* blanks between words are one space (a word is parted by it), indentation goes, a line break stays one, comments and blank lines go */
	fm("puts   a \t b\n\n\n    puts c  # d\n", "puts a b\nputs c # d");
	fm("if {$x} {\n    puts a  ;# c\n}\n", "if {$x} {\n    puts a  ;# c\n}");
	fm("proc f {a b} {\n    return $a\n}\n# c\nf 1 2\n", "proc f {a b} {\n    return $a\n}\nf 1 2");
	fm("# only\n", "");
	fm("puts a ;# c\nputs b", "puts a ;\nputs b");
	fm("puts a;# c1\n# c2\n\n# c3\nputs b", "puts a;\nputs b");
	/* "#" in the middle of a command is a word: it stays */
	fm("puts a # b\nset x a#b", "puts a # b\nset x a#b");
	/* a continuation keeps its break; the blanks after it are a gap; and "#" after one at a command's start is a comment */
	fm("puts a \\\n      b", "puts a \\\n b");
	fm("puts a \\\r\n  b\r\nputs c", "puts a \\\n b\nputs c");
	fm("puts a \\\r  b\rputs c", "puts a \\\n b\nputs c");
	fm("puts a \\\n# not a comment\nputs b", "puts a \\\n# not a comment\nputs b");
	fm("puts a;\\\n# a comment\nputs b", "puts a;\\\n\nputs b");
	/* a braced body is a string: kept as typed, comments and indentation in it too */
	fm("proc f {} {\n    # c\n    puts   a\n}", "proc f {} {\n    # c\n    puts   a\n}");
	/* the blanks of a "${name}" and of an index are the name's and the key's: not closed up */
	fm("set ${a   b}  $c(d   e)  f", "set ${a   b} $c(d   e) f");
	fm("set $c(d\n  e)  f", "set $c(d\n  e) f");
	/* a quoted word and the code in a bracket of a bare word: the quoted one as typed, the bracket's code closed up */
	fm("set x [string   length   \"a   b\"]", "set x [string length \"a   b\"]");
	fm("set x \"a [string   length   b]\"", "set x \"a [string   length   b]\"");
	fm("set x [list a ;# c\n  b]", "set x [list a ;\nb]");
	fm("set x [a\n# c ]\nb]", "set x [a\nb]");
	/* the interpreter line is kept; a line break is one however the file ends its lines, a lone CR included */
	fmx("#!/usr/bin/tclsh\nputs a # c", "#!/usr/bin/tclsh\nputs a # c");
	fm("puts a\rputs b\r", "puts a\nputs b");
	fm("puts a\r\nputs b\r\n", "puts a\nputs b");
	fm("puts a # c\rputs b", "puts a # c\nputs b");
	fm("# c\rputs b", "puts b");
	fm("puts a\n\rputs b\n\r", "puts a\nputs b");
	/* a string that is not closed is kept as typed */
	fmx("puts {a  b", "puts {a  b");
	fmx("puts   \"a  b", "puts \"a  b");
	fmx("puts [a   \"b", "puts [a \"b");
	/* an escaped blank is a letter of its word: it is not a gap */
	fm("puts a\\ \\ b   c", "puts a\\ \\ b c");
	fm("puts a\\;b ; puts c", "puts a\\;b ; puts c");
}

/* The spelled-out bytes of a tcl quoted word, written as themselves: exactly what tcl 8.6 reads as an escape. */
static void unescapes(void)
{
	/* the names a script spells so that no marker finds them: hex, octal, \u and \U */
	fm("puts \"\\x65\\x76\\x61\\x6c \\101\\102 \\u0048\\u0069 \\U00000041\"", "puts \"eval AB Hi A\"");
	fm("puts \"\\x41B\\x4a\\x4A\"", "puts \"\\x41BJJ\"");
	fm("puts \"\\x41B\\x43\\x4a\"", "puts \"\\x41B\\x43J\"");
	fm("puts \"\\x41 B\\x4a \\x4g\"", "puts \"A BJ \\x4g\"");
	/* not a byte that is printable ASCII and not one of the bytes that mean something in a word */
	fm("puts \"\\x0a\\x7f\\x01\\2\\377 \\x22\\x5c\\x24\\x5b\\x28\\x7b\\x7d\"", "puts \"\\x0a\\x7f\\x01\\2\\377 \\x22\\x5c\\x24\\x5b\\x28\\x7b\\x7d\"");
	fm("puts \"\\u00e9\\u2022 \\U00110000 \\ud800\"", "puts \"\\u00e9\\u2022 \\U00110000 \\ud800\"");
	/* a backslash and the byte after it are a pair: "\\x41" is a backslash and the text x41; \q is q and stays */
	fm("puts \"\\\\x41 \\\\\\x41 \\q \\n \\$ \\[\"", "puts \"\\\\x41 \\\\A \\q \\n \\$ \\[\"");
	/* a "$" and the name after it: no name byte is written there - "$a\x62" is not "$ab" - and "$" and a letter is a variable */
	fm("puts \"$a\\x62 $\\x41 $a\\x2f $a\\x3a\\x3ab $a\\x20z $ \\x41\"", "puts \"$a\\x62 $\\x41 $a/ $a\\x3a\\x3ab $a z $ A\"");
	fm("puts \"${a}\\x62 $a(b)\\x62\"", "puts \"${a}b $a(b)b\"");
	/* a ")" is never written: it would end the index, and a "(" would open one after a name */
	fm("puts \"$a(b\\x29z) $a\\x28z)\"", "puts \"$a(b\\x29z) $a\\x28z)\"");
	fm("puts $a(b\\x41  c)  d", "puts $a(bA  c) d");
	/* what follows an escape still waiting for digits does not complete it: \1 then \x31 is not \11, \x4 then \x61 is not \x4a */
	fm("puts \"\\1\\x31 \\18 \\x4\\x61 \\u00\\x34\"", "puts \"\\1\\x31 \\18 \\x4\\x61 \\u00\\x34\"");
	fm("puts \"\\1\\x7a \\x4\\x7a \\u00\\x7a\"", "puts \"\\1z \\x4z \\u00z\"");
	/* a name that an escape ended is ended: "$a\x62" keeps its escape and what follows is free to be written */
	fm("puts \"$a\\x62\\x7a $a\\x62\\x2f\"", "puts \"$a\\x62z $a\\x62/\"");
	/* "\<line break>" eats the blanks after it: no blank is written there */
	fm("puts \"a\\\n  \\x20z\"", "puts \"a\\\n  \\x20z\"");
	fm("puts \"a\\\n\\x41 \\x20z\"", "puts \"a\\\nA  z\"");
	/* a word with a "[" is not given to it: the code in the brackets has braces, where nothing is an escape; a braced word, a bare word neither */
	fm("puts \"[list {\\x41}] \\x41\" {\\x41} \\x41", "puts \"[list {\\x41}] \\x41\" {\\x41} \\x41");
	/* a comment holding an escape is a comment */
	fm("puts a ;# \"\\x41\"", "puts a ;");
}

/* THE VALUE of a word, through the API: the lib decodes what the text says, never a value with a hole in it. */
static void val(const char *lit, uint32_t open, uint32_t close, uint8_t flags, const char *want, uint32_t want_n)
{
	uint8_t out[256];
	struct kgenome_textual_value_req rq = { .lang = TCL, .lit = (const uint8_t *)lit, .len = (uint32_t)strlen(lit),
						.open_len = open, .close_len = close, .flags = flags, .out = out, .cap = sizeof out };
	struct kgenome_textual_value_res rs;
	enum kgenome_textual_status st = kgenome_textual_value(&rq, &rs);

	if (!want) {
		if (st != KGENOME_TEXTUAL_NO_VALUE || rs.n_out) {
			printf("  FAIL value of %s: status %d, wanted no value\n", lit, (int)st);
			fails++;
		}
		return;
	}
	if (st != KGENOME_TEXTUAL_OK || rs.n_out != want_n || memcmp(out, want, want_n)) {
		printf("  FAIL value of %s: status %d, %u bytes, wanted %u\n", lit, (int)st, rs.n_out, want_n);
		fails++;
	}
}

#define V(lit, want) val(lit, 1, 1, 0, want, (uint32_t)sizeof(want) - 1u)
#define NOV(lit) val(lit, 1, 1, 0, NULL, 0)

static void values(void)
{
	/* braced: the bytes, backslashes too; a backslash, a line break and the blanks after it are ONE space; breaks are "\n" */
	V("{a b}", "a b");
	V("{a\\{b\\\\}", "a\\{b\\\\");
	V("{a\\\n    b}", "a b");
	V("{a\\\r\n\t b\\\rc}", "a b c");
	V("{a\r\nb\rc}", "a\nb\nc");
	V("{a\\\\\nb}", "a\\\\\nb");
	V("{$x [y] \\n}", "$x [y] \\n");
	V("{}", "");
	/* quoted: the escapes, and no value where a name or a command is substituted */
	V("\"a\\nb\"", "a\nb");
	V("\"\\a\\b\\f\\n\\r\\t\\v\\\\\\\"\"", "\a\b\f\n\r\t\v\\\"");
	V("\"\\x41\\x4a\\101\\u0048\\U00000069\"", "AJAHi");
	V("\"\\x414\"", "A4");
	V("\"\\777 \\18 \\x \\xzz \\u \\8\"", "?7 \x01" "8 x xzz u 8");
	V("\"\\q\\ \\$\\[\\{\"", "q $[{");
	V("\"\\xe9 \\351 \\u00e9 \\u20AC\"", "\xc3\xa9 \xc3\xa9 \xc3\xa9 \xe2\x82\xac");
	/* a character past U+FFFF is U+FFFD in this build; the digit that would take \U past U+10FFFF is the next character */
	V("\"\\U0001F600 \\U0010FFFF \\U00110000 \\ud800 \\u0000\"", "\xef\xbf\xbd \xef\xbf\xbd \xef\xbf\xbd" "0 \xed\xa0\x80 \0");
	V("\"\\UFFFFFFFF \\U20000000 \\U0011 \\U000000411\"", "\xef\xbf\xbd" "FFF \xef\xbf\xbd" "000 \x11 A1");
	V("\"a\\\n   b\"", "a b");
	V("\"a\nb\"", "a\nb");
	V("\"$ $: $é a$ \"", "$ $: $\xc3\xa9 a$ ");
	NOV("\"$a\"");
	NOV("\"${a}\"");
	NOV("\"$a(b)\"");
	NOV("\"$::a\"");
	NOV("\"$(\"");
	NOV("\"a [b] c\"");
	V("\"\\$a \\[b]\"", "$a [b]");
	V("\"\"", "");
	/* a word that was not closed has none */
	val("{abc", 1, 0, KGENOME_TEXTUAL_F_OPEN, NULL, 0);
	val("\"abc", 1, 0, KGENOME_TEXTUAL_F_OPEN, NULL, 0);
}

/* TCL HAS NO DECODER ROW: binary decode and zlib are `[command subcommand arg]`, which the form's decode machinery cannot read. */
static uint32_t hook_calls;

static int fake_decode(void *user, const uint8_t *chain, uint32_t n_chain, const uint8_t *in, uint32_t len,
		       const uint8_t **out, uint32_t *out_len)
{
	(void)user;
	(void)chain;
	(void)n_chain;
	(void)in;
	(void)len;
	(void)out;
	(void)out_len;
	hook_calls++;
	return 0;
}

static void decoders(void)
{
	static const char *const src[] = {
		"set x [binary decode base64 \"YWJj\"]", "eval [binary decode hex {616263}]", "set x [zlib decompress $y]",
		"set x [string reverse \"abc\"]", "eval [subst \"abc\"]", "set x [encoding convertfrom utf-8 \"abc\"]",
		"set x [binary decode base64 -strict {YWJj}]",
	};
	uint8_t out[512];
	unsigned i;

	for (i = 0; i < sizeof src / sizeof src[0]; i++) {
		struct kgenome_textual_form_req rq = { .in = (const uint8_t *)src[i], .n = (uint32_t)strlen(src[i]), .lang = TCL,
						       .out = out, .cap = KGENOME_TEXTUAL_FORM_CAP(strlen(src[i])) + 64u,
						       .decode = fake_decode };
		struct kgenome_textual_form_res rs;

		kgenome_textual_form(&rq, &rs);
		CK(rs.n_decoded == 0 && rs.n_refused == 0 && rs.n_folded == 0);
	}
	CK(hook_calls == 0);
}

/* ---- (c) any text at all ---- */

static void properties(void)
{
	/* the spans partition the text, and the form of a form is itself, on text drawn from what changes the lexer's mind:
	 * the quotes, braces, brackets, parentheses, "$", "#", ";", blanks and line breaks of all kinds, a backslash */
	partition_for(TCL, "#{}[]()\"$;\\\n\r\t\f\v xa1:,=", 2024u);
	partition_for(TCL, "{}\\\n#;", 77u);
	partition_for(TCL, "[]$(){}\"\n ", 31u);
	form_property_for(TCL, "#{}[]()\"$;\\\n\r\t\f\v xa1:,=", 99u);
	form_property_for(TCL, "\"\\x41u{}$a\\\n ]\r[", 5u);
	form_property_for(TCL, "$a(\"b c)\n;#{[]}\\", 6u);
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

static uint32_t lex_whole(const uint8_t *in, uint32_t n, struct whole *c)
{
	struct kgenome_textual_lex_req rq = { .in = in, .n = n, .lang = TCL, .sink = whole_sink, .user = c };
	struct kgenome_textual_lex_res rs;
	enum kgenome_textual_status st = kgenome_textual_lex(&rq, &rs);

	return (st == KGENOME_TEXTUAL_OPEN || st == KGENOME_TEXTUAL_OK) && c->next == n && !c->broken && rs.n_span == c->n;
}

/* The spans partition a text cut at every length, and a hostile one is read in time proportional to it. */
static void hostile(void)
{
	static const char sample[] =
		"#!/usr/bin/tclsh\nproc f {a} {\n  puts \"a [b {c}] $d(e f) ${g}\" ;# h\n}\nset x [a \\\n \"b\\\"\" {c\\}} ;# d\r\n# e \\\r\n f\r\nputs $a(b [c \"d\"])\r";
	static struct rend r;
	uint32_t n;

	for (n = 0; n <= sizeof sample - 1u; n++) {
		lex(&r, sample, n, TCL);
		if (r.broken) {
			printf("  FAIL partition when the sample is cut at %u\n", n);
			fails++;
			return;
		}
	}
	/* NESTING: brackets, indexes and quoted words nested far past TCL_DEPTH are one open string from where the bound was met, and no stack overflow */
	{
		static uint8_t deep[1u << 20];
		static const char *const unit[] = { "[", "\"[", "$a(", "$a($b([", "[\"$a(", "set x [", "\"$a([" };
		uint32_t k;

		for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
			size_t ul = strlen(unit[k]);
			uint32_t w = 0;
			struct whole c = { 0 };

			while (w + ul + 8u <= sizeof deep) {
				memcpy(deep + w, unit[k], ul);
				w += (uint32_t)ul;
			}
			memcpy(deep + w, ")]\"", 3);
			w += 3;
			CK(lex_whole(deep, w, &c));
		}
		/* below the bound it is what it looks like: one word, and the code after it */
		memcpy(deep, "set x [a [b [c \"d\"]]] y", 24);
		lex(&r, (const char *)deep, 24, TCL);
		CK(!r.broken && strcmp(r.out, "C{set x [a [b [c }S*{\"d\"}C{]]] y}") == 0);
	}
	/* LINEAR WORK. Each unit repeated to 600 KB is a text whose literal never closes, or whose lookahead never finds what it looks for.
	 * A lexer that read to the end again for every "${", "$a(" or "{" would do 10^11 steps here. */
	{
		static const char *const unit[] = { "${a ", "$a(b ", "$a(b\n", "{a ", "\"a ", "[a ", "# a \\\n", "\\\n", "{{{{", "a{ ", "$a(\"b ",
						    "set x [a $b(c) {d} ", "\"$a(", "$a(b) ${c} $", "puts \"a [b] c\" ;" };
		static uint8_t big[600u * 1024u];
		clock_t t0 = clock();
		uint32_t k;

		for (k = 0; k < sizeof unit / sizeof unit[0]; k++) {
			size_t ul = strlen(unit[k]);
			uint32_t w = 0;
			struct whole c = { 0 };

			while (w + ul <= sizeof big) {
				memcpy(big + w, unit[k], ul);
				w += (uint32_t)ul;
			}
			CK(lex_whole(big, w, &c));
		}
		CK((double)(clock() - t0) / CLOCKS_PER_SEC < 20.0);
	}
	/* one huge unclosed literal of each kind is one span flagged open, and a lot of NUL bytes is only bytes */
	{
		static uint8_t huge[1u << 20];
		static const char *const open[] = { "{", "\"", "\"a [b {", "set x {", "\"$a(" };
		uint32_t k;

		for (k = 0; k < sizeof open / sizeof open[0]; k++) {
			size_t ol = strlen(open[k]);
			struct whole c = { 0 };
			struct kgenome_textual_lex_req rq;
			struct kgenome_textual_lex_res rs;

			memcpy(huge, open[k], ol);
			memset(huge + ol, k % 2u ? 'x' : 0, sizeof huge - ol);
			rq = (struct kgenome_textual_lex_req){ .in = huge, .n = sizeof huge, .lang = TCL, .sink = whole_sink, .user = &c };
			CK(kgenome_textual_lex(&rq, &rs) == KGENOME_TEXTUAL_OPEN && c.next == sizeof huge && !c.broken);
		}
	}
}

int main(void)
{
	comments();
	braces();
	quotes();
	substitutions();
	line_endings();
	generator();
	forms();
	unescapes();
	values();
	decoders();
	properties();
	hostile();
	if (fails) {
		printf("FAIL: %d\n", fails);
		return 1;
	}
	printf("textual_tcl: ok\n");
	return 0;
}
