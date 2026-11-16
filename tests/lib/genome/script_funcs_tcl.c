/*
 * genome / script_funcs_tcl - the Tcl function strategy (celllysis/script_funcs_tcl.c) from CONSTRUCTED text only, linked
 * against libkgenome.a alone.
 *
 * WHAT IS ASSERTED: as in script_funcs_py.c (the kit is script_funcs_kit.h): exact (off, len,
 * name_off, name_len) and END_OPEN per entry, the properties of any answer, and the same entries under CRLF, lone CR and behind a
 * BOM (tcl's lexer: "\n", "\r\n" and a lone "\r" are line breaks).
 *
 * WHY THE OLD TESTS MISSED IT: every group is (a) - the strategy was a stub (NO_TABLE) and no Tcl proc was ever read. The groups
 * that read inside a braced word (namespace eval, oo::class, if bodies, a brace or a quote escaped by a backslash) are also (b):
 * the lexer delivers a braced word as one STRING, so the proc in it exists only for a reader that walks the word's script, and the
 * boundary bytes (an escaped "}", a "[" in a quoted word) decide where that script ends.
 */

#include "hk.h"

#include <kgenome.h>
#include <celllysis/script_private.h>

#define SF_LANG  KGENOME_TEXTUAL_LANG_TCL
#define SF_STRAT kgenome_script_funcs_tcl
#define SF_CR    1

#include "script_funcs_kit.h"

/* ---- Tcl ---------------------------------------------------------------------------------------------------------------- */

static void shapes(void)
{
	SF_CASE("braced args and body", "proc f {a b} {\n  return $a\n}\nf 1 2\n", { "proc f", "$a\n}", "f", 0 });
	SF_CASE("bare args", "proc g x {puts $x}\n", { "proc g", "}", "g", 0 });
	SF_CASE("qualified name, empty args", "proc ::ns::h {} {}\n", { "proc", "{} {}", "::ns::h", 0 });
	SF_CASE("after ;", "set x 1; proc k {} {return 1}\n", { "proc k", "1}", "k", 0 });
	SF_CASE("indented, at the end without a break", "  proc k {} {return 1}", { "proc k", "1}", "k", 0 });
	SF_CASE("braced name", "proc {my proc} {} {}\n", { "proc", "{} {}", "my proc", 0 });
	SF_CASE("quoted body", "proc f {} \"return 1\"\n", { "proc f", "1\"", "f", 0 });
	SF_CASE("escaped braces in the body", "proc f {} {\n  puts \\}\n  puts \\{\n}\nx\n", { "proc f", "\\{\n}", "f", 0 });
	SF_CASE("inside a bracket", "set p [proc q {} {return 1}]\n", { "proc q", "1}", "q", 0 });
	SF_CASE("continued line", "proc f \\\n {} \\\n {return 1}\n", { "proc f", "1}", "f", 0 });
}

static void containers(void)
{
	SF_CASE("namespace eval: its procs are units",
		"namespace eval ns {\n  variable v 1\n  proc a {} {\n    return 1\n  }\n  proc b {x} { return $x }\n}\nproc c {} {}\n",
		{ "proc a", "1\n  }", "a", 0 }, { "proc b", "$x }", "b", 0 }, { "proc c", "{} {}", "c", 0 });
	SF_CASE("an escaped brace in a body inside a namespace",
		"namespace eval n {\n  proc a {} {\n    puts \\}\n  }\n  proc b {} {}\n}\n",
		{ "proc a", "\\}\n  }", "a", 0 }, { "proc b", "{} {}", "b", 0 });
	SF_CASE("nested namespaces", "namespace eval a {\n  namespace eval b {\n    proc deep {} { }\n  }\n}\n",
		{ "proc deep", "{ }", "deep", 0 });
	SF_CASE("if and else bodies at the top level", "if {1} {\n  proc p1 {} {}\n} else {\n  proc p2 {} {}\n}\n",
		{ "proc p1", "{} {}", "p1", 0 }, { "proc p2", "{} {}", "p2", 0 });
	SF_CASE("a proc in a proc is the outer's", "proc outer {} {\n  proc inner {} {}\n}\n", { "proc outer", "{}\n}", "outer", 0 });
	SF_CASE("a comment in a namespace body", "namespace eval n {\n  # proc no {} {}\n  proc yes {} {}\n}\n",
		{ "proc yes", "{} {}", "yes", 0 });
	SF_CASE("words with brackets and quotes in a namespace body",
		"namespace eval n {\n  set a \"x [list \"y\" ;] z\"; proc p {} {}\n  set b [string map {; x} $c]; proc q {} {}\n}\n",
		{ "proc p", "{} {}", "p", 0 }, { "proc q", "{} {}", "q", 0 });
	SF_CASE("oo::class and oo::define",
		"oo::class create Foo {\n  constructor {} { set x 1 }\n  method bar {a} {\n    return $a\n  }\n  destructor { }\n}\n"
		"oo::define Foo method baz {} { return 2 }\n",
		{ "constructor", "1 }", "constructor", 0 }, { "method bar", "$a\n  }", "bar", 0 }, { "destructor", "{ }", "destructor", 0 },
		{ "oo::define", "2 }", "baz", 0 });
	SF_CASE("oo::define constructor on one line", "oo::define C constructor {} {set x 1}\n", { "oo::define", "1}", "constructor", 0 });
	SF_CASE("a proc in a proc's args is the outer's", "proc f [proc g {} {}] {}\n", { "proc f", "] {}", "f", 0 });
	SF_NONE("namespace without eval, oo::class without create",
		"namespace export {proc a {} {}}\noo::class new {method m {} {}}\n");
	SF_CASE("raw words: nested braces, escapes in quotes and bare words",
		"namespace eval n {\n  proc a {} {if {1} {x}}\n  set x \"a\\\"b\"; proc p {} {}\n  set y a\\ b; proc q {} {}\n}\n",
		{ "proc a", "{x}}", "a", 0 }, { "proc p", "{} {}", "p", 0 }, { "proc q", "{} {}", "q", 0 });
	SF_CASE("a quoted brace inside a namespace body ends with the lexer's span",
		"namespace eval n {set x \"}\"}\nproc q {} {}\n", { "proc q", "{} {}", "q", 0 });
	SF_CASE("oo::define with a body", "oo::define Foo {\n  method m {} {}\n}\n", { "method m", "{} {}", "m", 0 });
}

static void literals(void)
{
	SF_NONE("comments, quoted words and plain braced words",
		"# proc no {} {}\nputs \"proc x {} {}\"\nset s {proc y {} {}}\nputs proc a b c\nlist proc {} {}\n");
	SF_NONE("method outside a class body", "method m {} {}\n");
}

static void open_ends(void)
{
	SF_CASE("body not closed", "proc f {} {\n  puts x\n", { "proc f", NULL, "f", 1 });
	SF_CASE("no body", "proc g {a}", { "proc g", NULL, "g", 1 });
	SF_NONE("no body, a break after the args: the command ended, it is not a definition", "proc g {a}\nputs 1\n");
	SF_CASE("quoted body not closed", "proc f {} \"x", { "proc f", NULL, "f", 1 });
	SF_CASE("escaped brace leaves the body open", "proc f {} {a\\}", { "proc f", NULL, "f", 1 });
	SF_CASE("variable body at the end is closed", "proc f {} ${x}", { "proc f", "${x}", "f", 0 });
	SF_CASE("bare body at the end of an open namespace", "namespace eval n {\n proc p {} x", { "proc p", "{} x", "p", 0 });
	SF_CASE("namespace not closed", "namespace eval n {\n  proc p {} {\n", { "proc p", NULL, "p", 1 });
}

static void hostile(void)
{
	sf_hostile("100000 procs", "", "proc f {} {}\n", 100000u, 100000u);
	sf_hostile("100000 nested namespaces, never closed, one proc each", "", "namespace eval a {\nproc f {} {}\n", 100000u,
		   100000u);
	sf_hostile("100000 open brackets in a quoted word in a namespace", "namespace eval a {\nset x \"", "[", 100000u, 0u);
	sf_hostile("100000 proc words with no body", "", "proc ", 100000u, 1u);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	shapes();
	containers();
	literals();
	open_ends();
	hostile();
	if (hk_fails) {
		printf("script_funcs_tcl: %d FAILED\n", hk_fails);
		return 1;
	}
	printf("script_funcs_tcl: ok\n");
	return 0;
}
