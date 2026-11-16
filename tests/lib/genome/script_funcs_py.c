/*
 * genome / script_funcs_py - the Python function strategy (celllysis/script_funcs_py.c) from CONSTRUCTED text only, linked
 * against libkgenome.a alone.
 *
 * WHAT IS ASSERTED. A case is a source and the entries it must give, each by its exact (off, len, name_off, name_len) and END_OPEN
 * flag, written as markers in the source (the entry starts at the first `from` after the previous entry, ends after the first `to`
 * after its start, and its name is the first `name` after its start). Every answer is also checked for the properties any answer
 * must have (sf_props): kind SCRIPT, end source SCRIPT, in start order, disjoint, inside the text, the name inside the entry,
 * END_OPEN exactly when the entry runs to the end of the text and then P_ENDS on the list; and no NO_TABLE (the stub's answer).
 * Every case is run again with CRLF and with lone-CR line ends and with a UTF-8 BOM in front (sf_variants): the same entries,
 * moved by the bytes that were added.
 *
 * WHY THE OLD TESTS MISSED IT, per group (the owner's (a)/(b)/(c)): no test of any language read a Python function before this
 * file - every group below is (a), the strategy was a stub that answered NO_TABLE and no line of it ran. The groups that pin a
 * boundary (tabs to the next multiple of 8, a continuation line at column 0, a header with no body at the end of the text) are
 * also (b): the shape that decides them is a boundary input no corpus file was chosen for.
 */

#include "hk.h"

#include <kgenome.h>
#include <celllysis/script_private.h>

#define SF_LANG  KGENOME_TEXTUAL_LANG_PY
#define SF_STRAT kgenome_script_funcs_py
#define SF_CR    1      /* a lone CR ends a line in this language */

#include "script_funcs_kit.h"

/* ---- Python ------------------------------------------------------------------------------------------------------------- */

static void shapes(void)
{
	SF_CASE("plain", "def f(a):\n    return a\n\nx = 1\n",
		{ "def f", "return a", "f", 0 });
	SF_CASE("at end, no break", "x = 1\ndef f(): return 1",
		{ "def f", "return 1", "f", 0 });
	SF_CASE("async", "async def h():\n    await x\nh()\n",
		{ "async", "await x", "h", 0 });
	SF_CASE("async, tab between", "async\tdef  h2():\n    pass\n",
		{ "async", "pass", "h2", 0 });
	SF_CASE("decorators", "@dec\n@other(1,\n  2)\ndef g():\n    pass\nrest()\n",
		{ "@dec", "pass", "g", 0 });
	SF_CASE("decorator, comment and blank between", "@dec\n# why\n\ndef g():\n    pass\n",
		{ "@dec", "pass", "g", 0 });
	SF_CASE("one-liners", "def f(): return 1\ndef g(): return 2\n",
		{ "def f", "return 1", "f", 0 }, { "def g", "return 2", "g", 0 });
	SF_CASE("trailing comment not in the entry", "def f(): return 1  # one\nz = 0\n",
		{ "def f", "return 1", "f", 0 });
	SF_CASE("non-ascii name", "def \xc3\xa9t\xc3\xa9():\n    pass\n",
		{ "def", "pass", "\xc3\xa9t\xc3\xa9", 0 });
}

static void classes_and_nesting(void)
{
	SF_CASE("methods are units, the class is not",
		"class A:\n    def m(self):\n        return 1\n    @property\n    def p(self):\n        return 2\nprint(1)\n",
		{ "def m", "return 1", "m", 0 }, { "@property", "return 2", "p", 0 });
	SF_CASE("nested def belongs to the outer",
		"def outer():\n    def inner():\n        pass\n    return inner\nouter()\n",
		{ "def outer", "return inner", "outer", 0 });
	SF_CASE("nested decorated def", "def o():\n    @d\n    def i():\n        pass\n    return i\n",
		{ "def o", "return i", "o", 0 });
	SF_CASE("decorated class is not a function", "@dataclass\nclass C:\n    x: int\ndef f():\n    pass\n",
		{ "def f", "pass", "f", 0 });
	SF_CASE("def after a class line at the same indent", "class A:\n    x = 1\ndef f():\n    pass\n",
		{ "def f", "pass", "f", 0 });
	SF_CASE("else at the def's column ends it",
		"if x:\n    def f():\n        pass\nelse:\n    def f():\n        return 0\n",
		{ "def f", "pass", "f", 0 }, { "def f", "return 0", "f", 0 });
	SF_NONE("lambda is not a unit", "f = lambda x: x\ng = (lambda: 0)\n");
	SF_NONE("def not at a line start", "x = 1; def f(): pass\n");
	SF_NONE("async that is a call", "async(1)\nasync.x = 2\n");
	SF_NONE("names that hold def", "define = 1\nundef()\nasync = 2\nmy_def = 3\n");
}

static void continuations(void)
{
	SF_CASE("brackets, triple string, backslash at column 0 do not end the body",
		"def f():\n    x = (1,\n2)\n    y = \"\"\"\nnot code\n\"\"\"\n    z = 1 + \\\n3\n    return z\nw = 0\n",
		{ "def f", "return z", "f", 0 });
	SF_CASE("blank and comment lines at column 0 do not end the body",
		"def f():\n    a = 1\n\n# comment at col 0\n    b = 2\nc = 3\n",
		{ "def f", "b = 2", "f", 0 });
	SF_CASE("a comment-only line is not the end", "def f():\n    a = 1\n    # tail\nc = 3\n",
		{ "def f", "a = 1", "f", 0 });
	SF_CASE("a brace holds the line", "def f():\n    d = {\n'a': 1}\n    return d\nx\n", { "def f", "return d", "f", 0 });
	SF_CASE("multi-line header", "def f(a,\nb):\n    return a\nx\n",
		{ "def f", "return a", "f", 0 });
}

static void tabs(void)
{
	/* a form feed resets the column (2.1.8): "\f    def g" is column 4, nested in f */
	SF_CASE("form feed", "def f():\n  x = 1\n\f    def g(): pass\ny\n", { "def f", "pass", "f", 0 });
	/* a tab is the next multiple of 8: "\tdef m" and "        def n" are the same column, so m ends where n starts */
	SF_CASE("tab is 8 columns",
		"class A:\n\tdef m(self):\n\t\tpass\n        def n(self):\n\t\tpass\n",
		{ "def m", "pass", "m", 0 }, { "def n", "pass", "n", 0 });
	/* "  \t" is column 8 too, deeper than 4 spaces: the second def is nested in the first */
	SF_CASE("spaces then tab",
		"class B:\n    def m(self):\n  \tdef n():\n  \t\tpass\n  \treturn n\n",
		{ "def m", "return n", "m", 0 });
}

static void keywords_in_literals(void)
{
	SF_NONE("strings and comments", "s = 'def no(): pass'\n# def nope():\nx = \"\"\"\ndef hidden():\n    pass\n\"\"\"\n");
	SF_NONE("f-string and raw", "s = f\"{x}\\ndef a(): pass\"\nr = r'def b(): pass'\n");
	SF_NONE("decorator in a comment only", "# @dec\nclass C:\n    pass\n");
}

static void open_ends(void)
{
	SF_CASE("open bracket at the end", "x = 1\ndef f(x,\n  y", { "def f", NULL, "f", 1 });
	SF_CASE("header with no body", "def g():\n", { "def g", NULL, "g", 1 });
	SF_CASE("triple string not closed", "def h():\n    s = \"\"\"never\n  closed\n", { "def h", NULL, "h", 1 });
	SF_CASE("backslash at the end", "def k():\n    return 1 + \\\n", { "def k", NULL, "k", 1 });
	SF_CASE("a string after the joined break", "def k():\n    return 1 + \\\n\"x\"", { "def k", "\"x\"", "k", 0 });
	SF_CASE("closed body at the end is not open", "def k():\n    return 1\n", { "def k", "return 1", "k", 0 });
	SF_CASE("prefixed triple string not closed", "def h():\n    s = rb\"\"\"x\n", { "def h", NULL, "h", 1 });
	SF_CASE("blanks after the last line", "def f(): pass\n   ", { "def f", "pass", "f", 0 });
	SF_CASE("triple string closed at the end", "def k():\n    return \"\"\"a\"\"\"", { "def k", "\"\"\"a\"\"\"", "k", 0 });
}

static void hostile(void)
{
	sf_hostile("100000 one-line defs", "", "def f(): pass\n", 100000u, 100000u);
	sf_hostile("100000 decorators then one def", "", "@d\n", 100000u, 0u);
	sf_hostile("one def, 100000 continued lines", "def f(x,\n", "  x,\n", 100000u, 1u);
	sf_hostile("one def, 100000 nested defs one column deeper each time is quadratic; 100000 at the same depth",
		   "def f():\n", " def g(): pass\n", 100000u, 1u);
	sf_hostile("100000 unclosed brackets", "def f(", "(", 100000u, 1u);
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	shapes();
	classes_and_nesting();
	continuations();
	tabs();
	keywords_in_literals();
	open_ends();
	hostile();
	if (hk_fails) {
		printf("script_funcs_py: %d FAILED\n", hk_fails);
		return 1;
	}
	printf("script_funcs_py: ok\n");
	return 0;
}
