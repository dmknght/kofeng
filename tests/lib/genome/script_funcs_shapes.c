/*
 * genome / script_funcs_shapes - the brace rows the island package added to the brace walk (celllysis/script_funcs.c), from CONSTRUCTED
 * text only, each to its language's specification: php's arrow function `fn` (php 7.4), javascript's arrow functions and keyword-less
 * methods (ECMA-262 15.3, 15.4) and its module wrapper, java's methods in a jsp's "<%!" (JLS 8.4) and c#'s in an aspx's
 * <script runat="server"> (C# 15.6), cfscript's `function` with its access word and attributes. The kit is script_funcs_kit.h.
 *
 * WHY THE OLD TESTS MISSED IT: (a) none of these was read - an arrow, a method, `fn`, a java or c# method was not a declaration
 * (script_funcs.h named them "the next case"), and jsp, aspx and cfm answered an empty table. The boundary groups (an expression body's
 * end at a string, a bracket, a line break; a header at a tag; `new T() {`; a header ending in ";") are also (b).
 */

#include "hk.h"

#include <kgenome.h>
#include <celllysis/script_private.h>

/* The brace walk is the strategy of these rows: the table kgenome_script_funcs_of_text builds, as a list. */
static int brace_rows(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	struct kgenome_func_set fs;
	uint32_t i;

	kgenome_script_funcs_of_text(t, &fs);
	for (i = 0; i < fs.n; i++)
		(void)kgenome_fntab_list_add(l, &fs.v[i]);
	l->partial |= fs.partial;
	kgenome_funcs_free(&fs);
	return fs.status == KGENOME_OK;
}

#define SF_LANG  KGENOME_TEXTUAL_LANG_JS
#define SF_STRAT brace_rows
#define SF_CR    1

#include "script_funcs_kit.h"

/* A case of language `lang`: `src` gives exactly the entries listed (sf_want initializers), and the same under CRLF / CR / a BOM when the
 * language is javascript (the kit's variants run the kit's language). */
#define LCASE(lang, name, src, ...) do { \
	static const struct sf_want w_[] = { __VA_ARGS__ }; \
	sf_check_lang(lang, name, src, strlen(src), w_, (uint32_t)(sizeof w_ / sizeof w_[0])); \
} while (0)
#define LNONE(lang, name, src) sf_check_lang(lang, name, src, strlen(src), NULL, 0)

static void php_fn(void)
{
	/* `fn` (php 7.4): `&`, a return type, a body of one expression ending at ";"; a fn inside a function is nested */
	LCASE(KGENOME_TEXTUAL_LANG_PHP, "php fn",
	      "<?php $f = fn($x) => $x + 1; $g = static fn&($x): ?int => [$x, ($y)];\nfunction h() { $k = fn() => 2; }\n",
	      { "fn($x)", "$x + 1", NULL, 0 }, { "static fn&", "($y)]", NULL, 0 }, { "function h", "2; }", "h", 0 });
	/* an expression runs to the closing tag (php reads "?>" as ";"); `fn` called as a method is not a declaration */
	LCASE(KGENOME_TEXTUAL_LANG_PHP, "php fn at a tag", "<?php $f = fn($a) => $a ?>x", { "fn(", "=> $a", NULL, 0 });
	LNONE(KGENOME_TEXTUAL_LANG_PHP, "php fn method", "<?php $o->fn($x); A::fn($y);");
}

static void js_arrows(void)
{
	/* the expression ends at the "," of the call (a string holding one is not it); a line break between the parameters and "=>" is
	 * not an arrow (ECMA-262 15.3: [no LineTerminator here]); a parenthesised body is one expression */
	SF_CASE("js arrows", "f(x => 'a,b' + y, z);\ng = async (a) => { await a; };\nh = async b => b;\n(c)\n=> d;\nk = (q) => (r, s);\n",
		{ "x =>", "+ y", NULL, 0 }, { "async (a)", "await a; }", NULL, 0 }, { "async b", "=> b", NULL, 0 }, { "(q)", "(r, s)", NULL, 0 });
}

static void js_methods(void)
{
	SF_CASE("js methods", "class A { *gen() { yield 1; } static #p() { } async *it() { } }\nconst o = { get x() { return 1; }, set x(v) { } };\n",
		{ "*gen", "1; }", "gen", 0 }, { "static #p", "{ }", "#p", 0 }, { "async *it", "{ }", "it", 0 }, { "get x", "1; }", "x", 0 },
		{ "set x", "{ }", "x", 0 });
	/* a call then a block on the next line is two statements; a keyword is not a method's name */
	SF_NONE("js not methods", "foo(x)\n{ y(); }\nif (a) { }\nwhile (b) { }\nswitch (c) { }\n");
}

static void js_wrappers(void)
{
	/* a module wrapper at a statement's start is the top level (fn_wrapper): its functions are the units */
	SF_CASE("js wrappers", "(function ($) { function a() { } $.b = function () { }; })(jQuery);\n+function () { function c() { } }();\n",
		{ "function a", "{ }", "a", 0 }, { "function () { };", "{ }", NULL, 0 }, { "function c", "{ }", "c", 0 });
	/* not at a statement's start: a function, outermost */
	SF_CASE("js not a wrapper", "x = (function () { function a() { } })();\n", { "function ()", "} }", NULL, 0 });
}

static void java_jsp(void)
{
	/* a header ending in ";" has no body; `new T() {` is a call (an anonymous class) and its method is one; a scriptlet is the body of
	 * _jspService and declares nothing */
	LCASE(KGENOME_TEXTUAL_LANG_JSP, "jsp",
	      "<%! public <T> List<T> f(T x) throws IOException, X.Y { return null; } abstract void g(); { k = 1; }\n"
	      "Runnable r = new Runnable() { public void run() { } };\n@Override String s() { return \"}\"; } %><% void notone() { } %>",
	      { "public <T>", "null; }", "f", 0 }, { "public void run", "{ }", "run", 0 }, { "@Override", "\"}\"; }", "s", 0 });
}

static void cs_aspx(void)
{
	LCASE(KGENOME_TEXTUAL_LANG_ASPX, "aspx c#",
	      "<%@ Page Language=\"C#\" %><script runat=\"server\">\n[WebMethod(\"x\")] public static string M<T>(T a) where T : class { return \"\"; }\n"
	      "public Foo(int a) : base(a) { }\npublic int P() => 1;\nint Q() { return R(1); }\n</script><% void notone() { } %>",
	      { "[WebMethod", "\"\"; }", "M", 0 }, { "public Foo", "{ }", "Foo", 0 }, { "public int P", "=> 1", "P", 0 }, { "int Q", "(1); }", "Q", 0 });
}

static void cfscript(void)
{
	/* the access word and the return type in front, attributes after ")"; a <cffunction> to its end tag; one closed by "/>" has no body
	 * and is the tag (a stray end tag after it closes nothing); the last never closes */
	LCASE(KGENOME_TEXTUAL_LANG_CFM, "cfscript",
	      "<cfscript>remote any function f(a) access=\"public\" output=false { return a; }\nfunction g() { }</cfscript>"
	      "<cffunction name=\"h\"><cfreturn 1></cffunction><cffunction name=\"s\"/><cfset y=1></cffunction><cffunction name=\"k\">",
	      { "remote any", "a; }", "f", 0 }, { "function g", "{ }", "g", 0 }, { "<cffunction name=\"h\"", "</cffunction>", "h", 0 },
	      { "<cffunction name=\"s\"/>", "/>", "s", 0 }, { "<cffunction name=\"k\"", "", "k", 1 });
}

int main(void)
{
	php_fn();
	js_arrows();
	js_methods();
	js_wrappers();
	java_jsp();
	cs_aspx();
	cfscript();
	printf("script_funcs_shapes: %s (%d failure(s))\n", hk_fails ? "FAIL" : "ok", hk_fails);
	return hk_fails != 0;
}
