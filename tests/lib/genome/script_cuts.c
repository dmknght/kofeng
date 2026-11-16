/*
 * script_cuts - WHERE kgenome_script_funcs_build CUTS a script into functions, attacked per language
 * row (owner, 2026-11-14: "Agent fix phai tao luon ca test case coverage duoc cac case co the gay
 * ngat sai"; tests simulate the bytes, no real sample is embedded). tests/lib/genome/script_funcs.c
 * pins the NAME of a function; this file pins its START and END, and the properties every table must
 * have whatever the text says.
 *
 * Each SP-n group below was RED on the tree before its fix (celllysis/script_funcs.c, 2026-11-14):
 *   SP-1  php keywords in any case (`FUNCTION f`) were not declarations
 *   SP-2  powershell: `Function`, `filter`, `workflow`, Verb-Noun and scope-prefixed names missed
 *   SP-3  perl: `sub Foo::bar`, `sub Foo'bar`, attributes (`:lvalue`, `:prototype($)`) missed
 *   SP-4  shell: `my-func() {` began at "func", `function log-info {` missed, `a.b() {` began at "b"
 *   SP-5  shell: `echo }`, `echo \}` and every other "}" that is a byte of a word closed the function
 *   SP-6  a "{" in the parameter list (`function f({a})`, `f(o = {})`) was taken for the body's
 *   SP-7  php return type: a comment in it lost the function; `function a() function b() {` made a
 *   SP-8  modifiers (`public static`, `async`, `export default`, `my sub`) cut off the declaration
 *   SP-9  names: JS `$` and UTF-8, php high bytes, and a byte order mark before the first keyword
 *   SP-10 nested functions counted against the table cap before being dropped: the outer was lost
 *   SP-12 perl `$sub{a}` and `@sub{...}` (a hash named sub) were anonymous subs
 *   SP-13 a header longer than 512 bytes (a long destructured parameter list) was not a declaration
 * Why the old tests missed each (top-level CLAUDE.md, "Tests"): SP-1..4, SP-7..9, SP-12 (b) no input
 * of that shape; SP-5, SP-6 (b) every fixture's braces were braces; SP-10, SP-13 (b) no input at
 * the cap.
 *
 * The properties, checked on EVERY table this file builds (table_ok): entries in start order and
 * disjoint (every byte in at most one function), inside the buffer, a closed entry ends on a code
 * "}" and an open one at the end with END_OPEN, a name inside its own entry.
 * The oracle (exhaustive_*): every sequence of up to six tokens of a small alphabet of braces,
 * quotes, comments and declarations, against a naive per-declaration forward brace match over the
 * lexer's code bytes - an independent algorithm (quadratic, no stack), not this builder's walk.
 */
#include <kgenome.h>
#include <string.h>

#include "hk.h"

/* The code bytes of `src` as the lexer reads them: the test's own, for the oracle and table_ok. */
struct codemap {
	uint8_t *code;
	uint64_t n;
};

static int codemap_sink(void *u, const struct kgenome_textual_span *sp)
{
	struct codemap *m = u;

	if (sp->kind == KGENOME_TEXTUAL_CODE && (uint64_t)sp->off + sp->len <= m->n)
		memset(m->code + sp->off, 1, sp->len);
	return 1;
}

static uint8_t *code_of(uint32_t lang, const char *src, uint64_t n)
{
	struct codemap m;
	struct kgenome_textual_lex_req rq;
	struct kgenome_textual_lex_res res;

	m.code = calloc(n ? (size_t)n : 1u, 1);
	m.n = n;
	memset(&rq, 0, sizeof rq);
	rq.in = (const uint8_t *)src;
	rq.n = (uint32_t)n;
	rq.lang = lang;
	rq.sink = codemap_sink;
	rq.user = &m;
	if (m.code)
		(void)kgenome_textual_lex(&rq, &res);
	return m.code;
}

/* The languages whose function body is a brace block (the brace walk's five rows); the others close on a keyword, an indent or a tag. */
static int brace_lang(uint32_t lang)
{
	return lang == KGENOME_TEXTUAL_LANG_PHP || lang == KGENOME_TEXTUAL_LANG_JS || lang == KGENOME_TEXTUAL_LANG_PERL ||
	       lang == KGENOME_TEXTUAL_LANG_PSH || lang == KGENOME_TEXTUAL_LANG_SH;
}

static int has_arrow(const char *s, uint64_t n)
{
	uint64_t i;

	for (i = 0; i + 1u < n; i++)
		if (s[i] == '=' && s[i + 1u] == '>')
			return 1;
	return 0;
}

/* The invariants of any table (see the header). */
static void table_ok(uint32_t lang, const char *src, uint64_t n, const struct kgenome_func_set *fs)
{
	uint8_t *code = code_of(lang, src, n);
	uint32_t i;

	CK(code != NULL);
	for (i = 0; code && i < fs->n; i++) {
		const struct kgenome_func *f = &fs->v[i];
		uint64_t end = f->off + f->len;

		CK(f->kind == KGENOME_FN_SCRIPT);
		CK(f->len > 0 && end <= n);
		if (i)
			CK(f->off >= fs->v[i - 1u].off + fs->v[i - 1u].len);
		if (f->flags & KGENOME_FN_F_END_OPEN)
			CK(end == n);
		else if (end && end <= n && !(f->flags & KGENOME_FN_F_EVAL_ISLAND) && brace_lang(lang))
			/* a brace body ends at its code "}"; an expression body (js arrow, php fn, island package) at its expression's end */
			CK((src[end - 1u] == '}' && code[end - 1u]) || has_arrow(src + f->off, f->len));
		/* a name lies in its function; an anonymous one names no place (name_off 0 since the island package: fn_emit) */
		CK(!f->name_len ? f->name_off == 0u : (f->name_off >= f->off && (uint64_t)f->name_off + f->name_len <= end));
	}
	free(code);
}

static void build(uint32_t lang, const char *src, struct kgenome_func_set *fs)
{
	uint64_t n = strlen(src);

	memset(fs, 0, sizeof *fs);
	kgenome_script_funcs_build(lang, (const uint8_t *)src, n, fs);
	table_ok(lang, src, n, fs);
}

/* Entry `k` begins at the first occurrence of `from` and ends right after the first occurrence of
 * `to` at or after it, and is named `name` (NULL: anonymous). */
static void expect(const char *src, const struct kgenome_func_set *fs, uint32_t k, const char *from,
		   const char *to, const char *name)
{
	const char *a = strstr(src, from), *b = a ? strstr(a, to) : NULL;

	CK(a && b && k < fs->n);
	if (!a || !b || k >= fs->n) {
		printf("    entry %u of %u: want [%s .. %s]\n", k, fs->n, from, to);
		return;
	}
	CK(fs->v[k].off == (uint64_t)(a - src));
	CK(fs->v[k].off + fs->v[k].len == (uint64_t)(b - src) + strlen(to));
	if (name) {
		CK(fs->v[k].name_len == strlen(name) && !memcmp(src + fs->v[k].name_off, name, strlen(name)));
	} else {
		CK(fs->v[k].name_len == 0);
	}
	if (fs->v[k].off != (uint64_t)(a - src) || fs->v[k].off + fs->v[k].len != (uint64_t)(b - src) + strlen(to))
		printf("    entry %u: got off=%llu len=%llu want off=%llu end=%llu\n", k,
		       (unsigned long long)fs->v[k].off, (unsigned long long)fs->v[k].len,
		       (unsigned long long)(a - src), (unsigned long long)(b - src) + strlen(to));
}

static void count_is(const struct kgenome_func_set *fs, uint32_t want)
{
	CK(fs->n == want);
	if (fs->n != want)
		printf("    got %u function(s), want %u\n", fs->n, want);
}

/* ---- SP-1: php keywords are case-insensitive ------------------------------------------------- */
static void php_keyword_in_any_case(void)
{
	static const char src[] =
		"<?php\nFUNCTION Foo($a) { return 1; }\nFunction bar() { }\nfUnCtIoN &baz() {}\n"
		"$f = FUNCTION () USE ($a) { };\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_PHP, src, &fs);
	count_is(&fs, 4);
	expect(src, &fs, 0, "FUNCTION Foo", "1; }", "Foo");
	expect(src, &fs, 1, "Function bar", "{ }", "bar");
	expect(src, &fs, 2, "fUnCtIoN &baz", "{}", "baz");
	expect(src, &fs, 3, "FUNCTION ()", "{ }", NULL);
	kgenome_funcs_free(&fs);
}

/* ---- SP-2: powershell ------------------------------------------------------------------------ */
static void psh_case_kinds_and_names(void)
{
	static const char src[] =
		"Function Get-Foo { param($a) }\nfunction global:Set-Bar($x) { }\nFUNCTION baz { }\n"
		"filter Qux { $_ }\nWorkflow Wf { }\nfunction Plain.Dot { }\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_PSH, src, &fs);
	count_is(&fs, 6);
	expect(src, &fs, 0, "Function Get-Foo", "$a) }", "Get-Foo");
	expect(src, &fs, 1, "function global:Set-Bar", "{ }", "global:Set-Bar");
	expect(src, &fs, 2, "FUNCTION baz", "{ }", "baz");
	expect(src, &fs, 3, "filter Qux", "$_ }", "Qux");
	expect(src, &fs, 4, "Workflow Wf", "{ }", "Wf");
	expect(src, &fs, 5, "function Plain.Dot", "{ }", "Plain.Dot");
	kgenome_funcs_free(&fs);
}

/* ---- SP-3: perl ------------------------------------------------------------------------------ */
static void perl_qualified_names_and_attributes(void)
{
	static const char src[] =
		"sub Foo::Bar::baz { return 1; }\nsub Old'style { }\nsub lv : lvalue { $x }\n"
		"sub pr :prototype($) ($x) { }\nsub m2 :method :lvalue { }\nsub fwd :lvalue;\nsub plain { }\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_PERL, src, &fs);
	count_is(&fs, 6);
	expect(src, &fs, 0, "sub Foo::Bar::baz", "1; }", "Foo::Bar::baz");
	expect(src, &fs, 1, "sub Old'style", "{ }", "Old'style");
	expect(src, &fs, 2, "sub lv", "$x }", "lv");
	expect(src, &fs, 3, "sub pr", "{ }", "pr");
	expect(src, &fs, 4, "sub m2", "{ }", "m2");
	expect(src, &fs, 5, "sub plain", "{ }", "plain");
	kgenome_funcs_free(&fs);
}

/* ---- SP-12: a sigil makes the word a variable ------------------------------------------------ */
static void sigils_are_not_keywords(void)
{
	static const char perl[] = "my %sub = (a => 1);\nprint $sub{a};\nmy @x = @sub{qw(a)};\nsub f : { }\nsub b { }\n";
	static const char js[] = "var $function = 1;\nclass A { functional(a) { return 1; } }\nfunction b() { }\n";
	static const char php[] = "<?php\n$function = 1;\n@function_exists('x');\nfunction a() junk { }\nfunction b() { }\n";
	static const char psh[] = "$function = 1\nfunction { }\nfunction b { }\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_PERL, perl, &fs);
	count_is(&fs, 1);
	expect(perl, &fs, 0, "sub b", "{ }", "b");
	kgenome_funcs_free(&fs);
	/* "functional" is not the keyword - and since the island package it IS a method of class A (a keyword-less method, ECMA-262 15.4) */
	build(KGENOME_TEXTUAL_LANG_JS, js, &fs);
	count_is(&fs, 2);
	expect(js, &fs, 0, "functional", "return 1; }", "functional");
	expect(js, &fs, 1, "function b", "{ }", "b");
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PHP, php, &fs);
	count_is(&fs, 1);
	expect(php, &fs, 0, "function b", "{ }", "b");
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PSH, psh, &fs);
	count_is(&fs, 1);
	expect(psh, &fs, 0, "function b", "{ }", "b");
	kgenome_funcs_free(&fs);
	/* a modifier word with a sigil in front is a variable, not part of the declaration */
	build(KGENOME_TEXTUAL_LANG_PERL, "print $our sub g { }\n", &fs);
	count_is(&fs, 1);
	expect("print $our sub g { }\n", &fs, 0, "sub g", "{ }", "g");
	kgenome_funcs_free(&fs);
}

/* ---- SP-6/SP-7: a header that straddles a close, two headers on one brace -------------------- */
static void headers_that_are_not_declarations(void)
{
	/* the inner header's level closes before its "{": a ends there, the inner is nothing */
	static const char js[] = "function a() { return function (x }) { y(); }\nfunction b() { }\n";
	/* `a`'s return type swallows `function b()` and both claim b's brace: b is the declaration */
	static const char php[] = "<?php\nfunction a(): function b() { }";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_JS, js, &fs);
	count_is(&fs, 2);
	expect(js, &fs, 0, "function a", "(x }", "a");
	expect(js, &fs, 1, "function b", "{ }", "b");
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PHP, php, &fs);
	count_is(&fs, 1);
	expect(php, &fs, 0, "function b", "{ }", "b");
	CK(fs.partial == 0);
	kgenome_funcs_free(&fs);
}

/* Headers that start like a declaration and are not one: each text has exactly `n` functions, the
 * last one named "z" (every header before it gives up and costs nothing after). */
static void headers_that_give_up(void)
{
	static const struct { uint32_t lang; const char *src; uint32_t n; } c[] = {
		{ KGENOME_TEXTUAL_LANG_PHP,  "<?php\n$f = function () use $x { };\nfunction z($s = \")\") { }\n", 1 },
		{ KGENOME_TEXTUAL_LANG_JS,   "function a(s = \")\" /* ) */) { }\nfunction z() { }\n", 2 },
		{ KGENOME_TEXTUAL_LANG_PERL, "sub a ($x { }\nsub z { }\n", 1 },
		{ KGENOME_TEXTUAL_LANG_PSH,  "function a ( { }\nfunction z { }\n", 1 },
		{ KGENOME_TEXTUAL_LANG_SH,   "function () { :; }\nfunction f (x) { :; }\nz() { :; }\n", 1 },
		/* a group at byte 0, an argument "{", a "{" after a word that only ends like a reserved one */
		{ KGENOME_TEXTUAL_LANG_SH,   "{ echo top; }\nf() { echo { ; x.then { ; }\nz() { :; }\n", 2 },
	};
	unsigned k;

	for (k = 0; k < sizeof c / sizeof c[0]; k++) {
		struct kgenome_func_set fs;

		build(c[k].lang, c[k].src, &fs);
		count_is(&fs, c[k].n);
		if (fs.n == c[k].n && fs.n) {
			const struct kgenome_func *z = &fs.v[fs.n - 1u];

			CK(z->name_len == 1u && c[k].src[z->name_off] == 'z');
			CK(z->off + z->len == strlen(c[k].src) - 1u);
		}
		kgenome_funcs_free(&fs);
	}
}

/* ---- the eval() island's word and the fragment flag ------------------------------------------ */
static void eval_word_and_fragment(void)
{
	static const char lit[] = "<?php eval('function x() { }');\n";
	static const char glued[] = "<?php \xff" "eval('function x() { }');\n";
	static const char frag[] = "function a() { }\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_PHP, lit, &fs);
	count_is(&fs, 1);
	CK(fs.n == 1 && (fs.v[0].flags & KGENOME_FN_F_EVAL_ISLAND));
	kgenome_funcs_free(&fs);
	/* "\xffeval" is one php name, not eval: no island */
	build(KGENOME_TEXTUAL_LANG_PHP, glued, &fs);
	count_is(&fs, 0);
	kgenome_funcs_free(&fs);
	/* a tagless php island: code from byte 0 only when asked as a fragment */
	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs(&(const struct kgenome_script_funcs_req){ .lang = KGENOME_TEXTUAL_LANG_PHP,
			     .flags = KGENOME_TEXTUAL_FRAGMENT, .in = (const uint8_t *)frag, .n = sizeof frag - 1u }, &fs);
	count_is(&fs, 1);
	CK(fs.n == 1 && fs.v[0].off == 0 && fs.v[0].len == sizeof frag - 2u);
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PHP, frag, &fs);
	count_is(&fs, 0);
	kgenome_funcs_free(&fs);
}

/* ---- SP-4: shell names ----------------------------------------------------------------------- */
static void sh_names_with_punctuation(void)
{
	static const char src[] =
		"#!/bin/bash\nmy-func() { echo hi; }\nfunction log-info { echo x; }\na.b() { :; }\n"
		"ns::f() { :; }\nfunction my-other() { :; }\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_SH, src, &fs);
	count_is(&fs, 5);
	expect(src, &fs, 0, "my-func()", "hi; }", "my-func");
	expect(src, &fs, 1, "function log-info", "x; }", "log-info");
	expect(src, &fs, 2, "a.b()", ":; }", "a.b");
	expect(src, &fs, 3, "ns::f()", ":; }", "ns::f");
	expect(src, &fs, 4, "function my-other", ":; }", "my-other");
	kgenome_funcs_free(&fs);
}

/* ---- SP-5: a shell "}" that is a byte of a word ---------------------------------------------- */
static void sh_braces_that_are_words(void)
{
	/* each body below was checked with bash: the function ends at its LAST "}" */
	static const char *const bodies[] = {
		"f() { echo }; }\n",
		"f() { echo \\}; }\n",
		"f() { echo ${x}; echo ${y:-}; }\n",
		"f() { echo {a,b} {1..3}; }\n",
		"f() { find . -exec rm {} \\; ; }\n",
		"f() { [[ $a =~ ^x{2}$ ]]; }\n",
		"f() { case $x in a) echo }; esac; }\n",
		"f() { x=$(echo \"}\"); }\n",
		"f() {\n  { (echo a) }\n}\n",
		"f() {\n  if true; then { echo g; } fi\n}\n",
		"f(){ :;}\n",
		"f() {\r\n  echo }\r\n}\r\n",
		"f() { echo '}' \"}\" # }\n}\n",
		"f() { cat <<EOF\n}\nEOF\n}\n",
		"f() { a=( } ); }\n",
		"f() { echo x;}y; }\n",
		"f() { echo !{ ; }\n",
		"f() { echo }{ x; }\n",
	};
	unsigned k;

	for (k = 0; k < sizeof bodies / sizeof bodies[0]; k++) {
		char src[256];
		struct kgenome_func_set fs;
		const char *last;

		snprintf(src, sizeof src, "#!/bin/sh\n%sg() { :; }\n", bodies[k]);
		build(KGENOME_TEXTUAL_LANG_SH, src, &fs);
		last = strstr(src, "g() {");
		count_is(&fs, 2);
		if (fs.n == 2) {
			const char *close = last;

			while (close > src && *close != '}')
				close--;
			CK(fs.v[0].off == 10u);
			CK(fs.v[0].off + fs.v[0].len == (uint64_t)(close - src) + 1u);
			if (fs.v[0].off + fs.v[0].len != (uint64_t)(close - src) + 1u)
				printf("    body %u: f ends at %llu, want %llu\n", k,
				       (unsigned long long)(fs.v[0].off + fs.v[0].len),
				       (unsigned long long)((close - src) + 1));
		}
		kgenome_funcs_free(&fs);
	}
}

/* ---- SP-6: braces in a parameter list -------------------------------------------------------- */
static void braces_in_parameters(void)
{
	static const char js[] =
		"function a({x, y}) { return x; }\nfunction b(o = {}) { return o; }\n"
		"function c(f = function () { return {}; }) { return f(); }\nfunction d([p, {q}] = [1, {}]) { }\n";
	static const char perl[] = "sub a ($x = {}) { return $x; }\nsub b { }\n";
	static const char psh[] = "function a($s = { 1 }) { & $s }\nfunction b { }\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_JS, js, &fs);
	count_is(&fs, 4);
	expect(js, &fs, 0, "function a", "return x; }", "a");
	expect(js, &fs, 1, "function b", "return o; }", "b");
	expect(js, &fs, 2, "function c", "return f(); }", "c");
	expect(js, &fs, 3, "function d", "{ }", "d");
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PERL, perl, &fs);
	count_is(&fs, 2);
	expect(perl, &fs, 0, "sub a", "return $x; }", "a");
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PSH, psh, &fs);
	count_is(&fs, 2);
	expect(psh, &fs, 0, "function a", "$s }", "a");
	kgenome_funcs_free(&fs);
}

/* ---- SP-7: php return types ------------------------------------------------------------------ */
static void php_return_types(void)
{
	static const char src[] =
		"<?php\nfunction a(): array { return []; }\nfunction b(): ?Foo /* c */ { }\n"
		"function c(): A|B { }\nfunction d(): (A&B)|null { }\nfunction e(): \\Ns\\T { }\n"
		"function f(): static { }\nfunction g() # c\n{ }\n";
	static const char twin[] = "<?php\nfunction a() function b() { }\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_PHP, src, &fs);
	count_is(&fs, 7);
	expect(src, &fs, 0, "function a", "[]; }", "a");
	expect(src, &fs, 1, "function b", "{ }", "b");
	expect(src, &fs, 2, "function c", "{ }", "c");
	expect(src, &fs, 3, "function d", "{ }", "d");
	expect(src, &fs, 4, "function e", "{ }", "e");
	expect(src, &fs, 5, "function f", "{ }", "f");
	expect(src, &fs, 6, "function g", "{ }", "g");
	kgenome_funcs_free(&fs);
	/* `a` has no body of its own: b's brace is not a's */
	build(KGENOME_TEXTUAL_LANG_PHP, twin, &fs);
	count_is(&fs, 1);
	expect(twin, &fs, 0, "function b", "{ }", "b");
	kgenome_funcs_free(&fs);
}

/* ---- SP-8: modifiers belong to the declaration ----------------------------------------------- */
static void modifiers_are_part_of_the_declaration(void)
{
	static const char php[] =
		"<?php\nclass K {\n  public static function a() { }\n  private function b() { }\n"
		"  final PUBLIC function c() { }\n  abstract protected function d();\n}\n"
		"$s = static function () { };\nreturn function () { return 2; };\n";
	static const char js[] =
		"export default async function f() { }\nasync function* g() { }\nexport function h() { }\n"
		"x = async function () { };\n";
	static const char perl[] = "my sub a { }\nour sub b { }\nmy $c = sub { };\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_PHP, php, &fs);
	count_is(&fs, 5);
	expect(php, &fs, 0, "public static function a", "{ }", "a");
	expect(php, &fs, 1, "private function b", "{ }", "b");
	expect(php, &fs, 2, "final PUBLIC function c", "{ }", "c");
	expect(php, &fs, 3, "static function ()", "{ }", NULL);
	expect(php, &fs, 4, "function () { return 2", "2; }", NULL);
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_JS, js, &fs);
	count_is(&fs, 4);
	expect(js, &fs, 0, "export default async function f", "{ }", "f");
	expect(js, &fs, 1, "async function* g", "{ }", "g");
	expect(js, &fs, 2, "export function h", "{ }", "h");
	expect(js, &fs, 3, "async function ()", "{ }", NULL);
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PERL, perl, &fs);
	count_is(&fs, 3);
	expect(perl, &fs, 0, "my sub a", "{ }", "a");
	expect(perl, &fs, 1, "our sub b", "{ }", "b");
	expect(perl, &fs, 2, "sub { }", "{ }", NULL);
	kgenome_funcs_free(&fs);
}

/* ---- SP-9: name bytes ------------------------------------------------------------------------ */
static void name_bytes_and_byte_order_mark(void)
{
	static const char js[] =
		"\xef\xbb\xbf" "function $init() { }\nfunction _$x() { }\nfunction caf\xc3\xa9() { }\n"
		"var $function = 1;\nfunction b() { }\n";
	static const char php[] = "<?php\nfunction \xff\xfe\xfd($a) { }\n$function = 1;\nfunction b() { }\n";
	static const char psh[] = "\xef\xbb\xbf" "function First { }\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_JS, js, &fs);
	count_is(&fs, 4);
	expect(js, &fs, 0, "function $init", "{ }", "$init");
	expect(js, &fs, 1, "function _$x", "{ }", "_$x");
	expect(js, &fs, 2, "function caf", "{ }", "caf\xc3\xa9");
	expect(js, &fs, 3, "function b", "{ }", "b");
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PHP, php, &fs);
	count_is(&fs, 2);
	expect(php, &fs, 0, "function \xff", "{ }", "\xff\xfe\xfd");
	kgenome_funcs_free(&fs);
	build(KGENOME_TEXTUAL_LANG_PSH, psh, &fs);
	count_is(&fs, 1);
	expect(psh, &fs, 0, "function First", "{ }", "First");
	kgenome_funcs_free(&fs);
}

/* ---- SP-10: the table cap counts outermost functions only ------------------------------------ */
static void nested_closures_do_not_fill_the_table(void)
{
	/* one function holding KGENOME_FNTAB_MAX + 1 closures: one unit, not 2^20 */
	const uint64_t k = (1u << 20) + 1u;
	static const char head[] = "function o() {", body[] = "function(){};", tail[] = "}\nfunction p() { }\n";
	uint64_t n = sizeof head - 1u + k * (sizeof body - 1u) + sizeof tail - 1u, i, at = 0;
	char *src = malloc((size_t)n + 1u);
	struct kgenome_func_set fs;

	CK(src != NULL);
	if (!src)
		return;
	memcpy(src, head, sizeof head - 1u);
	at = sizeof head - 1u;
	for (i = 0; i < k; i++, at += sizeof body - 1u)
		memcpy(src + at, body, sizeof body - 1u);
	memcpy(src + at, tail, sizeof tail);
	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)src, n, &fs);
	count_is(&fs, 2);
	CK(fs.partial == 0);
	if (fs.n == 2) {
		CK(fs.v[0].off == 0 && fs.v[0].len == n - (sizeof tail - 1u) + 1u);
		CK(fs.v[1].off == n - (sizeof tail - 1u) + 2u);
	}
	kgenome_funcs_free(&fs);
	free(src);
}

/* ---- boundaries ------------------------------------------------------------------------------ */
static void offsets_zero_and_end(void)
{
	static const struct { uint32_t lang; const char *src; uint32_t n; } c[] = {
		{ KGENOME_TEXTUAL_LANG_JS,   "function a(){}", 1 },
		{ KGENOME_TEXTUAL_LANG_PERL, "sub a{}", 1 },
		{ KGENOME_TEXTUAL_LANG_PSH,  "function a{}", 1 },
		{ KGENOME_TEXTUAL_LANG_SH,   "f(){ :;}", 1 },
		{ KGENOME_TEXTUAL_LANG_PHP,  "<?php function a(){}", 1 },
		{ KGENOME_TEXTUAL_LANG_JS,   "{", 0 },
		{ KGENOME_TEXTUAL_LANG_JS,   "}", 0 },
		{ KGENOME_TEXTUAL_LANG_JS,   "function", 0 },
		{ KGENOME_TEXTUAL_LANG_JS,   "function a(", 0 },
		{ KGENOME_TEXTUAL_LANG_JS,   "function a()", 0 },
		{ KGENOME_TEXTUAL_LANG_SH,   "f()", 0 },
		{ KGENOME_TEXTUAL_LANG_PERL, "sub", 0 },
		{ KGENOME_TEXTUAL_LANG_PHP,  "<?php function", 0 },
	};
	unsigned k;

	for (k = 0; k < sizeof c / sizeof c[0]; k++) {
		struct kgenome_func_set fs;

		build(c[k].lang, c[k].src, &fs);
		count_is(&fs, c[k].n);
		if (c[k].n && fs.n) {
			const char *kw = c[k].lang == KGENOME_TEXTUAL_LANG_PHP ? strstr(c[k].src, "function") : c[k].src;

			CK(fs.v[0].off == (uint64_t)(kw - c[k].src) && fs.v[0].off + fs.v[0].len == strlen(c[k].src));
		}
		kgenome_funcs_free(&fs);
	}
}

/* Unterminated at the end: the function runs to the end, said open, and the one closed before it
 * keeps its exact end. */
static void unterminated_at_end(void)
{
	static const struct { uint32_t lang; const char *src; } c[] = {
		{ KGENOME_TEXTUAL_LANG_PHP,  "<?php\nfunction z() { }\nfunction a() { $s = \"x" },
		{ KGENOME_TEXTUAL_LANG_PHP,  "<?php\nfunction z() { }\nfunction a() { $s = <<<EOT\nx\n" },
		{ KGENOME_TEXTUAL_LANG_PHP,  "<?php\nfunction z() { }\nfunction a() { /* x" },
		{ KGENOME_TEXTUAL_LANG_JS,   "function z() { }\nfunction a() { var s = `x${" },
		{ KGENOME_TEXTUAL_LANG_JS,   "function z() { }\nfunction a() { var r = /x" },
		{ KGENOME_TEXTUAL_LANG_PERL, "sub z { }\nsub a { my $s = q{x" },
		{ KGENOME_TEXTUAL_LANG_PSH,  "function z { }\nfunction a { $s = @\"\nx" },
		{ KGENOME_TEXTUAL_LANG_SH,   "#!/bin/sh\nz() { :; }\na() { cat <<E\nx\n" },
	};
	unsigned k;

	for (k = 0; k < sizeof c / sizeof c[0]; k++) {
		struct kgenome_func_set fs;
		const char *a = strstr(c[k].src, c[k].lang == KGENOME_TEXTUAL_LANG_PERL ? "sub a" :
				       c[k].lang == KGENOME_TEXTUAL_LANG_SH ? "a()" : "function a");

		build(c[k].lang, c[k].src, &fs);
		count_is(&fs, 2);
		if (fs.n == 2) {
			CK(!(fs.v[0].flags & KGENOME_FN_F_END_OPEN));
			CK(fs.v[1].off == (uint64_t)(a - c[k].src));
			CK(fs.v[1].flags & KGENOME_FN_F_END_OPEN);
			CK(fs.partial & KGENOME_FNTAB_P_ENDS);
		}
		kgenome_funcs_free(&fs);
	}
}

/* LF, CRLF: the same functions, the same names (the twin path). */
static void line_endings_twin(void)
{
	static const struct { uint32_t lang; const char *src; } c[] = {
		{ KGENOME_TEXTUAL_LANG_PHP,  "<?php\n// }\nfunction a() {\n  # }\n  return 1;\n}\nfunction b()\n{\n}\n" },
		{ KGENOME_TEXTUAL_LANG_JS,   "// }\nfunction a() {\n  return 1;\n}\nfunction b()\n{\n}\n" },
		{ KGENOME_TEXTUAL_LANG_PERL, "# }\nsub a {\n  return 1;\n}\nsub b\n{\n}\n" },
		{ KGENOME_TEXTUAL_LANG_PSH,  "# }\nfunction a {\n  return 1\n}\nfunction b\n{\n}\n" },
		{ KGENOME_TEXTUAL_LANG_SH,   "#!/bin/sh\n# }\na() {\n  echo }\n}\nb()\n{\n  :\n}\n" },
	};
	unsigned k;

	for (k = 0; k < sizeof c / sizeof c[0]; k++) {
		char crlf[512];
		size_t i, o = 0;
		struct kgenome_func_set lf, cr;

		for (i = 0; c[k].src[i] && o + 2u < sizeof crlf; i++) {
			if (c[k].src[i] == '\n')
				crlf[o++] = '\r';
			crlf[o++] = c[k].src[i];
		}
		crlf[o] = 0;
		build(c[k].lang, c[k].src, &lf);
		build(c[k].lang, crlf, &cr);
		count_is(&lf, 2);
		count_is(&cr, 2);
		for (i = 0; i < lf.n && i < cr.n; i++) {
			CK(lf.v[i].name_len == cr.v[i].name_len);
			CK(!(cr.v[i].flags & KGENOME_FN_F_END_OPEN));
		}
		kgenome_funcs_free(&lf);
		kgenome_funcs_free(&cr);
	}
}

/* A page: several islands, a function spanning two of them, a closing tag inside a string. */
static void php_page_islands(void)
{
	static const char src[] =
		"<html><?php function a() { ?><b>}</b><?php } ?>\n<p>{</p>\n"
		"<?php $s = \"?> function no() { }\"; function b() { } ?>\n<?php // ?> function c() {\n";
	struct kgenome_func_set fs;

	build(KGENOME_TEXTUAL_LANG_PHP, src, &fs);
	count_is(&fs, 2);
	expect(src, &fs, 0, "function a", "<?php }", "a");
	expect(src, &fs, 1, "function b", "{ }", "b");
	kgenome_funcs_free(&fs);
}

/* Strings, comments, heredocs, templates and regexes that hold braces and keywords. */
static void braces_and_keywords_in_literals(void)
{
	static const struct { uint32_t lang; const char *src; } c[] = {
		{ KGENOME_TEXTUAL_LANG_PHP, "<?php\nfunction a() { $s = '}'; $t = \"{$x} }\"; $h = <<<E\n}function x(){\nE;\n"
					    "$n = <<<'N'\n}\nN;\n/* } function y(){ */ # }\n}\nfunction b() { }\n" },
		{ KGENOME_TEXTUAL_LANG_JS,  "function a() { var s = '}', t = `${ {k:1}.k } }`, r = /}{/g, q = x / 2 / 3;"
					    " // }\n /* function y(){ */ }\nfunction b() { }\n" },
		{ KGENOME_TEXTUAL_LANG_PERL, "sub a { my $s = '}'; my $r = qr{\\}}; $x =~ s{a}{b}g; my %h; $h{k} = 1; # }\n}\n"
					     "=pod\nsub y { }\n=cut\nsub b { }\n" },
		{ KGENOME_TEXTUAL_LANG_PSH, "function a { $s = '}'; $t = @\"\n}\n\"@\n # }\n <# } #>\n}\nfunction b { }\n" },
		{ KGENOME_TEXTUAL_LANG_SH,  "#!/bin/sh\na() { s='}'; t=\"}\"; # }\n cat <<'E'\n}\nfunction y() {\nE\n}\nb() { :; }\n" },
	};
	unsigned k;

	for (k = 0; k < sizeof c / sizeof c[0]; k++) {
		struct kgenome_func_set fs;

		build(c[k].lang, c[k].src, &fs);
		count_is(&fs, 2);
		if (fs.n == 2) {
			const char *b = strstr(c[k].src, c[k].lang == KGENOME_TEXTUAL_LANG_PERL ? "sub b" :
					       c[k].lang == KGENOME_TEXTUAL_LANG_SH ? "b()" : "function b");

			const char *close = b;

			/* perl's POD stands between a and b: a ends at the last "}" before the POD */
			if (c[k].lang == KGENOME_TEXTUAL_LANG_PERL)
				close = strstr(c[k].src, "=pod");
			while (close > c[k].src && *close != '}')
				close--;
			CK(fs.v[1].off == (uint64_t)(b - c[k].src));
			CK(fs.v[0].off + fs.v[0].len == (uint64_t)(close - c[k].src) + 1u);
			CK(fs.v[0].name_len == 1u && c[k].src[fs.v[0].name_off] == 'a');
		}
		kgenome_funcs_free(&fs);
	}
}

/* Deep nesting: depth past anything real, bounded time, one unit. */
static void deep_nesting(void)
{
	const unsigned depth = 100000u;
	size_t n = depth * 13u + depth + 1u, at = 0;
	char *src = malloc(n + 1u);
	unsigned i;
	struct kgenome_func_set fs;

	CK(src != NULL);
	if (!src)
		return;
	for (i = 0; i < depth; i++, at += 13u)
		memcpy(src + at, "function(){ ", 12u), src[at + 12u] = ' ';
	for (i = 0; i < depth; i++)
		src[at++] = '}';
	src[at] = 0;
	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)src, at, &fs);
	count_is(&fs, 1);
	if (fs.n == 1)
		CK(fs.v[0].off == 0 && fs.v[0].len == at && !(fs.v[0].flags & KGENOME_FN_F_END_OPEN));
	kgenome_funcs_free(&fs);
	/* the same, one close short: the outermost runs to the end, said open */
	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)src, at - 1u, &fs);
	count_is(&fs, 1);
	if (fs.n == 1)
		CK(fs.v[0].len == at - 1u && (fs.v[0].flags & KGENOME_FN_F_END_OPEN));
	kgenome_funcs_free(&fs);
	free(src);
}

/*
 * SP-13: A PARAMETER LIST OF ANY LENGTH is matched (the paren table), where the whole header used to
 * be bounded at 512 bytes from the keyword - real bundles have destructured parameter lists longer
 * than that. What stays bounded (FN_LOOKAHEAD, the cost bound) is one RUN that is not a list: 600
 * blanks between the name and "(" give the candidate up. Pinned so a change to either is a decision.
 */
static void lookahead_bound(void)
{
	static const size_t lens[] = { 480, 520, 600, 5000 };
	char *src = malloc(6000);
	struct kgenome_func_set fs;
	unsigned k;

	CK(src != NULL);
	if (!src)
		return;
	for (k = 0; k < sizeof lens / sizeof lens[0]; k++) {
		size_t at, i;

		memcpy(src, "function a({", 12u);
		for (i = 0; i < lens[k]; i++)
			src[12u + i] = (i % 8u == 7u) ? ',' : 'x';
		at = 12u + lens[k];
		memcpy(src + at, "}) { }", 7u);
		build(KGENOME_TEXTUAL_LANG_JS, src, &fs);
		count_is(&fs, 1);
		CK(fs.n == 1 && fs.v[0].off == 0 && fs.v[0].off + fs.v[0].len == at + 6u);
		kgenome_funcs_free(&fs);
	}
	memcpy(src, "function a", 10u);
	memset(src + 10, ' ', 600);
	memcpy(src + 610, "() { }", 7u);
	build(KGENOME_TEXTUAL_LANG_JS, src, &fs);
	count_is(&fs, 0);
	kgenome_funcs_free(&fs);
	free(src);
}

/* EVERY ROW HAS A STRATEGY since the island package (2026-11-14): these rows were pinned at 0 ("no strategy yet, never a wrong cut") so
 * that a strategy would be added on purpose - it was (script_funcs_<lang>.c, script_funcs.c's java/c#/cfml rows; each language's own
 * tests are tests/lib/genome/script_funcs_<lang>.c and script_islands.c). Here only the count of each, read by its own language's spec. */
static void rows_without_a_strategy(void)
{
	static const struct { uint32_t lang; const char *src; uint32_t n; } c[] = {
		{ KGENOME_TEXTUAL_LANG_PY,   "def a(x):\n\tif x:\n\t\treturn 1\n        return 2\nclass K:\n    def m(self): pass\n", 2 },
		{ KGENOME_TEXTUAL_LANG_RUBY, "def a(x)\n  if x then 1 end\n  [1].each do |y| y end\nend\nx = 1 if y\n", 1 },
		{ KGENOME_TEXTUAL_LANG_LUA,  "local function a(x)\n  if x then return 1 end\n  for i=1,2 do end\nend\n", 1 },
		{ KGENOME_TEXTUAL_LANG_TCL,  "proc a {x} {\n  return [expr {$x+1}]\n}\n", 1 },
		{ KGENOME_TEXTUAL_LANG_BAT,  "@echo off\ncall :sub\ngoto :eof\n:sub\necho {\nexit /b\n", 1 },
		{ KGENOME_TEXTUAL_LANG_VBS,  "Function A(x)\n  A = x\nEND FUNCTION\nSub B()\nEnd Sub\n", 2 },
		{ KGENOME_TEXTUAL_LANG_ASP,  "<% Function A(x)\n A = x\nEnd Function %>\n", 1 },
		{ KGENOME_TEXTUAL_LANG_JSP,  "<%! int a(int x) { return x; } %>\n", 1 },
		{ KGENOME_TEXTUAL_LANG_ASPX, "<script runat=\"server\">void A() { }</script>\n", 1 },
		{ KGENOME_TEXTUAL_LANG_CFM,  "<cfscript>function a() { }</cfscript>\n", 1 },
	};
	unsigned k;

	for (k = 0; k < sizeof c / sizeof c[0]; k++) {
		struct kgenome_func_set fs;

		build(c[k].lang, c[k].src, &fs);
		count_is(&fs, c[k].n);
		CK(fs.status == KGENOME_OK && !(fs.partial & KGENOME_FNTAB_P_NO_TABLE));
		kgenome_funcs_free(&fs);
	}
}

/* UTF-16: the lexers read bytes, so a UTF-16 text has no keyword in it - an empty table, no crash,
 * never a cut inside a character. */
static void utf16_text(void)
{
	static const char narrow[] = "function a() { }\n";
	uint8_t wide[64];
	size_t i;
	struct kgenome_func_set fs;

	wide[0] = 0xff;
	wide[1] = 0xfe;
	for (i = 0; narrow[i]; i++) {
		wide[2u + 2u * i] = (uint8_t)narrow[i];
		wide[3u + 2u * i] = 0;
	}
	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, wide, 2u + 2u * i, &fs);
	count_is(&fs, 0);
	kgenome_funcs_free(&fs);
}

/*
 * THE ORACLE: every sequence of up to `len` tokens, against a naive forward match - for each
 * declaration token whose bytes are all code, the body brace at its fixed offset, matched to the
 * first code "}" that returns the depth to zero (or the end: open); then the outermost kept. A
 * different algorithm from the builder's (no stack, a scan per declaration).
 */
struct alpha {
	uint32_t lang;
	const char *prefix;
	const char *const *tok;
	unsigned n_tok;
	const char *decl[2];            /* the declaration tokens */
	unsigned brace_at[2];           /* where their body's "{" is */
};

static uint32_t oracle(const struct alpha *a, const char *src, uint64_t n, uint64_t *off, uint64_t *end,
		       int *open)
{
	uint8_t *code = code_of(a->lang, src, n);
	uint32_t m = 0, keep = 0, i;
	uint64_t at;
	unsigned d;

	for (at = 0; code && at < n; at++) {
		for (d = 0; d < 2u; d++) {
			uint64_t len = strlen(a->decl[d]), k, depth = 0, b;

			if (at + len > n || memcmp(src + at, a->decl[d], len))
				continue;
			for (k = 0; k < len && code[at + k]; k++)
				;
			if (k < len || (at && code[at - 1u] && (src[at - 1u] == '_' ||
			    (src[at - 1u] >= 'a' && src[at - 1u] <= 'z'))))
				continue;
			off[m] = at;
			open[m] = 1;
			end[m] = n;
			for (b = at + a->brace_at[d]; b < n; b++) {
				if (!code[b])
					continue;
				if (src[b] == '{')
					depth++;
				else if (src[b] == '}' && --depth == 0) {
					end[m] = b + 1u;
					open[m] = 0;
					break;
				}
			}
			m++;
		}
	}
	free(code);
	for (i = 0; i < m; i++) {
		if (keep && end[i] <= end[keep - 1u])
			continue;
		off[keep] = off[i];
		end[keep] = end[i];
		open[keep] = open[i];
		keep++;
	}
	return keep;
}

static void exhaustive(const struct alpha *a, unsigned len)
{
	unsigned idx[8], k, total = 1, run, bad = 0;

	for (k = 0; k < len; k++)
		total *= a->n_tok;
	for (run = 0; run < total; run++) {
		char src[256];
		size_t at = strlen(a->prefix);
		uint64_t off[16], end[16];
		int open[16];
		uint32_t want, i;
		struct kgenome_func_set fs;
		unsigned r = run;

		memcpy(src, a->prefix, at);
		for (k = 0; k < len; k++, r /= a->n_tok) {
			idx[k] = r % a->n_tok;
			memcpy(src + at, a->tok[idx[k]], strlen(a->tok[idx[k]]));
			at += strlen(a->tok[idx[k]]);
		}
		src[at] = 0;
		want = oracle(a, src, at, off, end, open);
		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(a->lang, (const uint8_t *)src, at, &fs);
		if (fs.n != want) {
			bad++;
		} else {
			for (i = 0; i < want; i++)
				if (fs.v[i].off != off[i] || fs.v[i].off + fs.v[i].len != end[i] ||
				    !(fs.v[i].flags & KGENOME_FN_F_END_OPEN) != !open[i])
					break;
			bad += i < want;
		}
		if (bad == 1 && (fs.n != want || i < want)) {
			printf("    first mismatch: [%s] got %u want %u\n", src, fs.n, want);
			bad++;
		}
		kgenome_funcs_free(&fs);
	}
	CK(bad == 0);
	printf("  exhaustive lang=%u: %u texts, %u mismatch(es)\n", a->lang, total, bad ? bad - 1u : 0u);
}

static void exhaustive_alphabets(void)
{
	static const char *const php_tok[] = { "function f(){", "{", "}", "'}'", "/*}*/", "#}\n", "\"{$a}\"", "?>}<?php " };
	static const char *const js_tok[]  = { "function f(){", "function g({a}){", "{", "}", "'}'", "/}/", "`${}`", "//}\n" };
	static const struct alpha php = { KGENOME_TEXTUAL_LANG_PHP, "<?php ", php_tok, 8, { "function f(){", "function f(){" }, { 12, 12 } };
	static const struct alpha js = { KGENOME_TEXTUAL_LANG_JS, "", js_tok, 8, { "function f(){", "function g({a}){" }, { 12, 15 } };

	exhaustive(&php, 6);
	exhaustive(&js, 6);
}

/* Order independence: two complete programs in either order give the same functions, shifted. */
static void order_independence(void)
{
	static const struct { uint32_t lang; const char *a, *b; } c[] = {
		{ KGENOME_TEXTUAL_LANG_JS,   "function a({x}) { return '}'; }\n", "var s = `}`; export function b() { if (1) { } }\n" },
		{ KGENOME_TEXTUAL_LANG_PERL, "sub A::a :lvalue { $h{1} }\n", "my $x = sub { 1 };\nsub b ($y = {}) { }\n" },
		{ KGENOME_TEXTUAL_LANG_PSH,  "Function Get-A { @{} }\n", "filter B { $_ }\n" },
		{ KGENOME_TEXTUAL_LANG_SH,   "a-b() { echo }; }\n", "function c { echo ${x}; }\n" },
	};
	unsigned k;

	for (k = 0; k < sizeof c / sizeof c[0]; k++) {
		char ab[512], ba[512];
		struct kgenome_func_set fa, fb, fab, fba;
		size_t la = strlen(c[k].a), lb = strlen(c[k].b);
		uint32_t i;

		snprintf(ab, sizeof ab, "%s%s", c[k].a, c[k].b);
		snprintf(ba, sizeof ba, "%s%s", c[k].b, c[k].a);
		build(c[k].lang, c[k].a, &fa);
		build(c[k].lang, c[k].b, &fb);
		build(c[k].lang, ab, &fab);
		build(c[k].lang, ba, &fba);
		count_is(&fab, fa.n + fb.n);
		count_is(&fba, fa.n + fb.n);
		for (i = 0; fab.n == fa.n + fb.n && fba.n == fa.n + fb.n && i < fa.n; i++) {
			CK(fab.v[i].off == fa.v[i].off && fab.v[i].len == fa.v[i].len);
			CK(fba.v[fb.n + i].off == fa.v[i].off + lb && fba.v[fb.n + i].len == fa.v[i].len);
		}
		for (i = 0; fab.n == fa.n + fb.n && fba.n == fa.n + fb.n && i < fb.n; i++) {
			CK(fab.v[fa.n + i].off == fb.v[i].off + la && fab.v[fa.n + i].len == fb.v[i].len);
			CK(fba.v[i].off == fb.v[i].off && fba.v[i].len == fb.v[i].len);
		}
		kgenome_funcs_free(&fa);
		kgenome_funcs_free(&fb);
		kgenome_funcs_free(&fab);
		kgenome_funcs_free(&fba);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	php_keyword_in_any_case();
	psh_case_kinds_and_names();
	perl_qualified_names_and_attributes();
	sigils_are_not_keywords();
	headers_that_are_not_declarations();
	eval_word_and_fragment();
	headers_that_give_up();
	sh_names_with_punctuation();
	sh_braces_that_are_words();
	braces_in_parameters();
	php_return_types();
	modifiers_are_part_of_the_declaration();
	name_bytes_and_byte_order_mark();
	nested_closures_do_not_fill_the_table();
	offsets_zero_and_end();
	unterminated_at_end();
	line_endings_twin();
	php_page_islands();
	braces_and_keywords_in_literals();
	deep_nesting();
	lookahead_bound();
	rows_without_a_strategy();
	utf16_text();
	exhaustive_alphabets();
	order_independence();
	printf("script_cuts: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
