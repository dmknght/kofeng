/*
 * script_funcs.c - see script_funcs.h.
 *
 * ONE FORWARD PASS, two counters, no per-function re-scan of the body - shared by every language
 * this file knows, PHP included.
 *
 * `is_code[]` (one byte per input byte, built from ONE kgenome_textual_lex pass, the SAME driver
 * for every language it is given) says which bytes are real code and not inside a string, a
 * comment or markup: the lexer already does the hard part (quote and heredoc ends, nested
 * comments, a language's own escaping) and this reads nothing else - a candidate keyword, a "("
 * or a "{" that sits outside is_code is not real code, and is not a byte this file inspects again.
 *
 * THE NAME: each language's shape-matcher already walks past the identifier between the keyword
 * (or, for shell's bare form, the identifier itself) and the parameter list, so its (off, len) is
 * captured there (struct kgenome_func.name_off/name_len, funcs.h) and carried on `pending[]` until
 * the matching "}" - no second pass over the text, and no copy of the bytes (an offset into the
 * object, same convention as `value`/`shndx`). Zero length is an anonymous function where the
 * language allows one (PHP's `function (...) {...}`, a bare perl `sub {...}`, a JS function
 * expression) and kof_func_name names it `block_<line>` instead (2026-11-06) - never the binary's
 * own fcn_<offset>, which no script word implies.
 *
 * A keyword's HEADER is matched forward from it: each run of it bounded (FN_LOOKAHEAD), each
 * parenthesised list looked up in the text's one paren table (built once, SP-13). Its BODY is not
 * scanned at all: the declaration is pushed on the open stack with the "{" its shape found, ARMED
 * with the depth that "{" opens when the one brace walk reaches it (SP-6: not the next "{" counted,
 * which a parameter list may hold), and the walk - one counter, ONCE over the whole buffer - closes
 * it at the "}" that returns to that depth. A function nested forty deep costs forty stack slots and
 * one pass, not forty passes - the naive "scan forward from each keyword to its own matching close"
 * was quadratic on a file of nested closures (pathological, but exactly what a hostile input would
 * be), and this is why it is not written that way. This is language-agnostic: the walk is ONE
 * implementation, run for all five languages below; what a "{" is, is the row's (shell: SP-5).
 *
 * NESTING: a language that lets a function be declared inside another's body (PHP, JS, perl) has
 * both keywords found, because the outer stays open until ITS OWN depth is reached. Only the
 * OUTERMOST is a unit (fn_emit, SP-10): a function that closes inside an open body is not appended,
 * and one that sat in an outer's header (a default value) is taken back off the list when the outer
 * closes - so the list is in start order and disjoint as it is built. Not kgenome_fntab_merge
 * (fntab.h): that routine's "is this start check-only" test is vacuously true whenever `source` is
 * 0, which every entry here is for every language (struct kgenome_func.source has no spare
 * KGENOME_FN_S_* bit for "a script's own declaration shape", all eight are taken, see funcs.h), so
 * calling it silently dropped every script function (caught by tests/unit/mutation_units.c's
 * script_functions(), RED on an earlier version of this file, PHP only at the time). A nested helper
 * is not given its own unit today (owner's brief, 2026-11-05): kgenome_funcs_at/kgenome_funcs_start's
 * binary search - which EVERY consumer of struct kgenome_func_set shares, not only mutation - assumes
 * a later entry's end never dips below an earlier one's, which two kept overlapping (not merely
 * adjacent) entries would break. The inner function's bytes are not lost: they are hashed as part of
 * the outer unit's window sketch (rule 4). Scoring a nested helper as a unit of its own regardless of
 * its wrapper is the next algorithm, once a second table (or a relaxed lookup) is worth the cost for
 * scripts specifically: not done here.
 *
 * THE BRACE-DELIMITED LANGUAGES (island package, 2026-11-14: each language dispatched to its own reading, owner: "chia dispatch mỗi ngôn
 * ngữ theo đúng tiêu chuẩn ngôn ngữ"): one row each in LANG_ROWS - php, javascript (and asp's jscript), perl, powershell, shell, java (a
 * jsp's "<%!"), c# (an aspx's <script runat="server">) and cfscript - with its keywords, case, name bytes, modifiers, a shape matcher, and
 * where a keyword-less declaration may stand (shell's `name() {`, a javascript method, a java or c# method). Everything from "{" onward -
 * the brace walk, the open stack, END_OPEN - is the ONE shared implementation (rule 10). The languages that close a body on a keyword,
 * an indentation or a label are strategies of their own, one file each (script_private.h, script_funcs_<lang>.c: python, ruby, lua, tcl,
 * batch, vb); kgenome_script_funcs_of_text dispatches. A declaration starts at the first modifier word in front of its keyword (SP-8:
 * `public static function`, `export default async function`, `my sub`), not at the keyword.
 *
 *   - PHP ("function", any case: SP-1): shape_php - optional "&" (by-reference return), a name
 *     (zero length for an anonymous closure; high bytes are name bytes: SP-9), "(...)", an optional
 *     "use (...)" closure-variable list, an optional ": type" return type (SP-7), then "{".
 *   - JS ("function", also "function*"): shape_js - a generator's "*" (with or without a space on
 *     either side: a JS source may write "function*name", "function *name" or "function* name",
 *     all valid) is skipped before the name is read; a name is optional (a function EXPRESSION,
 *     `var f = function (x) {...}`, has none); no "use" clause and no return-type colon exist in
 *     plain JS, so the header ends at "(...)" and then "{" directly. Arrow functions
 *     (`(a) => {...}`) are the documented next case, not this one (same gap PHP's own header
 *     already names for its own arrow form).
 *   - PERL ("sub"): shape_perl - a name is optional (a bare `sub {...}` is a real, if less common,
 *     anonymous closure, perlsub(1)); an optional PARENTHESISED PROTOTYPE or signature
 *     (`sub foo ($$) {...}`, `sub foo($x, $y) {...}`) is skipped the same way PHP's parameter list
 *     is - its contents are never inspected, only balanced - because this file only needs to find
 *     the "{" the prototype or signature precedes, not validate what is in it; a forward
 *     declaration with no body (`sub foo($$);`, common in this tree's own real perl samples, see
 *     RandPasswd.pm) ends in ";" and is correctly not a match, the same way PHP's abstract method
 *     is not.
 *   - PSH / PowerShell ("function", "filter", "workflow", any case: SP-2; a Verb-Noun or
 *     scope-prefixed name): shape_psh - a name, then EITHER an optional "(...)" parameter
 *     list OR nothing at all before "{": PowerShell allows a function's parameters to be written
 *     either in parens right after the name or as a `param(...)` statement as the FIRST line of
 *     the body - the second form needs no special case here at all, because `param(...)` is then
 *     just ordinary code inside the already-opened body, read like anything else between the
 *     matching braces.
 *   - SH (posix shell, bash, busybox ash) has TWO independent shapes, because POSIX itself defines
 *     the bareword one and bash adds the keyword one on top:
 *       - shape_sh_keyword ("function" + a REQUIRED name - shell's "function" always names one,
 *         unlike PHP/JS's keyword - + an optional, and if present STRICTLY EMPTY, "()" + "{"):
 *         bash's `function name { ... }` / `function name() { ... }`.
 *       - shape_sh_bareword (an identifier directly, no keyword, + a REQUIRED, STRICTLY EMPTY
 *         "()" + "{"): POSIX's `name() { ... }`. The parens must be EMPTY (shell functions
 *         declare no parameter list; `name(args)` is not shell syntax) - match_empty_parens, not
 *         the paren table, enforces this, which is also exactly what tells a DECLARATION apart from a
 *         CALL: a call (`somefunc arg1 arg2`) never has a "(" at all after the name, so it is never
 *         a candidate in the first place, and a subshell group or an arithmetic expression that
 *         happens to follow a bare word is never immediately "()" with nothing but whitespace
 *         inside.
 *     No shell or powershell function-shape reader existed to reuse (phenotype's scope walker reads neither: diag_text_lang_sh.c and
 *     diag_text_lang_psh.c set no `fn_kw`), so these shapes are this file's; js and perl's are mirrored as knowledge, not called, because
 *     phenotype's scope stack is a diagnose-scan lifetime this file has no use for.
 *
 * SHELL'S OWN DOUBLE DETECTION, AND WHY IT DOES NOT DOUBLE-COUNT: the main loop tries the keyword
 * form first at every byte (as every other language does); only when that fails AND the language
 * is shell does it also try the bareword form at that byte (an `if` / `else if`, never both at the
 * same position). `claimed_until` stops it from ALSO firing a moment later when the loop reaches
 * the keyword-form's OWN name (`function foo() {`: once "function" matches and shape_sh_keyword
 * succeeds, the name "foo" would otherwise look like its own bareword candidate a few bytes later
 * in the same single pass) - it is set to the end of whatever name a successful keyword match just
 * consumed, and the bareword check is skipped for every byte before it. This costs one extra
 * bounded check (skip_trivia then look for "(") per identifier-START byte of a shell script, not
 * per byte and not unbounded (FN_LOOKAHEAD caps it exactly as every other forward scan here is
 * capped): the pass stays O(n) with a slightly larger constant for shell, not a new pass.
 *
 * WHAT IS NOT HANDLED, named rather than silently missed: a shell function whose body is a subshell (`name() ( ... )`) - POSIX allows
 * it, only the brace form is read (a subshell closes on ")", its own shape, not started); a php or javascript function whose body is ONE
 * expression (php `fn`, an arrow `x => x + 1`, c#'s `=> expr;`) IS read (expr_end) and ends where the expression does. A function whose
 * body never closes is emitted to the end of the buffer with KGENOME_FN_F_END_OPEN (rule 4). A php function that spans two page islands
 * (`<?php function f() { ?> html <?php } ?>`, every WordPress template helper) is one entry with the markup between, and the island it
 * stands in is joined across the tags (script_islands.c), so it is cut as one unit.
 */

#include <stdlib.h>
#include <string.h>

#include <kofcore.h>
#include <kgenome_budget.h>   /* kgenome_grow_cap */
#include <textual/textual.h>
#include <genotype/image/fntab.h>

#include "script_funcs.h"
#include "script_private.h"

/*
 * How far one RUN of a header is read before the candidate is given up: the white space, comments
 * and name between the keyword and "(", the run after ")" up to "{" (php's return type, perl's
 * attributes), counted again from the end of every parenthesised list. A parenthesised list itself
 * is NOT bounded by it any more (SP-13, 2026-11-14): its close is looked up in the text's one paren
 * table (struct paren_tab), so a parameter list of any length costs a binary search. With the whole
 * header bounded at 512 bytes from the keyword, 2 files of the measured corpora lost declarations
 * whose destructured or defaulted parameter lists were longer (wordpress block-editor.js,
 * block-library.js); with the table, the corpora give exactly what an unbounded read gives. The
 * bound is a cost bound only: a file of nothing but keywords pays it once per keyword.
 */
#define FN_LOOKAHEAD KGENOME_SCRIPT_LOOKAHEAD


/*
 * A declaration whose shape matched and whose body has not closed yet. It is pushed when its
 * keyword is read and ARMED when the walk reaches the body brace the shape found (`brace_off`):
 * only then does it know the depth its body opens (SP-6, 2026-11-14). It was pushed with "the
 * depth the next counted `{` opens", which is a different brace whenever one stands between the
 * keyword and the body - `function f({a, b}) {`, `function f(o = {}) {` - and the function then
 * closed at the parameter list's own "}" with its whole body cut off into the remainder (JS
 * destructuring and default parameters: every modern bundle).
 * `kw_depth` is the depth at the keyword: a "}" that closes that level before the body brace is
 * reached means the header straddles a close, and the candidate is not a declaration (dropped,
 * never emitted - it has no body). Entries are kept at most once per declaration
 * (kgenome_fntab_list_add's own KGENOME_FNTAB_MAX bounds what is emitted).
 */
struct fn_pending {
	uint64_t kw_off;        /* the declaration's first byte: the keyword, or a modifier before it */
	uint64_t brace_off;     /* the body's "{" the shape found */
	uint64_t kw_depth;      /* brace depth at the keyword */
	uint64_t depth;         /* brace depth the body opened; 0 until armed */
	/* The identifier's own span, captured once by the language's shape-matcher at the point it
	 * is already walked past - not a second scan. Zero length for an anonymous function where
	 * the language allows one. */
	uint64_t name_off;
	uint64_t name_len;
	uint8_t  wrapper;       /* a javascript module wrapper (fn_wrapper): its body is the top level, it is no unit */
};

struct fn_stack {
	struct fn_pending *v;
	uint64_t n, cap;
};

/* Append one pending entry, growing the array as kgenome_fntab_list_add's own callers do
 * (kgenome_grow_cap). 0 on an allocation failure - the caller stops the whole scan the same way
 * the dedup below already does on KGENOME_NOMEM. Shared by every language and both of shell's
 * shapes: one place pushes, so a bug in growing the array cannot differ by caller (rule 10). */
static int fn_pending_push(struct fn_stack *st, const struct fn_pending *e)
{
	if (st->n == st->cap) {
		uint32_t nc = kgenome_grow_cap((uint32_t)st->cap, 64u);
		struct fn_pending *np = nc ? realloc(st->v, (size_t)nc * sizeof *np) : NULL;

		if (!np)
			return 0;
		st->v = np;
		st->cap = nc;
	}
	st->v[st->n++] = *e;
	return 1;
}

static int is_ident(uint8_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/*
 * WHICH BYTES MAY BE PART OF A NAME, per language - one table, read by every shape below, by the
 * keyword's word boundary and by shell's bareword start (2026-11-14, SP-2/SP-3/SP-4/SP-9). One
 * ASCII-identifier rule for every language was wrong for each of them in a different way, and every
 * miss was a declaration silently dropped into the remainder (measured on constructed text, tests/
 * lib/genome/script_cuts.c):
 *   - PHP: a name is [A-Za-z0-9_\x80-\xff] (php's own lexer rule); `function \xff\xfe()` - the
 *     high-byte names obfuscated shells use - was not a function at all.
 *   - JS: `$` is a name byte (`function $init()`, `function _$x()`), and so is every byte of a
 *     UTF-8 identifier; both were missed.
 *   - Perl: a package-qualified name (`sub Foo::bar`, the old `sub Foo'bar`) stopped at the first
 *     `::`, so the declaration failed - the `::` is read as part of the name by shape_perl itself,
 *     not here, because a single `:` is the attribute introducer and must stay a separator.
 *   - PowerShell: Verb-Noun (`function Get-Foo`) is the language's own naming convention, and a
 *     scope prefix (`function global:Bar`) is part of the name: `-`, `:` and `.` are name bytes.
 *   - Shell: bash takes `my-func() {`, `a.b() {`, `ns::f() {` - and the old rule found `func()`
 *     INSIDE `my-func()`, a function starting three bytes late under the wrong name.
 * A high byte is a name byte everywhere: no language here gives one a syntactic meaning, and a
 * keyword or a name next to one is what the author typed.
 */
enum name_set { NAMES_PHP, NAMES_JS, NAMES_PERL, NAMES_PSH, NAMES_SH, NAMES_JAVA, NAMES_CS, NAMES_CFML };

static int is_name(enum name_set s, uint8_t c)
{
	if (is_ident(c) || c >= 0x80u)
		return 1;
	switch (s) {
	case NAMES_JS:   return c == '$';
	case NAMES_JAVA: return c == '$';       /* JLS 3.8: a Java letter includes "$" and "_" */
	case NAMES_PSH:  return c == '-' || c == ':' || c == '.';
	case NAMES_SH:   return c == '-' || c == ':' || c == '.' || c == '@' || c == '+';
	default:         return 0;
	}
}

static uint8_t fold_byte(uint8_t c)
{
	return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32u) : c;
}

/*
 * Does a word start at `at`: the byte before it is not a name byte (nor a sigil - `$`, `@`, `%` -
 * which makes the word a variable: perl's `$sub{a}` and `@sub{...}` read as two anonymous subs,
 * SP-12), or is the last byte of a UTF-8 byte order mark. The mark is three high bytes, so
 * with high bytes counted as name bytes `\xef\xbb\xbffunction` at the head of a file read as one
 * word and the file's first declaration was lost (measured: a JS file with a BOM, found while
 * fixing the name table; PowerShell editors write one by default). U+FEFF is white space to JS and
 * PowerShell and never part of a name in any language here.
 */
static int word_starts(enum name_set s, const uint8_t *p, const uint8_t *code, uint64_t at)
{
	if (!at || !code[at - 1u])
		return 1;
	if (at >= 3u && p[at - 3u] == 0xefu && p[at - 2u] == 0xbbu && p[at - 1u] == 0xbfu)
		return 1;
	return !is_name(s, p[at - 1u]) && p[at - 1u] != '$' && p[at - 1u] != '@' && p[at - 1u] != '%';
}


/*
 * One row per language: the keywords that open a declaration, whether they are matched without
 * regard to case, the modifier words that belong to the declaration in front of its keyword, the
 * shape matcher, and - shell only - which "{" and "}" are braces at all. A language not listed
 * answers an empty table (kgenome_script_funcs_build's own early return), exactly as
 * kgenome_funcs_build answers a format it has no case for.
 *
 * CASE (SP-1, SP-2): php's keywords and powershell's are case-insensitive - `FUNCTION f()`,
 * `Function Get-Foo` are declarations to the interpreter, and an obfuscated php shell writes them
 * that way on purpose. The other three languages' keywords are case-sensitive, and folding them
 * would make `Function` in a JS file a declaration that JS itself rejects.
 *
 * MODIFIERS (SP-8): `public static function f()` is ONE declaration. The unit started at the
 * keyword, so "public static " was cut off into the remainder unit before it - a declaration split
 * between two units, and a class's remainder made of "}\n\n    public " fragments. A modifier is
 * taken only when it is the whole word right in front of the keyword (or in front of a modifier
 * already taken), separated by white space alone: `return function` or `= function` is not one.
 */
struct shape_in;
struct shape_out;
typedef int (*shape_fn)(const struct shape_in *in, struct shape_out *out);
typedef int (*brace_fn)(const uint8_t *p, uint64_t n, uint64_t at);

struct lang_row {
	uint32_t lang;
	const char *const *kw;          /* NULL-terminated */
	uint8_t fold;                   /* keywords and modifiers case-insensitive */
	enum name_set names;
	const char *const *mods;        /* NULL, or NULL-terminated */
	shape_fn shape;
	brace_fn brace;                 /* NULL: every code "{" and "}" is a brace */
	/* A declaration with NO keyword, tried at a name's first byte where no keyword matched: shell's `name() {`, a javascript method
	 * `m() {`, a java or c# method `void m() {`. NULL: none. */
	shape_fn bare;
	/* Javascript's arrow functions, tried at a "(" and at a name: `(a) => {...}`, `a => a + 1`. */
	uint8_t arrow;
	/* Where a declaration may stand at all (enum fn_gate): a jsp's methods are declared in "<%!" only (its scriptlets are the body
	 * of the one _jspService method: JSP 2.3, 1.5), an aspx page's in <script runat="server"> only (its "<% %>" is the body of the
	 * page's render method). */
	uint8_t gate;
};

enum fn_gate { GATE_ANY = 0, GATE_JSP_DECL, GATE_ASPX_SCRIPT };

/* What a shape matcher reads: the text, its code bitmap, the keyword's own first byte `at` (for
 * shell's bareword form, the name's first byte) and the byte right after it, the row and the
 * text's paren table. A run's lookahead is counted from `at`, and again from each ")". */
struct shape_in {
	const uint8_t *p;
	const uint8_t *code;
	uint64_t n;
	uint64_t at, after;
	const struct lang_row *row;
	const struct kgenome_script_text *t;     /* the one lex: its paren table */
};

/* What a match answers: the body's opening "{" and the name's span (0 length: anonymous). */
struct shape_out {
	uint64_t brace, name_off, name_len;
	/* An EXPRESSION body (js `x => x + 1`, php `fn ($x) => $x`, c# `int F() => 1;`): its first byte; `brace` is then not read. */
	uint64_t expr;
	/* Where the declaration begins when the shape knows it (a keyword-less method begins at its first modifier or return type);
	 * 0 when the keyword (and its modifiers, decl_start) does. */
	uint64_t start;
};

/* Is the word `kw` the whole word at `at`, in code: a code byte on both sides (or the buffer's
 * edge) that is not a name byte of this language, so "myfunction", "my-function" (shell),
 * "functional" and "$function" (a variable: word_starts) do not match "function", and
 * "subroutine" does not match perl's "sub". */
static int is_keyword_at(const uint8_t *p, const uint8_t *code, uint64_t n, uint64_t at,
			  const char *kw, const struct lang_row *row)
{
	uint64_t k, kwlen = strlen(kw);

	if (at + kwlen > n || !code[at])
		return 0;
	for (k = 0; k < kwlen; k++)
		if (!code[at + k] || (row->fold ? fold_byte(p[at + k]) : p[at + k]) != (uint8_t)kw[k])
			return 0;
	if (!word_starts(row->names, p, code, at))
		return 0;
	if (at + kwlen < n && code[at + kwlen] && is_name(row->names, p[at + kwlen]))
		return 0;
	return 1;
}

/* The keyword of this row that starts at `at`, or NULL. */
static const char *keyword_at(const uint8_t *p, const uint8_t *code, uint64_t n, uint64_t at,
			      const struct lang_row *row)
{
	const char *const *k;

	for (k = row->kw; *k; k++)
		if (is_keyword_at(p, code, n, at, *k, row))
			return *k;
	return NULL;
}

/* Forward from `at` (a code byte, or the lookahead's edge) to the next code byte that is not
 * whitespace; a run that is not code (a comment, a string that has no business there) is
 * transparent - a hostile or malformed declaration either way finds no brace and is given up on,
 * never mismatched. */
static uint64_t skip_trivia(const uint8_t *p, const uint8_t *code, uint64_t n, uint64_t at, uint64_t limit)
{
	while (at < n && at < limit && (!code[at] || p[at] == ' ' || p[at] == '\t' || p[at] == '\r' || p[at] == '\n'))
		at++;
	return at;
}

/* The end of the run of code name bytes from `i`. */
static uint64_t scan_name(const struct shape_in *in, uint64_t i, uint64_t limit)
{
	while (i < limit && in->code[i] && is_name(in->row->names, in->p[i]))
		i++;
	return i;
}


/* Shell only: "(" at `open` closes on the VERY NEXT code byte being ")" (trivia in between is
 * allowed, anything else is not) - a shell function declares no parameter list, so unlike
 * a parameter list (the paren table) this is not a balanced-content match, it is "empty, or not a declaration".
 * This is also what tells a declaration's "()" apart from a subshell or an arithmetic expansion
 * that happens to follow a bare word with something inside its parens. */
static int match_empty_parens(const uint8_t *p, const uint8_t *code, uint64_t n, uint64_t open, uint64_t *close)
{
	uint64_t limit = open + FN_LOOKAHEAD < n ? open + FN_LOOKAHEAD : n;
	uint64_t i = skip_trivia(p, code, n, open + 1u, limit);

	if (i < limit && code[i] && p[i] == ')') {
		*close = i;
		return 1;
	}
	return 0;
}

static uint64_t run_limit(const struct shape_in *in, uint64_t from)
{
	return from + FN_LOOKAHEAD < in->n ? from + FN_LOOKAHEAD : in->n;
}

static uint64_t shape_limit(const struct shape_in *in)
{
	return run_limit(in, in->at);
}

/* The parenthesised list at `i` (a code "("), whatever its length: `*close` its ")", and the run
 * after it gets a lookahead of its own. 0 when the "(" is not closed. */
static int skip_parens(const struct shape_in *in, uint64_t i, uint64_t *close, uint64_t *limit)
{
	if (!kgenome_script_paren_close(in->t, i, close))
		return 0;
	*limit = run_limit(in, *close + 1u);
	return 1;
}

/* The body's "{" at `i`, or no match. */
static int shape_brace(const struct shape_in *in, uint64_t i, uint64_t limit, struct shape_out *out)
{
	if (i >= limit || !in->code[i] || in->p[i] != '{')
		return 0;
	out->brace = i;
	return 1;
}

/*
 * PHP: the shape from the keyword (skip an optional "&", a name, the parameter list, an optional
 * "use (...)", an optional ": type") to the "{" that begins its body, or 0 when this "function" is
 * not one - no "(", no "{" within the lookahead, or the declaration ends in ";" (abstract, an
 * interface method: no body to cut a unit from).
 *
 * THE RETURN TYPE (SP-7, 2026-11-14) is a colon and then a TYPE: names, `\`, `?`, `|`, `&` and
 * the parentheses of a DNF type, with white space and comments between them. It was "anything up
 * to `{` or `;`", which (a) stopped at a comment (`): ?Foo /\* c *\/ {` was not a function) and
 * (b) without a colon at all read `function a() function b() {` as a's return type "function b()"
 * and gave a and b the same body brace. A header with neither `{` nor `:` after its parameters is
 * not a declaration.
 */
static int shape_php_fn(const struct shape_in *in, struct shape_out *out);

static int shape_php(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i;

	if (in->after - in->at == 2u)
		return shape_php_fn(in, out);

	i = skip_trivia(p, code, n, in->after, limit);
	if (i < limit && code[i] && p[i] == '&')
		i = skip_trivia(p, code, n, i + 1u, limit);
	out->name_off = i;
	i = scan_name(in, i, limit);
	out->name_len = i - out->name_off;        /* 0 for an anonymous closure: `function (...) {...}` */
	i = skip_trivia(p, code, n, i, limit);
	if (i >= limit || !code[i] || p[i] != '(' || !skip_parens(in, i, &close, &limit))
		return 0;
	i = skip_trivia(p, code, n, close + 1u, limit);
	if (i + 3u <= limit && code[i] && code[i + 1u] && code[i + 2u] &&
	    fold_byte(p[i]) == 'u' && fold_byte(p[i + 1u]) == 's' && fold_byte(p[i + 2u]) == 'e' &&
	    !(i + 3u < limit && code[i + 3u] && is_name(NAMES_PHP, p[i + 3u]))) {
		i = skip_trivia(p, code, n, i + 3u, limit);
		if (i >= limit || !code[i] || p[i] != '(' || !skip_parens(in, i, &close, &limit))
			return 0;
		i = skip_trivia(p, code, n, close + 1u, limit);
	}
	if (i < limit && code[i] && p[i] == ':') {
		for (i++; i < limit; i++) {
			uint8_t c = p[i];

			if (!code[i] || c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
			    is_name(NAMES_PHP, c) || c == '\\' || c == '?' || c == '|' || c == '&' ||
			    c == '(' || c == ')')
				continue;
			break;
		}
	}
	return shape_brace(in, i, limit, out);
}

/*
 * JS: "function" (optionally "function*", a generator - the "*" may sit with or without
 * whitespace on either side), an optional name (a function EXPRESSION has none), "(...)", then
 * "{" directly - plain JS has no "use" clause and no return-type colon (that is TypeScript, out
 * of scope: this is KGENOME_TEXTUAL_LANG_JS only). A parameter list may hold braces of its own
 * (`function f({a, b})`, `function f(o = {})`): the paren table skips them here, and the brace walk
 * (kgenome_script_funcs_build) opens the body at the brace this found, not at the first "{" it
 * counts (SP-6).
 */
static int shape_js(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i;

	i = skip_trivia(p, code, n, in->after, limit);
	if (i < limit && code[i] && p[i] == '*')
		i = skip_trivia(p, code, n, i + 1u, limit);
	out->name_off = i;
	i = scan_name(in, i, limit);
	out->name_len = i - out->name_off;        /* 0 for a function expression: `function (x) {...}` */
	i = skip_trivia(p, code, n, i, limit);
	if (i >= limit || !code[i] || p[i] != '(' || !skip_parens(in, i, &close, &limit))
		return 0;
	return shape_brace(in, skip_trivia(p, code, n, close + 1u, limit), limit, out);
}

/*
 * Perl: "sub", an optional name (a bare `sub {...}` is a real anonymous closure, perlsub(1)), then
 * in any order a parenthesised prototype or signature (`sub foo ($$)`, `sub foo($x,$y)` - balanced
 * by the paren table and never inspected) and attributes (`:lvalue`, `:method`, `:prototype($)`),
 * then "{". A declaration with no body (`sub foo($$);`, a forward declaration) ends in ";" and
 * correctly does not match. The NAME may be package-qualified (SP-3): `Foo::Bar::baz` and the old
 * `Foo'bar` are one name, read here because a single ":" is the attribute introducer - a name
 * byte table cannot say "two colons yes, one no".
 */
static int shape_perl(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i;

	i = skip_trivia(p, code, n, in->after, limit);
	out->name_off = i;
	for (;;) {
		i = scan_name(in, i, limit);
		if (i > out->name_off && i + 2u < limit && code[i] && code[i + 1u] && code[i + 2u] &&
		    p[i] == ':' && p[i + 1u] == ':' && is_name(NAMES_PERL, p[i + 2u]))
			i += 2u;
		else if (i > out->name_off && i + 1u < limit && code[i] && code[i + 1u] &&
			 p[i] == '\'' && is_name(NAMES_PERL, p[i + 1u]))
			i += 1u;
		else
			break;
	}
	out->name_len = i - out->name_off;        /* 0 for a bare anonymous sub */
	for (;;) {
		i = skip_trivia(p, code, n, i, limit);
		if (i < limit && code[i] && p[i] == '(') {
			if (!skip_parens(in, i, &close, &limit))
				return 0;
			i = close + 1u;
		} else if (i + 1u < limit && code[i] && p[i] == ':' && !(code[i + 1u] && p[i + 1u] == ':')) {
			uint64_t a = skip_trivia(p, code, n, i + 1u, limit), e = scan_name(in, a, limit);

			if (e == a)
				return 0;       /* a ":" with no attribute name: not a declaration */
			i = e;          /* an attribute's "(...)" is read by the "(" branch, as a signature is */
		} else {
			break;
		}
	}
	return shape_brace(in, i, limit, out);
}

/*
 * PowerShell: "function" (or "filter", or "workflow": the same declaration with another kind of
 * body, SP-2), a name, then EITHER an optional "(...)" parameter list OR nothing at all before "{"
 * - the `param(...)` form (the parameter list as the first statement of the body) needs no case
 * here: it is read as ordinary code once the body's own "{" is open.
 */
static int shape_psh(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i;

	i = skip_trivia(p, code, n, in->after, limit);
	out->name_off = i;
	i = scan_name(in, i, limit);
	out->name_len = i - out->name_off;
	if (!out->name_len)
		return 0;       /* `function {` names nothing: not a declaration */
	i = skip_trivia(p, code, n, i, limit);
	if (i < limit && code[i] && p[i] == '(') {
		if (!skip_parens(in, i, &close, &limit))
			return 0;
		i = skip_trivia(p, code, n, close + 1u, limit);
	}
	return shape_brace(in, i, limit, out);
}

/*
 * Shell, bash's keyword form: "function", a REQUIRED name (unlike PHP/JS, shell's "function"
 * keyword never introduces an anonymous function - there is nothing to assign an anonymous shell
 * function to), then an optional "()" which, if present, MUST be strictly empty
 * (match_empty_parens, not a balanced list: a shell function declares no parameters), then "{".
 */
static int shape_sh_keyword(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i;

	i = skip_trivia(p, code, n, in->after, limit);
	out->name_off = i;
	i = scan_name(in, i, limit);
	out->name_len = i - out->name_off;
	if (out->name_len == 0)
		return 0;       /* "function" with no name at all is not a shell declaration */
	i = skip_trivia(p, code, n, i, limit);
	if (i < limit && code[i] && p[i] == '(') {
		if (!match_empty_parens(p, code, n, i, &close))
			return 0;
		i = skip_trivia(p, code, n, close + 1u, limit);
	}
	return shape_brace(in, i, limit, out);
}

/*
 * Shell, POSIX's bareword form: a name directly (no keyword at all) + a REQUIRED, strictly empty
 * "()" + "{" - `name() { ... }`. The empty-parens requirement is what tells this apart from a CALL
 * (`somefunc arg1 arg2` has no "(" at all after the name) and from a subshell group or arithmetic
 * expansion that happens to follow a bare word. `in->at` is the name's own first byte, already
 * known to start a name (the caller checks the byte before it is not a name byte of shell).
 */
static int shape_sh_bareword(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i;

	out->name_off = in->at;
	i = scan_name(in, in->at, limit);
	out->name_len = i - in->at;
	i = skip_trivia(p, code, n, i, limit);
	if (i >= limit || !code[i] || p[i] != '(' || !match_empty_parens(p, code, n, i, &close))
		return 0;
	return shape_brace(in, skip_trivia(p, code, n, close + 1u, limit), limit, out);
}

/* ---- the declarations with no braces around their body, and with no keyword ---------------------------------------------- */

/* Is the word [s, e) one of `set` (exact case). */
static int word_in(const uint8_t *p, uint64_t s, uint64_t e, const char *const *set)
{
	for (; *set; set++)
		if (strlen(*set) == e - s && !memcmp(p + s, *set, (size_t)(e - s)))
			return 1;
	return 0;
}

/* The last code byte before `at` that is not white space and not in a comment, within the lookahead: its offset + 1, or 0 when a byte
 * that is not code or a comment (a tag, markup, a string) or the start of the text comes first. `*nl` says a line break was crossed. */
static uint64_t prev_sig(const struct shape_in *in, uint64_t at, int *nl)
{
	uint64_t floor = at > FN_LOOKAHEAD ? at - FN_LOOKAHEAD : 0, j = at;

	*nl = 0;
	while (j > floor) {
		uint8_t k = in->t->kind[j - 1u], c = in->p[j - 1u];

		if (k == KGENOME_TEXTUAL_COMMENT || (k == KGENOME_TEXTUAL_CODE && (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
										  c == '\v' || c == '\f'))) {
			*nl |= c == '\n' || c == '\r';
			j--;
			continue;
		}
		return k == KGENOME_TEXTUAL_CODE ? j : 0;
	}
	return 0;
}

/* Is there a byte before `at`, within the lookahead, that is not white space and not a comment (prev_sig answered 0 for a string, a tag
 * or markup, and for the start of the text alike). */
static int prev_any(const struct shape_in *in, uint64_t at)
{
	uint64_t floor = at > FN_LOOKAHEAD ? at - FN_LOOKAHEAD : 0, j = at;

	while (j > floor) {
		uint8_t k = in->t->kind[j - 1u], c = in->p[j - 1u];

		if (k != KGENOME_TEXTUAL_COMMENT && !(k == KGENOME_TEXTUAL_CODE && (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
										  c == '\v' || c == '\f')))
			return 1;
		j--;
	}
	return 0;
}

/* The first code byte at or after `at` that is not white space or a comment, without crossing a line break (`*nl` set when one stops it). */
static uint64_t next_sig_line(const struct shape_in *in, uint64_t at, uint64_t limit, int *nl)
{
	*nl = 0;
	while (at < limit) {
		uint8_t k = in->t->kind[at], c = in->p[at];

		if (k == KGENOME_TEXTUAL_CODE && (c == '\n' || c == '\r')) {
			*nl = 1;
			return at;
		}
		if (k == KGENOME_TEXTUAL_COMMENT || (k == KGENOME_TEXTUAL_CODE && (c == ' ' || c == '\t' || c == '\v' || c == '\f')))
			at++;
		else
			break;
	}
	return at;
}

/* Where an expression body ends (js arrow, php fn, c# "=>" member): the first "," ";" or unmatched closing bracket at its own depth,
 * a byte that is not code (php's "?>", the end of a page's island), or the end of the text - and in javascript a line break after which
 * the expression cannot go on (ECMA-262 12.10, automatic semicolon insertion: the next line does not begin with an operator, "(", "[" or
 * a template, and the line did not end in one). [Unverified: the asi rule is read from the standard, not run.] Answers the byte after
 * its last code byte. */
static uint64_t expr_end(const struct shape_in *in, uint64_t at)
{
	const uint8_t *p = in->p;
	uint64_t i, depth = 0, end = at;
	uint8_t last = 0;
	int js = in->row->arrow != 0;

	for (i = at; i < in->n; i++) {
		uint8_t k = in->t->kind[i], c = p[i];

		if (k == KGENOME_TEXTUAL_STRING) {
			last = 'a';
			end = i + 1u;
			continue;
		}
		if (k == KGENOME_TEXTUAL_COMMENT)
			continue;
		if (k != KGENOME_TEXTUAL_CODE)
			break;
		if (c == '(' || c == '[' || c == '{') {
			depth++;
		} else if (c == ')' || c == ']' || c == '}') {
			if (!depth)
				break;
			depth--;
		} else if (!depth && (c == ',' || c == ';')) {
			break;
		} else if (js && !depth && (c == '\n' || c == '\r') && last && !strchr("+-*/%&|^=<>?:,.!~", last)) {
			uint64_t q = i;
			int nl;

			while (q < in->n && in->t->kind[q] == KGENOME_TEXTUAL_CODE && (p[q] == '\n' || p[q] == '\r'))
				q++;
			q = next_sig_line(in, q, in->n, &nl);
			while (nl && q < in->n && in->t->kind[q] == KGENOME_TEXTUAL_CODE && (p[q] == '\n' || p[q] == '\r'))
				q = next_sig_line(in, q + 1u, in->n, &nl);
			if (q >= in->n || in->t->kind[q] == KGENOME_TEXTUAL_CODE ? !(q < in->n && strchr(".?:+-*/%&|^=<>,([", p[q])) : 1)
				break;
		}
		if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
			last = c;
			end = i + 1u;
		}
	}
	return end;
}

/*
 * PHP's arrow function (php 7.4, "Arrow Functions"): `fn`, an optional "&", "(...)", an optional ": type", "=>" and ONE expression - its
 * body ends where the expression does (expr_end). `static fn` takes the modifier as `function` does.
 */
static int shape_php_fn(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i;

	i = skip_trivia(p, code, n, in->after, limit);
	if (i < limit && code[i] && p[i] == '&')
		i = skip_trivia(p, code, n, i + 1u, limit);
	if (i >= limit || !code[i] || p[i] != '(' || !skip_parens(in, i, &close, &limit))
		return 0;
	i = skip_trivia(p, code, n, close + 1u, limit);
	if (i < limit && code[i] && p[i] == ':')
		for (i++; i < limit && (!code[i] || is_name(NAMES_PHP, p[i]) || strchr(" \t\r\n\\?|&()", p[i])); i++)
			;
	if (i + 1u >= limit || !code[i] || p[i] != '=' || p[i + 1u] != '>')
		return 0;
	out->name_off = out->name_len = 0;
	out->expr = skip_trivia(p, code, n, i + 2u, limit);
	return out->expr < n;
}

/*
 * JAVASCRIPT'S ARROW FUNCTION (ECMA-262 15.3): `(params) => body` or `name => body`, optionally `async` in front; no line break may stand
 * between the parameters and "=>". The body is a block "{...}" (the brace walk closes it) or ONE expression (expr_end). `in->at` is the
 * "(" or the parameter's first byte. Anonymous: a unit's name is its own (kof_func_name names it block_<line>).
 */
static int shape_js_arrow(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i, b;
	int nl;

	if (p[in->at] == '(') {
		if (!skip_parens(in, in->at, &close, &limit))
			return 0;
		i = close + 1u;
	} else {
		i = scan_name(in, in->at, limit);
		if (i == in->at || word_in(p, in->at, i, (const char *const[]){ "async", "await", "yield", "typeof", "new", "return",
									      "delete", "void", "in", "of", "instanceof", "case",
									      NULL }))
			return 0;
	}
	i = next_sig_line(in, i, limit, &nl);
	if (i + 1u >= limit || !code[i] || p[i] != '=' || p[i + 1u] != '>')
		return 0;       /* a line break stopped next_sig_line short of "=>": no arrow */
	b = skip_trivia(p, code, n, i + 2u, n);
	out->name_off = out->name_len = 0;
	{
		uint64_t pv = prev_sig(in, in->at, &nl);

		out->start = in->at;
		if (pv >= 5u && !memcmp(p + pv - 5u, "async", 5u) && (pv == 5u || !is_name(NAMES_JS, p[pv - 6u])) && !nl)
			out->start = pv - 5u;
	}
	if (b < n && code[b] && p[b] == '{') {
		out->brace = b;
		return 1;
	}
	out->expr = b;
	return b < n;
}

/*
 * A JAVASCRIPT METHOD WITH NO KEYWORD (ECMA-262 15.4, MethodDefinition: in a class body or an object literal): `name(params) {`, after
 * any of `static`, `async`, `get`, `set`, "*"; a "#name" is a private one. It is told from a call by what stands before it - "{", "}",
 * ";" or "," (the member before it ended) - and by "{" following the ")" ON THE SAME LINE: a call followed by a block on the next line
 * is two statements (asi), and on the same line it is a syntax error, so no valid text reads as both.
 */
static const char *const JS_NOT_METHOD[] = { "if", "for", "while", "switch", "catch", "function", "with", "return", "typeof", "new",
					      "delete", "void", "await", "yield", "do", "else", "try", "finally", "class", "super",
					      "import", "in", "of", "instanceof", "case", "throw", "var", "let", "const", NULL };

static int shape_js_method(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i, j, s;
	int nl;

	i = scan_name(in, in->at + (p[in->at] == '#'), limit);
	if (i == in->at || word_in(p, in->at, i, JS_NOT_METHOD))
		return 0;
	out->name_off = in->at;
	out->name_len = i - in->at;
	i = skip_trivia(p, code, n, i, limit);
	if (i >= limit || !code[i] || p[i] != '(' || !skip_parens(in, i, &close, &limit))
		return 0;
	i = next_sig_line(in, close + 1u, limit, &nl);
	if (i >= limit || !code[i] || p[i] != '{')
		return 0;       /* a line break stopped next_sig_line short of "{": a call, then a block */
	out->brace = i;
	/* back over the modifiers to the byte that ended the member before */
	s = in->at;
	for (;;) {
		j = prev_sig(in, s, &nl);
		if (j && p[j - 1u] == '*') {
			s = j - 1u;
			continue;
		}
		if (j && is_name(NAMES_JS, p[j - 1u])) {
			uint64_t w = j;

			while (w > 0 && code[w - 1u] && is_name(NAMES_JS, p[w - 1u]))
				w--;
			if (word_in(p, w, j, (const char *const[]){ "static", "async", "get", "set", "accessor", NULL })) {
				s = w;
				continue;
			}
			return 0;
		}
		break;
	}
	if (j ? !strchr("{};,", p[j - 1u]) : prev_any(in, s))
		return 0;       /* after a string, a regular expression or a tag: not where a member begins */
	out->start = s;
	return 1;
}

/*
 * CFSCRIPT (cfml reference, "Defining functions in CFScript"): `function name(params)`, then any number of `attribute=value` pairs
 * (`output=false`, `access="remote"`), then "{". The access word and the return type in front are the row's modifiers.
 */
static int shape_cfml(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i;

	i = skip_trivia(p, code, n, in->after, limit);
	out->name_off = i;
	i = scan_name(in, i, limit);
	out->name_len = i - out->name_off;
	i = skip_trivia(p, code, n, i, limit);
	if (i >= limit || !code[i] || p[i] != '(' || !skip_parens(in, i, &close, &limit))
		return 0;
	for (i = skip_trivia(p, code, n, close + 1u, limit); i < limit && code[i] && is_name(NAMES_CFML, p[i]);) {
		i = skip_trivia(p, code, n, scan_name(in, i, limit), limit);
		if (i >= limit || !code[i] || p[i] != '=')
			return 0;
		/* the value: a string literal (not code: skip_trivia would step over it AND the next attribute's name) or a name */
		for (i++; i < limit && code[i] && (p[i] == ' ' || p[i] == '\t' || p[i] == '\r' || p[i] == '\n'); i++)
			;
		if (i < limit && !code[i] && in->t->kind[i] == KGENOME_TEXTUAL_STRING)
			while (i < limit && !code[i] && in->t->kind[i] == KGENOME_TEXTUAL_STRING)
				i++;
		else
			i = scan_name(in, i, limit);
		i = skip_trivia(p, code, n, i, limit);
	}
	return shape_brace(in, i, limit, out);
}

/*
 * A JAVA OR C# METHOD (JLS 8.4, C# 15.6): `[modifiers] Type name(params) [throws X, Y] {` - also a constructor, which has no type - with
 * no keyword: a name followed by its parameter list and a body, where what stands before the name is the return type (a name, ">", "]",
 * "?", "*") or the end of the member before ("{", "}", ";"). A call is never followed by "{" in either language, and `new T() {` (an
 * anonymous class) is a call. C# may write the body as "=> expression;"; java's throws list and c#'s `where` constraints and `: base(...)`
 * stand between ")" and "{". A header ending in ";" (abstract, an interface member, extern) has no body and is not a declaration.
 * The declaration begins at its first modifier, annotation or attribute: the first code byte after the member before it.
 */
static const char *const CLIKE_NOT_METHOD[] = { "if", "for", "while", "switch", "catch", "synchronized", "using", "lock", "foreach",
						 "fixed", "return", "new", "throw", "typeof", "sizeof", "nameof", "default", "checked",
						 "unchecked", "else", "do", "try", "finally", "case", "base", "this", "super", "assert", "when",
						 "await", "yield", "stackalloc", "goto", "in", "is", "as", "out", "ref", NULL };

static int shape_clike_method(const struct shape_in *in, struct shape_out *out)
{
	const uint8_t *p = in->p, *code = in->code;
	uint64_t n = in->n, limit = shape_limit(in), close, i, j, s;
	enum name_set ns = in->row->names;
	int nl;

	i = scan_name(in, in->at + (ns == NAMES_CS && p[in->at] == '@'), limit);
	if (i == in->at || word_in(p, in->at, i, CLIKE_NOT_METHOD))
		return 0;
	out->name_off = in->at;
	out->name_len = i - in->at;
	i = skip_trivia(p, code, n, i, limit);
	if (i < limit && code[i] && p[i] == '<' && ns == NAMES_CS) {
		/* a generic method's type parameters: `T F<T>(T x)` */
		while (i < limit && !(code[i] && p[i] == '>'))
			i++;
		i = skip_trivia(p, code, n, i + 1u, limit);
	}
	if (i >= limit || !code[i] || p[i] != '(' || !skip_parens(in, i, &close, &limit))
		return 0;
	j = prev_sig(in, in->at, &nl);
	if (j && is_name(ns, p[j - 1u])) {
		uint64_t w = j;

		while (w > 0 && code[w - 1u] && is_name(ns, p[w - 1u]))
			w--;
		if (word_in(p, w, j, CLIKE_NOT_METHOD))
			return 0;       /* `new T(...) {`, `return f(x)` */
	} else if (j && !strchr(">]?*{};.", p[j - 1u])) {
		return 0;
	}
	for (i = skip_trivia(p, code, n, close + 1u, limit); i < limit; i = skip_trivia(p, code, n, i + 1u, limit)) {
		if (!code[i])
			continue;
		if (p[i] == '{') {
			out->brace = i;
			break;
		}
		if (p[i] == ';' || p[i] == '}')
			return 0;
		if (p[i] == '=') {
			if (ns != NAMES_CS || i + 1u >= limit || p[i + 1u] != '>')
				return 0;
			out->expr = skip_trivia(p, code, n, i + 2u, n);
			break;
		}
		if (p[i] == '(' && !skip_parens(in, i, &close, &limit))
			return 0;
		if (p[i] == '(')
			i = close;
	}
	if (i >= limit)
		return 0;
	/* the declaration's first byte: after the member before it */
	s = in->at;
	for (;;) {
		uint64_t q = prev_sig(in, s, &nl);

		if (!q || strchr("{};", p[q - 1u]))
			break;
		s = q - 1u;
		while (s > 0 && in->t->kind[s - 1u] == KGENOME_TEXTUAL_STRING)
			s--;            /* an attribute's or an annotation's string argument */
		if (in->at - s > FN_LOOKAHEAD)
			break;
	}
	out->start = skip_trivia(p, code, n, s, in->at + 1u);
	return 1;
}

/*
 * WHICH "{" AND "}" OF A SHELL SCRIPT ARE BRACES (SP-5, 2026-11-14). In shell, `{` and `}` are
 * RESERVED WORDS, not characters: they group commands only as a word of their own in the position
 * of a command. Everywhere else they are ordinary bytes of a word - `echo }`, `echo \}`, `${x}`,
 * `{a,b}`, `find -exec rm {} \;`, `[[ $x =~ ^a{2}$ ]]` - and counting them closed a function at
 * the first such byte (checked with bash itself: `f() { echo }; }` prints "}" and f is still open).
 *   "{" opens a group when it is a word (white space or the end after it) at a command position.
 *   "}" closes one when it is a word ending at white space, ";", "&", "|", ")", "<", ">" or the end,
 *       and the code before it on its line ends a command: ";", "&", ")" or a line break.
 * A command position for "{" is the start, after a line break, ";", "&", "|", "(", ")", "{", "}"
 * or "!", or after a reserved word that is followed by a command (if then else elif do while until
 * time). The body brace of a declaration is a brace whatever this says - the shape already decided
 * it (`function name {` has the name, not a command end, before it).
 * Not read, the limit: a `}` written as the last word of a case arm (`a) }`) and a group closed by
 * a `}` glued to the word before it are rejected by bash too; a here-document's body is a string
 * span and is never consulted.
 */
static int sh_space(uint8_t c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int sh_cmd_before(const uint8_t *p, uint64_t at, int open)
{
	static const char *const words[] = { "if", "then", "else", "elif", "do", "while", "until", "time", NULL };
	uint64_t j = at, e;
	const char *const *w;

	while (j && (p[j - 1u] == ' ' || p[j - 1u] == '\t'))
		j--;
	if (!j)
		return 1;
	switch (p[j - 1u]) {
	case '\n': case '\r': case ';': case '&': case ')':
		return 1;
	case '|': case '(': case '{': case '}': case '!':
		return open;
	default:
		break;
	}
	if (!open)
		return 0;
	e = j;
	while (j && is_ident(p[j - 1u]))
		j--;
	if (j && is_name(NAMES_SH, p[j - 1u]))
		return 0;
	for (w = words; *w; w++)
		if (strlen(*w) == e - j && !memcmp(p + j, *w, e - j))
			return 1;
	return 0;
}

static int sh_brace(const uint8_t *p, uint64_t n, uint64_t at)
{
	uint8_t c = p[at];

	if (at && !sh_space(p[at - 1u]) && !strchr(";&|()", p[at - 1u]))
		return 0;       /* glued to the word before it: `${`, `\}`, `x}` */
	if (c == '{')
		return (at + 1u == n || sh_space(p[at + 1u])) && sh_cmd_before(p, at, 1);
	if (at + 1u < n && !sh_space(p[at + 1u]) && !strchr(";&|)<>", p[at + 1u]))
		return 0;
	return sh_cmd_before(p, at, 0);
}

static const char *const KW_FUNCTION[] = { "function", NULL };
static const char *const KW_PHP[]      = { "function", "fn", NULL };
static const char *const KW_SUB[]      = { "sub", NULL };
static const char *const KW_PSH[]      = { "function", "filter", "workflow", NULL };
static const char *const KW_NONE[]     = { NULL };
static const char *const MODS_PHP[]    = { "public", "protected", "private", "static", "final", "abstract", NULL };
static const char *const MODS_JS[]     = { "async", "export", "default", NULL };
static const char *const MODS_PERL[]   = { "my", "our", "state", NULL };
/* cfscript (cfml reference, "Defining functions in CFScript"): an access word and a return type may stand before `function` */
static const char *const MODS_CFML[]   = { "public", "private", "package", "remote", "static", "any", "string", "numeric", "boolean",
					   "struct", "array", "query", "void", "date", "binary", "uuid", "guid", "xml", NULL };

/*
 * The rows of the brace-delimited languages. JS's row also reads arrow functions and keyword-less methods; java (jsp) and c# (aspx) have
 * no keyword at all and are read by the method shape, gated to where their language declares members; cfml's is cfscript's `function`
 * (the <cffunction> tag is script_funcs_cfm.c's). Java's and c#'s keywords are case-sensitive, cfml's are not.
 */
static const struct lang_row LANG_ROWS[] = {
	{ KGENOME_TEXTUAL_LANG_PHP,  KW_PHP,      1u, NAMES_PHP,  MODS_PHP,  shape_php,        NULL,     NULL,               0u, GATE_ANY },
	{ KGENOME_TEXTUAL_LANG_JS,   KW_FUNCTION, 0u, NAMES_JS,   MODS_JS,   shape_js,         NULL,     shape_js_method,    1u, GATE_ANY },
	{ KGENOME_TEXTUAL_LANG_PERL, KW_SUB,      0u, NAMES_PERL, MODS_PERL, shape_perl,       NULL,     NULL,               0u, GATE_ANY },
	{ KGENOME_TEXTUAL_LANG_PSH,  KW_PSH,      1u, NAMES_PSH,  NULL,      shape_psh,        NULL,     NULL,               0u, GATE_ANY },
	{ KGENOME_TEXTUAL_LANG_SH,   KW_FUNCTION, 0u, NAMES_SH,   NULL,      shape_sh_keyword, sh_brace, shape_sh_bareword,  0u, GATE_ANY },
	{ KGENOME_TEXTUAL_LANG_JSP,  KW_NONE,     0u, NAMES_JAVA, NULL,      NULL,             NULL,     shape_clike_method, 0u, GATE_JSP_DECL },
	{ KGENOME_TEXTUAL_LANG_ASPX, KW_NONE,     0u, NAMES_CS,   NULL,      NULL,             NULL,     shape_clike_method, 0u, GATE_ASPX_SCRIPT },
	{ KGENOME_TEXTUAL_LANG_CFM,  KW_FUNCTION, 1u, NAMES_CFML, MODS_CFML, shape_cfml,       NULL,     NULL,               0u, GATE_ANY },
};

/* JScript in an asp page is javascript (the page's islands are lexed by the ecma lexer): the js row reads it. */
static const struct lang_row ROW_ASP_JSCRIPT =
	{ KGENOME_TEXTUAL_LANG_ASP,  KW_FUNCTION, 0u, NAMES_JS,   MODS_JS,   shape_js,         NULL,     shape_js_method,    1u, GATE_ANY };

/* Is the word [at, e) one of the row's modifiers. */
static int is_mod(const struct lang_row *row, const uint8_t *p, uint64_t at, uint64_t e)
{
	const char *const *m;
	uint64_t k;

	for (m = row->mods; m && *m; m++) {
		if (strlen(*m) != e - at)
			continue;
		for (k = 0; k < e - at; k++)
			if ((row->fold ? fold_byte(p[at + k]) : p[at + k]) != (uint8_t)(*m)[k])
				break;
		if (k == e - at)
			return 1;
	}
	return 0;
}

/* The declaration's first byte: the keyword at `kw`, or the first of the modifier words in front
 * of it (SP-8). Each step takes one whole word separated by white space alone; at most four steps
 * (`export default async function`, `abstract public static function` is three) and the white
 * space walked is bounded by FN_LOOKAHEAD, so a run of blanks before a keyword costs this bound and
 * no more. */
static uint64_t decl_start(const uint8_t *p, const uint8_t *code, uint64_t kw, const struct lang_row *row)
{
	uint64_t start = kw, floor = kw > FN_LOOKAHEAD ? kw - FN_LOOKAHEAD : 0;
	unsigned step;

	if (!row->mods)
		return kw;
	for (step = 0; step < 4u; step++) {
		uint64_t j = start, e, b;

		while (j > floor && code[j - 1u] && sh_space(p[j - 1u]))
			j--;
		if (j == start)
			break;          /* no white space: nothing separated to take */
		e = j;
		while (j > floor && code[j - 1u] && is_name(row->names, p[j - 1u]) && word_starts(row->names, p, code, j - 1u) == 0)
			j--;
		if (j > floor && code[j - 1u] && is_name(row->names, p[j - 1u]))
			j--;
		b = j;
		if (b == e || !word_starts(row->names, p, code, b) ||
		    !is_mod(row, p, b, e))
			break;
		start = b;
	}
	return start;
}

/* The one brace walk: the text, its code bitmap, the row, the open declarations and the depth. */
struct fn_walk {
	const uint8_t *p, *code;
	uint64_t n;
	const struct lang_row *row;
	struct fn_stack st;
	struct kgenome_fntab_list *l;
	const struct kgenome_script_text *t;
	uint64_t depth;
	uint64_t n_armed;               /* entries of `st` whose body is open */
	uint64_t claimed_until;         /* the end of the name a keyword form just took: not a keyword-less candidate again */
	uint64_t expr_until;            /* the end of an expression body just emitted: what it holds is inside it */
	uint8_t  allow;                 /* the row's gate: a declaration may stand here */
};

/*
 * ONE UNIT PER OUTERMOST FUNCTION, decided as the walk closes it (SP-10, 2026-11-14). A function
 * whose body closes while another body is still open around it is nested: not a unit of its own
 * (owner's brief, 2026-11-05 - kgenome_funcs_at's binary search, shared by every consumer of the
 * table, needs starts and ends both rising), and it is now not appended at all. It used to be
 * appended and thrown away by a sort-and-drop pass at the end - after it had counted against
 * KGENOME_FNTAB_MAX: one function holding 2^20 small closures filled the table with entries that
 * were all about to be dropped, the outer function's own close was then refused, and the
 * closures came back as 2^20 TOP-LEVEL functions (tests/lib/genome/script_cuts.c).
 * The one nesting the walk cannot see at close time is a function in another's HEADER (a default
 * value `function f(g = function () {...}) {`): the outer is not armed yet when the inner closes.
 * When the outer closes, every entry appended after its own start is inside it and is taken back
 * off the tail - so the list is in start order and disjoint as it is built, and the sort and the
 * drop pass are gone (one mechanism, not two).
 */
static int fn_emit(struct fn_walk *w, const struct fn_pending *e, uint64_t end, uint16_t flags)
{
	struct kgenome_func f;

	while (w->l->n && w->l->v[w->l->n - 1u].off >= e->kw_off)
		w->l->n--;
	memset(&f, 0, sizeof f);
	f.off = e->kw_off;
	f.len = end - e->kw_off;
	f.kind = KGENOME_FN_SCRIPT;
	f.end_source = KGENOME_FN_E_SCRIPT;
	f.flags = flags;
	f.name_len = (uint32_t)e->name_len;
	f.name_off = f.name_len ? (uint32_t)e->name_off : 0u;  /* an anonymous one names no place (where the shape stood looking for a name is not one) */
	return kgenome_fntab_list_add(w->l, &f) || w->l->status != KGENOME_NOMEM;
}

/* A candidate on top of the stack that can no longer be a declaration: its body brace is behind
 * the walk without having been armed (two headers claimed one brace and the other was armed), or -
 * at a "}" - the close of the level its keyword stood in comes before its body opens. */
static int fn_dead(const struct fn_walk *w, uint64_t i, int closing)
{
	const struct fn_pending *t = &w->st.v[w->st.n - 1u];

	return !t->depth && (t->brace_off < i || (closing && w->depth <= t->kw_depth));
}

/* One code "{" or "}" at `i`. 0 only on an allocation failure. */
static int fn_brace(struct fn_walk *w, uint64_t i)
{
	struct fn_pending *t;
	int open = w->p[i] == '{';

	while (w->st.n && fn_dead(w, i, !open))
		w->st.n--;
	t = w->st.n ? &w->st.v[w->st.n - 1u] : NULL;
	if (w->row->brace && !(open && t && !t->depth && t->brace_off == i) && !w->row->brace(w->p, w->n, i))
		return 1;       /* shell: a "{" or "}" that is a byte of a word, not a brace */
	if (open) {
		w->depth++;
		if (t && !t->depth && t->brace_off == i) {
			t->depth = w->depth;
			w->n_armed += !t->wrapper;
		}
		return 1;
	}
	if (t && t->depth && t->depth == w->depth) {
		w->st.n--;
		if (!t->wrapper) {
			w->n_armed--;
			if (!w->n_armed && !fn_emit(w, t, i + 1u, 0))
				return 0;
		}
	}
	if (w->depth)
		w->depth--;
	return 1;
}

/* A declaration of `shape` at `at` (the keyword's first byte, or a shell name's), whose keyword
 * ends at `after`: pushed when it matches. 0 only on an allocation failure. */
/*
 * A DECLARATION'S HEADER IS IN ONE PIECE OF CODE (IS-5, 2026-11-14): the shapes step over what is not code as trivia (a comment), and so
 * also over a closing tag and the markup after it - `function f() ?> html <?php {` read as f with the body "{" of the next piece. php
 * reads a closing tag as ";" (php manual, "Instruction separation"), so that is a declaration with no body (a syntax error), and a page's
 * islands then cut the "function" in two (found by the order-independence property of tests/lib/genome/script_islands.c: a page ending
 * in `function f() ` followed by a page starting with "{"). A header from `from` to its body that crosses a TAG or MARKUP byte is not a
 * declaration, in every language with tags; the bytes are bounded by the header's own lookahead.
 */
static int header_leaves_code(const struct kgenome_script_text *t, uint64_t from, uint64_t to)
{
	uint64_t i;

	for (i = from; i < to && i < t->n; i++)
		if (t->kind[i] == KGENOME_TEXTUAL_TAG || t->kind[i] == KGENOME_TEXTUAL_MARKUP)
			return 1;
	return 0;
}

/*
 * A JAVASCRIPT MODULE WRAPPER IS NOT A FUNCTION UNIT (island package, 2026-11-14). `(function () { ... })()`, `(() => { ... })()`,
 * `!function () { ... }()` at the start of a statement is the module pattern: a scope for the whole file, invoked where it is written. Read
 * as the outermost function, every function inside it is nested and the wrapper is the file's one unit: measured on the survey, 434 of
 * 581 .js files (WordPress 6.8's webpack and jQuery bundles) had ONE level-1 island of 90% of the text or more once arrows were read,
 * and the table held 2331 functions where it had held 16095 before arrows (format-library.js's InlineUI, 3784 bytes, among the lost).
 * With this rule: 35926 functions, 143 files with one island of 90% or more (a wrapper this does not see: `var x = (function () {`). So a
 * function expression that stands after "(", "!", "+", "-" or "~" at the start of a statement, with no body open around it, is a wrapper:
 * its braces are counted, it is no unit, and what it holds is read as the top level. [Inference: the pattern from the bundlers' output and
 * ECMA-262's grammar; whether it is invoked is not checked - `(function () {...})` that is only assigned later is rare and loses only its
 * own unit, its functions are kept.]
 */
static int fn_wrapper(const struct shape_in *in, uint64_t start)
{
	uint64_t j;
	int nl;

	j = prev_sig(in, start, &nl);
	if (!j || !strchr("(!+-~", in->p[j - 1u]))
		return 0;
	j = prev_sig(in, j - 1u, &nl);
	/* the start of the text, a UTF-8 byte order mark in front of it, or the end of a statement */
	return !j || (j == 3u && in->p[0] == 0xefu && in->p[1] == 0xbbu && in->p[2] == 0xbfu) || strchr(";{}", in->p[j - 1u]) != NULL;
}

static int fn_decl(struct fn_walk *w, shape_fn shape, uint64_t at, uint64_t after, int keyword)
{
	struct shape_in in;
	struct shape_out o;
	struct fn_pending e;

	in.p = w->p; in.code = w->code; in.n = w->n; in.at = at; in.after = after; in.row = w->row;
	in.t = w->t;
	memset(&o, 0, sizeof o);
	if (!shape(&in, &o) || header_leaves_code(w->t, o.start ? o.start : at, o.expr ? o.expr : o.brace))
		return 1;
	memset(&e, 0, sizeof e);
	e.kw_off = o.start ? o.start : keyword ? decl_start(w->p, w->code, at, w->row) : at;
	e.kw_depth = w->depth;
	e.name_off = o.name_off;
	e.name_len = o.name_len;
	/* Stop a keyword-less form from also firing on THIS declaration's own name a few bytes later in the same pass (`function foo() {`
	 * - "foo" alone would otherwise look like a shell bareword or a javascript method too). */
	if (keyword && o.name_off + o.name_len > w->claimed_until)
		w->claimed_until = o.name_off + o.name_len;
	if (o.expr) {
		/* AN EXPRESSION BODY has no brace to arm: its end is known now (expr_end). It is a unit when no body is open around it - it is
		 * outermost - and what it holds is part of it (expr_until). */
		uint64_t end = expr_end(&in, o.expr);

		if (end <= o.expr || w->n_armed)
			return 1;       /* nested: the outer's own close would take it back off the list (fn_emit) - not added only to save the work */
		if (end > w->expr_until)
			w->expr_until = end;
		return fn_emit(w, &e, end, 0);
	}
	if (o.brace < after || o.brace >= w->n)
		return 1;
	e.brace_off = o.brace;
	e.wrapper = (uint8_t)(w->row->arrow && !w->n_armed && fn_wrapper(&in, e.kw_off));
	return fn_pending_push(&w->st, &e);
}

void kgenome_script_funcs_build(uint32_t lang, const uint8_t *data, uint64_t data_n,
			    struct kgenome_func_set *out)
{
	const struct kgenome_script_funcs_req rq = { .lang = lang, .flags = 0u, .in = data, .n = data_n };

	kgenome_script_funcs(&rq, out);
}


static const struct lang_row *row_of(uint32_t lang);

/* The brace walk of a row (the five brace-delimited languages and the rows added beside them), over the one lex. */
static void brace_walk(const struct kgenome_script_text *t, const struct lang_row *row, struct kgenome_fntab_list *l)
{
	const uint8_t *data = t->p, *code = t->code;
	const uint64_t data_n = t->n;
	struct fn_walk w;
	uint64_t i, n_open = 0;

	memset(&w, 0, sizeof w);
	w.p = data;
	w.code = code;
	w.n = data_n;
	w.row = row;
	w.l = l;
	w.t = t;
	/* Every byte is read for the brace count (a "}" in the last bytes of the file closes a
	 * function as surely as any other); a keyword is looked for at every code byte, its own length
	 * checks inside is_keyword_at. */
	w.allow = row->gate == GATE_ANY;
	for (i = 0; i < data_n; i++) {
		const char *kw;

		if (row->gate && t->kind[i] == KGENOME_TEXTUAL_TAG && data[i] == '<' && i + 2u < data_n)
			w.allow = row->gate == GATE_JSP_DECL ? (data[i + 1u] == '%' && data[i + 2u] == '!')
							      : (i + 7u <= data_n && kgenome_script_lower(data[i + 1u]) == 's' &&
								 kgenome_script_lower(data[i + 2u]) == 'c');
		if (code[i] && (data[i] == '{' || data[i] == '}') && !fn_brace(&w, i)) {
			l->status = KGENOME_NOMEM;
			goto done_scan;
		}
		if (!w.allow || !code[i] || i < w.expr_until)
			continue;
		kw = keyword_at(data, code, data_n, i, row);
		if (kw) {
			if (!fn_decl(&w, row->shape, i, i + strlen(kw), 1)) {
				l->status = KGENOME_NOMEM;
				goto done_scan;
			}
			continue;
		}
		/* THE KEYWORD-LESS FORMS: tried only when no keyword matched at this byte, only at a name's own first byte (the byte before it is
		 * not a name byte: `my-func()` is one shell name, not `func()` inside it, SP-4) or - javascript - at a "(" that may open an arrow's
		 * parameters, and not inside a name a keyword form just claimed. */
		if (i < w.claimed_until)
			continue;
		if (row->bare && (is_name(row->names, data[i]) || (row->arrow && data[i] == '#')) &&
		    word_starts(row->names, data, code, i) && !fn_decl(&w, row->bare, i, i, 0)) {
			l->status = KGENOME_NOMEM;
			goto done_scan;
		}
		if (row->arrow && (data[i] == '(' || (is_name(row->names, data[i]) && word_starts(row->names, data, code, i))) &&
		    !fn_decl(&w, shape_js_arrow, i, i, 0)) {
			l->status = KGENOME_NOMEM;
			goto done_scan;
		}
	}
done_scan:
	/* Whatever never closed - truncated input, or genuinely malformed - is still evidence: run
	 * to the end of the buffer and said open, not dropped (rule 4). Said on the object
	 * (P_ENDS) from here: the dedup below may keep or drop any one of these entries (folded
	 * into an enclosing body) and a reader must not have to search the surviving table for a
	 * flag that might not be on it any more. A candidate whose body never opened (not armed)
	 * has no body: it was not a declaration, and is not one here either. */
	for (i = 0; i < w.st.n && l->status != KGENOME_NOMEM; i++) {
		if (!w.st.v[i].depth || w.st.v[i].wrapper)
			continue;
		/* the first open body holds every later one: it is the unit, they are nested */
		if (!n_open++)
			(void)fn_emit(&w, &w.st.v[i], data_n, KGENOME_FN_F_END_OPEN);
	}
	free(w.st.v);
	if (n_open)
		l->partial |= KGENOME_FNTAB_P_ENDS;
}

/*
 * WHICH STRATEGY READS A LANGUAGE (owner, 2026-11-14: "đảm bảo chia dispatch mỗi ngôn ngữ theo đúng tiêu chuẩn ngôn ngữ chứ không làm
 * gộp gây bug"): the brace walk with the language's row (LANG_ROWS), or the language's own strategy (script_private.h), one per
 * language and in its own file. A language with neither answers PARTIAL with KGENOME_FNTAB_P_NO_TABLE - "this text has functions
 * this build does not read" - and never an empty COMPLETE, which said "this text has no functions" (the scriptpart audit's
 * follow-up; P_NO_TABLE is the bit a PE of a machine the walk does not decode answers, the same fact for a script: the table
 * this object would have is not built).
 */
static const struct {
	uint32_t lang;
	kgenome_script_strategy fn;
} STRATEGIES[] = {
	{ KGENOME_TEXTUAL_LANG_PY,   kgenome_script_funcs_py },
	{ KGENOME_TEXTUAL_LANG_RUBY, kgenome_script_funcs_ruby },
	{ KGENOME_TEXTUAL_LANG_LUA,  kgenome_script_funcs_lua },
	{ KGENOME_TEXTUAL_LANG_TCL,  kgenome_script_funcs_tcl },
	{ KGENOME_TEXTUAL_LANG_BAT,  kgenome_script_funcs_bat },
	{ KGENOME_TEXTUAL_LANG_VBS,  kgenome_script_funcs_vb },
	{ KGENOME_TEXTUAL_LANG_CFM,  kgenome_script_funcs_cfm },
};

void kgenome_script_cfscript_funcs(const struct kgenome_script_text *t, struct kgenome_fntab_list *l)
{
	brace_walk(t, row_of(KGENOME_TEXTUAL_LANG_CFM), l);
}

static const struct lang_row *row_of(uint32_t lang)
{
	uint32_t ri;

	for (ri = 0; ri < sizeof LANG_ROWS / sizeof LANG_ROWS[0]; ri++)
		if (LANG_ROWS[ri].lang == lang)
			return &LANG_ROWS[ri];
	return NULL;
}

void kgenome_script_funcs_of_text(const struct kgenome_script_text *t, struct kgenome_func_set *out)
{
	const struct lang_row *row = row_of(t->lang);
	struct kgenome_fntab_list l;
	uint32_t si;
	int done = 0;

	memset(out, 0, sizeof *out);
	memset(&l, 0, sizeof l);
	if (t->lang == KGENOME_TEXTUAL_LANG_ASP || t->lang == KGENOME_TEXTUAL_LANG_ASPX) {
		/* A PAGE'S ISLANDS ARE IN THE LANGUAGE ITS DIRECTIVE NAMES (the lexer's own choice, kgenome_textual_page_syntax): vbscript and
		 * vb.net are read by the vb strategy, jscript by the javascript row, c# by its own. A page that mixes them (a c# page with a
		 * <script runat="server" language="vb">) is read in the page's language: the named limit, 0 such pages in the survey. */
		if (kgenome_textual_page_syntax(t->lang, t->p, (uint32_t)t->n, (uint32_t)t->n) == KGENOME_TEXTUAL_SYN_VB) {
			if (!kgenome_script_funcs_vb(t, &l))
				l.status = KGENOME_NOMEM;
		} else {
			brace_walk(t, t->lang == KGENOME_TEXTUAL_LANG_ASP ? &ROW_ASP_JSCRIPT : row, &l);
		}
		done = 1;
	} else if (row && t->lang != KGENOME_TEXTUAL_LANG_CFM) {
		brace_walk(t, row, &l);
		done = 1;
	}
	for (si = 0; !done && si < sizeof STRATEGIES / sizeof STRATEGIES[0]; si++)
		if (STRATEGIES[si].lang == t->lang) {
			if (!STRATEGIES[si].fn(t, &l))
				l.status = KGENOME_NOMEM;
			done = 1;
		}
	if (!done)
		l.partial |= KGENOME_FNTAB_P_NO_TABLE;
	/*
	 * NO kgenome_fntab_merge HERE: that routine answers "is this start backed only by check-only
	 * sources" as `!(all_source_bits & ~check_only)`, which is vacuously TRUE when a start's
	 * `source` is 0 - true of EVERY entry here (struct kgenome_func.source has no spare
	 * KGENOME_FN_S_* bit for "a script's own declaration shape", see funcs.h) - so calling it
	 * silently dropped the whole table (caught by tests/unit/mutation_units.c's
	 * script_functions(), RED on this file's original PHP-only version). Nothing is left for it
	 * to do anyway: fn_emit keeps the list in start order and disjoint as it is built.
	 */
	kgenome_script_eval_flag(t, &l);
	out->v = l.v;
	out->n = l.n;
	out->status = l.status;
	out->partial = l.partial;
	out->ccase = (uint8_t)KGENOME_FNTAB_C_SCRIPT;
	out->state = (out->partial & KGENOME_FNTAB_P_CAP) ? KGENOME_FNTAB_OVER_BUDGET :
		     out->partial ? KGENOME_FNTAB_PARTIAL : KGENOME_FNTAB_COMPLETE;
}

void kgenome_script_funcs(const struct kgenome_script_funcs_req *req, struct kgenome_func_set *out)
{
	struct kgenome_script_text t;

	memset(out, 0, sizeof *out);
	if (!req->in || !req->n || req->n > 0xffffffffu)
		return;
	if (!kgenome_script_text_make(req->lang, req->flags, req->in, req->n, &t)) {
		/* a language with no lexer row has no table at all (C_NONE, as kgenome_funcs_build answers a format it has no
		 * case for); one whose lex could not be afforded is short for want of memory */
		if (kgenome_textual_lang_known(req->lang))
			out->status = KGENOME_NOMEM;
		return;
	}
	kgenome_script_funcs_of_text(&t, out);
	kgenome_script_text_free(&t);
}
