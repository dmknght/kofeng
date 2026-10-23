#define _GNU_SOURCE
/*
 * diag_text_oracle - the constants the TEXT route's evaluator reports, against the real interpreters, over generated programs.
 *
 * An independent oracle (CLAUDE.md, audit loop): a program is generated, one assignment a line, from a grammar of what a script builds a value with - literals in every
 * spelling the language has (escapes, raw, triple quoted, $'..', q() and qq{}), the operators and methods the rows of the language have, the ones it does not (so that the
 * evaluator's refusal of what it does not model is asked too), and variables that hold earlier results. The same lines are run by python 3, perl and bash, one at a time, and
 * each answer is printed as hex. The evaluator is asked the same text (kgenome_diag_scan_text, on_const, with the engine's string functions) and, for every assignment it
 * says is a constant, the bytes must be the interpreter's. What the evaluator leaves alone is not a difference (it says nothing); what it says and the interpreter does not
 * (an error, another value) is a defect and is printed with the line.
 *
 * Interpreters this machine has: python3, perl, bash (and gawk, which has no row here: the route reads no awk). The others the route reads - php, js, ruby, lua, tcl, powershell,
 * vbscript, batch, cfml, jsp/asp pages - are not on this machine, and their cases are in script_methods.c against the language's reference text, [Unverified] against a real
 * one. A run without an interpreter says so and skips its programs.
 *
 * KNOWN: a difference listed in KNOWN_OPEN is reported with its line and is not a failure; it is a defect found by this test and not yet fixed. The test fails when a difference
 * is NOT in the list, and when a listed one stopped happening (the entry is then deleted).
 *
 * usage: diag_text_oracle [-v] [-d prefix] [seed]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#include "../lib/interp_oracle.h"
#include "normalizer_consts.h"

#define PY KGENOME_TEXTUAL_LANG_PY
#define PL KGENOME_TEXTUAL_LANG_PERL
#define SH KGENOME_TEXTUAL_LANG_SH

static int verbose;
static const char *dump_prefix;      /* -d <prefix>: the first program of each language is written to <prefix>_<language>.txt */
static unsigned fails;

/* ---- a deterministic generator, and a pool the generated text lives in ------------------- */

static uint64_t rstate = 88172645463325252ull;

static uint32_t rnd(uint32_t n)
{
	rstate ^= rstate << 13;
	rstate ^= rstate >> 7;
	rstate ^= rstate << 17;
	return (uint32_t)((rstate >> 11) % n);
}

static char pool[1u << 21];
static size_t pw;

static char *fmt(const char *f, ...) __attribute__((format(printf, 1, 2)));
static char *fmt(const char *f, ...)
{
	va_list ap;
	int n;
	char *p = pool + pw;

	va_start(ap, f);
	n = vsnprintf(p, sizeof pool - pw, f, ap);
	va_end(ap);
	if (n < 0 || pw + (size_t)n + 1u >= sizeof pool) {
		printf("  FAIL the pool is full\n");
		exit(2);
	}
	pw += (size_t)n + 1u;
	return p;
}

#define PICK(a) ((a)[rnd(sizeof (a) / sizeof (a)[0])])


/* characters a generated literal is made of: plain ones the languages agree on */
static const char *const plain[] = { "a", "b", "c", "A", "B", "Z", "x", "y", "0", "1", "9", " ", "_", "-", ".", ",", "/", ":", "=", ";", "!", "~", "ab", "AB", "abc", "Hello", "a b", "  " };

/* a search text or a replacement: sometimes empty (python's replace of "" inserts everywhere, which the evaluator must leave alone) */
static const char *pat_or_empty(void)
{
	return rnd(9) == 0 ? "" : plain[rnd(sizeof plain / sizeof plain[0])];
}

/* ---- python ------------------------------------------------------------------------------ */

static char *py_lit(void)
{
	static const char *const esc_any[] = { "\\n", "\\t", "\\\\", "\\x41", "\\x7a", "\\x00", "\\x7f", "\\101", "\\0", "\\u0041", "\\x5c", "\\a", "\\r", "\\x20", "\\xe9", "\\u00e9", "\\u20ac" };
	int style = (int)rnd(7), k, n = (int)rnd(5);
	char body[256] = "";
	char q1 = style == 1 || style == 3 ? '"' : '\'';
	int raw = style == 2 || style == 6;

	for (k = 0; k < n; k++) {
		const char *a;

		if (!raw && rnd(3) == 0)
			a = PICK(esc_any);
		else if (!raw && rnd(8) == 0)
			a = q1 == '"' ? "\\\"" : "\\'";
		else if (raw && rnd(6) == 0)
			a = "\\n";                      /* a raw string keeps the backslash and the n */
		else
			a = PICK(plain);
		strcat(body, a);
	}
	if (raw && n && body[strlen(body) - 1u] == '\\')
		strcat(body, "x");
	switch (style) {
	case 0: case 1: return fmt("%c%s%c", q1, body, q1);
	case 2: return fmt("r'%s'", body);
	case 3: return fmt("\"\"\"%s\"\"\"", body);
	case 4: return fmt("'''%s'''", body);
	case 5: return fmt("b'%s'.decode()", body);   /* bytes: no row, left alone */
	default: return fmt("R\"%s\"", body);
	}
}

static char *py_expr(int depth, int nv)
{
	char *a, *b, *c;
	uint32_t op = depth <= 0 ? rnd(3) : rnd(31);

	/* the methods and operators the language has and the table has no row for are asked too (the evaluator must leave them), but not in every line: a line of them says nothing about the rest */
	if (op == 20 || op == 21 || op == 22 || op == 23 || op == 24 || op == 26 || op == 27 || op == 28 || op == 29 || op > 29) {
		uint32_t keep = rnd(5);

		if (keep)
			op = 3 + rnd(17);
	}

	switch (op) {
	case 0: case 1: return py_lit();
	case 2: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; return nv ? fmt("v%u", j) : py_lit(); }
	case 3: case 4: case 5: a = py_expr(depth - 1, nv); b = py_expr(depth - 1, nv); return fmt("%s + %s", a, b);
	case 6: case 7: a = py_expr(depth - 1, nv); b = fmt("'%s'", pat_or_empty()); c = fmt("'%s'", PICK(plain)); return fmt("%s.replace(%s, %s)", a, b, c);
	case 8: a = py_expr(depth - 1, nv); return fmt("%s.upper()", a);
	case 9: a = py_expr(depth - 1, nv); return fmt("%s.lower()", a);
	case 10: a = py_expr(depth - 1, nv); return fmt("%s.strip()", a);
	case 11: a = py_expr(depth - 1, nv); return fmt("%s.lstrip()", a);
	case 12: a = py_expr(depth - 1, nv); return fmt("%s.rstrip()", a);
	case 13: a = py_expr(depth - 1, nv); return fmt("(%s)[::-1]", a);
	case 14: { int k = (int)rnd(7) - 2; a = py_expr(depth - 1, nv); return fmt("(%s) * %d", a, k); }
	case 15: { char *j = fmt("'%s'", PICK(plain)), *sp = fmt("'%s'", pat_or_empty()); a = py_expr(depth - 1, nv); return fmt("%s.join((%s).split(%s))", j, a, sp); }
	case 16: { char *j = fmt("'%s'", PICK(plain)); a = py_expr(depth - 1, nv); b = py_expr(depth - 1, nv); c = py_expr(depth - 1, nv); return fmt("%s.join([%s, %s, %s])", j, a, b, c); }
	case 17: { uint32_t big = rnd(4), n1 = rnd(0x110000u), n2 = rnd(256u); return fmt("chr(%u)", big == 0 ? n1 : n2); }
	case 18: a = py_lit(); b = py_lit(); return fmt("%s %s", a, b);                    /* two literals side by side are one */
	case 19: a = py_expr(depth - 1, nv); return fmt("(%s)", a);
	case 20: a = py_expr(depth - 1, nv); return fmt("%s.title()", a);       /* no row: the evaluator must leave these */
	case 21: { uint32_t k = rnd(3); a = py_expr(depth - 1, nv); return fmt("(%s)[%u:]", a, k); }
	case 22: a = py_expr(depth - 1, nv); return fmt("(%s)[::2]", a);
	case 23: a = py_expr(depth - 1, nv); return fmt("%s.capitalize()", a);
	case 24: { uint32_t k = rnd(9); a = py_expr(depth - 1, nv); return fmt("%s.center(%u)", a, k); }
	case 25: { int k = (int)rnd(4); a = py_expr(depth - 1, nv); b = py_expr(depth - 1, nv); return fmt("%s + %s * %d", a, b, k); }        /* precedence: * binds tighter than + */
	case 26: { char *p1 = fmt("'%s'", PICK(plain)), *p2 = fmt("'%s'", PICK(plain)); uint32_t k = rnd(3); a = py_expr(depth - 1, nv); return fmt("%s.replace(%s, %s, %u)", a, p1, p2, k); }   /* a count: not read */
	case 27: { char *p1 = fmt("'%s'", PICK(plain)); a = py_expr(depth - 1, nv); return fmt("%s.strip(%s)", a, p1); }     /* a set of characters: not read */
	case 28: a = py_expr(depth - 1, nv); return fmt("%s.swapcase()", a);
	case 29: a = py_expr(depth - 1, nv); b = py_expr(depth - 1, nv); return fmt("%s * %s", a, b);       /* str * str: an error */
	default: { uint32_t k = rnd(9); a = py_expr(depth - 1, nv); return fmt("%s.zfill(%u)", a, k); }
	}
}

/* ---- perl -------------------------------------------------------------------------------- */

static char *pl_lit(void)
{
	static const char *const esc_dq[] = { "\\n", "\\t", "\\\\", "\\x41", "\\x{41}", "\\x00", "\\101", "\\0", "\\e", "\\a", "\\\"", "\\$", "\\@", "\\x7f", "\\x{e9}", "\\xe9", "\\cA", "\\r", "\\033" };
	static const char *const esc_sq[] = { "\\\\", "\\'" };
	int style = (int)rnd(6), k, n = (int)rnd(5);
	char body[256] = "";

	for (k = 0; k < n; k++) {
		const char *a;

		if (style == 0 || style == 5)
			a = rnd(5) == 0 ? PICK(esc_sq) : PICK(plain);
		else if (style == 1 || style == 2 || style == 3)
			a = rnd(3) == 0 ? PICK(esc_dq) : PICK(plain);
		else
			a = PICK(plain);
		if (style == 4 && (strchr(a, '(') || strchr(a, ')')))
			a = "a";
		strcat(body, a);
	}
	switch (style) {
	case 0: return fmt("'%s'", body);
	case 1: return fmt("\"%s\"", body);
	case 2: return fmt("qq{%s}", body);
	case 3: return fmt("qq(%s)", body);
	case 4: return fmt("q(%s)", body);
	default: return fmt("q[%s]", body);
	}
}

static char *pl_expr(int depth, int nv)
{
	char *a, *b, *c;
	uint32_t op = depth <= 0 ? rnd(3) : rnd(25);

	if (op == 15 || op == 16 || op == 20) {
		uint32_t keep = rnd(4);

		if (keep)
			op = 3 + rnd(12);
	}

	switch (op) {
	case 0: case 1: return pl_lit();
	case 2: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; return nv ? fmt("$v%u", j) : pl_lit(); }
	case 3: case 4: case 5: a = pl_expr(depth - 1, nv); b = pl_expr(depth - 1, nv); return fmt("%s . %s", a, b);
	case 6: a = pl_expr(depth - 1, nv); return fmt("lc(%s)", a);
	case 7: a = pl_expr(depth - 1, nv); return fmt("uc(%s)", a);
	case 8: a = pl_expr(depth - 1, nv); return fmt("ucfirst(%s)", a);
	case 9: a = pl_expr(depth - 1, nv); return fmt("lcfirst(%s)", a);
	case 10: { char *j = fmt("'%s'", PICK(plain)); a = pl_expr(depth - 1, nv); b = pl_expr(depth - 1, nv); return fmt("join(%s, %s, %s)", j, a, b); }
	case 11: { char *j = pl_lit(); a = pl_expr(depth - 1, nv); b = pl_expr(depth - 1, nv); c = pl_expr(depth - 1, nv); return fmt("join(%s, %s, %s, %s)", j, a, b, c); }
	case 12: { int k = (int)rnd(6) - 1; a = pl_expr(depth - 1, nv); return fmt("(%s) x %d", a, k); }
	case 13: return fmt("chr(%u)", rnd(256u));
	case 14: { const char *p1 = PICK(plain); uint32_t j = nv ? rnd((uint32_t)nv) : 0u; const char *p2 = PICK(plain); return fmt("\"%s${v%u}%s\"", p1, j, p2); }     /* interpolation (a variable that may not exist) */
	case 15: a = pl_expr(depth - 1, nv); return fmt("scalar reverse(%s)", a);                 /* no row: left alone */
	case 16: { uint32_t o = rnd(3), l = rnd(4); a = pl_expr(depth - 1, nv); return fmt("substr(%s, %u, %u)", a, o, l); }
	case 17: a = pl_expr(depth - 1, nv); return fmt("lc %s", a);                              /* a named unary operator without brackets */
	case 18: { int k = (int)rnd(4); a = pl_expr(depth - 1, nv); b = pl_expr(depth - 1, nv); return fmt("%s . %s x %d", a, b, k); }        /* x binds tighter than . */
	case 19: a = pl_expr(depth - 1, nv); return fmt("ucfirst(lc(%s))", a);
	case 20: a = pl_expr(depth - 1, nv); return fmt("sprintf('%%s-', %s)", a);                /* no row */
	case 21: a = pl_expr(depth - 1, nv); return fmt("(%s)", a);
	case 22: a = pl_expr(depth - 1, nv); b = pl_expr(depth - 1, nv); return fmt("%s x %s", a, b);    /* the count is a string: the number it reads as */
	case 23: a = pl_expr(depth - 1, nv); return fmt("uc lc %s", a);
	default: a = pl_expr(depth - 1, nv); b = pl_expr(depth - 1, nv); return fmt("%s . '' . %s", a, b);
	}
}

/* ---- bash -------------------------------------------------------------------------------- */

static char *sh_lit(void)
{
	static const char *const esc_dq[] = { "\\$", "\\\\", "\\\"", "\\`", "\\n", "\\a", "\\x41" };      /* inside "..", only the first four are escapes: the rest stay as written */
	static const char *const esc_ansi[] = { "\\n", "\\t", "\\\\", "\\x41", "\\101", "\\e", "\\'", "\\u00e9", "\\x7f", "\\0", "\\a", "\\cA", "\\\"", "\\x4", "\\E" };
	int style = (int)rnd(5), k, n = (int)rnd(5);
	char body[256] = "";

	for (k = 0; k < n; k++) {
		const char *a;

		if (style == 1 && rnd(3) == 0)
			a = PICK(esc_dq);
		else if (style == 2 && rnd(3) == 0)
			a = PICK(esc_ansi);
		else
			a = PICK(plain);
		if (style == 0 && strchr(a, '\''))
			a = "a";
		strcat(body, a);
	}
	switch (style) {
	case 0: return fmt("'%s'", body);
	case 1: return fmt("\"%s\"", body);
	case 2: return fmt("$'%s'", body);
	case 3: {   /* unquoted: only characters with no meaning to the shell */
		char w[64] = "";

		for (k = 0; k < n; k++)
		{
			static const char *const safe[] = { "B", "9", "_", "-", ".", ",", "/", ":", "=", "x" };
			uint32_t pick = rnd(2);
			const char *c = safe[rnd(sizeof safe / sizeof safe[0])];

			strcat(w, pick ? "a" : c);
		}
		return fmt("%s", w[0] ? w : "z");
	}
	default: return fmt("\"%s\"", body);
	}
}

static const char *sh_pat(void)
{
	static const char *const pats[] = { "a", "b", "ab", "A", "x", " ", "-", ".", "/", "0", "Hello", "*", "?", "[a]", "a*", "\\*", "&", "%", "#" };
	return PICK(pats);
}

static char *sh_word(int depth, int nv)
{
	char *a, *b;
	uint32_t op = depth <= 0 ? rnd(3) : rnd(22);

	switch (op) {
	case 0: case 1: return sh_lit();
	case 2: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; return nv ? fmt("$v%u", j) : sh_lit(); }
	case 3: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; const char *p = sh_pat(), *r = PICK(plain); return fmt("${v%u//%s/%s}", j, p, r); }
	case 4: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; const char *p = sh_pat(), *r = PICK(plain); return fmt("${v%u/%s/%s}", j, p, r); }
	case 5: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; const char *p = sh_pat(); return fmt("${v%u#%s}", j, p); }
	case 6: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; const char *p = sh_pat(); return fmt("${v%u##%s}", j, p); }
	case 7: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; const char *p = sh_pat(); return fmt("${v%u%%%s}", j, p); }
	case 8: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; const char *p = sh_pat(); return fmt("${v%u%%%%%s}", j, p); }
	case 9: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u, o = rnd(4), l = rnd(4); return fmt("${v%u:%u:%u}", j, o, l); }
	case 10: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; return fmt("${v%u^^}", j); }
	case 11: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; return fmt("${v%u,,}", j); }
	case 12: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; return fmt("${v%u^}", j); }
	case 13: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; return fmt("${v%u,}", j); }
	case 14: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; return fmt("${#v%u}", j); }
	case 15: a = sh_word(depth - 1, nv); b = sh_word(depth - 1, nv); return fmt("%s%s", a, b);
	case 16: a = sh_word(depth - 1, nv); return fmt("$(echo %s)", a);
	case 17: a = sh_word(depth - 1, nv); return fmt("$(printf %%s %s)", a);
	case 18: a = sh_word(depth - 1, nv); return fmt("$(echo %s | rev)", a);
	case 19: a = sh_word(depth - 1, nv); return fmt("$(echo %s | tr a-z A-Z)", a);
	case 20: a = sh_word(depth - 1, nv); b = sh_word(depth - 1, nv); return fmt("$(printf '%%s-%%s' %s %s)", a, b);
	default: { uint32_t j = nv ? rnd((uint32_t)nv) : 0u; a = sh_word(depth - 1, nv); return fmt("${v%u:-%s}", j, a); }
	}
}

/* ---- the interpreters' programs: every line is run alone, and prints `index TAB hex` or `index TAB ERR` ------------ */

#define PROG_LINES 40u
#define LINE 4096u

/* base64 of n bytes (interp_oracle.h's b64 stops at a NUL, and the text the evaluator writes may hold one in a literal) */
static char *b64n(const char *p, size_t n)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, w = 0;
	char *o = malloc(n * 4u / 3u + 8u);

	for (i = 0; i < n; i += 3u) {
		uint32_t v = (uint32_t)(uint8_t)p[i] << 16 | (i + 1u < n ? (uint32_t)(uint8_t)p[i + 1u] << 8 : 0u) | (i + 2u < n ? (uint8_t)p[i + 2u] : 0u);

		o[w++] = t[v >> 18 & 63u];
		o[w++] = t[v >> 12 & 63u];
		o[w++] = i + 1u < n ? t[v >> 6 & 63u] : '=';
		o[w++] = i + 2u < n ? t[v & 63u] : '=';
	}
	o[w] = 0;
	return o;
}

static char *line_b64s(char (*lines)[LINE], const uint32_t *llen, unsigned n)
{
	unsigned i;
	char *o = malloc((size_t)n * (LINE * 2u) + 16u), *w;

	w = o;
	*w = 0;
	for (i = 0; i < n; i++) {
		char *e = b64n(lines[i], llen[i]);

		w += sprintf(w, "%s'%s'", i ? ", " : "", e);
		free(e);
	}
	return o;
}

static char *run_lines(int which, char (*lines)[LINE], const uint32_t *llen, unsigned n)
{
	char *list = line_b64s(lines, llen, n), *prog = malloc(strlen(list) + 1024u), *out;

	if (which == 1)
		sprintf(prog, "import base64,sys\ng={}\nfor i,b in enumerate([%s]):\n    l=base64.b64decode(b).decode('utf-8')\n    try:\n        exec(l,g)\n        v=g['v%%d'%%i]\n"
			      "        if not isinstance(v,str): raise TypeError\n        sys.stdout.write('%%d\\t%%s\\n'%%(i,v.encode('utf-8').hex()))\n    except BaseException:\n        sys.stdout.write('%%d\\tERR\\n'%%i)\n", list);
	else if (which == 0)
		sprintf(prog, "no warnings; my @l=(%s); for my $i (0..$#l){ my $l=decode_base64($l[$i]); no strict; ${\"v$i\"}=undef; my $r=eval $l; if($@){ print \"$i\\tERR\\n\"; next } my $v=${\"v$i\"};"
			      " if(!defined $v || $v =~ /[^\\x00-\\xff]/){ print \"$i\\tERR\\n\"; next } print \"$i\\t\".unpack('H*',$v).\"\\n\" }\n", list);
	else
		sprintf(prog, "l=(%s)\ni=0\nfor b in \"${l[@]}\"; do\n  s=$(printf %%s \"$b\" | base64 -d)\n  unset v$i\n  eval \"$s\" 2>/dev/null\n  n=v$i\n"
			      "  if [ -z \"${!n+set}\" ]; then printf '%%d\\tERR\\n' $i; else printf '%%d\\t%%s\\n' $i \"$(printf %%s \"${!n}\" | od -An -v -tx1 | tr -d ' \\n')\"; fi\n  i=$((i+1))\ndone\n", list);
	out = run_script(which, prog);
	free(list);
	free(prog);
	return out;
}

/* ---- the lists of known differences (defects found by this test and not yet fixed) ---------------- */

static const char *const KNOWN_OPEN[] = {
	NULL
};

static int known(const char *what)
{
	unsigned i;

	for (i = 0; KNOWN_OPEN[i]; i++)
		if (!strcmp(KNOWN_OPEN[i], what))
			return 1;
	return 0;
}

/* ---- the cases written by hand: a contract of the language the random grammar reaches only by luck ------------------------------- */

/* python: a method binds to the whole of the literals written side by side (they are one literal when the program is read) */
static const char *const py_fixed[] = {
	"'Banana'", "'a' 'b'.upper()", "'Ab' ''.replace('A', 'z')", "'a' 'b' 'c'[::-1]", "'a' 'b'.replace('a', 'x') + 'a'", "('a' 'b').replace('a', 'x')", "v0 'x'.upper()", "'x' + 'a' 'b'.upper()",
	"'a' 'b'.upper() 'c'", "'a'.upper() 'b'", NULL
};

/* perl: the string operators and what they bind to */
static const char *const pl_fixed[] = {
	"'Banana'", "lc 'AB' . 'CD'", "uc lc 'Ab' . 'cD'", "'a' . 'b' x 3", "('a' . 'b') x 3", "lc('AB') . 'CD'", "ucfirst lc 'ABC'", "join('-', 'a', 'b') x 2", "'a' x 2 . 'b' x 2", "\"a\\x41b\"",
	"'ab' x 2.7", "'ab' x '3'", "'ab' x -1", "lc \"\\x{c9}\"", NULL
};

/* bash: the tilde is expanded where the shell says (a word's start, after = and : in an assignment, in the operand of a parameter expansion): a value that depends on $HOME is
 * not a constant, and a quoted or escaped one is a plain character */
static const char *const sh_fixed[] = {
	"\"Banana\"", "~", "a:~", "~/x", "${v0//a/~}", "${v0/n/~}", "${v0:-~}", "${v0#~}", "${v0%~}", "$(echo ~)", "\"~\"", "'~'", "\\~", "x~", "~root", "a~", "${v0//a/\"~\"}", "${v0//a/\\~}", "${v0:+~}",
	"${v0//a/x~}", "${v0//a/~x}", "${xx:-~}", "a=~", "${v0//a/b:~}",
	"${v2}", "${v2,}", "${v2^^}", "a:b:~/x", "\"a:\"~", "a\\:~", "x=a:~", "\"~x\"", "${@P#~}", "${@P%~}", "${@P##~}", "${@P%%~}", "${@P//~/y}", "${@P/#~/y}", "${@P/~/y}", "\"~/x\"", "${@P#~/}", "${@P/#~\\//y}", NULL
};

struct stats {
	unsigned lines, ranges, evaluated, agree, unread, wrong, interp_err, known_seen, partial, subst_checked, subst_same, subst_diff, subst_repaired, lines_shown;
};

static void hexs(const uint8_t *p, size_t n, char *o)
{
	size_t k;

	for (k = 0; k < n; k++)
		sprintf(o + 2u * k, "%02x", p[k]);
	o[2u * n] = 0;
}

/* parse the interpreter's `index TAB hex|ERR` lines into ihex[] (strdup'ed) */
static void read_answers(char *out, char **ihex, unsigned n)
{
	char *at = out, *row;

	while ((row = strsep(&at, "\n")) != NULL && *row) {
		char *tab = strchr(row, '\t');
		unsigned idx = (unsigned)strtoul(row, NULL, 10);

		if (tab && idx < n)
			ihex[idx] = strdup(tab + 1);
	}
}

/*
 * run `n` generated lines through the interpreter and the evaluator, and compare, twice:
 *   WHOLE   an assignment whose whole right side the evaluator says is a constant: those bytes are what the interpreter printed;
 *   SUBST   the text with every constant the evaluator found written where it was computed (kgenome_textual_subst: the value as a literal of the language, what the normalised view
 *           holds) is the same program: each of its lines, run by the interpreter, prints what the original line did. This covers the parts of a line the evaluator reads (a
 *           method's receiver, an argument, the operand of an operator) and the writer of the literal, whose spelling the language must read back to the same bytes.
 */
static void compare(uint32_t lang, int which, const char *name, const char *lfmt, char (*lines)[LINE], unsigned n, struct stats *st)
{
	char *text = malloc((size_t)n * (LINE + 8u) + 1u), *w = text, *out, *text2 = NULL;
	unsigned i, line_of[PROG_LINES + 1u];
	struct cset cs;
	unsigned k;
	char *ihex[PROG_LINES], *ihex2[PROG_LINES];
	static char lines2[PROG_LINES][LINE];
	uint32_t w2, len1[PROG_LINES], len2[PROG_LINES];

	memset(ihex, 0, sizeof ihex);
	memset(ihex2, 0, sizeof ihex2);
	for (i = 0; i < n; i++) {
		line_of[i] = (unsigned)(w - text);
		len1[i] = (uint32_t)strlen(lines[i]);
		w += sprintf(w, "%s\n", lines[i]);
	}
	out = run_lines(which, lines, len1, n);
	if (!out) {
		free(text);
		return;
	}
	read_answers(out, ihex, n);
	free(out);
	consts_of(lang, (const uint8_t *)text, (size_t)(w - text), &cs);
	st->lines += n;
	for (k = 0; k < cs.n; k++) {
		unsigned stmt = 0;
		char gx[4096] = "";
		const char *iv;
		const char *ln, *rhs;
		size_t rl, ro;

		while (stmt + 1u < n && line_of[stmt + 1u] <= cs.c[k].off)
			stmt++;
		if (cs.c[k].n > 1500u)
			continue;
		ln = lines[stmt];
		rhs = strchr(ln, '=');
		if (!rhs)
			continue;
		rhs++;
		while (*rhs == ' ')
			rhs++;
		rl = strlen(rhs);
		if (rl && rhs[rl - 1u] == ';' && ln[0] == '$')
			rl--;
		ro = line_of[stmt] + (size_t)(rhs - ln);
		st->ranges++;
		if (cs.c[k].off != ro || cs.c[k].len != rl) {
			st->partial++;
			continue;
		}
		hexs(cs.c[k].v, cs.c[k].n, gx);
		iv = ihex[stmt] ? ihex[stmt] : "(no answer)";
		st->evaluated++;
		if (!strcmp(gx, iv)) {
			st->agree++;
		} else {
			char key[LINE + 80];

			snprintf(key, sizeof key, "%.64s: %s", name, lines[stmt]);
			if (!strcmp(iv, "ERR"))
				st->interp_err++;
			else
				st->wrong++;
			if (known(key)) {
				st->known_seen++;
			} else {
				fails++;
				if (st->wrong + st->interp_err <= 12u)
					printf("  FAIL %s (whole): [%s]\n       the evaluator says %s\n       the interpreter says %s\n", name, lines[stmt], gx, iv);
			}
		}
	}
	if (verbose && !st->lines_shown) {     /* the first program, line by line: what the evaluator said and what the interpreter said */
		st->lines_shown = 1;
		if (dump_prefix) {
			char fn[256];
			FILE *f;

			snprintf(fn, sizeof fn, "%s_%s.txt", dump_prefix, name);
			f = fopen(fn, "w");
			if (f) {
				fwrite(text, 1, (size_t)(w - text), f);
				fclose(f);
			}
		}
		for (i = 0; i < n; i++) {
			char gx[2048] = "-";

			for (k = 0; k < cs.n; k++)
				if (cs.c[k].off == line_of[i] + (unsigned)(strchr(lines[i], '=') - lines[i]) + (strchr(lines[i], '=')[1] == ' ' ? 2u : 1u))
					hexs(cs.c[k].v, cs.c[k].n < 900u ? cs.c[k].n : 900u, gx);
			printf("    %-60.60s evaluator %-30.30s interpreter %.30s\n", lines[i], gx, ihex[i] ? ihex[i] : "?");
		}
	}
	/* SUBST */
	w2 = consts_text(lang, (const uint8_t *)text, (size_t)(w - text), &cs, (uint8_t **)&text2);
	if (w2) {
		unsigned n2 = 0;
		const char *p = text2, *end = text2 + w2;
		char head[LINE], next[64];
		const char *at_s = strstr(lfmt, "%s");
		size_t hl = (size_t)(at_s - lfmt);

		text2[w2] = 0;
		/* a statement is the text from its `v<i> = ` to the start of the next one: a literal the evaluator wrote may hold a line break of its own (perl's q() does), so a line is not a statement */
		memcpy(head, lfmt, hl);
		head[hl] = 0;
		while (n2 < n && p < end) {
			const char *e;
			size_t l;

			snprintf(next, sizeof next, head, n2 + 1u);
			e = n2 + 1u < n ? memmem(p, (size_t)(end - p), next, strlen(next)) : NULL;
			while (e && e != p && e[-1] != '\n')
				e = memmem(e + 1, (size_t)(end - e - 1), next, strlen(next));
			l = e ? (size_t)(e - p) : (size_t)(end - p);
			if (l && p[l - 1u] == '\n')
				l--;
			if (l >= LINE)
				break;
			memcpy(lines2[n2], p, l);
			lines2[n2][l] = 0;
			len2[n2] = (uint32_t)l;
			n2++;
			p = e ? e : end;
		}
		if (n2 != n || p != end) {
			printf("  FAIL %s: the text with the constants written has %u lines, was %u\n", name, n2 + (p != end), n);
			if (verbose) {
				printf("---- text\n%s---- rewritten\n%.*s\n----\n", text, (int)w2, text2);
			}
			fails++;
		} else {
			out = run_lines(which, lines2, len2, n);
			if (out) {
				read_answers(out, ihex2, n);
				free(out);
				for (i = 0; i < n; i++) {
					int same_line = len1[i] == len2[i] && memcmp(lines[i], lines2[i], len1[i]) == 0;

					st->subst_checked += !same_line;
					if (same_line)
						continue;
					if (ihex[i] && ihex2[i] && !strcmp(ihex[i], ihex2[i])) {
						st->subst_same++;
					} else if (ihex[i] && !strcmp(ihex[i], "ERR")) {
						/* the line was an error (a SyntaxError of python's: a call and a literal side by side) and a part of it was read: the evaluator read code that never runs,
						 * and what it wrote there is not an answer to anything. Counted, not a difference. */
						st->subst_repaired++;
					} else {
						char key[LINE + 80];

						snprintf(key, sizeof key, "%.64s: %s", name, lines[i]);
						st->subst_diff++;
						if (known(key)) {
							st->known_seen++;
						} else {
							fails++;
							if (st->subst_diff <= 12u)
								printf("  FAIL %s (written): [%s]\n       became [%s]\n       the interpreter says %s, was %s\n", name, lines[i], lines2[i], ihex2[i] ? ihex2[i] : "(no answer)",
								       ihex[i] ? ihex[i] : "(no answer)");
						}
					}
				}
			}
		}
	}
	for (i = 0; i < n; i++) {
		free(ihex[i]);
		free(ihex2[i]);
	}
	free(text2);
	cset_free(&cs);
	free(text);
}

static void run_lang(uint32_t lang, int which, const char *name, unsigned total, char *(*gen)(int, int), const char *lfmt, const char *const *fixed)
{
	static char lines[PROG_LINES][LINE];
	struct stats st = { 0 };
	unsigned done = 0, nfixed = 0;

	while (fixed && fixed[nfixed])
		nfixed++;

	if (!have(which == 1 ? "python3" : which == 0 ? "perl" : "bash")) {
		printf("  %s: the interpreter is not on this machine: %u cases skipped\n", name, total);
		return;
	}
	while (done < total) {
		unsigned n = total - done < PROG_LINES ? total - done : PROG_LINES, i;

		pw = 0;
		for (i = 0; i < n; i++) {
			char *e;

			if (done == 0 && i < nfixed) {            /* the cases written by hand come first, in the first program; "@P" is the variable of the line before */
				char one[256], *at = one;
				const char *f = fixed[i];

				while (*f && at < one + sizeof one - 16) {
					if (f[0] == '@' && f[1] == 'P') {
						at += sprintf(at, "v%u", i ? i - 1u : 0u);
						f += 2;
					} else {
						*at++ = *f++;
					}
				}
				*at = 0;
				snprintf(lines[i], sizeof lines[i], lfmt, i, one);
				continue;
			}
			e = gen(1 + (int)rnd(3), (int)i);

			snprintf(lines[i], sizeof lines[i], lfmt, i, e);
		}
		compare(lang, which, name, lfmt, lines, n, &st);
		done += n;
	}
	if (!st.lines) {
		printf("  %s: the interpreter gave no answer (a tool it needs, base64, may be missing): skipped\n", name);
		return;
	}
	printf("  %s: %u generated assignments; %u values reported by the evaluator (%u whole right sides: %u equal to the interpreter's, %u different, %u of those the interpreter refused; %u of a part of a line); "
	       "%u lines rewritten with their constants: %u read back to the same answer, %u not (%u more were errors of the program, whose part the evaluator read); %u known open\n", name, st.lines, st.ranges, st.evaluated, st.agree, st.wrong, st.interp_err, st.partial,
	       st.subst_checked, st.subst_same, st.subst_diff, st.subst_repaired, st.known_seen);
	if (st.subst_checked * 8u < st.lines) {
		printf("  FAIL %s: the evaluator rewrote only %u of %u lines (a test that finds nothing proves nothing)\n", name, st.subst_checked, st.lines);
		fails++;
	}
}

int main(int argc, char **argv)
{
	int a;

	for (a = 1; a < argc; a++) {
		if (!strcmp(argv[a], "-v"))
			verbose = 1;
		else if (!strcmp(argv[a], "-d") && a + 1 < argc)
			dump_prefix = argv[++a];
		else
			rstate ^= (uint64_t)strtoull(argv[a], NULL, 10) * 0x9e3779b97f4a7c15ull;
	}
	(void)verbose;
	run_lang(PY, 1, "python", 1920, py_expr, "v%u = %s", py_fixed);
	run_lang(PL, 0, "perl", 1600, pl_expr, "$v%u = %s;", pl_fixed);
	run_lang(SH, 2, "bash", 1600, sh_word, "v%u=%s", sh_fixed);
	printf("diag_text_oracle: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
