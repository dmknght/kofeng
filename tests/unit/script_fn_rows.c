#define _GNU_SOURCE
/*
 * script_fn_rows - the string functions the function tables of vbscript, javascript, python, lua and perl have (libgenome/textual/<lang>/<lang>_fn.c), run with
 * the engine's own hook (kof_script_apply, kuncoat's algorithms): what a row says is checked against what the language does, and the whole path - the
 * form that writes a call on literals as its value, the evaluator that writes a computed right side where it was computed - against the same.
 *
 *   semantics   vbscript's Mid, Replace, LCase, UCase, perl's lcfirst and ucfirst, each against a reference written from the language's own rule and
 *               not from the code under test (exhaustive over small alphabets and every start and length around the boundaries); perl's two are also run
 *               through perl for every byte; vbscript's case maps are ASCII-only and a byte above 0x7f is refused (a locale maps it)
 *   form        `Chr(104) & Chr(116)`, `String.fromCharCode(104, 105)`, `chr(104)`, `string.char(104)`, `Mid("abc", 2)` written as the literal they come to,
 *               a call that is not on literals left as typed, `obj.chr(65)` (a member of something else) left as typed
 *   evaluator   the same expressions on the right of an assignment, reported by on_const
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "normalizer_ref.h"
#include "normalizer_consts.h"
#include <textual/textual.h>

/* ---- semantics -------------------------------------------------------------------------- */

static int run_fn(uint32_t lang, const char *name, const char *const *args, uint32_t n, uint8_t *out, uint32_t cap, uint32_t *w)
{
	struct kgenome_textual_fn f;
	struct kgenome_textual_arg a[4];
	uint32_t i;

	if (!kgenome_textual_fn_find(lang, (const uint8_t *)name, (uint32_t)strlen(name), &f))
		return -1;
	for (i = 0; i < n; i++) {
		a[i].p = (const uint8_t *)args[i];
		a[i].n = (uint32_t)strlen(args[i]);
	}
	return kgenome_textual_fn_run(&f, a, n, kof_script_apply, NULL, out, cap, w);
}

/* vbscript's Mid by its documentation: start counts from 1 and below it is an error; a length below 0 is an error; past the end is "". 1 + the answer, 0 for an error. */
static int vb_mid(const char *s, long start, long len, int has_len, char *out)
{
	long n = (long)strlen(s), take;

	if (start < 1 || (has_len && len < 0))
		return 0;
	if (start > n) {
		out[0] = 0;
		return 1;
	}
	take = has_len && len < n - start + 1 ? len : n - start + 1;
	memcpy(out, s + start - 1, (size_t)take);
	out[take] = 0;
	return 1;
}

static void mid_exhaustive(void)
{
	static const char *const subjects[] = { "", "a", "ab", "abc", "abcdef", "a b", "\x7f\x01x" };
	unsigned si;
	long start, len;

	for (si = 0; si < sizeof subjects / sizeof subjects[0]; si++)
		for (start = -2; start <= 9; start++)
			for (len = -3; len <= 9; len++) {
				char sa[16], la[16], want[16], got[16];
				const char *two[2], *three[3];
				uint8_t o[64];
				uint32_t w = 0;
				int ok, wn;

				snprintf(sa, sizeof sa, "%ld", start);
				snprintf(la, sizeof la, "%ld", len);
				three[0] = subjects[si]; three[1] = sa; three[2] = la;
				two[0] = subjects[si]; two[1] = sa;
				wn = vb_mid(subjects[si], start, len, 1, want);
				ok = run_fn(KGENOME_TEXTUAL_LANG_VBS, "mid", three, 3, o, sizeof o, &w);
				memcpy(got, o, w); got[w] = 0;
				NCKF(ok == wn && (!ok || !strcmp(got, want)), "Mid(%s, %ld, %ld): got ok=%d [%s], the rule says ok=%d [%s]", subjects[si], start, len, ok, got, wn, want);
				wn = vb_mid(subjects[si], start, 0, 0, want);
				ok = run_fn(KGENOME_TEXTUAL_LANG_VBS, "mid", two, 2, o, sizeof o, &w);
				memcpy(got, o, w); got[w] = 0;
				NCKF(ok == wn && (!ok || !strcmp(got, want)), "Mid(%s, %ld): got ok=%d [%s], the rule says ok=%d [%s]", subjects[si], start, ok, got, wn, want);
			}
	/* a subject with a byte above 0x7f is refused: Mid counts characters */
	{
		const char *a[3] = { "\xc3\xa9x", "1", "1" };
		uint8_t o[16];
		uint32_t w;

		NCK(run_fn(KGENOME_TEXTUAL_LANG_VBS, "mid", a, 3, o, sizeof o, &w) == 0);
	}
}

/* Replace(expression, find, replacement): replace all, binary compare, a search of nothing is the expression. */
static void replace_exhaustive(void)
{
	static const char alpha[] = "ab";
	unsigned s, f, r;

	for (s = 0; s < 729u; s++)              /* every subject of up to 6 letters over "ab": 1 + 2 + .. + 64 = 127 would do; 3^6 codes cover them with blanks */
		for (f = 0; f < 27u; f++)
			for (r = 0; r < 9u; r++) {
				char sb[8] = "", fb[5] = "", rb[4] = "", want[64], got[64];
				uint32_t sn = 0, fnn = 0, rn = 0, i, w = 0, wn = 0, x;
				const char *args[3];
				uint8_t o[64];
				int ok;

				for (x = s; x && sn < 6u; x /= 3u)
					if (x % 3u)
						sb[sn++] = alpha[x % 3u - 1u];
				for (x = f; x && fnn < 3u; x /= 3u)
					if (x % 3u)
						fb[fnn++] = alpha[x % 3u - 1u];
				for (x = r; x && rn < 2u; x /= 3u)
					if (x % 3u)
						rb[rn++] = alpha[x % 3u - 1u];
				/* the reference: scan left to right, at each place the search matches, write the replacement and skip it */
				for (i = 0; i < sn;) {
					if (fnn && i + fnn <= sn && !memcmp(sb + i, fb, fnn)) {
						memcpy(want + wn, rb, rn);
						wn += rn;
						i += fnn;
					} else {
						want[wn++] = sb[i++];
					}
				}
				want[wn] = 0;
				args[0] = sb; args[1] = fb; args[2] = rb;
				ok = run_fn(KGENOME_TEXTUAL_LANG_VBS, "replace", args, 3, o, sizeof o, &w);
				memcpy(got, o, w); got[w] = 0;
				NCKF(ok == 1 && !strcmp(got, want), "Replace(%s, %s, %s): got ok=%d [%s], want [%s]", sb, fb, rb, ok, got, want);
			}
}

/* LCase and UCase on ASCII: the two case maps, against python's for every byte below 0x80; above, refused. */
static void case_ascii(void)
{
	unsigned b;

	for (b = 0; b < 256u; b++) {
		char s[3] = { (char)b, 'x', 0 }, up[3] = { (char)b, 'x', 0 };
		const char *a[1] = { s };
		uint8_t o[8];
		uint32_t w = 0;
		int ok;

		if (b == 0)
			continue;       /* a NUL ends a C string; the lib takes lengths and the engine's tests of the hook cover it */
		ok = run_fn(KGENOME_TEXTUAL_LANG_VBS, "lcase", a, 1, o, sizeof o, &w);
		if (b >= 0x80u) {
			NCKF(ok == 0, "LCase of byte %u is refused", b);
			continue;
		}
		up[0] = (char)(b >= 'a' && b <= 'z' ? b - 32u : b);
		NCKF(ok == 1 && w == 2u && o[0] == (uint8_t)(b >= 'A' && b <= 'Z' ? b + 32u : b) && o[1] == 'x', "LCase of byte %u", b);
		ok = run_fn(KGENOME_TEXTUAL_LANG_VBS, "ucase", a, 1, o, sizeof o, &w);
		NCKF(ok == 1 && w == 2u && o[0] == (uint8_t)up[0] && o[1] == 'X', "UCase of byte %u", b);
	}
	/* the names fold: Chr, CHR, chr */
	{
		const char *a[1] = { "ABC" };
		uint8_t o[8];
		uint32_t w;

		NCK(run_fn(KGENOME_TEXTUAL_LANG_VBS, "LCase", a, 1, o, sizeof o, &w) == 1 && w == 3u && !memcmp(o, "abc", 3));
		NCK(run_fn(KGENOME_TEXTUAL_LANG_VBS, "LCASE", a, 1, o, sizeof o, &w) == 1);
		NCK(run_fn(KGENOME_TEXTUAL_LANG_JS, "lcase", a, 1, o, sizeof o, &w) == -1);        /* javascript has no such function */
	}
}

/* perl's lcfirst and ucfirst, through perl, for every byte as the first of a two byte string and as a whole string. */
static void perl_case(void)
{
	FILE *p = popen("perl -e 'for my $b (1..255) { my $s = chr($b).\"x\"; printf(\"%s %s %s %s\\n\", unpack(\"H*\", lcfirst($s)), unpack(\"H*\", ucfirst($s)), unpack(\"H*\", lcfirst(chr($b))), unpack(\"H*\", ucfirst(chr($b)))); }' 2>&1", "r");
	char line[128];
	unsigned b = 1, bad = 0;

	if (!p)
		return;
	while (fgets(line, sizeof line, p) && b < 256u) {
		char s[3] = { (char)b, 'x', 0 }, one[2] = { (char)b, 0 };
		const char *a2[1] = { s }, *a1[1] = { one };
		uint8_t o[8];
		uint32_t w = 0, i;
		char hex[64] = "";
		const char *names[4] = { "lcfirst", "ucfirst", "lcfirst", "ucfirst" };
		const char *const *args[4] = { a2, a2, a1, a1 };
		unsigned k;

		for (k = 0; k < 4u; k++) {
			int ok = run_fn(KGENOME_TEXTUAL_LANG_PERL, names[k], args[k], 1, o, sizeof o, &w);
			char part[16] = "";

			for (i = 0; ok == 1 && i < w; i++)
				snprintf(part + 2u * i, 4, "%02x", o[i]);
			strcat(hex, part);
			strcat(hex, k < 3u ? " " : "");
		}
		line[strcspn(line, "\n")] = 0;
		if (strcmp(hex, line) && bad++ < 3u)
			printf("  FAIL perl case of byte %u: perl [%s], the hook [%s]\n", b, line, hex);
		b++;
	}
	pclose(p);
	NCKF(!bad && b == 256u, "perl lcfirst/ucfirst over every byte: %u bad, stopped at %u", bad, b);
}

/* ---- the form and the evaluator ----------------------------------------------------------- */

static int form_apply(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n)
{
	return kof_script_apply(u, c, in, len, out, cap, n);
}

static void form_is(uint32_t lang, const char *src, const char *want)
{
	static uint8_t out[4096];
	struct kgenome_textual_form_req q = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = lang, .out = out, .cap = sizeof out,
					      .apply = form_apply };
	struct kgenome_textual_form_res r;
	enum kgenome_textual_status st = kgenome_textual_form(&q, &r);

	out[r.n_out] = 0;
	NCKF((st == KGENOME_TEXTUAL_OK || st == KGENOME_TEXTUAL_OPEN) && !strcmp((char *)out, want), "form of [%s]: got [%s], wanted [%s]", src, out, want);
}

static void const_is(uint32_t lang, const char *src, const char *want)
{
	struct cset s;
	int ok;

	consts_of(lang, (const uint8_t *)src, strlen(src), &s);
	ok = want ? s.n == 1u && s.c[0].n == strlen(want) && !memcmp(s.c[0].v, want, s.c[0].n) : s.n == 0u;
	NCKF(ok, "constants of [%s]: %u values, first [%.*s], wanted [%s]", src, s.n, s.n ? (int)s.c[0].n : 0, s.n ? (char *)s.c[0].v : "", want ? want : "none");
	cset_free(&s);
}

static void paths(void)
{
	const uint32_t VB = KGENOME_TEXTUAL_LANG_VBS, JS = KGENOME_TEXTUAL_LANG_JS, PY = KGENOME_TEXTUAL_LANG_PY, LU = KGENOME_TEXTUAL_LANG_LUA,
		       PL = KGENOME_TEXTUAL_LANG_PERL;

	/* the form: a call on literals is its value, and joins with what is around it */
	/* vbscript's row says concat '&' (the owner required a join in every language that has one; textual_vbs.c pinned it the other way before): the calls become literals and
	 * the "&" between them joins them. These four pinned `"h"&"t"&"tp"`, `"h"&"i"`, `"abc"&"DEF"` and the Replace that could not read a joined argument. */
	form_is(VB, "x = Chr(104) & Chr(116) & \"tp\"\n", "x=\"http\"");
	form_is(VB, "x = CHR(104) & chr(105)\n", "x=\"hi\"");
	form_is(VB, "x = ChrW(233)\n", "x=ChrW(233)");                      /* not printable ASCII: a table of bytes is data, as php's chr */
	form_is(VB, "x = Chr(200)\n", "x=Chr(200)");                        /* ANSI above 127: refused */
	form_is(VB, "x = Mid(\"abcdef\", 2, 3)\n", "x=\"bcd\"");
	form_is(VB, "x = Mid(\"abcdef\", 3)\n", "x=\"cdef\"");
	form_is(VB, "x = Mid(\"abcdef\", 0, 3)\n", "x=Mid(\"abcdef\",0,3)");     /* an error in the language: stays */
	form_is(VB, "x = Replace(\"a@b@c\", \"@\", \" \")\n", "x=\"a b c\"");
	form_is(VB, "x = LCase(\"ABC\") & UCase(\"def\")\n", "x=\"abcDEF\"");
	form_is(VB, "x = Replace(Chr(65) & \"b\", \"A\", \"x\")\n", "x=\"xb\"");   /* the join is one literal, and Replace reads it */
	form_is(VB, "x = Chr(y)\n", "x=Chr(y)");                            /* not on literals */
	form_is(VB, "x = obj.Chr(65)\n", "x=obj.Chr(65)");                  /* a member of obj */
	form_is(VB, "x = \"a\" & \"b\"\n", "x=\"ab\"");
	form_is(JS, "var x = String.fromCharCode(104, 105);\n", "var x='hi';");
	form_is(JS, "var x = String.fromCharCode(104)+String.fromCharCode(105)+'!';\n", "var x='hi!';");
	form_is(JS, "eval(String.fromCharCode(101,118,97,108));\n", "eval('eval');");
	form_is(JS, "var x = String.fromCharCode(0x20ac);\n", "var x=String.fromCharCode(0x20ac);");   /* hex: not a decimal number the stage reads */
	form_is(JS, "var x = String.fromCharCode(233);\n", "var x=String.fromCharCode(233);");           /* not printable ASCII */
	form_is(JS, "var x = foo.String.fromCharCode(65);\n", "var x=foo.String.fromCharCode(65);");     /* a member of foo */
	form_is(JS, "var x = String.fromCodePoint(65, 66);\n", "var x='AB';");
	form_is(JS, "var x = fromCharCode(65);\n", "var x=fromCharCode(65);");
	form_is(PY, "x = chr(104) + chr(105)\n", "x='hi'");
	form_is(PY, "x = chr(200)\n", "x=chr(200)");
	form_is(PY, "x = obj.chr(65)\n", "x=obj.chr(65)");
	form_is(LU, "x = string.char(104, 105) .. string.char(33)\n", "x='hi'..'!'");   /* lua has no row concat: ".." is not joined (lua_lang.c says why) */
	form_is(LU, "x = string.char(104, 105)\n", "x='hi'");
	form_is(LU, "x = other.char(65)\n", "x=other.char(65)");
	form_is(PL, "$x = chr(104) . chr(105);\n", "$x='h'.'i';");
	form_is(PL, "$x = ucfirst(\"abc\");\n", "$x='Abc';");
	form_is(PL, "$x = lcfirst(\"ABC\");\n", "$x='aBC';");
	form_is(PL, "$x = chr(300);\n", "$x=chr(300);");                      /* a wide character: refused */
	/* the evaluator: reported when it is a computed right side, written as one literal */
	const_is(VB, "x = Chr(104) & Chr(116) & Chr(116) & Chr(112)\n", "http");
	const_is(VB, "x = Replace(\"68@74\", \"@\", \" \") & \"!\"\n", "68 74!");
	const_is(JS, "var x = String.fromCharCode(104, 116, 116, 112) + \"://\";\n", "http://");
	const_is(JS, "var x = String.fromCharCode(0x41);\n", NULL);
	const_is(PY, "x = chr(104) + chr(116)\n", "ht");
	const_is(LU, "x = string.char(104, 116) .. \"tp\"\n", "http");
	const_is(PL, "$x = chr(104) . chr(116);\n", "ht");
	const_is(PL, "$x = ucfirst(\"abc\") . \"d\";\n", "Abcd");
	const_is(VB, "x = Chr(y) & \"a\"\n", NULL);
}

int main(void)
{
	mid_exhaustive();
	replace_exhaustive();
	case_ascii();
	perl_case();
	paths();
	printf("script_fn_rows: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
