#define _GNU_SOURCE
/*
 * script_methods - the methods, operators, suffixes, casts and list functions the evaluator reads (libgenome/textual/<lang>/<lang>_fn.c, rows of shape METHOD, OP, SUFFIX, CAST;
 * phenotype/diag_text_eval_ops.c reads them), run with the engine's own hook (kof_script_apply, kuncoat's ops): what a row says is checked against what the language does.
 *
 *   python 3 and perl   AGAINST THE INTERPRETER, over every case of a small alphabet each row accepts: the interpreter prints the expression and its answer, the evaluator is asked
 *                       the same expression, and the two must be the same bytes. A row is also asked what it must REFUSE - a call the language reads another way (an empty search,
 *                       a count argument, a str where a number is wanted, a character the case map is Unicode's for) - and has to leave it as written. A machine without python 3 or perl
 *                       says so and the cases of that language are skipped, visibly.
 *   javascript, ruby, powershell, lua, vbscript, php (implode, explode)
 *                       AGAINST THE LANGUAGE'S REFERENCE TEXT, case by case with the rule written beside it: [Unverified] against a real interpreter - this machine has none of them
 *                       (no node, ruby, pwsh, lua, wscript, php). Every boundary a flag of a row stands for has a case that accepts and one that refuses.
 *   the reading         precedence (python's `*` binds tighter than the join, powershell's -replace looser), a list left over is no value, a character is no string, a call of two values
 *                       is read where one is taken (lua's gsub), a method written without brackets only where the row says so, and the literals changed where they stand.
 * Nothing here is a detection rate: it asks whether an expression the language reads one way is evaluated that way or left alone.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "normalizer_ref.h"
#include "normalizer_consts.h"
#include <textual/textual.h>

#define PY KGENOME_TEXTUAL_LANG_PY
#define PL KGENOME_TEXTUAL_LANG_PERL
#define JS KGENOME_TEXTUAL_LANG_JS
#define RB KGENOME_TEXTUAL_LANG_RUBY
#define PS KGENOME_TEXTUAL_LANG_PSH
#define LU KGENOME_TEXTUAL_LANG_LUA
#define VB KGENOME_TEXTUAL_LANG_VBS
#define PH KGENOME_TEXTUAL_LANG_PHP

static unsigned skipped;

/* The single constant the evaluator finds in `src` (the right side of its one assignment), as a string, NULL when it finds none. */
static char *eval1(uint32_t lang, const char *src, unsigned *n_found)
{
	struct cset s;
	char *r = NULL;

	consts_of(lang, (const uint8_t *)src, strlen(src), &s);
	*n_found = s.n;
	if (s.n == 1u) {
		r = malloc(s.c[0].n + 1u);
		memcpy(r, s.c[0].v, s.c[0].n);
		r[s.c[0].n] = 0;
	}
	cset_free(&s);
	return r;
}

/* `src` must evaluate to exactly `want` (NULL: it must be left as written). */
static void is(uint32_t lang, const char *src, const char *want)
{
	unsigned n;
	char *r = eval1(lang, src, &n);
	int ok = want ? (r && !strcmp(r, want) && n == 1u) : n == 0u;

	NCKF(ok, "[%s]: got %s[%s] (%u values), wanted %s[%s]", src, r ? "" : "nothing ", r ? r : "", n, want ? "" : "nothing ", want ? want : "");
	free(r);
}

/* The same for a value that holds a NUL or any other byte a C string cannot: compared by length and bytes. */
static void is_bytes(uint32_t lang, const char *src, const char *want, size_t wn)
{
	struct cset s;
	int ok;

	consts_of(lang, (const uint8_t *)src, strlen(src), &s);
	ok = s.n == 1u && s.c[0].n == wn && !memcmp(s.c[0].v, want, wn);
	NCKF(ok, "[%s]: %u values, first of %u bytes, wanted %zu bytes", src, s.n, s.n ? s.c[0].n : 0u, wn);
	cset_free(&s);
}

/* The form of a text with the engine's hook: what a call on literals is written as. */
static void form_is(uint32_t lang, const char *src, const char *want)
{
	static uint8_t out[4096];
	struct kgenome_textual_form_req q = { .in = (const uint8_t *)src, .n = (uint32_t)strlen(src), .lang = lang, .out = out, .cap = sizeof out, .apply = kof_script_apply };
	struct kgenome_textual_form_res r;
	enum kgenome_textual_status st = kgenome_textual_form(&q, &r);

	out[r.n_out] = 0;
	NCKF((st == KGENOME_TEXTUAL_OK || st == KGENOME_TEXTUAL_OPEN) && !strcmp((char *)out, want), "form of [%s]: got [%s], wanted [%s]", src, out, want);
}

/* ---- the interpreters --------------------------------------------------------------------- */

static int have(const char *tool)
{
	char cmd[96];

	snprintf(cmd, sizeof cmd, "%s --version >/dev/null 2>&1", tool);
	return system(cmd) == 0;
}

static char *b64(const char *p)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t n = strlen(p), i, w = 0;
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

static char *run_script(int py, const char *script)
{
	char *code, *cmd, *buf;
	FILE *p;
	size_t w = 0, r;

	if (!have(py ? "python3" : "perl")) {
		skipped++;
		printf("  %s not found: its cases are skipped\n", py ? "python3" : "perl");
		return NULL;
	}
	code = b64(script);
	cmd = malloc(strlen(code) + 200u);
	sprintf(cmd, py ? "python3 -I -c \"import base64;exec(base64.b64decode('%s'))\" 2>&1" : "perl -MMIME::Base64 -e 'eval(decode_base64(\"%s\")); print STDERR $@ if $@' 2>&1", code);
	p = popen(cmd, "r");
	buf = malloc(1u << 26);
	free(code);
	free(cmd);
	if (!p || !buf) {
		free(buf);
		return NULL;
	}
	while ((r = fread(buf + w, 1, (1u << 26) - 1u - w, p)) > 0)
		w += r;
	buf[w] = 0;
	pclose(p);
	return buf;
}

static void hexs(const uint8_t *p, size_t n, char *o)
{
	size_t k;

	for (k = 0; k < n; k++)
		sprintf(o + 2u * k, "%02x", p[k]);
	o[2u * n] = 0;
}

/*
 * The interpreter's cases: lines of TAB-separated `tag expression hex-of-its-answer`. `A` is a case the row must evaluate, and to the interpreter's bytes; `R` one it must leave
 * alone. `prefix` is what makes the expression a statement of the language (`x = `, `$x = `); `suffix` ends it.
 */
static void interpreter(uint32_t lang, int py, const char *script, const char *prefix, const char *suffix, const char *what)
{
	char *out = run_script(py, script), *at = out, *line;
	unsigned long acc = 0, ref = 0, bad = 0;

	if (!out)
		return;
	while ((line = strsep(&at, "\n")) != NULL && *line) {
		char *tag = line, *expr = strchr(line, '\t'), *hex, src[512];
		unsigned n;
		char *got;

		if (!expr)
			continue;
		*expr++ = 0;
		hex = strchr(expr, '\t');
		if (!hex)
			continue;
		*hex++ = 0;
		snprintf(src, sizeof src, "%s%s%s\n", prefix, expr, suffix);
		got = eval1(lang, src, &n);
		if (*tag == 'A') {
			char gx[1024] = "";

			if (got)
				hexs((const uint8_t *)got, strlen(got), gx);
			acc++;
			if ((!got || strcmp(gx, hex)) && bad++ < 8u)
				printf("  FAIL %s: [%s] must be %s, the interpreter says %s\n", what, expr, got ? gx : "left alone", hex);
		} else {
			ref++;
			if (got && bad++ < 8u)
				printf("  FAIL %s: [%s] must be left alone, was evaluated to [%s]\n", what, expr, got);
		}
		free(got);
	}
	free(out);
	NCKF(!bad && acc > 100u && ref > 3u, "%s: %lu accepted cases, %lu refused cases, %lu differences", what, acc, ref, bad);
	printf("  %s: %lu cases the row evaluates to the interpreter's bytes, %lu it leaves alone\n", what, acc, ref);
}

static const char py_cases[] =
	"import itertools\n"
	"def words(al,mx):\n"
	"    for n in range(mx+1):\n"
	"        for t in itertools.product(al,repeat=n): yield ''.join(t)\n"
	"def A(e): print('A\\t'+e+'\\t'+eval(e).encode().hex())\n"
	"def R(e):\n"
	"    try: r=eval(e)\n"
	"    except Exception: r=''\n"
	"    print('R\\t'+e+'\\t'+(r.encode().hex() if isinstance(r,str) else ''))\n"
	"for s in words('aB',3):\n"
	"  for old in words('aB',2):\n"
	"    if not old: continue\n"
	"    for new in ['','x','xy']: A(repr(s)+'.replace('+repr(old)+', '+repr(new)+')')\n"
	"  R(repr(s)+\".replace('', 'x')\"); R(repr(s)+\".replace('a', 'b', 1)\"); R(repr(s)+'.split()'); R(repr(s)+\".strip('a')\")\n"
	"for s in words('aBAb',4):\n"
	"  A(repr(s)+'.lower()'); A(repr(s)+'.upper()')\n"
	"for s in words('a \\t\\x0b\\x0c\\x1c\\r\\n',4):\n"
	"  A(repr(s)+'.strip()'); A(repr(s)+'.lstrip()'); A(repr(s)+'.rstrip()')\n"
	"for s in ['\\xa0a','a\\xa0','\\x85a','\\u2003a ','\\xe9']:\n"
	"  R(repr(s)+'.strip()'); R(repr(s)+'.lower()'); R(repr(s)+'.upper()'); R(repr(s)+'[::-1]')\n"
	"for s in words('ab,',5):\n"
	"  for sep in [',','a','ab']:\n"
	"    for j in ['','-','ab']: A(repr(j)+'.join('+repr(s)+'.split('+repr(sep)+'))')\n"
	"  R(repr(s)+\".split('')\")\n"
	"for s in words('abB',4):\n"
	"  A(repr(s)+'[::-1]')\n"
	"  for n in [0,1,2,3,-1,-5]: A(repr(s)+' * '+str(n))\n"
	"  R(repr(s)+\" * '3'\"); R(repr(s)+' * 2.5')\n"
	"R(\"''.join('abc')\"); R(\"b'ab'.replace(b'a', b'c')\"); R(\"'ab'.join(['a', 1])\")\n"
	"for a in ['', 'a', 'b']:\n"
	"  for b in ['', 'a', 'b', 'ab']:\n"
	"    A(repr(a)+' + '+repr(b)+' * 2'); A('('+repr(a)+' + '+repr(b)+') * 2'); A(repr(a)+' * 2 + '+repr(b))\n"
	"    A(repr(a)+'.upper() + '+repr(b)+'.lower()'); A(repr(a)+'.replace('+repr('a')+', '+repr('b')+') + '+repr(b)+'[::-1]')\n";

static const char pl_cases[] =
	"sub h{return unpack('H*',$_[0]);}\n"
	"sub words{my($al,$mx)=@_;my @r=('');my @prev=('');for my $n(1..$mx){my @nx;for my $p(@prev){for my $c(split //,$al){push @nx,$p.$c;}}push @r,@nx;@prev=@nx;}return @r;}\n"
	"sub qs{my $s=shift;$s=~s/(\\\\|\")/\\\\$1/g;$s=~s/\\$/\\\\\\$/g;$s=~s/\\@/\\\\\\@/g;return '\"'.$s.'\"';}\n"
	"for my $s(words('aBAb',4)){my $e=qs($s);\n"
	"print \"A\\tlc($e)\\t\".h(lc($s)).\"\\n\";print \"A\\tuc($e)\\t\".h(uc($s)).\"\\n\";}\n"
	"for my $s(words('ab',3)){for my $n(0,1,2,3,-1){my $e=qs($s);print \"A\\t$e x $n\\t\".h($s x $n).\"\\n\";}}\n"
	"for my $s(words('ab',2)){for my $t(words('ab',2)){for my $sep('',',','ab'){my($e,$f,$g)=(qs($s),qs($t),qs($sep));print \"A\\tjoin($g, $e, $f)\\t\".h(join($sep,$s,$t)).\"\\n\";print \"A\\tjoin($g, $e)\\t\".h(join($sep,$s)).\"\\n\";}}}\n"
	"print \"R\\tjoin(\\\",\\\", (\\\"a\\\", \\\"b\\\"))\\t\".h(join(\",\",(\"a\",\"b\"))).\"\\n\";print \"R\\tlc(\\\"\\xc3\\x89\\\")\\t\\n\";print \"R\\t(\\\"ab\\\") x 3\\t\\n\";print \"R\\t\\\"ab\\\" x \\\"2.5\\\"\\t\\n\";print \"R\\tuc(\\\"\\xc3\\xa9\\\")\\t\\n\";\n";

static void against_interpreters(void)
{
	interpreter(PY, 1, py_cases, "x = ", "", "python 3");
	interpreter(PL, 0, pl_cases, "$x = ", ";", "perl");
}

/* ---- javascript: ECMA-262 -------------------------------------------------------------------- */

static void javascript(void)
{
	/* replace changes the FIRST match of a string pattern; replaceAll every one; an empty pattern and "$" in the replacement are patterns of their own */
	is(JS, "x = \"abc\".replace(\"b\", \"X\")\n", "aXc");
	is(JS, "x = \"abab\".replace(\"b\", \"X\")\n", "aXab");
	is(JS, "x = \"abab\".replaceAll(\"b\", \"X\")\n", "aXaX");
	is(JS, "x = \"a.b\".replace(\".\", \"-\")\n", "a-b");                      /* a string pattern is the text, not a regular expression */
	is(JS, "x = \"abc\".replace(\"\", \"X\")\n", NULL);                          /* inserts at the start in the language: not the op */
	is(JS, "x = \"abc\".replaceAll(\"\", \"X\")\n", NULL);
	is(JS, "x = \"abc\".replace(\"b\", \"$&\")\n", NULL);                        /* "$&" is the match */
	is(JS, "x = \"abc\".replace(\"b\", \"$$\")\n", NULL);
	is(JS, "x = \"abc\".replace(\"b\", \"a$\")\n", NULL);                        /* any "$" is refused: not worth a table of which are patterns */
	/* split and join: the idiom for replacing all, and the lists around it */
	is(JS, "x = \"a,b,c\".split(\",\").join(\"-\")\n", "a-b-c");
	is(JS, "x = \"a,,c\".split(\",\").join(\"-\")\n", "a--c");                   /* empty pieces are kept */
	is(JS, "x = \",a,\".split(\",\").join(\"-\")\n", "-a-");
	is(JS, "x = \"abc\".split(\"\").join(\"-\")\n", NULL);                       /* an empty separator cuts into characters */
	is(JS, "x = \"a,b\".split(\",\").join()\n", NULL);                           /* join() joins with a comma: no separator is not read */
	is(JS, "x = [\"a\", \"b\"].join(\"+\")\n", "a+b");
	is(JS, "x = [\"a\", \"b\",].join(\"+\")\n", "a+b");                          /* a trailing comma */
	is(JS, "x = [].join(\"+\")\n", "");
	is(JS, "x = [\"a\", \"b\"].join(1)\n", NULL);                                /* a number as the separator is joined as its text: not read */
	is(JS, "x = [\"a\", 1].join(\"+\")\n", NULL);                                /* a number is joined as its text, which is not read */
	is(JS, "x = [\"a\", b].join(\"+\")\n", NULL);                                /* a variable that is not constant */
	is(JS, "x = \"a,b\".split(\",\")\n", NULL);                                  /* a list is no value */
	is(JS, "x = [\"a\"]\n", NULL);
	/* the cuts: substring swaps and clamps below 0; slice and substr count from the end below 0: a number below 0 is refused */
	is(JS, "x = \"abcdef\".substring(1, 3)\n", "bc");
	is(JS, "x = \"abcdef\".substring(3, 1)\n", "bc");
	is(JS, "x = \"abcdef\".substring(2)\n", "cdef");
	is(JS, "x = \"abcdef\".substring(2, 2)\n", "");
	is(JS, "x = \"abcdef\".substring(4, 100)\n", "ef");
	is(JS, "x = \"abcdef\".substring(10)\n", "");
	is(JS, "x = \"abcdef\".substring(-1)\n", NULL);
	is(JS, "x = \"abcdef\".slice(1, 3)\n", "bc");
	is(JS, "x = \"abcdef\".slice(3, 1)\n", "");                                  /* slice does not swap */
	is(JS, "x = \"abcdef\".slice(2)\n", "cdef");
	is(JS, "x = \"abcdef\".slice(1, 100)\n", "bcdef");
	is(JS, "x = \"abcdef\".slice(10)\n", "");
	is(JS, "x = \"abcdef\".slice(-2)\n", NULL);
	is(JS, "x = \"abcdef\".slice(1, -1)\n", NULL);
	is(JS, "x = \"abcdef\".substr(1, 3)\n", "bcd");
	is(JS, "x = \"abcdef\".substr(2)\n", "cdef");
	is(JS, "x = \"abcdef\".substr(-3)\n", NULL);
	is(JS, "x = \"\xc3\xa9" "bc\".slice(0, 1)\n", NULL);                          /* UTF-16 units are not bytes: a subject above ASCII is refused */
	is(JS, "x = \"abc\".slice(1.5)\n", NULL);
	/* case and white space */
	is(JS, "x = \"AbC\".toLowerCase()\n", "abc");
	is(JS, "x = \"AbC\".toUpperCase()\n", "ABC");
	is(JS, "x = \"\xc3\xa9\".toUpperCase()\n", NULL);                            /* Unicode's map */
	is(JS, "x = \"  a \".trim()\n", "a");
	is(JS, "x = \"  a \".trimStart()\n", "a ");
	is(JS, "x = \"  a \".trimEnd()\n", "  a");
	is(JS, "x = \"\\t\\v\\f\\r\\n a\\n\".trim()\n", "a");                           /* the ASCII white space of ECMAScript */
	is_bytes(JS, "x = \"\\u0000a\\u0000\".trim()\n", "\0a\0", 3u);                     /* NUL is not white space to ECMAScript */
	is_bytes(JS, "x = \"\\u000ba\\u000c\".trim()\n", "a", 1u);
	is(JS, "x = \"a\".repeat(3)\n", "aaa");
	is(JS, "x = \"ab\".repeat(0)\n", "");
	is(JS, "x = \"ab\".repeat(-1)\n", NULL);                                     /* a RangeError */
	is(JS, "x = \"ab\".repeat(2.5)\n", NULL);
	is(JS, "x = \"a-b\".replace(\"-\", \"+\").toUpperCase()\n", "A+B");            /* a chain */
	is(JS, "x = \"a-b\".replace(\"-\", \"+\").foo()\n", "a+b");                     /* a method the table has not ends the chain: what is before it is still the literal's value */
	is(JS, "x = y.replace(\"-\", \"+\")\n", NULL);
	is(JS, "x = \"abc\".trim\n", NULL);                                         /* the function itself, not a call */
	is(JS, "x = \"abc\"[0].toUpperCase()\n", NULL);
}

/* ---- ruby ------------------------------------------------------------------------------------- */

static void ruby(void)
{
	is(RB, "x = \"abab\".gsub(\"b\", \"X\")\n", "aXaX");
	is(RB, "x = \"abab\".sub(\"b\", \"X\")\n", "aXab");
	is(RB, "x = \"a.b\".gsub(\".\", \"-\")\n", "a-b");                          /* a string pattern is the text */
	is(RB, "x = \"abc\".gsub(\"\", \"X\")\n", NULL);                              /* between every character */
	is(RB, "x = \"abc\".gsub(\"b\", \"\\\\1\")\n", NULL);                           /* "\1" in the replacement is a group */
	is(RB, "x = \"abc\".gsub(\"b\", \"\\\\\\\\\")\n", NULL);                         /* even a backslash is read */
	is(RB, "x = \"abc\".gsub(/b/, \"X\")\n", NULL);                              /* a regular expression has no string argument */
	is(RB, "x = \"abc\".reverse\n", "cba");
	is(RB, "x = \"abc\".reverse()\n", "cba");
	is(RB, "x = \"\xc3\xa9" "bc\".reverse\n", NULL);
	is(RB, "x = \"AbC\".upcase\n", "ABC");
	is(RB, "x = \"AbC\".downcase\n", "abc");
	is(RB, "x = \"\xc3\xa9\".upcase\n", NULL);
	is(RB, "x = \"abc\".tr(\"ab\", \"xy\")\n", "xyc");
	is(RB, "x = \"abc\".tr(\"a-c\", \"xyz\")\n", NULL);                           /* a range */
	is(RB, "x = \"abc\".tr(\"^a\", \"x\")\n", NULL);                              /* a negation */
	is(RB, "x = \"abc\".tr(\"ab\", \"x\")\n", NULL);                              /* the shorter list is padded: not the op */
	is(RB, "x = \"abc\".tr(\"aa\", \"xy\")\n", NULL);                            /* which pair wins is ruby's */
	is(RB, "x = [\"a\", \"b\"].join\n", "ab");                                  /* no separator joins with nothing */
	is(RB, "x = [\"a\", \"b\"].join(\"-\")\n", "a-b");
	is(RB, "x = \"a,b\".split(\",\").join(\"-\")\n", "a-b");
	is(RB, "x = \"a,b,,\".split(\",\").join(\"-\")\n", "a-b");                    /* the empty pieces at the end go */
	is(RB, "x = \",a,,\".split(\",\").join(\"-\")\n", "-a");                      /* the one at the front stays */
	is(RB, "x = \"a b\".split(\" \").join(\"-\")\n", NULL);                       /* " " is awk mode */
	is(RB, "x = \"abc\".split(\"\").join(\"-\")\n", NULL);
	is(RB, "x = \"ab\" * 3\n", "ababab");
	is(RB, "x = \"ab\" * 0\n", "");
	is(RB, "x = \"ab\" * -1\n", NULL);                                          /* an ArgumentError */
	is(RB, "x = \"ab\" * \"2\"\n", NULL);
	is(RB, "x = \"a\" + \"b\" * 2\n", "abb");
	is(RB, "x = \"Ab\".downcase.reverse\n", "ba");                              /* no brackets, chained */
	is(RB, "x = \"abc\".upcase!\n", NULL);                                       /* the one that changes its receiver is another method */
}

/* ---- powershell: .NET and about_Operators ---------------------------------------------------- */

static void powershell(void)
{
	is(PS, "$x = 'abc' -replace 'b','X'\n", "aXc");
	is(PS, "$x = 'abc' -replace 'B','X'\n", "aXc");                              /* -replace ignores case */
	is(PS, "$x = 'abc' -creplace 'B','X'\n", "abc");
	is(PS, "$x = 'abc' -ireplace 'B','X'\n", "aXc");
	is(PS, "$x = 'a-b-c' -replace '-'\n", "abc");                                /* no replacement removes the match */
	is(PS, "$x = 'a-b' -replace '-', ' '\n", "a b");
	is(PS, "$x = 'a.b' -replace '.','x'\n", NULL);                               /* a regular expression */
	is(PS, "$x = 'a b' -replace '\\s','x'\n", NULL);
	is(PS, "$x = 'abc' -replace 'b','$1'\n", NULL);                              /* a group */
	is(PS, "$x = 'abc' -replace '','x'\n", NULL);                                /* matches everywhere */
	is(PS, "$x = 'x\xc3\xa9' -replace 'x','y'\n", NULL);                          /* ignore case is Unicode's: the subject is ASCII */
	is(PS, "$x = 'x\xc3\xa9' -creplace 'x','y'\n", "y\xc3\xa9");                  /* ordinal: no such limit */
	is(PS, "$x = 'abc' -replace 'a','b','c'\n", NULL);                           /* three values on the right */
	is(PS, "$x = 'a' + 'b' -replace 'a','c'\n", "cb");                           /* looser than the join */
	is(PS, "$x = 'xa' -replace 'x','a' -replace 'a','b'\n", "bb");               /* left to right */
	is(PS, "$x = 'x' -replace 'x','a' + 'b'\n", NULL);                           /* ('x','a') + 'b' is an array sum */
	is(PS, "$x = 'xaby' -replace 'a' + 'b'\n", "xy");                           /* a lone right side is a join: the pattern is 'ab' */
	is(PS, "$x = 'xaby' -replace 'a' + 'b', 'c'\n", NULL);                       /* with a comma the ',' binds tighter: ('a') + ('b','c') */
	is(PS, "$x = 'a-b'.Replace('-', '+')\n", "a+b");
	is(PS, "$x = 'AbC'.Replace('b', 'x')\n", "AxC");                              /* ordinal */
	is(PS, "$x = 'abc'.Replace('', 'x')\n", NULL);                               /* an ArgumentException */
	is(PS, "$x = 'abcdef'.Substring(1, 3)\n", "bcd");
	is(PS, "$x = 'abcdef'.Substring(2)\n", "cdef");
	is(PS, "$x = 'abcdef'.Substring(6)\n", "");
	is(PS, "$x = 'abcdef'.Substring(7)\n", NULL);                                /* an exception, not a clamp */
	is(PS, "$x = 'abcdef'.Substring(1, 6)\n", NULL);
	is(PS, "$x = 'abcdef'.Substring(-1)\n", NULL);
	is(PS, "$x = 'ABC'.ToLower()\n", "abc");
	is(PS, "$x = 'ABCI'.ToLower()\n", NULL);                                     /* the Turkish culture lowers I to a dotless i */
	is(PS, "$x = 'abci'.ToUpper()\n", NULL);
	is(PS, "$x = 'ABCI'.ToLowerInvariant()\n", "abci");
	is(PS, "$x = 'abci'.ToUpperInvariant()\n", "ABCI");
	is(PS, "$x = \"  a \".Trim()\n", "a");
	is(PS, "$x = \"  a \".TrimStart()\n", "a ");
	is(PS, "$x = \"  a \".TrimEnd()\n", "  a");
	is(PS, "$x = '  a '.Trim(' ')\n", NULL);                                     /* an argument is a set of characters */
	is(PS, "$x = 'a-b'.Split('-')\n", NULL);                                     /* a list */
	is(PS, "$x = 'a-b'.Split('-')[0]\n", NULL);
	is(PS, "$x = 'a,b' -split ',' -join '-'\n", "a-b");
	is(PS, "$x = 'a1b' -split '1' -join '+'\n", "a+b");
	is(PS, "$x = 'aXb' -split 'x' -join '+'\n", "a+b");                          /* -split ignores case */
	is(PS, "$x = 'aXb' -csplit 'x' -join '+'\n", "aXb");                         /* case-sensitive: nothing to cut, and the join of a list of one is that one */
	is(PS, "$x = 'a.b' -split '.' -join '+'\n", NULL);
	is(PS, "$x = ('a','b') -join ''\n", "ab");
	is(PS, "$x = @('a','b') -join '-'\n", "a-b");
	is(PS, "$x = ('a','b','c') -join ','\n", "a,b,c");
	is(PS, "$x = -join ('x','y')\n", "xy");
	is(PS, "$x = [string]::Join(',', 'a', 'b')\n", "a,b");
	is(PS, "$x = [string]::Join('', ('a','b'))\n", "ab");
	is(PS, "$x = [string]::Join(',', 'a', 1)\n", NULL);
	is(PS, "$x = [string]::Join(',', 'x', ('a','b'))\n", NULL);                   /* strings beside a list: an object array of two, not read */
	is(PS, "$x = [string]::Join(',', ('a','b'), 'x')\n", NULL);
	is(PS, "$x = ('a','b') -join 1\n", NULL);
	is(PS, "$x = 'a' + [char]66\n", "aB");
	is(PS, "$x = 'a' + [char]66 + 'c'\n", "aBc");
	is(PS, "$x = [char]65 + 'b'\n", NULL);                                       /* a character plus a string: not read */
	is(PS, "$x = [char]65 + [char]66\n", NULL);                                  /* the number 131 */
	is(PS, "$x = [char]65\n", NULL);                                             /* a lone character is not a string and is not written as one */
	is(PS, "$x = 'a' + [char]'66'\n", NULL);                                     /* a string where the cast wants a number */
	is(PS, "$x = 'a' + [char]65536\n", NULL);
}

/* ---- lua ---------------------------------------------------------------------------------------- */

static void lua(void)
{
	/* the form: string.reverse, lower, upper and sub are rewritten like php's str_replace; rep (a banner's line) and gsub (two values) are the evaluator's alone */
	form_is(LU, "x = string.upper(\"ab\")\n", "x='AB'");
	form_is(LU, "x = string.sub(\"abcdef\", 2, 4)\n", "x='bcd'");
	form_is(LU, "x = string.rep(\"-\", 40)\n", "x=string.rep(\"-\",40)");
	form_is(LU, "print(string.gsub(\"abc\", \"b\", \"X\"))\n", "print(string.gsub(\"abc\",\"b\",\"X\"))");
	is(LU, "x = string.rep(\"ab\", 3)\n", "ababab");
	is(LU, "x = string.rep(\"ab\", 0)\n", "");
	is(LU, "x = string.rep(\"ab\", -2)\n", "");                                  /* a count below 1 is the empty string in lua */
	is(LU, "x = string.rep(\"ab\", 2, \",\")\n", NULL);                          /* the separator is a third argument */
	is(LU, "x = string.reverse(\"abc\")\n", "cba");
	is(LU, "x = string.lower(\"AbC\") .. string.upper(\"d\")\n", "abcD");
	is(LU, "x = string.upper(\"\xc3\xa9\")\n", NULL);
	is(LU, "x = string.sub(\"abcdef\", 2, 4)\n", "bcd");                         /* from 1, to 4 INCLUDED */
	is(LU, "x = string.sub(\"abcdef\", 2)\n", "bcdef");
	is(LU, "x = string.sub(\"abcdef\", 3, 3)\n", "c");
	is(LU, "x = string.sub(\"abcdef\", 4, 2)\n", "");
	is(LU, "x = string.sub(\"abcdef\", 2, 100)\n", "bcdef");
	is(LU, "x = string.sub(\"abcdef\", 7)\n", "");
	is(LU, "x = string.sub(\"abcdef\", 0)\n", NULL);                             /* lua reads 0 as 1 */
	is(LU, "x = string.sub(\"abcdef\", -2)\n", NULL);                            /* from the end in lua */
	is(LU, "x = string.sub(\"abcdef\", 2, -1)\n", NULL);
	is(LU, "x = string.sub(\"abcdef\", 2, 0)\n", "");
	/* gsub answers two values: read where one is taken */
	is(LU, "x = (string.gsub(\"abc\", \"b\", \"X\"))\n", "aXc");
	is(LU, "x = string.gsub(\"abc\", \"b\", \"X\") .. \"!\"\n", "aXc!");
	is(LU, "x = \"!\" .. string.gsub(\"abc\", \"b\", \"X\")\n", "!aXc");
	is(LU, "x = string.gsub(\"abc\", \"b\", \"X\")\n", NULL);                    /* `x, n = ...` would give n the count */
	is(LU, "x = f(string.gsub(\"abc\", \"b\", \"X\"))\n", NULL);                  /* the last argument spreads both */
	is(LU, "x = (string.gsub(\"a.c\", \"%.\", \"X\"))\n", NULL);                  /* a pattern with a magic character */
	is(LU, "x = (string.gsub(\"abc\", \"b\", \"%1\"))\n", NULL);                  /* "%" in the replacement */
	is(LU, "x = (string.gsub(\"abc\", \"\", \"X\"))\n", NULL);
	is(LU, "x = (string.gsub(\"aaa\", \"a\", \"b\"))\n", "bbb");
	is(LU, "x = (\"abc\"):rep(2)\n", NULL);                                      /* the method syntax is not read */
}

/* ---- vbscript ------------------------------------------------------------------------------------ */

static void vbscript(void)
{
	is(VB, "x = Left(\"abcdef\", 2)\n", "ab");
	is(VB, "x = Left(\"abc\", 5)\n", "abc");
	is(VB, "x = Left(\"abc\", 0)\n", "");
	is(VB, "x = Left(\"abc\", -1)\n", NULL);                                     /* an error */
	is(VB, "x = Right(\"abcdef\", 2)\n", "ef");
	is(VB, "x = Right(\"abc\", 5)\n", "abc");
	is(VB, "x = Right(\"abc\", 0)\n", "");
	is(VB, "x = Right(\"abc\", -1)\n", NULL);
	is(VB, "x = Left(\"\xc3\xa9" "bc\", 1)\n", NULL);                             /* characters, not bytes */
	is(VB, "x = Trim(\"  a  \")\n", "a");
	is(VB, "x = LTrim(\"  a  \")\n", "a  ");
	is(VB, "x = RTrim(\"  a  \")\n", "  a");
	is(VB, "x = Trim(\"\ta\t\")\n", "\ta\t");                                    /* a tab is not white space to Trim */
	is(VB, "x = StrReverse(\"abc\")\n", "cba");
	is(VB, "x = StrReverse(\"\xc3\xa9" "b\")\n", NULL);
	is(VB, "x = String(3, \"z\")\n", "zzz");
	is(VB, "x = String(0, \"z\")\n", "");
	is(VB, "x = String(-1, \"z\")\n", NULL);
	is(VB, "x = String(3, \"zy\")\n", NULL);                                     /* only the first character is used: not read */
	is(VB, "x = String(3, 65)\n", NULL);                                         /* a character code: not read */
	is(VB, "x = \"a\" & String(2, \"b\") & \"c\"\n", "abbc");
	/* the form rewrites a call on literals by name; String is the evaluator's alone */
	form_is(VB, "x = Left(\"abcdef\", 2) & Right(\"abcdef\", 2)\n", "x=\"abef\"");
	form_is(VB, "x = Trim(\"  a \") & StrReverse(\"abc\")\n", "x=\"acba\"");
	form_is(VB, "x = String(3, \"z\")\n", "x=String(3,\"z\")");
	is(VB, "x = \"a\" & \"b\"\n", "ab");
}

/* ---- php: implode and explode through the same ops ---------------------------------------------- */

static void php(void)
{
	is(PH, "<?php $x = implode(\",\", array(\"a\", \"b\"));\n", "a,b");
	is(PH, "<?php $x = join(\"-\", [\"a\", \"b\", \"c\"]);\n", "a-b-c");
	is(PH, "<?php $x = implode(array(\"p\", \"q\"));\n", "pq");
	is(PH, "<?php $x = implode(\",\", explode(\" \", \"a b c\"));\n", "a,b,c");
	is(PH, "<?php $x = implode(\"\", explode(\"x\", \"axbxc\"));\n", "abc");
	is(PH, "<?php $x = implode(\",\", array());\n", "");
	is(PH, "<?php $x = implode(\",\", array(\"a\", 1));\n", "a,1");
	is(PH, "<?php $x = implode(\",\", array(\"a\", $y));\n", NULL);
	is(PH, "<?php $x = explode(\",\", \"a,b\");\n", NULL);                       /* a list is no value */
	is(PH, "<?php $x = explode(\"\", \"abc\");\n", NULL);                        /* a ValueError */
	is(PH, "<?php $x = implode(\",\", explode(\"\", \"abc\"));\n", NULL);
	is(PH, "<?php $x = implode(\",\", array(\"k\" => \"a\"));\n", NULL);         /* keys: not read */
}

/* ---- the form's call stage reads CALL rows only ---------------------------------------------- */

/* A row of a name shorter than three bytes (perl's lc, uc) would switch the form's call stage off if it were in the form's table: perl's chr is still rewritten. */
static void form_stage(void)
{
	form_is(PL, "$x = chr(104) . chr(105);\n", "$x='h'.'i';");        /* the calls are rewritten; perl's row has no join byte, so the "." stays */
	form_is(PL, "$x = lc(\"AB\");\n", "$x=lc(\"AB\");");                          /* the evaluator's, not the form's */
	form_is(JS, "var x = \"a-b\".replace(\"-\", \"+\");\n", "var x=\"a-b\".replace(\"-\",\"+\");");   /* a method is no call of a name */
}

/* ---- the reading --------------------------------------------------------------------------------- */

static void reading(void)
{
	/* precedence */
	is(PY, "x = \"a\" + \"b\" * 2\n", "abb");
	is(PY, "x = (\"a\" + \"b\") * 2\n", "abab");
	is(PY, "x = \"a\" * 2 + \"b\"\n", "aab");
	is(PY, "x = 2 * 3\n", NULL);
	is(PY, "x = \"ab\" * 2 * 2\n", "abababab");
	is(PL, "$x = uc(\"x\") . \"y\" x 2;\n", "Xyy");
	is(PL, "$x = (\"ab\") x 3;\n", NULL);                                        /* a bracket in front makes it list repetition */
	is(PL, "$x = \"ab\" x -1;\n", "");
	/* a list left over is no value, and one consumed is the join's */
	is(PY, "x = [\"a\", \"b\"]\n", NULL);
	is(PY, "x = [\"a\"] + [\"b\"]\n", NULL);
	is(PY, "x = \"-\".join([\"a\", \"b\"])\n", "a-b");
	is(PY, "x = \"-\".join((\"a\", \"b\"))\n", "a-b");                           /* a tuple */
	is(PY, "x = \"-\".join(\"abc\")\n", NULL);                                   /* the characters of a str: not a list */
	is(PY, "x = \"-\".join([\"a\", \"b\"]).upper()\n", "A-B");
	is(PY, "x = \"a b\".split(\" \")\n", NULL);
	/* a method on a str of the program, and nothing else */
	is(PY, "x = b\"ab\".replace(b\"a\", b\"c\")\n", NULL);
	is(PY, "x = 5 .replace(\"a\", \"b\")\n", NULL);
	/* the literals changed where they stand: in a call, a condition, a statement - and an assignment's other terms stay */
	{
		static const char src[] = "f(\"a-b\".replace(\"-\", \"\"), g(\"X\".lower()))\nif (\"Abc\".lower() == y) {}\nz = y + \"abc\".upper() + \"d\"\nw = \"abc\".foo()\n";
		struct cset s;
		uint8_t *t = NULL;
		uint32_t w;

		consts_of(PY, (const uint8_t *)src, strlen(src), &s);
		w = consts_text(PY, (const uint8_t *)src, strlen(src), &s, &t);
		NCKF(s.n == 4u && w && !memcmp(t, "f('ab', g('x'))\nif ('abc' == y) {}\nz = y + 'ABC' + \"d\"\nw = \"abc\".foo()\n", w), "literals changed where they stand: %u values, [%.*s]", s.n, (int)w, t ? (char *)t : "");
		free(t);
		cset_free(&s);
	}
	/* a character is no string; a gsub's two values are one only where one is taken (above); no brackets only where the row says so */
	is(JS, "x = \"abc\".toUpperCase\n", NULL);
	is(RB, "x = \"abc\".upcase\n", "ABC");
}

/* The bounds: a program chooses how deep it nests, how long a chain is and how much a repeat or a split makes; none may crash the walk or run away, and past one the answer is "no value". */
static void bounds(void)
{
	size_t k, cap = 1u << 20;
	char *t = malloc(cap);
	unsigned n;
	struct cset s;
	char *r;

	/* nesting: a method whose argument is another, 20 deep, is read; 400 deep is past the evaluator's bound (256), which it says (cut), and is not a crash */
	for (k = 0; k < 2; k++) {
		unsigned depth = k ? 400u : 20u, i;
		size_t w = 0;

		w += (size_t)snprintf(t + w, cap - w, "x = ");
		for (i = 0; i < depth; i++)
			w += (size_t)snprintf(t + w, cap - w, "\"a\".replace(\"a\", ");
		w += (size_t)snprintf(t + w, cap - w, "\"a\"");
		for (i = 0; i < depth; i++)
			w += (size_t)snprintf(t + w, cap - w, ")");
		w += (size_t)snprintf(t + w, cap - w, "\n");
		consts_of(JS, (const uint8_t *)t, w, &s);
		if (!k)
			NCKF(s.n >= 1u && s.c[0].n == 1u && s.c[0].v[0] == 'a', "20 nested methods: %u values", s.n);
		else
			NCKF(s.cut > 0u, "400 nested methods: the bound said nothing (cut %u, %u values)", s.cut, s.n);
		cset_free(&s);
	}
	/* a long chain is a loop, not recursion: 5000 methods in a row are read */
	{
		size_t w = 0;
		unsigned i;

		w += (size_t)snprintf(t + w, cap - w, "x = \"AbC\"");
		for (i = 0; i < 5000u; i++)
			w += (size_t)snprintf(t + w, cap - w, ".toLowerCase()");
		w += (size_t)snprintf(t + w, cap - w, "\n");
		r = eval1(JS, t, &n);
		NCKF(r && !strcmp(r, "abc"), "5000 methods in a chain: [%s]", r ? r : "nothing");
		free(r);
	}
	/* what a repeat makes is bounded by the evaluator's value limit (a megabyte), a list by the same */
	r = eval1(JS, "x = \"ab\".repeat(100000)\n", &n);
	NCKF(r && strlen(r) == 200000u, "200 KB by repeat: %zu", r ? strlen(r) : 0);
	free(r);
	r = eval1(JS, "x = \"ab\".repeat(1000000)\n", &n);
	NCKF(!r, "2 MB by repeat is past the limit");
	free(r);
	r = eval1(JS, "x = \"ab\".repeat(4000000000)\n", &n);
	NCKF(!r, "four billion repeats");
	free(r);
	r = eval1(JS, "x = \"a\".repeat(300000).split(\"a\").join(\"-\")\n", &n);
	NCKF(!r, "a split of 300000 pieces is a list past the limit");
	free(r);
	r = eval1(JS, "x = \"a\".repeat(1000).split(\"a\").join(\"-\")\n", &n);
	NCKF(r && strlen(r) == 1000u, "a split of 1001 pieces and its join: %zu", r ? strlen(r) : 0);
	free(r);
	free(t);
}

/* The rows themselves: which shapes each language's table has, and that no language says reverse of perl. */
static void tables(void)
{
	struct kgenome_textual_fn f;
	const char *name;
	uint32_t k, n = 0;

	NCK(kgenome_textual_fn_shapes(PH) == 1u);                                    /* php: calls only */
	NCK((kgenome_textual_fn_shapes(JS) & (1u << KGENOME_TEXTUAL_SHAPE_METHOD)) != 0);
	NCK((kgenome_textual_fn_shapes(PY) & (1u << KGENOME_TEXTUAL_SHAPE_SUFFIX)) != 0);
	NCK((kgenome_textual_fn_shapes(PS) & (1u << KGENOME_TEXTUAL_SHAPE_CAST)) != 0);
	NCK((kgenome_textual_fn_shapes(PL) & (1u << KGENOME_TEXTUAL_SHAPE_OP)) != 0);
	NCK(kgenome_textual_fn_shapes(KGENOME_TEXTUAL_LANG_ASP) == 0u);                  /* asp: vbscript or jscript, the page cannot say which table */
	NCK(!kgenome_textual_fn_find(PL, (const uint8_t *)"reverse", 7u, &f));       /* context dependent: not a row */
	for (k = 0; kgenome_textual_fn_row(PS, k, &name, &f); k++)
		n++;
	NCK(n > 20u && !kgenome_textual_fn_row(PS, n, &name, &f));
	NCK(!kgenome_textual_fn_row(KGENOME_TEXTUAL_LANG_ASP, 0, &name, &f));
	/* the lookup is case-blind where the language is: powershell's method in any case, python's not */
	NCK(kgenome_textual_fn_find(PS, (const uint8_t *)".REPLACE", 8u, &f));
	NCK(!kgenome_textual_fn_find(PY, (const uint8_t *)".REPLACE", 8u, &f));
	/* a METHOD row is found by its spelling with the dot, never by the bare name a call would use */
	NCK(!kgenome_textual_fn_find(JS, (const uint8_t *)"replace", 7u, &f));
}

int main(void)
{
	tables();
	against_interpreters();
	javascript();
	ruby();
	powershell();
	lua();
	vbscript();
	php();
	form_stage();
	reading();
	bounds();
	if (skipped)
		printf("  SKIPPED: %u interpreter(s) not on this machine; the reference text cases ran\n", skipped);
	printf("script_methods: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
