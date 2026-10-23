#define _GNU_SOURCE
/*
 * script_cmds - what the evaluator of the COMMAND languages (sh, batch, tcl) says a word or an assignment comes to.
 *
 * The operations php's str_replace/substr/strrev/join do are done on the constants of a shell script, a batch file and a tcl script,
 * through the rows of each language (libgenome/textual/{sh,bat,tcl}/<lang>_fn.c) and the libuncoat ops under them. Two things are asked of
 * every text:
 *
 *   SOUND    - a constant the evaluator reports is the value the real interpreter computes. For sh the interpreter is bash, run on the very
 *              text (its answer is the oracle, never a number written by hand here).
 *   COMPLETE - what the rows describe is found: every case whose operator and operands are plain is reported.
 *
 * and the refusals: a text whose value the evaluator cannot know exactly (a glob in a pattern, `&` in a replacement, an unknown variable, a
 * name appended or assigned twice, text run by eval, a variable in a branch) gives NO constant. The refusals are in the tables with their
 * reason, so a mutant that stops refusing one is caught by a line that says what it let through.
 *
 * batch and tcl: tclsh and cmd.exe are not on the machine that built these tests, so their expected values are written by hand from the
 * documented semantics and are [Unverified] against the real interpreters. The quirks the batch rows rely on are listed at the table.
 * The ops under the rows (string map, format, join of a list) are checked against python and a written reference in strfn_shell.c.
 *
 * Every table's LAST line is the one asked about; the earlier lines are the setup.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "../lib/interp_oracle.h"
#include "normalizer_consts.h"

static unsigned ok_n, fails;

#define CK(c, ...) do { if (c) { ok_n++; } else { fails++; if (fails <= 60u) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

#define SH   KGENOME_TEXTUAL_LANG_SH
#define BAT  KGENOME_TEXTUAL_LANG_BAT
#define TCL  KGENOME_TEXTUAL_LANG_TCL

/* The first constant reported at or after the start of the LAST line of the text (`src` is NUL-terminated and ends in a newline), or NULL. */
static const struct one *last_const(const struct cset *s, const char *src)
{
	size_t n = strlen(src);
	const char *at = src + n;
	unsigned i;

	if (n)
		at--;                                   /* the final newline */
	while (at > src && at[-1] != '\n')
		at--;
	for (i = 0; i < s->n; i++)
		if (s->c[i].off >= (uint32_t)(at - src))
			return &s->c[i];
	return NULL;
}

static int is_value(const struct one *c, const char *want, size_t wn)
{
	return c && c->n == wn && !memcmp(c->v, want, wn);
}

/* ---- sh: bash is the oracle ---------------------------------------------------------------------------------------- */

struct shcase {
	const char *pre;        /* the lines before the last */
	const char *rhs;        /* what follows `vres=` on the last */
	int        must;        /* 1: the rows describe it, the evaluator must report it; 0: it may refuse, but never report a wrong value */
	const char *why;
};

static char *sh_text(const struct shcase *c)
{
	char *t = malloc(strlen(c->pre) + strlen(c->rhs) + 32u);

	sprintf(t, "%svres=%s\n", c->pre, c->rhs);
	return t;
}

#define CHUNK 300u

/* bash's answer for texts[0..n): one "[value]" line per text, "[!]" when the text makes bash fail. NULL when bash is not here. */
static char **bash_values(char *const *texts, unsigned n)
{
	char **v = calloc(n, sizeof *v);
	unsigned from;

	for (from = 0; from < n; from += CHUNK) {
		unsigned to = from + CHUNK < n ? from + CHUNK : n, i;
		size_t cap = 1u << 16, w = 0;
		char *scr = malloc(cap), *out, *at;

		for (i = from; i < to; i++) {
			const char *p;
			size_t need = strlen(texts[i]) * 5u + 256u;

			if (w + need > cap) {
				cap = (w + need) * 2u;
				scr = realloc(scr, cap);
			}
			/* each text is a script of its own: bash -c of it, then the value of vres is printed */
			w += (size_t)sprintf(scr + w, "r=$(bash -c '");
			for (p = texts[i]; *p; p++) {
				if (*p == '\'')
					w += (size_t)sprintf(scr + w, "'\\''");
				else
					scr[w++] = *p;
			}
			w += (size_t)sprintf(scr + w, "\nprintf %%s \"$vres\"' </dev/null 2>/dev/null) || r=!\nprintf '[%%s]@@\\n' \"$r\"\n");
		}
		scr[w] = 0;
		out = run_script(2, scr);
		free(scr);
		if (!out) {
			for (i = 0; i < n; i++)
				free(v[i]);
			free(v);
			return NULL;
		}
		at = out;
		for (i = from; i < to; i++) {            /* "[value]@@" and a line break: the value may hold line breaks of its own */
			char *end = strstr(at, "]@@\n");

			if (!end || *at != '[')
				break;
			*end = 0;
			v[i] = strdup(at + 1);
			at = end + 4;
		}
		free(out);
	}
	return v;
}

static void sh_check(const struct shcase *cs, unsigned n, const char *tag)
{
	char **texts = malloc(n * sizeof *texts), **want;
	unsigned i, found = 0, must = 0, missed = 0, wrong = 0;

	for (i = 0; i < n; i++)
		texts[i] = sh_text(&cs[i]);
	want = bash_values(texts, n);
	if (!want) {
		printf("  %s: bash is not available, %u cases skipped\n", tag, n);
		goto done;
	}
	for (i = 0; i < n; i++) {
		struct cset s;
		const struct one *c;

		if (!want[i])
			continue;
		consts_of(SH, (const uint8_t *)texts[i], strlen(texts[i]), &s);
		c = last_const(&s, texts[i]);
		if (!strcmp(want[i], "!")) {            /* bash itself fails on the text: any value would be a lie */
			CK(!c, "%s: `%s` makes bash fail and was reported as '%.*s'  [%s]", tag, cs[i].rhs, c ? (int)c->n : 0, c ? (const char *)c->v : "", cs[i].why);
			cset_free(&s);
			continue;
		}
		if (c) {
			found++;
			if (!is_value(c, want[i], strlen(want[i]))) {
				wrong++;
				CK(0, "%s: SOUND: `%s` reported '%.*s', bash says '%s'  [%s]", tag, cs[i].rhs, (int)c->n, (const char *)c->v, want[i], cs[i].why);
			}
		}
		if (cs[i].must) {
			must++;
			if (!c) {
				missed++;
				CK(0, "%s: COMPLETE: `%s` after `%s` was not reported (bash says '%s')  [%s]", tag, cs[i].rhs, cs[i].pre, want[i], cs[i].why);
			}
		}
		cset_free(&s);
	}
	printf("  %s: %u cases, %u reported (%u wrong), %u of %u expected found\n", tag, n, found, wrong, must - missed, must);
done:
	for (i = 0; i < n; i++) {
		free(texts[i]);
		if (want)
			free(want[i]);
	}
	free(texts);
	free(want);
}

/* ---- sh: generated operator cases ---------------------------------------------------------------------------------- */

static uint64_t seed = 0x5eed1234abcdULL;
static unsigned rnd(unsigned m)
{
	seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
	return (unsigned)(seed >> 33) % m;
}

static void rstr(char *o, const char *alpha, unsigned minl, unsigned maxl)
{
	unsigned n = minl + rnd(maxl - minl + 1u), i, na = (unsigned)strlen(alpha);

	for (i = 0; i < n; i++)
		o[i] = alpha[rnd(na)];
	o[n] = 0;
}

#define GEN 3000u

static void sh_generated(void)
{
	static struct shcase cs[GEN];
	static char store[GEN][2][96];
	unsigned i;

	for (i = 0; i < GEN; i++) {
		char x[40], p[8], r[8], *pre = store[i][0], *rhs = store[i][1];
		unsigned op = i % 13u, o = rnd(12), l = rnd(10);

		rstr(x, "abAB-./_01", 0, 14);
		rstr(p, "abAB-.01", 1, 3);   /* no "/" in a pattern: where the pattern ends is the shell's ambiguity, refused (listed in the fixed cases) */
		rstr(r, "abAB-./01", 0, 3);
		sprintf(pre, "vx=\"%s\"\n", x);
		switch (op) {
		case 0:  sprintf(rhs, "${vx//%s/%s}", p, r); break;
		case 1:  sprintf(rhs, "${vx/%s/%s}", p, r); break;
		case 2:  sprintf(rhs, "${vx#%s}", p); break;
		case 3:  sprintf(rhs, "${vx##%s}", p); break;
		case 4:  sprintf(rhs, "${vx%%%s}", p); break;
		case 5:  sprintf(rhs, "${vx%%%%%s}", p); break;
		case 6:  sprintf(rhs, "${vx:%u:%u}", o, l); break;
		case 7:  sprintf(rhs, "${vx:%u}", o); break;
		case 8:  sprintf(rhs, "${vx^^}"); break;
		case 9:  sprintf(rhs, "${vx,,}"); break;
		case 10: sprintf(rhs, "${#vx}"); break;
		case 11: sprintf(rhs, "\"a${vx//%s/%s}b\"", p, r); break;       /* the literal pieces around an expansion */
		default: sprintf(rhs, "${vx: -%u}", 1u + o % 6u); break;         /* a negative offset needs the space */
		}
		cs[i] = (struct shcase){ pre, rhs, 1, "generated" };
	}
	sh_check(cs, GEN, "sh generated operators");
}

/* ---- sh: fixed cases ----------------------------------------------------------------------------------------------- */

static void sh_fixed(void)
{
	static const struct shcase ok[] = {
		/* assignments and reads */
		{ "vx=hello\n",                        "$vx", 0, "a bare read is not built: nothing to tell (told, it is right)" },
		{ "vx=hello\n",                        "${vx}", 0, "a bare read is not built (told, it is right)" },
		{ "vx=hello\n",                        "\"$vx world\"", 1, "a read inside quotes" },
		{ "vx=hello\n",                        "'lit'$vx\"q\"", 1, "adjacent literal pieces" },
		{ "vx=a\nvy=b\n",                      "$vx$vy", 1, "two reads side by side" },
		{ "vx=a\nvy=${vx}b\n",                 "${vy}c", 1, "a name built from a name" },
		{ "export vx=hello\n",                 "${vx^^}", 0, "export: children read it, we may refuse" },
		{ "readonly vx=hello\n",               "${vx^^}", 1, "readonly" },
		{ "vx='a b'\n",                        "\"${vx// /_}\"", 1, "a space in the value, quoted read" },
		{ "vx=abcabc\n",                       "${vx//b/}", 1, "replace by nothing" },
		{ "vx=abcabc\n",                       "${vx//b}", 1, "no replacement part: delete" },
		{ "vx=abcabc\n",                       "${vx/b/ZZ}", 1, "replace the first" },
		{ "vx=abcabc\n",                       "${vx#ab}", 1, "cut a head" },
		{ "vx=abcabc\n",                       "${vx##abc}", 1, "cut the longest head, plain" },
		{ "vx=abcabc\n",                       "${vx%bc}", 1, "cut a tail" },
		{ "vx=abcabc\n",                       "${vx%%abc}", 1, "cut the longest tail, plain" },
		{ "vx=abcabc\n",                       "${vx:2:3}", 1, "slice" },
		{ "vx=abcabc\n",                       "${vx:4}", 1, "slice to the end" },
		{ "vx=abcabc\n",                       "${vx: -3}", 1, "slice from the end" },
		{ "vx=abcabc\n",                       "${vx: -3:2}", 1, "slice from the end, length" },
		{ "vx=abcabc\n",                       "${vx:0:99}", 1, "length past the end" },
		{ "vx=abcabc\n",                       "${vx:9}", 1, "offset past the end" },
		{ "vx=abcABC\n",                       "${vx^^}", 1, "upper" },
		{ "vx=abcABC\n",                       "${vx,,}", 1, "lower" },
		{ "vx=abcABC\n",                       "${#vx}", 1, "length" },
		{ "vx=abc\n",                          "${vx//b/${vx}}", 0, "an expansion inside the replacement: may refuse" },
		/* command substitution of pure string functions */
		{ "",                                  "$(printf '%s' abc)", 1, "printf %s" },
		{ "",                                  "$(printf %s abc def)", 1, "printf reuses its format" },
		{ "",                                  "$(printf '%s-%s' a b)", 1, "printf with two" },
		{ "",                                  "$(printf 'a\\tb')", 1, "printf escapes" },
		{ "",                                  "$(printf '%s\\n' abc)", 1, "trailing newline stripped" },
		{ "",                                  "$(echo -n abc)", 1, "echo -n" },
		{ "",                                  "$(echo abc)", 1, "echo, newline stripped" },
		{ "",                                  "$(echo abc | rev)", 1, "rev" },
		{ "",                                  "$(echo abc | tr a-z A-Z)", 1, "tr ranges" },
		{ "",                                  "$(echo abc | tr abc xyz)", 1, "tr sets" },
		{ "",                                  "$(echo aabbcc | tr -d b)", 0, "tr -d is a delete, not a translate: no row" },
		{ "",                                  "$(printf %s abc | rev | tr a-z A-Z)", 1, "a pipeline of two filters" },
		{ "vx=abc\n",                          "$(printf %s \"$vx\" | rev)", 1, "a read as the producer's argument" },
		{ "",                                  "`echo -n abc | rev`", 1, "backticks" },
		{ "",                                  "x$(echo -n abc | rev)y", 1, "adjacent to a substitution" },
		{ "vx=abc\n",                          "\"$(echo \"$vx\" | tr a-c A-C)\"", 1, "a quoted substitution of a read" },
		/* what the rows do not describe: refuse; if a value is reported it is right */
		{ "vx=abc\n",                          "${vx//[ab]/Z}", 0, "glob in the pattern" },
		{ "vx=abc\n",                          "${vx//?/Z}", 0, "glob in the pattern" },
		{ "vx=abc\n",                          "${vx//*/Z}", 0, "glob in the pattern" },
		{ "vx=abc\n",                          "${vx#a*}", 0, "glob in the pattern" },
		{ "vx=abc\n",                          "${vx%?}", 0, "glob in the pattern" },
		{ "vx=abc\n",                          "${vx//b/&&}", 0, "bash 5.2: & in the replacement" },
		{ "vx=abc\n",                          "${vx//b/\\&}", 0, "bash 5.2: backslash in the replacement" },
		{ "vx=abc\n",                          "${vx:-def}", 0, "default value" },
		{ "vx=abc\n",                          "${vx:-3}", 0, "`:-` is the default operator, not an offset of -3 (bash gives abc)" },
		{ "vx=abc\n",                          "${vx:-0}", 0, "`:-` again with a number" },
		{ "vx=abc\n",                          "${vx:=3}", 0, "`:=` assigns" },
		{ "vx=abc\n",                          "${vx:+3}", 0, "`:+` alternative" },
		{ "vx=abc\n",                          "${vx:?}", 0, "`:?`" },
		{ "vx=abc\n",                          "${vx:2:-2}", 0, "negative length before the offset: bash fails" },
		{ "vx=abc\n",                          "${vx: 1}", 1, "a blank before an unsigned offset" },
		{ "vx=abc\n",                          "${vx:1: 1}", 0, "a blank before the length" },
		{ "vx=abc\n",                          "${vx:0x1}", 0, "hex offset: arithmetic" },
		{ "vx=abc\n",                          "${vx:01}", 0, "octal-looking offset: arithmetic" },
		{ "vx=abc\n",                          "${VX^^}", 0, "an unset name of another case: bash gives the empty string" },
		{ "vx=abc\n",                          "${vx/b/x/y}", 0, "a slash in the replacement" },
		{ "vx=abc\n",                          "${vx//b/'q'}", 0, "a quoted replacement" },
		{ "vx=abc\n",                          "${vx//'b'/q}", 0, "a quoted pattern" },
		{ "vx=abc\n",                          "${vx//#b/q}", 0, "an anchored pattern" },
		{ "vx=abc\n",                          "${vx/%c/q}", 0, "an anchored pattern at the end" },
		{ "vx=abc\n",                          "${!vx}", 0, "indirection" },
		{ "vx=abc\n",                          "${vx[0]}", 0, "an array element" },
		{ "vx=abc\n",                          "${#vx}${vx}", 1, "length beside a read" },
		{ "vx=abc\n",                          "${vx@U}", 0, "a transformation operator" },
		{ "vx=bbc\n",                          "${vx//#b/q}", 0, "an anchored pattern that matches (bash: qbc)" },
		{ "vx=abc\n",                          "${vx//%c/q}", 0, "an anchored pattern at the end that matches (bash: abq)" },
		{ "vx=bbc\n",                          "${vx/#b/q}", 0, "an anchored pattern, first" },
		{ "vx=abc\n",                          "${vx///x}", 0, "an empty pattern" },
		{ "vx=abcABC\n",                       "${vx^}", 1, "upper-case the first" },
		{ "vx=ABCabc\n",                       "${vx,}", 1, "lower-case the first" },
		{ "vx=abcABC\n",                       "${vx^}${vx^^}", 1, "first and all, side by side" },
		{ "vx=abc\n",                          "${vx:1:-1}", 0, "negative length" },
		{ "vx=abc\n",                          "${vx:$vx}", 0, "an offset that is a read" },
		{ "vx=abc\n",                          "$((1+2))", 0, "arithmetic" },
		{ "vx=abc\n",                          "$'\\x41'", 0, "ansi-c quoting" },
		{ "vx=abc\n",                          "~root", 0, "tilde" },
		{ "vx=abc\n",                          "{a,b}", 0, "brace expansion" },
		{ "vx=abc\n",                          "$1", 0, "positional parameter" },
		{ "vx=abc\n",                          "$unknownvar", 0, "a name never assigned" },
		{ "",                                  "$(date)", 0, "a command that is not a string function" },
		{ "",                                  "$(printf '%d' 5)", 0, "printf %d" },
		{ "",                                  "$(printf '%s')", 0, "printf with no argument for %s" },
		{ "",                                  "$(echo abc | tr 'a-' 'xy')", 0, "tr with a dash at the end" },
		{ "",                                  "$(echo abc | tr '[:lower:]' '[:upper:]')", 0, "tr classes" },
		{ "",                                  "$(echo abc | tr -s a)", 0, "tr -s" },
		{ "",                                  "$(echo abc >/dev/null)", 0, "a redirection" },
		{ "",                                  "$(echo abc && echo def)", 0, "an and-list" },
		{ "",                                  "$(echo abc || echo def)", 0, "an or-list" },
		{ "",                                  "$(echo abc &)", 0, "a background job" },
		{ "",                                  "$(echo -e 'a\\tb')", 0, "echo -e reads backslashes" },
		{ "",                                  "$(echo -ne x)", 0, "echo -ne reads backslashes too" },
		{ "",                                  "$(echo -n -n abc)", 1, "echo -n twice" },
		{ "",                                  "$(echo -nn abc)", 1, "echo -nn" },
		{ "",                                  "$(echo -- abc)", 0, "echo -- prints the two dashes in bash" },
		{ "",                                  "$(echo -x abc)", 0, "echo -x prints -x" },
		{ "",                                  "$(echo -n)", 0, "echo with nothing" },
		{ "",                                  "$(printf -- %s abc)", 0, "printf with an option-looking first word" },
		{ "",                                  "$(printf '%5s' abc)", 0, "printf with a width" },
		{ "",                                  "$(printf '%s %s' a)", 0, "printf with too few arguments for one pass" },
		{ "",                                  "$(printf '%s' 'a b')", 1, "printf of an argument with a space" },
		{ "",                                  "$(printf '%%')", 1, "printf %%" },
		{ "",                                  "$(printf '\\x41')", 0, "printf escapes beyond \\n \\t \\\\" },
		{ "",                                  "$(printf '%b' 'a\\tb')", 0, "printf %b" },
		{ "",                                  "$(echo abc | rev | rev)", 1, "rev twice" },
		{ "",                                  "$(rev)", 0, "a filter with no producer reads the script's own input" },
		{ "",                                  "$(tr a b)", 0, "tr with no producer" },
		{ "",                                  "$(printf %s -abc | rev)", 1, "a filter's input may start with a dash (it is no option of the filter)" },
		{ "",                                  "$(printf %s -ab | tr a-b x-y)", 1, "tr over input that starts with a dash" },
		{ "",                                  "$(printf %s abc | tr a-c A-C | rev)", 1, "tr then rev" },
		{ "",                                  "$(printf %s 'a-c' | tr 'a\\-c' 'xyz')", 0, "tr with an escape" },
		{ "",                                  "$(printf %s abc | tr abc xy)", 0, "tr with sets of unequal length" },
		{ "",                                  "$(printf %s abc | tr c-a x)", 0, "tr with a reversed range" },
		{ "",                                  "$(printf %s 'a-' | tr -- '-' x)", 0, "tr with an option-looking set" },
		{ "",                                  "$(printf %s 'a-' | tr '-a' xy)", 0, "tr with a leading dash (an option for GNU tr)" },
		{ "",                                  "$(printf %s 'a-' | tr 'a-' xy)", 0, "tr with a trailing dash (GNU)" },
		{ "",                                  "$(printf 'a\\nb\\n' | rev)", 0, "rev of a subject with a line break" },
		{ "",                                  "$(tr a b)", 0, "tr with no input" },
		{ "",                                  "$(rev)", 0, "rev with no input" },
		{ "",                                  "$(echo abc; echo def)", 0, "two commands" },
	};
	/* a name that is not trusted: assigned twice, appended, written by something not read, or text run */
	static const struct shcase no[] = {
		{ "vx=a\nvx=b\n",                      "$vx$vx", 0, "assigned twice" },
		{ "vx=a\nvx+=b\n",                     "$vx$vx", 0, "appended" },
		{ "vx=a\nread vx\n",                   "$vx$vx", 0, "read by read" },
		{ "vx=a\neval \"vx=b\"\n",             "$vx$vx", 0, "eval runs text" },
		{ "vx=a\nf() { vx=b; }\n",             "$vx$vx", 0, "assigned in a function" },
		{ "vx=a\nif true; then vx=b; fi\n",    "$vx$vx", 0, "assigned in a branch" },
		{ "vx=a vz=1 true\n",                  "$vx$vx", 0, "an environment prefix is not an assignment of the shell" },
		{ "f() { local vx=a; }\n",             "$vx$vx", 0, "local" },
		{ "vx=a\nfor vx in 1 2; do :; done\n", "$vx$vx", 0, "a loop writes it" },
		{ "vx=a\n. ./other.sh\n",              "$vx$vx", 0, "source" },
		{ "vx=a\nexport vx=b\n",               "$vx$vx", 0, "export reassigns" },
		{ "vx=a\nwhile IFS== read vx; do :; done\n", "$vx$vx", 0, "an assignment after `while` is the loop's" },
		{ "f() {\nvx=a\n}\n",                   "$vx$vx", 0, "the only assignment is in a function body" },
		{ "(\nvx=a\n)\n",                       "$vx$vx", 0, "the only assignment is in a subshell" },
		{ "{\nvx=a\n}\n",                       "$vx$vx", 0, "the only assignment is in a brace group" },
		{ "vx=a\neval true\n",                   "$vx$vx", 0, "eval anywhere in the file" },
		{ "vx=a\nsource ./f\n",                  "$vx$vx", 0, "source anywhere in the file" },
		{ "VX=a\n",                               "$vx$vx", 0, "names are case sensitive" },
		{ "vx=a\nvx=b\n",                        "${vx}${vx}", 0, "twice, braced" },
		{ "vx=a\nvy=$vx\nvy=b\n",               "$vy$vy", 0, "the name read is assigned twice" },
	};
	unsigned i;

	sh_check(ok, sizeof ok / sizeof ok[0], "sh fixed");
	sh_check(no, sizeof no / sizeof no[0], "sh untrusted names");
	/* the second group is "no constant at all": a value of a refused name is a guess, not a wrong value */
	for (i = 0; i < sizeof no / sizeof no[0]; i++) {
		char *t = sh_text(&no[i]);
		struct cset s;
		const struct one *c;

		consts_of(SH, (const uint8_t *)t, strlen(t), &s);
		c = last_const(&s, t);
		CK(!c, "sh untrusted: `%s` after `%s` was reported as '%.*s'  [%s]", no[i].rhs, no[i].pre, c ? (int)c->n : 0, c ? (const char *)c->v : "", no[i].why);
		cset_free(&s);
		free(t);
	}
}

/* ---- sh: the shapes the source takes -------------------------------------------------------------------------------- */

static void sh_one(const char *t, unsigned want_n, const char *a, const char *b, const char *what)
{
	struct cset s;

	consts_of(SH, (const uint8_t *)t, strlen(t), &s);
	CK(s.n == want_n, "%s: %u constants, want %u", what, s.n, want_n);
	if (s.n == want_n && a)
		CK(is_value(&s.c[0], a, strlen(a)), "%s: first is '%.*s', want '%s'", what, (int)s.c[0].n, (const char *)s.c[0].v, a);
	if (s.n == want_n && b)
		CK(is_value(&s.c[1], b, strlen(b)), "%s: second is '%.*s', want '%s'", what, (int)s.c[1].n, (const char *)s.c[1].v, b);
	cset_free(&s);
}

static void sh_shapes(void)
{
	/* a command word is told where it stands */
	sh_one("vx=abcdef\necho ${vx#ab} \"q${vx:1:2}\"\n", 2, "cdef", "qbc", "word constants");
	/* an unquoted expansion that splits (a space) or globs (a star) is not one word: no value; quoted, it is */
	sh_one("vx='a b'\necho ${vx//a/c}\n", 0, NULL, NULL, "unquoted expansion with a space");
	sh_one("vx='a*'\necho ${vx//a/c}\n", 0, NULL, NULL, "unquoted expansion with a star");
	sh_one("vx='a b'\necho \"${vx//a/c}\"\n", 1, "c b", NULL, "quoted expansion with a space");
	/* a here-document body is data and the lines after it are read again: the body is neither an assignment nor a place the heredoc can swallow what follows */
	sh_one("cat <<EOF\nvx=a\nEOF\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "the line after a heredoc is read");
	sh_one("vx=a\ncat <<EOF\nvx=z\nEOF\nvr=$vx$vx\n", 0, NULL, NULL, "a body line that names the variable: the census is a raw scan (conservative)");
	sh_one("vx=a\ncat <<EOF\nvz=z\nEOF\nvr=$vx$vx\n", 1, "aa", NULL, "a body line that names another");
	sh_one("cat <<'EOF'\nvx=a\nEOF\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "a quoted delimiter");
	sh_one("cat <<\"EOF\"\nvx=a\nEOF\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "a double-quoted delimiter");
	sh_one("cat <<\\EOF\nvx=a\nEOF\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "a backslash delimiter");
	sh_one("cat <<-EOF\n\tvx=a\n\tEOF\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "<<- ends at a tab-indented delimiter");
	sh_one("cat <<EOF\n\tEOF\nEOF\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "<< does not strip tabs: the indented line is body");
	sh_one("cat <<EOF >o\nvx=a\nEOF\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "a redirection after the delimiter");
	sh_one("cat <<A <<B\nx\nA\ny\nB\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "two heredocs on one line");
	sh_one("cat <<EOF\nvx=a\nEOF\nvr=${vx}${vx}\n", 0, NULL, NULL, "a name assigned only in a heredoc body is no name");
	sh_one("cat <<EOF\n$(echo a)\nEOF\nvy=b\nvr=$vy$vy\n", 1, "bb", NULL, "a substitution in a body is data here");
	/* a comment is not a command */
	sh_one("vx=a # vx=b\nvr=$vx$vx\n", 0, NULL, NULL, "a comment that names the variable: the census is a raw scan, so the name is not trusted (conservative)");
	sh_one("vx=a # vz=b\nvr=$vx$vx\n", 1, "aa", NULL, "a comment that names another");
	sh_one("# it's a comment\nvx=a\nvr=$vx$vx\n", 1, "aa", NULL, "an apostrophe in a comment is no quote");
	sh_one("echo a # \"\nvx=a\nvr=$vx$vx\n", 1, "aa", NULL, "a quote after a comment mark is no quote");
	sh_one("echo a#b; vx=a\nvr=$vx$vx\n", 1, "aa", NULL, "a mark inside a word is no comment, and ; ends the command");
	sh_one("echo 'a # b'; vx=a\nvr=$vx$vx\n", 1, "aa", NULL, "a mark inside quotes is no comment");
	/* a variable read often is still assigned once */
	sh_one("vx=ab\nvr=$vx$vx$vx$vx$vx$vx$vx$vx$vx$vx\n", 1, "abababababababababab", NULL, "many reads");
	/* a cycle never gives a value */
	sh_one("vx=$vy\nvy=$vx\nvres=$vx$vx\n", 0, NULL, NULL, "a cycle");
	/* what is told: an operation in a word, or several quoted pieces and no read; one literal, or a read, is not built */
	sh_one("vx=abc\nvr=$vx\n", 0, NULL, NULL, "a bare read is not built");
	sh_one("echo \"ab\"'cd'\n", 1, "abcd", NULL, "two quoted pieces are one word");
	sh_one("echo 'ab'\n", 0, NULL, NULL, "one literal is not built");
	sh_one("vx=q\necho a\"b\"$vx\n", 0, NULL, NULL, "pieces with a read in a word of an argument are not told");
	sh_one("vx=abc\neval true\necho ${vx#a}\n", 0, NULL, NULL, "eval in the file: an expansion in a word is not told either");
	sh_one("vx=abc\nvx=abd\necho ${vx#a}\n", 0, NULL, NULL, "assigned twice: an expansion in a word is not told");
	sh_one("vx=abc\nvy=${vx#a}\necho ${vy%c} ${vy#b}\n", 3, "bc", "b", "a chain of two, and two words in one command");
	sh_one("vx=abc\necho ${vx#a} && echo ${vx%c}\n", 2, "bc", "ab", "two commands on one line");
	sh_one("vx=abc\necho ${vx#a}${vx%c}\n", 1, "bcab", NULL, "two expansions in one word");
	sh_one("vx=abc\nx=1 echo ${vx#a}\n", 1, "bc", NULL, "a word after an environment prefix");
	sh_one("vx=abc\nexport vy=${vx#a}\n", 1, "bc", NULL, "an assignment's own word is told once, as the value (not again as a word)");
	sh_one("vx=abc\nvy=${vx#a} echo hi\n", 0, NULL, NULL, "an environment prefix is not told");
	sh_one("vx=abc\nvy=${vx#a} echo ${vx%c}\n", 1, "ab", NULL, "the prefix is not told, the argument is");
	sh_one("vx=eecho\n${vx#e} hi\n", 0, NULL, NULL, "the command's own name is not replaced by a literal");
	sh_one("vr=$(rev)\n", 0, NULL, NULL, "a filter with no producer has no value");
	sh_one("cat <<EOF\nEOFX\nvx=a\nEOF\nvr=$vx$vx\n", 0, NULL, NULL, "a line that only begins with the delimiter does not end the body");
	sh_one("cat <<EOF\nEO\nvy=a\nEOF\nvr=$vy$vy\n", 0, NULL, NULL, "a line that is a prefix of the delimiter does not end it");
	/* the form stage: a text with no operation and no expansion reports nothing */
	sh_one("echo hello\nvx=plain\n", 0, NULL, NULL, "a plain text");
	/* a name read before it is assigned does not exist yet in the shell; still one assignment => flow-insensitive, as the other languages */
	sh_one("vx=a\nvr=\"$vx\"\"b\"\n", 1, "ab", NULL, "pieces");
}

/* ---- batch and tcl: hand-written, [Unverified] --------------------------------------------------------------------- */

/*
 * [Unverified] against cmd.exe (not on this machine). The quirks the batch rows rely on, from the documented behaviour of cmd:
 *   - `%v%` is replaced as text before the line is parsed (a macro), and `%%` is one `%` in a file; a value is whatever follows `=` up to
 *     the end of the line, TRAILING BLANKS INCLUDED; `set "v=text"` ends the value at the LAST quote of the line, the rest is ignored;
 *   - `%v:a=b%` replaces every `a` by `b`, ignoring case; `%v:a=%` deletes; `%v:*a=b%` (a star) is refused here;
 *   - `%v:~o,l%` takes l characters from offset o (a negative offset counts from the end, a negative length stops that many from the end); a
 *     start past the end is the empty text (PHP-substr reading for the rest);
 *   - `^`, `!` (delayed expansion), `%1`..`%9`, `%*` and a variable set by `set /a` or `set /p` are refused;
 *   - `call set` expands the line twice: a value with `%` or `^` is refused.
 */
struct lcase {
	const char *src;
	const char *want;       /* the value of the first constant at the last line, or NULL: none there */
	const char *why;
};

static void last_check(uint32_t lang, const char *tag, const struct lcase *c, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		struct cset s;
		const struct one *k;

		consts_of(lang, (const uint8_t *)c[i].src, strlen(c[i].src), &s);
		k = last_const(&s, c[i].src);
		if (c[i].want)
			CK(is_value(k, c[i].want, strlen(c[i].want)), "%s `%s`: got %s'%.*s', want '%s'  [%s]", tag, c[i].src, k ? "" : "(none) ", k ? (int)k->n : 0, k ? (const char *)k->v : "", c[i].want, c[i].why);
		else
			CK(!k, "%s `%s`: reported '%.*s', want nothing  [%s]", tag, c[i].src, k ? (int)k->n : 0, k ? (const char *)k->v : "", c[i].why);
		cset_free(&s);
	}
}

static void bat_cases(void)
{
	static const struct lcase t[] = {
		{ "set vsrc=hello\nset vres=%vsrc%x\n", "hellox", "adjacent literal after a read" },
		{ "set vsrc=hello\nset vres=x%vsrc%\n", "xhello", "adjacent literal before a read" },
		{ "set \"vsrc=hello\"\nset vres=%vsrc%%vsrc%\n", "hellohello", "quoted set, two reads side by side" },
		{ "set vsrc=hello\nset \"vres=%vsrc:l=L%\"\n", "heLLo", "replace" },
		{ "set vsrc=hello\nset \"vres=%vsrc:L=x%\"\n", "hexxo", "replace is case-insensitive" },
		{ "set vsrc=hello\nset \"vres=%vsrc:l=%\"\n", "heo", "replace by nothing" },
		{ "set vsrc=hello\nset \"vres=%vsrc:ll=%\"\n", "heo", "replace two bytes" },
		{ "set vsrc=hello\nset \"vres=%vsrc:~1,3%\"\n", "ell", "slice" },
		{ "set vsrc=hello\nset \"vres=%vsrc:~2%\"\n", "llo", "slice to the end" },
		{ "set vsrc=hello\nset \"vres=%vsrc:~-3%\"\n", "llo", "slice from the end" },
		{ "set vsrc=hello\nset \"vres=%vsrc:~-3,2%\"\n", "ll", "slice from the end, length" },
		{ "set vsrc=hello\nset \"vres=%vsrc:~0,-1%\"\n", "hell", "negative length" },
		{ "set vsrc=hello\nset \"vres=%vsrc:~9%\"\n", "", "start past the end" },
		{ "set vsrc=hello\nset vres=%vsrc:~1,2%%vsrc:~3,2%\n", "ello", "two slices side by side" },
		{ "set vsrc=hello\nset vmid=%vsrc:l=L%\nset \"vres=%vmid:~1,3%\"\n", "eLL", "a chain" },
		{ "set vsrc=abc \nset vres=%vsrc%x\n", "abc x", "the trailing blank of a value is kept" },
		{ "set \"vsrc=abc \"   \nset vres=%vsrc%x\n", "abc x", "quoted: ends at the last quote" },
		{ "set vsrc=100%%\nset vres=%vsrc%x\n", "100%x", "%% is one percent" },
		{ "set vsrc=hello\ncall set vres=%vsrc:l=L%\n", "heLLo", "call set" },
		{ "set vsrc=hello\nset vres=%vsrc%\n", NULL, "a bare read is not built" },
		{ "set VSRC=hello\nset vres=%vsrc%x\n", "hellox", "names are case-insensitive in cmd" },
		{ "set vsrc=hello\nset vres=%VSRC:L=x%\n", "hexxo", "a read in another case, with an operation" },
		{ "( set vsrc=hello\n)\nset vres=%vsrc%x\n", NULL, "the only assignment is inside a block" },
		{ "set vsrc=hello\nif 1==1 set vsrc=bye\nset vres=%vsrc%x\n", NULL, "a second assignment behind `if`" },
		{ "set vsrc=hello\nfor %%i in (1) do set vsrc=bye\nset vres=%vsrc%x\n", NULL, "a second assignment behind `for`" },
		{ "set vsrc=hello\nset vres=%vsrc:~1,2%%vsrc%\n", "elhello", "a slice beside a read" },
		{ "set \"vsrc=hello\" \"x\"\nset vres=%vsrc%x\n", NULL, "a quoted set with more quotes after it: the value holds a quote" },
		{ "set vsrc=h\xc3\xa9llo\nset vres=%vsrc:~0,2%x\n", NULL, "a slice of a subject with bytes above 0x7f: characters or bytes, depending on the code page" },
		{ "set vsrc=hello\nset vres=%1:~0,1%%vsrc%\n", NULL, "a parameter with an operation" },
		{ "set vsrc=hello\nset vres=%vsrc:l%x\n", NULL, "a replacement with no equals sign" },
		{ "set vsrc=hello\nset vres=%vsrc:~1,x%\n", NULL, "a length that is not a number" },
		{ "set vsrc=hello\nset vres=%vsrc:~ 1%\n", NULL, "a blank in the offset" },
		{ "set vsrc=hello\nset vres=%vsrc:ELL=y%\n", "hyo", "replace of three, any case" },
		{ "set vsrc=hello\nset vres=%vsrc:=x%\n", NULL, "an empty search" },
		{ "set vsrc=hello\nset vres=%vsrc:l=%%vsrc:o=0%\n", "heohell0", "two replaces side by side" },
		{ "set vsrc=h%%llo\nset vres=%vsrc%x\n", "h%llox", "%% inside a value" },
		{ "set vsrc=hello\nset vres=%vsrc:l=%%%\n", "heo%", "%% after a read" },
		{ "set vsrc=hello\nset vres=a & echo %vsrc:l=L%\n", "heLLo", "an & ends the command: the first value `a ` is a literal, the word of the second command is told" },
		{ "set vsrc=he\"llo\nset vres=%vsrc%x\n", NULL, "a quote in an unquoted value" },
		{ "set \"vsrc=hello\"\nset vres=%vsrc:~-2%%vsrc:~0,1%\n", "loh", "slices with signs" },
		{ "set vsrc=hello\nset vres=%vsrc:~-9%x\n", "hellox", "a negative start before the beginning: php's substr clamps, cmd does the same [Unverified]" },
		{ "set vsrc=hello\necho 50%vsrc is\nset vres=%vsrc%x\n", NULL, "a % with no closing one on its line is no expansion and still a mention of the name: not trusted (conservative)" },
		{ "set vsrc=he^llo\nset vres=%vsrc%x\n", NULL, "a caret is cmd's escape: refused" },
		{ "set vsrc=hello\nset vres=%vsrc:l=!%\n", NULL, "a bang may be delayed expansion: refused" },
		{ "setlocal enabledelayedexpansion\nset vsrc=hello\nset vres=!vsrc!x\n", NULL, "delayed expansion is refused" },
		{ "set vsrc=hello\nset vres=%vsrc:*l=L%\n", NULL, "a star in the search is a pattern: refused" },
		{ "set vsrc=hello\nset vres=%1%vsrc%\n", NULL, "a parameter is unknown" },
		{ "set vsrc=hello\nset vsrc=bye\nset vres=%vsrc%x\n", NULL, "assigned twice" },
		{ "set /a vsrc=1\nset vres=%vsrc%x\n", NULL, "arithmetic" },
		{ "set /p vsrc=\nset vres=%vsrc%x\n", NULL, "a prompt" },
		{ "set vsrc=hello\n( set vsrc=bye )\nset vres=%vsrc%x\n", NULL, "assigned in a block" },
		{ "set vsrc=hello\ncall set vres=%vsrc%%%x\n", NULL, "call set: a percent in the value" },
		{ "rem set vsrc=bye\nset vsrc=hello\nset vres=%vsrc%x\n", NULL, "a remark that names the variable: the census is a raw scan (conservative)" },
		{ "rem set vzzz=bye\nset vsrc=hello\nset vres=%vsrc%x\n", "hellox", "a remark that names another" },
		{ ":: set vsrc=bye\nset vsrc=hello\nset vres=%vsrc%x\n", NULL, "a :: line that names the variable (conservative)" },
		{ ":: set vzzz=bye\nset vsrc=hello\nset vres=%vsrc%x\n", "hellox", "a :: line that names another" },
		{ "set vsrc=hello\necho a%vsrc:l=L%\n", "aheLLo", "a word of a command that assigns nothing" },
	};

	last_check(BAT, "bat", t, sizeof t / sizeof t[0]);
}

/*
 * [Unverified] against tclsh (not on this machine). Relied on from the tcl 8.6 manual: `$v` and `${v}` read a variable; `[ ]` runs a
 * command and its result replaces the word; a double-quoted word substitutes, a braced word does not; `string map` takes the first
 * matching key of the list at each position and goes on after it; `string range a b` is inclusive and `end-N` counts from the end;
 * `join` puts the separator between elements; `format` is refused unless every conversion is `%s` or `%%` and the argument count is exact.
 */
static void tcl_cases(void)
{
	static const struct lcase t[] = {
		{ "set vsrc hello\nset vres [string toupper $vsrc]\n", "HELLO", "toupper" },
		{ "set vsrc a,b\nset vlist [split $vsrc ,]\nset vres $vlist-x\n", NULL, "a name that holds a list is no string" },
		{ "set vres \"a\\x00b[string toupper x]\"\n", NULL, "a value with a NUL is not written back" },
		{ "set vsrc a,b;c\nset vres [join [split $vsrc \",;\"] +]\n", NULL, "split by a set of two characters" },
		{ "set vsrc \"\\vhi\\v\"\nset vres [string trim $vsrc]x\n", NULL, "a vertical tab at the edge: which blanks trim takes is not read" },
		{ "set vsrc xxhixx\nset vres [string trimleft $vsrc x]\n", "hixx", "trimleft with a set" },
		{ "set vsrc xxhixx\nset vres [string trimright $vsrc x]\n", "xxhi", "trimright with a set" },
		{ "set vsrc xxhixx\nset vres [string trimleft $vsrc]x\n", "xxhixxx", "trimleft with the default set leaves x" },
		{ "set vsrc hello\nset vres $vsrc\n", NULL, "a bare read is not built" },
		{ "set vsrc hello\nset vres \"$vsrc\"\n", NULL, "a quoted bare read is not built" },
		{ "set vsrc hello\nset vres ${vsrc}!\n", "hello!", "a braced read with a literal" },
		{ "set vsrc hello\nset vres \"[string toupper $vsrc] there\"\n", "HELLO there", "a command inside quotes" },
		{ "set vsrc hello\nset vres [string toupper [string range $vsrc 0 1]]x\n", "HEx", "nested, then a literal" },
		{ "set vsrc hello\nset vres {[string toupper $vsrc]}\n", NULL, "braces do not substitute: one literal" },
		{ "set vsrc hello\nset vres [string toupper {$vsrc}]\n", "$VSRC", "a braced argument is the text as written" },
		{ "set vsrc hello\nset vres [string toupper $vsrc(1)]\n", NULL, "an array element is not a read of the name" },
		{ "set vsrc hello\nset vres [string range $vsrc end-9 end]\n", NULL, "end-N before the beginning: tcl clamps to 0, the row refuses a negative index instead" },
		{ "set vsrc hello\nset vres [string range $vsrc 0 end+2]\n", "hello", "end+N past the end clamps" },
		{ "set vsrc hello\nset vres [string range $vsrc -3 1]\n", NULL, "a negative first index: tcl reads it as 0, the row refuses it" },
		{ "set vsrc hello\nset vres [string range $vsrc 2 2]\n", "l", "one character" },
		{ "set vsrc hello\nset vres [string range $vsrc end end]\n", "o", "the last character" },
		{ "set vsrc hello\nset vres [string range $vsrc end-1 end-1]\n", "l", "the one before the last" },
		{ "set vsrc hello\nset vres [string index $vsrc 1]x\n", NULL, "string index has no row" },
		{ "set vsrc hello\nset vres [string toupper $vsrc]\nset vres2 [string tolower $vres]x\n", "hellox", "a result read by the next" },
		{ "set vsrc hello\nset vres [string map {l L} $vsrc]x\n", "heLLox", "map beside a literal" },
		{ "set vsrc hello\nset vres [string map {} $vsrc]\n", NULL, "an empty map list: no pairs" },
		{ "set vsrc hello\nset vres [string map {l L h} $vsrc]\n", NULL, "an odd map list" },
		{ "set vsrc hello\nset vres [string map {{} x} $vsrc]\n", NULL, "an empty key" },
		{ "set vsrc hello\nset vres [string map {l {L L}} $vsrc]\n", NULL, "a value with a space needs braces the op does not read" },
		{ "set vsrc hello\nset vres [string repeat $vsrc -1]\n", NULL, "a negative repeat count" },
		{ "set vsrc hello\nset vres [string repeat $vsrc 0]x\n", "x", "repeat zero times" },
		{ "set vsrc {a b c}\nset vres [join $vsrc +]\n", "a+b+c", "join of a list in a variable" },
		{ "set vsrc a,b\nset vres [join [split $vsrc ,] +]\n", "a+b", "split by a variable" },
		{ "set vsrc a,b\nset vres [split $vsrc ,]\n", NULL, "a list is not a value" },
		{ "set vres [concat { a } {b }]\n", NULL, "concat trims an argument with edge blanks: the row refuses it (NOEDGE)" },
		{ "set vres [concat a {} b]\n", NULL, "concat drops an empty argument: the row refuses it (NOEDGE)" },
		{ "set vres [string cat]x\n", "x", "cat of nothing" },
		{ "set vres [format %s%s a b]\n", "ab", "two conversions" },
		{ "set vres [format {%s x} a]\n", "a x", "a braced format" },
		{ "set vres [format %5s a]\n", NULL, "a width" },
		{ "set vres [format %% ]x\n", "%x", "%% alone" },
		{ "set vres [format a\\nb]x\n", "a\nbx", "the word reader turns \\n into the line break before format sees it, as tcl does" },
		{ "set vsrc a\nproc f {} {\n set vsrc b\n}\nset vres [string toupper $vsrc]x\n", NULL, "set inside a proc body" },
		{ "set vsrc a\nset vsrc2 b\nset vres [string toupper $vsrc]$vsrc2\n", "Ab", "a name that is the prefix of another is not confused with it" },
		{ "set vsrc HeLLo\nset vres [string tolower $vsrc]\n", "hello", "tolower" },
		{ "set vsrc hello\nset vres [string reverse $vsrc]\n", "olleh", "reverse" },
		{ "set vsrc hello\nset vres [string range $vsrc 1 3]\n", "ell", "range" },
		{ "set vsrc hello\nset vres [string range $vsrc 1 end]\n", "ello", "range to end" },
		{ "set vsrc hello\nset vres [string range $vsrc end-2 end]\n", "llo", "range from the end" },
		{ "set vsrc hello\nset vres [string range $vsrc 3 1]\n", "", "empty range" },
		{ "set vsrc hello\nset vres [string length $vsrc]\n", "5", "length" },
		{ "set vsrc hello\nset vres [string map {l L} $vsrc]\n", "heLLo", "map" },
		{ "set vsrc hello\nset vres [string map {l L he HE} $vsrc]\n", "HELLo", "map, two pairs" },
		{ "set vsrc hello\nset vres [string map {h x hello y} $vsrc]\n", "xello", "map: the first pair in the list wins" },
		{ "set vsrc hello\nset vres [string map [list l L] $vsrc]\n", NULL, "a list made by [list]: no row" },
		{ "set vsrc hello\nset vres [string map {l {}} $vsrc]\n", "heo", "map to nothing" },
		{ "set vres [string repeat ab 3]\n", "ababab", "repeat" },
		{ "set vsrc {  hi  }\nset vres [string trim $vsrc]\n", "hi", "trim" },
		{ "set vsrc {  hi  }\nset vres [string trimleft $vsrc]\n", "hi  ", "trimleft" },
		{ "set vsrc {  hi  }\nset vres [string trimright $vsrc]\n", "  hi", "trimright" },
		{ "set vsrc xxhixx\nset vres [string trim $vsrc x]\n", "hi", "trim with a set" },
		{ "set vsrc hello\nset vres [string cat $vsrc world]\n", "helloworld", "cat" },
		{ "set vsrc hello\nset vres \"${vsrc}world\"\n", "helloworld", "braced name inside quotes" },
		{ "set vsrc hello\nset vres $vsrc-x\n", "hello-x", "adjacency" },
		{ "set vsrc hello\nset vres [concat $vsrc world]\n", "hello world", "concat" },
		{ "set vres [join {a b c} -]\n", "a-b-c", "join" },
		{ "set vres [join {a b c} {}]\n", "abc", "join with nothing" },
		{ "set vres [join [split a,b,c ,] -]\n", "a-b-c", "split then join" },
		{ "set vres [join [split abc {}] .]\n", NULL, "split with an empty separator (into characters): refused" },
		{ "set vres [join {a {} b} -]\n", "a--b", "join with an empty element" },
		{ "set vres [format %s-%s a b]\n", "a-b", "format %s" },
		{ "set vres [format 100%%]\n", "100%", "format %%" },
		{ "set vres [string toupper [string reverse abc]]\n", "CBA", "nested" },
		{ "set vsrc a\nappend vsrc b\nset vres $vsrc-x\n", NULL, "appended: written by something the evaluator does not read" },
		{ "set vsrc a\nset vsrc b\nset vres $vsrc-x\n", NULL, "set twice" },
		{ "set vsrc a\neval {set vsrc b}\nset vres $vsrc-x\n", NULL, "eval" },
		{ "set vsrc a\nuplevel {set vsrc b}\nset vres $vsrc-x\n", NULL, "uplevel" },
		{ "set vsrc a\nproc f {} {set vsrc b}\nset vres $vsrc-x\n", NULL, "set in a proc body" },
		{ "set vres [format %d 5]\n", NULL, "format %d is refused" },
		{ "set vres [format %s a b]\n", NULL, "format with too many arguments is an error in tcl" },
		{ "set vres [format %s-%s a]\n", NULL, "format with too few" },
		{ "set vres [string map {a} abc]\n", NULL, "an odd map list is an error in tcl" },
		{ "set vsrc hello\nset vres [string range $vsrc 1 x]\n", NULL, "a bad index" },
		{ "set vsrc hello\nset vres [string match h* $vsrc]\n", NULL, "a command with no row" },
		{ "set vsrc hello\nset vres [string toupper $vsrc $vsrc]\n", NULL, "too many arguments" },
		{ "set vsrc {a b}\nputs [string toupper $vsrc]\n", "A B", "a word of a command that assigns nothing" },
	};

	last_check(TCL, "tcl", t, sizeof t / sizeof t[0]);
}

int main(void)
{
	sh_generated();
	sh_fixed();
	sh_shapes();
	bat_cases();
	tcl_cases();
	printf("script_cmds: %u checks, %u failed\n", ok_n, fails);
	return fails ? 1 : 0;
}
