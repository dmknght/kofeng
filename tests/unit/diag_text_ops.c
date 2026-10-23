#define _GNU_SOURCE
/*
 * diag_text_ops - ATTACKS on what the constant evaluator does with LISTS, CASTS and OPERATORS (phenotype/diag_text_eval_ops.c): powershell's -join (binary and unary), -split, -replace
 * (a comma list on its right), [char], [string]::Join; python's sep.join(list), tuples and implicit literal joins; perl's join and x; ruby's and javascript's list methods.
 *
 * Coverage of that file was 48% of its lines under the lib tests (diag_text*.c in tests/lib/genome) and 94% with the unit tests that drive the evaluator through the engine's
 * string functions (script_methods, script_cmds, script_fn_rows); what was left was the REFUSALS - a list where none is taken, a list that is not the last argument, a type the
 * language will not convert, a call whose spelling is broken by a blank - and the bounds (a list past the value limit, a first element bigger than the list's first block) and
 * memory refused. Each is a case here, with the rule it pins, and each says what the language does:
 *
 *   must      the value is exactly this (a documented row: the table says it reads it);
 *   sound     the evaluator says nothing or says exactly this - the language gives that value, no row promises to read it, and what it must never do is say another;
 *   refused   the evaluator says nothing: the language reads it another way (an error, a conversion, an array), or a bound says so.
 *
 * python and perl are on this machine: their shapes are also asked of the interpreter itself, over every small list the alphabet makes (the sweep at the end), and a difference is
 * a defect. powershell, ruby and javascript are not: their cases are written from the language's reference text and are [Unverified] against a real interpreter.
 *
 * MEMORY: every allocation of a scan over the list shapes is refused in turn (malloc, calloc and realloc are wrapped, UNIT_LIBS_diag_text_ops), and what comes back is the
 * constants of the unrefused scan or a status that says something was refused - never a shorter set with a clean status (the rule of tests/lib/genome/diag_text_oom.c, G9).
 *
 * usage: diag_text_ops
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../lib/interp_oracle.h"
#include "normalizer_ref.h"
#include "normalizer_consts.h"

#define PY KGENOME_TEXTUAL_LANG_PY
#define PL KGENOME_TEXTUAL_LANG_PERL
#define PS KGENOME_TEXTUAL_LANG_PSH
#define RB KGENOME_TEXTUAL_LANG_RUBY
#define JS KGENOME_TEXTUAL_LANG_JS

/* ---- the memory refusal -------------------------------------------------------------------- */

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);

static long armed, seen, fail_at;

static int refuse(void)
{
	return armed && ++seen == fail_at;
}

void *__wrap_malloc(size_t n)
{
	return refuse() ? NULL : __real_malloc(n);
}

void *__wrap_calloc(size_t a, size_t b)
{
	return refuse() ? NULL : __real_calloc(a, b);
}

void *__wrap_realloc(void *p, size_t n)
{
	return refuse() ? NULL : __real_realloc(p, n);
}

/* ---- asking ------------------------------------------------------------------------------ */

/* the constants of `src` in `lang`: how many, and the first as a C string (a NUL in a value cuts it, none of these has one) */
static unsigned ask(uint32_t lang, const char *src, char *first, size_t cap, struct cset *keep)
{
	struct cset s;
	unsigned n;

	consts_of(lang, (const uint8_t *)src, strlen(src), &s);
	n = s.n;
	first[0] = 0;
	if (s.n) {
		size_t l = s.c[0].n < cap - 1u ? s.c[0].n : cap - 1u;

		memcpy(first, s.c[0].v, l);
		first[l] = 0;
	}
	if (keep)
		*keep = s;
	else
		cset_free(&s);
	return n;
}

/* the evaluator reads `src` (one assignment) to exactly `want` */
static void must(uint32_t lang, const char *src, const char *want)
{
	char v[512];
	unsigned n = ask(lang, src, v, sizeof v, NULL);

	NCKF(n == 1u && !strcmp(v, want), "must [%s]: %u values, first [%s], wanted [%s]", src, n, v, want);
}

/* ... says nothing or exactly `want` */
static void sound(uint32_t lang, const char *src, const char *want)
{
	char v[512];
	unsigned n = ask(lang, src, v, sizeof v, NULL);

	NCKF(n == 0u || (n == 1u && !strcmp(v, want)), "sound [%s]: %u values, first [%s], the language says [%s]", src, n, v, want);
}

/* ... says nothing */
static void refused(uint32_t lang, const char *src)
{
	char v[512];
	unsigned n = ask(lang, src, v, sizeof v, NULL);

	NCKF(n == 0u, "refused [%s]: %u values, first [%s]", src, n, v);
}

/* ---- powershell: from the reference text ([Unverified]: no pwsh here) ------------------------ */

static void powershell(void)
{
	/* -join: the left is a list (an array is the comma list in brackets, or @( )); the right is the separator, a string */
	must(PS, "$x = ('a', 'b', 'c') -join ''\n", "abc");
	must(PS, "$x = ('a', 'b') -join ', '\n", "a, b");
	must(PS, "$x = @('a', 'b') -join '-'\n", "a-b");
	sound(PS, "$x = @() -join '-'\n", "");                                              /* an empty array joins to the empty string */
	must(PS, "$x = -join ('a', 'b', 'c')\n", "abc");                                    /* unary: no separator */
	must(PS, "$x = -join('a', 'b')\n", "ab");
	must(PS, "$x = -join @('a', 'b')\n", "ab");
	sound(PS, "$x = -join 'abc'\n", "abc");                                             /* a scalar is a list of one */
	refused(PS, "$x = ('a', 'b') -join 1\n");                                           /* the separator is converted from a number: not a string of the program */
	sound(PS, "$x = 'abc' -join ','\n", "abc");                                         /* a scalar on the left is the scalar */
	refused(PS, "$x = ('a', 1) -join ''\n");                                            /* "a1": an element that is a number is joined as its text, which is not read */
	refused(PS, "$x = ($y, 'b') -join ''\n");                                           /* an element that is no constant */
	refused(PS, "$x = (('a', 'b'), 'c') -join ''\n");                                   /* nested: the language flattens, the evaluator does not read a list inside a list */
	refused(PS, "$x = ('a', 'b') -replace 'a', 'c'\n");                                /* a list on the left of an operator that is not a join: the language maps it over the elements (an array), the evaluator reads one string */
	refused(PS, "$x = ('a,b', 'c') -split ','\n");
	refused(PS, "$x = ('a', 'b')\n");                                                   /* a list is no value, and the walk does not parse a table that nothing takes */
	refused(PS, "$x = @('a', 'b')\n");
	refused(PS, "$x = 'a', 'b' -join ''\n");                                            /* the comma binds tighter than -join: the array 'a', ('b' -join '') */
	/* [string]::Join: the separator and then the elements, or the separator and one list */
	must(PS, "$x = [string]::Join(',', 'a', 'b')\n", "a,b");
	must(PS, "$x = [string]::Join('-', ('a', 'b', 'c'))\n", "a-b-c");
	must(PS, "$x = [system.string]::Join('', 'a', 'b')\n", "ab");
	must(PS, "$x = [String]::JOIN('+', 'a', 'b')\n", "a+b");                            /* names are not case sensitive */
	refused(PS, "$x = [string]::Join(',', 1, 2)\n");                                    /* typed: a number is not turned into a string */
	refused(PS, "$x = [string]::Join(('a', 'b'))\n");                                   /* no separator: a list is the only argument */
	refused(PS, "$x = [string]::Join(('a', 'b'), ',')\n");                              /* a list is the last argument or nothing */
	refused(PS, "$x = [string]::Join(',', ('a', 'b'), 'c')\n");
	refused(PS, "$x = [string]::Join(',' 'a')\n");                                      /* no comma between the arguments */
	refused(PS, "$x = [string]::Join()\n");
	refused(PS, "$x = [string]::Join\n");                                               /* the function itself */
	refused(PS, "$x = [string]::Join(',', 'a'\n");                                      /* a bracket that does not close */
	sound(PS, "$x = [string] ::Join(',', 'a', 'b')\n", "a,b");                          /* blanks inside the spelling: the walk does not read it as one call */
	sound(PS, "$x = [ string]::Join(',', 'a', 'b')\n", "a,b");
	sound(PS, "$x = [string]:: Join(',', 'a', 'b')\n", "a,b");
	sound(PS, "$x = [string]::Join (',', 'a', 'b')\n", "a,b");
	refused(PS, "$x = [1]::Join(',', 'a', 'b')\n");                                     /* a type that is no name */
	refused(PS, "$x = [string]:Join(',', 'a', 'b')\n");
	must(PS, "$x = [string]::Join(',', 'a', 'b').ToUpper()\n", "A,B");                  /* a method on the call's answer */
	/* [char]: a character, which a join writes as the string it is and which is no string */
	sound(PS, "$x = [char]65\n", "A");
	must(PS, "$x = 'a' + [char]66\n", "aB");
	refused(PS, "$x = [char]65 + [char]66\n");                                          /* two characters add as numbers: 131 */
	refused(PS, "$x = [char]65536\n");                                                  /* past a UTF-16 unit: an error in the language */
	refused(PS, "$x = [char]-1\n");
	refused(PS, "$x = [char]'65'\n");                                                   /* a string that spells a number is an error: the operand is a number */
	refused(PS, "$x = [char]$y\n");
	sound(PS, "$x = [char](65)\n", "A");
	sound(PS, "$x = -join ([char]72, [char]105)\n", "Hi");
	sound(PS, "$x = ([char]72, [char]105) -join ''\n", "Hi");
	/* -replace and -split: a regular expression (a metacharacter makes the call unread), a comma list on the right of -replace, and the precedence of both */
	must(PS, "$x = 'hello' -replace 'l', 'L'\n", "heLLo");
	must(PS, "$x = 'hello' -replace 'L', 'x'\n", "hexxo");                              /* not case sensitive by default */
	must(PS, "$x = 'hello' -creplace 'L', 'x'\n", "hello");
	must(PS, "$x = 'aXb' -ireplace 'x', '_'\n", "a_b");
	must(PS, "$x = 'abc' -replace 'b'\n", "ac");                                        /* no replacement removes the match */
	must(PS, "$x = 'abc' -REPLACE 'B', 'x'\n", "axc");
	refused(PS, "$x = 'a.b' -replace '.', 'x'\n");                                      /* a metacharacter: a regular expression */
	refused(PS, "$x = 'ab' -replace 'a', '$1'\n");                                      /* "$" in the replacement is a group */
	refused(PS, "$x = 'a' -replace 'a', 'b', 'c'\n");                                   /* more than the two the operator takes */
	refused(PS, "$x = 'abc' -replace 'b', $y\n");
	refused(PS, "$x = 'abc' -replace $y, 'b'\n");
	refused(PS, "$x = 'ab' -replace 'a', 'c' + 'd'\n");                                 /* the comma list binds tighter than +: an array sum */
	must(PS, "$x = 'a' + 'b' -replace 'a', 'c'\n", "cb");                               /* -replace is looser than +: it replaces in the joined value */
	must(PS, "$x = 'a b' -split ' ' -join '_'\n", "a_b");                              /* the operators are of one precedence and go from the left: the list a split makes is the left of the join */
	must(PS, "$x = 'a,b,c' -split ',' -join '+'\n", "a+b+c");
	must(PS, "$x = 'a,,b' -split ',' -join '+'\n", "a++b");                              /* empty pieces are kept */
	sound(PS, "$x = ('a b' -split ' ') -join '_'\n", "a_b");                             /* a bracket that holds a split: the language says a_b; the evaluator reads a list only from a comma list, so it says nothing (a limit of what is read, not a wrong answer) */
	sound(PS, "$x = ('a,b,c' -split ',') -join '+'\n", "a+b+c");
	refused(PS, "$x = 'a.b' -split '.'\n");
	refused(PS, "$x = ('a,b' -split ',|;') -join '+'\n");
	refused(PS, "$x = 'a,b' -split ','\n");                                             /* a list nobody joined */
	refused(PS, "$x = 'a' + 'b,c' -split ','\n");
	refused(PS, "$x = ('a,b' -split ',')[0]\n");                                        /* an index: not read */
	/* methods and the list a split makes */
	must(PS, "$x = 'abc'.ToUpper()\n", "ABC");
	must(PS, "$x = '  a '.Trim()\n", "a");
	must(PS, "$x = 'abc'.Substring(1, 1)\n", "b");
	must(PS, "$x = 'abc'.Substring(1)\n", "bc");
	must(PS, "$x = 'a-b'.Replace('-', '+')\n", "a+b");
	sound(PS, "$x = ('a,b'.Split(',')) -join '/'\n", "a/b");
	must(PS, "$x = 'a,b'.Split(',') -join '/'\n", "a/b");
	refused(PS, "$x = 'a,b'.Split(',').ToUpper()\n");                                   /* a method of the string on a list */
}

/* ---- python ------------------------------------------------------------------------------ */

static void python(void)
{
	must(PY, "x = '-'.join(['a', 'b'])\n", "a-b");
	must(PY, "x = '-'.join(('a', 'b'))\n", "a-b");
	must(PY, "x = '-'.join(['a', 'b', ])\n", "a-b");                                    /* a trailing comma */
	must(PY, "x = '-'.join(['a' 'b', 'c'])\n", "ab-c");                                 /* two literals side by side are one element */
	sound(PY, "x = '-'.join([])\n", "");
	sound(PY, "x = '-'.join(['a'])\n", "a");
	must(PY, "x = '-'.join(['a', 'b']) * 2\n", "a-ba-b");
	must(PY, "x = '-'.join(['a', 'b']).upper()\n", "A-B");
	must(PY, "x = '-'.join('a,b'.split(','))\n", "a-b");
	must(PY, "x = ('a' 'b').upper()\n", "AB");
	/* a method binds to the WHOLE of literals written side by side: they are one literal when the program is read ("A" "b".replace(..) replaces in "Ab") */
	must(PY, "x = 'Ab' ''.replace('A', 'z')\n", "zb");
	must(PY, "x = 'a' 'b'\n", "ab");                                                   /* the join of two literals is not one literal: it is a constant of its own */
	must(PY, "x = 'a' 'b' 'c'\n", "abc");
	must(PY, "x = 'a'  'b'\n", "ab");
	must(PY, "x = 'a' 'b'.upper()\n", "AB");
	must(PY, "x = 'a' 'b' 'c'[::-1]\n", "cba");
	must(PY, "x = 'a' 'b'.replace('a', 'x') + 'a'\n", "xba");
	must(PY, "x = ('a' 'b').replace('a', 'x')\n", "xb");
	{   /* a SyntaxError: a call is not a literal to join. What the evaluator may say is the value of the literal with its method ("A"), never the join of the two ("Ab") */
		char v[512];
		unsigned n = ask(PY, "x = 'a'.upper() 'b'\n", v, sizeof v, NULL);

		NCKF(n == 0u || strcmp(v, "Ab") != 0, "not a join [x = 'a'.upper() 'b']: the evaluator says [%s]", v);
	}
	refused(PY, "x = '-'.join('abc')\n");                                               /* a str is an iterable of its characters: not a list here */
	refused(PY, "x = '-'.join(['a', 1])\n");                                            /* a TypeError */
	refused(PY, "x = '-'.join(['a', 'b'], 1)\n");
	refused(PY, "x = '-'.join(1)\n");
	refused(PY, "x = '-'.join(['a', y])\n");
	refused(PY, "x = '-'.join([['a'], 'b'])\n");
	refused(PY, "x = '-'.join(['a', 'b'][0])\n");
	refused(PY, "x = 'a'.replace('x')\n");                                              /* two arguments of three: a TypeError */
	sound(PY, "x = 'a'. upper()\n", "A");                                              /* a blank after the dot: the language allows it, the walk reads the method only when the name touches the dot */
	refused(PY, "x = 'a'.upper(\n");                                                   /* a bracket that does not close */
	refused(PY, "x = 'ab'[::-1\n");                                                    /* a suffix that stops in the middle of its spelling */
	refused(PY, "x = 'a'.1\n");
	refused(PY, "x = 'a'.'b'\n");
	refused(PY, "x = 'a'.upper(1)\n");
	refused(PY, "x = 'a'.replace(1, 'x')\n");                                           /* a number where a str is wanted */
	refused(PY, "x = 'ab' * '3'\n");
	refused(PY, "x = 'ab' * 2.5\n");
	must(PY, "f('a' 'b'.upper())\n", "AB");                                           /* a literal that is code's argument, with its method: the floating candidate starts at the FIRST literal */
	must(PY, "x = f('a' 'b' 'c'[::-1])\n", "cba");
	must(PY, "x = f('Ab' ''.replace('A', 'z'), 1)\n", "zb");
	refused(PY, "x = 'a,b'.split(',').upper()\n");                                      /* an AttributeError: a list has no upper */
	refused(PY, "x = 'a,b'.split(',')\n");                                              /* a list is no value */
	refused(PY, "x = 'a,b'.split('')\n");                                               /* a ValueError */
	/* the first element is bigger than the block a list starts with, and a list past the value bound is refused with a word */
	{
		char src[512], el[200];

		memset(el, 'a', 150);
		el[150] = 0;
		snprintf(src, sizeof src, "x = '-'.join(['%s', 'b'])\n", el);
		{
			char want[200];

			snprintf(want, sizeof want, "%s-b", el);
			must(PY, src, want);
		}
	}
	{
		struct cset s;
		unsigned n;
		/* each element is 600000 bytes: one fits in a value (1 MiB), two do not */
		static const char big[] = "x = '-'.join(['a' * 600000, 'b' * 600000])\n";

		consts_of(PY, (const uint8_t *)big, strlen(big), &s);
		n = s.n;
		NCKF(n == 0u && (s.cut != 0u || s.st != KGENOME_OK), "a list past the value bound says so: %u values, cut %u, status %d", n, s.cut, (int)s.st);
		cset_free(&s);
	}
}

/* ---- perl, ruby, javascript ------------------------------------------------------------- */

static void others(void)
{
	must(PL, "$x = join(',', 'a', 'b');\n", "a,b");
	sound(PL, "$x = join(',', ('a', 'b'));\n", "a,b");                                /* a bracket that holds a list is not read as one by perl's row */
	sound(PL, "$x = join(',', ('a', 'b'), 'c');\n", "a,b,c");                           /* a list in the middle is flattened by the language */
	sound(PL, "$x = join(',');\n", "");
	sound(PL, "$x = join(',', ());\n", "");
	must(PL, "$x = join('-', 'a', join('+', 'b', 'c'));\n", "a-b+c");
	sound(PL, "$x = ('ab') x 3;\n", "ababab");                                          /* a bracket on the left of x is list repetition, which is not one string (in this scalar assignment it is the string: the refusal is the safe side) */
	sound(PL, "$x = (lc('A')) x 2;\n", "aa");
	sound(PL, "@x = ('ab') x 3;\n", "ab");
	must(PL, "$x = 'ab' x 3;\n", "ababab");
	must(PL, "$x = 'ab' x -1;\n", "");
	refused(PL, "$x = 'ab' x 'z';\n");
	must(RB, "x = ['a', 'b'].join('-')\n", "a-b");
	sound(RB, "x = ['a', 'b'].join\n", "ab");
	must(RB, "x = 'a,b'.split(',').join('-')\n", "a-b");
	refused(RB, "x = 'a,b'.split(',')\n");
	refused(RB, "x = ['a', 1].join('-')\n");
	refused(RB, "x = ['a', y].join('-')\n");
	must(JS, "x = ['a', 'b'].join('-')\n", "a-b");
	must(JS, "x = 'a,b'.split(',').join('-')\n", "a-b");
	refused(JS, "x = ['a', 'b'].join()\n");                                             /* no separator: a comma in the language, not read */
	refused(JS, "x = 'a,b'.split(',').toUpperCase()\n");
}

/* ---- the interpreters: every small list the alphabet makes ------------------------------- */

/* Run `script` (python 3 or perl) that prints `tag TAB expression TAB hex`, ask the evaluator the same expression and compare. Returns the number of cases compared. */
static unsigned sweep(uint32_t lang, int py, const char *script, const char *prefix, const char *suffix, const char *what)
{
	char *out = run_script(py, script), *at, *line;
	unsigned acc = 0, bad = 0, found = 0;

	if (!out) {
		printf("  %s: the interpreter is not on this machine: skipped\n", what);
		return 0;
	}
	at = out;
	while ((line = strsep(&at, "\n")) != NULL && *line) {
		char *expr = strchr(line, '\t'), *hex, src[1024], v[1024];
		unsigned n;

		if (!expr)
			continue;
		*expr++ = 0;
		hex = strchr(expr, '\t');
		if (!hex)
			continue;
		*hex++ = 0;
		snprintf(src, sizeof src, "%s%s%s\n", prefix, expr, suffix);
		n = ask(lang, src, v, sizeof v, NULL);
		acc++;
		if (n == 1u) {
			char gx[2048] = "";
			size_t k;

			found++;
			for (k = 0; k < strlen(v); k++)
				sprintf(gx + 2u * k, "%02x", (uint8_t)v[k]);
			if (strcmp(gx, hex) && bad++ < 8u)
				printf("  FAIL %s: [%s] the evaluator says [%s], the interpreter %s\n", what, expr, v, hex);
		} else if (line[0] == 'A' && n > 1u) {
			bad++;
		}
	}
	free(out);
	NCKF(!bad && acc > 100u, "%s: %u cases, %u read by the evaluator, %u different", what, acc, found, bad);
	printf("  %s: %u cases, %u of them read by the evaluator, %u different from the interpreter's bytes\n", what, acc, found, bad);
	return acc;
}

static const char py_lists[] =
	"import itertools\n"
	"def words(al,mx):\n"
	"    for n in range(mx+1):\n"
	"        for t in itertools.product(al,repeat=n): yield ''.join(t)\n"
	"def A(e): print('A\\t'+e+'\\t'+eval(e).encode().hex())\n"
	"for sep in ['', '-', 'ab']:\n"
	"  for n in range(0,4):\n"
	"    for t in itertools.product(['', 'a', 'ab', 'B'], repeat=n):\n"
	"      els = ', '.join(repr(e) for e in t)\n"
	"      A(repr(sep)+'.join(['+els+'])'); A(repr(sep)+'.join(('+els+(',' if n==1 else '')+'))'); A(repr(sep)+'.join(['+els+(',' if n else '')+'])')\n"
	"      A(repr(sep)+'.join(['+els+']) * 2'); A(repr(sep)+'.join(['+els+']).upper()')\n"
	"for s in words('ab,',4):\n"
	"  for sep in [',', 'a']:\n"
	"    for j in ['', '-']:\n"
	"      A(repr(j)+'.join('+repr(s)+'.split('+repr(sep)+'))'); A(repr(j)+'.join(('+repr(s)+' '+repr(sep)+').split('+repr(sep)+'))')\n"
	"      A(repr(s)+' '+repr(sep)+'.replace('+repr('a')+', '+repr('z')+')'); A(repr(s)+' '+repr(sep)+'.upper()'); A(repr(s)+' '+repr(sep)+'[::-1]')\n"
	"      A(repr(s)+' '+repr(sep)+'.strip()'); A('('+repr(s)+' '+repr(sep)+') * 2')\n";

static const char pl_lists[] =
	"sub h{return unpack('H*',$_[0]);}\n"
	"sub qs{my $s=shift;$s=~s/(\\\\|\")/\\\\$1/g;$s=~s/\\$/\\\\\\$/g;$s=~s/\\@/\\\\\\@/g;return '\"'.$s.'\"';}\n"
	"my @al=('','a','ab','B');\n"
	"for my $sep('', '-', 'ab'){ my $q=qs($sep);\n"
	"  for my $n(0..3){ my @idx=(0) x $n; while(1){ my @t=map{$al[$_]}@idx; my $els=join(', ',map{qs($_)}@t);\n"
	"    print \"A\\tjoin($q, $els)\\t\".h(join($sep,@t)).\"\\n\" if $n;\n"
	"    print \"A\\tjoin($q, ($els))\\t\".h(join($sep,@t)).\"\\n\" if $n;\n"
	"    print \"A\\tjoin($q, $els) x 2\\t\".h(join($sep,@t) x 2).\"\\n\" if $n;\n"
	"    print \"A\\tuc(join($q, $els))\\t\".h(uc(join($sep,@t))).\"\\n\" if $n;\n"
	"    my $k=$n-1; while($k>=0){ $idx[$k]++; last if $idx[$k]<@al; $idx[$k]=0; $k--; } last if $k<0; } } }\n";

static void interpreters(void)
{
	unsigned total = 0;

	total += sweep(PY, 1, py_lists, "x = ", "", "python lists, tuples, implicit joins");
	total += sweep(PL, 0, pl_lists, "$x = ", ";", "perl join");
	printf("  %u cases against the interpreters\n", total);
}

/* ---- memory ------------------------------------------------------------------------------ */

struct oomprog {
	const char *name;
	uint32_t lang;
	const char *text;
};

static const struct oomprog OP[] = {
	{ "python lists", PY, "a = '-'.join(['a' * 40, 'b', 'c'])\nb = '-'.join('x,y,z'.split(','))\nc = ('p' 'q').upper() + 'r' * 3\nd = '+'.join(['k', a, b])\n" },
	{ "powershell lists", PS, "$a = ('a', 'b', 'c') -join ','\n$b = -join ('x', 'y')\n$c = [string]::Join('-', 'p', 'q') + [char]65\n$d = ('a,b' -split ',') -join '+'\n$e = 'hello' -replace 'l', 'L'\n" },
	{ "perl join", PL, "$a = join(',', 'a', 'b', 'c');\n$b = join('-', ('x', 'y'), 'z') . 'k' x 3;\n$c = uc(join('', 'p', 'q'));\n" },
	{ "ruby join", RB, "a = ['a', 'b', 'c'].join('-')\nb = 'x,y'.split(',').join('+')\n" },
};

/* a collector that allocates nothing: it runs INSIDE the scan, where the allocations are refused */
struct fixed {
	unsigned n;
	struct { uint32_t off, len, n; uint8_t v[256]; } c[32];
	enum kgenome_status st;
};

static void fixed_const(void *u, uint64_t off, uint64_t len, const uint8_t *v, uint32_t n)
{
	struct fixed *f = u;

	if (f->n < 32u) {
		f->c[f->n].off = (uint32_t)off;
		f->c[f->n].len = (uint32_t)len;
		f->c[f->n].n = n < 256u ? n : 256u;
		memcpy(f->c[f->n].v, v, f->c[f->n].n);
		f->n++;
	}
}

static void fixed_of(uint32_t lang, const char *text, struct fixed *f)
{
	struct kgenome_budget kb;
	struct kgenome_diag_text_req rq;
	struct kgenome_diag_scan *sc;

	memset(f, 0, sizeof *f);
	kgenome_budget_default(&kb, strlen(text), 0);
	memset(&rq, 0, sizeof rq);
	rq.base = (const uint8_t *)text;
	rq.size = strlen(text);
	rq.lang = lang;
	rq.budget = &kb;
	rq.apply = kof_script_apply;
	rq.on_const = fixed_const;
	rq.const_user = f;
	sc = kgenome_diag_scan_text(&rq);
	f->st = sc ? kgenome_diag_scan_status(sc) : KGENOME_NOMEM;
	kgenome_diag_scan_free(sc);
}

static void sig_fixed(const struct fixed *f, char *out, size_t cap)
{
	unsigned i, k;
	size_t n = 0;

	out[0] = 0;
	for (i = 0; i < f->n && n + 600u < cap; i++) {
		n += (size_t)snprintf(out + n, cap - n, "%u+%u=", f->c[i].off, f->c[i].len);
		for (k = 0; k < f->c[i].n; k++)
			n += (size_t)snprintf(out + n, cap - n, "%02x", f->c[i].v[k]);
		n += (size_t)snprintf(out + n, cap - n, ";");
	}
}

static void memory(void)
{
	size_t p;
	unsigned checked = 0, said = 0;
	static char ref[16384], got[16384];

	for (p = 0; p < sizeof OP / sizeof OP[0]; p++) {
		struct fixed f;
		long k, total;

		fixed_of(OP[p].lang, OP[p].text, &f);
		sig_fixed(&f, ref, sizeof ref);
		NCKF(f.n >= 2u && f.st == KGENOME_OK, "%s: the unrefused scan reads %u constants, status %d", OP[p].name, f.n, (int)f.st);
		armed = 1;
		seen = 0;
		fail_at = 0;
		fixed_of(OP[p].lang, OP[p].text, &f);
		armed = 0;
		total = seen;
		for (k = 1; k <= total; k++) {
			armed = 1;
			seen = 0;
			fail_at = k;
			fixed_of(OP[p].lang, OP[p].text, &f);
			armed = 0;
			sig_fixed(&f, got, sizeof got);
			checked++;
			if (strcmp(got, ref)) {
				said++;
				NCKF(f.st != KGENOME_OK, "%s: refusing allocation %ld of %ld left a different set of constants and the status is ok\n   unrefused %s\n   refused   %s", OP[p].name, k, total, ref, got);
			}
		}
	}
	printf("  %u refused allocations over %zu programs; %u changed what was read, each said so in its status\n", checked, sizeof OP / sizeof OP[0], said);
}

int main(void)
{
	powershell();
	python();
	others();
	interpreters();
	memory();
	printf("diag_text_ops: %u checks, %u failed\n", nr_ok + nr_bad, nr_bad);
	return nr_bad != 0;
}
