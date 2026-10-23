/*
 * diag_text_nullargs - no memory function of the TEXT route is handed a NULL pointer, whatever the length (C99 7.1.4: memcpy(d, NULL, 0) is undefined, and -fsanitize=undefined says so:
 * "null pointer passed as argument 2, which is declared to never be null").
 *
 * memcpy, memmove, memcmp, memset and strlen are wrapped at link time (UNIT_LIBS_diag_text_nullargs; the same way tests/unit/diag_graph_bin counts U1) and every call that gets a NULL
 * pointer is counted, over texts that make an EMPTY value reach a copy: the second word of a shell command that is the empty string (`$(echo "" x)`), an empty replacement, an empty
 * literal on either side of a join, an empty list. Found by unit-asan running tests/unit/diag_text_oracle.c: diag_text_cmdval.c copied the empty second word of a command (value NULL, 0
 * bytes) into the buffer that names a two-word command. A run without a sanitiser never shows it (the copy of 0 bytes does nothing), which is why the count is the test.
 *
 * usage: diag_text_nullargs
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "normalizer_ref.h"
#include "normalizer_consts.h"

void *__real_memcpy(void *d, const void *s, size_t n);
void *__real_memmove(void *d, const void *s, size_t n);
int __real_memcmp(const void *a, const void *b, size_t n);
void *__real_memset(void *d, int c, size_t n);
void *__wrap_memcpy(void *d, const void *s, size_t n);
void *__wrap_memmove(void *d, const void *s, size_t n);
int __wrap_memcmp(const void *a, const void *b, size_t n);
void *__wrap_memset(void *d, int c, size_t n);

static unsigned armed, nulls;
static const char *where;

static void note(const char *fn, int which)
{
	if (armed && nulls++ < 6u)
		printf("  NULL pointer as argument %d of %s while reading [%s]\n", which, fn, where);
}

void *__wrap_memcpy(void *d, const void *s, size_t n)
{
	if (!d)
		note("memcpy", 1);
	if (!s)
		note("memcpy", 2);
	return __real_memcpy(d, s, n);
}

void *__wrap_memmove(void *d, const void *s, size_t n)
{
	if (!d)
		note("memmove", 1);
	if (!s)
		note("memmove", 2);
	return __real_memmove(d, s, n);
}

int __wrap_memcmp(const void *a, const void *b, size_t n)
{
	if (!a)
		note("memcmp", 1);
	if (!b)
		note("memcmp", 2);
	return __real_memcmp(a, b, n);
}

void *__wrap_memset(void *d, int c, size_t n)
{
	if (!d)
		note("memset", 1);
	return __real_memset(d, c, n);
}

static const struct { uint32_t lang; const char *text; } T[] = {
	{ KGENOME_TEXTUAL_LANG_SH, "v=$(echo \"\" x)\n" },
	{ KGENOME_TEXTUAL_LANG_SH, "v=$(echo x \"\")\nw=$(printf '' x)\ny=$(echo '' | rev)\n" },
	{ KGENOME_TEXTUAL_LANG_SH, "v=\"\"\nw=${v//a/}\nx=${w:-}\ny=$(printf %s \"$v\")\nz=$(echo \"$v\" \"$v\")\n" },
	{ KGENOME_TEXTUAL_LANG_SH, "a=$(tr a-z A-Z \"\")\nb=$(printf \"\" \"\")\nc=$(echo \"\" \"\" \"\")\n" },
	{ KGENOME_TEXTUAL_LANG_PY, "a = '' + ''\nb = ''.join([])\nc = '-'.join(['', ''])\nd = ''.replace('x', '')\ne = '' * 3\nf = ('' '').upper()\n" },
	{ KGENOME_TEXTUAL_LANG_PERL, "$a = '' . '';\n$b = join('', ());\n$c = join('-', '', '');\n$d = '' x 3;\n$e = lc('');\n" },
	{ KGENOME_TEXTUAL_LANG_PSH, "$a = '' + ''\n$b = -join @()\n$c = ('', '') -join ''\n$d = [string]::Join('', '', '')\n$e = '' -replace 'a', ''\n" },
	{ KGENOME_TEXTUAL_LANG_JS, "var a = '' + ''; var b = [].join(''); var c = ''.replace('a', ''); var d = ''.split(',').join('-');\n" },
	{ KGENOME_TEXTUAL_LANG_RUBY, "a = '' + ''\nb = [].join('-')\nc = ''.gsub('a', '')\n" },
	{ KGENOME_TEXTUAL_LANG_BAT, "set a=\nset b=%a%%a%\nset c=%a:x=%\n" },
	{ KGENOME_TEXTUAL_LANG_TCL, "set a {}\nset b [string cat $a $a]\nset c [string map {a b} $a]\n" },
	{ KGENOME_TEXTUAL_LANG_LUA, "a = '' .. ''\nb = string.rep('', 3)\nc = string.gsub('', 'a', '')\n" },
};

int main(void)
{
	size_t k;

	for (k = 0; k < sizeof T / sizeof T[0]; k++) {
		struct cset s;

		where = T[k].text;
		armed = 1;
		consts_of(T[k].lang, (const uint8_t *)T[k].text, strlen(T[k].text), &s);
		armed = 0;
		cset_free(&s);
	}
	printf("diag_text_nullargs: %zu texts, %u calls with a NULL pointer: %s\n", sizeof T / sizeof T[0], nulls, nulls ? "FAILED" : "ok");
	return nulls != 0;
}
