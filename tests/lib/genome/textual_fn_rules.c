#define _GNU_SOURCE
/*
 * textual_fn_rules - what a row of the function table says about its ARGUMENTS, as kgenome_textual_fn_run applies it before the op is asked (the flags and fields of
 * struct kgenome_textual_fn): where a cut ends (a length, an end index exclusive or inclusive, how many bytes of the end to keep), what a start past the end and a number
 * below 0 do, and the bytes a parameter may not hold, an empty search, a list of translations with a byte twice, one-byte subjects, the ASCII subject.
 *
 * The op is not run here (the lib has no kuncoat): the hook is a RECORDER that answers php's substr over the numbers it was handed, so that what comes out is the cut
 * the language's own function makes - each reference below is written from the language's rule (ECMA-262 for slice, substring and substr; the lua manual for string.sub;
 * the vbscript reference for Mid, Left and Right; the .NET documentation for Substring) and differently from the code under test (an index walk, not the arithmetic).
 * [Unverified] against node, lua, wscript and powershell: none is on this machine; the rules are the documents'.
 *
 * Every start and end from -3 to 9 is asked of every subject of 0 to 6 bytes, with and without the optional number; a refusal and an answer must each be the language's.
 */

#include "textual_check.h"

#include <kofbytes.h>

/* php's substr over the numbers the call carries: the recorded call is what the row made of the language's arguments */
static int substr_hook(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n_out)
{
	int64_t from = c->k1, cnt;

	(void)u;
	if (c->op != KGENOME_TEXTUAL_DEC_SLICE)
		return 0;
	if (from < 0)
		from = (int64_t)len + from < 0 ? 0 : (int64_t)len + from;
	if (from > (int64_t)len) {
		*n_out = 0;
		return 1;
	}
	cnt = c->to_end ? (int64_t)len - from : c->k2;
	if (cnt < 0)
		cnt = (int64_t)len - from + cnt < 0 ? 0 : (int64_t)len - from + cnt;
	if (cnt > (int64_t)len - from)
		cnt = (int64_t)len - from;
	if ((uint64_t)cnt > cap)
		return 0;
	memcpy(out, in + from, (size_t)cnt);
	*n_out = (uint32_t)cnt;
	return 1;
}

/* One call of a row over (subject, first number, optional second number): 1 and the answer, or 0. */
static int cut(const struct kgenome_textual_fn *f, const char *s, long a, int has_b, long b, char *got)
{
	char na[24], nb[24];
	struct kgenome_textual_arg args[3];
	uint8_t out[64];
	uint32_t w = 0, n = 0;

	snprintf(na, sizeof na, "%ld", a);
	snprintf(nb, sizeof nb, "%ld", b);
	args[n].p = (const uint8_t *)s;
	args[n++].n = (uint32_t)strlen(s);
	{
		args[n].p = (const uint8_t *)na;
		args[n++].n = (uint32_t)strlen(na);
	}
	if (has_b) {
		args[n].p = (const uint8_t *)nb;
		args[n++].n = (uint32_t)strlen(nb);
	}
	if (!kgenome_textual_fn_run(f, args, n, substr_hook, NULL, out, sizeof out, &w))
		return 0;
	memcpy(got, out, w);
	got[w] = 0;
	return 1;
}

/* ---- the references: each is the language's rule written as an index walk ---------------------- */

static long minl(long a, long b) { return a < b ? a : b; }
static long maxl(long a, long b) { return a > b ? a : b; }

/* ECMA-262: substring clamps both numbers to 0..length and swaps them when the first is the larger. */
static void js_substring(const char *s, long a, int hb, long b, char *o)
{
	long n = (long)strlen(s), x = minl(maxl(a, 0), n), y = hb ? minl(maxl(b, 0), n) : n, lo = minl(x, y), hi = maxl(x, y), i, w = 0;

	for (i = lo; i < hi; i++)
		o[w++] = s[i];
	o[w] = 0;
}

/* slice: a number below 0 counts from the end (the row refuses those); otherwise the clamp, and no swap: an end before the start is the empty string. */
static void js_slice(const char *s, long a, int hb, long b, char *o)
{
	long n = (long)strlen(s), x = minl(a, n), y = hb ? minl(b, n) : n, i, w = 0;

	for (i = x; i < y; i++)
		o[w++] = s[i];
	o[w] = 0;
}

/* substr(start, length): the length is how many, clamped to what is left; a start past the end is "". */
static void js_substr(const char *s, long a, int hb, long b, char *o)
{
	long n = (long)strlen(s), x = minl(a, n), l = hb ? minl(b, n - x) : n - x, i, w = 0;

	for (i = x; i < x + l; i++)
		o[w++] = s[i];
	o[w] = 0;
}

/* lua: string.sub(s, i, j): from i (1 is the first), through j INCLUDED (default: the end); the numbers are the row's where they are not below 1 and 0. */
static void lua_sub(const char *s, long i, int hj, long j, char *o)
{
	long n = (long)strlen(s), x = i, y = hj ? minl(j, n) : n, k, w = 0;

	for (k = x; k <= y; k++)
		o[w++] = s[k - 1];
	o[w] = 0;
}

/* vbscript: Mid(s, start, length): from 1; a start past the end is "". */
static void vb_mid(const char *s, long a, int hb, long b, char *o)
{
	long n = (long)strlen(s), i, w = 0, end = hb ? minl(a - 1 + b, n) : n;

	for (i = a - 1; i < end; i++)
		o[w++] = s[i];
	o[w] = 0;
}

static void vb_left(const char *s, long a, char *o)
{
	long n = (long)strlen(s), i, w = 0;

	for (i = 0; i < minl(a, n); i++)
		o[w++] = s[i];
	o[w] = 0;
}

static void vb_right(const char *s, long a, char *o)
{
	long n = (long)strlen(s), i, w = 0;

	for (i = n - minl(a, n); i < n; i++)
		o[w++] = s[i];
	o[w] = 0;
}

static const char *const subjects[] = { "", "a", "ab", "abcdef", "abcd", "xyz" };

/* One row against its reference over every number: `ref_ok(a, hb, b)` says whether the language accepts the numbers at all. */
typedef void (*ref_fn)(const char *s, long a, int hb, long b, char *o);

static void run_row(const char *what, const struct kgenome_textual_fn *f, ref_fn ref, int (*ok_nums)(const char *s, long a, int hb, long b), int takes_b)
{
	unsigned si;
	long a, b;
	unsigned long cases = 0;

	for (si = 0; si < sizeof subjects / sizeof subjects[0]; si++)
		for (a = -3; a <= 9; a++)
			for (b = -3; b <= 9; b++) {
				int hb;

				for (hb = 0; hb <= (takes_b ? 1 : 0); hb++) {
					char want[16], got[64];
					int want_ok = ok_nums(subjects[si], a, hb, b), ok = cut(f, subjects[si], a, hb, b, got);

					if (want_ok)
						ref(subjects[si], a, hb, b, want);
					cases++;
					if (ok != want_ok || (ok && strcmp(got, want))) {
						printf("  FAIL %s(%s, %ld%s): the row says ok=%d [%s], the language says ok=%d [%s]\n", what, subjects[si], a, hb ? ", b" : "", ok, ok ? got : "",
						       want_ok, want_ok ? want : "");
						if (hb)
							printf("    b = %ld\n", b);
						fails++;
						return;
					}
				}
			}
	(void)cases;
}

static int ok_substring(const char *s, long a, int hb, long b) { (void)s; return a >= 0 && (!hb || b >= 0); }
static int ok_slice(const char *s, long a, int hb, long b) { (void)s; return a >= 0 && (!hb || b >= 0); }
static int ok_substr(const char *s, long a, int hb, long b) { (void)s; return a >= 0 && (!hb || b >= 0); }
static int ok_lua(const char *s, long i, int hj, long j) { (void)s; return i >= 1 && (!hj || j >= 0); }
static int ok_mid(const char *s, long a, int hb, long b) { (void)s; return a >= 1 && (!hb || b >= 0); }
static int ok_left(const char *s, long a, int hb, long b) { (void)s; (void)hb; (void)b; return a >= 0; }

static void ref_left(const char *s, long a, int hb, long b, char *o) { (void)hb; (void)b; vb_left(s, a, o); }
static void ref_right(const char *s, long a, int hb, long b, char *o) { (void)hb; (void)b; vb_right(s, a, o); }

/* .NET: Substring(start, length) is an exception for a start past the end and for a length that runs past it. */
static void net_substring(const char *s, long a, int hb, long b, char *o)
{
	long n = (long)strlen(s), i, w = 0, end = hb ? a + b : n;

	for (i = a; i < end; i++)
		o[w++] = s[i];
	o[w] = 0;
}

static int ok_net(const char *s, long a, int hb, long b)
{
	long n = (long)strlen(s);

	return a >= 0 && a <= n && (!hb || (b >= 0 && a + b <= n));
}

static void cuts(void)
{
	const uint8_t N = KGENOME_TEXTUAL_FN_NONE;
	struct kgenome_textual_fn substring = { .op = KGENOME_TEXTUAL_DEC_SLICE, .min_args = 2, .max_args = 3, .subject = 0, .param = { 1, 2 }, .numeric = 3,
						.flags = KGENOME_TEXTUAL_FN_ASCII | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_ENDIDX | KGENOME_TEXTUAL_FN_SWAP };
	struct kgenome_textual_fn slice = substring, substr = substring, lua = substring, mid = substring, left = substring, right = substring, net = substring;

	slice.flags = KGENOME_TEXTUAL_FN_ASCII | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_ENDIDX;
	substr.flags = KGENOME_TEXTUAL_FN_ASCII | KGENOME_TEXTUAL_FN_NONNEG;
	lua.flags = KGENOME_TEXTUAL_FN_BASE1 | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_ENDIDX;
	mid.flags = KGENOME_TEXTUAL_FN_ASCII | KGENOME_TEXTUAL_FN_BASE1 | KGENOME_TEXTUAL_FN_NONNEG;
	left.min_args = left.max_args = 2;
	left.param[0] = N;
	left.param[1] = 1;
	left.numeric = 2;
	left.flags = KGENOME_TEXTUAL_FN_ASCII | KGENOME_TEXTUAL_FN_NONNEG;
	right = left;
	right.flags |= KGENOME_TEXTUAL_FN_FROMEND;
	net.flags = KGENOME_TEXTUAL_FN_ASCII | KGENOME_TEXTUAL_FN_NONNEG | KGENOME_TEXTUAL_FN_STRICT;
	run_row("substring", &substring, js_substring, ok_substring, 1);
	run_row("slice", &slice, js_slice, ok_slice, 1);
	run_row("substr", &substr, js_substr, ok_substr, 1);
	run_row("string.sub", &lua, lua_sub, ok_lua, 1);
	run_row("Mid", &mid, vb_mid, ok_mid, 1);
	run_row("Left", &left, ref_left, ok_left, 0);
	run_row("Right", &right, ref_right, ok_left, 0);
	run_row("Substring", &net, net_substring, ok_net, 1);
}

/* ---- the rules about bytes ------------------------------------------------------------------------ */

/* The recorder that answers its subject as it is: a call that reaches it was allowed. */
static int echo_hook(void *u, const struct kgenome_textual_call *c, const uint8_t *in, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *n_out)
{
	(void)u;
	(void)c;
	if (len > cap)
		return 0;
	memcpy(out, in, len);
	*n_out = len;
	return 1;
}

static int run3(const struct kgenome_textual_fn *f, const char *a0, const char *a1, const char *a2, uint32_t n)
{
	struct kgenome_textual_arg a[3] = { { (const uint8_t *)a0, a0 ? (uint32_t)strlen(a0) : 0 }, { (const uint8_t *)a1, a1 ? (uint32_t)strlen(a1) : 0 },
					    { (const uint8_t *)a2, a2 ? (uint32_t)strlen(a2) : 0 } };
	uint8_t out[64];
	uint32_t w;

	return kgenome_textual_fn_run(f, a, n, echo_hook, NULL, out, sizeof out, &w);
}

static void bytes_rules(void)
{
	const uint8_t N = KGENOME_TEXTUAL_FN_NONE;
	struct kgenome_textual_fn rep = { .op = KGENOME_TEXTUAL_DEC_REPLACE, .min_args = 3, .max_args = 3, .subject = 0, .param = { 1, 2 } };
	struct kgenome_textual_fn f;

	CK(run3(&rep, "abc", "b", "x", 3));
	/* an empty search: refused where the language inserts between every character */
	f = rep;
	f.flags = KGENOME_TEXTUAL_FN_NOEMPTY;
	CK(!run3(&f, "abc", "", "x", 3));
	CK(run3(&f, "abc", "b", "", 3));
	CK(run3(&rep, "abc", "", "x", 3));                                       /* php's str_replace: the subject as it is */
	/* bytes a parameter may not hold, by role: the search, then the replacement; and the subject */
	f = rep;
	f.bad[1] = ".^";
	f.bad[2] = "$";
	CK(run3(&f, "a.b", "b", "x", 3));
	CK(!run3(&f, "abc", "a.", "x", 3));
	CK(!run3(&f, "abc", "^", "x", 3));
	CK(!run3(&f, "abc", "b", "$1", 3));
	CK(run3(&f, "abc", "b", "1", 3));
	f.bad[0] = "I";
	CK(!run3(&f, "ICE", "b", "x", 3));
	CK(run3(&f, "ice", "b", "x", 3));
	/* a byte of the list twice (ruby's tr) */
	f = rep;
	f.op = KGENOME_TEXTUAL_DEC_TRANSLATE;
	f.flags = KGENOME_TEXTUAL_FN_UNIQUE;
	CK(run3(&f, "abc", "abc", "xyz", 3));
	CK(!run3(&f, "abc", "aba", "xyz", 3));
	CK(!run3(&f, "abc", "aa", "xy", 3));
	CK(run3(&f, "abc", "ab", "xx", 3));                                       /* the second list may repeat */
	/* one byte of separator (.Split) and one byte of subject (String) */
	f = rep;
	f.op = KGENOME_TEXTUAL_DEC_SPLIT;
	f.min_args = f.max_args = 2;
	f.param[1] = N;
	f.flags = KGENOME_TEXTUAL_FN_ONESEP;
	CK(run3(&f, "a-b", "-", NULL, 2));
	CK(!run3(&f, "a-b", "--", NULL, 2));
	CK(!run3(&f, "a-b", "", NULL, 2));
	f.flags = KGENOME_TEXTUAL_FN_ONECHAR;
	f.subject = 1;
	f.param[0] = 0;
	CK(run3(&f, "-", "z", NULL, 2));
	CK(!run3(&f, "-", "zy", NULL, 2));
	CK(!run3(&f, "-", "", NULL, 2));
	CK(!run3(&f, "-", "\xc3\xa9", NULL, 2));
	/* the ASCII subject, and ignore case which needs it (the language folds Unicode's way) */
	f = rep;
	f.flags = KGENOME_TEXTUAL_FN_ASCII;
	CK(run3(&f, "abc", "b", "x", 3));
	CK(!run3(&f, "\xc3\xa9", "b", "x", 3));
	f.flags = KGENOME_TEXTUAL_FN_ICASE;
	CK(run3(&f, "ABC", "b", "x", 3));
	CK(!run3(&f, "A\xc3\xa9", "b", "x", 3));
	f.flags = 0;
	CK(run3(&f, "A\xc3\xa9", "b", "x", 3));
	/* a count that is not a number, and below 0 where the row says so (REPEAT: below 0 is the empty string, or an error) */
	f = rep;
	f.op = KGENOME_TEXTUAL_DEC_REPEAT;
	f.min_args = f.max_args = 2;
	f.param[0] = 1;
	f.param[1] = N;
	f.numeric = 1;
	CK(run3(&f, "ab", "3", NULL, 2));
	CK(run3(&f, "ab", "-1", NULL, 2));
	CK(!run3(&f, "ab", "x", NULL, 2));
	CK(!run3(&f, "ab", "2.5", NULL, 2));
	f.flags = KGENOME_TEXTUAL_FN_NONNEG;
	CK(!run3(&f, "ab", "-1", NULL, 2));
	CK(run3(&f, "ab", "0", NULL, 2));
	/* the number of arguments is the row's */
	CK(!run3(&f, "ab", NULL, NULL, 1));
	CK(!run3(&f, "ab", "1", "2", 3));
}

/* kofbytes.h against the definitions written out: every string over {a, b, 0xc3} to length 5, every set of up to two of them. */
static void byte_questions(void)
{
	static const uint8_t al[3] = { 'a', 'b', 0xc3 };
	unsigned len, idx, si;

	for (len = 0; len <= 5u; len++) {
		unsigned total = 1;

		for (idx = 0; idx < len; idx++)
			total *= 3u;
		for (idx = 0; idx < total; idx++) {
			uint8_t s[6];
			unsigned t = idx, i, j;
			int twice = 0, ascii = 1;

			for (i = 0; i < len; i++, t /= 3u)
				s[i] = al[t % 3u];
			for (i = 0; i < len; i++) {
				ascii &= s[i] < 0x80u;
				for (j = i + 1u; j < len; j++)
					twice |= s[i] == s[j];
			}
			CK(kof_bytes_has_twice(s, len) == twice);
			CK(kof_bytes_ascii(s, len) == ascii);
			for (si = 0; si < 9u; si++) {
				char set[3] = { (char)al[si % 3u], (char)al[si / 3u], 0 };
				int any = 0;

				for (i = 0; i < len; i++)
					any |= s[i] == (uint8_t)set[0] || s[i] == (uint8_t)set[1];
				CK(kof_bytes_has_any(s, len, set) == any);
			}
			CK(!kof_bytes_has_any(s, len, NULL) && !kof_bytes_has_any(s, len, ""));
		}
	}
}

int main(void)
{
	byte_questions();
	cuts();
	bytes_rules();
	printf("textual fn rules: %s\n", fails ? "FAILED" : "ok");
	return fails != 0;
}
