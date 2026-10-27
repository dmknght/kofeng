/*
 * kx_find - the viewer's Find, kofexamine/kv_find.c, driven without a terminal. The unit is INCLUDED into this file (find_bytes,
 * find_next and find_prev are static) and the three things it asks of the rest of the viewer - the bytes the row shows, where a
 * file offset is in the row's region, and the jump - are the stubs below. What is held is the search itself against a model: text,
 * case-insensitive text, hex (with the blanks a paste brings, an odd last digit), a regular expression (the compile and its
 * refusal), the scope (this region / the whole object), forward and backward with the wrap, the hit count and the index of the
 * hit, the "No match" and compiler-message texts, and the selection the hit leaves.
 * tests/tui has no test of Find (kv_find.c had 0 of 122 lines executed by it).
 *
 * Known defect pinned: EX-11 find_bytes cuts the pattern at 64 bytes (the field holds 79), so a search for a longer text finds
 * where its first 64 bytes are.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../kofexamine/kv.h"
#include "known_miss.h"

static int fails, checks;

#undef CK
#define CK(cond) do { checks++; if (!(cond)) { if (fails < 20) printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

/* ---- the stubs: what the rest of the viewer would answer ----------------------------------------------- */

static const uint8_t *g_bytes;
static uint64_t g_n, g_reg_lo, g_reg_hi;     /* the region of the row: file offsets [lo, hi) are in it */
static unsigned g_shows;
static uint64_t g_shown_at;

const uint8_t *view_bytes(const struct view *v, uint64_t *n)
{
	(void)v;
	*n = g_n;
	return g_bytes;
}

uint64_t view_unmap(const struct view *v, uint64_t off)
{
	(void)v;
	return off >= g_reg_lo && off < g_reg_hi ? off : KGENOME_BROKEN;
}

void view_show_in(struct view *v, uint32_t obj, uint8_t sym, uint64_t at, int flag)
{
	(void)v; (void)obj; (void)sym; (void)flag;
	g_shows++;
	g_shown_at = at;
}

#include "../../kofexamine/kv_find.c"

/* ---- the model ------------------------------------------------------------------------------------------ */

static struct view V;

/* every offset where `pat` (n bytes) is in the haystack, honouring case folding for text and the region scope */
static unsigned model_hits(const uint8_t *pat, unsigned n, int icase, int scope, uint64_t *out, unsigned cap)
{
	unsigned k = 0;
	uint64_t i;

	if (!n || n > g_n)
		return 0;
	for (i = 0; i + n <= g_n; i++) {
		unsigned j;
		int eq = 1;

		for (j = 0; j < n && eq; j++) {
			uint8_t a = g_bytes[i + j], b = pat[j];

			if (icase) {
				if (a >= 'A' && a <= 'Z') a = (uint8_t)(a + 32);
				if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + 32);
			}
			eq = a == b;
		}
		if (!eq)
			continue;
		if (scope == 0 && !(i >= g_reg_lo && i < g_reg_hi))
			continue;
		if (k < cap)
			out[k] = i;
		k++;
	}
	return k;
}

static void setup(const char *find, int hex, int icase, int regex, int scope)
{
	memset(&V, 0, sizeof V);
	snprintf(V.find, sizeof V.find, "%s", find);
	V.find_hex = hex;
	V.find_icase = icase;
	V.find_regex = regex;
	V.find_scope = scope;
	V.find_at = KGENOME_BROKEN;
	find_compile(&V);
	g_shows = 0;
}

static void check_run(const char *tag, const uint8_t *pat, unsigned pn, int icase, int scope)
{
	static uint64_t hits[4096];
	uint64_t at;
	unsigned nh = model_hits(pat, pn, icase, scope, hits, 4096), i;
	unsigned long steps = 0;

	/* forward from nothing: the first hit; each next one is the next; after the last it wraps to the first */
	V.find_at = KGENOME_BROKEN;
	for (i = 0; i < nh + 1 && nh; i++) {
		find_run(&V, 0);
		steps++;
		at = V.find_at;
		if (at != hits[i % nh]) {
			printf("  FAIL %s: forward step %u -> %llu wanted %llu\n", tag, i, (unsigned long long)at, (unsigned long long)hits[i % nh]);
			fails++;
			return;
		}
		CK(V.find_n == nh && V.find_i == (i % nh) + 1 && V.find_msg[0] == 0);
		CK(g_shown_at == at);
		if (at >= g_reg_lo && at < g_reg_hi)
			CK(V.sel_a == at && V.sel_b == at + pn - 1);
	}
	/* backward: from a hit to the one before it, from the first to the last (the wrap) */
	if (nh) {
		V.find_at = hits[0];
		find_run(&V, 1);
		CK(V.find_at == hits[nh - 1]);                 /* the wrap */
		if (nh >= 2) {
			V.find_at = hits[nh - 1];
			find_run(&V, 1);
			CK(V.find_at == hits[nh - 2]);
		}
	} else {
		V.find_at = KGENOME_BROKEN;
		find_run(&V, 0);
		CK(V.find_n == 0 && V.find_i == 0 && !strcmp(V.find_msg, "No match"));
		find_run(&V, 1);
		CK(V.find_n == 0 && !strcmp(V.find_msg, "No match"));
	}
	(void)steps;
}

static uint8_t hay[4096];

static void text_suite(void)
{
	unsigned i;

	for (i = 0; i < sizeof hay; i++)
		hay[i] = (uint8_t)"abcAbC xyzXYZ"[i % 13];
	memcpy(hay + 1000, "NEEDLE needle Needle", 20);
	g_bytes = hay;
	g_n = sizeof hay;
	g_reg_lo = 0;
	g_reg_hi = g_n;
	setup("needle", 0, 0, 0, 1);
	check_run("text exact", (const uint8_t *)"needle", 6, 0, 1);
	setup("needle", 0, 1, 0, 1);
	check_run("text icase", (const uint8_t *)"needle", 6, 1, 1);
	setup("abc", 0, 0, 0, 1);
	check_run("text many", (const uint8_t *)"abc", 3, 0, 1);
	setup("zzz-not-there", 0, 0, 0, 1);
	check_run("text absent", (const uint8_t *)"zzz-not-there", 13, 0, 1);
	/* the scope: this region only */
	g_reg_lo = 500;
	g_reg_hi = 1015;
	setup("abc", 0, 0, 0, 0);
	check_run("text region", (const uint8_t *)"abc", 3, 0, 0);
	setup("abc", 0, 0, 0, 1);
	check_run("text whole object, region set", (const uint8_t *)"abc", 3, 0, 1);
	g_reg_lo = 0;
	g_reg_hi = g_n;
	/* a pattern longer than the haystack, and an empty one: nothing */
	g_n = 4;
	setup("abcAbC", 0, 0, 0, 1);
	find_run(&V, 0);
	CK(!strcmp(V.find_msg, "No match") && V.find_n == 0);
	g_n = sizeof hay;
	setup("", 0, 0, 0, 1);
	find_run(&V, 0);
	CK(!strcmp(V.find_msg, "No match"));
}

static void hex_suite(void)
{
	static const struct { const char *text; unsigned n; uint8_t b[8]; } r[] = {
		{ "41 42", 2, { 'A', 'B' } }, { "4142", 2, { 'A', 'B' } }, { " 4 1  4 2 ", 2, { 'A', 'B' } },
		{ "414", 1, { 'A' } }, { "41g2", 1, { 'A' } }, { "zz", 0, { 0 } }, { "", 0, { 0 } }, { "FF fe", 2, { 0xff, 0xfe } }, { "\t41\t42", 2, { 'A', 'B' } } };
	unsigned i;
	uint8_t buf[64];

	g_bytes = hay;
	g_n = sizeof hay;
	g_reg_lo = 0;
	g_reg_hi = g_n;
	memcpy(hay + 2000, "\xff\xfe", 2);
	for (i = 0; i < sizeof r / sizeof r[0]; i++) {
		unsigned n;

		setup(r[i].text, 1, 0, 0, 1);
		n = find_bytes(&V, buf, sizeof buf);
		CK(n == r[i].n && !memcmp(buf, r[i].b, n));
		if (n) {
			check_run(r[i].text, r[i].b, n, 0, 1);
			/* case folding never applies to a hex pattern: "41" is not "61" */
			setup(r[i].text, 1, 1, 0, 1);
			check_run(r[i].text, r[i].b, n, 0, 1);
		}
	}
	/* the room: a hex pattern is cut at the room it is given, not past it */
	{
		char big[80];
		uint8_t small[3];

		memset(big, 0, sizeof big);
		memcpy(big, "41424344454647", 14);
		setup(big, 1, 0, 0, 1);
		CK(find_bytes(&V, small, sizeof small) == 3 && !memcmp(small, "ABC", 3));
	}
}

static void regex_suite(void)
{
	uint8_t prog[512];
	uint32_t n = 77;
	char err[96];

	g_bytes = hay;
	g_n = sizeof hay;
	g_reg_lo = 0;
	g_reg_hi = g_n;
	memset(hay + 3000, 'x', 10);
	memcpy(hay + 3000, "ab12cd", 6);
	/* a pattern with a concrete run compiles and finds the first match */
	setup("ab[0-9]{2}cd", 0, 0, 1, 1);
	CK(!V.find_rx_bad && V.find_prog_n > 0);
	find_run(&V, 0);
	CK(V.find_at == 3000 && V.find_n >= 1 && V.find_msg[0] == 0);
	setup("AB[0-9]{2}CD", 0, 1, 1, 1);
	find_run(&V, 0);
	CK(V.find_at == 3000);
	setup("AB[0-9]{2}CD", 0, 0, 1, 1);
	find_run(&V, 0);
	CK(!strcmp(V.find_msg, "No match") && V.find_n == 0);
	/* a pattern the engine refuses (an unbounded repeat): the field says so, the search does nothing, and the message is the compiler's, not "No match" */
	setup("ab[0-9]+cd", 0, 0, 1, 1);
	CK(V.find_rx_bad && V.find_prog_n == 0);
	find_run(&V, 0);
	CK(V.find_msg[0] && strcmp(V.find_msg, "No match") && V.find_n == 0);
	setup("((((", 0, 0, 1, 1);
	CK(V.find_rx_bad && V.find_prog_n == 0 && V.find_rx_err[0]);
	find_run(&V, 0);
	CK(V.find_n == 0 && !strcmp(V.find_msg, V.find_rx_err));
	/* rx_compile directly: empty text is "nothing to compile", not an error; the error is copied out */
	CK(rx_compile("", prog, sizeof prog, &n, err, sizeof err) == 0 && n == 0 && err[0] == 0);
	CK(rx_compile(NULL, prog, sizeof prog, &n, err, sizeof err) == 0 && n == 0);
	CK(rx_compile("((((", prog, sizeof prog, &n, err, sizeof err) == 0 && n == 0 && err[0]);
	CK(rx_compile("((((", prog, sizeof prog, &n, NULL, 0) == 0);
	CK(rx_compile("ab[0-9]{2}cd", prog, 4, &n, err, sizeof err) == 0 || n <= 4);      /* a room too small is a refusal, not an overflow */
	/* a regex field with the Regex tick off compiles nothing */
	setup("ab[0-9]{2}cd", 0, 0, 0, 1);
	CK(V.find_prog_n == 0 && !V.find_rx_bad);
}

static void hostile_suite(void)
{
	uint8_t *big = malloc(1u << 20);
	unsigned i;

	CK(big != NULL);
	if (!big)
		return;
	/* a megabyte with a hit on every byte: the hit counter counts them all (it is a count, not a list), and a search is not quadratic */
	memset(big, 'a', 1u << 20);
	g_bytes = big;
	g_n = 1u << 20;
	g_reg_lo = 0;
	g_reg_hi = g_n;
	setup("a", 0, 0, 0, 1);
	find_run(&V, 0);
	CK(V.find_at == 0 && V.find_n == (1u << 20) && V.find_i == 1);
	V.find_at = g_n - 1;
	find_run(&V, 1);
	CK(V.find_at == g_n - 2);
	big[(1u << 20) - 1] = 'b';
	setup("ab", 0, 0, 0, 1);
	find_run(&V, 0);
	CK(V.find_at == g_n - 2 && V.find_n == 1);
	/* a hit at the very last byte of a pattern's room, and none when the pattern is one byte longer than what is left */
	setup("b", 0, 0, 0, 1);
	find_run(&V, 0);
	CK(V.find_at == g_n - 1);
	big[(1u << 20) - 1] = 0;
	setup("a\x01", 0, 0, 0, 1);
	find_run(&V, 0);
	CK(!strcmp(V.find_msg, "No match"));
	/* bytes that are not text: NUL in the haystack, 0xff in the pattern */
	memset(big, 0xff, 4096);
	setup("\xff\xff", 0, 1, 0, 1);
	find_run(&V, 0);
	CK(V.find_at == 0 && V.find_n == 4095);
	for (i = 0; i < 64; i++)
		V.find[i] = 'q';
	free(big);

	/* EX-11 (2026-10-27, M) [sev M]: find_bytes holds 64 bytes and the field holds 79, so a text of 65..79 characters is searched
	 * as its first 64 and reported found where only that prefix is: a search that says "found" about text that is not in the object
	 * (a cap that changes the answer without saying). Trigger: type 70 characters whose first 64 occur. Fix: refuse (say "too long")
	 * or search what was typed. */
	{
		static uint8_t h2[256];
		char pat[80];

		memset(h2, 'k', sizeof h2);
		g_bytes = h2;
		g_n = sizeof h2;
		g_reg_lo = 0;
		g_reg_hi = g_n;
		memset(pat, 'k', 70);
		pat[70] = 'Z';
		pat[71] = 0;
		setup(pat, 0, 0, 0, 1);
		find_run(&V, 0);
		KM_CHECK(!strcmp(V.find_msg, "No match"), "a 71-character search is found where only its first 64 characters are", "EX-11");
	}
}

int main(void)
{
	text_suite();
	hex_suite();
	regex_suite();
	hostile_suite();
	printf("kx_find: %d checks, %s\n", checks, fails || km_failed() ? "FAILED" : "ok");
	return fails != 0 || km_failed();
}
