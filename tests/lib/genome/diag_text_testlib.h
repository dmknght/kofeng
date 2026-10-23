/*
 * diag_text_testlib.h - what the tests of the TEXT route share (diag_text_langs.c, diag_text_stmt.c): the failure count and its check, a scan of a text in a language, the
 * names the random tests give a variable (the hostile shapes are counted, not timed: diag_text_work.c). One definition, so the two tests cannot drift apart on what a scan or a name is.
 */

#ifndef KOFENG_TESTS_DIAG_TEXT_TESTLIB_H
#define KOFENG_TESTS_DIAG_TEXT_TESTLIB_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <phenotype/diag_scan.h>

static int fails;

#define CK(c, ...) do { if (!(c)) { printf("  FAIL %s:%d  ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static struct kgenome_diag_scan *scan_l(uint32_t lang, const char *src)
{
	struct kgenome_diag_text_req rq = { .base = (const uint8_t *)src, .size = strlen(src), .lang = lang };

	return kgenome_diag_scan_text(&rq);
}

static const char alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
static uint32_t rs = 20261020u;

static uint32_t rnd(void)
{
	rs = rs * 1103515245u + 12345u;
	return rs >> 16;
}

/* a name that is no keyword of any of the languages: two upper case letters, a digit, then letters (js, python, lua and ruby keywords are lower case) */
static void rname(char *o)
{
	uint32_t n = 3u + rnd() % 9u, i;

	o[0] = alpha[26u + rnd() % 26u];
	o[1] = alpha[26u + rnd() % 26u];
	o[2] = (char)('0' + rnd() % 10u);
	for (i = 3; i < n; i++)
		o[i] = alpha[rnd() % 52u];
	o[n] = 0;
}

#endif /* KOFENG_TESTS_DIAG_TEXT_TESTLIB_H */
