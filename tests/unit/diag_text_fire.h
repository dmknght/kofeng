/*
 * diag_text_fire.h - what the engine-level tests of the TEXT route share (diag_text_langs_golden.c, diag_text_stmt_golden.c): whether the verdict the engine makes for some bytes lists
 * a diagnose, and how many of the route's fixture set fire. One definition of "fires", so the two tests cannot disagree about what a verdict lists.
 */

#ifndef KOFENG_TESTS_DIAG_TEXT_FIRE_H
#define KOFENG_TESTS_DIAG_TEXT_FIRE_H

#include "caps_fix.h"
#include "caps_e2e.h"

/* whether the engine's verdict for the bytes lists the diagnose `name` */
static int fires(const char *src, const char *name)
{
	struct e2e r;
	const struct kof_finding *f;
	uint32_t i, k;

	if (!e2e_scan((const uint8_t *)src, strlen(src), &r) || !r.n)
		return 0;
	for (k = 0; k < r.n; k++) {
		if (!r.o[k].has_verdict)
			continue;
		f = &r.o[k].vf;
		for (i = 0; i < f->n_diag; i++) {
			const char *n = kdb_diagnose_name(e2e_eng, f->diag[i]);

			if (n && !strcmp(n, name))
				return 1;
		}
	}
	return 0;
}

/* how many of the diagnoses of the route's fixture set fire on the text */
static int fires_any(const char *src)
{
	static const char *const set[] = { "php_request_exec", "php_request_eval", "php_decode_eval", "php_request_call", "php_built_eval", "php_decode_exec",
					   "php_request_load", "php_decode_load", "php_decode_create", "php_request_create", "php_built_call", "php_create_call",
					   "php_decode_call", "php_built_exec", "php_built_create", "php_built_decode", "php_request_write" };
	uint32_t i;
	int n = 0;

	for (i = 0; i < sizeof set / sizeof set[0]; i++)
		n += fires(src, set[i]);
	return n;
}

/* A diagnose, a text, and whether the diagnose must fire on it. */
struct row {
	const char *diag;
	const char *src;
	int         want;
};

/* Every row, through the whole engine: a row that does not say what the engine does fails, whichever way it is wrong. */
static void fire_rows(const struct row *rows, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		char src[2048];
		int got;

		snprintf(src, sizeof src, "%s", rows[i].src);
		got = fires(src, rows[i].diag);
		if (got != rows[i].want) {
			printf("  FAIL %s %s the text:\n%s\n", rows[i].diag, rows[i].want ? "must fire on" : "must not fire on", rows[i].src);
			fails++;
		}
	}
}

#endif /* KOFENG_TESTS_DIAG_TEXT_FIRE_H */
