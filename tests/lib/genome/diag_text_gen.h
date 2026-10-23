/*
 * diag_text_gen.h - names and spacing for generated php, shared by the lib test (diag_text.c) and the engine test
 * (tests/unit/diag_text_e2e.c): one generator, so the two cannot drift into testing different things.
 */

#ifndef KOFENG_TESTS_DIAG_TEXT_GEN_H
#define KOFENG_TESTS_DIAG_TEXT_GEN_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * NAMES AND SPACING THAT A PERSON WRITING A SHELL WOULD NOT CHOOSE. The route reads a variable by its name and a call by its
 * spelling, so the checks above with short tidy names prove little: a variable can be any run of letters (either case), digits
 * and "_" that does not begin with a digit, and any byte from 0x80 up (php reads those as letters); variables are case sensitive
 * and functions are not; and anywhere php allows white space it allows a comment, a line break of either kind, a tab, or nothing.
 * Each template below is a program whose two facts are known whatever the names are and whatever sits between its tokens.
 */
static uint32_t rng_state = 20251019u;

static inline uint32_t rnd(void)
{
	rng_state = rng_state * 1103515245u + 12345u;
	return rng_state >> 16;
}

/* A variable name (without its "$"): 1 to 14 bytes, never starting with a digit. */
static inline void rname(char *o)
{
	static const char first[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
	static const char rest[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
	uint32_t n = 1u + rnd() % 14u, i;

	o[0] = first[rnd() % (sizeof first - 1u)];
	for (i = 1; i < n; i++) {
		uint32_t r = rnd() % 16u;

		o[i] = r == 0 ? (char)(0x80u + rnd() % 0x80u) : rest[rnd() % (sizeof rest - 1u)];
	}
	o[n] = 0;
	if (rnd() % 8u == 0u) {                 /* the name of a function the route knows: a variable is not that function */
		static const char *const known[] = { "eval", "base64_decode", "system", "exec", "a", "_get" };   /* "_GET" itself is the request, not a name */

		strcpy(o, known[rnd() % (sizeof known / sizeof known[0])]);
	}
}

/* What may stand where php allows white space. */
static inline const char *rsp(void)
{
	static const char *const v[] = { "", " ", "  ", "\t", "\n", "\r\n", " /* c */ ", "\n// c\n", "\n# c\n", "\t\t \n ",
					 "/**/", " /* a */ /* b */ " };

	return v[rnd() % (sizeof v / sizeof v[0])];
}

/* Fill `out` from `tpl`: "@" is a gap, "~1" "~2" "~3" are the template's variable names (the template writes the "$"). */
static inline void expand(char *out, size_t cap, const char *tpl, const char *const *vn)
{
	size_t w = 0;

	for (; *tpl && w + 64u < cap; tpl++) {
		if (*tpl == '@') {
			w += (size_t)snprintf(out + w, cap - w, "%s", rsp());
		} else if (*tpl == '~' && tpl[1] >= '1' && tpl[1] <= '3') {
			w += (size_t)snprintf(out + w, cap - w, "%s", vn[*++tpl - '1']);
		} else {
			out[w++] = *tpl;
		}
	}
	out[w] = 0;
}


#endif /* KOFENG_TESTS_DIAG_TEXT_GEN_H */
