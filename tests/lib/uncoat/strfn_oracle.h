#ifndef STRFN_ORACLE_H
#define STRFN_ORACLE_H

/*
 * strfn_oracle.h - what the tests of kuncoat's string ops that are checked against the real interpreters (strfn_lists.c, strfn_shell.c) share: the guard-buffer call, the
 * exact-room check, the enumeration of words over a small alphabet, and the runner that feeds an interpreter (python 3, perl or bash) a script and reads what it prints. A script
 * is passed base64 coded so that no quote of the shell is in the way. An interpreter that is not on the machine is SAID and its cases are skipped.
 */

#include "hostile_common.h"

#include <kofstrlist.h>

#include "../interp_oracle.h"

#define BIG 70000u

static struct hv_gb gin, gout;
static uint8_t res[BIG];

static inline struct kuncoat_step mk(uint32_t algo, uint32_t flags, uint32_t k32, const uint8_t *key, uint32_t klen)
{
	struct kuncoat_step s;

	memset(&s, 0, sizeof s);
	s.algo = algo;
	s.dir = KUNCOAT_DECODE;
	s.flags = flags;
	s.k32 = k32;
	s.key = key;
	s.key_len = klen;
	return s;
}

/* One call through the guard buffers; the answer is in `res`. */
static inline enum kuncoat_status T(const struct kuncoat_step *s, const uint8_t *in, size_t n, size_t cap, uint64_t *prod)
{
	const uint8_t *ip = hv_in(&gin, in, n);
	uint8_t *op = hv_out(&gout, cap);
	uint64_t p = 0xDEADBEEFu;
	enum kuncoat_status st = kuncoat_transform(s, ip, n, op, cap, &p);

	CK(hv_status_ok(st));
	CK(p <= cap);
	CK(hv_out_canary_ok(op));
	if (p <= cap && p <= BIG)
		memcpy(res, op, (size_t)p);
	*prod = p;
	return st;
}

/* The step must give exactly want[0..wn) with room for it and refuse with room for one byte less. */
static inline void exact(const struct kuncoat_step *s, const uint8_t *in, size_t n, const uint8_t *want, size_t wn, const char *what, unsigned long i)
{
	uint64_t p;
	enum kuncoat_status st;

	if (!wn) {
		st = T(s, in, n, 1, &p);
		CKF(st == KUNCOAT_OK && p == 0, "%s %lu: an empty answer, got status %d produced %llu", what, i, (int)st, (unsigned long long)p);
		return;
	}
	st = T(s, in, n, wn, &p);
	CKF(st == KUNCOAT_OK && p == wn && !memcmp(res, want, wn), "%s %lu: status %d produced %llu of %zu (subject %.*s)", what, i, (int)st, (unsigned long long)p, wn, (int)n,
	    (const char *)in);
	st = T(s, in, n, wn - 1u ? wn - 1u : 1u, &p);
	if (wn > 1u)
		CKF(st == KUNCOAT_OVER_BUDGET, "%s %lu: one byte short must be over budget, got %d", what, i, (int)st);
	else
		CKF(st == KUNCOAT_OK || st == KUNCOAT_OVER_BUDGET, "%s %lu: status %d", what, i, (int)st);
}

/* The `idx`th string of length `len` over the alphabet `al` (its digits low to high): the interpreters' scripts below enumerate the same words the same way. */
static inline void word(const char *al, uint8_t *o, unsigned idx, unsigned len)
{
	unsigned base = (unsigned)strlen(al), k;

	for (k = 0; k < len; k++) {
		o[k] = (uint8_t)al[idx % base];
		idx /= base;
	}
}

static inline unsigned ipow(unsigned b, unsigned e)
{
	unsigned r = 1;

	while (e--)
		r *= b;
	return r;
}

static inline void hexs(const uint8_t *p, size_t n, char *o)
{
	size_t k;

	for (k = 0; k < n; k++)
		sprintf(o + 2u * k, "%02x", p[k]);
	o[2u * n] = 0;
}

/* A framed list as the scripts print one: "<count>:<hex>,<hex>,...". */
static inline void list_text(const uint8_t *p, size_t n, char *o)
{
	uint64_t at = 0, scan = 0;
	const uint8_t *e;
	uint32_t l, cnt = 0, k;
	int broken = 0;
	char *w = o;

	while (kof_strlist_next(p, n, &scan, &e, &l, &broken))
		cnt++;
	w += sprintf(w, "%u:", cnt);
	cnt = 0;
	while (kof_strlist_next(p, n, &at, &e, &l, &broken)) {
		if (cnt++)
			*w++ = ',';
		for (k = 0; k < l; k++)
			w += sprintf(w, "%02x", e[k]);
	}
	*w = 0;
}

#endif /* STRFN_ORACLE_H */
