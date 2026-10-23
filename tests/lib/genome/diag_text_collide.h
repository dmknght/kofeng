/*
 * diag_text_collide.h - NAMES THAT SHARE ONE FNV-1A HASH, built for the tests of the tables of the TEXT route (diag_text_defects.c, diag_text_seed.c). One generator, so the two cannot
 * mean different things by "colliding": the attack the audit used (h/coll.c, G1), kept as the input the tables are measured against.
 */

#ifndef KOFENG_TESTS_DIAG_TEXT_COLLIDE_H
#define KOFENG_TESTS_DIAG_TEXT_COLLIDE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <kofcore.h>

static uint32_t fnv_run(uint32_t h, const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		h = kof_hash_step(h, (uint8_t)s[i]);
	return h;
}

struct hrec {
	uint32_t h;
	uint32_t idx;
};

static int hrec_cmp(const void *a, const void *b)
{
	const struct hrec *x = a, *y = b;

	return x->h != y->h ? (x->h < y->h ? -1 : 1) : (x->idx < y->idx ? -1 : x->idx > y->idx);
}

/*
 * 2^levels NAMES THAT HAVE ONE FNV-1A HASH, as the unseeded tables of the route hashed them: for each of `levels` pieces of 6 lower case letters, two pieces that take the hash
 * from the state the pieces before them left to the same new state (a birthday search over 300000 random pieces); a name is one piece of each level, so every combination hashes alike.
 * The route's hash of a name is this one run from KOF_HASH_INIT, or - for a path - from the state its fixed prefix leaves. This is the generator the audit used (h/coll.c), kept
 * here as the attack the fix is measured against: a seeded or otherwise different hash does not break THESE names, it makes the collision not carry over.
 */
static char **collide(uint32_t init, unsigned levels, size_t *count)
{
	enum { TRY = 300000 };
	static char cand[TRY][7];
	static struct hrec rec[TRY];
	char pair[16][2][7];
	uint32_t st = init, seed = 0x9e3779b9u;
	unsigned l, k;
	size_t n = (size_t)1 << levels, i, plen = 6u * levels;
	char **names;

	for (l = 0; l < levels; l++) {
		int found = 0;

		while (!found) {
			uint32_t i1;

			for (i1 = 0; i1 < TRY; i1++) {
				for (k = 0; k < 6; k++) {
					seed = seed * 1103515245u + 12345u;
					cand[i1][k] = (char)('a' + (seed >> 16) % 26u);
				}
				cand[i1][6] = 0;
				rec[i1].h = fnv_run(st, cand[i1], 6);
				rec[i1].idx = i1;
			}
			qsort(rec, TRY, sizeof rec[0], hrec_cmp);
			for (i1 = 1; i1 < TRY && !found; i1++)
				if (rec[i1].h == rec[i1 - 1u].h && memcmp(cand[rec[i1].idx], cand[rec[i1 - 1u].idx], 6) != 0) {
					memcpy(pair[l][0], cand[rec[i1 - 1u].idx], 7);
					memcpy(pair[l][1], cand[rec[i1].idx], 7);
					st = rec[i1].h;
					found = 1;
				}
		}
	}
	names = malloc(n * sizeof *names);
	for (i = 0; i < n; i++) {
		names[i] = malloc(plen + 1u);
		for (l = 0; l < levels; l++)
			memcpy(names[i] + 6u * l, pair[l][(i >> l) & 1u], 6);
		names[i][plen] = 0;
	}
	*count = n;
	return names;
}

static void names_free(char **names, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(names[i]);
	free(names);
}

#endif /* KOFENG_TESTS_DIAG_TEXT_COLLIDE_H */
