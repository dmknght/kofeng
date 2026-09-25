/*
 * slurp.h - read a whole file into memory, for the tests that need a fixture.
 *
 * Four of them had their own copy and two of those copies were subtly worse:
 * they refused a zero-length file by testing ftell() <= 0, which is the same
 * answer as "could not read it", and they allocated exactly n so a caller could
 * not terminate the buffer. This is the careful one of the two shapes.
 */

#ifndef KOFENG_TESTS_SLURP_H
#define KOFENG_TESTS_SLURP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * NULL on any failure, with *len set to 0. An EMPTY FILE IS NOT A FAILURE: it
 * comes back as a one-byte allocation and a length of zero, so a test that
 * feeds a decoder nothing gets to see what the decoder does with nothing.
 *
 * One byte more than the file, so a caller may NUL-terminate what it read
 * without a second allocation. The byte is not written here - a test that wants
 * a C string writes it, and one that wants bytes is not given a length that
 * includes it.
 */
static uint8_t *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *p;
	long n;

	*len = 0;
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	p = malloc((size_t)n + 1u);
	if (!p) {
		fclose(f);
		return NULL;
	}
	if (n && fread(p, 1u, (size_t)n, f) != (size_t)n) {
		free(p);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*len = (size_t)n;
	return p;
}

#endif /* KOFENG_TESTS_SLURP_H */
