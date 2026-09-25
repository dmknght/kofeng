/*
 * outsink.h - a bounded byte sink, for the decoder tests.
 *
 * The decoders report what they produced through a callback rather than a
 * buffer, so every test of one needs somewhere for the bytes to land. Two of
 * them had the same struct and the same five lines under the same names.
 */

#ifndef KOFENG_TESTS_OUTSINK_H
#define KOFENG_TESTS_OUTSINK_H

#include <stdint.h>
#include <string.h>

struct out {
	uint8_t *dst;
	uint64_t cap, n;
};

/*
 * COUNTS EVERYTHING AND STORES WHAT FITS, which is what lets a test assert on
 * the produced LENGTH of a stream that is larger than the buffer it was given.
 * Overrunning would be the bug the bound exists to catch, so the copy is
 * clamped and `n` is not.
 */
static int out_sink(void *user, const uint8_t *p, uint32_t n)
{
	struct out *o = user;

	if (o->n < o->cap) {
		uint64_t room = o->cap - o->n;

		memcpy(o->dst + o->n, p, (size_t)(n < room ? n : room));
	}
	o->n += n;
	return 1;
}

#endif /* KOFENG_TESTS_OUTSINK_H */
