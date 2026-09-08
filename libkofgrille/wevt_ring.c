/*
 * wevt_ring.c - see wevt_ring.h for why this cannot block.
 *
 * No Windows API is used here, on purpose: this is half of what a recorded
 * trace is replayed through, and the replay path has to build and run on a host
 * that has no ETW at all.
 */

#include <stdlib.h>
#include <string.h>

#include "wevt_ring.h"

/*
 * A power of two, so the index is a mask rather than a modulo, and at least
 * enough slots that a burst does not immediately wrap. The cap is what keeps a
 * caller's arithmetic from overflowing into a small allocation: 2^22 slots at
 * 512 bytes is 2GB, which is already past useful.
 */
#define RING_MIN 256u
#define RING_MAX (1u << 22)

static uint32_t round_pow2(uint32_t v)
{
	uint32_t p = RING_MIN;

	while (p < v && p < RING_MAX)
		p <<= 1;
	return p;
}

int kofw_ring_init(struct kofw_ring *r, uint32_t want)
{
	uint32_t cap;

	if (!r)
		return -1;
	memset(r, 0, sizeof *r);

	cap = round_pow2(want ? want : 16384u);

	r->slot = calloc(cap, sizeof *r->slot);
	if (!r->slot)
		return -1;

	r->mask = cap - 1u;
	atomic_init(&r->head, 0u);
	atomic_init(&r->tail, 0u);
	atomic_init(&r->produced, 0u);
	atomic_init(&r->dropped, 0u);
	atomic_init(&r->high_water, 0u);
	return 0;
}

void kofw_ring_free(struct kofw_ring *r)
{
	if (!r)
		return;
	free(r->slot);
	r->slot = NULL;
	r->mask = 0;
}

struct kofw_evt *kofw_ring_claim(struct kofw_ring *r)
{
	uint32_t h, t, depth;

	/*
	 * `head` is ours, so it is read relaxed - nobody else writes it and this
	 * thread's own last store is trivially visible to it.
	 *
	 * `tail` is the consumer's and is read ACQUIRE, which is what makes the
	 * slot it released safe to write into again. Without it the compiler and
	 * the machine are both free to start filling the record before they have
	 * seen that the consumer finished reading the previous one out of it.
	 */
	h = atomic_load_explicit(&r->head, memory_order_relaxed);
	t = atomic_load_explicit(&r->tail, memory_order_acquire);

	depth = h - t;
	if (depth > r->mask) {
		atomic_fetch_add_explicit(&r->dropped, 1u, memory_order_relaxed);
		return NULL;
	}

	/*
	 * Recorded on claim rather than on commit, and including the slot about to
	 * be filled, because what this measures is how close the ring came to the
	 * refusal above - not how much a consumer happened to leave behind.
	 */
	{
		uint64_t d = (uint64_t)depth + 1u;
		uint64_t hw = atomic_load_explicit(&r->high_water,
						   memory_order_relaxed);
		if (d > hw)
			atomic_store_explicit(&r->high_water, d,
					      memory_order_relaxed);
	}

	return &r->slot[h & r->mask];
}

uint32_t kofw_ring_commit(struct kofw_ring *r)
{
	uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
	uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);

	atomic_fetch_add_explicit(&r->produced, 1u, memory_order_relaxed);

	/*
	 * RELEASE, and this is the whole synchronisation of the structure: it
	 * publishes every byte written into the slot above, so a consumer that
	 * acquires this value sees a complete record rather than a half-filled one.
	 */
	atomic_store_explicit(&r->head, h + 1u, memory_order_release);

	return h - t;
}

int kofw_ring_take(struct kofw_ring *r, struct kofw_evt *out)
{
	uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);

	if (h == t)
		return 0;

	*out = r->slot[t & r->mask];

	/* RELEASE, so the producer cannot begin overwriting the slot until the
	 * copy above has actually happened. */
	atomic_store_explicit(&r->tail, t + 1u, memory_order_release);
	return 1;
}
