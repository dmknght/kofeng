/*
 * wevt_ring.h - the one place a record crosses a thread boundary.
 *
 * Single producer, single consumer, fixed capacity, and FULL MEANS DROP.
 *
 *
 * WHY IT CANNOT BLOCK, WHICH IS THE ONLY INTERESTING THING ABOUT IT
 *
 * The producer is an ETW callback running on the ProcessTrace thread. While it
 * is inside that callback, the session's buffers are not being drained - so a
 * producer that waits for space does not slow the stream down, it stops the
 * drain that would have made space, and ETW discards records at its own end
 * instead. The wait cannot succeed, and the loss it was trying to prevent
 * happens anyway, one layer further up where nothing counts it per subject.
 *
 * So the choice is not between losing records and not losing them. It is
 * between losing them where it is counted and losing them where it is not.
 *
 * This is deliberately NOT the queue in libkofeng's parallel walk, which blocks
 * the producer on a condition variable when full. That is right there - the
 * producer is a directory walk and slowing it down is exactly the intent - and
 * wrong here for the reason above. Two queues, because they answer to two
 * different producers.
 *
 *
 * WHY CLAIM/COMMIT RATHER THAN PUT
 *
 * A record is 512 bytes. Handing the producer the slot to fill in place removes
 * a copy of that from the callback, which is the one piece of code in this
 * library whose cost is paid by the whole machine rather than by us.
 */

#ifndef KOFGRILLE_WEVT_RING_H
#define KOFGRILLE_WEVT_RING_H

#include <stdatomic.h>
#include <stdint.h>

#include "kofgrille.h"

struct kofw_ring {
	struct kofw_evt *slot;
	uint32_t         mask;      /* capacity - 1; capacity is a power of two */

	/*
	 * Written by the producer, read by the consumer, and the other way round.
	 * Free running rather than wrapped, so full and empty are told apart by
	 * (head - tail) instead of by a spare slot; unsigned wraparound at 2^32 is
	 * defined and the difference stays right across it.
	 */
	_Atomic uint32_t head;
	_Atomic uint32_t tail;

	/*
	 * Counters, not statistics.
	 *
	 * `dropped` is the number a consumer needs to know it is looking at a
	 * partial stream; `high_water` is the number that says whether the ring is
	 * sized for this machine, and it is the one worth watching before the first
	 * drop rather than after it.
	 */
	_Atomic uint64_t produced;
	_Atomic uint64_t dropped;
	_Atomic uint64_t high_water;
};

/*
 * `want` is rounded up to a power of two. Non-zero on failure.
 */
int  kofw_ring_init(struct kofw_ring *, uint32_t want);
void kofw_ring_free(struct kofw_ring *);

/*
 * The slot to fill, or NULL when the ring is full - in which case the drop has
 * already been counted, so a caller that only returns has still reported it.
 *
 * Producer thread only. Valid until kofw_ring_commit().
 */
struct kofw_evt *kofw_ring_claim(struct kofw_ring *);

/*
 * Publish the claimed slot. Producer thread only, exactly once per successful
 * claim.
 *
 * Returns how deep the ring was BEFORE this record, so a producer can wake a
 * sleeping consumer on the empty-to-nonempty edge only. Waking on every commit
 * would put a syscall in the callback for every event of a burst, which is the
 * one thing that file is not allowed to do; waking on the edge costs one for
 * the whole burst.
 *
 * The value can be stale by a record - the tail it is measured against is the
 * consumer's - so it is a hint for skipping a wakeup, never a fact to schedule
 * on. Whoever waits must also cap its wait.
 */
uint32_t kofw_ring_commit(struct kofw_ring *);

/* 1 and fills *out, or 0 when empty. Consumer thread only. */
int  kofw_ring_take(struct kofw_ring *, struct kofw_evt *out);

#endif /* KOFGRILLE_WEVT_RING_H */
