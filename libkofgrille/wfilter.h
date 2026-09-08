/*
 * wfilter.h - classifying a path, tracking a process tree, refusing a record.
 *
 * All three used to live in the tools, which was wrong for one reason: each of
 * them needs knowledge that belongs to the collector. Which module directories
 * every process draws from, which pid belongs to a launched tree, what a
 * location id means - a tool that reimplements those reimplements them slightly
 * differently, and the day a rule engine becomes the consumer it would have to
 * be written a third time.
 *
 * None of this touches ETW, so it is also the half that keeps working when
 * records come from a replayed trace file rather than a live session.
 */

#ifndef KOFGRILLE_WFILTER_H
#define KOFGRILLE_WFILTER_H

#include <stdint.h>

#include "kofgrille.h"

/*
 * How many processes are remembered at once.
 *
 * The table serves two jobs with opposite failure modes. As a name cache a full
 * one is recycled and a forgotten name costs a column. As the membership of a
 * tracked tree, losing an entry loses EVENTS - so there it refuses and counts
 * instead, and the count reaches the caller as kofw_health.untracked.
 */
#define KOFW_PTAB_MAX 4096u

struct kofw_pent {
	uint32_t pid;
	uint64_t create_time;   /* 0 when not known yet */
	uint8_t  used;
	uint8_t  alive;
	uint8_t  tracked;       /* in the subtree named by filter.root_pid */
	char     image[120];
};

struct kofw_ptab {
	struct kofw_pent e[KOFW_PTAB_MAX];
	uint32_t n;
	uint32_t n_alive_tracked;
	uint64_t overflow;
};

void kofw_ptab_init(struct kofw_ptab *);

struct kofw_pent *kofw_ptab_find(struct kofw_ptab *, uint32_t pid);

/*
 * Insert or refresh. `recycle` says what a full table means - see the note on
 * KOFW_PTAB_MAX. NULL when it was full and recycling was refused.
 */
struct kofw_pent *kofw_ptab_add(struct kofw_ptab *, uint32_t pid,
				uint64_t create_time, const char *image,
				int recycle);

/* The entry for this exact process, or NULL. create_time of 0 means the caller
 * has no discriminator and the pid alone has to do. */
struct kofw_pent *kofw_ptab_of(struct kofw_ptab *, uint32_t pid,
			       uint64_t create_time);

/*
 * Fold one record into the table and decide whether the caller should see it.
 *
 * Does three things in the order they have to happen: classifies the object
 * path, updates process membership and liveness, then applies the filter.
 * Membership must be updated BEFORE filtering, because a ProcessStart is about
 * a pid the set has by definition not heard of yet and is admitted on its
 * parent - filtering first would refuse the very event that grows the tree.
 *
 * Returns non-zero to hand the record over, zero to refuse it.
 */
int kofw_filter_apply(struct kofw_ptab *, const struct kofw_filter *,
		      struct kofw_evt *);

#endif /* KOFGRILLE_WFILTER_H */
