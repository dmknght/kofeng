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

/*
 * WHERE EACH PROCESS HAS AN IMAGE MAPPED.
 *
 * Eight ranges to a block, blocks chained out of one pool, because the number
 * per process varies by two orders of magnitude - a console tool maps a dozen
 * modules and a PowerShell host maps well over a hundred - and a fixed array
 * sized for the second would be mostly waste multiplied by every process in the
 * table.
 *
 * uint32 for the size: an image is not four gigabytes.
 */
#define KOFW_MODS_PER_BLK 8u
#define KOFW_MODBLK_MAX   4096u
#define KOFW_MODBLK_NONE  0xffffu

/*
 * HOW LATE IS LATE, in FILETIME ticks: five seconds.
 *
 * A program's own imports are mapped before it runs a line of its own code, and
 * that burst is over in well under a second even on a slow disk. Five is not a
 * measured threshold - it is a deliberately loose one, chosen so that a slow
 * machine or a cold cache cannot push an ordinary startup past it. Tightening it
 * would find more and invent more; this errs toward saying nothing.
 */
#define KOFW_LATE_LOAD_TICKS 50000000ull

struct kofw_modblk {
	uint64_t base[KOFW_MODS_PER_BLK];
	uint32_t size[KOFW_MODS_PER_BLK];
	uint16_t next;
	uint8_t  n;
};

struct kofw_pent {
	uint32_t pid;
	uint64_t create_time;   /* 0 when not known yet */
	uint8_t  used;
	uint8_t  alive;
	uint8_t  tracked;       /* in the subtree named by filter.root_pid */

	/*
	 * WHETHER THE MODULE LIST CAN BE TRUSTED TO BE COMPLETE, which is the
	 * whole difference between this being evidence and being noise.
	 *
	 * `mods_whole` is set only when this process's own ProcessStart was
	 * seen, so every image it has ever mapped was witnessed. A process that
	 * predates the session has a module list that begins in the middle, and
	 * "this address is in none of the modules I know about" then means
	 * nothing at all.
	 *
	 * `mods_full` clears it again if the pool ran out. Same reasoning: a
	 * partial list cannot support a negative claim.
	 */
	uint8_t  mods_whole;
	uint8_t  mods_full;
	uint16_t mods;          /* head block, or KOFW_MODBLK_NONE */

	char     image[120];
};

struct kofw_ptab {
	struct kofw_pent e[KOFW_PTAB_MAX];
	uint32_t n;
	uint32_t n_alive_tracked;
	uint64_t overflow;

	struct kofw_modblk blk[KOFW_MODBLK_MAX];
	uint16_t blk_free;      /* head of the free list */
	uint64_t mod_exhausted; /* times the pool had nothing left */
	uint64_t unbacked;      /* threads flagged - see KOFW_EF_UNBACKED */
	uint64_t late_loads;    /* modules flagged - see KOFW_EF_LATE_LOAD */
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
 * WHY A RECORD WAS REFUSED, not merely that it was.
 *
 * One number for "filtered" cost an afternoon: a run that suppressed 431
 * system module loads by default reported `modules loaded: 0` beside
 * `filtered out: 431`, which reads as "the filter ate everything and I do not
 * know why". The three reasons call for three different next steps -
 * --all-images, a different --only, a different root - so they are counted
 * apart.
 */
enum kofw_refuse {
	KOFW_REFUSE_NONE = 0,
	KOFW_REFUSE_TYPE,   /* the caller did not ask for this event type */
	KOFW_REFUSE_LOC,    /* the object is in a location being dropped */
	KOFW_REFUSE_SCOPE   /* the subject is outside the tracked tree */
};

/*
 * Fold one record into the table and decide whether the caller should see it.
 *
 * Does three things in the order they have to happen: classifies the object
 * path, updates process membership and liveness, then applies the filter.
 * Membership must be updated BEFORE filtering, because a ProcessStart is about
 * a pid the set has by definition not heard of yet and is admitted on its
 * parent - filtering first would refuse the very event that grows the tree.
 *
 * Returns non-zero to hand the record over, zero to refuse it - THE SAME
 * POLARITY IT ALWAYS HAD. The reason comes out through `why` (enum
 * kofw_refuse, may be NULL) rather than through the return value, and that is
 * deliberate: returning the reason directly would make 0 mean "keep", so every
 * caller that was not updated would invert. The unit test caught exactly that
 * happening, which is the argument for not doing it.
 */
int kofw_filter_apply(struct kofw_ptab *, const struct kofw_filter *,
		      struct kofw_evt *, uint8_t *why);

#endif /* KOFGRILLE_WFILTER_H */
