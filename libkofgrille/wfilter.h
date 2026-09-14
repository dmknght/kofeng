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

/*
 * HOW MUCH OF A PROCESS IMAGE PATH IS KEPT.
 *
 * WAS 120, AND THAT WAS MEASURED TO BE TOO SHORT. On this desktop, of 75
 * processes with a readable path: mean 62 characters, longest 155, and FIVE of
 * them - one in fifteen - longer than 119. Through ETW it is worse than that
 * ratio suggests, because the collector is handed DEVICE paths:
 * \Device\HarddiskVolume3\ in place of C:\ is twenty-one characters more on
 * every one of them, which pushes roughly one process in seven over the edge.
 *
 * 256 rather than 260. MAX_PATH is the number Windows conventionally stops at
 * and 256 is the power of two under it, which is past everything measured with
 * room to spare - and a path longer than this is a long-path executable, which
 * is worth the flag beside it rather than four more kilobytes a process.
 *
 * AND IT COSTS NOTHING PER ENTRY, because the path is not in the entry - see
 * kofw_pent.image_off. This is a bound on one path, not a field multiplied by
 * KOFW_PTAB_MAX, which is what made the old number a trade at all:
 *
 *   inline at 120   992KB, and one process in seven cut
 *   inline at 256  1568KB, nothing cut
 *   pooled at 256   704KB, nothing cut
 *
 * The first row is where this started. Raising the bound alone made it worse
 * before the pool made it better than either, which is the argument for fixing
 * the shape rather than tuning the number.
 *
 * Contrast KOFW_FNAME_MAX, which stays inline and stays small for a reason that
 * does not apply here: a cut FILE path still names the directory written to,
 * which is the fact a rule uses. A cut PROCESS image loses the executable's
 * name, which is the whole of what it is for.
 */
#define KOFW_IMAGE_MAX 256u

/*
 * THE POOL EVERY IMAGE PATH GOES INTO - see kofw_ptab.names for the sizing,
 * and kofw_pent.image_off for why it is a pool at all.
 */
#define KOFW_NAME_POOL (128u * 1024u)

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

	/*
	 * THE IMAGE WAS TOO LONG AND WAS CUT.
	 *
	 * Said rather than left to be discovered, for the reason kofw_evt.flags
	 * gives for the same condition: a truncated path still LOOKS like a
	 * path, so a reader comparing it against anything gets an answer that
	 * is wrong without appearing to be.
	 *
	 * The copy was always bounded - there is no overflow here and never
	 * was - but it was silent, and silent is the half that matters.
	 */
	uint8_t  image_cut;

	/*
	 * THE IMAGE PATH LIVES IN A POOL, NOT IN THIS STRUCT.
	 *
	 * Inline it was 256 bytes times KOFW_PTAB_MAX, which is 1.1MB held to
	 * store paths averaging 62 characters for the seventy-odd processes a
	 * real machine runs. Measured: 21KB of this table in use out of 1568KB
	 * allocated - one and a third per cent.
	 *
	 * The pool is the same answer kofw_modblk already gives one struct
	 * above, and for the same reason its comment gives: a fixed array sized
	 * for the worst case is mostly waste multiplied by every process in the
	 * table. Module RANGES got that treatment; the string beside them did
	 * not, and it was the larger half.
	 *
	 * An offset and not a pointer, so the table stays memcpy-able and has
	 * nothing to fix up when it is cleared.
	 */
	uint32_t image_off;    /* into kofw_ptab.names */
	uint16_t image_len;    /* 0 when there is no image */
};

struct kofw_ptab {
	struct kofw_pent e[KOFW_PTAB_MAX];
	uint32_t n;
	uint32_t n_alive_tracked;
	uint64_t overflow;

	/*
	 * Module loads whose base or size did not decode.
	 *
	 * Non-zero means at least one process's module list is incomplete and
	 * its UNBACKED answer has been withdrawn - see mods_add. Counted
	 * rather than only acted on, because "no unbacked threads were seen"
	 * and "we stopped being able to tell" are different results.
	 */
	uint64_t mod_undecoded;

	/* Image paths that did not fit KOFW_IMAGE_MAX. Non-zero means at least
	 * one process is named by a path that is not its whole path. */
	uint64_t image_cuts;

	/*
	 * WHERE THE IMAGE PATHS ACTUALLY ARE.
	 *
	 * Sized for what a machine holds rather than for the worst case an
	 * entry could hold: 128KB is about fifteen hundred paths at the
	 * measured average, against a table that has never been seen to hold
	 * more than a few hundred live processes. Inline, the same coverage
	 * cost 1.1MB.
	 *
	 * FULL MEANS NEW ENTRIES LOSE THEIR NAME, not that anything already
	 * stored moves. Offsets already handed out stay valid for the life of
	 * the table, and the only moment they are all invalidated at once is
	 * the whole-table recycle - which clears every entry in the same
	 * statement, so there is nothing left pointing in here. Counted in
	 * names_full, because a process with no name is a column a reader
	 * cannot fill and should be told about.
	 */
	char     names[KOFW_NAME_POOL];
	uint32_t names_used;
	uint64_t names_full;

	struct kofw_modblk blk[KOFW_MODBLK_MAX];
	uint16_t blk_free;      /* head of the free list */
	uint64_t mod_exhausted; /* times the pool had nothing left */
	uint64_t unbacked;      /* threads flagged - see KOFW_EF_UNBACKED */
	uint64_t late_loads;    /* modules flagged - see KOFW_EF_LATE_LOAD */

	/*
	 * WHETHER THE LAST RECORD THIS FILTER SAW WAS KEPT.
	 *
	 * A KOF_EVT_CONT record is not an event - it is the tail of the one in
	 * front of it - so it has no pid to test, no path to classify and no
	 * decision of its own to make. It has to inherit the decision made
	 * about its parent, or the two halves of one submission are filtered
	 * apart: chunks kept behind a dropped parent are bytes belonging to
	 * nothing, and chunks dropped behind a kept parent leave a hole the
	 * reassembly can only report as loss.
	 *
	 * Here rather than in the filter because the filter is const, and this
	 * is state about the stream rather than about the policy. There is one
	 * consumer thread, so it needs no more protection than the rest of the
	 * table.
	 */
	uint8_t  last_kept;
};

/* ------------------------------------------------- FileKey -> path */

/*
 * WHAT A WRITE NAMES ITS TARGET BY, TURNED BACK INTO A PATH.
 *
 * FileIo Write carries FileObject and FileKey - kernel pointers - and no
 * filename at all. That is why the write subscription enables the FILENAME
 * keyword alongside it: FILENAME emits separate records that map one of those
 * pointers to a path, and this is where they are kept.
 *
 * Without it a write is a byte count against an address nobody can resolve,
 * which is what `[unknown] [miss 0x40]` on every PowerShell write was.
 *
 * RECYCLED WHOLE WHEN FULL, not evicted one at a time. A forgotten mapping
 * costs one write its path and the next name record puts it back; an LRU would
 * cost a pointer per entry and a policy to get wrong, on a table whose whole
 * job is to be a cache.
 */
#define KOFW_FTAB_MAX  4096u

/*
 * HOW LONG ONE FILE PATH MAY BE - and it is no longer a memory trade.
 *
 * WHAT THIS USED TO SAY, and the reasoning was sound for the shape it had:
 * "128 and not 200 ... every byte here is four kilobytes of a service's
 * resident set, and 200 cost 852KB to hold names that are almost all shorter
 * than 128. A name that does not fit is cut, and a cut path in a WRITE event
 * still says which directory was written to."
 *
 * THE PREMISE WAS MEASURED AND IS WRONG. Sixteen thousand real file paths from
 * System32, Windows, Program Files and LocalAppData: mean 83, longest 218, and
 * 26% of them longer than 128. Through ETW it is worse again, because those are
 * device paths - \Device\HarddiskVolume3\ for C:\ - so roughly a THIRD of file
 * names were being cut, not the handful "almost all shorter than 128" implies.
 *
 * And the trade the old number was making no longer exists: the bytes live in a
 * pool now, so this is a bound on ONE path rather than a field multiplied by
 * KOFW_FTAB_MAX. Raising it costs nothing per entry.
 */
#define KOFW_FNAME_MAX 256u

/*
 * THE POOL THOSE PATHS LIVE IN.
 *
 * Sized from the same measurement and from when the table recycles: it is
 * emptied at half full, so at most KOFW_FTAB_MAX/2 names are ever live, and at
 * the measured average plus a device prefix that is about 215KB. 256KB is that
 * with room, against 544KB for the inline form that truncated a third of them.
 */
#define KOFW_FPOOL     (256u * 1024u)

struct kofw_fent {
	uint64_t key;
	uint32_t off;     /* into kofw_ftab.names */
	uint16_t len;     /* 0 when this entry has no name */
};

struct kofw_ftab {
	struct kofw_fent e[KOFW_FTAB_MAX];
	uint32_t n;
	uint64_t resolved, unresolved, recycled;

	/*
	 * APPEND ONLY, for the reason kofw_ptab's pool is: an entry being
	 * refreshed must not disturb the offsets handed to every other entry.
	 * A name identical to the one already stored is therefore not appended
	 * again - which matters here far more than it does for processes,
	 * because this runs on every file the machine opens and the same key
	 * arrives with the same name constantly.
	 */
	char     names[KOFW_FPOOL];
	uint32_t names_used;
	uint64_t names_full;   /* names dropped for want of pool */
	uint64_t name_cuts;    /* paths longer than KOFW_FNAME_MAX */
};

void kofw_ftab_init(struct kofw_ftab *);

/* Remember that `key` is `name`. Silently ignores a zero key or an empty
 * name - both mean the record did not carry the pair. */
void kofw_ftab_add(struct kofw_ftab *, uint64_t key, const char *name);

/*
 * Fill in a record's object path from its key, if it has one and needs one.
 *
 * Does nothing to a record that already has a path, so a name record keeps its
 * own. Non-zero when a path was supplied.
 */
int kofw_ftab_resolve(struct kofw_ftab *, struct kofw_evt *);

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
 * The image path of a process, or "" when it has none.
 *
 * The entry holds an OFFSET into the table's pool rather than the bytes - see
 * kofw_pent.image_off - so the table is the only thing that can resolve it, and
 * that is why this takes both.
 */
const char *kofw_pent_image(const struct kofw_ptab *,
			    const struct kofw_pent *);

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
	KOFW_REFUSE_SCOPE,  /* the subject is outside the tracked tree */
	/* A continuation whose parent was refused - see kofw_filter_apply. It
	 * is not a decision about this record; there was none to make. */
	KOFW_REFUSE_PARENT
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

/*
 * THE BYTES THAT MAKE TWO EVENTS THE SAME EVENT, written into `buf`.
 *
 * Returns how many were written, or 0 when this verb must never be collapsed -
 * see may_collapse in the .c, which is where the reasoning lives and where the
 * damage would be if the list were wrong. A caller that gets 0 has been told
 * "do not deduplicate this", not "the buffer was too small".
 *
 * WHAT IS DELIBERATELY ABSENT FROM THE IDENTITY: the stamp, the sequence
 * number and the thread. Those differ on every record by construction, so
 * including any of them would mean nothing ever matches and the whole
 * mechanism would quietly do nothing while appearing to work.
 *
 * The result is fed to koffridge_seen, which hashes it - see koffridge.h for why the
 * bytes are not stored.
 */
size_t kofw_evt_ident(const struct kofw_evt *, void *buf, size_t cap,
		      int *coarse);

#endif /* KOFGRILLE_WFILTER_H */
