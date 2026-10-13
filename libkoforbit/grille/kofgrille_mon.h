/*
 * kofgrille_mon.h - the monitor: its options, the error values, open and next, and
 * the health counters. *
 * A part of <kofgrille.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFGRILLE_MON_H
#define KOFGRILLE_MON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "kofevt.h"
#include "kofgrille_evt.h"

/* ----------------------------------------------------------------- monitor */

struct kofw_mon;

struct kofw_mon_option {
	/*
	 * How many records may be in flight, rounded up to a power of two.
	 *
	 * This is the collector's whole memory budget: capacity * 512 bytes, taken
	 * once at open. 0 asks for the default.
	 */
	uint32_t ring_capacity;

	/*
	 * COLLAPSING THE SAME FACT WHEN IT IS RESTATED - on by default, and the
	 * polarity is the point.
	 *
	 * ETW repeats itself constantly: ONE nslookup produces eight identical
	 * CreateKey records for a key it only reads, and registry is the
	 * loudest provider here by a wide margin. A collector that had to be
	 * TOLD to collapse those would ship spamming, and every caller would
	 * have to know to ask.
	 *
	 * Set `dedup_off` for a DISCOVERY run, where the question is what the
	 * stream really looks like and a reduction is the wrong answer -
	 * kofmontrace is that caller, for the same reason it defaults to loud.
	 *
	 * WHICH VERBS ARE AFFECTED IS NOT A CHOICE HERE, deliberately. Some
	 * repeats are the evidence - a beacon is the same connection at a
	 * regular interval, and byte counts are sums of repeats - so the list
	 * lives in one place next to its reasoning and is not something a
	 * caller can widen by accident. See may_collapse in wfilter.c.
	 *
	 * `dedup_max` is how many distinct identities are remembered and
	 * `dedup_window` how long a repeat stays suppressed, in the same units
	 * as a record's stamp. 0 takes the defaults in koffridge_seen.c.
	 */
	uint32_t dedup_off;
	uint32_t dedup_max;
	uint64_t dedup_window;

	/*
	 * The session's name, which OUTLIVES THIS PROCESS.
	 *
	 * An ETW session is a kernel object owned by nobody: if this process dies
	 * without stopping it, the session keeps running and keeps buffering. The
	 * name is how the next run finds the leftover one and stops it - and two
	 * builds that pick the same name will fight over it. NULL takes the
	 * default.
	 */
	const char *session_name;

	/* Per-buffer size in KB, and the buffer count handed to ETW. 0 takes the
	 * defaults, whose reasoning lives beside them in the .c. */
	uint32_t buffer_kb;
	uint32_t min_buffers, max_buffers;

	/* A mask of KOFW_SUB_*. Zero takes KOFW_SUB_PROCESS alone. */
	uint32_t providers;

	/*
	 * KEEP THE EVENTS THIS PROCESS RAISES.
	 *
	 * Off by default, and the default is the safe one: reading a file to
	 * scan it raises file events, which are handled, which causes more of
	 * the same, and on a loaded machine that loop does not converge.
	 *
	 * On is for a tool that LAUNCHES something and wants to watch it. There
	 * the most important event in the whole run - the ProcessStart of the
	 * thing it just launched - is raised by this process, and the filter
	 * that protects a service is exactly what would hide it.
	 *
	 * A caller that turns this on takes on the loop itself, and the way to
	 * carry that is to consume a bounded subtree rather than everything -
	 * which is what kofmontrace does.
	 */
	int trace_self;

	/*
	 * NO OPTION TO RUN WITHOUT EVENT_TRACE_SYSTEM_LOGGER_MODE.
	 *
	 * There was one, as an escape hatch for "the provider enabled and then
	 * delivered nothing". It is removed because for a SENSOR the escape
	 * hatch is the failure: several of the kernel providers deliver nothing
	 * into an ordinary private session, so a sensor running that way
	 * collects nothing and reports success. An option whose only effect is
	 * to make the collector silently useless is not a diagnostic, it is a
	 * way of shipping a broken machine.
	 *
	 * If a provider enables and delivers nothing, that is a GUID or a
	 * keyword to check with `logman query providers <name>`, not a session
	 * mode to flip.
	 */
};

#define KOFW_ERR_ARG      (-1)
#define KOFW_ERR_MEM      (-2)
#define KOFW_ERR_ACCESS   (-3)   /* not elevated: a real-time session needs it */
#define KOFW_ERR_SESSION  (-4)   /* the session could not be started */
#define KOFW_ERR_PROVIDER (-5)   /* the session started, the provider refused */
#define KOFW_ERR_CONSUMER (-6)   /* the session started, it could not be opened */
#define KOFW_ERR_THREAD   (-7)
#define KOFW_ERR_PLATFORM (-8)   /* built without the Windows collector */

/*
 * THE PID NAMES A DIFFERENT PROCESS NOW.
 *
 * The snapshot half's own failure - see wproc.h - and it is separate from
 * KOFW_ERR_ACCESS because the two call for opposite responses. Refused means
 * try again with more rights; this means the pid was reused between being
 * observed and being acted on, and trying again is precisely the wrong thing.
 */
#define KOFW_ERR_GONE     (-9)

const char *kofw_err_name(int err);

/*
 * Start collecting. NULL on failure, and *err is a KOFW_ERR_*.
 *
 * Requires elevation. Nothing here degrades gracefully without it - an
 * unelevated process cannot start a real-time ETW session at all - so that is
 * reported rather than worked around.
 */
struct kofw_mon *kofw_mon_open(const struct kofw_mon_option *, int *err);

/*
 * Take the next record, waiting up to `wait_ms`. 1 if one was taken, 0 if the
 * wait expired with nothing there.
 *
 * ONE consumer. The ring is single-producer single-consumer by construction -
 * that is what lets the producer be wait-free, which is what keeps the ETW
 * callback from ever blocking - so calling this from two threads is not a race
 * to be locked around, it is outside what the structure can express.
 */
int kofw_mon_next(struct kofw_mon *, struct kofw_evt *out, uint32_t wait_ms);

/*
 * HOW MUCH WAS LOST, AND WHERE.
 *
 * Not a log line. A verdict computed over a stream that dropped records is a
 * different claim from one computed over a whole stream, and that difference
 * has to reach whoever reads the verdict - the same reason a scan carries
 * enum kof_broken rather than quietly returning what it managed.
 *
 * The three losses are distinct and are never added together:
 *
 *   etw_events_lost   the provider wrote faster than the session drained.
 *   etw_rt_buf_lost   real-time buffers lost between the session and here.
 *   ring_dropped      this library's ring was full when the callback arrived.
 *
 * The first two mean the collector never saw it. The third means it saw it and
 * chose dropping over stalling the callback - which is the only choice there
 * is, since blocking there stops ProcessTrace draining and turns a bounded,
 * counted loss into an unbounded, invisible one.
 */
struct kofw_health {
	uint64_t produced;         /* records the callback wrote */
	uint64_t ring_dropped;
	uint64_t ring_high_water;  /* the deepest the ring has ever been */
	uint64_t decode_failed;    /* payload the learned schema did not fit */

	/*
	 * Events dropped whole because the schema cache had no slot left.
	 *
	 * Its own line rather than part of decode_failed, because it is not a
	 * count of bad events - it is the collector announcing that it has
	 * stopped learning new shapes. Non-zero means every event id first seen
	 * from here on is discarded, permanently, and kofw_mon_describe() names
	 * the shapes it filled up on.
	 */
	uint64_t schema_full;
	uint64_t skipped_self;     /* our own events, refused at the callback */

	/* Records the consumer-side filter refused. Counted rather than
	 * silently dropped: "the sample did nothing" and "everything it did was
	 * filtered out" are different results. */
	uint64_t filtered;

	/*
	 * The same number broken out by WHICH test refused, because the three
	 * call for three different next steps and one total tells a reader to
	 * take none of them. `filtered_loc` in particular is the default
	 * suppression of system module loads, which looks like a bug the first
	 * time somebody meets it.
	 */
	uint64_t filtered_loc;    /* the object's location was being dropped */
	uint64_t filtered_scope;  /* the subject was outside the tracked tree */
	uint64_t filtered_type;   /* the caller did not ask for that type */

	/*
	 * RECORDS THAT SAID WHAT AN EARLIER ONE ALREADY SAID.
	 *
	 * COUNTED AND NOT MERELY DROPPED, which is the rule the ring already
	 * follows for a full buffer and wdiff follows for a relocation it
	 * explained away: a report that stops showing something leaves a reader
	 * unable to tell a quiet machine from a filter that swallowed the
	 * evidence. A large number here is normal and is the reduction working;
	 * a number that is a large FRACTION of everything collected is worth
	 * knowing, because it says the stream is mostly restatement.
	 */
	uint64_t filtered_dup;

	/*
	 * OF THOSE, HOW MANY WERE DROPPED UNDER A COARSE IDENTITY - a record
	 * about a DIFFERENT object the same process touched, collapsed because
	 * the object was somewhere no rule cares about. This is the precision
	 * deliberately traded to keep the table from being filled by service
	 * churn, and it is counted so the size of the trade is visible rather
	 * than assumed. See object_matters in wfilter.c.
	 */
	uint64_t filtered_coarse;

	/*
	 * WHEN THE STREAM HAS MORE DISTINCT FACTS THAN THE TABLE HOLDS.
	 *
	 * The duplicate table does not GROW - it is one allocation made at open
	 * and it evicts instead. So the cost of a very diverse stream is not
	 * memory, it is that the reduction stops working while still being paid
	 * for: a hash and a probe per record, for a table that no longer
	 * remembers anything long enough to match.
	 *
	 * That degradation is INVISIBLE from the outside - the collector looks
	 * like it is working and the event count simply stays high - which is
	 * why the number is here. Measured against a synthetic stream of 200k
	 * events into a table of 8192:
	 *
	 *   2000 distinct   99% suppressed, no evictions
	 *   8000 distinct   94% suppressed
	 *  50000 distinct   53% suppressed, and the evictions say so
	 *
	 * A large `dedup_evicted` beside a small `filtered_dup` means the table
	 * is too small for this machine - kofw_mon_option.dedup_max is the
	 * answer, and the memory is 48 bytes an entry.
	 */
	uint64_t dedup_evicted;
	uint32_t dedup_used, dedup_cap;

	/* Processes a tracked tree could not admit because its table was full.
	 * Non-zero means the scoped view is INCOMPLETE. */
	uint64_t untracked;

	/* Threads whose entry point was in no mapped image - see
	 * KOFW_EF_UNBACKED. A count of facts, not of verdicts. */
	uint64_t unbacked_threads;

	/* Modules mapped long after their process started - see
	 * KOFW_EF_LATE_LOAD. Expect a non-zero count on any real machine; it is
	 * a population to look through, not an alarm. */
	uint64_t late_loads;

	/*
	 * Command lines read, and lost to the race.
	 *
	 * The ratio is the useful number and it is expected to be poor: the
	 * processes worth reading are the short-lived ones. A high `lost` is
	 * the method's limit showing, not a fault - but it also bounds what any
	 * conclusion drawn from command lines can claim.
	 */
	uint64_t cmdline_got, cmdline_lost;

	/* Times a process' module list could not be extended because the range
	 * pool was empty. Non-zero means KOFW_EF_UNBACKED is being withheld for
	 * those processes, so a zero unbacked count is less meaningful. */
	uint64_t mod_pool_exhausted;

	/*
	 * Module loads whose base or size did not decode, so at least one
	 * process's module list is incomplete.
	 *
	 * It matters for one reason: KOFW_EF_UNBACKED is a claim that an
	 * address is in NO mapped image, and a list with a hole in it cannot
	 * support that. Non-zero here means the collector stopped answering
	 * for those processes rather than answering wrongly - and a reader
	 * seeing no unbacked threads needs to know which of the two happened.
	 */
	uint64_t mod_undecoded;

	/*
	 * Holes in kofw_evt.seq, counted BEFORE the filter runs.
	 *
	 * This has to live here rather than in a consumer, and the reason is
	 * exactly why it moved: once the library refuses records, the sequence
	 * numbers a consumer SEES are legitimately not contiguous, so a consumer
	 * counting its own gaps reports every filtered record as a lost one. A
	 * scoped trace on a busy machine then claims hundreds of losses and has
	 * had none.
	 */
	uint64_t seq_gaps;

	/*
	 * WHICH SUBSCRIPTIONS THE PROVIDER ACCEPTED, and which it refused.
	 *
	 * Masks of KOFW_SUB_*. `sub_asked & ~sub_enabled` is the set that was
	 * asked for and is not running, and it belongs in this struct for the
	 * same reason every other field here does: it is a reason the stream is
	 * incomplete, and a reader about to conclude "the sample did no network
	 * activity" has to be told the network provider never started.
	 *
	 * This used to be invisible in the worst possible way. One provider
	 * refusing aborted kofw_mon_open entirely, so the only two outcomes
	 * were "everything" and "nothing" - and when the session DID start,
	 * nothing anywhere said whether a provider had delivered a single
	 * record. A subscription that quietly is not running looks exactly like
	 * a machine that is not doing that thing.
	 */
	uint32_t sub_asked;
	uint32_t sub_enabled;

	uint32_t etw_events_lost;
	uint32_t etw_buffers_lost;
	uint32_t etw_rt_buf_lost;
};

#endif /* KOFGRILLE_MON_H */
