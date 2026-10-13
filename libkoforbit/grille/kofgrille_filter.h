/*
 * kofgrille_filter.h - filtering and tracking, the monitor's health and description,
 * the conversion to the neutral record, and close. *
 * A part of <kofgrille.h>, which includes it: include that, not this. Split from it by
 * purpose; the text is unchanged.
 */

#ifndef KOFGRILLE_FILTER_H
#define KOFGRILLE_FILTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "kofevt.h"
#include "kofgrille_evt.h"
#include "kofgrille_mon.h"

/* ------------------------------------------------------------- filtering */

/*
 * WHAT A CONSUMER WANTS TO SEE, as data.
 *
 * Here rather than in each tool, because every one of these decisions needs
 * knowledge that belongs to the collector - which module paths are the ones
 * every process loads, which pid belongs to a tracked tree, what a location id
 * means. A tool that reimplemented them would be reimplementing them slightly
 * differently, and the day a rule engine becomes the consumer it would have to
 * be written a third time.
 *
 * Zeroing the struct means "everything", which is the answer a caller who
 * forgot a field should get: less filtering, never more.
 *
 * Filtering happens in kofw_mon_next on the consumer thread. It is NOT a
 * substitute for the keyword and event-id filters the session applies at the
 * provider - those stop an event being produced at all, and this only stops one
 * being handed over. Both counters are reported, and a record refused here is
 * counted in kofw_health.filtered rather than vanishing.
 */
_Static_assert(KOF_EVT_TYPE_COUNT <= 32,
	       "kofw_filter.types is a 32-bit mask of 1u << verb");

struct kofw_filter {
	/*
	 * Types to keep, as 1u << enum kof_evt_verb. Zero keeps all of them.
	 *
	 * THIRTY-TWO VERBS IS THE CEILING, and it is asserted because nothing
	 * about adding a verb would otherwise say so: the shift is in a tool,
	 * the enum is in another library, and 1u << 32 is undefined behaviour
	 * rather than a filter that quietly keeps the wrong records. The count
	 * went from 23 to 28 the day the Linux process verbs landed.
	 */
	uint32_t types;

	/*
	 * Locations to REFUSE, as 1u << enum kof_evt_loc, tested against
	 * kofw_evt.obj_loc.
	 *
	 * The one that earns its keep is KOF_LOC_SYSTEM against module loads:
	 * `cmd.exe /c` maps 27 modules before running a command and all 27 are
	 * the loader's own furniture, so a view that prints them prints almost
	 * nothing else. Note this refuses by the OBJECT's location - a process
	 * started from System32 is not affected, only a module loaded from it.
	 */
	uint32_t drop_loc;

	/*
	 * Only events of this process and its descendants. Zero means no
	 * scoping.
	 *
	 * The set grows from ProcessStart events whose parent is already in it,
	 * so a grandchild is included and an unrelated process is not. Seed it
	 * with kofw_mon_track() BEFORE the process can run - see that function.
	 *
	 * WHAT THIS CANNOT FOLLOW, and it matters: parentage. Code injected into
	 * an existing process, or a payload that migrates into one, is running
	 * somewhere that is not a descendant of anything tracked, and no amount
	 * of care here will attribute it. That is a property of the method, not
	 * a gap to be fixed later, and a scoped trace that comes back empty may
	 * mean the subject left the tree rather than that it did nothing.
	 */
	uint32_t root_pid;

	/*
	 * PROVIDERS EXEMPT FROM THE SUBTREE SCOPE, as 1u << enum kofw_provider.
	 *
	 * Scoping to a process tree is what turns a stream into evidence, and it
	 * is wrong for exactly one kind of record: the ones whose value does not
	 * depend on whose tree they came from.
	 *
	 * AMSI is that kind. It reports the CONTENT an application submitted,
	 * it is low volume enough to be free, and the moment it matters most is
	 * the moment the scope has already lost the subject - a payload that
	 * migrated is running in a process that is nobody's descendant, and its
	 * script submissions are attributed to a pid outside the tree and
	 * dropped. The trace then shows a clean subtree and says nothing about
	 * the thing that walked out of it.
	 *
	 * Exempting a provider BREAKS the tool's promise that everything shown
	 * belongs to one tree, so it is never a default: a caller asks, and the
	 * caller says so in its own output.
	 *
	 * By provider and not by event type on purpose - a type only exists
	 * once its ids have been established, and the records this is for are
	 * still arriving as KOF_EVT_RAW.
	 */
	uint32_t scope_exempt_prov;
};

/*
 * Apply a filter from now on. NULL clears it back to "everything".
 *
 * Copied, not referenced, so the caller's struct need not outlive the call.
 */
void kofw_mon_filter(struct kofw_mon *, const struct kofw_filter *);

/*
 * Put a pid into the tracked set by hand, before any event mentions it.
 *
 * A caller that LAUNCHED the process has to do this, and has to do it while the
 * process is still suspended: otherwise the target can create a child, write a
 * file and exit before the first record is drained, and every one of those
 * events belongs to a pid the set has never heard of.
 *
 * `image` is only for reporting and may be NULL. Non-zero on failure, which
 * means the set is full - see kofw_health.untracked.
 */
int kofw_mon_track(struct kofw_mon *, uint32_t pid, const char *image);

/* How many tracked processes have not yet stopped. Zero once a tracked tree has
 * finished, which is what a trace waits for. Meaningless without a root_pid. */
uint32_t kofw_mon_tracked_alive(const struct kofw_mon *);

/*
 * WHICH tracked processes have not stopped - not just how many.
 *
 * The count alone turns "the trace will not finish" into a number, and a number
 * is not a diagnosis. A tracer waits for the tracked tree to empty, so a count
 * stuck above zero has exactly two causes and they call for opposite responses:
 * a descendant really is still running, or a ProcessStop was never matched to
 * its entry and the counter is wrong about the world. Naming the processes
 * separates them in one glance - a familiar long-lived child is the first, a
 * process that visibly exited is the second.
 *
 * Walks the entries: `i` from 0 upward until it returns NULL. Fills *pid when
 * non-NULL. The name is borrowed and valid until the next kofw_mon_next.
 */
const char *kofw_mon_tracked_nth(struct kofw_mon *, uint32_t i, uint32_t *pid);

/*
 * What this pid is, for reporting. "" when the collector has not seen it start.
 * Never NULL.
 *
 * `create_time` of 0 means the caller has no discriminator and the pid alone
 * has to do; pass the record's when it has one, because a pid is reused and a
 * table keyed on the number alone will confidently return another process's
 * name.
 */
const char *kofw_mon_name_of(struct kofw_mon *, uint32_t pid,
			     uint64_t create_time);

void kofw_mon_health(struct kofw_mon *, struct kofw_health *);

/*
 * The same, in the terms every collector has - see struct kof_evt_health.
 *
 * This direction and not the other: kofevt must not learn what an ETW buffer
 * is, so each collector maps its own counters onto the neutral ones. What is
 * ETW-specific (buffers lost versus events lost, self-skipped, untracked)
 * stays in struct kofw_health for anything that wants it.
 */
void kofw_mon_health_neutral(struct kofw_mon *, struct kof_evt_health *);

/*
 * Print what the NEUTRAL line cannot say.
 *
 * kof_evt_health_print covers what every collector has - kept, dropped, lost,
 * gaps. These are this collector's own: how many threads it called unbacked,
 * how many module lists it stopped being able to answer for, how many loads
 * arrived late, how much it refused and why.
 *
 * Two lines rather than one struct, because the day a Linux collector exists
 * it will have its own second line and neither of them should have to know
 * about the other's counters. Call it after the neutral one.
 */
void kofw_health_print_extra(FILE *out, const struct kofw_health *);

/*
 * THE PAYLOAD SHAPES THIS RUN ACTUALLY LEARNED, as text.
 *
 * A field arriving absent - kofw_evt.miss - has two causes that look identical
 * from the outside: the provider on this Windows build does not carry it, or
 * the walk stopped before reaching it. They call for opposite responses, and
 * nothing else here can tell them apart.
 *
 * Returns bytes written, excluding the NUL, and never writes past `cap`.
 */
size_t kofw_mon_describe(struct kofw_mon *, char *buf, size_t cap);

/* The stamp's unit is KOF_TICKS_PER_SEC, defined once in kofevt.h - see
 * there for why it is a constant and not a query. */

/*
 * THE COLLECTOR'S RECORD, TURNED INTO THE ONE EVERYTHING ELSE READS.
 *
 * struct kofw_evt is this library's internal transport: it carries what ETW
 * gave, including the things only ETW has - which provider, which per-processor
 * buffer, which payload version. struct kof_evt is what a log, a viewer, a
 * rule and a Linux collector all speak.
 *
 * The conversion lives HERE and not in kofevt, and that direction is the whole
 * design: kofevt must not know what an ETW record looks like or it stops being
 * neutral, so each collector is responsible for producing the neutral form.
 * The Linux twin will have its own function with the same shape and kofevt will
 * not learn about either.
 *
 * What is dropped is named rather than quietly lost: cpu, provider and
 * raw_version are ETW's own bookkeeping and have no meaning on another
 * platform. raw_id survives because a discovery run needs it.
 */
void kofw_evt_to_kof(const struct kofw_evt *in, struct kof_evt *out);

/*
 * NO AUTOLOGGER, AND THAT IS A DECISION RATHER THAN A GAP.
 *
 * An autologger is a session described in the registry that the kernel starts
 * during boot, so a consumer attaching later receives everything since. It is
 * the obvious way to see what ran before anything was watching, and there was
 * an implementation of it here for about an hour.
 *
 * It is removed because it puts this library in the business of installing
 * something. A registry-described session needs administrator to write, it
 * OUTLIVES the process, the product and the uninstaller, and a session nobody
 * ever attaches to keeps buffering forever with no process anywhere aware of
 * it. Those are lifecycle problems that belong to whatever installs and
 * removes the product, designed once and carefully - not to a collector, and
 * not decided as a side effect of wanting boot coverage.
 *
 * So the sensor is started by a system service, which is a thing the operating
 * system already knows how to start early and stop cleanly, and this library
 * does exactly one thing: collect while it is asked to.
 */

void kofw_mon_close(struct kofw_mon *);

#endif /* KOFGRILLE_FILTER_H */
