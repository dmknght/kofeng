/*
 * kofmon.h - what a sensor needs from a collector, and nothing about which
 * collector it is.
 *
 * WHY THIS EXISTS.
 *
 * kofwatchtower is the sensor: it opens a collector, drains it, and publishes
 * what comes out down the channel. That job has nothing platform-specific in
 * it - measured, the whole program is 375 lines and exactly TWO of them are
 * Windows: the <windows.h> include and the Ctrl-C handler. Everything else is
 * a loop.
 *
 * What made it a Windows program anyway was the SHAPE of the calls in that
 * loop: kofw_mon_open, kofw_mon_next, kofw_evt_to_kof. Each is fine and each
 * belongs to libkofgrille, and together they mean the only way to write a
 * Linux sensor is to write a second sensor - a second argument parser, a
 * second drain loop, a second set of health lines, and two places for the same
 * bug.
 *
 * So the loop keeps its calls and the calls stop naming a platform. A
 * collector supplies one of these; the sensor holds it and never learns which.
 *
 *
 * IT HANDS BACK struct kof_evt, WHICH IS THE WHOLE POINT.
 *
 * Not the collector's own record. libkofgrille normalises kofw_evt into
 * kof_evt already - kofw_evt_to_kof, and wtext.c calls that direction "to the
 * neutral record" - and libkofantarc will do the same from whatever fanotify
 * and the netlink connector give it. The conversion is each collector's
 * business precisely because only it knows its own fields.
 *
 * What that buys: the record the sensor publishes is the record the channel
 * carries is the record the log stores is the record kofwatchman decides on.
 * One layout, four places, and a rule written against it runs on a trace from
 * either machine.
 *
 *
 * WHAT IS DELIBERATELY NOT HERE.
 *
 * No open. A collector's options are its own - ETW session names and provider
 * GUIDs on one side, mount points and a netlink socket on the other - and a
 * neutral open would either take a union of both or take nothing useful. The
 * HOST opens its collector, with its collector's own header in scope, and
 * passes the result as one of these. That is one #ifdef in the sensor's main,
 * against eleven in its loop.
 *
 * No filter. kofw_mon_filter takes a kofw_filter, which is Windows-shaped
 * today (see wfilter.c, which reads KOFW_EF_LATE_LOAD and friends). Filtering
 * is worth making neutral and is not made neutral by being renamed, so it
 * stays where it is until there is a second implementation to compare against
 * - which is the same rule that kept wtext.c and wevt_ring.c out of orbit.
 */

#ifndef KOFORBIT_KOFMON_H
#define KOFORBIT_KOFMON_H

#include <stdint.h>
#include <stdio.h>

#include "kofevt.h"

/*
 * A collector, as a sensor sees it.
 *
 * `self` is the collector's own handle - struct kofw_mon *, struct kofa_mon *
 * - and every call below takes it back. A vtable and a handle rather than an
 * opaque struct with function pointers inside it, so a collector can hand out
 * a static table and keep its own state where it already is.
 */
struct kof_mon_api {
	void *self;

	/*
	 * The next record, already normalised, waiting up to `wait_ms`.
	 * 1 when one was taken, 0 when the wait expired with nothing there.
	 *
	 * THE WAIT IS THE CONTRACT AND NOT A HINT. A sensor's loop must be
	 * able to notice that it has been asked to stop, and it can only do
	 * that between calls - so a collector that blocks past `wait_ms`
	 * makes Ctrl-C take as long as its quietest hour.
	 */
	int (*next)(void *self, struct kof_evt *out, uint32_t wait_ms);

	/*
	 * What the collector lost, in the neutral shape - see
	 * kof_evt_health. Both platforms drop records and both count them in
	 * more than one place; the neutral form is what a log header and a
	 * summary line can both be written against.
	 *
	 * May be NULL: a collector that cannot measure its own losses says so
	 * by not offering this, which is a different statement from reporting
	 * zero and is the one the tree insists on everywhere else.
	 */
	void (*health)(void *self, struct kof_evt_health *out);

	/*
	 * The image name behind a pid, or NULL. Borrowed, and only valid
	 * until the next `next` - a collector keeps this in the same table it
	 * uses to fill the record, and that table moves on.
	 *
	 * Here because a record carries a pid long after the process that had
	 * it is gone, and a sensor printing a live line wants the name. May
	 * be NULL.
	 */
	const char *(*name_of)(void *self, uint32_t pid, uint64_t start_time);

	/*
	 * Anything the neutral health cannot say, printed by the collector
	 * itself. ETW's own EventsLost, a fanotify queue overflow: real
	 * numbers that mean nothing on the other platform, so they are
	 * rendered where they are understood rather than carried in a struct
	 * that would need a field per platform. May be NULL.
	 */
	void (*print_extra)(void *self, FILE *out);

	/* Release the collector. */
	void (*close)(void *self);
};

/*
 * Drain one record. The two-line convenience the sensor's loop actually
 * writes, so that a NULL api or a NULL `next` is one check here instead of one
 * at every call site.
 */
static inline int kof_mon_next(const struct kof_mon_api *a,
			       struct kof_evt *out, uint32_t wait_ms)
{
	return (a && a->next) ? a->next(a->self, out, wait_ms) : 0;
}

static inline void kof_mon_close(const struct kof_mon_api *a)
{
	if (a && a->close)
		a->close(a->self);
}

#endif /* KOFORBIT_KOFMON_H */
