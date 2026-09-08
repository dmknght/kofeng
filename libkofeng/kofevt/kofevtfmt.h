/*
 * kofevtfmt.h - how an event is PRESENTED.
 *
 * The third of kofevt's three jobs, after the record and the log. It is here
 * for the same reason they are: a debug tracer, a service, a viewer and
 * whatever reads a recorded log all have to show the same event the same way,
 * and a rendering that lives in one tool is a rendering the others reimplement
 * slightly differently.
 *
 * It took one afternoon to demonstrate that. The tracer's renderer counted a
 * tally inside its print switch, so a run with --quiet came back with
 * different totals from a run without - the numbers were a side effect of
 * somebody looking at them.
 *
 * NO OS AND NO COLLECTOR. It renders a struct kof_evt, so a line printed from
 * a live Windows session and the same line printed on Linux from the recorded
 * log are produced by the same code, which is what makes a log worth keeping.
 */

#ifndef KOFEVT_FMT_H
#define KOFEVT_FMT_H

#include <stdio.h>

#include "kofevt.h"

/*
 * WHAT A RUN ADDED UP TO.
 *
 * Counters rather than a score: "4 files created, 2 registry writes, 31 KB
 * received" is something a reader can act on, and a number computed from those
 * is not - see the note in kofevt.h on why nothing here is summed.
 */
struct kof_evt_tally {
	uint64_t proc, image, thread;
	uint64_t file_new, file_del, file_ren, file_wr;
	uint64_t reg, amsi;
	uint64_t conn, bytes_sent, bytes_recv;
	uint64_t raw;
};

/*
 * Count one event without printing it.
 *
 * Separate from rendering, and that separation is the bug it was written to
 * fix: a quiet run and a loud one must not come back with different totals for
 * the same stream.
 */
void kof_evt_count(const struct kof_evt *, struct kof_evt_tally *);

/*
 * Print one event as a line, and count it.
 *
 * `secs` is however the caller wants time shown - seconds since the first
 * event, usually. `who` names the subject and may be "" or NULL; the caller
 * knows a process table and this file does not.
 */
void kof_evt_render(const struct kof_evt *, double secs, const char *who,
		    FILE *out, struct kof_evt_tally *);

/* The summary, to `out`. `what` names what was watched - "the whole machine",
 * "subtree of pid 4242". */
void kof_evt_print_tally(const struct kof_evt_tally *, double secs,
			 const char *what, FILE *out);

#endif /* KOFEVT_FMT_H */
