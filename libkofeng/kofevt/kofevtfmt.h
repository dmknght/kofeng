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

/* ------------------------------------------------- for a browsing UI */

/*
 * WHAT A UI NEEDS THAT A STREAM OF LINES DOES NOT.
 *
 * kof_evt_render writes a line to a FILE, which is what a tracer wants. A
 * viewer wants three other things, and they are here rather than in the viewer
 * because a viewer, a TUI and a future dashboard must not each invent their
 * own vocabulary for the same record - the way two renderers of the same event
 * already drifted once.
 *
 * ONE LINE PER EVENT, and it holds no pointer into the record: a browsing UI
 * keeps thousands of these while the records themselves stay on disk, which is
 * the whole reason it can open a log it could not load.
 */

/* Enough for a label; a path is cut rather than the buffer grown. */
#define KOF_EVT_LABEL_MAX 96u

/*
 * The object-panel label for one event: what happened, to whom, and to what.
 * `index` is the event's position in the log, because that is how a reader
 * refers to it. Returns bytes written, excluding the NUL.
 */
size_t kof_evt_label(const struct kof_evt *, uint64_t index, char *out,
		     size_t cap);

/*
 * ONE FIELD AT A TIME, for a properties panel.
 *
 * Enumerated rather than returned as a struct because a panel draws a variable
 * number of rows and only the fields this event actually carries are worth a
 * row - a file event has no ports, a network event has no exit code. Returns 0
 * when `i` is past the last field this event has.
 *
 * `name` and `val` are filled with text ready to print. The record is the only
 * source: nothing here reads a file, opens a process or asks the OS anything,
 * so it draws the same for a live event and for one replayed from a log years
 * later.
 */
int kof_evt_field(const struct kof_evt *, unsigned i,
		  char *name, size_t ncap, char *val, size_t vcap);

/* How many fields kof_evt_field will yield for this event. */
unsigned kof_evt_n_fields(const struct kof_evt *);

/* ----------------------------------------------- events that carry CONTENT */

/*
 * SOME EVENTS ARE ABOUT SOMETHING; ONE IS SOMETHING.
 *
 * Every other verb reports that a thing happened - a file appeared, a key was
 * set. KOF_EVT_AMSI_SCAN reports what a script actually CONTAINED, after the
 * host expanded it: a decoded -EncodedCommand, a block a downloader built at
 * run time, a macro body. A viewer should show that as text in a pane, not as
 * a path in a column, and this is how it knows to.
 *
 * Non-zero when the event carries content, and then `*text` and `*len` point
 * into the record.
 */
int kof_evt_content(const struct kof_evt *, const char **text, size_t *len);

/*
 * WHAT THE CONTENT IS NOT: THE ORIGINAL BYTES.
 *
 * The collector converts a submitted buffer to text at the edge - control
 * characters to '.', bytes above 0x7f to '?' - because the record is printed
 * to terminals and an escape sequence in it is a report that lies about what
 * it says. That conversion is not reversible.
 *
 * So an AMSI submission that WAS a PE cannot be recovered from a record and
 * cannot be handed to the engine. What survives is enough to see what a thing
 * is and not enough to scan it. This function says whether the content looks
 * like it began as a binary, so a viewer can say so rather than showing a
 * screen of '?' and letting a reader conclude the payload was junk.
 *
 * Recovering the real bytes needs a path that does not go through a fixed
 * record - a blob stream beside the log, with the record carrying an offset -
 * and there is not one yet.
 */
int kof_evt_content_looks_binary(const struct kof_evt *);

#endif /* KOFEVT_FMT_H */
