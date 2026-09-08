/*
 * wrender.h - printing an event, and counting what a run produced.
 *
 * All that is left in the tools once classification, filtering and process
 * tracking moved into libkofgrille: this is presentation and nothing else. It
 * makes no decisions about what an event MEANS - kofw_evt.obj_loc already
 * carries that - so a second consumer that renders differently can ignore this
 * file entirely without losing any judgement the collector made.
 */

#ifndef KOFWINMON_WRENDER_H
#define KOFWINMON_WRENDER_H

#include <stdint.h>

#include "kofgrille.h"

/*
 * What a run produced, counted as it goes.
 *
 * Kept apart from the printed lines because the lines are a transcript and this
 * is the answer. Somebody reading four hundred events wants to know what came
 * out of them, and scrolling is not that.
 */
struct wm_tally {
	uint64_t proc, image;
	uint64_t file_new, file_del, file_ren;
	uint64_t conn, bytes_sent, bytes_recv;
	uint64_t raw;
};

/* Print one event and count it. `who` is the subject's name for the column and
 * may be "" - see kofw_mon_name_of. */
void wm_render(const struct kofw_evt *e, double secs, const char *who,
	       struct wm_tally *t);

void wm_print_tally(const struct wm_tally *t, double secs, const char *what,
		    uint64_t suppressed);

/*
 * LOSS IS PART OF THE RESULT, not a footnote.
 *
 * A run that dropped records is a different claim from one that did not, and a
 * reader about to conclude "the sample did nothing" has to be told which kind
 * they are holding. The three losses - ETW's own, this library's ring, and
 * holes in the sequence - are reported apart and never summed: they happen at
 * different places and only the middle one is a choice anybody made.
 */
void wm_print_health(const struct kofw_health *h, double secs);

/* Seconds between two FILETIME stamps, signed and clamped at zero: an event's
 * stamp is when it HAPPENED and is routinely older than a wall-clock reading
 * taken while waiting for it, and unsigned subtraction there yields 1.8e19
 * rather than a small negative. */
double   wm_secs_since(uint64_t t0, uint64_t t);

/* Now, on the same clock kofw_evt.stamp uses. */
uint64_t wm_now(void);

const char *wm_leaf(const char *path);

#endif /* KOFWINMON_WRENDER_H */
