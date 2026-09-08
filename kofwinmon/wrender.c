/*
 * wrender.c - see wrender.h.
 */

#include <stdio.h>
#include <string.h>

#include <windows.h>

#include "wrender.h"

void wm_banner(const char *tool)
{
	fprintf(stderr, "%s (kofgrille) build %llu\n", tool,
		(unsigned long long)KOFENG_BUILD);
	if (KOFENG_BUILD == 0u)
		fputs("  built without a build stamp - cannot tell you which "
		      "build this is\n", stderr);
	fputs("  collects: process, image, file, file-write, network, "
	      "registry, thread\n"
	      "  typed:    process, image, file, network\n"
	      "  UNtyped (arrive as `raw`): registry, thread, IPv6 - their\n"
	      "            event ids are not established yet, so --raw must be\n"
	      "            on to see them at all. See wevt_decode.c.\n",
	      stderr);
}

const char *wm_leaf(const char *path)
{
	const char *last = path;

	for (; *path; path++) {
		if (*path == '\\' || *path == '/')
			last = path + 1;
	}
	return last;
}

double wm_secs_since(uint64_t t0, uint64_t t)
{
	int64_t d = (int64_t)(t - t0);

	return d < 0 ? 0.0 : (double)d / (double)KOFW_TICKS_PER_SEC;
}

uint64_t wm_now(void)
{
	FILETIME       ft;
	ULARGE_INTEGER u;

	GetSystemTimeAsFileTime(&ft);
	u.LowPart  = ft.dwLowDateTime;
	u.HighPart = ft.dwHighDateTime;
	return u.QuadPart;
}

/*
 * COUNTING, SEPARATED FROM PRINTING.
 *
 * One switch, so a --quiet run and a loud run cannot come back with different
 * totals for the same stream. The tally used to be incremented inside the
 * render switch, which meant the numbers were a side effect of somebody
 * looking at them.
 */
/*
 * RENDERING AND COUNTING MOVED TO libkofeng/kofevt/kofevtfmt.c.
 *
 * They belong there because a viewer, a service and this tracer have to show
 * the same event the same way, and because the same code then prints a live
 * session and a log replayed on a host with no ETW. What stays here is the
 * health line, which is the one thing that IS collector-specific: ETW's own
 * losses, this library's ring, the subtree filter's refusals.
 */

void wm_print_health(const struct kofw_health *h, double secs)
{
	fprintf(stderr,
		"-- %6.1fs  kept %llu (%.1f/s)  ring drop %llu  high-water %llu"
		"  etw lost %lu/%lu/%lu  undecoded %llu  self %llu\n",
		secs,
		(unsigned long long)h->produced,
		secs > 0.0 ? (double)h->produced / secs : 0.0,
		(unsigned long long)h->ring_dropped,
		(unsigned long long)h->ring_high_water,
		(unsigned long)h->etw_events_lost,
		(unsigned long)h->etw_buffers_lost,
		(unsigned long)h->etw_rt_buf_lost,
		(unsigned long long)h->decode_failed,
		(unsigned long long)h->skipped_self);

	if (h->ring_dropped || h->etw_events_lost || h->etw_rt_buf_lost ||
	    h->seq_gaps)
		fprintf(stderr,
			"   INCOMPLETE: ring dropped %llu, seq gaps %llu, "
			"etw lost %lu/%lu\n",
			(unsigned long long)h->ring_dropped,
			(unsigned long long)h->seq_gaps,
			(unsigned long)h->etw_events_lost,
			(unsigned long)h->etw_rt_buf_lost);

	/*
	 * REFUSED BY THE FILTER, BROKEN OUT BY WHICH TEST.
	 *
	 * One total cost an afternoon: a run suppressing 431 system module
	 * loads by default reported `modules loaded: 0` beside `filtered out:
	 * 431`, which reads as "the filter ate everything and I do not know
	 * why". The three reasons call for three different next steps -
	 * --all-images, a different scope, a different type set - so they are
	 * printed apart. Here rather than with the tally because a refusal is a
	 * property of this collector's filter, not of the events.
	 */
	if (h->filtered)
		fprintf(stderr,
			"   filtered out %llu  (location %llu, out of tree "
			"%llu, type %llu)\n",
			(unsigned long long)h->filtered,
			(unsigned long long)h->filtered_loc,
			(unsigned long long)h->filtered_scope,
			(unsigned long long)h->filtered_type);

	if (h->untracked)
		fprintf(stderr,
			"   INCOMPLETE: %llu process(es) could not be tracked; "
			"the scoped view is missing their events\n",
			(unsigned long long)h->untracked);

	/*
	 * Reported next to the losses rather than with the tally, because both
	 * numbers here qualify a NEGATIVE result. A run that found no unbacked
	 * thread means something only if the module lists were complete, and
	 * mod_pool_exhausted is what says they were not.
	 */
	/*
	 * Both halves, always, because the ratio is the fact. A run that read
	 * three command lines and lost forty has not said much about what ran,
	 * and the forty is the only thing that admits it.
	 */
	if (h->cmdline_got || h->cmdline_lost)
		fprintf(stderr,
			"   command lines     : %llu read, %llu lost to the "
			"race (the short-lived ones)\n",
			(unsigned long long)h->cmdline_got,
			(unsigned long long)h->cmdline_lost);

	if (h->late_loads)
		fprintf(stderr,
			"   %llu module(s) mapped late - see [late] above; "
			"common and legitimate on its own\n",
			(unsigned long long)h->late_loads);

	if (h->unbacked_threads)
		fprintf(stderr,
			"   %llu thread(s) started in no mapped image "
			"(reflective load or injection - see the trace)\n",
			(unsigned long long)h->unbacked_threads);
	if (h->mod_pool_exhausted)
		fprintf(stderr,
			"   INCOMPLETE: the module-range pool ran out %llu "
			"time(s); unbacked-thread detection was withheld for "
			"the processes affected\n",
			(unsigned long long)h->mod_pool_exhausted);

	/*
	 * Its own line, and worded as a state rather than a count, because that
	 * is what it is: the collector has stopped learning event shapes, so
	 * every id first seen from here on is discarded whole. Everything else
	 * above says how much was lost; this one says the losses will continue.
	 */
	/*
	 * A REFUSED PROVIDER IS THE FIRST THING TO PRINT AND THE LAST THING
	 * ANYBODY GUESSES.
	 *
	 * Everything else in this function says how much was lost. This one
	 * says a whole class of event was never collected at all - and it is
	 * the difference between "the sample did no network activity" and "the
	 * network provider never started". Those read identically in a trace
	 * and call for opposite next steps.
	 */
	{
		uint32_t missing = h->sub_asked & ~h->sub_enabled;
		uint32_t b;

		if (missing) {
			fputs("   INCOMPLETE: provider(s) REFUSED and never "
			      "collected:", stderr);
			for (b = 1u; b; b <<= 1) {
				if (missing & b)
					fprintf(stderr, " %s",
						kofw_sub_name(b));
			}
			fputs("\n", stderr);
		}
	}

	if (h->schema_full)
		fprintf(stderr,
			"   INCOMPLETE: the schema cache is FULL - %llu event(s) "
			"were dropped whole and every new event id will be too; "
			"run with --schema to see what it filled up on\n",
			(unsigned long long)h->schema_full);
}
