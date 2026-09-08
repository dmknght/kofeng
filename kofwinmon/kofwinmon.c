/*
 * kofwinmon - print what the machine is doing, and what it cost to find out.
 *
 * This detects nothing, deliberately. Its whole job is to answer the two
 * questions that have to be answered before any detection can be designed:
 * what does the event stream actually look like, and what does collecting it
 * cost.
 *
 * So the health counters are not a footer nobody reads. A run that printed a
 * thousand events and lost four hundred is a different result from one that
 * printed a thousand, and the difference is the only thing that says whether
 * the ring is sized for this machine and whether the next provider can be
 * afforded. Turn a provider on, run for a minute while the machine does real
 * work, and read the line - that is the whole method.
 *
 * For the events of ONE program rather than of everything, see kofwintrace in
 * this directory.
 *
 * KNOWN, AND NOT A BUG: this process's own events are refused at the callback,
 * so a process launched FROM here is not reported. Launch test processes from
 * another shell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "kofgrille.h"
#include "wrender.h"

static volatile LONG g_stop;

static BOOL WINAPI on_ctrl(DWORD type)
{
	(void)type;
	/* Only ask the loop to finish. Doing the teardown here would run it on
	 * the control handler's own thread while the main thread is still
	 * inside kofw_mon_next. */
	InterlockedExchange(&g_stop, 1);
	return TRUE;
}

static void usage(void)
{
	fputs("usage: kofwinmon [options]\n"
	      "\n"
	      "  --seconds N      stop after N seconds (0 = until ctrl-c)\n"
	      "  --stats-every N  health line every N seconds (default 10)\n"
	      "  --ring N         records in flight (default 16384, 512B each)\n"
	      "  --quiet          health only, no per-event lines\n"
	      "  --schema         at exit, print the payload shapes TDH described\n"
	      "  --raw            also print events this build has no type for\n"
	      "\n"
	      "  --image          subscribe to module loads\n"
	      "  --all-images     ... and do not suppress the system ones\n"
	      "  --file           subscribe to file create/delete/rename\n"
	      "  --file-write     ... and to writes into existing files\n"
	      "  --net            subscribe to network events\n"
	      "  --registry       subscribe to registry create/set/delete\n"
	      "  --thread         subscribe to thread create/exit - the only\n"
	      "                   in-box view of an in-memory module load\n"
	      "  --no-system-logger  plain session, if a provider delivers\n"
	      "                   nothing after enabling successfully\n"
	      "  --all            every provider, system images and raw events\n"
	      "\n"
	      "Process start/stop is always on: everything else is scoped BY a\n"
	      "process, so a collector without it cannot attribute what it sees.\n"
	      "\n"
	      "Requires an elevated prompt: a real-time ETW session cannot be\n"
	      "started without one.\n", stderr);
}

int main(int argc, char **argv)
{
	struct kofw_mon_option opt;
	struct kofw_mon   *mon;
	struct kofw_health health;
	struct kofw_evt    e;
	struct wm_tally    tally;
	double   run_secs = 0.0, stats_every = 10.0, next_stats, secs = 0.0;
	double   ev_secs = 0.0;
	/*
	 * TWO BASELINES, because they answer to different things. `t_wall0` is
	 * when this started and drives the deadlines - it has to advance even
	 * when no event arrives. `t_ev0` is the first event's own stamp and
	 * drives the printed column. Deriving both from one baseline looked
	 * equivalent and was not: an event's stamp is when it HAPPENED and is
	 * routinely older than a wall-clock reading taken while waiting for it,
	 * so every offset clamped to 0.000.
	 */
	uint64_t t_wall0, t_ev0 = 0;
	int      quiet = 0, show_schema = 0, show_raw = 0, show_all_img = 0;
	int      want_file = 0, want_image = 0, want_net = 0, want_write = 0;
	int      want_reg = 0, want_thread = 0;
	struct kofw_filter filt;
	int      err = 0, i;

	memset(&opt, 0, sizeof opt);
	memset(&tally, 0, sizeof tally);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--seconds") && i + 1 < argc)
			run_secs = atof(argv[++i]);
		else if (!strcmp(argv[i], "--stats-every") && i + 1 < argc)
			stats_every = atof(argv[++i]);
		else if (!strcmp(argv[i], "--ring") && i + 1 < argc)
			opt.ring_capacity = (uint32_t)strtoul(argv[++i],
							      NULL, 10);
		else if (!strcmp(argv[i], "--quiet"))
			quiet = 1;
		else if (!strcmp(argv[i], "--schema"))
			show_schema = 1;
		else if (!strcmp(argv[i], "--raw"))
			show_raw = 1;
		else if (!strcmp(argv[i], "--image"))
			want_image = 1;
		else if (!strcmp(argv[i], "--all-images"))
			want_image = show_all_img = 1;
		else if (!strcmp(argv[i], "--file"))
			want_file = 1;
		else if (!strcmp(argv[i], "--file-write"))
			want_file = want_write = 1;
		else if (!strcmp(argv[i], "--net"))
			want_net = 1;
		else if (!strcmp(argv[i], "--registry"))
			want_reg = 1;
		else if (!strcmp(argv[i], "--thread"))
			want_thread = 1;
		else if (!strcmp(argv[i], "--no-system-logger"))
			opt.no_system_logger = 1;
		/*
		 * Everything, which is what kofwintrace takes by default and
		 * what kofwinmon does NOT: this one watches the whole machine
		 * with no subtree filter in front of it, so "everything" here
		 * is a firehose somebody has to ask for on purpose.
		 */
		else if (!strcmp(argv[i], "--all"))
			want_image = show_all_img = want_file = want_write =
				want_net = want_reg = show_raw = 1;
		else {
			/* Named, rather than only printing the usage: the
			 * whole question a reader has is WHICH argument was
			 * wrong, and a wall of usage text does not answer it. */
			fprintf(stderr, "kofwinmon: unknown option '%s'\n\n",
				argv[i]);
			usage();
			return 2;
		}
	}

	/*
	 * QUIET SUPPRESSES THE STREAM, not the code that writes to it. The
	 * per-event counters live in the same switch as the printing, so
	 * skipping the printing would skip the counting and the summary would
	 * come out as zeros.
	 */
	if (quiet && !freopen("NUL", "w", stdout))
		fputs("kofwinmon: could not silence stdout; printing anyway\n",
		      stderr);

	SetConsoleCtrlHandler(on_ctrl, TRUE);


	opt.providers = KOFW_SUB_PROCESS |
			(want_image ? KOFW_SUB_IMAGE : 0u) |
			(want_file  ? KOFW_SUB_FILE  : 0u) |
			(want_write ? KOFW_SUB_FILE_WRITE : 0u) |
			(want_net   ? KOFW_SUB_NET   : 0u) |
			(want_reg   ? KOFW_SUB_REGISTRY : 0u) |
			(want_thread ? KOFW_SUB_THREAD : 0u);

	{
		struct kofw_filter f;

		memset(&f, 0, sizeof f);
		/* Watching the machine means seeing all of it, except the
		 * module loads every process performs - see kofw_filter. */
		if (!show_all_img)
			f.drop_loc = 1u << KOFW_LOC_SYSTEM;
		if (!show_raw)
			f.types = ~(uint32_t)(1u << KOFW_EVT_RAW);
		filt = f;
	}

	mon = kofw_mon_open(&opt, &err);
	if (!mon) {
		fprintf(stderr, "kofwinmon: %s\n", kofw_err_name(err));
		if (err == KOFW_ERR_ACCESS)
			fputs("kofwinmon: run this from an elevated prompt.\n",
			      stderr);
		return 1;
	}
	kofw_mon_filter(mon, &filt);

	fprintf(stderr,
		"kofwinmon: whole machine, providers: process%s%s%s%s\n"
		"kofwinmon: verify one with `logman query providers <name>` - a\n"
		"kofwinmon: wrong provider is silent, not an error, so if nothing\n"
		"kofwinmon: arrives that is the first thing to check.\n\n",
		want_image ? " image" : "", want_file ? " file" : "",
		want_write ? " file-write" : "", want_net ? " net" : "");

	t_wall0    = wm_now();
	next_stats = stats_every;

	while (!g_stop) {

		if (!kofw_mon_next(mon, &e, 200)) {
			/* Nothing arrived; the clock still has to advance so a
			 * quiet machine prints its health line and --seconds
			 * still expires. */
			secs = wm_secs_since(t_wall0, wm_now());
			goto tick;
		}

		if (t_ev0 == 0)
			t_ev0 = e.stamp;
		ev_secs = wm_secs_since(t_ev0, e.stamp);
		secs    = wm_secs_since(t_wall0, wm_now());

		wm_render(&e, ev_secs,
			  kofw_mon_name_of(mon, e.pid,
					   e.type == KOFW_EVT_PROC_START ||
					   e.type == KOFW_EVT_PROC_STOP
						   ? e.create_time : 0),
			  &tally);

tick:
		if (run_secs > 0.0 && secs >= run_secs)
			break;
		if (secs >= next_stats) {
			kofw_mon_health(mon, &health);
			wm_print_health(&health, secs);
			next_stats += stats_every;
		}
	}

	fflush(stdout);

	if (show_schema) {
		static char desc[32768];

		if (kofw_mon_describe(mon, desc, sizeof desc))
			fprintf(stderr, "\n-- payload shapes learned:\n%s",
				desc);
	}

	kofw_mon_health(mon, &health);
	wm_print_tally(&tally, secs, "whole machine", health.filtered);
	wm_print_health(&health, secs);

	kofw_mon_close(mon);
	return 0;
}
