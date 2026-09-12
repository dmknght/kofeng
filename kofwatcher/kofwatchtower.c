/*
 * kofwatchtower - print what the machine is doing, and what it cost to find out.
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
 * For the events of ONE program rather than of everything, see kofmontrace in
 * this directory.
 *
 * KNOWN, AND NOT A BUG: this process's own events are refused at the callback,
 * so a process launched FROM here is not reported. Launch test processes from
 * another shell.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "kofgrille.h"
#include "kofevt.h"
#include "kofevtfmt.h"
#include "kofchan.h"

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
	kof_evt_banner(stderr, "kofwatchtower", (uint32_t)KOFENG_BUILD,
		       "process, image, file, network, registry, amsi");
	fputs("\nusage: kofwatchtower [options]\n"
	      "\n"
	      "It PUBLISHES to a shared-memory channel that kofwatchman reads.\n"
	      "That is the whole of what it does with an event: normalise it and\n"
	      "hand it over. Deciding, scanning and logging are watchman's.\n"
	      "\n"
	      "SILENT BY DEFAULT. A sensor's job is to collect and hand over,\n"
	      "not to print - it runs as a service where there is nobody to\n"
	      "read a terminal, and a process writing thousands of lines a\n"
	      "second to a console nobody is watching is spending the machine's\n"
	      "time on nothing. Ask for output when you are debugging it.\n"
	      "\n"
	      "  --channel NAME   publish under this name instead of the\n"
	      "                   default, for running two sensors at once\n"
	      "  --ring N         records in flight (default 16384, 640B each).\n"
	      "                   THIS IS THE MEMORY BUDGET: 16384 slots is 8MB,\n"
	      "                   plus about 2MB of fixed tables. Nothing here\n"
	      "                   grows under load and nothing allocates on the\n"
	      "                   collection path. A deeper ring does not prevent\n"
	      "                   loss, it postpones it - what prevents loss is a\n"
	      "                   consumer that keeps up.\n"
	      "\n"
	      "It also has no deadline. A sensor runs until it is stopped -\n"
	      "Ctrl-C or the service manager. A protection product that turned\n"
	      "itself off after N seconds would be worse than one that never\n"
	      "started, and an option for it is one somebody sets by accident.\n"
	      "\n"
	      "  --print          per-event lines, for debugging\n"
	      "  --stats-every N  a health line every N seconds (0 = never,\n"
	      "                   which is the default)\n"
	      "  --health         one health line at exit\n"

	      "\n"
	      "THERE ARE NO PROVIDER FLAGS, and that is deliberate. What a\n"
	      "sensor collects is a property of the product, not of a command\n"
	      "line: if the set is wrong it is wrong on every machine, and a\n"
	      "flag only means somebody sets it without knowing what it costs.\n"
	      "See KOFW_SUB_SENSOR for the set and for the two subscriptions\n"
	      "left out of it. Choosing providers is what kofmontrace is for.\n"
	      "\n"
	      "Requires an elevated prompt: a real-time ETW session cannot be\n"
	      "started without one.\n", stderr);
}

int main(int argc, char **argv)
{
	struct kofw_mon_option opt;
	struct kofw_mon   *mon;
	struct kofw_health health;
	struct kof_evt_health nh;
	struct kofw_evt    e;
	struct kof_evt     ke;
	struct kof_evt_tally tally;
	/*
	 * NO DEADLINE, AND NOT AS A DEFAULT - THERE IS NO OPTION FOR ONE.
	 *
	 * A sensor runs until it is stopped. "Collect for thirty seconds and
	 * exit" is a thing a tracer does, because somebody is standing there;
	 * a service that stopped on its own would be a protection product that
	 * turns itself off, and an option for it is an option somebody sets by
	 * accident. Ctrl-C, or the service manager, and nothing else.
	 */
	double   stats_every = 0.0, next_stats, secs = 0.0;
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
	/*
	 * SILENT UNLESS ASKED. stats_every 0 means never, which is what a
	 * service wants: the health line is a debugging affordance, not a log
	 * format.
	 */
	int      do_print = 0, show_health = 0;
	struct kof_chan_pub *chan = NULL;
	const char *chan_name = NULL;
	struct kofw_filter filt;
	int      err = 0, i;

	memset(&opt, 0, sizeof opt);
	memset(&tally, 0, sizeof tally);
	/*
	 * THE RING IS THIS SERVICE'S MEMORY BUDGET, and 16384 slots is 8MB.
	 *
	 * It was 65536 - 32MB - on the reasoning that a machine-wide stream is
	 * denser than a tracer's. True, and the wrong trade for something that
	 * runs on every machine forever: a deeper ring does not prevent loss,
	 * it postpones it, and what actually prevents loss is a consumer that
	 * keeps up. 8MB is a service; 32MB is a service somebody notices.
	 *
	 * Every other allocation here is fixed at open and never grows -
	 * measured: 1.0MB process table, 0.6MB FileKey table, 0.3MB schema
	 * cache, in one block. So the resident set is this number plus about
	 * two megabytes, and it does not move under load. That property
	 * matters more than the number: no growth, no fragmentation, and not
	 * one allocation on the callback path.
	 */
	opt.ring_capacity = 16384u;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--stats-every") && i + 1 < argc)
			stats_every = atof(argv[++i]);
		else if (!strcmp(argv[i], "--ring") && i + 1 < argc)
			opt.ring_capacity = (uint32_t)strtoul(argv[++i],
							      NULL, 10);
		else if (!strcmp(argv[i], "--channel") && i + 1 < argc)
			chan_name = argv[++i];
		else if (!strcmp(argv[i], "--print"))
			do_print = 1;
		else if (!strcmp(argv[i], "--health"))
			show_health = 1;
		else if (!strcmp(argv[i], "--help") ||
			 !strcmp(argv[i], "-h") ||
			 !strcmp(argv[i], "/?")) {
			usage();
			return 0;
		} else {
			/* Named, rather than only printing the usage: the whole
			 * question a reader has is WHICH argument was wrong,
			 * and a wall of usage text does not answer it. */
			fprintf(stderr, "kofwatchtower: unknown option '%s'\n\n",
				argv[i]);
			usage();
			return 2;
		}
	}

	SetConsoleCtrlHandler(on_ctrl, TRUE);

	/*
	 * THE SUBSCRIPTION IS NOT A CHOICE HERE.
	 *
	 * See KOFW_SUB_SENSOR for the set and for the two left out of it. A
	 * sensor's subscription is a property of the product: if it is wrong it
	 * is wrong on every machine, and a flag only means somebody sets it
	 * without knowing what it costs. Choosing providers is what the tracer
	 * is for.
	 */
	opt.providers = KOFW_SUB_SENSOR;

	/*
	 * NO CONSUMER-SIDE FILTER.
	 *
	 * The tracer drops system module loads and untyped events because it
	 * is showing a person a screen. A sensor is not showing anybody
	 * anything - it hands everything over, and deciding what matters is
	 * watchman's job. Filtering here would mean the record watchman never
	 * receives is one nobody can decide about later, and a log that was
	 * pre-judged by the wrong half.
	 *
	 * A cleared filter means "everything", which is the answer a caller who
	 * forgot a field should get: less filtering, never more.
	 */
	memset(&filt, 0, sizeof filt);

	mon = kofw_mon_open(&opt, &err);
	if (!mon) {
		fprintf(stderr, "kofwatchtower: %s\n", kofw_err_name(err));
		if (err == KOFW_ERR_ACCESS)
			fputs("kofwatchtower: run this from an elevated "
			      "prompt.\n", stderr);
		return 1;
	}
	kofw_mon_filter(mon, &filt);

	/*
	 * ONE LINE, AND ONLY WHAT A READER CANNOT INFER.
	 *
	 * A provider that refused is the reason a run looks quiet, and a wrong
	 * provider is silent rather than an error - so that is worth saying
	 * even in a silent tool. What it collects is fixed and in --help.
	 */
	{
		struct kofw_health h0;
		uint32_t missing, b;

		kofw_mon_health(mon, &h0);
		missing = h0.sub_asked & ~h0.sub_enabled;
		if (missing) {
			fputs("kofwatchtower: REFUSED by the provider:", stderr);
			for (b = 1u; b; b <<= 1)
				if (missing & b)
					fprintf(stderr, " %s",
						kofw_sub_name(b));
			fputs("\n  a wrong provider is silent, not an error - "
			      "check with `logman query providers <name>`\n",
			      stderr);
		}
	}

	/*
	 * THE CHANNEL, opened before the first event can arrive.
	 *
	 * Failing to open it is fatal rather than degraded: a sensor with
	 * nowhere to hand records is collecting for nothing, and a service
	 * that ran anyway would look healthy while doing no work at all. The
	 * usual cause is a second sensor already publishing - which is refused
	 * on purpose, two publishers on one ring interleave into it.
	 */
	chan = kof_chan_publish_open(chan_name, opt.ring_capacity);
	if (!chan) {
		fputs("kofwatchtower: cannot publish a channel - another "
		      "sensor may already be running\n", stderr);
		kofw_mon_close(mon);
		return 1;
	}

	/*
	 * NO LOG HERE, AND NO SHAPE DUMP.
	 *
	 * A sensor collects and hands over. What is worth keeping out of that
	 * stream is a DECISION - which events, for how long, at what cost in
	 * disk - and decisions belong to the half that is deciding. Putting a
	 * recorder here would mean the sensor persisting things nobody asked
	 * for, and two places that both write logs in slightly different ways.
	 *
	 * The shape dump went with it for a related reason: it is a diagnostic
	 * about DECODING, wanted by somebody debugging why an event looks
	 * wrong, and that person is running the tracer. See kofmontrace
	 * --schema.
	 *
	 * The consequence, stated rather than discovered: until the channel to
	 * kofwatchman exists, this tool has no output but --print. That is the
	 * honest state of a sensor with nothing attached to it.
	 */

	t_wall0    = kof_evt_now();
	next_stats = stats_every;

	while (!g_stop) {

		if (!kofw_mon_next(mon, &e, 200)) {
			/* Nothing arrived; the clock still has to advance so
			 * --stats-every fires and --seconds still expires. */
			secs = kof_evt_secs_since(t_wall0, kof_evt_now());
			goto tick;
		}

		if (t_ev0 == 0)
			t_ev0 = e.stamp;
		ev_secs = kof_evt_secs_since(t_ev0, e.stamp);
		secs    = kof_evt_secs_since(t_wall0, kof_evt_now());

		/*
		 * CONVERTED ONCE, HERE. This was missing - the loop rendered a
		 * kof_evt nothing had filled in, which is the kind of bug that
		 * prints plausible garbage rather than crashing.
		 */
		kofw_evt_to_kof(&e, &ke);

		/*
		 * HANDED OVER FIRST, and its refusal is not this tool's
		 * problem to solve: a full channel means the subscriber is not
		 * keeping up, which is counted in the channel header where the
		 * subscriber can see it too.
		 */
		(void)kof_chan_publish(chan, &ke);

		/*
		 * Counted always, printed only when asked - so a silent run and
		 * a --print run produce the same numbers. The counters used to
		 * live in the render switch, which made the totals a side
		 * effect of somebody looking at them.
		 */
		if (do_print)
			kof_evt_render(&ke, ev_secs,
				       kofw_mon_name_of(mon, e.pid,
						e.type == KOF_EVT_PROC_START ||
						e.type == KOF_EVT_PROC_STOP
							? e.create_time : 0),
				       stdout, &tally);
		else
			kof_evt_count(&ke, &tally);

tick:
		if (stats_every > 0.0 && secs >= next_stats) {
			kofw_mon_health(mon, &health);
			kofw_mon_health_neutral(mon, &nh);
			kof_evt_health_print(stderr, &nh, secs);
			kofw_health_print_extra(stderr, &health);
			next_stats += stats_every;
		}
	}



	/*
	 * At exit, only if asked. A sensor that printed a summary to a console
	 * nobody is watching is spending the machine's time on nothing - and
	 * one running as a service has no console at all.
	 */
	kof_chan_publish_close(chan);

	if (show_health) {
		kofw_mon_health(mon, &health);
		kofw_mon_health_neutral(mon, &nh);
		kof_evt_print_tally(&tally, secs, "the whole machine", stderr);
		kof_evt_health_print(stderr, &nh, secs);
		kofw_health_print_extra(stderr, &health);
	}


	fflush(stdout);



	kofw_mon_health(mon, &health);
	kof_evt_print_tally(&tally, secs, "whole machine", stderr);
	kofw_mon_health_neutral(mon, &nh);
	kof_evt_health_print(stderr, &nh, secs);
	/* And the half only this collector has - see kofw_health_print_extra
	 * for why the unbacked count and the reasons it may be unanswerable
	 * belong on the same screen. */
	kofw_health_print_extra(stderr, &health);

	kofw_mon_close(mon);
	return 0;
}
