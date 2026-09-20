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

/*
 * _GNU_SOURCE on the POSIX side: the collector needs the fanotify
 * declarations, which are GNU extensions and invisible under a bare -std=c11.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ONE SENSOR, TWO PLATFORMS, AND ONE PLACE THAT KNOWS WHICH.
 *
 * The collector is the only thing that differs, so it is the only thing behind
 * the adapter below. The subscription, the channel, the ring, the drain loop
 * and every option are shared - which is the arrangement in which a fix to any
 * of them cannot land on one platform and miss the other.
 */
#ifdef _WIN32
#include <windows.h>
#include "kofgrille.h"
#include "../libkofeng/core/kofplatform.h"
#else
#include <signal.h>
#include "kofantarc.h"
#include <poll.h>

#include "afan.h"
#include "apev.h"
/* The POSIX half needs this too: kof_utf8_init is called on both paths and is
 * declared here for both. It used to be reached only from the _WIN32 branch,
 * which left the call on this side with no declaration at all - invisible
 * until something forced this file to be compiled again. */
#include "../libkofeng/core/kofplatform.h"
#endif

#include "kofevt.h"
#include "kofevtfmt.h"
#include "kofchan.h"

#ifdef _WIN32
static volatile LONG g_stop;

static BOOL WINAPI on_ctrl(DWORD type)
{
	(void)type;
	/* Only ask the loop to finish. Doing the teardown here would run it on
	 * the control handler's own thread while the main thread is still
	 * inside the collector. */
	InterlockedExchange(&g_stop, 1);
	return TRUE;
}

static void stop_on_signal(void) { SetConsoleCtrlHandler(on_ctrl, TRUE); }
#else
static volatile sig_atomic_t g_stop;

/* Same contract as the Windows handler above: ask, do not tear down. A signal
 * handler that closed the collector would free memory the main thread is
 * reading inside a blocking read. */
static void on_ctrl(int sig) { (void)sig; g_stop = 1; }

static void stop_on_signal(void)
{
	signal(SIGINT, on_ctrl);
	signal(SIGTERM, on_ctrl);
}
#endif

/* ----------------------------------------------------------- the collector */

/*
 * WHAT THE SUBSCRIPTION MEANS ON EACH HOST.
 *
 * KOFW_SUB_SENSOR is a set of ETW providers. fanotify is one session with one
 * mask and no choice inside it, so there is nothing to name on the Linux side
 * - which is why this adapter takes no provider argument at all rather than
 * taking one and ignoring it.
 *
 * WHAT THE LINUX SENSOR NEEDS: CAP_SYS_ADMIN, for the filesystem-wide mark.
 * Without it the session opens DEGRADED - dirent events only, no actor on
 * anything this process did not do itself - and a sensor whose records carry
 * no pid cannot support a single rule that asks who did something. It still
 * runs, and it says so at open, because a degraded session is a working test
 * surface and a silent one is a product that looks healthy while deciding
 * nothing.
 */
struct sensor {
#ifdef _WIN32
	struct kofw_mon  *mon;
	struct kofw_evt   raw;
#else
	struct kofa_fan          *fan;
	const struct kof_mon_api *api;
	/*
	 * AND THE PROCESS HALF, which is a SECOND session rather than another
	 * subscription on the first.
	 *
	 * Windows has one ETW session carrying every keyword, so the struct
	 * above assumed one collector. Linux has two mechanisms that have
	 * nothing in common - fanotify for files, the netlink connector for
	 * processes - and neither can report the other's events. A sensor
	 * that watched only files could see a dropper write its payload and
	 * never see it run.
	 *
	 * OPTIONAL, and that is not a hedge. The connector needs
	 * CAP_NET_ADMIN and refuses silently - see apev.h - so a host that
	 * grants CAP_SYS_ADMIN for fanotify and not this one still gets the
	 * file stream, and is TOLD which half it is missing rather than left
	 * to infer it from a quiet screen.
	 */
	struct kofa_pev          *pev;
	const struct kof_mon_api *pev_api;
	int                       pev_err;
	int                       turn;   /* which stream is asked first */
#endif
};

static int sensor_open(struct sensor *s, uint32_t ring)
{
	int err = 0;

	memset(s, 0, sizeof *s);
#ifdef _WIN32
	{
		struct kofw_mon_option opt;

		memset(&opt, 0, sizeof opt);
		/*
		 * THE SUBSCRIPTION IS NOT A CHOICE HERE.
		 *
		 * See KOFW_SUB_SENSOR for the set and for the two left out of
		 * it. A sensor's subscription is a property of the product: if
		 * it is wrong it is wrong on every machine, and a flag only
		 * means somebody sets it without knowing what it costs.
		 * Choosing providers is what the tracer is for.
		 */
		opt.providers = KOFW_SUB_SENSOR;
		opt.ring_capacity = ring;
		s->mon = kofw_mon_open(&opt, &err);
		if (!s->mon) {
			fprintf(stderr, "kofwatchtower: %s\n",
				kofw_err_name(err));
			if (err == KOFW_ERR_ACCESS)
				fputs("kofwatchtower: run this from an "
				      "elevated prompt.\n", stderr);
			return 0;
		}
		{
			/*
			 * NO CONSUMER-SIDE FILTER.
			 *
			 * The tracer drops system module loads and untyped
			 * events because it is showing a person a screen. A
			 * sensor is not showing anybody anything - it hands
			 * everything over, and deciding what matters is
			 * watchman's job. Filtering here would mean the record
			 * watchman never receives is one nobody can decide
			 * about later, and a log that was pre-judged by the
			 * wrong half.
			 *
			 * A cleared filter means "everything", which is the
			 * answer a caller who forgot a field should get: less
			 * filtering, never more.
			 */
			struct kofw_filter filt;

			memset(&filt, 0, sizeof filt);
			kofw_mon_filter(s->mon, &filt);
		}
	}
#else
	{
		struct kofa_fan_option fo;

		memset(&fo, 0, sizeof fo);
		fo.capacity = ring;
		/* trace_self stays OFF: this process publishes to a channel
		 * and watchman reads the files it names, so reporting our own
		 * reads is the feedback loop afan.h describes. */
		s->fan = kofa_fan_open(&fo, &err);
		if (!s->fan) {
			fprintf(stderr, "kofwatchtower: %s\n",
				kofa_err_name(err));
			if (err == KOFA_ERR_DENIED)
				fputs("kofwatchtower: run this as root.\n",
				      stderr);
			return 0;
		}
		s->api = kofa_fan_api(s->fan);
	}
	{
		struct kofa_pev_option po;

		memset(&po, 0, sizeof po);
		/* Off for the reason the file half gives: this process's own
		 * helpers are not evidence about the host. */
		s->pev = kofa_pev_open(&po, &s->pev_err);
		s->pev_api = s->pev ? kofa_pev_api(s->pev) : NULL;
	}
#endif
	return 1;
}

#ifndef _WIN32
/*
 * ONE EXEC, ONE RECORD - the half of the answer only the sensor has.
 *
 * The two Linux collectors report the same exec from opposite ends. fanotify
 * sees the binary opened with intent to execute and files an image load; the
 * process connector sees the exec and files a process start. Both are correct
 * and both are wanted - an image load is how a library dropped in /tmp becomes
 * visible - but the program's OWN binary produces one of each, and a consumer
 * counting executions would count it twice.
 *
 * NEITHER COLLECTOR MAY DECIDE THIS ALONE. afan running by itself is the only
 * thing reporting that exec at all, so a library that suppressed it would turn
 * a duplicate into a gap; apev cannot see the image load. The sensor is what
 * knows both are open, so the sensor is what drops one - and it drops the
 * IMAGE LOAD rather than the start, because the start carries the parent, the
 * command line and the verdict-bearing path while the load carries the path
 * alone.
 *
 * Returns 1 to keep the record, and 0 the way `next` reports "nothing this
 * time" - which the caller's loop already handles, because a wait expiring is
 * the same answer.
 */
static int sensor_keep(struct sensor *s, struct kof_evt *out)
{
	const char *img;

	if (!s->pev || out->verb != KOF_EVT_IMAGE_LOAD)
		return 1;
	if (out->miss & KOF_F_PID)
		return 1;              /* degraded fanotify: no pid to match */
	img = kof_evt_object(out);
	if (!img || !*img)
		return 1;
	/*
	 * AND BEFORE DECIDING, HAND THE PATH OVER.
	 *
	 * This record is fanotify's, and fanotify got the path from the kernel
	 * without racing anything - see kofa_pev_hint_image. The process
	 * collector is about to need exactly that path for the start it will
	 * report a moment from now, and its own source for it is /proc, which
	 * a short-lived process empties before it can be read.
	 *
	 * So the answer travels from the collector that has it to the one that
	 * does not, through the sensor, which is the only place that holds
	 * both. It is done here rather than after the duplicate test because a
	 * record that is ABOUT to be dropped as a duplicate is still the one
	 * carrying the path.
	 */
	kofa_pev_hint_image(s->pev, out->pid, img);
	/*
	 * No clock is offered: the two collectors stamp from different
	 * sources - fanotify records carry no time of their own here - so a
	 * window computed across them would compare two unrelated scales. The
	 * image match against a process that is still marked running is what
	 * decides, and apev drops the entry the moment the process exits.
	 */
	return !kofa_pev_is_own_image(s->pev, out->pid, img, 0);
}
#endif

static int sensor_next(struct sensor *s, struct kof_evt *out, uint32_t wait_ms)
{
#ifdef _WIN32
	if (!kofw_mon_next(s->mon, &s->raw, wait_ms))
		return 0;
	/*
	 * CONVERTED ONCE, HERE. This was missing - the loop rendered a
	 * kof_evt nothing had filled in, which is the kind of bug that prints
	 * plausible garbage rather than crashing.
	 */
	kofw_evt_to_kof(&s->raw, out);
	return 1;
#else
	/*
	 * TWO STREAMS, AND NEITHER MAY STARVE THE OTHER.
	 *
	 * Asking one with the full wait and the other with what is left would
	 * hand the whole budget to whichever is busier - on a machine doing a
	 * build that is the file stream, and the process events it is there
	 * to correlate with would arrive minutes late or not at all.
	 *
	 * So each call drains the other one first with no wait at all, and
	 * only then blocks on one of them; which one blocks alternates. Every
	 * record that is already queued is taken immediately whichever stream
	 * holds it, and the wait the caller asked for is still bounded.
	 */
	if (!s->pev_api)
		return kof_mon_next(s->api, out, wait_ms);
	/*
	 * BOTH STREAMS ARE DRAINED FIRST, AND THEN BOTH ARE WAITED ON.
	 *
	 * Blocking on one of them was the bug. This alternated which one got
	 * the wait, so half the time it sat on the file stream for the whole
	 * 200 ms while process records aged in a socket nobody was reading -
	 * and the things worth catching do not last that long. Measured:
	 * `whoami` exists for 0.5 ms and `ls` for 0.74 ms, and their path and
	 * command line are read out of /proc, which is empty the moment they
	 * are gone. Every short command therefore came back as
	 * "[cmd unread: process gone]" whenever the filesystem was quiet.
	 *
	 * So nothing blocks inside a collector any more. Both are asked with
	 * no wait, and if neither had anything the sensor waits on both
	 * descriptors at once and asks again. A collector that cannot be
	 * waited on - ETW, where records arrive on a callback thread - says so
	 * with -1 and keeps the old arrangement.
	 */
	s->turn = !s->turn;
	{
		const struct kof_mon_api *a = s->turn ? s->pev_api : s->api;
		const struct kof_mon_api *b = s->turn ? s->api : s->pev_api;
		struct pollfd pf[2];
		int nf = 0, fa, fb;

		if (kof_mon_next(a, out, 0))
			return sensor_keep(s, out);
		if (kof_mon_next(b, out, 0))
			return sensor_keep(s, out);

		fa = a->pollfd ? a->pollfd(a->self) : -1;
		fb = b->pollfd ? b->pollfd(b->self) : -1;
		if (fa < 0 || fb < 0) {
			/* One of them cannot be waited on, so it has to be
			 * given the wait directly - and the other is then
			 * asked again straight after. */
			if (kof_mon_next(fa < 0 ? a : b, out, wait_ms))
				return sensor_keep(s, out);
			if (kof_mon_next(fa < 0 ? b : a, out, 0))
				return sensor_keep(s, out);
			return 0;
		}
		pf[nf].fd = fa; pf[nf].events = POLLIN; pf[nf++].revents = 0;
		pf[nf].fd = fb; pf[nf].events = POLLIN; pf[nf++].revents = 0;
		if (poll(pf, (nfds_t)nf, (int)wait_ms) <= 0)
			return 0;
		if ((pf[0].revents & POLLIN) && kof_mon_next(a, out, 0))
			return sensor_keep(s, out);
		if ((pf[1].revents & POLLIN) && kof_mon_next(b, out, 0))
			return sensor_keep(s, out);
		return 0;
	}
#endif
}

/* The image name behind the pid of the record sensor_next last returned - read
 * off the RAW record, because the Windows lookup is keyed on (pid,
 * create_time) and a pid alone names whoever holds it now. Linux has no such
 * map and returns the empty string, which kof_evt_render prints as unknown. */
static const char *sensor_name_of(struct sensor *s, uint32_t pid)
{
#ifdef _WIN32
	(void)pid;
	return kofw_mon_name_of(s->mon, s->raw.pid,
				s->raw.type == KOF_EVT_PROC_START ||
				s->raw.type == KOF_EVT_PROC_STOP
					? s->raw.create_time : 0);
#else
	/*
	 * THE PROCESS COLLECTOR IS THE ONE THAT KNOWS, and it was never asked.
	 *
	 * This returned "" unconditionally, from when Linux had a single
	 * collector and that collector watched files - a file session has no
	 * idea what a pid is called. Every live line therefore printed "?" in
	 * the name column, including the lines that carried a perfectly good
	 * image two columns further along.
	 *
	 * The name comes out of the process collector's own table, which was
	 * filled from the stream: fanotify's exec-open where there was one,
	 * /proc only as the fallback.
	 */
	if (s->pev_api && s->pev_api->name_of) {
		const char *n = s->pev_api->name_of(s->pev_api->self,
						    pid, 0);

		if (n && *n)
			return kof_path_leaf(n);
	}
	return "";
#endif
}

static void sensor_health(struct sensor *s, struct kof_evt_health *nh)
{
#ifdef _WIN32
	kofw_mon_health_neutral(s->mon, nh);
#else
	s->api->health(s->api->self, nh);
	/*
	 * BOTH SESSIONS' LOSSES IN ONE NUMBER. They are two streams into one
	 * consumer, and a consumer deciding whether to trust a quiet run
	 * cares that something was dropped, not which socket dropped it.
	 */
	if (s->pev_api && s->pev_api->health) {
		struct kof_evt_health ph;

		memset(&ph, 0, sizeof ph);
		s->pev_api->health(s->pev_api->self, &ph);
		nh->produced += ph.produced;
		nh->dropped  += ph.dropped;
	}
#endif
}

/* The half only one collector has: the unbacked count on Windows, the mode and
 * the watched set on Linux. Beside the neutral half, because a reader deciding
 * whether to trust a quiet run needs both. */
static void sensor_extra(struct sensor *s, FILE *out)
{
#ifdef _WIN32
	struct kofw_health h;

	kofw_mon_health(s->mon, &h);
	kofw_health_print_extra(out, &h);
#else
	s->api->print_extra(s->api->self, out);
	if (s->pev_api && s->pev_api->print_extra)
		s->pev_api->print_extra(s->pev_api->self, out);
#endif
}

/*
 * WHAT WAS ASKED FOR AND WHAT WAS GRANTED. A provider that refused is the
 * reason a run looks quiet, and a wrong provider is SILENT rather than an
 * error - so it is worth saying even in a silent tool. Linux has one session
 * that either opened or did not, and sensor_open has already failed if it did
 * not, so nothing is reported there.
 */
static void sensor_report_refused(struct sensor *s, FILE *out)
{
#ifdef _WIN32
	struct kofw_health h;
	uint32_t missing, b;

	kofw_mon_health(s->mon, &h);
	missing = h.sub_asked & ~h.sub_enabled;
	if (!missing)
		return;
	fputs("kofwatchtower: REFUSED by the provider:", out);
	for (b = 1u; b; b <<= 1)
		if (missing & b)
			fprintf(out, " %s", kofw_sub_name(b));
	fputs("\n  a wrong provider is silent, not an error - "
	      "check with `logman query providers <name>`\n", out);
#else
	/*
	 * THE FILE HALF EITHER OPENED OR SENSOR_OPEN ALREADY FAILED, so there
	 * is nothing to say about it. The process half is optional and its
	 * absence is exactly the kind of thing that makes a run look quiet -
	 * a host with CAP_SYS_ADMIN and no CAP_NET_ADMIN watches every write
	 * and sees nothing execute - so it is named.
	 */
	if (!s->pev)
		fprintf(out, "kofwatchtower: no process events (%s) - "
			"files only; the connector needs CAP_NET_ADMIN\n",
			kofa_err_name(s->pev_err));
#endif
}

static void sensor_close(struct sensor *s)
{
#ifdef _WIN32
	kofw_mon_close(s->mon);
#else
	kof_mon_close(s->api);
	if (s->pev_api)
		kof_mon_close(s->pev_api);
#endif
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
	      "  --channel-private  keep the channel to this account only.\n"
	      "                   By default a sensor started from a terminal\n"
	      "                   also lets THAT terminal's owner subscribe,\n"
	      "                   because `sudo kofwatchtower` and then\n"
	      "                   `kofwatchman` as yourself is how this is run.\n"
	      "                   A sensor with no terminal - a service - is\n"
	      "                   private already and this changes nothing.\n"
	      "  --channel-group G  let members of unix group G subscribe.\n"
	      "                   A channel is private to the account that\n"
	      "                   published it, so a root sensor and a CLI run\n"
	      "                   as somebody else cannot meet without this.\n"
	      "                   It is not free: G can READ every path this\n"
	      "                   sensor reports, and can WRITE the cursor and\n"
	      "                   so make the sensor believe records were\n"
	      "                   consumed. It cannot forge one.\n"
	      "\n"
	      "THERE ARE NO PROVIDER FLAGS, and that is deliberate. What a\n"
	      "sensor collects is a property of the product, not of a command\n"
	      "line: if the set is wrong it is wrong on every machine, and a\n"
	      "flag only means somebody sets it without knowing what it costs.\n"
	      "On Windows see KOFW_SUB_SENSOR for the set and the two\n"
	      "subscriptions left out of it; on Linux it is one fanotify\n"
	      "session, which needs root for a filesystem-wide mark.\n"
	      "left out of it. Choosing providers is what kofmontrace is for.\n"
	      "\n"
	      "Requires an elevated prompt: a real-time ETW session cannot be\n"
	      "started without one.\n", stderr);
}

int main(int argc, char **argv)
{
	struct sensor         sen;
	struct kof_evt_health nh;
	struct kof_evt        ke;
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
	/*
	 * WHO MAY SUBSCRIBE, or NULL for "only this account".
	 *
	 * A sensor normally runs as root and a consumer normally does not, and
	 * the channel is created private to whoever published it - so the
	 * ordinary deployment is refused by a channel that is working. This is
	 * the operator saying which group may read it, which is the moment
	 * they decide who gets to see every path on the machine. See
	 * kof_chan_publish_grant for the second cost, which is the cursor.
	 */
	const char *chan_group = NULL;
	/* Keep the channel to this account even when the default would widen
	 * it. For an operator who knows the consumer runs as the same user. */
	int chan_private = 0;
	uint32_t ring;
	int      i;

	kof_utf8_init(&argc, &argv);

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
	ring = 16384u;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--stats-every") && i + 1 < argc)
			stats_every = atof(argv[++i]);
		else if (!strcmp(argv[i], "--ring") && i + 1 < argc)
			ring = (uint32_t)strtoul(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--channel") && i + 1 < argc)
			chan_name = argv[++i];
		else if (!strcmp(argv[i], "--channel-group") && i + 1 < argc)
			chan_group = argv[++i];
		else if (!strcmp(argv[i], "--channel-private"))
			chan_private = 1;
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

	stop_on_signal();

	if (!sensor_open(&sen, ring))
		return 1;

	/*
	 * ONE LINE, AND ONLY WHAT A READER CANNOT INFER. What it collects is
	 * fixed and in --help; what it was refused is not.
	 */
	sensor_report_refused(&sen, stderr);

	/*
	 * THE CHANNEL, opened before the first event can arrive.
	 *
	 * Failing to open it is fatal rather than degraded: a sensor with
	 * nowhere to hand records is collecting for nothing, and a service
	 * that ran anyway would look healthy while doing no work at all. The
	 * usual cause is a second sensor already publishing - which is refused
	 * on purpose, two publishers on one ring interleave into it.
	 */
	chan = kof_chan_publish_open(chan_name, ring);
	if (!chan) {
		fputs("kofwatchtower: cannot publish a channel - another "
		      "sensor may already be running\n", stderr);
		sensor_close(&sen);
		return 1;
	}

	/*
	 * FATAL WHEN IT WAS ASKED FOR AND DID NOT HAPPEN.
	 *
	 * The whole reason to pass it is that a subscriber cannot otherwise
	 * attach; carrying on would produce a sensor that collects correctly
	 * and hands nothing to anybody, which is the failure this flag exists
	 * to prevent and is invisible from the outside.
	 */
	if (chan_group) {
		/*
		 * ASKED FOR EXPLICITLY, SO A FAILURE IS FATAL. The whole
		 * reason to pass it is that a subscriber cannot otherwise
		 * attach; carrying on would produce a sensor that collects
		 * correctly and hands nothing to anybody, which is the failure
		 * this flag exists to prevent and is invisible from outside.
		 */
		if (kof_chan_publish_grant(chan, chan_group) != 0) {
			fprintf(stderr, "kofwatchtower: cannot grant '%s' "
				"access to the channel: %s\n",
				chan_group, strerror(errno));
			kof_chan_publish_close(chan);
			sensor_close(&sen);
			return 1;
		}
		fprintf(stderr, "kofwatchtower: group '%s' may subscribe\n",
			chan_group);
	} else if (!chan_private) {
		/*
		 * NOBODY NAMED ONE, so widen to whoever is at the terminal -
		 * see kof_chan_publish_grant_console for why that is the
		 * controlling terminal and not descriptor 0, and why it is not
		 * SUDO_UID.
		 *
		 * NOT FATAL HERE, because nothing was asked for. No terminal
		 * means a service, and a service's channel staying private is
		 * the right answer rather than a problem to report.
		 *
		 * ANNOUNCED EITHER WAY. Whether this channel can be read by a
		 * second account is a fact about the machine, and a sensor
		 * that widened access silently would be the wrong kind of
		 * convenient.
		 */
		char who[64];

		if (kof_chan_publish_grant_console(chan, who, sizeof who) == 0) {
			fprintf(stderr, "kofwatchtower: the channel belongs to "
				"'%s' - that account may subscribe\n"
				"  (whoever logged in; --channel-private to "
				"refuse, --channel-group for a team)\n", who);
		} else if (errno != ENOSYS) {
			/*
			 * SAY SO NOW, SAY WHICH REASON, AND SAY WHAT TO TYPE.
			 *
			 * The three causes were one message, and that was not
			 * enough to act on: "no terminal" is a service and is
			 * correct, "the terminal belongs to root" is a root
			 * shell rather than sudo from a user's one, and a
			 * refused chown is neither. They need different
			 * responses and only one of them is a fault.
			 *
			 * Said HERE and not left for the other side: the
			 * problem would otherwise be found minutes later as
			 * kofwatchman refusing to attach, by which point the
			 * sensor has to be restarted anyway.
			 */
			const char *because =
				errno == ENOTTY
				? "nothing identifies a login session, so "
				  "there is nobody to grant it to"
				: errno == EPERM
				? "the login session is root's own"
				: "the channel's ownership could not be "
				  "changed on this filesystem";

			fprintf(stderr, "kofwatchtower: the channel is private "
				"to this account: %s.\n", because);
			fputs("  Only a process running as the same user can "
			      "subscribe. To let another:\n"
			      "      kofwatchtower --channel-group <group>\n",
			      stderr);
		}
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

		if (!sensor_next(&sen, &ke, 200)) {
			/* Nothing arrived; the clock still has to advance so
			 * --stats-every fires and --seconds still expires. */
			secs = kof_evt_secs_since(t_wall0, kof_evt_now());
			goto tick;
		}

		if (t_ev0 == 0)
			t_ev0 = ke.stamp;
		ev_secs = kof_evt_secs_since(t_ev0, ke.stamp);
		secs    = kof_evt_secs_since(t_wall0, kof_evt_now());

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
				       sensor_name_of(&sen, ke.pid),
				       stdout, &tally);
		else
			kof_evt_count(&ke, &tally);

tick:
		if (stats_every > 0.0 && secs >= next_stats) {
			sensor_health(&sen, &nh);
			kof_evt_health_print(stderr, &nh, secs);
			sensor_extra(&sen, stderr);
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
		sensor_health(&sen, &nh);
		kof_evt_print_tally(&tally, secs, "the whole machine", stderr);
		kof_evt_health_print(stderr, &nh, secs);
		sensor_extra(&sen, stderr);
	}


	fflush(stdout);




	kof_evt_print_tally(&tally, secs, "whole machine", stderr);
	sensor_health(&sen, &nh);
	kof_evt_health_print(stderr, &nh, secs);
	/* And the half only this collector has - see sensor_extra
	 * for why the unbacked count and the reasons it may be unanswerable
	 * belong on the same screen. */
	sensor_extra(&sen, stderr);

	sensor_close(&sen);
	return 0;
}
