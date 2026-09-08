/*
 * kofwatchman - the half that decides.
 *
 * kofwatchtower is a SENSOR: it collects, normalises and hands over, and it
 * does nothing with what it sees. This is the other half - it takes those
 * records, loads a signature database, and says which of them was worth
 * reporting.
 *
 * The split is for STABILITY rather than for privilege. Matching means running
 * compiled modules out of a database file and, for anything that names a file,
 * reading and scanning that file - work whose cost is bounded by nothing in
 * particular. Doing it inside the collector means a slow scan stops the drain,
 * a full ring, and dropped events; and the events dropped are not the ones
 * being scanned, they are everybody else's. Behind a boundary, the same slow
 * scan costs a queue and not a stream.
 *
 *
 * WHAT IT CONNECTS TO TODAY, AND WHAT IT WILL
 *
 * A recorded log. The shared-memory channel is designed and not built, so this
 * reads what kofmontrace and kofwatchtower write with --log, live or finished.
 *
 * That is not a stopgap so much as the same interface arriving early: the
 * channel will carry the same struct kof_evt, in the same order, with the same
 * header saying which record and which platform. Everything below the read
 * loop is what it will be. When the channel lands, only where records come
 * from changes - which is exactly the property the fixed-record format was
 * chosen for.
 *
 *
 * WHAT IT DOES NOT DO YET, SAID PLAINLY
 *
 * There is no event-rule database. bases/evts is designed - facts, windows,
 * M-of-N - and not implemented, so nothing here evaluates a SEQUENCE of
 * events. What it does instead is the part that already works: an event that
 * names a file gets that file scanned by the engine, which is the same engine,
 * the same database and the same finding a scan on the command line produces.
 *
 * That is a real answer to "is this process running something known", and it
 * is not an answer to "did this process behave like a dropper". The second one
 * needs the fact layer, and this file is where it will be consumed.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kofeng.h"
#include "kofevt.h"
#include "kofevtfmt.h"
#include "kofevtlog.h"

/*
 * THE LIVE CHANNEL IS PLATFORM SPECIFIC; THIS PROGRAM IS NOT.
 *
 * Attaching to a sensor means a shared-memory transport, and that is a
 * different object on every operating system. Reading a RECORDING is not - it
 * is a file of normalised records - so this tool builds and runs everywhere
 * the engine does, and analyses a Windows recording on the CI.
 *
 * So the channel is compiled in where there is one, and where there is not the
 * recording path is the whole program. That is not a limitation to work
 * around: on a host with no sensor there is nothing live to attach to.
 */
#ifdef _WIN32
#include "wchan.h"
#endif

static void usage(void)
{
	kof_evt_banner(stderr, "kofwatchman", (uint32_t)KOFENG_BUILD,
		       "verdicts over a recorded event log");
	fputs("\nusage: kofwatchman [options]\n"
	      "\n"
	      "  --channel NAME attach to this channel instead of the default\n"
	      "  --log FILE    read a RECORDED log instead of attaching to a\n"
	      "                running sensor. Optional: with no --log this\n"
	      "                attaches to kofwatchtower, which is what a\n"
	      "                real-time run does. A log is for analysing after\n"
	      "                the fact, and for the CI, which has no sensor.\n"
	      "  --record FILE persist what was received to a log. THIS is\n"
	      "                where a log gets written: the sensor collects and\n"
	      "                hands over, and what is worth keeping is a\n"
	      "                decision - so it belongs to the half that is\n"
	      "                deciding. Works with --log too, which is how a\n"
	      "                recording gets filtered down to a smaller one.\n"
	      "  --db DIR      the signature database (default build/release/databases)\n"
	      "  --all         print every event, not only the ones that matched\n"
	      "  --no-scan     do not scan files, only read and count\n"
	      "\n"
	      "The two sources hand over the SAME struct kof_evt in the same\n"
	      "order, which is what the record format was normalised for: a log\n"
	      "recorded on Windows is analysed here by this same binary.\n",
	      stderr);
}

/*
 * WHAT A MATCH IS REPORTED AS, and who it is reported against.
 *
 * The finding comes from the engine and names the FILE. What makes it useful
 * here is the event: which process touched that file, and which one caused it
 * to. A verdict that says only "this file is Mirai" is a scan result; one that
 * says "pid 4242 (bash) wrote a file that is Mirai" is the thing a real-time
 * product exists to produce, and the difference is entirely the event.
 */
struct hit_ctx {
	const struct kof_evt *e;
	uint64_t              n;
};

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct hit_ctx *c = user;
	uint32_t i;

	(void)bytes;
	(void)len;
	if (!res || !c)
		return 0;

	for (i = 0; i < res->n; i++) {
		if (res->v[i].level != KOF_LEVEL_INFECT &&
		    res->v[i].level != KOF_LEVEL_SUSPECT)
			continue;
		c->n++;
		printf("MALICIOUS  %s\n", res->v[i].name);
		printf("           %-9s pid=%lu  actor=%lu\n",
		       kof_evt_verb_name(c->e->verb),
		       (unsigned long)c->e->pid,
		       (unsigned long)c->e->actor_pid);
		printf("           %s\n", name ? name : "?");
		if (*kof_evt_cmdline(c->e))
			printf("           cmdline: %s\n",
			       kof_evt_cmdline(c->e));
	}

	/*
	 * The object's own children were scanned too, so `broken` matters: an
	 * exhausted budget is "do not know", not "clean", and saying nothing
	 * about it is how a decompression bomb becomes a way of not being
	 * scanned.
	 */
	if (res->broken)
		printf("NOT FULLY EXAMINED  %s  (reason %u)\n",
		       name ? name : "?", (unsigned)res->broken);
	return 0;
}

struct seen {
	char     path[512];
	uint64_t at;
};

/*
 * WHAT HAS ALREADY BEEN SCANNED, so five hundred writes to one file are one
 * scan.
 *
 * Not an optimisation - a correctness property of the queue. An unbounded
 * stream of events naming the same path would otherwise turn into an unbounded
 * stream of scans, and the thing that falls behind is the reader, which is the
 * failure this whole split exists to prevent.
 *
 * Fixed and recycled whole: forgetting costs one duplicate scan, and an LRU
 * would cost a policy to get wrong.
 */
#define SEEN_MAX 4096u

static struct seen g_seen[SEEN_MAX];
static uint32_t    g_n_seen;

static int already_scanned(const char *path)
{
	uint32_t i;

	if (!path || !*path)
		return 1;
	for (i = 0; i < g_n_seen; i++) {
		if (!strcmp(g_seen[i].path, path))
			return 1;
	}
	if (g_n_seen >= SEEN_MAX)
		g_n_seen = 0;              /* recycled whole - see above */
	snprintf(g_seen[g_n_seen].path, sizeof g_seen[0].path, "%s", path);
	g_n_seen++;
	return 0;
}

/*
 * A path from an event is not a path a scanner can open.
 *
 * ETW delivers device paths - \Device\HarddiskVolume3\Windows\... - and a
 * registry key or a named pipe is not a file at all. Rather than guess a
 * mapping, only paths that look openable are offered, and the rest are counted
 * as skipped so the difference between "scanned and clean" and "never scanned"
 * stays visible.
 */
static int looks_openable(const char *p)
{
	if (!p || !*p)
		return 0;
	if (!strncmp(p, "\\Device\\", 8) || !strncmp(p, "\\REGISTRY\\", 10))
		return 0;
	/* A drive letter, or an absolute unix path. */
	return (p[1] == ':' && (p[2] == '\\' || p[2] == '/')) || p[0] == '/';
}

/*
 * WHERE RECORDS COME FROM, and why it is an abstraction with one member.
 *
 * A live sensor and a recorded log are the same stream: the same struct
 * kof_evt, in the same order, with the same header saying which record and
 * which platform. Everything after next() is identical, so the difference is
 * one function pointer and not two programs.
 *
 * Written now, with only one of the two implemented, because the alternative
 * is a main() shaped around reading a file that has to be turned inside out
 * the day the channel lands - and that is the version where the two paths
 * quietly stop behaving the same.
 */
struct wm_source {
	struct kofevt_log_r  *log;    /* a recording, or NULL */
#ifdef _WIN32
	struct kofw_chan_sub *chan;   /* the live sensor, or NULL */
#else
	void                 *chan;   /* always NULL off Windows */
#endif
};

static int source_next(struct wm_source *s, struct kof_evt *out)
{
#ifdef _WIN32
	if (s->chan)
		return kofw_chan_next(s->chan, out, 200u);
#endif
	if (s->log)
		return kofevt_log_read(s->log, out);
	return 0;
}

static void source_close(struct wm_source *s)
{
#ifdef _WIN32
	if (s->chan)
		kofw_chan_sub_close(s->chan);
#endif
	if (s->log)
		kofevt_log_free(s->log);
	s->chan = NULL;
	s->log  = NULL;
}

int main(int argc, char **argv)
{
	const char *log_path = NULL, *rec_path = NULL;
	struct kofevt_log_w *rec = NULL;
	const char *db_path  = "build/release/databases";
	int         show_all = 0, do_scan = 1, i;

	struct kofevt_log_r *lr;
	struct wm_source src;
	const struct kofevt_log_hdr *h = NULL;
	const char *chan_name = NULL;
	const char *why = "";
	kof_engine  *eng = NULL;
	kof_scanner *sc  = NULL;
	struct kof_evt e;
	struct kof_evt_tally tally;
	uint64_t n = 0, scanned = 0, skipped = 0;
	uint64_t t0 = 0;
	int      have_t0 = 0;
	struct hit_ctx hits;

	memset(&tally, 0, sizeof tally);
	memset(&hits, 0, sizeof hits);
	memset(&src, 0, sizeof src);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--log") && i + 1 < argc)
			log_path = argv[++i];
		else if (!strcmp(argv[i], "--channel") && i + 1 < argc)
			chan_name = argv[++i];
		else if (!strcmp(argv[i], "--record") && i + 1 < argc)
			rec_path = argv[++i];
		else if (!strcmp(argv[i], "--db") && i + 1 < argc)
			db_path = argv[++i];
		else if (!strcmp(argv[i], "--all"))
			show_all = 1;
		else if (!strcmp(argv[i], "--no-scan"))
			do_scan = 0;
		else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage();
			return 0;
		} else {
			fprintf(stderr, "kofwatchman: unknown option '%s'\n\n",
				argv[i]);
			usage();
			return 2;
		}
	}
	/*
	 * NO --log MEANS THE LIVE SENSOR, which is the ordinary way to run
	 * this and is the one not built yet.
	 *
	 * It reports that rather than falling back to something else: a
	 * real-time protection tool that silently analysed a stale file
	 * instead of the running machine would be worse than one that does
	 * nothing, because it would look like it was working.
	 */
	/*
	 * NO --log MEANS THE LIVE SENSOR, which is the ordinary way to run
	 * this: watchman is the client, kofwatchtower is the server.
	 */
	if (!log_path) {
#ifdef _WIN32
		src.chan = kofw_chan_sub_open(chan_name, &why);
#else
		(void)chan_name;
		why = "this build has no live channel - it is a Windows "
		      "transport; pass --log FILE";
#endif
		if (!src.chan) {
			kof_evt_banner(stderr, "kofwatchman",
				       (uint32_t)KOFENG_BUILD,
				       "verdicts over an event stream");
			fprintf(stderr, "\nkofwatchman: %s\n", why);
			fputs("  start kofwatchtower first, or pass --log FILE "
			      "to read a recording.\n", stderr);
			return 1;
		}
	} else {
		lr = kofevt_log_open(log_path, 0, KOFEVT_REC_NONE, &why);
		if (!lr) {
			fprintf(stderr, "kofwatchman: %s: %s\n", log_path, why);
			return 1;
		}
		src.log = lr;
		h = kofevt_log_header(lr);
	}

	/*
	 * WHAT IT IS HOLDING, said before anything is concluded from it.
	 *
	 * Which platform produced the log, which record, which build, and
	 * whether the writer closed cleanly. A verdict computed over a stream
	 * whose provenance nobody stated is a verdict nobody can check.
	 */
	fputs("kofwatchman: connected to real-time protection\n", stderr);
#ifdef _WIN32
	if (src.chan) {
		const struct kofw_chan_hdr *ch = kofw_chan_sub_header(src.chan);

		fprintf(stderr, "  source   live sensor, pid %lu\n",
			(unsigned long)ch->pid);
		fprintf(stderr, "  channel  %u slot(s) of %u bytes\n",
			(unsigned)ch->capacity, (unsigned)ch->rec_size);
	} else
#endif
	{
		fprintf(stderr, "  source   %s (recorded)\n", log_path);
		fprintf(stderr, "  platform %s/%s, sensor build %lu, record "
			"%u bytes\n",
			kof_evt_platform_name((uint8_t)h->platform),
			kof_evt_arch_name((uint8_t)h->arch),
			(unsigned long)h->build, (unsigned)h->rec_size);
		if (h->n_records)
			fprintf(stderr, "  %llu event(s)\n",
				(unsigned long long)h->n_records);
		else
			fputs("  event count unknown - the sensor did not close "
			      "cleanly, so the log is however far it got\n",
			      stderr);
	}

	/*
	 * A NEUTRAL RECORD IS THE ONE THIS CAN DECODE.
	 *
	 * A log of a collector's own transport record has the right size and
	 * the wrong fields, and reading one as the other produces a stream that
	 * is entirely plausible and entirely wrong - the reason rec_kind exists
	 * beside rec_size.
	 */
	if (h && h->rec_kind != KOFEVT_REC_KOF) {
		fputs("kofwatchman: this log holds a collector's own record, "
		      "not the neutral one - nothing here can read it\n",
		      stderr);
		source_close(&src);
		return 1;
	}
	if (h && h->rec_size != sizeof(struct kof_evt)) {
		fputs("kofwatchman: the log's record is not this build's size\n",
		      stderr);
		source_close(&src);
		return 1;
	}

	/*
	 * OPENED FROM WHAT THE SOURCE SAID, not from what this build assumes.
	 *
	 * The recorder copies the source's own provenance - platform, arch,
	 * sensor build, which subscriptions were running - because a recording
	 * made from a Windows stream is still a Windows recording however it
	 * was written, and a reader of the second file must not be told it came
	 * from here.
	 */
	if (rec_path) {
		struct kofevt_log_info li;

		memset(&li, 0, sizeof li);
		li.rec_size    = (uint32_t)sizeof(struct kof_evt);
		li.head_size   = (uint16_t)KOF_EVT_HEAD;
		li.len_off     = (uint16_t)offsetof(struct kof_evt, text_len);
		li.rec_kind    = KOFEVT_REC_KOF;
		/*
		 * From the SOURCE where there is one: a recording made from a
		 * Windows stream is still a Windows recording however it was
		 * written, and a reader of the second file must not be told it
		 * came from here. From a live channel there is no such header
		 * yet, so 0 asks kofevt for this host - which is correct,
		 * because for a live channel this host IS the source.
		 */
		if (h) {
			li.build       = h->build;
			li.platform    = (uint8_t)h->platform;
			li.arch        = (uint8_t)h->arch;
			li.root_pid    = h->root_pid;
			li.sub_asked   = h->sub_asked;
			li.sub_enabled = h->sub_enabled;
			li.started     = h->started;
		} else {
			li.build   = (uint32_t)KOFENG_BUILD;
			li.started = kof_evt_now();
		}
		rec = kofevt_log_create(rec_path, &li);
		if (!rec)
			fprintf(stderr, "kofwatchman: cannot write '%s' - "
				"continuing without recording\n", rec_path);
		else
			fprintf(stderr, "  recording to %s\n", rec_path);
	}

	if (do_scan) {
		eng = kof_engine_open(db_path);
		if (!eng) {
			fprintf(stderr, "kofwatchman: cannot load a database "
				"from %s - continuing without scanning\n",
				db_path);
			do_scan = 0;
		} else {
			sc = kof_scanner_new(eng);
			if (!sc) {
				kof_engine_close(eng);
				eng = NULL;
				do_scan = 0;
			}
		}
	}

	while (source_next(&src, &e)) {
		const char *obj = kof_evt_object(&e);
		double secs;

		n++;
		if (!have_t0) {
			have_t0 = 1;
			t0 = e.stamp;
		}
		secs = kof_evt_secs_since(t0, e.stamp);

		if (rec)
			(void)kofevt_log_write(rec, &e);

		kof_evt_count(&e, &tally);
		if (show_all)
			kof_evt_render(&e, secs, "", stdout, &tally);

		if (!do_scan || !looks_openable(obj)) {
			if (*obj)
				skipped++;
			continue;
		}
		if (already_scanned(obj))
			continue;

		hits.e = &e;
		(void)kof_scan_path(sc, obj, NULL, on_object, &hits);
		scanned++;
	}

	if (do_scan) {
		kof_scanner_free(sc);
		kof_engine_close(eng);
	}

	kof_evt_print_tally(&tally,
			    have_t0 ? kof_evt_secs_since(t0, e.stamp) : 0.0,
			    "the log", stderr);
	fprintf(stderr, "   read %llu event(s), scanned %llu file(s), "
		"skipped %llu unopenable path(s), matched %llu\n",
		(unsigned long long)n, (unsigned long long)scanned,
		(unsigned long long)skipped, (unsigned long long)hits.n);

	if (rec) {
		uint64_t nrec = kofevt_log_close(rec);

		fprintf(stderr, "   recorded %llu event(s) to %s\n",
			(unsigned long long)nrec, rec_path);
	}

	source_close(&src);
	return hits.n ? 1 : 0;
}
