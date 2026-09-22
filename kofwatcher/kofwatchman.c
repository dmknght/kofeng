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

/*
 * Before the first system header, or it does nothing.
 *
 * This file includes kofplatform.h, which calls memmem, lstat and realpath -
 * GNU or POSIX extensions that a bare -std=c11 does not declare. The header
 * deliberately does not define the macro for its includers; the translation
 * unit that needs it says so, which is here.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "kofeng.h"
#include "kofcore/kofplatform.h"
#include <kofmod/kofsig.h>   /* KOF_EVT_AMSI - the target a submission is */
/* The record layout a KOF_EVT_PROC rule is written against, and the one
 * builder that writes it - see scan_proc_event. */
#include <kofmod/proc.h>
#include "kofproc.h"
#include "kofevt.h"
#include "kofevtfmt.h"
#include "koffridge.h"
#include "fidset.h"   /* struct kof_fid, kof_fid_of */
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
 *
 * THE TEST USED TO BE _WIN32 AND IS NOW WHETHER A BACKEND IS LINKED. When the
 * channel lived in the Windows collector those were the same question; since
 * it moved to libkoforbit/kofchan they are not, because chan_posix.c is a real
 * backend on a real host. KOF_HAVE_CHAN is set by the build that links one -
 * which is the difference between "this OS is Windows" and "this build can
 * attach to a sensor", and only the second was ever what these sites meant.
 */
#ifdef KOF_HAVE_CHAN
#include "kofchan.h"
#endif

/*
 * STOPPED BY THE OPERATOR, not by the source running out.
 *
 * A real-time client has no natural end: it attaches and keeps deciding until
 * somebody stops it. Ctrl-C sets this, the loop notices, and the summary and
 * the log get finished properly - which a kill would not do, and the log's
 * record count is written by seeking back at close.
 */
static volatile int g_stop;

static void on_sigint(int sig)
{
	(void)sig;
	g_stop = 1;
}

static void usage(void)
{
	kof_evt_banner(stderr, "kofwatchman", (uint32_t)KOFENG_BUILD,
		       "verdicts over a live event stream");
	fputs("\nusage: kofwatchman [options]\n"
	      "\n"
	      "Attaches to a running kofwatchtower and keeps deciding until it\n"
	      "is stopped. It is the client; the sensor is the server.\n"
	      "\n"
	      "  --replay FILE read a log written earlier instead of attaching\n"
	      "                to a sensor. For analysing after the fact, and\n"
	      "                for the CI, which has no sensor to attach to.\n"
	      "  --channel NAME attach to this channel instead of the default\n"

	      "  --db DIR      the signature database (default build/release/databases)\n"
	      "  --all         print every event, not only the ones that matched\n"
	      "  --no-scan     do not scan files, only read and count\n"
	      "\n"
	      "A live channel and a replay hand over the SAME struct kof_evt in\n"
	      "the same order, which is what the record format was normalised\n"
	      "for: a log written on Windows is replayed here by this same\n"
	      "binary. Ctrl-C to stop - it finishes the log properly.\n",
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
		/*
		 * WHOSE NUMBER IS THE SECOND ONE, and it is not the same
		 * question on every verb.
		 *
		 * kof_evt.actor_pid is who CAUSED the event. On a file event
		 * that is the process the event is about, so printing it
		 * beside the pid put the same number twice under two names;
		 * on a process START it is whoever launched it, which is the
		 * PARENT and is worth a word that says so rather than the
		 * vaguer one the field carries for the platforms where an
		 * actor can be neither.
		 *
		 * So the line names what the number is: the parent of a start,
		 * an actor only where it differs from the subject, and nothing
		 * at all where it would repeat.
		 */
		printf("           %-9s pid=%lu",
		       kof_evt_verb_name(c->e->verb),
		       (unsigned long)c->e->pid);
		if (c->e->verb == KOF_EVT_PROC_START) {
			if (c->e->miss & KOF_F_PPID)
				printf("  parent=?");
			else
				printf("  parent=%lu",
				       (unsigned long)c->e->ppid);
		} else if (c->e->actor_pid &&
			   c->e->actor_pid != c->e->pid) {
			printf("  actor=%lu",
			       (unsigned long)c->e->actor_pid);
		}
		printf("\n");
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

/*
 * Scan a gathered submission, as the file it turned out to be.
 *
 * SCANNED AS AN ORDINARY OBJECT, not as an event. What a submission carries is
 * a PowerShell script or, often enough, an executable - and an executable that
 * arrived down a channel is the same executable it would have been on disk, so
 * it wants the same modules. This is the model a zip entry already uses: the
 * container hands over bytes, and what they ARE is the engine's question.
 *
 * The event is still named in whatever fires, through hit_ctx, so a finding
 * says which submission and which process it came out of rather than pointing
 * at a buffer nobody can locate afterwards.
 */
static void scan_submission(kof_scanner *sc, struct kof_evt_join *j,
			    const struct kof_evt *head, int do_scan,
			    struct hit_ctx *hits, uint64_t *scanned)
{
	struct kof_scan_option opt;
	char name[96];

	if (!do_scan || !sc || !j || j->idle || !j->len)
		return;
	/*
	 * A SHORT GATHER IS STILL SCANNED, and that is deliberate: a chunk was
	 * lost or the buffer filled, but the bytes in hand are real and a
	 * marker inside them is still a marker. What must not happen is
	 * treating it as whole - kof_evt_join_whole is what says so, and a
	 * caller reporting on this should carry that through.
	 */
	snprintf(name, sizeof name, "event//%llu//%s",
		 (unsigned long long)head->seq, kof_evt_verb_name(head->verb));
	hits->e = head;

	/*
	 * ONCE, DECLARED, and the second pass this used to make is gone.
	 *
	 * A submission is not a file format - a script block sniffs as nothing -
	 * so without a declaration every rule written about a submission is
	 * filtered out before it runs. The caller is the only side that knows
	 * what this is, and as_format is how it says.
	 *
	 * It used to scan a second time WITHOUT the declaration, so that a
	 * submission carrying an executable would sniff as that executable and
	 * reach the modules any executable gets. That was a stopgap and it is
	 * no longer needed: the AMSI parse now DECLARES the carried image as an
	 * entry, and the engine's ordinary declared-children walk opens it as a
	 * PE child of this object - which is the same answer a zip member gets,
	 * arrived at by the same road. See declare_carried in amsi_parse.c.
	 *
	 * The second pass was not merely redundant, it was worse than this: it
	 * scanned the whole submission as though the event's metadata were part
	 * of the executable, and it reported the image under the event's own
	 * name rather than as something the event carried.
	 */
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	opt.as_format = KOF_EVT_AMSI;
	(void)kof_scan_bytes(sc, j->buf, (uint64_t)j->len, name, &opt,
			     on_object, hits);
	(*scanned)++;
}

/*
 * Scan a PUSHED process event, as the process it is about.
 *
 * NOT "SCAN PROCESS", WHICH IS A DIFFERENT JOB. kofscanner --scan-procs is an
 * ON-DEMAND sweep: an operator asks, /proc is walked, every process alive at
 * that instant is examined. This is the other half - the sensor pushes what
 * just happened, one record at a time, and nothing was asked. They meet at the
 * RECORD, not at the code path: both produce a kof_proc_rec and a rule is
 * written once against it, which is the whole point of the snapshot and the
 * stream sharing a layout.
 *
 * THE COMMAND LINE IS AN OBJECT, and until this existed it was not one. An
 * event that named a file got that file scanned - which answers "is this
 * process running something known" and answers nothing at all about
 * `bash -c exec bash -i &>/dev/tcp/...`, where the image is /usr/bin/bash and
 * every byte that matters is in the argument. The whole of a living-off-the-
 * land technique sits in the half nothing was looking at.
 *
 * AS A kof_proc_rec AND TARGET KOF_EVT_PROC, which is the record a rule about
 * a process is written against - identity, command line, environment,
 * connections, with the partition kofmod/proc.h describes. A rule written for
 * it runs on a record built from a live start event and on one built from the
 * /proc snapshot, because they are the same record; the collector that filled
 * it is not the rule's business.
 *
 * kof_proc_build_rec is the one writer, shared with both collectors, for the
 * reason kofproc.h gives: the region partition only holds because the arena is
 * written in one order, and a second place writing it is a second opinion
 * about that order.
 *
 * WHAT IS ABSENT STAYS ABSENT. A start event carries who it is and what it was
 * asked to do; it carries no descriptor table, no environment and no
 * connections. Those offsets are left zero, which the parse reads as "not
 * here", and KOF_PROC_F_FDS_READ is NOT set - so proc_revshell, which counts
 * sockets, sees a record that never claims to have counted any rather than one
 * claiming zero. A record that lies about what it looked at is worse than a
 * record with less in it.
 */
static void scan_proc_event(kof_scanner *sc, const struct kof_evt *e, int do_scan,
			 struct hit_ctx *hits, uint64_t *scanned)
{
	uint8_t rec[KOF_PROC_REC_MAX];
	struct kof_proc_build pb;
	struct kof_scan_option opt;
	const struct kof_evt_proc *pr;
	const char *cmd;
	char name[96];
	uint32_t n;

	if (!do_scan || !sc || !e)
		return;
	if (e->verb != KOF_EVT_PROC_START && e->verb != KOF_EVT_PROC_INFO)
		return;
	/*
	 * NOTHING TO SEARCH, NOTHING TO SCAN. The command line is the whole
	 * reason this record is built - see KOF_SCAN_PROC_CLAIMED, where the
	 * head and the descriptors are fields rather than regions - so a start
	 * whose argv was lost to the race would produce a record with no
	 * searchable byte in it. Scanning it would cost a scan per process on
	 * the machine to look through nothing.
	 */
	cmd = kof_evt_cmdline(e);
	if (!cmd || !*cmd)
		return;

	pr = kof_evt_as_proc(e);

	memset(&pb, 0, sizeof pb);
	pb.os         = e->os;
	pb.pid        = e->pid;
	pb.ppid       = (e->miss & KOF_F_PPID) ? 0u : e->ppid;
	pb.start_time = pr ? pr->create_time : 0;
	pb.exe        = kof_evt_image(e);
	pb.cmdline    = cmd;

	n = kof_proc_build_rec(&pb, rec, sizeof rec);
	if (!n)
		return;                 /* refused rather than truncated */

	snprintf(name, sizeof name, "process//%lu//%.40s",
		 (unsigned long)e->pid, kof_path_leaf(pb.exe ? pb.exe : ""));

	hits->e = e;
	memset(&opt, 0, sizeof opt);
	opt.all_matches = 1;
	/* DECLARED, like a submission: a record has no magic and never sniffs
	 * as anything - see the note in amsi_parse.h that scan_submission
	 * points at. */
	opt.as_format = KOF_EVT_PROC;
	(void)kof_scan_bytes(sc, rec, (uint64_t)n, name, &opt, on_object, hits);
	(*scanned)++;
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
 * SHOULD THIS FILE BE SCANNED - the verdict cache, which this tool did not use.
 *
 * WHY THE PATH LIST ABOVE IS NOT ENOUGH, and it is a detection hole rather than
 * a performance note. It remembers a PATH, so a file written once, scanned
 * clean, and then OVERWRITTEN is never looked at again - which is a dropper's
 * whole sequence: put something harmless where it will be scanned, let it pass,
 * replace it. The identity this uses is struct kof_fid - volume, node, size,
 * birth and last-write, all in nanoseconds - so a file that changed is a
 * different key and is scanned again.
 *
 * It is also what makes the realtime half agree with the on-demand half. They
 * were answering the same question with two different mechanisms and only one
 * of them could be right.
 *
 * THE DISCIPLINE IS koffridge.h's, AND IT IS THERE BECAUSE IT WAS GOT WRONG:
 * skip only on a CLEAN hit, and store clean only after a scan that found
 * nothing. The path list is kept in front of it as a cheap first filter - it
 * costs no file handle, and a burst naming one path is the common case - but
 * nothing is skipped on its say-so alone any more.
 */
static int scan_needed(struct koffridge *fr, const char *path,
		       struct kof_fid *id)
{
	if (!fr || !kof_fid_of(path, id)) {
		/*
		 * No identity, so no caching - koffridge.h says a key that
		 * could not be established must not be invented. Scanned every
		 * time, which is the safe direction.
		 *
		 * kof_fid_of ALSO answers zero for a symlink and for anything
		 * that is not a regular file, which lands here and is right:
		 * what a link names is another file with its own identity, and
		 * a link is what an attacker repoints after it was called
		 * clean. This used to follow the link and cache the target,
		 * which is faster and is the window that closes.
		 */
		return 1;
	}
	return !koffridge_skip(fr, id, sizeof *id);
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
#ifdef KOF_HAVE_CHAN
	struct kof_chan_sub *chan;   /* the live sensor, or NULL */
#else
	void                 *chan;   /* always NULL off Windows */
#endif
};

/*
 * 1 with a record, 0 when the SOURCE IS FINISHED - which a live channel never
 * is.
 *
 * That distinction is the whole difference between the two sources and it was
 * wrong: the loop treated "nothing there right now" as "nothing more ever" and
 * exited, so watchman attached to a running sensor, drained whatever happened
 * to be buffered, and quit. A real-time client waits.
 *
 * So an empty channel returns -1: nothing yet, keep going. A replay returns 0
 * at the end of the file, because there a file really does end.
 */
static int source_next(struct wm_source *s, struct kof_evt *out)
{
#ifdef KOF_HAVE_CHAN
	if (s->chan)
		return kof_chan_next(s->chan, out, 200u) ? 1 : -1;
#endif
	if (s->log)
		return kofevt_log_read(s->log, out) ? 1 : 0;
	return 0;
}

static void source_close(struct wm_source *s)
{
#ifdef KOF_HAVE_CHAN
	if (s->chan)
		kof_chan_sub_close(s->chan);
#endif
	if (s->log)
		kofevt_log_free(s->log);
	s->chan = NULL;
	s->log  = NULL;
}

int main(int argc, char **argv)
{
	const char *replay_path = NULL;
	const char *db_path  = "build/release/databases";
	int         show_all = 0, do_scan = 1, i;

	struct kofevt_log_r *lr;
	struct wm_source src;
	const struct kofevt_log_hdr *h = NULL;
	const char *chan_name = NULL;
	/*
	 * PLAIN int AND NOT THE ENUM. kofchan.h is included only by a build
	 * that HAS a channel, so naming kof_chan_why here breaks the build
	 * that has none - which is the configuration this variable exists to
	 * be harmless in.
	 */
	int chan_denied = 0;
	const char *why = "";
	kof_engine  *eng = NULL;
	kof_scanner *sc  = NULL;
	struct kof_evt e;
	struct kof_evt_tally tally;
	uint64_t n = 0, scanned = 0, skipped = 0, cached = 0;
	struct koffridge *fridge = NULL;
	uint64_t t0 = 0;
	int      have_t0 = 0;
	struct hit_ctx hits;

	/* argv and a log path, before either is read - see kof_utf8_init. */
	kof_utf8_init(&argc, &argv);

	memset(&tally, 0, sizeof tally);
	memset(&hits, 0, sizeof hits);
	signal(SIGINT, on_sigint);
	memset(&src, 0, sizeof src);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--replay") && i + 1 < argc)
			replay_path = argv[++i];       /* read */
		else if (!strcmp(argv[i], "--channel") && i + 1 < argc)
			chan_name = argv[++i];
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
	if (!replay_path) {
#ifdef KOF_HAVE_CHAN
		{
			int reason = 0;

			src.chan = kof_chan_sub_open(chan_name, &why, &reason);
			chan_denied = (reason == KOF_CHAN_WHY_DENIED);
		}
#else
		(void)chan_name;
		why = "this build has no live channel - it is a Windows "
		      "transport; pass --replay FILE";
#endif
		if (!src.chan) {
			kof_evt_banner(stderr, "kofwatchman",
				       (uint32_t)KOFENG_BUILD,
				       "verdicts over an event stream");
			fprintf(stderr, "\nkofwatchman: %s\n", why);
			/*
			 * THE ADVICE HAS TO MATCH THE REASON. Told that a
			 * channel exists and is not readable, this used to
			 * answer "start kofwatchtower first" - the one action
			 * that cannot help, because the sensor is already
			 * running. Somebody following it starts a second
			 * sensor, which is refused, and now has two wrong
			 * answers.
			 */
			if (chan_denied)
				fputs("  The sensor is ALREADY RUNNING. A "
				      "channel is private to the account that\n"
				      "  published it, so a root sensor cannot "
				      "be read by an ordinary user\n"
				      "  unless it was told to allow one:\n"
				      "      kofwatchtower --channel-group "
				      "<your group>\n", stderr);
			else
				fputs("  start kofwatchtower first, or pass "
				      "--replay FILE to read a recording.\n",
				      stderr);
			return 1;
		}
	} else {
		lr = kofevt_log_open(replay_path, 0, KOFEVT_REC_NONE, &why);
		if (!lr) {
			fprintf(stderr, "kofwatchman: %s: %s\n", replay_path,
				why);
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
#ifdef KOF_HAVE_CHAN
	if (src.chan) {
		const struct kof_chan_hdr *ch = kof_chan_sub_header(src.chan);

		fprintf(stderr, "  source   live sensor, pid %lu\n",
			(unsigned long)ch->pid);
		fprintf(stderr, "  channel  %u slot(s) of %u bytes\n",
			(unsigned)ch->capacity, (unsigned)ch->rec_size);
	} else
#endif
	{
		fprintf(stderr, "  source   %s (replay)\n", replay_path);
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
	/*
	 * head_size TOO, AND rec_size IS NOT ENOUGH.
	 *
	 * A log written before a field was added to the record has the same
	 * rec_size (the record is fixed at 512) and the same rec_kind, and its
	 * head is two bytes shorter - so the text lands two bytes early and
	 * every path comes back shifted. It reads, it scans, it finds nothing,
	 * and nothing anywhere says why. Found exactly that way: a log from
	 * before content_len existed stopped matching a sample it had matched
	 * an hour earlier.
	 *
	 * kofevtlog cannot check this - it is deliberately record-agnostic and
	 * uses the file's own head_size for I/O. The knowledge that
	 * KOFEVT_REC_KOF means KOF_EVT_HEAD lives here, with the struct.
	 */
	if (h && h->head_size != (uint16_t)KOF_EVT_HEAD) {
		fprintf(stderr, "kofwatchman: this log's record head is %u "
			"bytes and this build's is %u - it was written by a "
			"different version of the record, and every field "
			"after the head would be read at the wrong offset\n",
			(unsigned)h->head_size, (unsigned)KOF_EVT_HEAD);
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
			} else {
				/*
				 * KEYED ON THE DATABASE, which is not optional:
				 * every verdict in the table is only true of
				 * one signature build, so a cache that outlived
				 * one would serve answers the current rules no
				 * longer give.
				 *
				 * IN MEMORY ONLY, AND THAT IS A DECISION. The
				 * on-demand scanner writes its cache to a
				 * per-user file; this one runs as a service, so
				 * WHERE that file lives is a security question
				 * - a table something else can write is a table
				 * that can mark malware clean - and it is not
				 * one to answer as a side effect of a
				 * performance change. So the saving costs are
				 * paid within a run and nothing is written.
				 *
				 * A failure is not fatal: the cache is a
				 * reduction, never a correctness property, and
				 * scan_needed answers "scan it" when there is
				 * no table.
				 */
				/* Keyed on the DATABASE, not on the date
				 * printed on it - see kof_engine_db_stamp. In
				 * memory and never saved, so the stamp only has
				 * to outlive this run; it costs nothing to be
				 * right about it anyway. */
				fridge = koffridge_open(4096u,
							kof_engine_db_stamp(eng));
			}
		}
	}

	/*
	 * THE SUBMISSION BEING GATHERED, if one is.
	 *
	 * A content event whose payload did not fit one record is followed by
	 * continuations - see KOF_EVT_CONT. The VIEWER joins them when it reads
	 * a log, which is presentation; this is the half that decides, and
	 * without the same joining here it never sees more than the first four
	 * hundred bytes of anything. A rule written about a carried executable
	 * could not fire in production however well it matched in the viewer,
	 * which is worse than not having the rule: the tool that shows it and
	 * the tool that acts on it would disagree.
	 *
	 * Held across iterations because a chain arrives over several of them.
	 */
	static uint8_t join_buf[1024u * 1024u];
	struct kof_evt_join join;
	struct kof_evt join_head;
	int joining = 0;

	memset(&join, 0, sizeof join);
	memset(&join_head, 0, sizeof join_head);

	while (!g_stop) {
		int got = source_next(&src, &e);
		const char *obj;
		double secs;

		if (got == 0)
			break;              /* a replay ran out */
		if (got < 0)
			continue;           /* live, nothing yet - keep going */

		obj = kof_evt_object(&e);

		n++;
		if (!have_t0) {
			have_t0 = 1;
			t0 = e.stamp;
		}
		secs = kof_evt_secs_since(t0, e.stamp);


		/*
		 * COUNTED ONCE, AND IT WAS BEING COUNTED TWICE.
		 *
		 * kof_evt_render COUNTS as well as printing - kofevtfmt.h says
		 * so where it declares them - so calling both added every
		 * event to the tally twice whenever --all was given. The
		 * symptom was a summary that disagreed with its own trace: a
		 * replay of nslookup.kevt printed one ProcStart and reported
		 * "processes started : 2", and reported 48 untyped events over
		 * 26 records.
		 *
		 * Which is the bug kofevtfmt.h was split out to fix, arriving
		 * from the other side. There it was a tally counted inside a
		 * print switch, so --quiet and loud disagreed; here it is a
		 * caller counting first and then asking a renderer that counts
		 * too. The lesson is the same one, so the note is here as well:
		 * kof_evt_render is not a printer, it is a printer AND a
		 * counter, and a caller that wants only the count asks for
		 * kof_evt_count INSTEAD.
		 */
		if (show_all)
			kof_evt_render(&e, secs, "", stdout, &tally);
		else
			kof_evt_count(&e, &tally);

		/*
		 * GATHER, AND SCAN WHEN THE CHAIN ENDS.
		 *
		 * A continuation extends whatever is open. Anything else ends
		 * it - the collector emits a chain immediately behind its
		 * parent, so the next ordinary record IS the end of it - and
		 * the assembled bytes go to the scanner before this record is
		 * looked at itself.
		 */
		if (e.verb == KOF_EVT_CONT) {
			if (joining)
				(void)kof_evt_join_add(&join, &e);
			continue;   /* not an event: nothing else applies */
		}
		if (joining) {
			scan_submission(sc, &join, &join_head, do_scan,
					&hits, &scanned);
			joining = 0;
		}
		if (do_scan && kof_evt_join_start(&join, &e, join_buf,
						  sizeof join_buf)) {
			join_head = e;
			joining = 1;
			/*
			 * Left open rather than scanned here: the chunks that
			 * finish it have not arrived. A submission that fits
			 * one record is closed by the next event, which is the
			 * same path and one iteration later.
			 */
			continue;
		}

		/*
		 * BOTH HALVES OF A START, because they are two different
		 * questions: what it is running, and what it was told to do.
		 * The file half below answers the first from the image path;
		 * this answers the second, and neither substitutes for it.
		 */
		scan_proc_event(sc, &e, do_scan, &hits, &scanned);

		if (!do_scan || !looks_openable(obj)) {
			if (*obj)
				skipped++;
			continue;
		}
		if (already_scanned(obj))
			continue;

		{
			struct kof_fid id;
			uint64_t before;

			if (!scan_needed(fridge, obj, &id)) {
				cached++;
				continue;
			}

			hits.e = &e;
			before = hits.n;
			(void)kof_scan_path(sc, obj, NULL, on_object, &hits);
			scanned++;

			/*
			 * ONLY A CLEAN SCAN IS REMEMBERED AS CLEAN. The engine
			 * reports through the callback and returns nothing, so
			 * the hit counter is what makes this knowable - see the
			 * note on koffridge_get for what storing the wrong
			 * answer here costs.
			 */
			if (fridge && hits.n == before)
				(void)koffridge_put(fridge, &id, sizeof id,
						    NULL);
		}
	}

	/* A run that ended mid-chain still has bytes worth looking at, and they
	 * are as complete as they are ever going to be. */
	if (joining)
		scan_submission(sc, &join, &join_head, do_scan, &hits, &scanned);

	if (do_scan) {
		kof_scanner_free(sc);
		koffridge_close(fridge);
		kof_engine_close(eng);
	}

	kof_evt_print_tally(&tally,
			    have_t0 ? kof_evt_secs_since(t0, e.stamp) : 0.0,
			    "the log", stderr);
	/*
	 * `cached` IS REPORTED, not merely acted on. It is the number of files
	 * this run did NOT open because the verdict cache had already answered
	 * for that exact file - and a reader who cannot see it cannot tell a
	 * quiet interval from a cache that is answering for everything.
	 */
	fprintf(stderr, "   read %llu event(s), scanned %llu file(s), "
		"cached %llu, skipped %llu unopenable path(s), matched %llu\n",
		(unsigned long long)n, (unsigned long long)scanned,
		(unsigned long long)cached,
		(unsigned long long)skipped, (unsigned long long)hits.n);

	source_close(&src);
	return hits.n ? 1 : 0;
}
