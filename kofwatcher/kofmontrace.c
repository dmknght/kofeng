/*
 * kofmontrace - run a program and show only what IT did.
 *
 * Point it at a file, it launches it, and it prints the event trace of that
 * process and everything the process went on to create. Nothing else on the
 * machine appears, which is the entire difference between this and kofwatchtower:
 * kofwatchtower answers "what does this machine do and what does watching it cost",
 * this answers "what did THIS program do".
 *
 * That scoping is what turns a stream into evidence. An unattributed list of
 * every file created on a busy machine is not evidence of anything; the files
 * created by one subtree, in order, with the process that created each, is.
 *
 *
 * WHY IT LAUNCHES THE TARGET INSTEAD OF ATTACHING
 *
 * Because the beginning is the part that matters and the part nothing else can
 * get. A dropper's whole life is measured in milliseconds - by the time
 * anything could notice a new process and attach to it, the file is written,
 * the child is running and the parent is gone. Launching it means the session
 * is already collecting before the first instruction executes.
 *
 * The cost is that this process is then the target's parent, so its own
 * CreateProcess raises the most important event in the run - which is why it
 * asks for kofw_mon_option.trace_self. The filter that protects a long-running
 * service is exactly the one that would hide the thing this exists to show, and
 * what makes turning it off safe here is the subtree filter below: everything
 * outside one bounded tree is discarded, so there is no loop to run away.
 *
 *
 * SAFETY, PLAINLY
 *
 * This RUNS what you give it, with the privileges it was started with. It does
 * not sandbox it and it does not undo anything it did - files it wrote, keys it
 * set and connections it made all outlive the trace. That is what makes the
 * trace real and it is also the whole risk: a machine that runs live samples
 * through this is a machine that has run live samples.
 *
 * What it DOES do is contain the tree's lifetime. Everything launched goes into
 * a job object with KILL_ON_JOB_CLOSE, so the target and every descendant die
 * when this exits - on Ctrl-C, on a deadline, and on this process being killed
 * outright. That is not sandboxing; it is the difference between stopping a
 * trace and stopping the run, which used to be two different things without
 * anything saying so. --leave-running gives the old behaviour to somebody who
 * means it.
 */

/*
 * _GNU_SOURCE, not _POSIX_C_SOURCE, and only on the POSIX side. kofplatform.h
 * uses memmem, and the collector needs the fanotify declarations - both are
 * GNU extensions, and asking for strict POSIX here hides them and leaves
 * implicit declarations that link to the wrong prototype.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ONE TRACER, TWO PLATFORMS, AND ONE PLACE THAT KNOWS WHICH.
 *
 * Everything below the adapter is the same code on both: the same options,
 * the same drain loop, the same report. What differs is the collector and how
 * a subject is started, scoped and contained - and it differs HERE rather
 * than at the forty-odd call sites it used to.
 */
#ifdef _WIN32
#include <windows.h>

#include "kofgrille.h"
#else
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include "kofantarc.h"
#include "afan.h"
#endif

/*
 * THE COLLECTOR'S OWN VERSION, recorded in a log header so a reader can tell
 * which producer wrote it. Two collectors, two numbers, one name here.
 */
#ifdef _WIN32
#define TRACER_MAJOR KOFW_MAJOR
#define TRACER_MINOR KOFW_MINOR
#else
#define TRACER_MAJOR KOFA_MAJOR
#define TRACER_MINOR KOFA_MINOR
#endif

/*
 * WHAT WAS ASKED FOR, in one vocabulary, because the FLAGS ARE THE SAME ON
 * BOTH PLATFORMS and a flag that exists on one host only is a flag somebody
 * has to remember the host for. On Windows each of these is a distinct ETW
 * subscription. On Linux fanotify answers the file ones and nothing answers
 * the rest - the banner still prints what was asked, and the health line at
 * the end is where a run learns that it got less than it asked for.
 */
#ifdef _WIN32
#define TRACER_SUB_PROCESS    KOFW_SUB_PROCESS
#define TRACER_SUB_IMAGE      KOFW_SUB_IMAGE
#define TRACER_SUB_FILE       KOFW_SUB_FILE
#define TRACER_SUB_FILE_WRITE KOFW_SUB_FILE_WRITE
#define TRACER_SUB_FILE_OPEN  KOFW_SUB_FILE_OPEN
#define TRACER_SUB_NET        KOFW_SUB_NET
#define TRACER_SUB_REGISTRY   KOFW_SUB_REGISTRY
#define TRACER_SUB_AMSI       KOFW_SUB_AMSI
#define TRACER_SUB_DNS        KOFW_SUB_DNS
#define TRACER_SUB_THREAD     KOFW_SUB_THREAD
#else
#define TRACER_SUB_PROCESS    (1u << 0)
#define TRACER_SUB_IMAGE      (1u << 1)
#define TRACER_SUB_FILE       (1u << 2)
#define TRACER_SUB_FILE_WRITE (1u << 3)
#define TRACER_SUB_FILE_OPEN  (1u << 4)
#define TRACER_SUB_NET        (1u << 5)
#define TRACER_SUB_REGISTRY   (1u << 6)
#define TRACER_SUB_AMSI       (1u << 7)
#define TRACER_SUB_DNS        (1u << 8)
#define TRACER_SUB_THREAD     (1u << 9)
#endif
#include "kofevt.h"
#include "kofevtfmt.h"
#include "kofevtlog.h"

/*
 * AND THE ENGINE, WHICH THIS TOOL DID NOT USED TO LINK.
 *
 * It links it for the report: a trace says which files the program created and
 * which strings it used, and only the bytes say what those files ARE and
 * whether those strings are in the sample at all. Hashing an artefact, naming
 * the packer that produced it and checking a candidate string against the
 * subject's bytes are all engine work, and doing them anywhere else would mean
 * a second opinion on questions the engine already answers.
 *
 * The cost is in the Makefile and is written down there: this stopped
 * cross-building, because $(LIB) is built for the host. kofwatchtower stays in
 * the cross block and keeps libkofgrille type-checked on a machine with no ETW.
 */
#include "kofeng.h"
#include "kofreport.h"

/* ---------------------------------------------- answering the report's question
 *
 * WHY THIS LIVES HERE AND NOT IN libkoforbit.
 *
 * It used to sit in kofrepart.c, which made a library in orbit the place that
 * decided a host's scan policy: which options, which ceiling, whether the
 * interpreter runs. koffridge.h states the rule for the whole of orbit - it
 * may know the engine's TYPES, never drive it - and holding a kof_scanner and
 * calling kof_scan_path is driving it.
 *
 * So orbit now declares struct kof_rep_engine and this supplies one. The four
 * lines that build the options are the same four lines; what changed is that
 * they are the host's, which is the side that owns the scanner and knows what
 * a scan of a collected artefact is allowed to cost here.
 */

struct scan_sink {
	struct kof_fp_verdict *v;
	uint32_t               depth0_seen;
	uint32_t               f_version;
};

static void on_note(uint32_t fact, const char *what, uint64_t value, void *user)
{
	struct scan_sink *s = (struct scan_sink *)user;

	if (!s || !s->v || !what)
		return;

	/*
	 * THE FIRST NOTE FROM A MODULE WHOSE NAME IS ITS PACKER'S.
	 *
	 * `what` is authored text - "UPX.ELF.version", "Rar.entries" - and the
	 * part before the first dot is the module. Taken whole up to the last
	 * dot, so "UPX.ELF" survives and the field name does not: which packer
	 * AND which of its variants is the useful half, and a report saying
	 * "UPX" where the module said "UPX.ELF" would be throwing away the one
	 * thing that distinguishes two unpackers.
	 *
	 * First wins. A scan of a nested object emits notes from every layer,
	 * and the outermost is the one the artefact IS.
	 */
	if (!s->v->packer[0]) {
		const char *dot = strrchr(what, '.');
		size_t      n   = dot ? (size_t)(dot - what) : strlen(what);

		if (n >= sizeof s->v->packer)
			n = sizeof s->v->packer - 1u;
		memcpy(s->v->packer, what, n);
		s->v->packer[n] = '\0';
	}

	if (!s->f_version)
		s->f_version = kof_fact_id("version");
	if (fact == s->f_version && !s->v->packer_version)
		s->v->packer_version = value;
}

static int on_object(const char *name, const void *bytes, uint64_t len,
		     const struct kof_result *res, void *user)
{
	struct scan_sink *s = (struct scan_sink *)user;

	(void)name;
	if (!s || !s->v || !res)
		return 0;

	/*
	 * THE FIRST OBJECT IS THE ONE THE REPORT IS ABOUT; the rest are what
	 * came out of it.
	 *
	 * A file scan reports the file and then every child the engine
	 * produced, in that order, so the first callback is the artefact itself
	 * and each later one is evidence that something was inside it. Counting
	 * children rather than describing them is deliberate: a report about a
	 * dropped file needs to say "packed, one payload came out"; describing
	 * the payload is a scan of the payload, which is a thing somebody asks
	 * for separately.
	 */
	if (!s->depth0_seen++) {
		s->v->asked    = 1;
		s->v->examined = res->examined;
		s->v->broken   = res->broken;
		s->v->depth    = res->heur_depth;
		s->v->packed   = (res->heur_depth || res->from_packer) ? 1u : 0u;
		if (bytes && len)
			s->v->entropy8 = kof_entropy_eighths(bytes, len);
		if (res->n)
			snprintf(s->v->finding, sizeof s->v->finding, "%s",
				 res->v[0].name);
	} else {
		s->v->children++;
		/* A CHILD IS WHAT PROVES THE PARENT WAS PACKED, and the parent's
		 * own record may not say so: from_packer is set on the object
		 * an unpacker PRODUCED, not on the one it read. */
		if (res->from_packer)
			s->v->packed = 1;
		/*
		 * A FINDING ON A CHILD IS THE FINDING, when the parent had
		 * none. That is the normal shape of a packed sample: the stub
		 * matches nothing and the payload matches a family, and a
		 * report that showed only the parent's verdict would say
		 * "nothing known" about a recognised trojan.
		 */
		if (!s->v->finding[0] && res->n)
			snprintf(s->v->finding, sizeof s->v->finding, "%s",
				 res->v[0].name);
	}
	return 0;
}

/*
 * DESCEND, AND DO NOT INTERPRET.
 *
 * A report wants to know what came out of a collected file, so the static
 * unpackers and the container walk are on. Emulation is not: kofeng.h measures
 * a UPX-with-LZMA sample at forty million instructions and the worst in its
 * corpus at two hundred and fifty, and a report over a dozen collected files
 * would inherit all of it. A caller who wants that scans the collected file,
 * which is what the files are collected FOR.
 *
 * The note callback is installed and then PUT BACK, because a host that had
 * one of its own must not lose it to this.
 */
static int rep_ask(void *user, const char *path, struct kof_fp_verdict *v)
{
	kof_scanner            *sc = (kof_scanner *)user;
	struct kof_scan_option  opt;
	struct scan_sink        sink;

	if (!sc || !path || !*path || !v)
		return -1;

	memset(&sink, 0, sizeof sink);
	sink.v = v;

	memset(&opt, 0, sizeof opt);
	opt.emu_use = KOF_EMU_NEVER;

	kof_scanner_on_debug(sc, on_note, &sink);
	(void)kof_scan_path(sc, path, &opt, on_object, &sink);
	kof_scanner_on_debug(sc, NULL, NULL);
	return 0;
}

#ifdef _WIN32
static volatile LONG g_stop;

static BOOL WINAPI on_ctrl(DWORD type)
{
	(void)type;
	InterlockedExchange(&g_stop, 1);
	return TRUE;
}

static void stop_on_signal(void) { SetConsoleCtrlHandler(on_ctrl, TRUE); }
#else
static volatile sig_atomic_t g_stop;

static void on_ctrl(int sig) { (void)sig; g_stop = 1; }

static void stop_on_signal(void)
{
	signal(SIGINT, on_ctrl);
	signal(SIGTERM, on_ctrl);
}
#endif

/* ------------------------------------------------------------- the spiller */

/*
 * COPY A CREATED FILE WHILE IT STILL EXISTS.
 *
 * THE PROBLEM THIS SOLVES, precisely. Collection happens after the traced tree
 * is dead - kofrepart.c opens with why, and the reasons are right: a file read
 * while its writer runs hashes to something that was never on the disk, and
 * unbounded I/O on the drain path costs a full ring rather than a queue. But a
 * dropper that writes its second stage and deletes it has nothing left to
 * collect by then, and that is not an unusual sample, it is the common one.
 * Every metasploit payload that stages through a file cleans up after itself.
 *
 * So the copy happens HERE, on the event, and it stays a FALLBACK: the report
 * still reads the disk at the end and only reaches for this when the original
 * is gone. See kof_report_spill.
 *
 * AND IT IS BOUNDED, because the objection in kofrepart.c does not stop being
 * true just because the copy is useful:
 *
 *   - one copy per path, not per event: a build tool writing a file in a loop
 *     costs one copy, not a thousand
 *   - a per-file ceiling and a total budget, both small by default
 *   - a fixed table, so a sample that touches ten thousand paths runs out of
 *     slots rather than out of disk
 *   - NOTHING UNDER THE REPORT DIRECTORY is ever copied. The copies live
 *     there, and copying them would raise events that produce more copies -
 *     a loop that fills a disk at the speed of the ring.
 */
#define SPILL_MAX_FILES  256u
#define SPILL_MAX_ONE    (16u * 1024u * 1024u)
#define SPILL_MAX_TOTAL  (256u * 1024u * 1024u)

struct spiller {
	char     dir[512];      /* <report>/spill */
	char     guard[512];    /* the report root: never copy from under it */
	size_t   guard_len;
	uint32_t n;
	uint64_t bytes, skipped_big, skipped_full, failed;
	int      ready;
	/* Paths already copied. Hashes only - the strings live in the report's
	 * arena and this table exists to answer "again?" in one compare. */
	uint64_t seen[SPILL_MAX_FILES * 2u];
};

static uint64_t spill_hash(const char *s)
{
	uint64_t h = 1469598103934665603ull;

	for (; *s; s++) {
		h ^= (uint64_t)(unsigned char)*s;
		h *= 1099511628211ull;
	}
	return h ? h : 1ull;   /* 0 means an empty slot */
}

static int spill_seen(struct spiller *sp, const char *path)
{
	uint64_t h = spill_hash(path);
	size_t   n = sizeof sp->seen / sizeof sp->seen[0];
	size_t   i = (size_t)(h % n);
	size_t   k;

	for (k = 0; k < n; k++, i = (i + 1) % n) {
		if (!sp->seen[i]) {
			sp->seen[i] = h;
			return 0;
		}
		if (sp->seen[i] == h)
			return 1;
	}
	return 1;   /* full: treat everything as seen rather than thrash */
}

static void spill_init(struct spiller *sp, const char *rep_dir)
{
	memset(sp, 0, sizeof *sp);
	if (!rep_dir || !*rep_dir)
		return;
	snprintf(sp->guard, sizeof sp->guard, "%s", rep_dir);
	sp->guard_len = strlen(sp->guard);
	snprintf(sp->dir, sizeof sp->dir, "%s/spill", rep_dir);
	sp->ready = (kof_report_mkpath(sp->dir) == 0);
	if (!sp->ready)
		fprintf(stderr, "kofmontrace: cannot make %s - a file the "
			"sample deletes will not be captured\n", sp->dir);
}

static void spill_take(struct spiller *sp, struct kof_report *rep,
		       const struct kof_evt *e)
{
	const char *path;
	char  out[640];
	FILE *in, *dst;
	unsigned char buf[64u * 1024u];
	uint64_t wrote = 0;
	size_t   got;

	if (!sp->ready || !rep)
		return;
	if (e->verb != KOF_EVT_FILE_NEW && e->verb != KOF_EVT_FILE_WRITE)
		return;
	path = kof_evt_object(e);
	if (!path || !*path)
		return;
	/* Our own copies, and the report we are writing into. */
	if (sp->guard_len && !strncmp(path, sp->guard, sp->guard_len))
		return;
	if (sp->n >= SPILL_MAX_FILES) {
		sp->skipped_full++;
		return;
	}
	if (spill_seen(sp, path))
		return;

	in = fopen(path, "rb");
	if (!in) {
		/* Already gone, or not ours to read. Not an error: the report
		 * will say the bytes were not captured, which is true. */
		sp->failed++;
		return;
	}
	snprintf(out, sizeof out, "%s/%04u.bin", sp->dir, sp->n);
	dst = fopen(out, "wb");
	if (!dst) {
		fclose(in);
		sp->failed++;
		return;
	}
	while ((got = fread(buf, 1, sizeof buf, in)) > 0) {
		if (wrote + got > SPILL_MAX_ONE ||
		    sp->bytes + wrote + got > SPILL_MAX_TOTAL) {
			/*
			 * A TRUNCATED COPY IS WORSE THAN NONE. Its digest
			 * would name bytes that were never a file, and every
			 * tool downstream treats a digest as an identity. So
			 * the partial copy is removed and the report goes on
			 * saying the bytes were not captured.
			 */
			fclose(dst);
			fclose(in);
			remove(out);
			sp->skipped_big++;
			return;
		}
		if (fwrite(buf, 1, got, dst) != got) {
			fclose(dst);
			fclose(in);
			remove(out);
			sp->failed++;
			return;
		}
		wrote += got;
	}
	fclose(in);
	if (fclose(dst) != 0 || kof_report_spill(rep, path, out) != 0) {
		remove(out);
		sp->failed++;
		return;
	}
	sp->n++;
	sp->bytes += wrote;
}

static void spill_report(const struct spiller *sp, FILE *out)
{
	if (!sp->ready || (!sp->n && !sp->skipped_big && !sp->skipped_full &&
			   !sp->failed))
		return;
	fprintf(out, "   %u file(s) copied during the run, %.2f MB",
		sp->n, (double)sp->bytes / 1048576.0);
	if (sp->skipped_big)
		fprintf(out, "; %llu over the per-file ceiling",
			(unsigned long long)sp->skipped_big);
	if (sp->skipped_full)
		fprintf(out, "; %llu past the table",
			(unsigned long long)sp->skipped_full);
	if (sp->failed)
		fprintf(out, "; %llu unreadable",
			(unsigned long long)sp->failed);
	fputs("\n   These stand in ONLY where the original was deleted before "
	      "the run ended.\n", out);
}

/* ------------------------------------------------------------ the subject */

/*
 * WHAT A TRACER NEEDS: a collector scoped to one program, and a way to start,
 * hold and end that program. The two platforms answer both differently and
 * nothing below this block says so.
 *
 * SCOPING IS THE INTERESTING HALF. Windows is told about every process start
 * and keeps a tracked set - see kofw_mon_track. Linux has no such stream
 * without the netlink connector, which needs CAP_NET_ADMIN and drops records
 * under load, so the scope is a PROCESS GROUP: the child gets its own with
 * setpgid, every descendant inherits it, and an event is in scope exactly when
 * getpgid(pid) returns it. One syscall per event, nothing to build, nothing to
 * poll, and the kernel is not going to forget which group a process is in.
 *
 * WHAT ESCAPES THAT, plainly: a process that calls setsid() leaves the group
 * and stops being reported. That is the hole a daemonising payload walks
 * through, and it is why the Windows side tracks instead of grouping. The
 * honest position is that this scopes a well-behaved subject.
 *
 * AND WITHOUT PRIVILEGE THERE IS NOTHING TO SCOPE BY: an unprivileged fanotify
 * listener is handed pid 0 for every event it did not cause itself. A degraded
 * run reports what it can see and attributes none of it - see afan.h.
 */
struct tracer {
#ifdef _WIN32
	struct kofw_mon    *mon;
	struct kofw_evt     raw;
	STARTUPINFOA        si;
	PROCESS_INFORMATION pi;
	HANDLE              job;
	char                cmd[8192];
#else
	struct kofa_fan          *fan;
	const struct kof_mon_api *api;
	pid_t                     kid, group;
	uint32_t                  asked, granted;
	uint64_t                  out_of_scope, unattributed;
	int                       running;
	int                       unscoped;

	/*
	 * WHAT WE LEARNED WHILE THE ANSWER STILL EXISTED.
	 *
	 * getpgid() on a process that has exited returns -1, and an event
	 * arrives AFTER the thing that caused it - so a program that writes a
	 * file and exits inside one poll interval can no longer be asked which
	 * group it was in. That is not an edge case, it is the shape of a
	 * dropper: the trace was losing exactly the events it exists to catch.
	 *
	 * So every resolution is remembered. A pid seen once while it lived is
	 * still answerable after it dies, which covers everything that raised
	 * more than one event or lived longer than one drain.
	 *
	 * Open addressing, fixed size, no allocation on the event path. A full
	 * table is not an error: an entry is overwritten and the pid becomes
	 * unknown again, which falls back to the rule below rather than to a
	 * wrong answer.
	 */
	struct { uint32_t pid; uint8_t known, in; } seen[512];
#endif
	uint32_t root_pid;
};

static int tracer_open(struct tracer *t, unsigned providers, uint32_t ring)
{
	int err = 0;

	memset(t, 0, sizeof *t);
#ifdef _WIN32
	{
		struct kofw_mon_option opt;

		memset(&opt, 0, sizeof opt);
		opt.providers = providers;
		opt.ring_capacity = ring;
		opt.trace_self = 1;   /* our own CreateProcess raises the most
				       * important event in the run */
		t->mon = kofw_mon_open(&opt, &err);
		if (!t->mon) {
			fprintf(stderr, "kofmontrace: %s\n",
				kofw_err_name(err));
			return 0;
		}
	}
#else
	{
		struct kofa_fan_option fo;

		(void)providers; (void)ring;
		memset(&fo, 0, sizeof fo);
		/* Our own events are the only ones carrying a pid in a
		 * degraded session, and the group test below is what scopes -
		 * so the self-filter must not drop them first. */
		fo.trace_self = 1;
		t->fan = kofa_fan_open(&fo, &err);
		if (!t->fan) {
			fprintf(stderr, "kofmontrace: %s\n",
				kofa_err_name(err));
			return 0;
		}
		t->api = kofa_fan_api(t->fan);
		t->api->print_extra(t->api->self, stderr);

		/*
		 * WHAT THIS HOST CAN ACTUALLY DELIVER, worked out here so the
		 * REFUSED line below can say the rest out loud.
		 *
		 * fanotify watches FILES. It has nothing to say about a
		 * connection, a name lookup or a thread, and there is no
		 * registry or AMSI to have an opinion about - so six of the
		 * ten providers this tool offers can never arrive on Linux.
		 * The banner used to announce all ten anyway, which is the
		 * exact failure the note beside it warns about: a trace that
		 * shows no network activity, truthfully, to somebody who
		 * asked for network activity and was told they had it.
		 *
		 * FILE_WRITE AND IMAGE ARE PRIVILEGE-DEPENDENT. The full mask
		 * carries FAN_CLOSE_WRITE and FAN_OPEN_EXEC; the unprivileged
		 * fallback carries neither, so a degraded session reports
		 * creates, deletes and renames and nothing else. See the mask
		 * pair in afan.c.
		 */
		t->asked = providers;
		t->granted = providers & TRACER_SUB_FILE;
		if (kofa_fan_mode(t->fan) != KOFA_FAN_DEGRADED)
			t->granted |= providers & (TRACER_SUB_FILE_WRITE |
						   TRACER_SUB_IMAGE);
		/*
		 * NOTHING TO SCOPE BY, SAID OUT LOUD.
		 *
		 * Unprivileged, every record about another process arrives
		 * with KOF_F_PID in `miss` - so the group test below has
		 * nothing to test and would refuse the entire trace, which
		 * looks exactly like a program that did nothing. Showing
		 * everything and saying so is the only honest answer: the
		 * lines are real, the attribution is not, and a reader told
		 * that can still use them.
		 */
		if (kofa_fan_mode(t->fan) == KOFA_FAN_DEGRADED) {
			t->unscoped = 1;
			fputs("kofmontrace: UNSCOPED: this session cannot "
			      "attribute events, so every record below is "
			      "shown and NONE is known to belong to the "
			      "traced program - run as root to scope it\n",
			      stderr);
		}
	}
#endif
	return 1;
}

/*
 * Start it, STOPPED, so that "the subject is known" happens strictly before
 * "the subject can do anything". Windows creates it suspended; POSIX raises
 * SIGSTOP on itself after setpgid and before exec.
 */
static int tracer_start(struct tracer *t, char **argv, const char *cmdline)
{
#ifdef _WIN32
	memset(&t->si, 0, sizeof t->si);
	t->si.cb = sizeof t->si;
	memset(&t->pi, 0, sizeof t->pi);
	snprintf(t->cmd, sizeof t->cmd, "%s", cmdline);
	if (!CreateProcessA(NULL, t->cmd, NULL, NULL, FALSE,
			    CREATE_SUSPENDED, NULL, NULL, &t->si, &t->pi)) {
		fprintf(stderr, "kofmontrace: cannot run '%s' (error %lu)\n",
			argv[0], (unsigned long)GetLastError());
		return 0;
	}
	t->root_pid = t->pi.dwProcessId;
	return 1;
#else
	(void)cmdline;
	t->kid = fork();
	if (t->kid < 0) {
		perror("kofmontrace: fork");
		return 0;
	}
	if (t->kid == 0) {
		setpgid(0, 0);
		raise(SIGSTOP);
		execvp(argv[0], argv);
		fprintf(stderr, "kofmontrace: cannot run %s: %s\n",
			argv[0], strerror(errno));
		_exit(127);
	}
	/* Set on both sides: whichever runs first, the group is right before
	 * the child can produce an event. */
	setpgid(t->kid, t->kid);
	t->group = t->kid;
	t->root_pid = (uint32_t)t->kid;
	t->running = 1;

	/*
	 * WAIT FOR IT TO ACTUALLY BE STOPPED, and this is not belt and braces.
	 *
	 * A SIGCONT delivered before the child reaches raise(SIGSTOP) is not
	 * queued and not remembered - it is simply gone, and the child then
	 * stops and never starts again. The tracer sits out its whole timeout
	 * watching a process that never ran, and the trace is empty for a
	 * reason nothing in it mentions. WUNTRACED returns when the child has
	 * stopped, which is the only point at which SIGCONT is certain to be
	 * seen.
	 */
	{
		int st;

		if (waitpid(t->kid, &st, WUNTRACED) == t->kid &&
		    !WIFSTOPPED(st)) {
			/* It exited before it ever stopped: exec failed, or
			 * the program is gone. Nothing to trace and nothing
			 * to resume. */
			t->running = 0;
			fprintf(stderr, "kofmontrace: %s did not start\n",
				argv[0]);
			return 0;
		}
	}
	return 1;
#endif
}

/* Scope the collector to it. Windows is told; POSIX already is, by the group. */
static int tracer_track(struct tracer *t, const char *leaf)
{
#ifdef _WIN32
	return kofw_mon_track(t->mon, t->root_pid, leaf) == 0;
#else
	(void)t; (void)leaf;
	return 1;
#endif
}

/*
 * Contain the lifetime, BEFORE it runs - a child created before the container
 * exists is outside it forever. Non-zero when contained.
 */
static int tracer_contain(struct tracer *t)
{
#ifdef _WIN32
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;

	t->job = CreateJobObjectW(NULL, NULL);
	if (t->job) {
		memset(&eli, 0, sizeof eli);
		eli.BasicLimitInformation.LimitFlags =
			JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		if (!SetInformationJobObject(t->job,
					     JobObjectExtendedLimitInformation,
					     &eli, sizeof eli) ||
		    !AssignProcessToJobObject(t->job, t->pi.hProcess)) {
			CloseHandle(t->job);
			t->job = NULL;
		}
	}
	return t->job != NULL;
#else
	/* The group was created at fork and every descendant inherits it, so
	 * there is nothing to assign and nothing that can be created outside
	 * it - which is the one respect in which this is stronger than the
	 * job object it replaces. */
	(void)t;
	return 1;
#endif
}

static void tracer_resume(struct tracer *t)
{
#ifdef _WIN32
	ResumeThread(t->pi.hThread);
#else
	kill(t->kid, SIGCONT);
#endif
}

/* The next record, already neutral and already scoped. */
#ifndef _WIN32
#define TRACER_SEEN (sizeof ((struct tracer *)0)->seen / \
		     sizeof ((struct tracer *)0)->seen[0])

/* Was this pid in the traced group? 1 yes, 0 no, -1 never resolved. */
static int seen_get(const struct tracer *t, uint32_t pid)
{
	size_t i = (size_t)(pid * 2654435761u) % TRACER_SEEN;
	size_t n;

	for (n = 0; n < 8; n++, i = (i + 1) % TRACER_SEEN) {
		if (!t->seen[i].known)
			return -1;
		if (t->seen[i].pid == pid)
			return t->seen[i].in;
	}
	return -1;
}

static void seen_put(struct tracer *t, uint32_t pid, int in)
{
	size_t i = (size_t)(pid * 2654435761u) % TRACER_SEEN;
	size_t n;

	for (n = 0; n < 8; n++, i = (i + 1) % TRACER_SEEN) {
		if (!t->seen[i].known || t->seen[i].pid == pid) {
			t->seen[i].pid = pid;
			t->seen[i].known = 1;
			t->seen[i].in = (uint8_t)(in ? 1 : 0);
			return;
		}
	}
	/* Every probe taken: overwrite the first. See the note on the table. */
	i = (size_t)(pid * 2654435761u) % TRACER_SEEN;
	t->seen[i].pid = pid;
	t->seen[i].known = 1;
	t->seen[i].in = (uint8_t)(in ? 1 : 0);
}
#endif

static int tracer_next(struct tracer *t, struct kof_evt *out, uint32_t wait_ms,
		       int all)
{
#ifdef _WIN32
	(void)all;
	if (!kofw_mon_next(t->mon, &t->raw, wait_ms))
		return 0;
	kofw_evt_to_kof(&t->raw, out);
	return 1;
#else
	for (;;) {
		if (!kof_mon_next(t->api, out, wait_ms))
			return 0;
		if (all || t->unscoped)
			return 1;
		if (out->miss & KOF_F_PID) {
			t->out_of_scope++;
			continue;
		}
		{
			pid_t g = getpgid((pid_t)out->pid);
			int known;

			if (g >= 0) {
				/* The kernel still knows. Answer, and
				 * remember for after it exits. */
				seen_put(t, out->pid, g == t->group);
				if (g == t->group)
					return 1;
				t->out_of_scope++;
				continue;
			}
			/*
			 * IT HAS EXITED. Answer from what was learned while it
			 * lived, and when nothing was - a process that wrote
			 * one file and was gone before the drain - SHOW IT.
			 *
			 * That is the deliberate choice: a trace that drops
			 * what it cannot prove drops the dropper, and the
			 * whole run is then clean for the one reason nobody
			 * would suspect. Counted separately and reported at
			 * the end, so nothing here is mistaken for attributed.
			 */
			known = seen_get(t, out->pid);
			if (known == 1)
				return 1;
			if (known == 0) {
				t->out_of_scope++;
				continue;
			}
			t->unattributed++;
			out->miss |= KOF_F_PID;
			return 1;
		}
	}
#endif
}

/*
 * The image name for the pid of the record tracer_next last returned. It reads
 * the RAW record rather than the neutral one because the Windows lookup is
 * keyed on (pid, create_time) and create_time is a collector field - a pid on
 * its own names whoever holds it now, which after a reuse is the wrong
 * process. Linux has no such map and returns the empty string, which
 * kof_evt_render already treats as "not known".
 */
static const char *tracer_name_of(struct tracer *t)
{
#ifdef _WIN32
	return kofw_mon_name_of(t->mon, t->raw.pid,
				t->raw.type == KOF_EVT_PROC_START ||
				t->raw.type == KOF_EVT_PROC_STOP
					? t->raw.create_time : 0);
#else
	(void)t;
	return "";
#endif
}

static int tracer_alive(struct tracer *t)
{
#ifdef _WIN32
	return kofw_mon_tracked_alive(t->mon) != 0;
#else
	int st;

	if (!t->running)
		return 0;
	if (waitpid(t->kid, &st, WNOHANG) == t->kid)
		t->running = 0;
	return t->running;
#endif
}

static void tracer_health(struct tracer *t, struct kof_evt_health *nh)
{
#ifdef _WIN32
	kofw_mon_health_neutral(t->mon, nh);
#else
	t->api->health(t->api->self, nh);
#endif
}

static void tracer_extra(struct tracer *t, FILE *out)
{
#ifdef _WIN32
	struct kofw_health h;

	kofw_mon_health(t->mon, &h);
	kofw_health_print_extra(out, &h);
#else
	t->api->print_extra(t->api->self, out);
#endif
}

/*
 * WHAT THE COLLECTOR WAS ASKED FOR AND WHAT IT GOT. Windows can refuse a
 * provider one at a time; the Linux collector is one subscription that either
 * opened or did not, and tracer_open has already failed if it did not - so
 * asked and enabled are equal and the "REFUSED" report never fires.
 */
static void tracer_subs(struct tracer *t, uint32_t *asked, uint32_t *enabled)
{
#ifdef _WIN32
	struct kofw_health h;

	kofw_mon_health(t->mon, &h);
	*asked = h.sub_asked;
	*enabled = h.sub_enabled;
#else
	*asked = t->asked;
	*enabled = t->granted;
#endif
}

static const char *tracer_sub_name(uint32_t bit)
{
#ifdef _WIN32
	return kofw_sub_name(bit);
#else
	switch (bit) {
	case TRACER_SUB_PROCESS:    return "process";
	case TRACER_SUB_IMAGE:      return "image";
	case TRACER_SUB_FILE:       return "file";
	case TRACER_SUB_FILE_WRITE: return "file-write";
	case TRACER_SUB_FILE_OPEN:  return "file-open";
	case TRACER_SUB_NET:        return "net";
	case TRACER_SUB_REGISTRY:   return "registry";
	case TRACER_SUB_AMSI:       return "amsi";
	case TRACER_SUB_DNS:        return "dns";
	case TRACER_SUB_THREAD:     return "thread";
	default:                    return "?";
	}
#endif
}

/*
 * The output filter. Windows applies it inside the collector, which is where
 * dropping belongs when the collector is the thing producing the volume.
 * fanotify has no such knob - the mask is set at open and there is nothing
 * per-event to tune - so the flags that matter there are carried on the tracer
 * and applied by tracer_next.
 */
static void tracer_filter(struct tracer *t, uint32_t root_pid, int no_scope,
			  int show_all_img, int show_raw, int amsi_anywhere)
{
#ifdef _WIN32
	struct kofw_filter f;

	memset(&f, 0, sizeof f);
	/*
	 * NO SCOPE AT ALL, when asked.
	 *
	 * Scoping to a tree is what makes a trace readable, and it has one
	 * failure that is not a bug and cannot be fixed from inside:
	 * parentage. A payload that migrates is running in a process that is
	 * nobody's descendant, and everything it does from there - including
	 * every process it goes on to create - is attributed outside the tree
	 * and dropped. The trace shows a clean subtree and says nothing about
	 * the thing that walked out of it.
	 *
	 * There is no clever repair for that: no event says "this process is
	 * now running somebody else's code". So the honest option is to turn
	 * the scope off and take the noise, which on a quiet test machine is a
	 * fair trade.
	 */
	f.root_pid = no_scope ? 0u : root_pid;
	if (!show_all_img)
		f.drop_loc = 1u << KOF_LOC_SYSTEM;
	if (!show_raw)
		f.types = ~(uint32_t)(1u << KOF_EVT_RAW);
	if (amsi_anywhere)
		f.scope_exempt_prov = 1u << KOFW_PROV_AMSI;
	kofw_mon_filter(t->mon, &f);
#else
	(void)t; (void)root_pid; (void)no_scope;
	(void)show_all_img; (void)show_raw; (void)amsi_anywhere;
#endif
}

/*
 * THE SUBJECT AS A PATH THAT CAN BE OPENED. Both hosts resolve a bare name
 * against PATH before running it, so the report has to resolve it the same
 * way or every digest in it is "could not be read". Non-zero when `out` holds
 * a path.
 */
static int tracer_resolve(const char *name, char *out, size_t cap)
{
#ifdef _WIN32
	return SearchPathA(NULL, name, ".exe", (DWORD)cap, out, NULL) != 0;
#else
	const char *path, *p, *e;
	size_t nlen = strlen(name);

	if (strchr(name, '/')) {   /* already a path: execvp does not search */
		if (nlen >= cap)
			return 0;
		memcpy(out, name, nlen + 1);
		return access(out, X_OK) == 0;
	}
	/*
	 * The search this has to match is execvp's, which falls back to
	 * confstr when PATH is unset - so the fallback is the same one, not a
	 * guess at /bin:/usr/bin.
	 */
	path = getenv("PATH");
	if (!path || !*path) {
		static char def[1024];

		if (confstr(_CS_PATH, def, sizeof def) == 0)
			return 0;
		path = def;
	}
	for (p = path; *p; p = (*e ? e + 1 : e)) {
		size_t dlen;

		e = strchr(p, ':');
		if (!e)
			e = p + strlen(p);
		dlen = (size_t)(e - p);
		if (dlen == 0) {   /* an empty field means "." */
			p = ".";
			dlen = 1;
		}
		if (dlen + 1 + nlen >= cap)
			continue;
		memcpy(out, p, dlen);
		out[dlen] = '/';
		memcpy(out + dlen + 1, name, nlen + 1);
		if (access(out, X_OK) == 0)
			return 1;
	}
	return 0;
#endif
}

/*
 * HOW MANY RECORDS WERE SHOWN WITHOUT BEING ATTRIBUTED - see tracer_next.
 * Zero on Windows, which tracks processes and therefore always knows.
 */
static void tracer_report_unattributed(struct tracer *t, FILE *out)
{
#ifdef _WIN32
	(void)t; (void)out;
#else
	if (!t->unattributed)
		return;
	fprintf(out, "   %llu event(s) shown but NOT attributed: the process "
		"that caused them had already exited\n"
		"   and was never seen alive, so it could not be placed in or "
		"out of the traced group.\n",
		(unsigned long long)t->unattributed);
#endif
}

/* How many records the scope refused - the one number that says whether a
 * quiet trace was quiet or merely narrow. */
static uint64_t tracer_filtered_scope(struct tracer *t)
{
#ifdef _WIN32
	struct kofw_health h;

	kofw_mon_health(t->mon, &h);
	return h.filtered_scope;
#else
	return t->out_of_scope;
#endif
}

/* Two Windows-only readouts. Both have no Linux counterpart and say so by
 * being empty rather than by being printed wrong. */
static int tracer_describe(struct tracer *t, char *buf, size_t cap)
{
#ifdef _WIN32
	return kofw_mon_describe(t->mon, buf, cap) != 0;
#else
	(void)t; (void)buf; (void)cap;
	return 0;
#endif
}

static const char *tracer_tracked_nth(struct tracer *t, uint32_t k,
				      uint32_t *pid)
{
#ifdef _WIN32
	return kofw_mon_tracked_nth(t->mon, k, pid);
#else
	(void)t; (void)k; (void)pid;
	return NULL;
#endif
}

/* End the run. The container is what makes this one call rather than a hunt. */
static void tracer_stop(struct tracer *t)
{
#ifdef _WIN32
	if (t->job) {
		TerminateJobObject(t->job, 1);
		CloseHandle(t->job);
		t->job = NULL;
	}
#else
	kill(-t->group, SIGKILL);
	if (t->running) {
		int st;

		(void)waitpid(t->kid, &st, 0);
		t->running = 0;
	}
#endif
}

static void tracer_close(struct tracer *t)
{
#ifdef _WIN32
	if (t->pi.hThread)  CloseHandle(t->pi.hThread);
	if (t->pi.hProcess) CloseHandle(t->pi.hProcess);
	kofw_mon_close(t->mon);
#else
	kof_mon_close(t->api);
#endif
}

static void usage(void)
{
	kof_evt_banner(stderr, "kofmontrace", (uint32_t)KOFENG_BUILD,
		       "process, image, file, network, registry, amsi, dns");
	fputs("\nusage: kofmontrace [options] <program> [args...]\n"
	      "\n"
	      "EVERY PROVIDER IS ON BY DEFAULT, and so is --raw. This is a tool\n"
	      "for finding out what a program does and what the stream looks\n"
	      "like, and a default that collected less would answer neither.\n"
	      "The subtree filter is what makes that affordable: everything\n"
	      "outside one process tree is discarded before it is printed.\n"
	      "\n"
	      "NOTHING STOPS THIS ON ITS OWN. It collects until Ctrl-C. Neither\n"
	      "a deadline nor the traced tree exiting ends the run unless you\n"
	      "ask for it, because both end traces early in the case that\n"
	      "matters: a payload that migrates leaves the process it was\n"
	      "launched in, that process exits, and the tracked tree empties at\n"
	      "the moment the interesting half starts running somewhere else.\n"
	      "\n"
	      "  --timeout N     stop after N seconds. Default 0 = never.\n"
	      "                  For an unattended run.\n"
	      "  --until-exit    stop once the traced tree has exited, plus\n"
	      "                  --grace. The old default. Right when the\n"
	      "                  target really is the whole story - a script,\n"
	      "                  an installer - and wrong for anything that\n"
	      "                  might hand off.\n"
	      "  --grace N       with --until-exit, keep collecting N seconds\n"
	      "                  after the tree exits (default 2). Events are\n"
	      "                  delivered up to a flush timer late, so the\n"
	      "                  last thing a process did routinely arrives\n"
	      "                  after its own ProcessStop.\n"
	      "  --ring N        records in flight (default 65536, 640B each)\n"
	      "  --log FILE      record every event this run KEPT into FILE, as\n"
	      "                  fixed 640-byte records behind a header. The\n"
	      "                  point is replay: a rule that cannot be run\n"
	      "                  again over a recorded trace cannot be\n"
	      "                  regression tested, and a false positive nobody\n"
	      "                  can reproduce cannot be fixed. The file reads\n"
	      "                  on a host with no ETW at all.\n"
	      "  --report DIR    after the run, write a report into DIR: what\n"
	      "     (-r DIR)     the program left behind, deduplicated, with\n"
	      "                  the bytes of the files it created and of the\n"
	      "                  ranges it wrote into files that already\n"
	      "                  existed. Three files: report.txt to read,\n"
	      "                  report.json for a pipeline, and\n"
	      "                  candidates.tsv - the observed strings, each\n"
	      "                  marked with whether it is ACTUALLY in the\n"
	      "                  sample's bytes, which is what makes it usable\n"
	      "                  as signature material.\n"
	      "                  OFF by default, unlike every provider: a trace\n"
	      "                  prints what it sees and changes nothing, while\n"
	      "                  this scans and writes copies of what a live\n"
	      "                  sample produced onto this disk.\n"
	      "                  Nothing is filtered out of it. Fingerprints\n"
	      "                  that hold a random name, a pid or a user\n"
	      "                  profile are GROUPED as such, with the reason\n"
	      "                  and the invariant part of each - a dropped\n"
	      "                  candidate is a judgement nobody can check.\n"
	      "  --db PATH       the database the report identifies artefacts\n"
	      "                  with (default build/release/databases).\n"
	      "                  Without one the report still has every\n"
	      "                  fingerprint and every digest, and identifies\n"
	      "                  nothing - and says so rather than showing\n"
	      "                  empty columns.\n"
	      "  --no-collect    report on the files the tree created without\n"
	      "                  copying them into DIR. They are still hashed\n"
	      "                  and scanned in place.\n"
	      "  --schema        at exit, print every payload shape that\n"
	      "                  arrived, with a record count for each\n"
	      "  --all-images    do not suppress system module loads\n"
	      "  --quiet         collect and count, print no per-event lines.\n"
	      "                  The renderer is one printf per event and a\n"
	      "                  console retires a few thousand lines a second;\n"
	      "                  with --thread the stream is denser than that,\n"
	      "                  so the consumer falls behind and the ring drops\n"
	      "                  events of EVERY kind. Redirecting stdout to a\n"
	      "                  file does the same and keeps the detail.\n"
	      "\n"
	      "  --no-image      do not subscribe to module loads\n"
	      "  --no-file       do not subscribe to file create/delete/rename\n"
	      "  --no-file-write do not subscribe to writes into existing files\n"
	      "  --no-net        do not subscribe to network events\n"
	      "  --leave-running the target and its children SURVIVE this\n"
	      "                  tracer. Off by default: everything launched\n"
	      "                  goes into a job object that the kernel kills\n"
	      "                  when this exits, including on Ctrl-C and\n"
	      "                  including if this is killed itself. Ask for\n"
	      "                  this only when you mean to leave a sample\n"
	      "                  running on the machine.\n"
	      "  --no-registry   do not subscribe to registry create/set/delete\n"
	      "  --no-dns        do not subscribe to name lookups. ON by\n"
	      "                  default, and it is the network evidence worth\n"
	      "                  most: an address is rented and reassigned,\n"
	      "                  while the domain is what the operator chose\n"
	      "                  and paid for, and is still searchable a year\n"
	      "                  later. User-mode provider like AMSI, so a\n"
	      "                  payload that resolves names itself or over\n"
	      "                  HTTPS does not appear here and its connection\n"
	      "                  still does under --net.\n"
	      "  --no-scope      show events from EVERY process, not only the\n"
	      "                  launched tree. Use this when the subject can\n"
	      "                  MIGRATE: a payload that moves into another\n"
	      "                  process is nobody's descendant, so it and\n"
	      "                  everything it starts fall outside the tree and\n"
	      "                  are dropped. No event announces a migration,\n"
	      "                  so nothing here can follow one - turning the\n"
	      "                  scope off and taking the noise is the only\n"
	      "                  honest answer. Check `filtered out (... out of\n"
	      "                  tree N ...)` in the summary: a large N is what\n"
	      "                  this looks like before you turn it off.\n"
	      "  --no-amsi-anywhere\n"
	      "                  show AMSI records only from the traced tree.\n"
	      "                  ON by default means EVERY process is shown,\n"
	      "                  which breaks the promise that every line\n"
	      "                  belongs to one tree and is worth it: a payload\n"
	      "                  that migrated is nobody's descendant, so its\n"
	      "                  submissions are attributed outside the tree and\n"
	      "                  dropped at exactly the moment they matter.\n"
	      "  --no-amsi       do not subscribe to AMSI. That provider\n"
	      "                  reports what an application handed to\n"
	      "                  AmsiScanBuffer - an expanded PowerShell\n"
	      "                  command, a macro body - and is the ONLY\n"
	      "                  source of content here: everything else says\n"
	      "                  that something happened, this says what it\n"
	      "                  said. Free on a machine running no scripts.\n"
	      "                  Note the content is a PREFIX: a script block\n"
	      "                  is usually longer than the record, so most of\n"
	      "                  these arrive [cut].\n"
	      "\n"
	      "  --no-pipe       stop subscribing to file OPENS. ON by default:\n"
	      "                  it is the only\n"
	      "                  way a named pipe is visible - and a pipe is\n"
	      "                  how getsystem works: create a pipe, get a\n"
	      "                  SYSTEM service to connect, impersonate the\n"
	      "                  token that arrives. Expensive: CREATE fires on\n"
	      "                  every open the machine performs. Use --quiet.\n"
	      "  --no-thread     stop subscribing to thread create/exit. ON by\n"
	      "                  default here even though it is the highest\n"
	      "                  volume of\n"
	      "                  anything here - and it is the ONLY in-box way\n"
	      "                  to see a payload that was loaded in memory:\n"
	      "                  ImageLoad fires when the kernel maps an image\n"
	      "                  section, and a manually mapped DLL never maps\n"
	      "                  one, so there is no image event to miss. What\n"
	      "                  it does instead is start a thread whose entry\n"

	      "  --no-raw        hide events this build has no type for\n"
	      "\n"
	      "Registry, thread and the IPv6 and UDP network events are all\n"
	      "typed now. What still arrives untyped is a short list - an\n"
	      "accepted connection, a retransmit, the TCP copy step, the\n"
	      "resolver's intermediate stages - and --no-raw hides exactly\n"
	      "those. See type_of() in wevt_decode.c for what each one is and\n"
	      "why it is not a verb.\n"
	      "\n"
	      "Requires an elevated prompt.\n"
	      "\n"
	      "THIS EXECUTES THE FILE. It does not sandbox it and does not undo\n"
	      "what it did; it does kill the tree it launched when it exits.\n",
	      stderr);
}

int main(int argc, char **argv)
{
	struct tracer         tr;
	struct spiller        spill;
	struct kof_evt_health nh;
	struct kof_evt        ke;
	struct kof_evt_tally  tally;
	char     cmd[8192];
	/*
	 * NOTHING STOPS THIS ON ITS OWN, and both defaults got there the same
	 * way - by being wrong in the case that matters.
	 *
	 * A 60 second deadline was a backstop for a target that never exits. It
	 * cut off exactly the runs somebody had waited for, so it went to 0.
	 *
	 * The subtree emptying then became the stopping condition, and that is
	 * worse, because it is not a timeout going off - it is the trace ending
	 * on a signal that should have started it. A payload that migrates
	 * leaves the process it was launched in; that process exits; the tracked
	 * tree is empty at precisely the moment the interesting half begins
	 * running somewhere else.
	 *
	 * So: Ctrl-C ends a run. --timeout N for unattended. --until-exit for
	 * the old behaviour, when the target really is the whole story.
	 */
	double   timeout = 0.0, grace = 2.0, exited_at = -1.0;
	double   secs = 0.0, ev_secs = 0.0;
	uint64_t t_wall0, t_ev0 = 0;
	uint32_t root_pid, alive = 1;
	int      contained;
	/*
	 * AMSI FROM EVERYWHERE, ON BY DEFAULT.
	 *
	 * It breaks the promise that every line belongs to the traced tree,
	 * which is why it was opt-in - and that was the wrong trade. A payload
	 * that migrated is running somewhere that is nobody's descendant, so
	 * its submissions are attributed outside the tree and dropped at
	 * exactly the moment they matter. AMSI is low volume, so the cost of
	 * being right is a few extra lines; the cost of being tidy is missing
	 * the thing being traced for.
	 */
	int      leave_running = 0, stop_on_exit = 0, amsi_anywhere = 1;
	int      no_scope = 0;
	/*
	 * LOUD BY DEFAULT, and that is a decision rather than an oversight.
	 *
	 * Every provider off-by-default made the common case a run that
	 * collected process events and nothing else - and somebody then
	 * reported that the tool showed no network activity, which was true
	 * and was not what they meant. A tool whose job is "show me what this
	 * program did" cannot have a default that answers "not much".
	 *
	 * show_raw goes with it. Registry ids are not typed yet, so with raw
	 * hidden the registry subscription would cost its volume and print
	 * nothing at all.
	 */
	int      want_file = 1, want_image = 1, want_net = 1;
	/*
	 * EVERYTHING ON, INCLUDING THE TWO EXPENSIVE ONES.
	 *
	 * thread and pipe were opt-in here for the same reason they are absent
	 * from KOFW_SUB_SENSOR: they are an order of magnitude more traffic
	 * than the rest. That is the right answer for a sensor on every
	 * machine forever, and the wrong one for this: a tracer is pointed at
	 * one program by somebody who is watching, its subtree filter throws
	 * away everything else on the machine, and the two of them are the
	 * only view there is of an in-memory load and of getsystem. Making
	 * somebody remember a flag to see those is making them miss them.
	 */
	int      want_write = 1, want_reg = 1, want_thread = 1, want_open = 1;
	int      want_amsi = 1, want_dns = 1;
	int      show_raw = 1, show_all_img = 0, show_schema = 0, quiet = 0;
	const char *log_path = NULL;
	struct kofevt_log_w *log = NULL;
	unsigned providers;
	uint32_t ring;
	int      i, first;
	size_t   n;

	/*
	 * THE REPORT, AND WHY IT IS A DIRECTORY RATHER THAN A FILE.
	 *
	 * Because there are bytes to keep. A report that only wrote text would
	 * name the files the sample created and leave a reader with nothing to
	 * scan, and copying them somewhere requires somewhere - so the option
	 * takes a directory, the report goes in it, the collected artefacts go
	 * under it, and the whole thing can be sent to somebody as one folder.
	 *
	 * OFF BY DEFAULT, unlike every provider above. A trace prints what it
	 * sees and changes nothing; a report EXECUTES a scan and WRITES copies
	 * of what a live sample produced onto the disk of whoever ran it. That
	 * is not a default anybody should get by not reading the options.
	 */
	const char *rep_dir = NULL;
	const char *db_path = "build/release/databases";
	int      want_collect = 1;
	struct kof_report *rep = NULL;
	kof_engine  *eng = NULL;
	kof_scanner *sc  = NULL;
	/* Which record in the log the report should point a fingerprint at.
	 * The count of records WRITTEN, so it is the log's own index and not
	 * an event count - a run with no log passes KOF_REP_NO_INDEX. */
	uint64_t rep_index = 0;
	enum kof_rep_end how = KOF_END_UNKNOWN;

	memset(&tally, 0, sizeof tally);
	/* 32MB. The old 16384 was sized for process events alone; with the
	 * registry in the same session a burst fills that in well under a
	 * second, and a ring drop is a record nothing can get back. */
	ring = 65536u;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
			timeout = atof(argv[++i]);
		else if (!strcmp(argv[i], "--grace") && i + 1 < argc)
			grace = atof(argv[++i]);
		else if (!strcmp(argv[i], "--ring") && i + 1 < argc)
			ring = (uint32_t)strtoul(argv[++i],
							      NULL, 10);
		else if (!strcmp(argv[i], "--raw"))
			show_raw = 1;          /* the default; kept so an old
						* command line still works */
		else if (!strcmp(argv[i], "--no-raw"))
			show_raw = 0;
		else if (!strcmp(argv[i], "--schema"))
			show_schema = 1;
		else if (!strcmp(argv[i], "--all-images"))
			show_all_img = 1;
		else if (!strcmp(argv[i], "--no-image"))
			want_image = 0;
		else if (!strcmp(argv[i], "--no-file"))
			want_file = 0;
		else if (!strcmp(argv[i], "--no-file-write"))
			want_write = 0;
		else if (!strcmp(argv[i], "--no-net"))
			want_net = 0;
		else if (!strcmp(argv[i], "--leave-running"))
			leave_running = 1;
		else if (!strcmp(argv[i], "--until-exit"))
			stop_on_exit = 1;
		else if (!strcmp(argv[i], "--no-amsi-anywhere"))
			amsi_anywhere = 0;
		else if (!strcmp(argv[i], "--amsi-anywhere"))
			amsi_anywhere = 1;      /* now a default; kept working */
		else if (!strcmp(argv[i], "--no-scope"))
			no_scope = 1;
		else if (!strcmp(argv[i], "--no-amsi"))
			want_amsi = 0;
		else if (!strcmp(argv[i], "--no-registry"))
			want_reg = 0;
		else if (!strcmp(argv[i], "--no-dns"))
			want_dns = 0;
		else if ((!strcmp(argv[i], "--report") ||
			  !strcmp(argv[i], "-r")) && i + 1 < argc)
			rep_dir = argv[++i];
		else if (!strcmp(argv[i], "--db") && i + 1 < argc)
			db_path = argv[++i];
		else if (!strcmp(argv[i], "--no-collect"))
			want_collect = 0;
		else if (!strcmp(argv[i], "--no-thread"))
			want_thread = 0;
		else if (!strcmp(argv[i], "--no-pipe"))
			want_open = 0;
		/* The old opt-in spellings, kept so a command line in
		 * somebody's history still works. They now confirm a default. */
		else if (!strcmp(argv[i], "--thread"))
			want_thread = 1;
		else if (!strcmp(argv[i], "--pipe"))
			want_open = 1;
		else if ((!strcmp(argv[i], "--log") ||
			  !strcmp(argv[i], "-o")) && i + 1 < argc)
			log_path = argv[++i];
		/*
		 * COLLECT WITHOUT PRINTING, and it is not a cosmetic option.
		 *
		 * The renderer is one printf per event on the consumer thread,
		 * and a Windows console retires a few thousand lines a second
		 * at best. With --thread the stream is an order of magnitude
		 * denser than that, so the consumer falls behind, the ring
		 * fills and the PRODUCER drops - which loses events of every
		 * kind, not just the ones nobody wanted to read. The tally,
		 * the health line and --schema are all still computed.
		 *
		 * Redirecting stdout to a file does the same thing and keeps
		 * the detail; this is for when the detail is not wanted at all.
		 */
		else if (!strcmp(argv[i], "--quiet"))
			quiet = 1;
		/*
		 * Asked for explicitly, so it goes to stdout and exits 0 -
		 * `kofmontrace --help | more` has to work, and a help request
		 * is not an error. The usage printed on a BAD argument still
		 * goes to stderr with a non-zero exit, because that one is.
		 */
		else if (!strcmp(argv[i], "--help") ||
			 !strcmp(argv[i], "-h") ||
			 !strcmp(argv[i], "/?")) {
			usage();
			return 0;
		}
		/* The old opt-in spellings, which now only confirm a default.
		 * Accepted rather than refused: a command line somebody has in
		 * their shell history should not start failing. */
		else if (!strcmp(argv[i], "--file-write"))
			want_write = 1;
		else if (!strcmp(argv[i], "--net"))
			want_net = 1;
		/*
		 * AN UNKNOWN OPTION IS AN ERROR, NOT A PROGRAM NAME.
		 *
		 * Falling through to `break` made argv[i] the thing to launch,
		 * so a typo - or a flag this build is too old to know - came
		 * back as "cannot run '--schema' (error 2)". That reads like
		 * the tool is broken rather than like the argument was wrong,
		 * and it is indistinguishable from a stale binary, which is
		 * exactly the confusion it caused.
		 *
		 * Only arguments that LOOK like options are refused; the
		 * program being traced may legitimately be called anything
		 * that does not start with a dash.
		 */
		else if (argv[i][0] == '-' && argv[i][1] != '\0') {
			fprintf(stderr, "kofmontrace: unknown option '%s'\n\n",
				argv[i]);
			usage();
			return 2;
		}
		else
			break;
	}
	first = i;
	if (first >= argc) {
		usage();
		return 2;
	}

	/*
	 * THE REPORT DIRECTORY, MADE NOW - BEFORE A LIVE SAMPLE IS EXECUTED.
	 *
	 * kof_report_finish makes it too, because it writes into it. But that
	 * runs at the END, and a failure there means the sample has already
	 * been run on this machine, its artefacts have been collected, and the
	 * only thing left to do with the error is print it. `--report out\dns`
	 * with no `out` did exactly that: three "cannot write" lines after the
	 * run, blaming the files rather than the missing directory.
	 *
	 * So it is created here and a failure REFUSES TO RUN ANYTHING. That is
	 * the right way round for a tool whose first line of documentation is
	 * that it executes what you give it: being unable to record the
	 * evidence is a reason not to create the evidence.
	 */
	if (rep_dir && kof_report_mkpath(rep_dir) != 0) {
		fprintf(stderr, "kofmontrace: cannot create the report "
			"directory '%s' - refusing to run the target, because "
			"there would be nowhere to write what it did\n",
			rep_dir);
		return 2;
	}

	/* The target and its arguments, re-joined. Quoted only where a space
	 * makes it necessary, which is enough for a test harness and is not a
	 * general command-line composer. */
	n = 0;
	for (i = first; i < argc; i++) {
		int q = strchr(argv[i], ' ') != NULL;
		int w = snprintf(cmd + n, sizeof cmd - n, "%s%s%s%s",
				 i > first ? " " : "", q ? "\"" : "",
				 argv[i], q ? "\"" : "");
		if (w < 0 || (size_t)w >= sizeof cmd - n) {
			fputs("kofmontrace: command line too long\n", stderr);
			return 2;
		}
		n += (size_t)w;
	}

	stop_on_signal();

	providers = TRACER_SUB_PROCESS |
			(want_image ? TRACER_SUB_IMAGE : 0u) |
			(want_file  ? TRACER_SUB_FILE  : 0u) |
			(want_write ? TRACER_SUB_FILE_WRITE : 0u) |
			(want_net   ? TRACER_SUB_NET   : 0u) |
			(want_reg   ? TRACER_SUB_REGISTRY : 0u) |
			(want_amsi  ? TRACER_SUB_AMSI : 0u) |
			(want_dns   ? TRACER_SUB_DNS  : 0u) |
			(want_thread ? TRACER_SUB_THREAD : 0u) |
			(want_open  ? TRACER_SUB_FILE_OPEN : 0u);

	if (!tracer_open(&tr, providers, ring))
		return 1;

	/*
	 * SUSPENDED, THEN RESUMED AFTER THE PID IS RECORDED.
	 *
	 * Not caution for its own sake. If the target ran immediately it could
	 * create a child, write a file and exit before this thread got as far
	 * as putting its pid in the watched set - and every one of those events
	 * would then belong to nobody and be dropped. Creating it suspended
	 * makes "the subtree is known" happen strictly before "the subtree can
	 * do anything", which is the only ordering with no hole in it.
	 */
	if (!tracer_start(&tr, argv + first, cmd)) {
		tracer_close(&tr);
		return 1;
	}

	root_pid = tr.root_pid;

	/*
	 * SCOPE IT BEFORE IT RUNS. The process is still suspended here, so
	 * "the subtree is known" happens strictly before "the subtree can do
	 * anything" - the only ordering with no hole in it.
	 */
	if (!tracer_track(&tr, kof_path_leaf(argv[first]))) {
		fputs("kofmontrace: could not track the root process\n", stderr);
		tracer_stop(&tr);
		tracer_close(&tr);
		return 1;
	}
	tracer_filter(&tr, root_pid, no_scope, show_all_img, show_raw,
		      amsi_anywhere);

	/* Said out loud, because it breaks the promise the rest of the output
	 * makes: with this on, not every line below belongs to the traced
	 * tree. */
	if (amsi_anywhere)
		fputs("kofmontrace: --amsi-anywhere: AMSI records from ANY "
		      "process are shown, not only the traced tree\n", stderr);

	fprintf(stderr, "kofmontrace: build %llu\n",
		(unsigned long long)KOFENG_BUILD);
	fprintf(stderr, "kofmontrace: %s\nkofmontrace: root pid %lu, providers:"
		" process%s%s%s%s%s%s%s%s%s\n\n",
		cmd, (unsigned long)root_pid,
		want_image ? " image" : "", want_file ? " file" : "",
		want_write ? " file-write" : "", want_net ? " net" : "",
		want_reg ? " registry" : "", want_amsi ? " amsi" : "",
		want_dns ? " dns" : "",
		/* thread and file-open were subscribed and not announced, which
		 * is the one thing this line exists to prevent: when a provider
		 * enables and then delivers nothing, the banner is what says
		 * whether it was ever asked for. */
		want_thread ? " thread" : "", want_open ? " file-open" : "");

	/*
	 * SAID AT THE START, not only in the summary. A provider that refused
	 * is the reason a run looks quiet, and learning it after waiting sixty
	 * seconds for a timeout is learning it too late to change the command
	 * line.
	 */
	/*
	 * THE DEFAULT SUPPRESSION, ANNOUNCED.
	 *
	 * `cmd /c` maps 27 modules before it runs anything and all 27 are the
	 * loader's own furniture, so hiding them is right - and hiding them
	 * SILENTLY is what makes somebody conclude the provider is broken when
	 * their DLL happened to live in System32. One line, at the point where
	 * changing the command line is still free.
	 */
	if (!show_all_img && want_image)
		fputs("kofmontrace: system module loads are SUPPRESSED "
		      "(--all-images to show them)\n", stderr);

	{
		uint32_t asked, enabled, missing, b;

		tracer_subs(&tr, &asked, &enabled);
		missing = asked & ~enabled;
		if (missing) {
			fputs("kofmontrace: NOT AVAILABLE on this host:",
			      stderr);
			for (b = 1u; b; b <<= 1)
				if (missing & b)
					fprintf(stderr, " %s",
						tracer_sub_name(b));
			fputs("\n\n", stderr);
		}
	}

	/*
	 * CONTAINED WHILE THE TARGET IS STILL STOPPED.
	 *
	 * Ctrl-C used to stop the tracer and leave the sample running. Killing
	 * the root alone would not have fixed it either: it kills one process
	 * and orphans the tree under it, which for a dropper is the half that
	 * matters. So the container holds the whole descendancy - a job object
	 * on Windows, a process group on Linux, see tracer_contain.
	 *
	 * Here, before the resume, for the same reason the pid is recorded
	 * before it: after that instruction the target can create children, and
	 * a child created before the container exists is outside it forever.
	 */
	contained = leave_running ? 1 : tracer_contain(&tr);
	/*
	 * Loud, not silent. Without the container this tool leaves whatever it
	 * ran behind when it exits, and that is a fact about the machine
	 * somebody has to know before they trust the trace to have ended the
	 * run.
	 */
	if (!contained)
		fputs("kofmontrace: WARNING could not contain the target; "
		      "it and anything it starts will SURVIVE this tracer\n",
		      stderr);

	/*
	 * OPENED AFTER THE SESSION AND BEFORE THE TARGET RUNS.
	 *
	 * After, because the header records which providers actually enabled -
	 * a trace where the registry provider refused is a different artefact
	 * from one where the machine touched no registry, and no record in the
	 * file can show that difference.
	 *
	 * Before ResumeThread, because the first thing the target does is the
	 * part nothing else can get.
	 *
	 * The writes themselves raise file events. They do not feed back: this
	 * process is not in the traced subtree, so its own events are refused
	 * by the scope filter before they ever reach the writer.
	 */
	if (log_path) {
		struct kofevt_log_info li;
		uint32_t asked, enabled;

		tracer_subs(&tr, &asked, &enabled);
		memset(&li, 0, sizeof li);
		/* The record this collector produces, named as well as sized:
		 * another collector's 640-byte record is not this one. */
		li.rec_size    = (uint32_t)sizeof(struct kof_evt);
		/* The shape, so the log can write only the text a record
		 * actually has - offsetof at the one place that knows the
		 * layout. */
		li.head_size   = (uint16_t)KOF_EVT_HEAD;
		li.len_off     = (uint16_t)offsetof(struct kof_evt, text_len);
		li.rec_kind    = KOFEVT_REC_KOF;
		li.build       = (uint32_t)KOFENG_BUILD;
		li.src_major   = TRACER_MAJOR;
		li.src_minor   = TRACER_MINOR;
		/* 0 asks kofevt for this host, so the tool does not have
		 * to know how to spell it. */
		li.platform    = 0u;
		li.arch        = 0u;
		li.root_pid    = root_pid;
		li.sub_asked   = asked;
		li.sub_enabled = enabled;
		li.started     = kof_evt_now();
		log = kofevt_log_create(log_path, &li);
		if (!log)
			fprintf(stderr, "kofmontrace: cannot write '%s' - "
				"continuing without a log\n", log_path);
		else
			fprintf(stderr, "kofmontrace: recording to %s\n",
				log_path);
	}

	/*
	 * THE REPORT, OPENED BEFORE THE TARGET RUNS.
	 *
	 * Same reason the log is: the first thing a dropper does is the part
	 * nothing else can get, and a report whose accumulator started after
	 * ResumeThread would be missing exactly the writes that happen in the
	 * first milliseconds.
	 *
	 * The engine is opened here too rather than at the end, so that a
	 * missing database is reported before a live sample has been run - not
	 * after, when the run cannot be taken back.
	 */
	spill_init(&spill, rep_dir);

	if (rep_dir) {
		struct kof_report_info ri;

		/*
		 * THE SUBJECT AS A PATH THAT CAN BE OPENED, not as it was
		 * typed.
		 *
		 * `--report out\dns cmd /c ping ...` gave a report whose
		 * subject was "cmd" with "sha256: not computed - the subject
		 * could not be read", because a bare name is resolved by
		 * CreateProcess against PATH and nothing had resolved it here.
		 * Everything the report does with the subject needs a real
		 * file: the digest, the engine's verdict, and the search that
		 * decides whether an observed string is in its bytes. Without
		 * one, every candidate comes back "unchecked".
		 *
		 * SearchPath and not the image path from the trace, which is
		 * the other candidate and is worse: the kernel reports
		 * \Device\HarddiskVolume14\... , and a device path cannot be
		 * handed to fopen. This resolves it the same way the launch
		 * did, which is the only answer that is certainly the same
		 * file.
		 */
		static char subj[1024];
		const char *subject = argv[first];

		if (tracer_resolve(argv[first], subj, sizeof subj))
			subject = subj;

		memset(&ri, 0, sizeof ri);
		ri.tool        = "kofmontrace";
		ri.subject     = subject;
		ri.subject_cmd = cmd;
		ri.root_pid    = root_pid;
		ri.build       = (uint32_t)KOFENG_BUILD;
		/* Asked of kofevt rather than spelled here, so this tool and
		 * the log header cannot name the same machine differently. */
		ri.platform    = kof_evt_platform_self();
		ri.arch        = kof_evt_arch_self();
		ri.started     = kof_evt_now();
		ri.dir         = rep_dir;
		ri.log         = log_path;
		{
			uint32_t asked, enabled;

			tracer_subs(&tr, &asked, &enabled);
			ri.sub_asked   = asked;
			ri.sub_enabled = enabled;
		}

		rep = kof_report_open(&ri);
		if (!rep) {
			fprintf(stderr, "kofmontrace: cannot open a report - "
				"continuing without one\n");
		} else {
			eng = kof_engine_open(db_path);
			if (eng)
				sc = kof_scanner_new(eng);
			if (!sc) {
				/*
				 * NOT FATAL, AND NOT SILENT. Without the
				 * engine the report still has every
				 * fingerprint, every process and every
				 * digest-less artefact; what it loses is the
				 * identification and the check of whether an
				 * observed string is in the sample's bytes.
				 * The report says so in its own
				 * completeness section rather than showing
				 * empty columns.
				 */
				if (eng) {
					kof_engine_close(eng);
					eng = NULL;
				}
				fprintf(stderr, "kofmontrace: no database at "
					"%s - the report will identify "
					"nothing (use --db)\n", db_path);
			}
			fprintf(stderr, "kofmontrace: report -> %s\n", rep_dir);
		}
	}

	t_wall0 = kof_evt_now();
	tracer_resume(&tr);

	while (!g_stop) {

		if (!tracer_next(&tr, &ke, 200, no_scope)) {
			secs = kof_evt_secs_since(t_wall0, kof_evt_now());
			goto tick;
		}

		if (t_ev0 == 0)
			t_ev0 = ke.stamp;
		ev_secs = kof_evt_secs_since(t_ev0, ke.stamp);
		/* The deadline clock still has to advance while events flow, or
		 * a program that never stops producing them never times out. */
		secs = kof_evt_secs_since(t_wall0, kof_evt_now());

		/*
		 * Everything that decides WHETHER this record belongs to the
		 * tree - growing the set on a ProcessStart, retiring it on a
		 * ProcessStop, refusing everything outside it - happened inside
		 * tracer_next. What arrives here is already scoped.
		 */
		/* Recorded before it is rendered, so a --quiet run and a loud
		 * one produce the same file. */
		/*
		 * CONVERTED ONCE, HERE, AND EVERYTHING DOWNSTREAM IS NEUTRAL.
		 *
		 * The log, the renderer and the tally all take struct kof_evt,
		 * so a recorded log is collector-independent and the line a
		 * viewer prints from it is produced by the same code that
		 * printed it live.
		 */
		if (log)
			(void)kofevt_log_write(log, &ke);

		/*
		 * FED HERE, BESIDE THE LOG AND BEFORE THE RENDERER.
		 *
		 * Not inside the `if (!quiet)` below, and that is the one thing
		 * about this line worth a comment: the tally used to be counted
		 * inside the print switch, so a --quiet run came back with
		 * different numbers from a loud one - the totals were a side
		 * effect of somebody looking at them. See the note at the top
		 * of kofevtfmt.h. A report fed from the printing path would
		 * reproduce that bug with a whole report instead of a counter.
		 *
		 * The index is the log's, so every [#N] in the report is a
		 * record `kofviewer` can be pointed at. It advances only when
		 * a record was actually written: an event index would look the
		 * same and refer to nothing.
		 */
		if (rep) {
			kof_report_feed(rep, &ke,
					log ? rep_index : KOF_REP_NO_INDEX);
			if (log)
				rep_index++;
			/* AFTER the feed, because the fingerprint the copy
			 * attaches to is what the feed just created. */
			spill_take(&spill, rep, &ke);
		}

		if (!quiet)
			kof_evt_render(&ke, ev_secs, tracer_name_of(&tr),
				  stdout, &tally);
		else
			kof_evt_count(&ke, &tally);

tick:
		alive = (uint32_t)tracer_alive(&tr);
		/*
		 * THE SUBTREE EMPTYING IS NOT A REASON TO STOP, unless asked.
		 *
		 * It was the default and it was wrong for the case that matters
		 * most. A payload that migrates leaves the process it was
		 * launched in, and that process then exits - so the tracked tree
		 * empties at exactly the moment the interesting half begins
		 * running somewhere else. Stopping there ends the trace on the
		 * event that should have started it.
		 *
		 * So nothing stops this on its own now. Ctrl-C ends it, or
		 * --timeout for an unattended run, or --until-exit for the old
		 * behaviour when the target really is the whole story.
		 */
		if (stop_on_exit && alive == 0 && exited_at < 0.0)
			exited_at = secs;
		/*
		 * The grace window, and it is not politeness. Events are
		 * delivered up to a flush timer after they happened, so the
		 * last thing a process did routinely arrives after its own
		 * ProcessStop. Stopping the instant the subtree is empty
		 * truncates exactly the tail that matters.
		 */
		if (exited_at >= 0.0 && secs - exited_at >= grace) {
			how = KOF_END_TREE_EXIT;
			break;
		}
		if (timeout > 0.0 && secs >= timeout) {
			how = KOF_END_TIMEOUT;
			break;
		}
	}

	/*
	 * WHY THE RUN ENDED, RECORDED RATHER THAN INFERRED.
	 *
	 * A reader of the report has to know this before reading anything
	 * else: a trace that hit a deadline may have stopped in the middle of
	 * the interesting part, and one that ended because the tree exited is
	 * probably complete. Nothing in the records themselves says which, and
	 * `how` is still KOF_END_UNKNOWN here only if the loop left by the
	 * while condition - which is Ctrl-C.
	 */
	if (how == KOF_END_UNKNOWN)
		how = KOF_END_INTERRUPT;

	fflush(stdout);

	{
		char what[64];

		snprintf(what, sizeof what, "subtree of pid %lu",
			 (unsigned long)root_pid);
		kof_evt_print_tally(&tally, secs, what, stderr);
	}

	tracer_health(&tr, &nh);
	kof_evt_health_print(stderr, &nh, secs);
	/* And the half only this collector has - the unbacked count on
	 * Windows, the queue and permission state on Linux. Same screen as the
	 * neutral half, because a reader deciding whether to trust a quiet run
	 * needs both. */
	tracer_extra(&tr, stderr);
	tracer_report_unattributed(&tr, stderr);
	spill_report(&spill, stderr);

	/*
	 * THE SHAPES, AND WHY THIS IS ON THE TOOL PEOPLE ACTUALLY DEBUG WITH.
	 *
	 * An event that did not appear has two causes that look identical from
	 * the outside: the provider never sent it, or it arrived and this build
	 * had no type for it. Only this dump tells them apart - a shape listed
	 * for an id means the record reached the decoder. Without it the answer
	 * to "why did I not see the DLL load" is a guess.
	 */
	if (show_schema) {
		static char shapes[16384];

		if (tracer_describe(&tr, shapes, sizeof shapes))
			fprintf(stderr, "\n-- payload shapes learned:\n%s",
				shapes);
	}

	/* An overflowed tracking table is reported by wm_print_health above,
	 * because it is a kind of incompleteness and belongs beside the other
	 * kinds rather than in a line of its own. */
	/*
	 * NAMED, not just counted - because this line is the answer to "why did
	 * the trace not finish on its own".
	 *
	 * With no deadline, the run ends when the tracked tree empties, so a
	 * non-zero count here is the whole explanation for a trace that sat
	 * until Ctrl-C. It has two causes needing opposite responses, and only
	 * the names separate them: a descendant that really is still running -
	 * a service, a shell waiting on input - or a process that visibly
	 * exited in the trace above, which means its ProcessStop was never
	 * matched to its entry and the counter, not the machine, is wrong.
	 */
	if (alive) {
		/* Neither `i` nor `n`: main already has both in scope by here.
		 * A shadowed index is harmless until somebody moves code
		 * between the two scopes, and this function is long enough
		 * that they will. */
		uint32_t k, pid;
		const char *nm;

		fprintf(stderr, "   %lu process(es) still running at exit:\n",
			(unsigned long)alive);
		for (k = 0; (nm = tracer_tracked_nth(&tr, k, &pid)) != NULL;
		     k++)
			fprintf(stderr, "     pid %-6lu %s\n",
				(unsigned long)pid, *nm ? nm : "?");
		fputs("   If one of those has a ProcStop above, the count is "
		      "wrong rather than the machine.\n", stderr);
	}

	/*
	 * KILL THE TREE BEFORE ANYTHING ELSE IS TORN DOWN.
	 *
	 * Closing the job handle would do it on its own - that is what
	 * KILL_ON_JOB_CLOSE is - but doing it explicitly means the processes are
	 * gone before this returns rather than at some point during exit, and it
	 * gives the line below something true to say. The process group the
	 * Linux side kills has no such fallback, so there it is the only thing
	 * that ends the run.
	 */
	if (contained && !leave_running) {
		if (alive)
			fprintf(stderr, "   terminating %lu process(es) still "
				"in the traced tree\n", (unsigned long)alive);
		tracer_stop(&tr);
	} else if (alive) {
		fputs("   WARNING those processes were NOT terminated\n",
		      stderr);
	}

	if (log) {
		uint64_t nrec = kofevt_log_close(log);

		fprintf(stderr, "   recorded %llu event(s) to %s\n",
			(unsigned long long)nrec, log_path);
	}

	/*
	 * THE REPORT, AND IT HAPPENS HERE FOR ONE REASON: THE TREE IS DEAD.
	 *
	 * Everything below opens files the sample wrote, hashes them, copies
	 * them and hands them to the engine, and not one of those is safe or
	 * even meaningful while the sample is still running:
	 *
	 *   - a file being written as it is read hashes to a value that was
	 *     never on the disk,
	 *   - a file can change between the hash and the scan, so the report
	 *     would name one thing and describe another,
	 *   - and a process still executing is still producing artefacts, so
	 *     the collection would be of a moment nobody can reproduce.
	 *
	 * TerminateJobObject above is the first instant none of that is true.
	 * It is also why this is after the log is closed: the log is evidence
	 * too, and a report that referenced records still sitting in a stdio
	 * buffer would point at a file that does not have them yet.
	 */
	if (rep) {
		struct kof_report_stage stage;
		char path[1024];
		FILE *f;
		int   rc;

		kof_report_ended(rep, how, secs);
		kof_report_health(rep, &nh, tracer_filtered_scope(&tr));

		struct kof_rep_engine rep_eng;

		memset(&stage, 0, sizeof stage);
		stage.collect = want_collect ? 1u : 0u;

		/* The report asks through an interface; this supplies one over
		 * the scanner this program already owns. NULL when there is no
		 * engine, which is a legal report - see kof_report_stage. */
		rep_eng.user = sc;
		rep_eng.ask  = rep_ask;
		stage.engine = (eng && sc) ? &rep_eng : NULL;

		fprintf(stderr, "\nkofmontrace: collecting artefacts...\n");
		rc = kof_report_finish(rep, &stage);
		if (rc < 0)
			fprintf(stderr, "kofmontrace: the artefact phase could "
				"not use '%s' (%d) - the report is written "
				"without collected files\n", rep_dir, rc);

		/*
		 * THREE FILES, AND EACH HAS A DIFFERENT READER.
		 *
		 * A failure to write one is reported and does not stop the
		 * others: a full disk must not cost the text report because
		 * the JSON could not be written.
		 */
		snprintf(path, sizeof path, "%s/report.txt", rep_dir);
		f = fopen(path, "wb");
		if (f) {
			/* No colour into a file. The escapes would make it
			 * ungreppable, which is the one thing a report of this
			 * shape is read with. */
			kof_report_write_text(rep, f, 0);
			fclose(f);
			fprintf(stderr, "   %s\n", path);
		} else {
			fprintf(stderr, "   cannot write %s\n", path);
		}

		snprintf(path, sizeof path, "%s/report.json", rep_dir);
		f = fopen(path, "wb");
		if (f) {
			kof_report_write_json(rep, f);
			fclose(f);
			fprintf(stderr, "   %s\n", path);
		} else {
			fprintf(stderr, "   cannot write %s\n", path);
		}

		snprintf(path, sizeof path, "%s/candidates.tsv", rep_dir);
		f = fopen(path, "wb");
		if (f) {
			kof_report_write_candidates(rep, f);
			fclose(f);
			fprintf(stderr, "   %s\n", path);
		} else {
			fprintf(stderr, "   cannot write %s\n", path);
		}

		/*
		 * AND TO THE TERMINAL, IN COLOUR, because the person who just
		 * ran a live sample is sitting there and the first question is
		 * "what did it do". Making them open a file to find out is
		 * making them not look.
		 *
		 * stderr, like every other summary this tool prints, so that a
		 * run whose stdout was redirected to a file still shows it.
		 */
		kof_report_write_text(rep, stderr, 1);

		kof_report_close(rep);
	}

	if (sc)
		kof_scanner_free(sc);
	if (eng)
		kof_engine_close(eng);

	tracer_close(&tr);
	return 0;
}
