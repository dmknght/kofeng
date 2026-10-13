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

#include "kofmontrace_int.h"
#include "kofstop.h"

/*
 * ONE LINE A FLAG - see the same note on kofscanner's usage.
 *
 * This was a hundred and sixty-six lines. Thirty-four of them were flags; the
 * rest argued for the defaults - why nothing stops the trace on its own, what
 * a mark on a directory reports and what it does not, why --log exists at all.
 * Every one of those arguments is a comment beside the code that implements
 * it, which is where somebody changing the behaviour will meet it.
 */
static void usage(void)
{
	fprintf(stderr,
	"kofmontrace - run a program and collect what it does\n"
	"\n"
	"usage: kofmontrace [options] <program> [args...]\n"
	"\n"
	"  --db PATH        scan what the run touches with this database\n"
	"  --report DIR     write a report into DIR afterwards\n"
	"    (-r DIR)\n"
	"  --log FILE       record every kept event into FILE, for replay\n"
	"  --watch PATH     watch this FILE, repeatable\n"
	"\n"
	"  --timeout N      stop after N seconds (0 = never, the default)\n"
	"  --until-exit     stop once the traced tree has exited\n"
	"  --grace N        with --until-exit, keep collecting N more (default 2)\n"
	"  --leave-running  do not kill the tree when the trace ends\n"
	"  --ring N         records in flight (default 65536, 640B each)\n"
	"\n"
	"  --quiet          no per-event lines\n"
	"  --print          per-event lines even with --report\n"
	"  --schema         print the record layout and exit\n"
	"  --all-images     keep image loads from outside the traced tree\n"
	"  --no-collect     do not run anything; just print what would be\n"
	"\n"
	"  Providers are all on. Turn one off with --no-<name>:\n"
	"    image file file-write net registry dns scope amsi pipe thread raw\n"
	"    amsi-anywhere\n"
	"\n"
	"Nothing stops this on its own: it collects until Ctrl-C unless\n"
	"--timeout or --until-exit says otherwise.\n");
}

/*
 * What main() shares between its steps: the options as parsed, then the
 * state each step leaves for the next. Declared here so the steps take one
 * pointer and not forty arguments.
 */
struct mt_run {
	struct tracer         tr;
	struct spiller        spill;
	struct kof_evt_health nh;
	struct kof_evt        ke;
	struct kof_evt_tally  tally;
	char     cmd[8192];
	double   timeout, grace, exited_at;
	double   secs, ev_secs;
	uint64_t t_wall0, t_ev0;
	uint32_t root_pid, alive;
	int      contained;
	int      leave_running, stop_on_exit, amsi_anywhere;
	int      no_scope;
	int      want_file, want_image, want_net;
	int      want_write, want_reg, want_thread, want_open;
	int      want_amsi, want_dns;
	int      show_raw, show_all_img, show_schema, quiet;
	const char *log_path;
	struct kofevt_log_w *log;
	unsigned providers;
	uint32_t ring;
	int      first;
	const char *rep_dir;
	const char *db_path;
	int      want_collect;
	struct kof_report *rep;
	kof_engine  *eng;
	kof_scanner *sc;
	uint64_t rep_index;
	enum kof_rep_end how;
};

/* Step: the defaults of every option and the zero state of the run. */
static void mt_init(struct mt_run *m)
{
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
	m->timeout = 0.0; m->grace = 2.0; m->exited_at = -1.0;
	m->secs = 0.0; m->ev_secs = 0.0;
	m->t_ev0 = 0;
	m->alive = 1;
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
	m->leave_running = 0; m->stop_on_exit = 0; m->amsi_anywhere = 1;
	m->no_scope = 0;
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
	m->want_file = 1; m->want_image = 1; m->want_net = 1;
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
	m->want_write = 1; m->want_reg = 1; m->want_thread = 1;
	m->want_open = 1;
	m->want_amsi = 1; m->want_dns = 1;
	m->show_raw = 1; m->show_all_img = 0; m->show_schema = 0;
	m->quiet = 0;
	m->log_path = NULL;
	m->log = NULL;
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
	m->rep_dir = NULL;
	m->db_path = "build/release/databases";
	m->want_collect = 1;
	m->rep = NULL;
	m->eng = NULL;
	m->sc  = NULL;
	/* Which record in the log the report should point a fingerprint at.
	 * The count of records WRITTEN, so it is the log's own index and not
	 * an event count - a run with no log passes KOF_REP_NO_INDEX. */
	m->rep_index = 0;
	m->how = KOF_END_UNKNOWN;

	memset(&m->tally, 0, sizeof m->tally);
	/* 32MB. The old 16384 was sized for process events alone; with the
	 * registry in the same session a burst fills that in well under a
	 * second, and a ring drop is a record nothing can get back. */
	m->ring = 65536u;
}

/*
 * Step: read the command line. -1 to carry on, otherwise the exit status
 * main returns (help is 0, a bad argument 2).
 */
static int mt_parse_args(struct mt_run *m, int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
			m->timeout = atof(argv[++i]);
		else if (!strcmp(argv[i], "--grace") && i + 1 < argc)
			m->grace = atof(argv[++i]);
		else if (!strcmp(argv[i], "--ring") && i + 1 < argc)
			m->ring = (uint32_t)strtoul(argv[++i],
							      NULL, 10);
		else if (!strcmp(argv[i], "--watch") && i + 1 < argc) {
			if (kmt_n_watch + 1u < sizeof kmt_watch / sizeof kmt_watch[0])
				kmt_watch[kmt_n_watch++] = argv[++i];
			else
				i++;   /* said below, once, not per name */
		}
		else if (!strcmp(argv[i], "--raw"))
			m->show_raw = 1;          /* the default; kept so an old
						* command line still works */
		else if (!strcmp(argv[i], "--no-raw"))
			m->show_raw = 0;
		else if (!strcmp(argv[i], "--schema"))
			m->show_schema = 1;
		else if (!strcmp(argv[i], "--all-images"))
			m->show_all_img = 1;
		else if (!strcmp(argv[i], "--no-image"))
			m->want_image = 0;
		else if (!strcmp(argv[i], "--no-file"))
			m->want_file = 0;
		else if (!strcmp(argv[i], "--no-file-write"))
			m->want_write = 0;
		else if (!strcmp(argv[i], "--no-net"))
			m->want_net = 0;
		else if (!strcmp(argv[i], "--leave-running"))
			m->leave_running = 1;
		else if (!strcmp(argv[i], "--until-exit"))
			m->stop_on_exit = 1;
		else if (!strcmp(argv[i], "--no-amsi-anywhere"))
			m->amsi_anywhere = 0;
		else if (!strcmp(argv[i], "--amsi-anywhere"))
			m->amsi_anywhere = 1;      /* now a default; kept working */
		else if (!strcmp(argv[i], "--no-scope"))
			m->no_scope = 1;
		else if (!strcmp(argv[i], "--no-amsi"))
			m->want_amsi = 0;
		else if (!strcmp(argv[i], "--no-registry"))
			m->want_reg = 0;
		else if (!strcmp(argv[i], "--no-dns"))
			m->want_dns = 0;
		else if ((!strcmp(argv[i], "--report") ||
			  !strcmp(argv[i], "-r")) && i + 1 < argc)
			m->rep_dir = argv[++i];
		else if (!strcmp(argv[i], "--db") && i + 1 < argc)
			m->db_path = argv[++i];
		else if (!strcmp(argv[i], "--no-collect"))
			m->want_collect = 0;
		else if (!strcmp(argv[i], "--no-thread"))
			m->want_thread = 0;
		else if (!strcmp(argv[i], "--no-pipe"))
			m->want_open = 0;
		/* The old opt-in spellings, kept so a command line in
		 * somebody's history still works. They now confirm a default. */
		else if (!strcmp(argv[i], "--thread"))
			m->want_thread = 1;
		else if (!strcmp(argv[i], "--pipe"))
			m->want_open = 1;
		else if ((!strcmp(argv[i], "--log") ||
			  !strcmp(argv[i], "-o")) && i + 1 < argc)
			m->log_path = argv[++i];
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
			m->quiet = 1;
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
			m->want_write = 1;
		else if (!strcmp(argv[i], "--net"))
			m->want_net = 1;
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
	m->first = i;
	if (m->first >= argc) {
		usage();
		return 2;
	}
	return -1;
}

/*
 * Step: checks that must pass before anything is started - the report
 * directory - and the target's command line re-joined. -1 to carry on.
 */
static int mt_prepare(struct mt_run *m, int argc, char **argv)
{
	size_t n;
	int    i;

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
	if (m->rep_dir && kof_report_mkpath(m->rep_dir) != 0) {
		fprintf(stderr, "kofmontrace: cannot create the report "
			"directory '%s' - refusing to run the target, because "
			"there would be nowhere to write what it did\n",
			m->rep_dir);
		return 2;
	}

	/* The target and its arguments, re-joined. Quoted only where a space
	 * makes it necessary, which is enough for a test harness and is not a
	 * general command-line composer. */
	n = 0;
	for (i = m->first; i < argc; i++) {
		int q = strchr(argv[i], ' ') != NULL;
		int w = snprintf(m->cmd + n, sizeof m->cmd - n, "%s%s%s%s",
				 i > m->first ? " " : "", q ? "\"" : "",
				 argv[i], q ? "\"" : "");
		if (w < 0 || (size_t)w >= sizeof m->cmd - n) {
			fputs("kofmontrace: command line too long\n", stderr);
			return 2;
		}
		n += (size_t)w;
	}
	return -1;
}

/*
 * Step: open the tracer, start the target suspended and scope the trace to
 * it. -1 to carry on, otherwise the exit status.
 */
static int mt_start(struct mt_run *m, char **argv)
{
	stop_on_signal();

	m->providers = TRACER_SUB_PROCESS |
			(m->want_image ? TRACER_SUB_IMAGE : 0u) |
			(m->want_file  ? TRACER_SUB_FILE  : 0u) |
			(m->want_write ? TRACER_SUB_FILE_WRITE : 0u) |
			(m->want_net   ? TRACER_SUB_NET   : 0u) |
			(m->want_reg   ? TRACER_SUB_REGISTRY : 0u) |
			(m->want_amsi  ? TRACER_SUB_AMSI : 0u) |
			(m->want_dns   ? TRACER_SUB_DNS  : 0u) |
			(m->want_thread ? TRACER_SUB_THREAD : 0u) |
			(m->want_open  ? TRACER_SUB_FILE_OPEN : 0u);

	if (!kmt_tracer_open(&m->tr, m->providers, m->ring))
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
	if (!kmt_tracer_start(&m->tr, argv + m->first, m->cmd)) {
		kmt_tracer_close(&m->tr);
		return 1;
	}

	m->root_pid = m->tr.root_pid;

	/*
	 * SCOPE IT BEFORE IT RUNS. The process is still suspended here, so
	 * "the subtree is known" happens strictly before "the subtree can do
	 * anything" - the only ordering with no hole in it.
	 */
	if (!kmt_tracer_track(&m->tr, kof_path_leaf(argv[m->first]))) {
		fputs("kofmontrace: could not track the root process\n", stderr);
		kmt_tracer_stop(&m->tr);
		kmt_tracer_close(&m->tr);
		return 1;
	}
	kmt_tracer_filter(&m->tr, m->root_pid, m->no_scope, m->show_all_img, m->show_raw,
		      m->amsi_anywhere);
	return -1;
}

/* Step: say what is being traced, and what is not available. */
static void mt_announce(struct mt_run *m)
{
	/* Said out loud, because it breaks the promise the rest of the output
	 * makes: with this on, not every line below belongs to the traced
	 * tree. */
	if (m->amsi_anywhere)
		fputs("kofmontrace: --amsi-anywhere: AMSI records from ANY "
		      "process are shown, not only the traced tree\n", stderr);

	fprintf(stderr, "kofmontrace: build %llu\n",
		(unsigned long long)KOFENG_BUILD);
	fprintf(stderr, "kofmontrace: %s\nkofmontrace: root pid %lu, providers:"
		" process%s%s%s%s%s%s%s%s%s\n\n",
		m->cmd, (unsigned long)m->root_pid,
		m->want_image ? " image" : "", m->want_file ? " file" : "",
		m->want_write ? " file-write" : "", m->want_net ? " net" : "",
		m->want_reg ? " registry" : "", m->want_amsi ? " amsi" : "",
		m->want_dns ? " dns" : "",
		/* thread and file-open were subscribed and not announced, which
		 * is the one thing this line exists to prevent: when a provider
		 * enables and then delivers nothing, the banner is what says
		 * whether it was ever asked for. */
		m->want_thread ? " thread" : "", m->want_open ? " file-open" : "");

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
	if (!m->show_all_img && m->want_image)
		fputs("kofmontrace: system module loads are SUPPRESSED "
		      "(--all-images to show them)\n", stderr);

	{
		uint32_t asked, enabled, missing, b;

		kmt_tracer_subs(&m->tr, &asked, &enabled);
		missing = asked & ~enabled;
		if (missing) {
			fputs("kofmontrace: NOT AVAILABLE on this host:",
			      stderr);
			for (b = 1u; b; b <<= 1)
				if (missing & b)
					fprintf(stderr, " %s",
						kmt_tracer_sub_name(b));
			fputs("\n\n", stderr);
		}
	}
}

/* Step: put the target in its container while it is still stopped. */
static void mt_contain(struct mt_run *m)
{
	/*
	 * CONTAINED WHILE THE TARGET IS STILL STOPPED.
	 *
	 * Ctrl-C used to stop the tracer and leave the sample running. Killing
	 * the root alone would not have fixed it either: it kills one process
	 * and orphans the tree under it, which for a dropper is the half that
	 * matters. So the container holds the whole descendancy - a job object
	 * on Windows, a process group on Linux, see kmt_tracer_contain.
	 *
	 * Here, before the resume, for the same reason the pid is recorded
	 * before it: after that instruction the target can create children, and
	 * a child created before the container exists is outside it forever.
	 */
	m->contained = m->leave_running ? 1 : kmt_tracer_contain(&m->tr);
	/*
	 * Loud, not silent. Without the container this tool leaves whatever it
	 * ran behind when it exits, and that is a fact about the machine
	 * somebody has to know before they trust the trace to have ended the
	 * run.
	 */
	if (!m->contained)
		fputs("kofmontrace: WARNING could not contain the target; "
		      "it and anything it starts will SURVIVE this tracer\n",
		      stderr);
}

/* Step: open the event log, if one was asked for. */
static void mt_open_log(struct mt_run *m)
{
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
	if (m->log_path) {
		struct kofevt_log_info li;
		uint32_t asked, enabled;

		kmt_tracer_subs(&m->tr, &asked, &enabled);
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
		li.root_pid    = m->root_pid;
		li.sub_asked   = asked;
		li.sub_enabled = enabled;
		li.started     = kof_evt_now();
		m->log = kofevt_log_create(m->log_path, &li);
		if (!m->log)
			fprintf(stderr, "kofmontrace: cannot write '%s' - "
				"continuing without a log\n", m->log_path);
		else
			fprintf(stderr, "kofmontrace: recording to %s\n",
				m->log_path);
	}
}

/* Step: open the report and, with it, the engine and the scanner. */
static void mt_open_report(struct mt_run *m, char **argv)
{
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
	kmt_spill_init(&m->spill, m->rep_dir);

	if (m->rep_dir) {
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
		const char *subject = argv[m->first];

		if (kmt_tracer_resolve(argv[m->first], subj, sizeof subj))
			subject = subj;

		memset(&ri, 0, sizeof ri);
		ri.tool        = "kofmontrace";
		ri.subject     = subject;
		ri.subject_cmd = m->cmd;
		ri.root_pid    = m->root_pid;
		ri.build       = (uint32_t)KOFENG_BUILD;
		/* Asked of kofevt rather than spelled here, so this tool and
		 * the log header cannot name the same machine differently. */
		ri.platform    = kof_evt_platform_self();
		ri.arch        = kof_evt_arch_self();
		ri.started     = kof_evt_now();
		ri.dir         = m->rep_dir;
		ri.log         = m->log_path;
		{
			uint32_t asked, enabled;

			kmt_tracer_subs(&m->tr, &asked, &enabled);
			ri.sub_asked   = asked;
			ri.sub_enabled = enabled;
		}

		m->rep = kof_report_open(&ri);
		if (!m->rep) {
			fprintf(stderr, "kofmontrace: cannot open a report - "
				"continuing without one\n");
		} else {
			m->eng = keng_open(m->db_path);
			if (m->eng)
				m->sc = kscan_new(m->eng);
			if (!m->sc) {
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
				if (m->eng) {
					keng_close(m->eng);
					m->eng = NULL;
				}
				fprintf(stderr, "kofmontrace: no database at "
					"%s - the report will identify "
					"nothing (use --db)\n", m->db_path);
			}
			fprintf(stderr, "kofmontrace: report -> %s\n", m->rep_dir);
		}
	}
}

/* Step: the collection loop, until a stop condition or Ctrl-C. */
static void mt_loop(struct mt_run *m)
{
	while (!g_stop) {

		if (!kmt_tracer_next(&m->tr, &m->ke, 200, m->no_scope)) {
			m->secs = kof_evt_secs_since(m->t_wall0, kof_evt_now());
			goto tick;
		}

		if (m->t_ev0 == 0)
			m->t_ev0 = m->ke.stamp;
		m->ev_secs = kof_evt_secs_since(m->t_ev0, m->ke.stamp);
		/* The deadline clock still has to advance while events flow, or
		 * a program that never stops producing them never times out. */
		m->secs = kof_evt_secs_since(m->t_wall0, kof_evt_now());

		/*
		 * Everything that decides WHETHER this record belongs to the
		 * tree - growing the set on a ProcessStart, retiring it on a
		 * ProcessStop, refusing everything outside it - happened inside
		 * kmt_tracer_next. What arrives here is already scoped.
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
		if (m->log)
			(void)kofevt_log_write(m->log, &m->ke);

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
		if (m->rep) {
			kof_report_feed(m->rep, &m->ke,
					m->log ? m->rep_index : KOF_REP_NO_INDEX);
			if (m->log)
				m->rep_index++;
			/* AFTER the feed, because the fingerprint the copy
			 * attaches to is what the feed just created. */
			kmt_spill_take(&m->spill, m->rep, &m->ke);
		}

		if (!m->quiet)
			kof_evt_render(&m->ke, m->ev_secs, kmt_tracer_name_of(&m->tr),
				  stdout, &m->tally);
		else
			kof_evt_count(&m->ke, &m->tally);

tick:
		m->alive = (uint32_t)kmt_tracer_alive(&m->tr);
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
		if (m->stop_on_exit && m->alive == 0 && m->exited_at < 0.0)
			m->exited_at = m->secs;
		/*
		 * The grace window, and it is not politeness. Events are
		 * delivered up to a flush timer after they happened, so the
		 * last thing a process did routinely arrives after its own
		 * ProcessStop. Stopping the instant the subtree is empty
		 * truncates exactly the tail that matters.
		 */
		if (m->exited_at >= 0.0 && m->secs - m->exited_at >= m->grace) {
			m->how = KOF_END_TREE_EXIT;
			break;
		}
		if (m->timeout > 0.0 && m->secs >= m->timeout) {
			m->how = KOF_END_TIMEOUT;
			break;
		}
	}
}

/* Step: the end-of-run summary, the kill of the tree and the log close. */
static void mt_summary(struct mt_run *m)
{
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
	if (m->how == KOF_END_UNKNOWN)
		m->how = KOF_END_INTERRUPT;

	fflush(stdout);

	{
		char what[64];

		snprintf(what, sizeof what, "subtree of pid %lu",
			 (unsigned long)m->root_pid);
		kof_evt_print_tally(&m->tally, m->secs, what, stderr);
	}

	kmt_tracer_health(&m->tr, &m->nh);
	kof_evt_health_print(stderr, &m->nh, m->secs);
	/* And the half only this collector has - the unbacked count on
	 * Windows, the queue and permission state on Linux. Same screen as the
	 * neutral half, because a reader deciding whether to trust a quiet run
	 * needs both. */
	kmt_tracer_extra(&m->tr, stderr);
	kmt_tracer_report_unattributed(&m->tr, stderr);
	kmt_spill_report(&m->spill, stderr);

	/*
	 * THE SHAPES, AND WHY THIS IS ON THE TOOL PEOPLE ACTUALLY DEBUG WITH.
	 *
	 * An event that did not appear has two causes that look identical from
	 * the outside: the provider never sent it, or it arrived and this build
	 * had no type for it. Only this dump tells them apart - a shape listed
	 * for an id means the record reached the decoder. Without it the answer
	 * to "why did I not see the DLL load" is a guess.
	 */
	if (m->show_schema) {
		static char shapes[16384];

		if (kmt_tracer_describe(&m->tr, shapes, sizeof shapes))
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
	if (m->alive) {
		/* Neither `i` nor `n`: main already has both in scope by here.
		 * A shadowed index is harmless until somebody moves code
		 * between the two scopes, and this function is long enough
		 * that they will. */
		uint32_t k, pid;
		const char *nm;

		fprintf(stderr, "   %lu process(es) still running at exit:\n",
			(unsigned long)m->alive);
		for (k = 0; (nm = kmt_tracer_tracked_nth(&m->tr, k, &pid)) != NULL;
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
	if (m->contained && !m->leave_running) {
		if (m->alive)
			fprintf(stderr, "   terminating %lu process(es) still "
				"in the traced tree\n", (unsigned long)m->alive);
		kmt_tracer_stop(&m->tr);
	} else if (m->alive) {
		fputs("   WARNING those processes were NOT terminated\n",
		      stderr);
	}

	if (m->log) {
		uint64_t nrec = kofevt_log_close(m->log);

		fprintf(stderr, "   recorded %llu event(s) to %s\n",
			(unsigned long long)nrec, m->log_path);
	}
}

/* Step: the report, written once the tree is dead. */
static void mt_report(struct mt_run *m)
{
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
	if (m->rep) {
		struct kof_report_stage stage;
		char path[1024];
		FILE *f;
		int   rc;

		kof_report_ended(m->rep, m->how, m->secs);
		kof_report_health(m->rep, &m->nh, kmt_tracer_filtered_scope(&m->tr));

		struct kof_rep_engine rep_eng;

		memset(&stage, 0, sizeof stage);
		stage.collect = m->want_collect ? 1u : 0u;

		/* The report asks through an interface; this supplies one over
		 * the scanner this program already owns. NULL when there is no
		 * engine, which is a legal report - see kof_report_stage. */
		rep_eng.user = m->sc;
		rep_eng.ask  = kmt_rep_ask;
		stage.engine = (m->eng && m->sc) ? &rep_eng : NULL;

		fprintf(stderr, "\nkofmontrace: collecting artefacts...\n");
		rc = kof_report_finish(m->rep, &stage);
		if (rc < 0)
			fprintf(stderr, "kofmontrace: the artefact phase could "
				"not use '%s' (%d) - the report is written "
				"without collected files\n", m->rep_dir, rc);

		/*
		 * THREE FILES, AND EACH HAS A DIFFERENT READER.
		 *
		 * A failure to write one is reported and does not stop the
		 * others: a full disk must not cost the text report because
		 * the JSON could not be written.
		 *
		 * kof_fopen_trunc, not fopen: these three names are as
		 * guessable as the spill files and the sample was alive until
		 * a moment ago. O_NOFOLLOW makes a planted link a refusal.
		 */
		snprintf(path, sizeof path, "%s/report.txt", m->rep_dir);
		f = kof_fopen_trunc(path);
		if (f) {
			/* No colour into a file. The escapes would make it
			 * ungreppable, which is the one thing a report of this
			 * shape is read with. */
			kof_report_write_text(m->rep, f, 0);
			fclose(f);
			fprintf(stderr, "   %s\n", path);
		} else {
			fprintf(stderr, "   cannot write %s\n", path);
		}

		snprintf(path, sizeof path, "%s/report.json", m->rep_dir);
		f = kof_fopen_trunc(path);
		if (f) {
			kof_report_write_json(m->rep, f);
			fclose(f);
			fprintf(stderr, "   %s\n", path);
		} else {
			fprintf(stderr, "   cannot write %s\n", path);
		}

		snprintf(path, sizeof path, "%s/candidates.tsv", m->rep_dir);
		f = kof_fopen_trunc(path);
		if (f) {
			kof_report_write_candidates(m->rep, f);
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
		kof_report_write_text(m->rep, stderr, 1);

		kof_report_close(m->rep);
	}
}

/* Step: release what the run opened. */
static void mt_teardown(struct mt_run *m)
{
	if (m->sc)
		kscan_free(m->sc);
	if (m->eng)
		keng_close(m->eng);

	kmt_tracer_close(&m->tr);
}

int main(int argc, char **argv)
{
	struct mt_run m;
	int rc;

	kof_utf8_init(&argc, &argv);
	mt_init(&m);

	rc = mt_parse_args(&m, argc, argv);
	if (rc >= 0)
		return rc;
	rc = mt_prepare(&m, argc, argv);
	if (rc >= 0)
		return rc;
	rc = mt_start(&m, argv);
	if (rc >= 0)
		return rc;
	mt_announce(&m);
	mt_contain(&m);
	mt_open_log(&m);
	mt_open_report(&m, argv);

	m.t_wall0 = kof_evt_now();
	kmt_tracer_resume(&m.tr);

	mt_loop(&m);
	mt_summary(&m);
	mt_report(&m);
	mt_teardown(&m);
	return 0;
}
