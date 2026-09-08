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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "kofgrille.h"
#include "kofevt.h"
#include "kofevtfmt.h"
#include "kofevtlog.h"

static volatile LONG g_stop;

static BOOL WINAPI on_ctrl(DWORD type)
{
	(void)type;
	InterlockedExchange(&g_stop, 1);
	return TRUE;
}

static void usage(void)
{
	kof_evt_banner(stderr, "kofmontrace", (uint32_t)KOFENG_BUILD,
		       "process, image, file, network, registry, amsi");
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
	      "  --ring N        records in flight (default 65536, 512B each)\n"
	      "  --log FILE      record every event this run KEPT into FILE, as\n"
	      "                  fixed 512-byte records behind a header. The\n"
	      "                  point is replay: a rule that cannot be run\n"
	      "                  again over a recorded trace cannot be\n"
	      "                  regression tested, and a false positive nobody\n"
	      "                  can reproduce cannot be fixed. The file reads\n"
	      "                  on a host with no ETW at all.\n"
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
	      "Registry events currently arrive UNTYPED, so --no-raw hides them\n"
	      "entirely. See the note in wevt_decode.c on establishing the ids.\n"
	      "\n"
	      "Requires an elevated prompt.\n"
	      "\n"
	      "THIS EXECUTES THE FILE. It does not sandbox it and does not undo\n"
	      "what it did; it does kill the tree it launched when it exits.\n",
	      stderr);
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
	STARTUPINFOA        si;
	PROCESS_INFORMATION pi;
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
	HANDLE   job = NULL;
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
	int      want_amsi = 1;
	int      show_raw = 1, show_all_img = 0, show_schema = 0, quiet = 0;
	const char *log_path = NULL;
	struct kofevt_log_w *log = NULL;
	int      err = 0, i, first;
	size_t   n;

	memset(&opt, 0, sizeof opt);
	memset(&tally, 0, sizeof tally);
	/* 32MB. The old 16384 was sized for process events alone; with the
	 * registry in the same session a burst fills that in well under a
	 * second, and a ring drop is a record nothing can get back. */
	opt.ring_capacity = 65536u;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
			timeout = atof(argv[++i]);
		else if (!strcmp(argv[i], "--grace") && i + 1 < argc)
			grace = atof(argv[++i]);
		else if (!strcmp(argv[i], "--ring") && i + 1 < argc)
			opt.ring_capacity = (uint32_t)strtoul(argv[++i],
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

	SetConsoleCtrlHandler(on_ctrl, TRUE);

	opt.providers = KOFW_SUB_PROCESS |
			(want_image ? KOFW_SUB_IMAGE : 0u) |
			(want_file  ? KOFW_SUB_FILE  : 0u) |
			(want_write ? KOFW_SUB_FILE_WRITE : 0u) |
			(want_net   ? KOFW_SUB_NET   : 0u) |
			(want_reg   ? KOFW_SUB_REGISTRY : 0u) |
			(want_amsi  ? KOFW_SUB_AMSI : 0u) |
			(want_thread ? KOFW_SUB_THREAD : 0u) |
			(want_open  ? KOFW_SUB_FILE_OPEN : 0u);
	opt.trace_self = 1;   /* see the header comment */

	mon = kofw_mon_open(&opt, &err);
	if (!mon) {
		fprintf(stderr, "kofmontrace: %s\n", kofw_err_name(err));
		if (err == KOFW_ERR_ACCESS)
			fputs("kofmontrace: run this from an elevated prompt.\n",
			      stderr);
		return 1;
	}

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
	memset(&si, 0, sizeof si);
	si.cb = sizeof si;
	memset(&pi, 0, sizeof pi);

	if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED,
			    NULL, NULL, &si, &pi)) {
		fprintf(stderr, "kofmontrace: cannot run '%s' (error %lu)\n",
			argv[first], (unsigned long)GetLastError());
		kofw_mon_close(mon);
		return 1;
	}

	root_pid = pi.dwProcessId;

	/*
	 * SCOPE IT BEFORE IT RUNS. The process is still suspended here, so
	 * "the subtree is known" happens strictly before "the subtree can do
	 * anything" - the only ordering with no hole in it.
	 */
	if (kofw_mon_track(mon, root_pid, kof_path_leaf(argv[first])) != 0) {
		fputs("kofmontrace: could not track the root process\n", stderr);
		TerminateProcess(pi.hProcess, 1);
		kofw_mon_close(mon);
		return 1;
	}
	{
		struct kofw_filter f;

		memset(&f, 0, sizeof f);
		/*
		 * NO SCOPE AT ALL, when asked.
		 *
		 * Scoping to a tree is what makes a trace readable, and it has
		 * one failure that is not a bug and cannot be fixed from
		 * inside: parentage. A payload that migrates is running in a
		 * process that is nobody's descendant, and everything it does
		 * from there - including every process it goes on to create -
		 * is attributed outside the tree and dropped. The trace shows a
		 * clean subtree and says nothing about the thing that walked
		 * out of it.
		 *
		 * There is no clever repair for that: no event says "this
		 * process is now running somebody else's code". So the honest
		 * option is to turn the scope off and take the noise, which on
		 * a quiet test machine is a fair trade.
		 */
		f.root_pid = no_scope ? 0u : root_pid;
		if (!show_all_img)
			f.drop_loc = 1u << KOF_LOC_SYSTEM;
		if (!show_raw)
			f.types = ~(uint32_t)(1u << KOF_EVT_RAW);
		if (amsi_anywhere)
			f.scope_exempt_prov = 1u << KOFW_PROV_AMSI;
		kofw_mon_filter(mon, &f);
	}

	/* Said out loud, because it breaks the promise the rest of the output
	 * makes: with this on, not every line below belongs to the traced
	 * tree. */
	if (amsi_anywhere)
		fputs("kofmontrace: --amsi-anywhere: AMSI records from ANY "
		      "process are shown, not only the traced tree\n", stderr);

	fprintf(stderr, "kofmontrace: build %llu\n",
		(unsigned long long)KOFENG_BUILD);
	fprintf(stderr, "kofmontrace: %s\nkofmontrace: root pid %lu, providers:"
		" process%s%s%s%s%s%s%s%s\n\n",
		cmd, (unsigned long)root_pid,
		want_image ? " image" : "", want_file ? " file" : "",
		want_write ? " file-write" : "", want_net ? " net" : "",
		want_reg ? " registry" : "", want_amsi ? " amsi" : "",
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
		struct kofw_health h0;
		uint32_t missing, b;

		kofw_mon_health(mon, &h0);
		missing = h0.sub_asked & ~h0.sub_enabled;
		if (missing) {
			fputs("kofmontrace: REFUSED by the provider:", stderr);
			for (b = 1u; b; b <<= 1)
				if (missing & b)
					fprintf(stderr, " %s",
						kofw_sub_name(b));
			fputs("\n\n", stderr);
		}
	}

	/*
	 * A JOB OBJECT, ASSIGNED WHILE THE TARGET IS STILL SUSPENDED.
	 *
	 * Ctrl-C used to stop the tracer and leave the sample running. The
	 * console sends CTRL_C_EVENT to the process group, so a well-behaved
	 * console child dies with it - but a sample is not a well-behaved
	 * console child, and anything it spawned into its own group never got
	 * the event at all. Somebody stopping a trace reasonably believes they
	 * stopped the run.
	 *
	 * TerminateProcess on the root would not have fixed it either: it kills
	 * one process and orphans the tree under it, which for a dropper is the
	 * half that matters. A job holds the whole descendancy, and
	 * KILL_ON_JOB_CLOSE means the kernel does the killing when the last
	 * handle goes - so it still happens if this tracer crashes or is killed
	 * itself, which is exactly when it is most needed.
	 *
	 * Assigned before ResumeThread for the same reason the pid is recorded
	 * before it: after that instruction the target can create children, and
	 * a child created before the job exists is outside it forever.
	 */
	if (!leave_running) {
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli;

		job = CreateJobObjectW(NULL, NULL);
		if (job) {
			memset(&eli, 0, sizeof eli);
			eli.BasicLimitInformation.LimitFlags =
				JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
			if (!SetInformationJobObject(
				    job, JobObjectExtendedLimitInformation,
				    &eli, sizeof eli) ||
			    !AssignProcessToJobObject(job, pi.hProcess)) {
				CloseHandle(job);
				job = NULL;
			}
		}
		/*
		 * Loud, not silent. Without the job this tool leaves whatever
		 * it ran behind when it exits, and that is a fact about the
		 * machine somebody has to know before they trust the trace to
		 * have ended the run.
		 */
		if (!job)
			fputs("kofmontrace: WARNING could not contain the "
			      "target in a job object; it and anything it "
			      "starts will SURVIVE this tracer\n", stderr);
	}

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
		struct kofw_health h1;
		struct kofevt_log_info li;

		kofw_mon_health(mon, &h1);
		memset(&li, 0, sizeof li);
		/* The record this collector produces, named as well as sized:
		 * another collector's 512-byte record is not this one. */
		li.rec_size    = (uint32_t)sizeof(struct kof_evt);
		/* The shape, so the log can write only the text a record
		 * actually has - offsetof at the one place that knows the
		 * layout. */
		li.head_size   = (uint16_t)KOF_EVT_HEAD;
		li.len_off     = (uint16_t)offsetof(struct kof_evt, text_len);
		li.rec_kind    = KOFEVT_REC_KOF;
		li.build       = (uint32_t)KOFENG_BUILD;
		/* 0 asks kofevt for this host, so the tool does not have
		 * to know how to spell it. */
		li.platform    = 0u;
		li.arch        = 0u;
		li.root_pid    = root_pid;
		li.sub_asked   = h1.sub_asked;
		li.sub_enabled = h1.sub_enabled;
		li.started     = kof_evt_now();
		log = kofevt_log_create(log_path, &li);
		if (!log)
			fprintf(stderr, "kofmontrace: cannot write '%s' - "
				"continuing without a log\n", log_path);
		else
			fprintf(stderr, "kofmontrace: recording to %s\n",
				log_path);
	}

	t_wall0 = kof_evt_now();
	ResumeThread(pi.hThread);

	while (!g_stop) {

		if (!kofw_mon_next(mon, &e, 200)) {
			secs = kof_evt_secs_since(t_wall0, kof_evt_now());
			goto tick;
		}

		if (t_ev0 == 0)
			t_ev0 = e.stamp;
		ev_secs = kof_evt_secs_since(t_ev0, e.stamp);
		/* The deadline clock still has to advance while events flow, or
		 * a program that never stops producing them never times out. */
		secs = kof_evt_secs_since(t_wall0, kof_evt_now());

		/*
		 * Everything that decides WHETHER this record belongs to the
		 * tree - growing the set on a ProcessStart, retiring it on a
		 * ProcessStop, refusing everything outside it - happened inside
		 * kofw_mon_next. What arrives here is already scoped.
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
		kofw_evt_to_kof(&e, &ke);

		if (log)
			(void)kofevt_log_write(log, &ke);

		if (!quiet)
			kof_evt_render(&ke, ev_secs,
				  kofw_mon_name_of(mon, e.pid,
						   e.type == KOF_EVT_PROC_START ||
						   e.type == KOF_EVT_PROC_STOP
							   ? e.create_time : 0),
				  stdout, &tally);
		else
			kof_evt_count(&ke, &tally);

tick:
		alive = kofw_mon_tracked_alive(mon);
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
		if (exited_at >= 0.0 && secs - exited_at >= grace)
			break;
		if (timeout > 0.0 && secs >= timeout)
			break;
	}

	fflush(stdout);

	{
		char what[64];

		snprintf(what, sizeof what, "subtree of pid %lu",
			 (unsigned long)root_pid);
		kofw_mon_health(mon, &health);
		kof_evt_print_tally(&tally, secs, what, stderr);
	}

	kofw_mon_health_neutral(mon, &nh);
	kof_evt_health_print(stderr, &nh, secs);
	/* And the half only this collector has - see kofw_health_print_extra
	 * for why the unbacked count and the reasons it may be unanswerable
	 * belong on the same screen. */
	kofw_health_print_extra(stderr, &health);

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

		if (kofw_mon_describe(mon, shapes, sizeof shapes))
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
		for (k = 0; (nm = kofw_mon_tracked_nth(mon, k, &pid)) != NULL;
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
	 * gives the line below something true to say.
	 */
	if (job) {
		if (alive)
			fprintf(stderr, "   terminating %lu process(es) still "
				"in the traced tree\n", (unsigned long)alive);
		TerminateJobObject(job, 1);
		CloseHandle(job);
	} else if (alive) {
		fputs("   WARNING those processes were NOT terminated: this "
		      "run had no job object\n", stderr);
	}

	if (log) {
		uint64_t nrec = kofevt_log_close(log);

		fprintf(stderr, "   recorded %llu event(s) to %s\n",
			(unsigned long long)nrec, log_path);
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	kofw_mon_close(mon);
	return 0;
}
