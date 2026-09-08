/*
 * kofwintrace - run a program and show only what IT did.
 *
 * Point it at a file, it launches it, and it prints the event trace of that
 * process and everything the process went on to create. Nothing else on the
 * machine appears, which is the entire difference between this and kofwinmon:
 * kofwinmon answers "what does this machine do and what does watching it cost",
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
 * This RUNS what you give it, with the privileges it was started with, and it
 * does not sandbox, contain or undo anything. That is what makes the trace real
 * and it is also the whole risk. A machine that runs live samples through this
 * is a machine that has run live samples.
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
	InterlockedExchange(&g_stop, 1);
	return TRUE;
}

static void usage(void)
{
	fputs("usage: kofwintrace [options] <program> [args...]\n"
	      "\n"
	      "  --timeout N   give up after N seconds (default 60)\n"
	      "  --grace N     keep collecting N seconds after the subtree\n"
	      "                exits (default 2)\n"
	      "  --raw         also print events this build has no type for\n"
	      "  --schema      at exit, print the payload shapes TDH described\n"
	      "  --all-images  do not suppress system module loads\n"
	      "  --no-image    do not subscribe to module loads at all\n"
	      "  --no-file     do not subscribe to file events\n"
	      "  --file-write  also subscribe to writes into EXISTING files\n"
	      "  --net         also subscribe to network events\n"
	      "  --ring N      records in flight (default 16384, 512B each)\n"
	      "\n"
	      "Requires an elevated prompt.\n"
	      "\n"
	      "THIS EXECUTES THE FILE. It does not sandbox or contain it.\n",
	      stderr);
}

int main(int argc, char **argv)
{
	struct kofw_mon_option opt;
	struct kofw_mon   *mon;
	struct kofw_health health;
	struct kofw_evt    e;
	struct wm_tally    tally;
	STARTUPINFOA        si;
	PROCESS_INFORMATION pi;
	char     cmd[8192];
	double   timeout = 60.0, grace = 2.0, exited_at = -1.0;
	double   secs = 0.0, ev_secs = 0.0;
	uint64_t t_wall0, t_ev0 = 0;
	uint32_t root_pid, alive = 1;
	int      want_file = 1, want_image = 1, want_net = 0, want_write = 0;
	int      show_raw = 0, show_all_img = 0, show_schema = 0;
	int      err = 0, i, first;
	size_t   n;

	memset(&opt, 0, sizeof opt);
	memset(&tally, 0, sizeof tally);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--timeout") && i + 1 < argc)
			timeout = atof(argv[++i]);
		else if (!strcmp(argv[i], "--grace") && i + 1 < argc)
			grace = atof(argv[++i]);
		else if (!strcmp(argv[i], "--ring") && i + 1 < argc)
			opt.ring_capacity = (uint32_t)strtoul(argv[++i],
							      NULL, 10);
		else if (!strcmp(argv[i], "--raw"))
			show_raw = 1;
		else if (!strcmp(argv[i], "--schema"))
			show_schema = 1;
		else if (!strcmp(argv[i], "--all-images"))
			show_all_img = 1;
		else if (!strcmp(argv[i], "--no-image"))
			want_image = 0;
		else if (!strcmp(argv[i], "--no-file"))
			want_file = 0;
		else if (!strcmp(argv[i], "--file-write"))
			want_write = 1;
		else if (!strcmp(argv[i], "--net"))
			want_net = 1;
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
			fputs("kofwintrace: command line too long\n", stderr);
			return 2;
		}
		n += (size_t)w;
	}

	SetConsoleCtrlHandler(on_ctrl, TRUE);

	opt.providers = KOFW_SUB_PROCESS |
			(want_image ? KOFW_SUB_IMAGE : 0u) |
			(want_file  ? KOFW_SUB_FILE  : 0u) |
			(want_write ? KOFW_SUB_FILE_WRITE : 0u) |
			(want_net   ? KOFW_SUB_NET   : 0u);
	opt.trace_self = 1;   /* see the header comment */

	mon = kofw_mon_open(&opt, &err);
	if (!mon) {
		fprintf(stderr, "kofwintrace: %s\n", kofw_err_name(err));
		if (err == KOFW_ERR_ACCESS)
			fputs("kofwintrace: run this from an elevated prompt.\n",
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
		fprintf(stderr, "kofwintrace: cannot run '%s' (error %lu)\n",
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
	if (kofw_mon_track(mon, root_pid, wm_leaf(argv[first])) != 0) {
		fputs("kofwintrace: could not track the root process\n", stderr);
		TerminateProcess(pi.hProcess, 1);
		kofw_mon_close(mon);
		return 1;
	}
	{
		struct kofw_filter f;

		memset(&f, 0, sizeof f);
		f.root_pid = root_pid;
		if (!show_all_img)
			f.drop_loc = 1u << KOFW_LOC_SYSTEM;
		if (!show_raw)
			f.types = ~(uint32_t)(1u << KOFW_EVT_RAW);
		kofw_mon_filter(mon, &f);
	}

	fprintf(stderr, "kofwintrace: %s\nkofwintrace: root pid %lu, providers:"
		" process%s%s%s%s\n\n",
		cmd, (unsigned long)root_pid,
		want_image ? " image" : "", want_file ? " file" : "",
		want_write ? " file-write" : "", want_net ? " net" : "");

	t_wall0 = wm_now();
	ResumeThread(pi.hThread);

	while (!g_stop) {

		if (!kofw_mon_next(mon, &e, 200)) {
			secs = wm_secs_since(t_wall0, wm_now());
			goto tick;
		}

		if (t_ev0 == 0)
			t_ev0 = e.stamp;
		ev_secs = wm_secs_since(t_ev0, e.stamp);
		/* The deadline clock still has to advance while events flow, or
		 * a program that never stops producing them never times out. */
		secs = wm_secs_since(t_wall0, wm_now());

		/*
		 * Everything that decides WHETHER this record belongs to the
		 * tree - growing the set on a ProcessStart, retiring it on a
		 * ProcessStop, refusing everything outside it - happened inside
		 * kofw_mon_next. What arrives here is already scoped.
		 */
		wm_render(&e, ev_secs,
			  kofw_mon_name_of(mon, e.pid,
					   e.type == KOFW_EVT_PROC_START ||
					   e.type == KOFW_EVT_PROC_STOP
						   ? e.create_time : 0),
			  &tally);

tick:
		alive = kofw_mon_tracked_alive(mon);
		if (alive == 0 && exited_at < 0.0)
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
		if (secs >= timeout)
			break;
	}

	fflush(stdout);

	{
		char what[64];

		snprintf(what, sizeof what, "subtree of pid %lu",
			 (unsigned long)root_pid);
		kofw_mon_health(mon, &health);
		wm_print_tally(&tally, secs, what, health.filtered);
	}

	wm_print_health(&health, secs);

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
	if (alive)
		fprintf(stderr, "   %lu process(es) still running at exit\n",
			(unsigned long)alive);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	kofw_mon_close(mon);
	return 0;
}
