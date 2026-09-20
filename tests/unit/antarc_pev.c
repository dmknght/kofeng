/*
 * antarc_pev.c - the Linux process-event collector.
 *
 * WHAT A CI CAN TEST HERE, and the answer is the important half.
 *
 * The netlink process connector needs CAP_NET_ADMIN and a CI has none. What
 * makes that worth a test rather than a skip is HOW the kernel refuses:
 * measured on this machine, socket, bind, ADD_MEMBERSHIP and the LISTEN
 * message all report success and then nothing is ever delivered - no event, no
 * ack, no NLMSG_ERROR. See apev.h.
 *
 * So the thing that must not regress is exactly the thing an unprivileged run
 * CAN check: that kofa_pev_open refuses to hand back a session it has not
 * proved delivers. A collector that opened here would report a machine where
 * nothing ever runs, which is the worst failure a sensor has - it looks like
 * good news.
 *
 * Run as root, the same test asserts the opposite and drains a real exec.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "apev.h"

static int failures;

static void ok(int cond, const char *what)
{
	printf("  %-4s %s\n", cond ? "ok" : "FAIL", what);
	if (!cond)
		failures++;
}

/*
 * EVERY VERB THIS COLLECTOR CAN EMIT HAS A NAME, AND THEY ARE ALL DIFFERENT.
 *
 * ptrace, setuid, setsid, comm and coredump used to arrive as KOF_EVT_RAW with
 * an id and a dictionary to explain it. They have verbs now - see the note
 * above KOF_EVT_PROC_ATTACH - and a verb IS the name, so what has to hold is
 * that the neutral vocabulary actually knows them: a verb kof_evt_verb_name
 * cannot name is a record that prints as a number in every log and report.
 *
 * Distinctness is checked because these were added as a block, and a
 * copy-pasted case label returning the neighbour's string is the exact mistake
 * a block of five invites.
 */
static void verbs_are_named(void)
{
	static const uint16_t V[] = {
		KOF_EVT_PROC_START, KOF_EVT_PROC_STOP,
		KOF_EVT_PROC_ATTACH, KOF_EVT_PROC_PRIVILEGE,
		KOF_EVT_PROC_SESSION, KOF_EVT_PROC_RENAME,
		KOF_EVT_PROC_CRASH,
		/* The collector emits these too - a task that is not its own
		 * group leader is a thread, see ev_tgid. */
		KOF_EVT_THREAD_START, KOF_EVT_THREAD_STOP
	};
	size_t n = sizeof V / sizeof V[0], i, j;
	int named = 1, distinct = 1, proc_kind = 1;

	for (i = 0; i < n; i++) {
		const char *a = kof_evt_verb_name(V[i]);

		if (!a || !*a || !strcmp(a, "?"))
			named = 0;
		/*
		 * AND EACH IS A PROCESS RECORD. kof_evt_kind_of decides which
		 * half of the union a reader may touch, and a verb plainly
		 * about a process that answered otherwise would hand
		 * kof_evt_as_proc a NULL.
		 */
		/*
		 * A THREAD RECORD IS NOT A PROCESS RECORD. kof_evt_kind_of
		 * files the thread verbs with the image loads, because what
		 * they name is a place in memory rather than a process's own
		 * facts - so they are exempt from this check rather than
		 * quietly expected to fail it.
		 */
		if (V[i] != KOF_EVT_THREAD_START &&
		    V[i] != KOF_EVT_THREAD_STOP &&
		    kof_evt_kind_of(V[i]) != KOF_EK_PROC)
			proc_kind = 0;
		for (j = i + 1; j < n; j++)
			if (!strcmp(a, kof_evt_verb_name(V[j])))
				distinct = 0;
	}
	ok(named, "every process verb has a name");
	ok(distinct, "and no two of them share one");
	ok(proc_kind, "and each is a process-kind record");
	printf("       ");
	for (i = 0; i < n; i++)
		printf("%s ", kof_evt_verb_name(V[i]));
	printf("\n");
}

int main(void)
{
	struct kofa_pev_option o;
	struct kofa_pev *p;
	int err = 0;
	int privileged = geteuid() == 0;

	memset(&o, 0, sizeof o);
	o.trace_self = 1;
	p = kofa_pev_open(&o, &err);

	if (!privileged) {
		/*
		 * THE WHOLE POINT. Not "it failed" - it must fail with the
		 * error that says privilege, having discovered that by
		 * probing, because nothing in the syscalls said so.
		 */
		ok(p == NULL, "unprivileged: no session is handed back");
		ok(err == KOFA_ERR_DENIED || err == KOFA_ERR_UNSUPPORTED,
		   "and it says denied or unsupported, not OK");
		printf("       err=%s\n", kofa_err_name(err));
		/* The duplicate test must answer NO on a session that saw no
		 * start - the safe direction, because a duplicate is noise and
		 * a dropped event is a gap. */
		ok(!kofa_pev_is_own_image(NULL, 1, "/bin/true", 0),
		   "the duplicate test refuses without a session");
		/* And the hint is safe on one too - the sensor calls it
		 * whenever fanotify reports an exec-open, including on a host
		 * where the process collector never opened. */
		kofa_pev_hint_image(NULL, 1, "/bin/true");
		ok(1, "the image hint is safe without a session");
		verbs_are_named();
		if (p)
			kofa_pev_close(p);
		printf("antarc pev: %s\n", failures ? "FAILED" : "ok");
		return failures != 0;
	}

	ok(p != NULL, "privileged: the session opens");
	if (!p) {
		printf("       err=%s\n", kofa_err_name(err));
		printf("antarc pev: FAILED\n");
		return 1;
	}
	ok(kofa_pev_api(p) != NULL, "and hands out a monitor api");

	/*
	 * A REAL EXEC, AND THE RECORD FOR IT. /bin/true is the smallest thing
	 * that is certainly on the machine and certainly not this process.
	 */
	{
		struct kof_evt e;
		int saw_start = 0, saw_path = 0, saw_stop = 0, i;
		int saw_parent = 0, dedup = 0, stop_tid_ok = 1;
		char img[512];
		pid_t kid = fork();

		img[0] = '\0';

		if (kid == 0) {
			execl("/bin/true", "true", (char *)NULL);
			execl("/usr/bin/true", "true", (char *)NULL);
			_exit(127);
		}
		for (i = 0; i < 200; i++) {
			if (!kof_mon_next(kofa_pev_api(p), &e, 50))
				continue;
			if (e.verb == KOF_EVT_PROC_START &&
			    e.pid == (uint32_t)kid) {
				saw_start = 1;
				if (e.off_image != KOF_TEXT_NONE &&
				    strstr(e.text + e.off_image, "true")) {
					saw_path = 1;
					snprintf(img, sizeof img, "%s",
						 e.text + e.off_image);
				}
				/*
				 * THE PARENT COMES FROM THE FORK RECORD, not
				 * from /proc - which is why it is right even
				 * for a process that has already exited. This
				 * test forked the child, so the answer is
				 * known exactly.
				 */
				if (!(e.miss & KOF_F_PPID) &&
				    e.ppid == (uint32_t)getpid() &&
				    e.actor_pid == e.ppid)
					saw_parent = 1;
				/* And the sensor's duplicate test agrees the
				 * image belongs to this start. */
				if (img[0] &&
				    kofa_pev_is_own_image(p, (uint32_t)kid,
							  img, 0))
					dedup = 1;
			}
			if (e.verb == KOF_EVT_PROC_STOP &&
			    e.pid == (uint32_t)kid) {
				saw_stop = 1;
				/*
				 * A PROCESS STOP IS ITS LEADER'S. The task and
				 * the thread group are the same number there,
				 * and a record where they differ would be a
				 * thread's exit filed as the program ending -
				 * which is what this used to do, dozens of
				 * times over, on anything threaded.
				 */
				if (e.tid && e.tid != e.pid)
					stop_tid_ok = 0;
			}
			if (saw_start && saw_stop)
				break;
		}
		waitpid(kid, NULL, 0);
		ok(saw_start, "an exec becomes ProcStart with the right pid");
		ok(saw_path, "and carries the image path");
		ok(saw_stop, "and its exit becomes ProcStop");
		ok(saw_parent,
		   "the start names the parent, and the parent is the actor");
		ok(dedup,
		   "an exec-open of that image is recognised as the duplicate");
		ok(stop_tid_ok,
		   "a process stop names the leader task, not a thread");

		/*
		 * AND THE HINT FILLS A START THAT /proc COULD NOT.
		 *
		 * The path fanotify would have supplied is handed over for a
		 * pid that has not started yet, and the next start on that pid
		 * must carry it. This is the shape that answers the race an
		 * obfuscated shell wins - see kofa_pev_hint_image.
		 */
		{
			struct kof_evt e2;
			int filled = 0, k;
			pid_t k2;

			kofa_pev_hint_image(p, 0xffffffu, "/bin/true");
			k2 = fork();
			if (k2 == 0) {
				execl("/bin/true", "true", (char *)NULL);
				execl("/usr/bin/true", "true", (char *)NULL);
				_exit(127);
			}
			kofa_pev_hint_image(p, (uint32_t)k2, "/hinted/path");
			for (k = 0; k < 200; k++) {
				if (!kof_mon_next(kofa_pev_api(p), &e2, 50))
					continue;
				if (e2.verb == KOF_EVT_PROC_START &&
				    e2.pid == (uint32_t)k2 &&
				    e2.off_image != KOF_TEXT_NONE &&
				    !strcmp(e2.text + e2.off_image,
					    "/hinted/path"))
					filled = 1;
				if (e2.verb == KOF_EVT_PROC_STOP &&
				    e2.pid == (uint32_t)k2)
					break;
			}
			waitpid(k2, NULL, 0);
			ok(filled,
			   "a hinted path fills the start /proc would race");
		}
	}

	/*
	 * A FORK THAT NEVER EXECS PRODUCES NEITHER RECORD.
	 *
	 * The connector reports an EXIT for every process, including one that
	 * only forked - a subshell, a coprocess - and those carry no image and
	 * raised no start. A stop with no start is the shape that leaks
	 * entries out of whatever table a consumer keeps, so the collector
	 * remembers which pids it called started and emits a stop only for
	 * those. This is the test of that; it is the one assertion here that
	 * the unprivileged run cannot reach at all.
	 */
	{
		struct kof_evt e;
		int stray = 0, i;
		pid_t kid = fork();

		if (kid == 0)
			_exit(0);
		for (i = 0; i < 100; i++) {
			if (!kof_mon_next(kofa_pev_api(p), &e, 50))
				continue;
			if (e.pid == (uint32_t)kid)
				stray++;
		}
		waitpid(kid, NULL, 0);
		ok(!stray, "a fork with no exec produces no record at all");
		if (stray)
			printf("       %d record(s) for a fork-only pid\n",
			       stray);
	}

	kofa_pev_close(p);
	printf("antarc pev: %s\n", failures ? "FAILED" : "ok");
	return failures != 0;
}
