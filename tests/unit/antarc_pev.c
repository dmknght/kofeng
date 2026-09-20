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
		int saw_parent = 0, dedup = 0;
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
			    e.pid == (uint32_t)kid)
				saw_stop = 1;
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
